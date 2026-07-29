# TASM2 offline patch — The Amazing Spider-Man 2 (iOS 1.3.1)

Gameloft's servers for *The Amazing Spider-Man 2* have been dead since ~2018,
and the iOS build hangs forever on **“Downloading profile”**. This patches the
game so it launches, plays **and saves** entirely offline.

Eight instructions, all in the arm64 slice, every one derived from the
disassembly and verified on the binary that actually ships. No new save
format, no injected code, no size change.

**Confirmed on device** (LiveContainer, iOS): a continuous playthrough through
the prologue, all of chapter 1 and into chapter 2, with the app force-quit
several times along the way. Settings, trophies, exploration, skills, position,
tutorial state and the story cursor all survive.

## Get it

The workflow builds the IPA from the archive.org copy, and running a workflow
needs write access to the repository it runs in — so **fork this one first**.
The Actions tab of somebody else's repository will not run it for you.

1. **Fork**, then **Actions** tab → *Patch TASM2 IPA* → **Run workflow**
2. Download `SpiderMan2_patched.ipa` from the release the run creates
3. Install with LiveContainer / SideStore / Sideloadly

> **Patch before installing, not after.** LiveContainer loads apps with
> `dlopen()` and converts the binary from `MH_EXECUTE` to `MH_DYLIB` **at
> install time**. Replacing the binary inside an already-installed `.app`
> overwrites that conversion and produces `cannot dlopen a main executable`.
> When updating, delete the app first rather than installing over the top.

## What works

| | |
|---|---|
| Launch | no more “Downloading profile” spinner |
| Story | prologue plays once, then the chapters advance on their own |
| Saves | all 17 save objects persist to `Documents/ud_*.sav` |
| Profile | the story cursor persists in `ud_OObjects.sav` |
| Settings, trophies, fog of war, skills, position, tutorial state | all persist |

## What still does not

- **Anything genuinely online**: shop purchases, events, friends. The servers
  are gone; the game says so with a *“Le réseau actuel est indisponible”*
  dialog, which is honest.
- **A waiting spinner** sits on screen while a request is pending, and offline
  some requests never answer, so it can stay. It is genuine feedback, not
  noise: those pages really are still loading. Removing it was tried
  (`0x1001e7b94` → `ret`) and **broke the skills menu**, because the function
  is void but not side-effect-free — it opens with a 185-instruction call that
  the menus depend on. The edit is kept in the patcher behind `--kill-spinner`,
  off by default, with the reasoning written up; the promising direction, not
  attempted, is to disable only the `Waiting.Mask` input blocker at
  `0x1001e7d80` so the spinner stays and taps pass through.
- **The “network unavailable” dialog** still appears now and then. It is
  emitted from 15 separate places, each of which looks the text up and builds
  its own message box through the same helper every other dialog in the game
  uses — there is no shared switch to flip. Removing it would mean fifteen
  guessed control-flow edits for the sake of one OK tap, on a build that
  works. Left alone deliberately.

## How it works

### 1. Get past the login — `0x1000ab7b8`

`UI_DOWNLOADING_PROFILE` has exactly one emission site. A shared predicate
decides between that spinner and the game's own `UI_FIRST_CHECK` (“nothing to
download, carry on”), and it keeps answering “yes” because the login never
completes.

```
bl <predicate>   ->   mov w0, #0
```

Applied only at that call site; the predicate itself is called from ~50 other
places and is left alone. Self-locating through the single reference to the
string: every ADRP/ADD pair forming that address is collected, each ADD has to
sit within eight instructions of its ADRP, and exactly one candidate must
survive — a first-match rule would patch a wrong `bl` in silence if a stale
register value ever produced one.

### 2. Make every save object local — `0x10021bc7c`

Each save object has a byte at `+0x25`: *“persist me to a local
`ud_<Name>.sav`”*. The constructor sets it on **five** of the seventeen — the
settings. Everything else rode in the Gameloft profile.

`CSaveMgr::ReloadAll` already walks all seventeen, already holds `1` in `w25`,
and its first act on each is the branch that skips the non-local ones:

```
0x10021bc78   ldrb w8, [x20, #0x25]
0x10021bc7c   cbz  w8, <next object>   ->   strb w25, [x20, #0x25]
```

From there the other twelve take exactly the path the five already take, with
the game's own serialisers on both ends.

### 3–4. Carry the chapter in `ud_QuestManager` — `0x1001ff4c8`, `0x1001ff594`

That object persists two ints. The second, `progressMgr+0x2dc`, is the
pending-mission id: the constructor sets it to `-1`, its only producer resets
its source to `-1` right after use, and its only consumer reads `-1` as
“nothing pending”. Every save stored the constructor default, so the slot was
free.

```
0x1001ff4c8   ldr w1, [x20, #0x2dc]  ->  mov w1, #1              serialise
0x1001ff594   str w0, [x19, #0x2dc]  ->  str w0, [x19, #0x2a4]   restore
```

Still two ints at version 3 — format, length and version byte unchanged.

### 5. Produce the chapter locally — `0x1001edd28`

`0x1001edd54` does not compute a chapter; it reads one out of the
mission-result map, whose only wholesale writer is the JSON callback of the
*mission finished* HTTP request. Offline the map stays empty and
`map["chapter"]` default-inserts 0.

```
0x1001edd28   ldr w20, [sp, #0x10]  ->  mov w20, #1
```

`w20` is read nowhere between that load and the store.

### 6–7. Stop the tutorial bitmask being discarded — `0x1003cc5f4`, `0x1003cc5b8`

Two paths threw it away, and device data caught both:

```
0x1003cc5f4   cbz w0, +0x14      ->  nop   the deserialiser stops discarding
                                           the saved value when the chapter is 0
0x1003cc5b8   str wzr, [x0, #4]  ->  nop   CTutorialMgr::Reset becomes a no-op
```

The second matters most: its single caller is the tail of the script
dispatcher at `0x1001205ec`, so the game's own scripts request the reset, and
one runs whenever the opening sequence plays. Before: `132926 → 62`
(`0x0002073e → 0x0000003e`, nine tutorial steps down to five). After:
`132926 → 153406 → 161790`.

### 8. Let the profile reach disk — `0x10021163c`

**The one that made story progression work.**

`progressMgr+0x50` is not an HTTP client in this build. It is a **local
mission server** (`0x100416000..0x100422000`) that reads the bundled
`ch0.json … ch8.json` and synthesises the answers Gameloft's server used to
send: request `0x16` fills the whole story cursor (`progressMgr+0x110`, a
`map<string,vector<int>>` keyed `"mm"`/`"sm"`/`"prm"`/`"rm"`) from
`profile["_ca"] == "chN"`; request `0x15` advances `profile["_ca"]` to
`chapterDoc["nc"]`.

Its state is save object 16 — the profile document — and object 16 is the only
one of the seventeen the writer refuses to write:

```
0x100211620   ldr  w8, [x19, #0x1c]      ; SaveIndex
0x100211624   cmp  w8, #0x10
0x100211628   b.ne <normal write>
0x100211634   ldr  w8, [saveMgr, #0xfc8]
0x100211638   and  w8, w8, #0xff00ff
0x10021163c   cbz  w8, <exit without writing>   ->   nop
```

`+0xfc8` is *“did this file already exist when the manager was constructed”*;
`+0xfca` is *“the cloud profile was touched”*, set only on two dead-offline
paths. Clean install ⇒ both zero ⇒ never written ⇒ never exists. A loop that
locks itself, and the reason object 16's `Reset` default of `"ch0"` was what
the game started from every launch.

The read-back side already ran for object 16 unconditionally, so the `nop`
enables no new code path — the file simply starts existing.

> `ud_OObjects.sav` is the one save file `tools/decode_sav.py` cannot read,
> and that is by design: object 16's constructor sets the device-key flag at
> `0x100215920`, so its XXTEA key comes from a device secret rather than from
> the file's own trailer.

### Complementary edits

Dead Gameloft hostnames are rewritten to `.invalid` (RFC 6761: never
resolves), and the jailbreak detection paths and function are neutralised.
Every edit preserves length exactly.

| Neutralised host | Role |
|---|---|
| livewebapp.gameloft.com | autologin.php |
| eve.gameloft.com | profile services |
| pjsmmm-legacy.gameloft.com | legacy backend |
| ingameads.gameloft.com | ads / iphoneloading.php |
| 201205igp.gameloft.com | IGP / freemium |

### Opting out

`--no-local-save`, `--no-persist-chapter`, `--no-tutorial-guards`,
`--no-profile-save`. An unknown flag is an error rather than a silent no-op, so
a typo cannot quietly drop an edit; `--no-force-prologue-skip` still works as
the former name of `--no-tutorial-guards`.

The patcher writes nothing if a site is missing or ambiguous, and
`patch_tasm2.py --verify <binary>` re-checks the binary that ships: all eight
edits — the main patch included — plus the jailbreak edit, plus that no live
Gameloft host survived, plus that the removed prologue-skip edit is **absent**,
so a binary built by an older patcher cannot pass. The build workflow runs it
after rezipping, and that is the only gate on the release.

## Tools

`tools/` is the analysis harness. The three scripts that open the executable
themselves — `scan.py`, `summary.py`, `st.py` — read its path from `TASM2_BIN`,
defaulting to `/home/user/AmazingSpiderMan2`; the sweeps and closures import it
from `st.py`, so the variable covers them too. `machoscan.py` is a library and
takes the path as an argument, and `decode_sav.py` / `encode_sav.py` work on
`.sav` files named on the command line, not on the executable. Imports resolve
relative to each script's own location, so the directory works wherever it is
cloned:

```
pip install -r tools/requirements.txt      # capstone, for the disassembler
TASM2_BIN=/path/to/AmazingSpiderMan2 python3 tools/scan.py dis 0x10021bc3c 40
```

`patch_tasm2.py` itself depends on nothing outside the standard library, which
is why the build workflow installs nothing.

| | |
|---|---|
| `machoscan.py` | FAT/Mach-O parsing, `LC_FUNCTION_STARTS` for exact function bounds, libc stub names from the indirect symbol table, ADRP/ADD cross-references |
| `scan.py` | `dis` / `fn` / `str` / `sref` / `xref` / `callers` / `info` |
| `summary.py` | dense per-function overview |
| `decode_sav.py` | decodes a `ud_*.sav` all the way to plain bytes |
| `encode_sav.py` | the inverse; refuses to write what it cannot read back |
| `sav-reader.html` | the same decoder as a self-contained page, to read a save on the phone |
| `st.py`, `sweep2.py`, `sweep2d8.py` | field sweeps that match a store's **byte range**, not its immediate — see below |
| `thisclose.py`, `closure2.py`, `closure3.py` | symbolic tracking of a base register through a function |

Matching `str Wt,[Xn,#imm]` against an offset is **not** an enumeration of a
field's writers: it misses every wider store at a lower offset. That is not
hypothetical — it is how the progress manager's constructor
(`str d1,[x9]`, `x9 = progressMgr+0x2a4`) escaped the first sweep in this
repo, and it cost a device test.

## Binary facts

- FAT `armv7 + arm64`; all edits are in the arm64 slice
- `cryptid=0` on both slices → already decrypted, no Apple ID prompt
- SDK iphoneos10.3 / Xcode 8.3, MinimumOSVersion 8.0
- Original SHA1 `b3d322a788bbeeb1a006ba0da23a28300a5b7105`, 33,375,152 bytes,
  unchanged after patching

The IPA is ~769 MB, which is why the workflow publishes it as a **Release**
(2 GB limit) rather than an artifact (bounded by the 500 MB account quota).

## Why the servers were not simply replaced

Giving the game a server was tried on device and is a dead end. Redirecting
works end to end — the phone really did reach a Cloudflare Worker under our
control — but the only HTTP traffic is the ad WebView. `autologin.php` is
never called, even with the profile patch removed so the game attempts a
genuine login.

The profile went exclusively through the **federation server: raw TCP, an
opcode-based binary protocol** (`_socket`/`_connect`/`_send`/`_recv`,
`port=7744&type=gs`, `Send federation request, opcode[%d]`). Framing,
handshake, opcodes and any encryption would have to be reconstructed with no
reference capture, the servers having been dead since ~2018. Hostname length
is *not* the obstacle — a DNS rewrite points any name anywhere without
touching the binary.

Which is the irony of this project: the local replacement Gameloft shipped in
the same binary was there the whole time, behind one `cbz`.

## No-patch alternative

Blocking those domains via DNS (NextDNS, AdGuard, an iOS profile) **before the
first launch** produces the same network failure as the host rewrite, without
touching any file and fully reversibly. It does not solve saving.

## Further reading

[LOCAL_SAVE_DESIGN.md](LOCAL_SAVE_DESIGN.md) — the save subsystem, the decoded
file format, the full reasoning behind each edit, and the log of everything
that was tried and did not work, including the two conclusions that device
data had to overturn.
