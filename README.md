# TASM2 offline patch — The Amazing Spider-Man 2 (iOS 1.3.1)

Patches the iOS build of **The Amazing Spider-Man 2 (1.3.1)** so it can be
launched and played after Gameloft shut down its servers.

**Scope, stated up front:** the game launches and plays offline, and its save
objects are now persisted locally instead of to Gameloft's dead profile
server — see [Local saving](#local-saving). Three device snapshots drove that
patch to its current shape, and the save format is now fully decoded, so the
next test can be measured rather than inferred.

## The problem

On launch the game hangs forever on **“Downloading profile”**
(`UI_DOWNLOADING_PROFILE`). It waits for a Gameloft profile server that no
longer exists, and the wait never ends.

Internal error strings in the binary:

- `[COnlineManager] anubi server init profile failed`
- `[CFedServerManager::GetProfile] Failed to get profile info from Seshat`

## The fix

### Main patch (from arm64 disassembly)

`UI_DOWNLOADING_PROFILE` has **exactly one emission site** in the whole
binary. In the update loop a shared predicate decides between showing that
spinner and emitting the game's own `UI_FIRST_CHECK` state (“no profile to
download, carry on”):

```
bl   sub_100346c10         ; predicate: "download profile?"
cbz  w0, UI_FIRST_CHECK    ; == 0 -> carry on
...  UI_DOWNLOADING_PROFILE ; != 0 -> infinite spinner (server is dead)
```

The predicate keeps answering “yes” because the online login never completes.
The patch replaces that `bl` with `mov w0, #0`, so the `cbz` is always taken
and the game follows its native offline path.

Four bytes, length preserved, applied **only at that call site** — the shared
predicate itself is called from ~50 other places and is left alone. The patch
self-locates through the single reference to the string, so it does not rely
on hardcoded offsets.

### Local save patch (one instruction)

Every save object carries a byte at `+0x25`: *"persist me to a local
`ud_<Name>.sav` file"*. The manager's constructor sets `+0x24 = 1`
("server-persisted") on all seventeen and `+0x25 = 1` on only **five** of them
— the settings. Everything else, story progress included, travelled inside the
Gameloft profile blob, which is why it evaporates offline.

Those five work perfectly, and device data proves it: `ud_Sound`'s state
carried across a relaunch unchanged. So the fix is not to bypass the seven
branches that read the flag — an earlier build `nop`ed six of them and made
things *worse*, producing objects that were armed but still not local, which
let a good `ud_Tutorial.sav` be overwritten with a regressed one.

The fix is to set the flag. `CSaveMgr::ReloadAll` already walks all seventeen
objects at session start, already holds `1` in `w25`, and already has the
object in `x20`. Its first act on each object is the branch that skips the
non-local ones:

```
0x10021bc78   ldrb w8, [x20, #0x25]
0x10021bc7c   cbz  w8, <next object>   ->   strb w25, [x20, #0x25]
```

Four bytes. From there every object is genuinely local, so all seven original
gates pass on their own — including one in `SaveObj::Save` that no `nop` could
have fixed safely. Twelve objects become byte-for-byte equivalent in treatment
to the five that already work, with **the game's own serialisers on both
ends** — no new save format, no injected code.

The site is located by an 8-byte signature that occurs exactly once in
`__text`; the patcher writes nothing if it is missing or ambiguous, and
`--verify-local-save` re-checks the binary that actually ships. Pass
`--no-local-save` to build without it.

Full reasoning, the save-object layout and the decoded file format:
[LOCAL_SAVE_DESIGN.md](LOCAL_SAVE_DESIGN.md).

### Complementary patches

Dead Gameloft hostnames are rewritten to `.invalid` (RFC 6761: never
resolves), and the jailbreak detection paths and function are neutralised.
Every edit preserves length exactly, so no Mach-O offset shifts.

| Neutralised host | Role |
|---|---|
| livewebapp.gameloft.com | autologin.php |
| eve.gameloft.com | profile services |
| pjsmmm-legacy.gameloft.com | legacy backend |
| ingameads.gameloft.com | ads / iphoneloading.php |
| 201205igp.gameloft.com | IGP / freemium |

## Usage

1. **Actions** tab → *Patch TASM2 IPA* → **Run workflow**
2. The patched IPA is published as a **GitHub Release** under the chosen tag
   (`patched-latest` by default). Download `SpiderMan2_patched.ipa`.
3. Install with LiveContainer / SideStore / Sideloadly.

### Patch before installing, not after

LiveContainer loads apps with `dlopen()` and converts the binary from
`MH_EXECUTE` to `MH_DYLIB` **at install time**. Replacing the binary inside an
already-installed `.app` overwrites that conversion and produces:

```
cannot dlopen a main executable
```

## Local saving

Three earlier attempts failed, and the conclusion drawn from them — that the
code to save progress locally did not exist — was wrong. It does exist: it is
the system that keeps your settings. It was simply gated off for the eleven
objects that Gameloft kept server-side.

| Attempt | Result |
|---|---|
| **v1** — remove the writer's "dirty" gate | Regression: stuck at 45 % on load. The writer flushes `ud_*.sav` **untimed** (only `ud_Spider2.sav` has a 20 s timer), so without the gate it ran every frame → I/O storm. |
| **v2** — set the dirty flag on the event-driven flush | Files appeared for the objects that were already local-capable, but progression still did not come back. |
| **v3** — patch `ldrb [x22,#0x25]` | That is `0x10021a1b4`, the save-all **loop filter** — one gate out of seven. Letting the loop reach `Save` changes nothing while `Save` still routes the blob to the upload queue. No file appeared, and the flag looked innocent. |
| **v4** — three gates `nop`ed | 9 files instead of 6, and the main menu appeared for the first time. But 8 objects stayed silent, and progress did not come back. |
| **v5** — six gates `nop`ed | Made it *worse*: `ud_Tutorial.sav` went from `0x0002073e` (nine steps) to `0x0000003e` (five). Arming an object without making it local means it gets written from a state that was never restored. |
| **v6** — one instruction, in `ReloadAll` | The flag itself is set, so the twelve server objects take the exact path the five settings objects already take. **Verified on device: the save objects are written and restored correctly.** |
| **v7** — `--persist-chapter` | Disproved by measurement: the field persists, but `chapter` is always 0 offline because only profile appliers ever write it. Off by default; do not enable. |

### `ud_Spider2.sav` is dead code

Its writer does:

```
sprintf(buf, "%s/ud_Spider2.sav", docs)   ; buf receives the PATH
fopen(...) ; rand()                        ; random key, never stored
XOR(buf, key ^ index) ; fwrite(buf, 0x7bf) ; that same buf is written out
```

Confirmed against a real 1983-byte file pulled off the device: with the
recovered key (`0xff`), the decrypted content starts with
`/var/mobile/Containers/Data/Application/<UUID>/Documents/…` — the file's own
path — followed by 47 % zeros and leftover stack data. **No game data at
all.** And `%s/ud_Spider2.sav` is referenced exactly once in the entire
binary: by that writer. No reader exists.

### What persists, before and after

The local save system (`ud_<Name>.sav`, writer `0x1002115f0` / reader
`0x1002119ac`) covered only the objects with the local flag set — settings,
essentially. The other eleven rode in the server profile, which is what the
game means by *“Connect online just once to retrieve your last save.”*

The profile deserialiser `ApplyProfile` (`0x10021cef8`) makes that explicit:
it walks the same 17 objects, keyed `ud_<Name>`, and writes each blob into the
**same field** (`+0x60`) the local reader fills. Server profile and local file
were two sources feeding one sink. The patch simply keeps the sink fed from
the local one.

Still server-only: the profile's scalar fields (`chapter`, `finish_ch8`,
`missionCount`, …). See
[LOCAL_SAVE_DESIGN.md](LOCAL_SAVE_DESIGN.md#what-is-not-covered).

## Replacing the server (branch `serveur-gameloft`)

Giving the game a server is the architecturally correct answer, and it was
tested on device. Result: **the HTTP path is a dead end.**

Redirecting works end to end — the phone really did reach a Cloudflare Worker
we controlled. But the only HTTP traffic is the ad WebView
(`sec-fetch-dest: document`, `accept: text/html`, identical payload across
launches). **`autologin.php` is never called**, even with the profile patch
removed so the game attempts a genuine login.

The profile — and therefore saving — goes exclusively through the
**federation server: raw TCP, opcode-based binary protocol** (`_socket`,
`_connect`, `_send`, `_recv` stubs; `port=7744&type=gs`;
`Send federation request, opcode[%d]`).

Two consequences, recorded on that branch:

1. String-length limits are **not** the real obstacle — a DNS rewrite
   (NextDNS, AdGuard, an iOS DNS profile) can point any hostname at an IP of
   your choice without touching the binary.
2. The real obstacle is the **protocol**: framing, handshake, opcodes and
   possible encryption would have to be reconstructed with **no reference
   capture available**, the servers having been dead since ~2018.

Continuing would require **dynamic analysis on the device** (Frida or LLDB,
breakpoints on `send`/`recv` around `CFedServerManager`).

## Binary facts

- FAT `armv7 + arm64`
- `cryptid=0` on both slices → already decrypted, no Apple ID prompt
- SDK iphoneos10.3 / Xcode 8.3, MinimumOSVersion 8.0
- Original SHA1: `b3d322a788bbeeb1a006ba0da23a28300a5b7105`
- Size: 33,375,152 bytes (unchanged after patching)

## Why a Release and not an artifact

The IPA is ~769 MB. Actions artifacts are bounded by the account storage quota
(500 MB on personal accounts), which makes the upload fail. A GitHub Release
accepts files up to 2 GB and does not count against that quota.

## Status

- ✅ **Verified on device** (LiveContainer, iOS): the “Downloading profile”
  hang is gone; the game launches and plays offline.
- 🔬 **Not yet confirmed:** the local save patch. Three device snapshots
  drove it to its current shape — see
  [Device results](LOCAL_SAVE_DESIGN.md#device-results). The save format is
  now fully decoded (`tools/decode_sav.py`), so the next test can be measured
  rather than inferred.

### How to check the local save on device

The same A/B/C protocol that settled the previous question works here, and
one snapshot is enough to tell whether the write half works:

1. Install the patched build, play past a checkpoint, force-quit.
2. Look at the app's `Documents/`. Before this patch there were at most six
   `ud_*.sav` files; **if the write half works, you should now see up to 17**,
   with names you have not seen before.
3. Relaunch and check whether progress is back.

Three outcomes, each diagnostic:

| What you see | What it means |
|---|---|
| ~17 `ud_*.sav` files, progress restored | done |
| ~17 files, progress **not** restored | writes and arming work; the profile scalars are the remaining half — see [what is not covered](LOCAL_SAVE_DESIGN.md#what-is-not-covered) |
| still ~9 files (no `ud_Economy`, `ud_Item`, `ud_FriendList`) | `ReloadAll` still is not arming them; start again at `0x10021bc7c` |

## No-patch alternative

Blocking those domains via DNS (NextDNS, AdGuard, manual DNS) **before the
first launch** produces the same network failure as the host rewrite, without
touching any file and fully reversibly. It does not solve saving.
