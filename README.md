# TASM2 offline patch — The Amazing Spider-Man 2 (iOS 1.3.1)

Patches the iOS build of **The Amazing Spider-Man 2 (1.3.1)** so it can be
launched and played after Gameloft shut down its servers.

**Scope, stated up front:** the game launches, plays and **saves** offline.
Settings, trophies, exploration, skills, position and the story cursor all
persist across relaunches, and the story advances chapter by chapter without a
server — confirmed on device up to chapter 2. See
[Local saving](#local-saving) and [Status](#status). Every step was measured on
real device data rather than inferred; the save format is fully decoded
(`tools/decode_sav.py`, and `tools/sav-reader.html` to read a save on the
phone itself).

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
`--verify` re-checks the binary that actually ships. Pass `--no-local-save` to
build without it.

### Chapter patch (two instructions)

Restoring the save objects is not enough on its own: the game still relaunched
the prologue every time. The trigger is one 32-bit field, and it is not in any
save object.

```
0x1001fc864   ldr  w8, [progressMgr, #0x2a4]   ; chapter
0x1001fc868   cbnz w8, <normal flow>
0x1001fc988   ... "story01_mission01"          ; the prologue = the tutorial
```

Persisting it was necessary and not sufficient. A device run stored
`(250454, 0)`: the chapter really was written and read back — it was just 0,
because **nothing offline ever produces a chapter**. `0x1001edd54` does not
compute one; it reads it out of the mission-result map, whose only wholesale
writer is `0x1001f129c`, the JSON callback of the *mission finished* HTTP
request. Offline that request never completes, the map stays empty, and
`map["chapter"]` default-inserts 0. The story cursor was server-computed.

So it has to be produced locally, which is a second edit — one instruction:

```
0x1001edd28   ldr w20, [sp, #0x10]  ->  mov w20, #1
```

`w20` is read nowhere between that load and the store, so a completed mission
now sets the chapter to 1 instead of 0. Nothing else offline writes the field,
so it stays 1 — monotone, and never above what the game would unlock first.
Deliberately conservative: incrementing per mission would reach 8 in eight
missions, side missions included, because the mission→chapter mapping lived in
the server's answer.

`ud_QuestManager.sav` persists two ints (`v=3`, confirmed on a real device
file). The second one, `progressMgr+0x2dc`, is the pending-mission id: the
constructor initialises it to `-1`, its only producer resets its source to
`-1` straight after use, and its only consumer reads `-1` as "nothing
pending". Every save stored the constructor default. So the slot now carries
the chapter instead, on both sides:

```
0x1001ff4c8   ldr w1, [x20, #0x2dc]  ->  ldr w1, [x20, #0x2a4]     serialise
0x1001ff594   str w0, [x19, #0x2dc]  ->  str w0, [x19, #0x2a4]     restore
```

Still two ints at version 3 — file format, length and version unchanged, with
the game's own serialiser on both ends. Disable with `--no-persist-chapter`.

> **Delete `Documents/ud_QuestManager.sav` once** before the first launch of a
> build carrying this. A file written by an earlier build holds `-1` in that
> slot, and it would now be read as the chapter.

### Prologue override (two instructions)

The third device run settled the write half: `ud_QuestManager.sav` came back
`(250454, 1)`. The chapter is saved. The prologue still replayed and
`ud_Tutorial.sav` still regressed, so the value is not reaching
`progressMgr+0x2a4` on the way back in.

Restore order is not the explanation. The manager's object array — the one
`ReloadAll` walks in order — is filled at `0x100218d00` from stack spills;
resolving those puts the quest object (which carries the chapter) at
**position 8** and the tutorial object at **position 10**. The chapter is
restored two objects *before* the tutorial reads it, so a working restore
would have spared the bitmask. It did not.

Why it does not land is still open. The behaviour is closed anyway, by taking
the chapter out of both decisions that consult it:

```
0x1001fc868   cbnz w8, +0xc   ->  b +0xc      never re-request the prologue
0x1003cc5f4   cbz  w0, +0x14  ->  nop         never wipe the tutorial bitmask
```

This is an override, not a restoration: a genuinely fresh install now starts
in the open world instead of the prologue. That is the trade — a prologue that
replays forever is the bug, and offline the game has no other way to know it
has already been played. `--no-force-prologue-skip` restores the faithful
behaviour.

Full reasoning, the save-object layout and the decoded file format:
[LOCAL_SAVE_DESIGN.md](LOCAL_SAVE_DESIGN.md).

### Profile save patch (one instruction)

The mission cursor never needed reconstructing. `progressMgr+0x50` is not an
HTTP client in this build — it is a **local mission server**
(`0x100416000..0x100422000`) that reads the bundled `ch0.json … ch8.json` and
synthesises the answers the Gameloft server used to send. Request `0x16` fills
the whole RAM cursor (`progressMgr+0x110`, a
`std::map<std::string,std::vector<int>>` keyed `"mm"`/`"sm"`/`"prm"`/`"rm"`) by
reading `profile["_ca"] == "chN"` and indexing `chapters[N]`; request `0x15`
advances `profile["_ca"]` to `chapterDoc["nc"]` at `0x10041b308`.

That profile is save object 16 — and it is the only object in the binary the
writer refuses to write:

```
0x100211620   ldr  w8, [x19, #0x1c]      ; SaveIndex
0x100211624   cmp  w8, #0x10             ; == 16 ?
0x100211628   b.ne <normal write>
0x100211634   ldr  w8, [saveMgr, #0xfc8]
0x100211638   and  w8, w8, #0xff00ff
0x10021163c   cbz  w8, <exit without writing>   ->   nop
```

`+0xfc8` is *"did this file already exist when the manager was constructed"*
(`0x100218e28` `fopen "rb"`), `+0xfca` is *"the cloud profile was touched"*, set
only on two dead-offline paths. Clean install ⇒ both 0 ⇒ never written ⇒ never
exists. A closed loop, and the reason object 16's `Reset` default of `"ch0"`
(`0x100215b10`) is what the game starts from every single launch.

The read-back side already runs for object 16 unconditionally, so the `nop`
enables no new code path: the file simply starts existing. Disable with
`--no-profile-save`.

> Two consequences worth knowing. A `ud_*.sav` you have never seen appears in
> `Documents` — its name comes from a runtime config lookup, so it cannot be
> derived from the binary. And the whole short-key profile now carries over,
> not just the chapter: if it ever holds a bad value, deleting that one file
> resets it.

**Confirmed on device.** The predicted file appeared: `ud_OObjects.sav`,
914 bytes, `v=2` — matching object 16's declared version — rewritten between
two sessions. The game now drops the player into the open world and the main
menu reads *"Tu as terminé 0 % du chapitre 1"*, the `UI_chapter_progress`
string, which `0x10021deb0` only selects when the chapter is non-zero; before
this patch it always rendered `UI_prologue_progress_2`.

`ud_OObjects.sav` is the one save file `tools/decode_sav.py` cannot read, and
that is by design rather than a bug: object 16's constructor sets the
device-key flag at `0x100215920` (`strb w21,[x19,#0x26]`), so its XXTEA key is
derived from a device secret instead of from the file's own trailer.

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
| **v6** — one instruction, in `ReloadAll` | The flag itself is set, so the twelve server objects take the exact path the five settings objects already take. **Verified on device: the save objects are written and restored correctly.** A fourth snapshot then showed `ud_Tutorial.sav` coming back intact at `0x0002073e` — and the prologue still replaying, which ruled the tutorial bitmask out as the trigger. |
| **v7** — chapter in `ud_QuestManager` | Half of it. The chapter now has a slot, and device data proves it round-trips — but it round-tripped a 0. |
| **v8** — produce the chapter locally | `mov w20, #1` at `0x1001edd28`. The chapter was never computed offline at all; the map it came from is filled only by the *mission finished* HTTP response. One instruction supplies the value the server used to. |
| **v9** — write the chapter as a constant | Measured `(250454, 1)`: the save half is proven. |
| **v10** — override the prologue decision | The chapter is saved and still does not come back. Both readers of it — the launch check and the tutorial deserialiser — stop consulting it. |
| **v11** — neuter `CTutorialMgr::Reset` | Measured: `ud_Tutorial.sav` holds at 132926 across a relaunch instead of falling to 62. The tutorial bitmask persists — and the story mission still restarted, which is what pointed at the real cause. |
| **v12** — let the profile object reach disk | The mission cursor was never missing: the game contains a **local mission server** that computes it from the bundled `chN.json`. Its state is save object 16, the one object the writer is forbidden to write. One `nop` opens the loop. |

Two corrections this table has had to make, both from device data rather than
from reading:

- v7 was once recorded as *disproved by measurement*. It had never been
  tested — the build installed was run #19, whose job log shows only the main
  and local-save patches, so the `0` read back was the pending-mission id.
- The claim that the chapter is produced locally at mission completion was
  also wrong, and this time the measurement disproved it properly:
  `(250454, 0)` after a completed prologue. The map that `0x1001edd54` reads
  is network-fed, and `map["chapter"]` on an empty map inserts 0.

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

`chapter` was the one field that had no sink at all; the chapter patch gives
it one. Still without a local home: `finish_ch8` (`+0x2a8`, endgame only) and
the profile's other scalars, which the local save objects `ud_Economy`,
`ud_Item` and `ud_MCSkill` are expected to cover. See
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

**Story progression works offline.** Measured on device, three snapshots from
one continuous playthrough:

| | after the prologue | ~50 % of chapter 1 | chapter 2 |
|---|---|---|---|
| `ud_OObjects.sav` (the profile) | 914 B | 1042 B | **1074 B** |
| `ud_Tutorial.sav` | 132926 | 153406 | **161790** |
| `ud_MCSkill.sav` | `(0, 0, 200)` | `(0, 0, 200)` | `(0, 0, 110)` — points spent |
| `ud_FogOfWar.sav` | — | 880 B | 880 B |

The profile file grows as the story advances, and the player reached chapter 2
after completing chapter 1 **across several force-quits**. Every earlier
symptom is gone: the prologue does not replay, the tutorial bitmask holds, and
the menu reads *"chapitre 2"*.

- ✅ the “Downloading profile” hang (LiveContainer, iOS)
- ✅ the local save patch — all 17 objects written and read back
- ✅ the tutorial bitmask — holds across relaunches
- ✅ the profile save patch — the mission cursor persists and the chapter
  advances on its own

### One redundancy, deliberately left alone

`ud_QuestManager.sav`'s second int is pinned to the constant 1 by the chapter
patch, so `progressMgr+0x2a4` is always restored as 1 — while the *real*
chapter now lives in `profile["_ca"]` and reached `"ch2"`. The pin is
therefore redundant, and reverting `0x1001ff4c8` to `ldr w1,[x20,#0x2a4]`
would make the file carry the true value. It has not been changed: the build
above is the one that was measured working through chapter 2, and there is no
observed problem to fix.

## No-patch alternative

Blocking those domains via DNS (NextDNS, AdGuard, manual DNS) **before the
first launch** produces the same network failure as the host rewrite, without
touching any file and fully reversibly. It does not solve saving.
