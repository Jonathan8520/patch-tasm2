# Local save — how it works, and why it is one instruction

Status: **implemented** in `patch_tasm2.py` (`patch_local_save`), and
partially confirmed on device — see [Device results](#device-results). This
file is the reasoning behind that instruction, and the map of the save
subsystem for anyone who needs to go further.

All addresses are virtual addresses in the arm64 slice, which is linked at
`0x100000000`. The tooling that produced them is in `tools/` (see the bottom
of this file).

## The mistake that cost three attempts

Earlier work concluded that story progress "is simply never serialised
locally" and that saving it would mean **writing** a save system. That was
wrong, and the reason it looked right is worth recording.

The game does have a complete local save system — a per-object writer and a
symmetric reader, with the game's own serialisers on both ends. It is the
system that stores your settings today. What it does **not** do by default is
apply to the objects that hold progression: those are flagged
"server-persisted", and their blobs travelled in the Gameloft profile.

So nothing had to be written. The code was all there; it was gated off for
eleven of the seventeen save objects.

## The save subsystem

The save manager is a singleton at `[0x101074560]`. It owns 17 save objects,
as a plain pointer array:

```
mgr + 0xa40 + 8*i     for i in 0..16      (mgr + 0xa40 is the manager itself)
```

Each save object shares a common base layout:

| Offset | Meaning |
|---|---|
| `+0x1c` | index (0..16); the file name is `ud_<GetConfig("SaveIndex"+i)>.sav` |
| `+0x24` | byte — persisted to the **server** profile (constructor sets it to 1) |
| `+0x25` | byte — persisted to a **local** `ud_<Name>.sav` file (constructor sets it to 0) |
| `+0x28` | byte — reload in progress |
| `+0x29` | byte — state ready, i.e. there is something worth saving |
| `+0x2a` | byte — an incoming payload is waiting at `+0x60` |
| `+0x30` | serialised state **out** (what gets written) |
| `+0x48` | scratch copy |
| `+0x60` | serialised state **in** (what gets applied) |

The functions that matter:

| Address | Role |
|---|---|
| `0x1002115f0` | `WriteFile(obj, std::string* blob)` — `fopen("%s/ud_%s.sav","wb+")` |
| `0x1002119ac` | `ReadFile(obj)` — `fopen(...,"rb")`, falls back to a per-index default at `mgr+0xb60+i*0x30` when the file is missing |
| `0x100212080` | `Load(obj)` — applies `+0x60` to the object |
| `0x100212484` | `Reload(obj, bool runVirtuals)` — reset, then `ReadFile` + `Load` |
| `0x10021254c` | `Save(obj)` — serialise into `+0x30`, then write locally **or** queue for upload |
| `0x10021a158` | `CSaveMgr::Update(mgr)` — the save-all / load-all state machine |
| `0x10021cef8` | `ApplyProfile(int err, rapidjson::Value* doc)` — applies a server profile |

### File format — fully decoded

Four layers, all recovered and confirmed against real files pulled off a
device. `tools/decode_sav.py` implements the whole chain.

1. **File obfuscation** (writer `0x1002115f0`): a 4-byte header equal to
   `length ^ 0x2a`, then the payload **twice** — first XORed byte-wise with
   `(i + 42) % 127`, then that same buffer XORed again with `(7*i) % 23`.
   `ReadFile` consumes only the first copy; the second is dead weight,
   almost certainly a copy-paste slip. Every file is exactly `4 + 2N` bytes,
   which is a free integrity check.

2. **JSON envelope**: `{"b": <base64>, "t": <GMT time>, "v": <format>}`.
   `v` comes from `mgr[index*0x30 + 0xb54]` and is a per-object *format*
   version — it does not move when the same object is written again.

3. **The blob** (decoder `0x100211224` → `0x1002113a8`):
   `[body][origLen][compLen][padLen][unix ts]`, the body padded to a multiple
   of 4 and **XXTEA**-encrypted (delta `0x9e3779b9`, `6 + 52/n` rounds) with a
   128-bit key built entirely from the file's own trailer:

   ```
   key[0] = (ts & 0xff000000) ^ compLen
   key[1] = (ts & 0x00ff0000) ^ compLen
   key[2] = (ts & 0x0000ff00) ^ origLen
   key[3] = (ts & 0x000000ff) ^ origLen
   ```

   No device secret is mixed in unless the object sets its `+0x26` flag, and
   none of the seventeen does.

4. **zlib**: bytes `[0, compLen-4)` inflate to `origLen`, and the four bytes at
   `compLen-4` are a `crc32` of the result. It verifies on every file.

That also explains the header/size ratio first seen on device (header `123`,
payload `246` bytes): one length and two copies, not a 16-bit unit count.

### What the objects actually hold

Decoded from a real post-tutorial container:

| Object | Bytes | Content |
|---|---|---|
| `ud_Tutorial` | 4 | a bitmask of completed tutorial steps — `0x0002073e`, nine bits set |
| `ud_QuestManager` | 8 | a quest bitmask (`0x0003d256`, ten bits) plus a current-quest id of `-1` |
| `ud_InitPos` | 12 | three floats — where Spider-Man was standing |
| `ud_MCSkill` | 12 | `(0, 0, 200)` |
| `ud_Sound` | 34 | two ints, the string `1.3.1e`, five volume floats |
| `ud_Control` | 86 | on-screen button coordinates |
| `ud_Trophy` | 932 | header `(50, 84)` then exactly 84 records of 11 bytes |
| `ud_System` | 183 | flags and a unix timestamp |

This settles the question the whole patch turns on: **story progress really is
written to disk**, in files the unpatched game never reads back.

## What the profile carried

`ApplyProfile` is the clearest statement of what Gameloft kept server-side.
It takes a **rapidjson** value (the engine embeds rapidjson — `document.h`,
`reader.h`, `writer.h` all appear in the binary's assert strings) and applies:

- `userdata` — an object whose members are `ud_<Name>`; each value is written
  straight into that save object's `+0x60`, with `+0x2a = 1`. **This is the
  same field the local reader fills.** The two paths converge exactly.
- `chapter`, `finish_ch8`, `missionCount` (an array of three counters),
  `skill`, `xp`, `inventory`, `coins`, `goods` — scalars applied to a widely
  used manager at `[0x101074a30]` (`+0x2a4`, `+0x2a8`, `+0x2f0..+0x2f8`, …).

The important half is `userdata`: the profile was, for the most part, a
bundle of the very same `ud_` blobs the local files hold.

Note also what `ApplyProfile` does when a member is **absent**: it assigns an
empty string and still sets `+0x2a = 1`. An empty payload is therefore a
supported input, which is what makes the first launch after patching safe.

## The fix: one instruction

`+0x25` is read in seven places inside the save subsystem. An earlier build
neutralised six of them with `nop`. That was the wrong shape of fix, and the
device proved it: bypassing the *readers* while leaving the flag false
produces objects that are "armed" but still not local — a state no part of the
machine expects. See [Device results](#device-results).

The manager's constructor is explicit about the intent. It inlines all
seventeen save objects as subobjects (index 0 is the manager itself, at
version 8 — that is `ud_System`; the next is at `mgr+0x1b8`, then `+0x224`,
`+0x250`, …). For every one of them it sets `+0x24 = 1` ("server-persisted"),
and for exactly **five** it also sets `+0x25 = 1`:

```
0x1002182b4  strb w23, [x19, #0x275]     ; object at +0x250
0x100218330  strb w23, [x19, #0x2ed]     ; object at +0x2c8
0x100218558  strb w23, [x19, #0x4f5]     ; object at +0x4d0
0x100218658  strb w23, [x19, #0x605]     ; object at +0x5e0
0x100218690  strb w23, [x19, #0x659]     ; object at +0x634
```

Those five work perfectly, and the device data proves it: `ud_Sound`'s first
field carried the value 27 unchanged from one session into the next. So the
job is not to route around the flag — it is to **set it**.

`CSaveMgr::ReloadAll` (`0x10021bc3c`) already walks all seventeen objects at
session start, already holds the constant 1 in `w25`, and already has the
object pointer in `x20`. Its first act on each object is the branch that skips
the non-local ones:

```
0x10021bc78   ldrb w8, [x20, #0x25]
0x10021bc7c   cbz  w8, <next object>   ->   strb w25, [x20, #0x25]
```

One instruction. From that point every object is genuinely local, so all seven
original gates pass on their own — including `0x1002126a4` in `SaveObj::Save`,
which selects `+0x30` over `+0x48` as the document to build into and which no
`nop` could have fixed safely. Twelve objects become byte-for-byte equivalent
in treatment to the five that already work.

The eight bytes of `ldrb` + `cbz` are unique in `__text`, so the patch
self-locates, and `--verify-local-save` re-checks the binary that actually
ships.

### Why the flag is set here and not in the constructor

The seventeen constructors are inlined into one 935-instruction function with
constant offsets, so each object's flag store would be a separate site with a
different immediate, and the ones that do not set it have no spare slot to add
a store. `ReloadAll` is the earliest single place that iterates the array, and
it sets the flag before its own `ReadFile`, in the same iteration.

## Device results

Three full container snapshots were taken on device, and they are what settled
the design. All three are decoded by `tools/decode_sav.py`.

**A** — end of the tutorial, **B** — after a relaunch, both on a build that
`nop`ed three gates. Between them, `ud_QuestManager`, `ud_Tutorial`,
`ud_Trophy`, `ud_MCSkill`, `ud_InitPos`, `ud_Control` and
`ud_WorldEnvironment` are **bit-identical**: never read, never rewritten. Only
`ud_Sound` and `ud_System` moved.

**C** — after installing the six-`nop` build. Two things changed, and both
matter:

- `ud_Tutorial` and `ud_MCSkill` were now rewritten, so the patch really did
  take effect and really did arm those objects.
- `ud_Tutorial`'s payload went from `0x0002073e` (nine tutorial steps) to
  `0x0000003e` (five). The value **regressed**: the object started from zero,
  re-accumulated the first five steps as the tutorial was replayed, and
  overwrote a good save.

Arming an object without making it local is therefore actively harmful: the
object gets written, but from a state that was never restored. That is what
motivated replacing six `nop`s with the single store.

Two control results from the same data:

- `ud_Sound`'s first field held 27 in B and still 27 in C — **the local path
  restores correctly** for the objects that own the flag.
- Nothing outside `Documents` holds game state. The preferences plist carries
  only `launchCount` (2 → 3), a StoreKit timestamp and Facebook SDK data; the
  rest of the container is shader and HTTP caches plus the allocator's two
  64 MB backing files.

## What is still missing offline

`RequestLoadAll` (`0x10021bd40`) is what sets `mgr[0xf51]`, which
`CSaveMgr::Update` consumes at `0x10021a8f0` to run `Reload(obj, 1)` over all
seventeen objects — reset, `ReadFile`, `Load`. That is the game's own restore
path, and it is designed to fire **late**, when a profile arrives
asynchronously.

It has exactly five callers, and every one of them is a network path:

| Caller | Context |
|---|---|
| `0x10018dd70` | `[CSnsServerManager] SNS request failed`, `UI_GamecenterLoginFail`, `isNeedReload` |
| `0x1001d0a1c` | `UI_Request_TimeOut`, `isNeedReload` |
| `0x10034d07c` | `UI_Request_TimeOut`, `isNeedReload` |
| `0x1003bb52c` | the connectivity screen, Facebook login/logout |
| `0x100087008` | the social/friend-list manager |

**Offline none of them runs, so the late restore never happens.** Three of the
five are failure handlers — the game was built to fall back to the local copy
when the network fails, which is precisely the case we are in, but the profile
request is skipped entirely by the main patch, so there is no failure to
handle.

Marking the objects local makes `ReloadAll` restore them at session start
instead. Whether that is early enough for every object is the open question
the next device test answers.

## Evidence this path works offline

It is already running. Settings persist across a real force-quit today, and
they persist through exactly these functions: `Save` → `WriteFile` for
`ud_Sound.sav` / `ud_Control.sav`, and `Reload` → `ReadFile` → `Load` on the
next launch. The A/B/C snapshots taken on device showed `ud_Sound.sav`
changing between sessions, which means the save-all loop runs offline, and
showed settings surviving, which means the load-all runs offline too.

The patch does not introduce a new mechanism. It widens a proven one from 6
objects to 17.

## What is not covered

The profile scalars (`chapter`, `finish_ch8`, `missionCount`, …) have no local
file. They are only ever restored by `ApplyProfile`, which needs a document.
Whether that matters depends on something static analysis could not settle
cheaply: whether gameplay recomputes those counters from the restored save
objects, or reads them as the source of truth.

There is one encouraging data point. Every one of the 28 derived save-object
vtables overrides both serialise slots (`+0x18`, `+0x28`) with real code — the
base class implements them as bare `ret`, so an object that did not override
them would write nothing. And three of those overrides reach straight into the
progress manager, e.g.

```
0x100216c10   adrp x8, 0x101074000
              ldr  x0, [x8, #0xa30]      ; the progress manager
              b    0x1001f7054           ; tail-call into it
```

So at least one save object is bound to that manager, and its blob carries
progress state. The scalars the profile carried separately may well be a
summary the game recomputes.

If the device test shows progression coming back but a counter or a chapter
label reading wrong, that block is the culprit, and the fix does not need a
new format — everything needed to call the game's own deserialiser is now
known:

```
ApplyProfile(0, doc)          @ 0x10021cef8   — no callers, free to call
mgr singleton                 @ [0x101074560]
progress manager              @ [0x101074a30]
doc                           rapidjson::Value*, so parseable from a text file
```

An injected dylib (LiveContainer loads tweaks) could build that document from
a JSON file and call it. That route is *not* implemented here, because the
three NOPs cover the save objects and shipping untested injected code would
have been worse than shipping nothing.

## Tooling

`tools/` holds the analysis harness used throughout:

- `machoscan.py` — FAT/Mach-O parsing, `LC_FUNCTION_STARTS` for exact function
  bounds, the indirect symbol table for libc stub names, and an ADRP/ADD index
  giving string and call cross-references.
- `scan.py` — `dis` / `fn` / `str` / `sref` / `xref` / `callers` / `info`.
- `summary.py` — dense per-function overview: strings, calls, struct offsets.

They expect the executable at `/home/user/AmazingSpiderMan2`, overridable with
`TASM2_BIN`. The `Publish binary for analysis` workflow extracts it from the
IPA and publishes it under the `analysis-binary` tag, so the analysis can be
redone without the 769 MB download.
