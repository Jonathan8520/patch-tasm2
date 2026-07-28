# Local save — the reasoning, and everything that was tried

Status: **done and confirmed on device.** This file is the map of the save
subsystem and the record of how the eight shipped edits were arrived at,
including the false trails, because they are the expensive part.

All addresses are virtual addresses in the arm64 slice, linked at
`0x100000000`. The tooling that produced them is in `tools/` (see the bottom
of this file).

## The twelve attempts

Each row was a real build installed on a real device. The measurements are
what moved the design; the reasoning between them was wrong twice.

| Attempt | Result |
|---|---|
| **v1** — remove the writer's "dirty" gate | Regression: stuck at 45 % on load. The writer flushes `ud_*.sav` untimed, so without the gate it ran every frame → I/O storm. |
| **v2** — set the dirty flag on the event-driven flush | Files appeared for the objects that were already local-capable, but progression still did not come back. |
| **v3** — patch `ldrb [x22,#0x25]` | That is `0x10021a1b4`, the save-all loop filter — one gate out of seven. Letting the loop reach `Save` changes nothing while `Save` still routes the blob to the upload queue. |
| **v4** — three gates `nop`ed | 9 files instead of 6, and the main menu appeared for the first time. Eight objects stayed silent. |
| **v5** — six gates `nop`ed | Made it *worse*: `ud_Tutorial.sav` went from `0x0002073e` (nine steps) to `0x0000003e` (five). Arming an object without making it local means it gets written from a state that was never restored. |
| **v6** — one instruction, in `ReloadAll` | Set the flag instead of bypassing its readers. **Verified: the save objects are written and restored correctly.** A later snapshot showed `ud_Tutorial.sav` returning intact and the prologue still replaying, which ruled the tutorial bitmask out as the trigger. |
| **v7** — chapter in `ud_QuestManager` | The chapter gets a slot and round-trips — but it round-tripped a 0. |
| **v8** — produce the chapter locally | `mov w20,#1` at `0x1001edd28`. The chapter was never computed offline at all: the map it comes from is filled only by the *mission finished* HTTP response. |
| **v9** — write the chapter as a constant | Measured `(250454, 1)`. The save half is proven; the value still did not come back into RAM. |
| **v10** — override the prologue decision | Removed the `story01_mission01` request outright. It only skipped the opening cinematic — the tutorial still ran, which proved the tutorial is not that level. **Later reverted**, see below. |
| **v11** — neuter `CTutorialMgr::Reset` | `ud_Tutorial.sav` holds at 132926 across a relaunch instead of falling to 62. The bitmask persists — and the story mission still restarted, which is what finally pointed at the real cause. |
| **v12** — let the profile object reach disk | The mission cursor was never missing. The game contains a local mission server that computes it from the bundled `chN.json`; its state is save object 16, the one object the writer is forbidden to write. One `nop` opens the loop. **This is the fix.** |

v10 was reverted once v12 landed: it was a stopgap, it cost the game its
opening cinematic, and with the chapter persisting it is unnecessary.

### The two conclusions device data had to overturn

- **"`--persist-chapter` is disproved."** It had never been tested. The build
  installed was run #19, whose job log lists only the main and local-save
  patches, so the `0` read back was the pending-mission id, not a chapter.
  Never trust a measurement without checking which binary produced it.
- **"The chapter is produced locally at mission completion."** Also wrong, and
  this time the measurement disproved it properly: `(250454, 0)` after a
  completed prologue. The map `0x1001edd54` reads is network-fed, and
  `map["chapter"]` on an empty map inserts 0.

Both errors came from sweeps that were not sound. See
[Tooling](#tooling).

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

   No device secret is mixed in unless the object sets its `+0x26` flag.
   Exactly one of the seventeen does: object 16, the profile document, whose
   constructor sets it at `0x100215920`. That is why `ud_OObjects.sav` is the
   one file `decode_sav.py` cannot read — by design, not by bug.

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
self-locates, and `--verify` re-checks the binary that actually ships (both
this patch and the chapter one).

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

## The real blocker: `chapter`

A fourth device snapshot settled it. A known-good `Documents` was restored
into a fresh container and the game relaunched. **Seven of the nine
`ud_*.sav` came back bit-identical**, and `ud_MCSkill` and `ud_System` were
rewritten with identical content — read, applied, re-serialised. The save
objects restore correctly. Nothing was destroyed.

The tutorial still replayed, and the reason is a single 32-bit field.

### The launch decision

`chapter` lives at `progressMgr+0x2a4` (the manager at `[0x101074a30]`), and
`0x1001fc844` reads it to decide what to do at start:

```
0x1001fc860   x8 = *(0x101074a30)
0x1001fc864   w8 = x8->[0x2a4]              ; chapter
0x1001fc868   cbnz w8, 0x1001fc874          ; non-zero -> normal flow
0x1001fc86c   w8 = x8->[0x1bd]              ; "prologue already left" (runtime only)
0x1001fc870   cbz  w8, 0x1001fc95c
   ...
0x1001fc988   "story01_mission01"           ; the prologue -- i.e. the tutorial
0x1001fc9a0   bl <request level>
```

**`chapter == 0` is the trigger.** Not the tutorial bitmask: the fourth
snapshot has `ud_Tutorial.sav` restored intact at `0x0002073e` and the
prologue still launches. The two flags at `+0x1bd` / `+0x1bf` are runtime
state on the game-mode object, reset every launch.

That `chapter` is the story cursor, and that 0 means the prologue, is
confirmed three independent ways:

| Where | What it shows |
|---|---|
| `0x1001f2ac0` | bounds `chapter - 1` to `0..7` → `chapter ∈ {0, 1..8}` |
| `0x10021deb0` | `chapter == 0` → `UI_prologue_progress_2`, else `UI_chapter_progress` |
| `0x100215afc` | the profile mirrors it as `_ca = "ch<N>"` |

### It is never produced offline

This file said twice that the chapter is produced locally at mission
completion. Device data disproved it: a completed prologue on the v7 build
stored `(250454, 0)`.

The complete writer set, from a sweep that matches a store's **byte range**
against the field rather than its immediate against the offset — the
distinction matters, see [Tooling](#tooling):

| Writer | What it is |
|---|---|
| `0x1001f68ec` | the constructor, an 8-byte `str d1,[x9]` with `x9 = progressMgr+0x2a4`, writing 0 |
| `0x1001edd54` | mission completion — but see below |
| `0x1001ff530` | the legacy `v0`/`v1` deserialise branch (nothing writes such a stream) |
| `0x10021bf84` | the in-`Update` profile applier — behind `HasMember("_ca")` |
| `0x10021d134` | `ApplyProfile` — behind `HasMember("_ca")` |

Both appliers are guarded, and offline the document they are handed is built
from `mgr[0xa28]`, an empty `std::map`, so neither fires. The
`chapter >= 8 ? 0 : chapter + 1` at `0x1001f25d8` is never stored back — it
feeds the `BossComing` HUD banner.

That leaves `0x1001edd54`, and it does not compute a chapter either. It reads
one out of the mission-result map at `missionObj+0x320`, and that map has
exactly one wholesale writer: `0x1001f129c`, reached only from `0x1001f7dd8`,
the JSON response callback registered for the *mission finished* HTTP request.
Offline the request never completes, the map stays empty, and
`map["chapter"]` default-inserts 0 (`str wzr,[x24,#0x38]` at `0x1001ed694`)
which goes straight into the field. `+0x2d8` — the respawn node id — is
written by the same event three instructions earlier, which is why the device
file reads `(250454, 0)`: a real local id beside a fabricated 0.

**The story cursor was server-computed.** Persisting it was necessary; it was
never going to be sufficient.

### One field, three symptoms

`chapter == 0` does not only replay the prologue:

| Symptom | Mechanism |
|---|---|
| the prologue relaunches every session | `0x1001fc844` requests `story01_mission01` |
| the tutorial bitmask regresses | the tutorial deserialiser `0x1003cc5d0` calls `0x1001f9388` (`chapter != 0`) and does `str wzr,[x19,#4]` when it is 0 — it throws the saved value away |
| chapter-gated content stays locked | every reader of `+0x2a4` |

The `132926 → 54` regression on device was therefore a *consequence*, not a
second bug: the file was restored correctly and then wiped by the game.

### Producing it locally — one instruction

```
0x1001edd28   ldr w20, [sp, #0x10]   ->   mov w20, #1
...           w20 untouched
0x1001edd54   str w20, [progressMgr, #0x2a4]
```

`w20` is read nowhere between the two, and the eight bytes of the load plus
its neighbouring `adrp` occur exactly once in `__text`. A completed mission
now sets the chapter to 1; nothing else offline writes the field, so it stays
1 — monotone and never regressing.

### And the serialiser writes the constant, not the field

A second device run, on the build carrying the edit above, still produced
`(250454, 0)`. Two readings survive that measurement, and the save files alone
cannot separate them:

1. the binary under test did not carry the edit (an install that kept the old
   executable would look exactly like this — the two runs are byte-identical
   in every decoded field);
2. the object was flushed at a moment when the chapter was still 0.

Reading 2 is not obviously available: `+0x2d8` and `+0x2a4` are written three
instructions apart, `+0x2d8` from inside the callee at `0x1001edd48` and
`+0x2a4` right after it returns, with no call between them, so no flush can
land in the gap. If the `250454` in the file was produced by that event, the
chapter beside it is whatever `w20` held. It can only be reading 2 if the
`250454` came from restoring an earlier file instead.

Rather than spend another device run separating them, the serialiser stops
reading the field:

```
0x1001ff4c8   ldr w1, [x20, #0x2a4]   ->   mov w1, #1
```

Offline the chapter is only ever 0 or 1, so a constant 1 *is* `max(chapter, 1)`
— and unlike a read it cannot lose a race with the flush. The saved file then
reports chapter 1 from its first write onward, whatever the ordering, which
makes the next measurement decisive: `(n, 1)` means the build is running and
the mechanism holds; `(n, 0)` can then only mean the executable under test is
not this one.

The cost is that the local save can no longer carry a chapter above 1. Nothing
offline produces one, so nothing is lost today; it is the first thing to undo
if a real chapter advance is ever built.

Conservative on purpose. `min(chapter + 1, 8)` per completed mission would
reach the last chapter in eight missions, side missions included, because
which mission belongs to which chapter lived in the server's answer and in the
data paks it indexed. Setting 1 cannot unlock content out of order. If the
story turns out to be gated beyond chapter 1, that needs a code cave rather
than an in-place edit — the dead `ud_Spider2.sav` writer is one, and
`0x1001edd54` already holds the progress manager in `x0`, so a `bl` fits in
the slot the `str` occupies.

### The fix: give it the slot that was already wasted

`ud_QuestManager` persists exactly two ints, through a helper pair called from
nowhere else in the binary:

```
0x1001ff4a8  serialise    writes progressMgr+0x2d8, then +0x2dc
0x1001ff4dc  deserialise  version 3 reads them straight back
```

and the device file agrees: `v=3`, 8-byte payload, `(250454, -1)`.

**The second slot is worth nothing.** `+0x2dc` is the pending-mission id:

- the constructor initialises it to `-1` (`0x1001f6910`: `mov x11, #-1` →
  `str x11, [x19+0x2dc]`, covering `+0x2dc` and `+0x2e0`);
- its only producer, `0x10020a1dc`, copies it out of `[x19+0x3c4]` and
  immediately resets that source to `-1`;
- its only consumer, `0x1001f96e8`, treats `-1` as "nothing pending".

So every save stored the constructor default, and *not* restoring it leaves it
at exactly the value it was being restored to. Two 4-byte edits hand the slot
to the chapter, on both sides:

```
0x1001ff4c8   ldr w1, [x20, #0x2dc]  ->  ldr w1, [x20, #0x2a4]
0x1001ff594   str w0, [x19, #0x2dc]  ->  str w0, [x19, #0x2a4]
```

Still two ints, still version 3: the file format, its length and its version
byte are all unchanged, and the game's own serialiser sits on both ends.

`ReloadAll` reaches the restore: at `0x10021bcdc` it re-tests `+0x25` — which
the local-save patch has just set — then calls `ReadFile` (`0x1002119ac`) and
`Load` (`0x100212080`), which dispatches to this object's `Restore`. The
progress manager is already constructed at that point; the unpatched restore
path already dereferences it to write `+0x2d8`, and does so on device without
crashing.

**One-time caveat.** A `ud_QuestManager.sav` written by an earlier build holds
`-1` in that slot, and after the patch it would be read as `chapter = -1`.
Delete that one file before the first launch of a build carrying this patch;
everything else in `Documents` can stay.

#### Why the earlier "disproof" was not one

This file previously recorded `--persist-chapter` as *tried, measured and
wrong*, on the strength of a device run that produced `(250454, 0)`. That run
never carried the patch. The job log for workflow run #19 — the build that was
installed — lists only

```
>>> LOCAL SAVE patched: every save object is now marked locally-persisted
>>> MAIN PATCH applied: skip UI_DOWNLOADING_PROFILE -> UI_FIRST_CHECK
```

with no chapter lines: the flag was opt-in and was not passed. The `0` in that
file was `+0x2dc`, not a chapter. The conclusion drawn from it —
that story progression was server-authoritative — does not follow, and
`0x1001edd54` shows it is false.

### A quirk worth recording

The tutorial object's deserialiser reads three of its four bytes when the
stored version is 0:

```
0x100216cc4   cmp w9, #1
0x100216cc8   b.lt <skip>          ; version 0 -> the fourth byte is not read
```

while its serialiser always writes four. `ud_Tutorial.sav` carries `v = 0`, so
its fourth byte never round-trips. It happened to be zero in every sample.

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

## The local mission server — and the lock on its state

`progressMgr+0x50` is not an HTTP client in this build. It is a local mission
server at `0x100416000..0x100422000` that reads the bundled
`ch0.json … ch8.json` and synthesises the answers Gameloft's server used to
send:

| Request | What it does, offline |
|---|---|
| `0x16` | reads `profile["_ca"] == "chN"`, indexes `chapters[N]` (`0x100417cb4`–`0x100417cf4`) and fills `progressMgr+0x110`, the `map<string,vector<int>>` keyed `"mm"`/`"sm"`/`"prm"`/`"rm"` that is the story cursor |
| `0x15` | advances `profile["_ca"]` to `chapterDoc["nc"]` at `0x10041b308` |

So the cursor never needed reconstructing. Its state is save object 16
(`mgr+0x970`, SaveIndex 16, version 2, ctor `0x1002157bc`) — the profile
document — and object 16 is the only one of the seventeen that the writer
refuses to write:

```
0x100211620   ldr  w8, [x19, #0x1c]      ; SaveIndex
0x100211624   cmp  w8, #0x10
0x100211628   b.ne <normal write>
0x100211634   ldr  w8, [saveMgr, #0xfc8]
0x100211638   and  w8, w8, #0xff00ff
0x10021163c   cbz  w8, <exit without writing>
```

`+0xfc8` is set at construction only if the file already exists
(`0x100218e28` `fopen "rb"` → `0x100218e34` / `0x100218e40`); `+0xfca` is set
only at `0x10021d878` and `0x10021da18`, both cloud paths. Clean install ⇒
both zero ⇒ never written ⇒ never exists. A closed loop, and the reason object
16's `Reset` default chapter `"ch0"` (`0x100215b10`) was what the game started
from every launch.

One `nop` at `0x10021163c` opens it. The read-back side already ran for object
16 unconditionally, so no new code path is enabled.

**Device result:** `ud_OObjects.sav` appeared (914 bytes, `v=2`), the player is
dropped into the open world, and the menu shows `UI_chapter_progress`
("chapitre 1") instead of `UI_prologue_progress_2`. That string switch is
`0x10021deb0`, which selects the chapter variant only when the chapter is
non-zero.

`ud_OObjects.sav` is the one file `tools/decode_sav.py` cannot read: object
16's constructor sets the device-key flag at `0x100215920`
(`strb w21,[x19,#0x26]`), so its XXTEA key comes from a device secret rather
than from the file's own trailer.

## What is not covered

`chapter` now has a home. The other profile scalars still do not:

| Field | Where it is | Consequence offline |
|---|---|---|
| `finish_ch8` (`+0x2a8`) | written by four gameplay paths (`0x1001f7448`, `0x1001f8738`, `0x1003c4758`, `0x1003c52e0`), read at `0x100333398` | endgame flag resets; only matters past chapter 8 |
| `missionCount`, `xp`, `coins`, `inventory`, skills | mirrored in the profile, but the save objects `ud_Economy`, `ud_Item`, `ud_MCSkill` carry them too — and those are local now | expected to survive; unconfirmed on device |

There is no room for a second scalar in `ud_QuestManager`: its serialiser is
thirteen instructions with no padding after it, so adding a third `WriteInt`
would need a code cave and relocated calls. If a device test shows a specific
counter reading wrong, that is the point at which it becomes worth doing.

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
- `decode_sav.py` / `encode_sav.py` — the save format, both directions.
- `sav-reader.html` — the same decoder as a self-contained page, so a save can
  be read on the device instead of shipping a container snapshot back.

Field sweeps get their own layer, because the naive one is not sound. Matching
`str Wt,[Xn,#imm]` misses a field that is written by a wider store at a lower
offset — that is how the progress manager's constructor
(`str d1,[x9]`, `x9 = progressMgr+0x2a4`) escaped the first pass:

- `st.py` — decodes every AArch64 load/store form: scaled immediate, unscaled
  `STUR`, pre/post-index with writeback, register offset, `STP` pairs, SIMD
  structures, exclusives and atomics, reporting the base register, the byte
  offset and the **width**. A field sweep asks "does this store's byte range
  cover my field", not "is its immediate equal to my offset".
- `sweep2.py`, `sweep2d8.py` — linear sweeps over `__text` for a byte range,
  with per-function reset so register state never leaks across a boundary.
- `thisclose.py`, `closure2.py`, `closure3.py` — symbolic tracking of a base
  register (`this`, or a global loaded from a fixed address) through a
  function, including writeback forms, so a store can be attributed to an
  object rather than to a register number.

They expect the executable at `/home/user/AmazingSpiderMan2`, overridable with
`TASM2_BIN`. The `Publish binary for analysis` workflow extracts it from the
IPA and publishes it under the `analysis-binary` tag, so the analysis can be
redone without the 769 MB download.
