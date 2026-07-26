# Local save — how it works, and why it is six NOPs

Status: **implemented** in `patch_tasm2.py` (`patch_local_save`), and
partially confirmed on device — see [Device results](#device-results). This
file is the reasoning behind those six instructions, and the map of the save
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

### File format

`WriteFile` emits: a 4-byte header equal to `length ^ 0x2a`, then the payload
**twice** — first XORed byte-wise with `(i + 42) % 127`, then that same buffer
XORed again with `(7*i) % 23` and written a second time. `ReadFile` reads the
header and only the first copy; the second is dead weight, almost certainly a
copy-paste slip in the original code.

That explains the header/size ratio observed on device (header `123`, payload
`246` bytes): it is one length and two copies, not a 16-bit unit count.

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

## The six gates

`+0x25` is read in seven places inside the save subsystem. Six of them each
block a part of local persistence:

| Site | Function | Effect when `+0x25 == 0` |
|---|---|---|
| `0x10021a1b8` | `CSaveMgr::Update` save-all loop | the object is skipped entirely — `Save` is never called |
| `0x1002127a8` | `SaveObj::Save` | the blob goes to the upload queue instead of `ud_<Name>.sav` |
| `0x10021250c` | `SaveObj::Reload` | `ReadFile` is skipped, so nothing is read back |
| `0x10021bc7c` | `CSaveMgr::ReloadAll` | the object is skipped entirely — never armed, never loaded |
| `0x10021bce0` | `CSaveMgr::ReloadAll` | its `ReadFile` is skipped |
| `0x10021236c` | `SaveObj::Load` self-reload | its `ReadFile` is skipped, after the state has already been cleared — the object is left wiped **and** unarmed |

Replacing each `cbz` with a `nop` routes every object down the path the
surviving settings already use. The flag byte itself is left untouched, so if
a profile ever does arrive the profile path still behaves as designed.

`CSaveMgr::ReloadAll` (`0x10021bc3c`) is the one that decides whether an
object ever becomes usable. For each object it resets the state, calls
`ReadFile`, then `Load`. That is also what makes an object **state-ready**,
which is `SaveObj::Save`'s second condition (`+0x28 == 0 && +0x29 != 0`). An
object ReloadAll skips is never armed, so `Save` returns without writing —
even with the save-all, write and read gates neutralised.

It has two callers, both benign:

- `0x100276da8`, in the session init that loads `Constants.bin` — this is the
  startup load. (The earlier notes called `0x100276760` an "event-driven
  flush"; it is not, it is initialisation.)
- `0x10021a21c`, immediately after the save-all loop — the files it re-reads
  were just written, so it is a no-op in practice.

Its two gates must be patched **together**: the first skips the object, the
second skips only the read. Neutralising the first alone would reset an
object's strings and then not read them back, wiping it.

### The invariant that makes this safe

Three functions reset a save object — `Load`'s self-reload branch, `Reload`
and `ReloadAll`. Each clears `+0x30`, `+0x48` and `+0x60` and sets
`+0x28 = 1`, then reads the file back. Before the sixth gate was patched, the
self-reload branch cleared the state and then, for a server-backed object,
took `0x100212440`, found `+0x24 != 0`, and returned — leaving the object
**wiped and unarmed**. With all six gates neutralised, every reset is followed
by a `ReadFile`; this was checked mechanically against the patched binary, not
by eye.

`Load`'s self-reload tail-calls `Load` again, and that recursion is bounded at
exactly one level in both directions:

- `ReadFile` sets `+0x2a = 1` on *both* of its paths — file read
  (`0x100212020`) and file missing (`0x100211af4`) — and the function has a
  single exit at `0x100212078`, so the re-entry takes the apply branch and
  finishes.
- Even if `+0x2a` were somehow left clear, the re-entry falls straight out at
  `0x100212424`.

There is no path on which it loops.

A seventh site, `0x1002126ac` in `Save`, is deliberately left alone. It picks
`+0x48` rather than `+0x30` as the document to build into while an object
occupies the upload slot (`mgr+0xfa0`, fed from a queue at `mgr+0xf90`). That
is the game's own staging design — the writer promotes `+0x48` into `+0x30`
after each write — so forcing it would clobber a buffer in flight. The cost of
leaving it is at most a one-save lag, on one object at a time.

### How the first launch after patching resolves itself

On the first launch the 8 newly-enabled objects have no file yet. Startup
`ReloadAll` reads nothing, falls back to the per-index default at
`mgr+0xb60+i*0x30`, and — crucially — arms them. From that point every
save-all writes them, and the next launch reads them back. The chicken and
egg resolves in one session, because the startup `ReloadAll` runs before any
gameplay.

### Why this is not the v1 regression

The v1 attempt hung the game at 45 % by removing a *dirty* gate, so the writer
ran every frame. Nothing here touches a dirty gate or a timer. The cadence of
save-all is unchanged — it is still driven by `mgr+0xfa8`; only the number of
objects it processes changes, from 6 to 17.

### Why v3 looked like the flag was not the lock

v3 patched `ldrb w8, [x22, #0x25]` — that is `0x10021a1b4`, the save-all loop
filter, and only that. Letting the loop reach `Save` achieves nothing while
`Save` itself still routes the blob to the upload queue at `0x1002127a8`. No
file appears, and the flag looks innocent. All six gates have to go.

## Device results

The three-gate build was tested on device. It was not enough, but it moved a
long way and it named the missing piece.

Before the patch: at most six `ud_*.sav` files. With three gates, after the
tutorial:

```
ud_System.sav 234   ud_Tutorial.sav 178   ud_InitPos.sav 202
ud_QuestManager.sav 186   ud_Trophy.sav 626   ud_MCSkill.sav 186
ud_Control.sav 250   ud_Sound.sav 218   ud_WorldEnvironment.sav 178
```

Nine files, including `QuestManager`, `Trophy` and `MCSkill` — objects that
had never written anything. They survived a real relaunch untouched (still
stamped 01:44 after a restart at 01:46). And the game showed its **main menu**
for the first time instead of dropping straight into the tutorial, which means
it did detect a save.

But nine files, not seventeen — `Economy`, `Item` and `FriendList` among the
missing, and those three *had* appeared under the old v2 experiment. That is
what pointed at `ReloadAll`: those eight objects were never armed, so
`SaveObj::Save` refused them. The tutorial still restarted, consistent with
the objects that carry mission state never being loaded at startup.

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
