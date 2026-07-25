# Local save via injected dylib — design notes and go/no-go

Status: **GO on the core idea**, one unknown left (see "Remaining unknown").
Nothing here is implemented yet. These notes exist so the work can be picked
up without redoing the analysis.

## Why a byte patch cannot work, and what changes the game

Controlled A/B/C test on device (fresh install → prologue finished → real
force-quit and relaunch) proved the vanilla game writes only:

| File | Content | Survives relaunch |
|---|---|---|
| `ud_Control.sav` | settings (byte-identical across all three snapshots) | yes |
| `ud_Sound.sav` | settings + a session counter (content genuinely changes) | yes |
| `ud_InitPos.sav` | created after playing | yes, untouched |
| `ud_Spider2.sav` | dead code (stack garbage XORed with `rand()`) | n/a |
| `dateS` / `dateI` | plain-text session timestamps | yes |

Playing the entire prologue created **one** new file (`ud_InitPos.sav`), and
the relaunch wiped nothing. So there is no reset to defeat and no flag to
flip: story progress is simply never serialised locally. It lived in the
server profile.

Conclusion: the only way to get local saving is to **add** code. Two things
make that far more tractable than it first looks.

## Key insight 1 — reuse the game's own serialiser

The game already owns both halves: it built a profile blob to upload, and it
parsed a profile blob to apply. We do not need to understand the progression
layout — only to call those two functions and store the blob in a file.

## Key insight 2 — a dylib, not hand-written ARM64

LiveContainer can load tweaks (dylibs) into the app. So the glue can be plain
C / Objective-C with `fopen`/`fread` and a function hook, instead of assembling
ARM64 into a code cave. A free GitHub Actions macOS runner can build the
arm64 dylib.

## Found so far (arm64 slice, addresses as loaded at 0x100000000)

| What | Address | Notes |
|---|---|---|
| **Profile deserialiser** | `0x10021cef8` | `ApplyProfile(x0 = save manager, x1 = document)`. Reads key `"userdata"` from the document, then walks the save-object array at `+0xa40`, using `"ud_"` and `"SaveIndex"`. |
| Save manager singleton | `[0x101074000 + 0x560]` | Loaded all over the binary; trivial to obtain from a hook. |
| Document accessors | `0x100a77490`, `0x100a76c2c` | has-member / get-member style. |
| Save object array | save manager `+0xa40 .. +0xac0` | 17 slots, each object pointer valid (dereferenced before any flag test). |
| Per-object writer | `0x1002115f0` | `fopen(path,"wb+")`, header = 4-byte count XOR `0x2a`, count is in 16-bit units. |
| Per-object reader | `0x100211a2c` | `fopen(path,"rb")`, same header format. |
| Event-driven "flush save" | `0x100276760` | Calls the writer twice with dt=0; a natural place to hook "save now". |
| Per-frame writer call | `0x10027a60c` | Do **not** hook this one: it runs every frame. |
| JSON reader in engine | `glwebtools::JsonReader` | Referenced by string; a route to build a document from text. |

`0x10021cef8` has **no direct callers** (invoked via vtable/callback), which
means nothing prevents us from calling it ourselves.

## Remaining unknown (the actual go/no-go)

Constructing the `document` argument (x1). Two sub-questions:

1. Which class is it, and can it be built from a JSON/text buffer using the
   engine's own reader?
2. Is there a symmetric **serialiser** that produces that document from the
   save objects? It is likely adjacent to `0x10021cef8` — look for a function
   in `0x10021c000-0x10021e000` that writes the `"userdata"` key rather than
   reading it.

If both answers are yes, the design is:

```
on save  : serialise -> document -> text -> write ud_Profile.json
on launch: read ud_Profile.json -> text -> document -> ApplyProfile(mgr, doc)
```

If the document can only be produced by the network layer, the idea collapses
back to the federation-protocol problem documented in `serveur/README.md`.

## Suggested order of work

1. Find the serialiser (the `"userdata"` writer) next to `0x10021cef8`.
2. Determine the document class and how to build one from text.
3. Write the dylib: hook `0x100276760` (save) and the save-manager init
   (`0x100218078`, load), call the two functions.
4. Build it on a macOS runner, load it with LiveContainer, iterate.

Step 2 is the decision point. Everything before it is analysis; everything
after depends on it.
