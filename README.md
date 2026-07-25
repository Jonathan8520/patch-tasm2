# TASM2 offline patch — The Amazing Spider-Man 2 (iOS 1.3.1)

Patches the iOS build of **The Amazing Spider-Man 2 (1.3.1)** so it can be
launched and played after Gameloft shut down its servers.

**Scope, stated up front:** the game launches and plays offline. Story
progress is **not** kept between launches — that is not an oversight, it is a
property of the binary and is documented in
[Local saving](#local-saving-why-it-cannot-be-patched-in).

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

## Local saving: why it cannot be patched in

Three attempts, all disproved by testing on a real device. Summarised so
nobody repeats them:

| Attempt | Result |
|---|---|
| **v1** — remove the writer's "dirty" gate | Regression: stuck at 45 % on load. The writer flushes `ud_*.sav` **untimed** (only `ud_Spider2.sav` has a 20 s timer), so without the gate it ran every frame → I/O storm. The removed branch was also what **re-armed** the `+0xfa9` flag, permanently blocking mark-dirty. |
| **v2** — set the dirty flag on the event-driven flush | Writing worked (file updated on time), but nothing reads the progress back. |
| **v3** — persist all 17 save objects (`ldrb [x22,#0x25]` filter) | No extra file appeared: that flag is not the lock. |

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

### What actually persists

The real local save system (`ud_<Name>.sav`, symmetric reader at
`0x100211a2c` / writer at `0x1002115f0`) only covers **Sound, Control,
InitPos, Economy, Item, FriendList** — settings and inventory. Story progress
is not among them: it lived in the server profile, which the game says itself:
*“Connect online just once to retrieve your last save.”*

Restoring progress would mean **writing** a save system (serialisation and
deserialisation injected into the binary), not unlocking existing code. That
is out of reach of a byte patch.

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

Verified on device (LiveContainer, iOS):

- ✅ the “Downloading profile” hang is gone; the game launches and plays offline
- ❌ story progress is not kept between launches, and this is not a lock to
  bypass — the code to save it locally does not exist in this binary

## No-patch alternative

Blocking those domains via DNS (NextDNS, AdGuard, manual DNS) **before the
first launch** produces the same network failure as the host rewrite, without
touching any file and fully reversibly. It does not solve saving either.
