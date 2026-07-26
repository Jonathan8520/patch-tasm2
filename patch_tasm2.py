#!/usr/bin/env python3
"""
Patch TASM2 (1.3.1): unblocks the infinite "Downloading profile" spinner
(UI_DOWNLOADING_PROFILE) so the game can be launched and played offline.

Main patch (derived from arm64 disassembly, not from guesswork): neutralises
the "do we need to download the profile?" decision at the single call site
that leads to the spinner, routing the game to its own native UI_FIRST_CHECK
state ("no profile to download") instead.

Local save patch: one `cbz` in CSaveMgr::ReloadAll becomes a store that marks
every save object locally-persisted, so all 17 use the same local file path
the five settings objects already use. See
LOCAL_SAVE_DESIGN.md. Disable with --no-local-save.

Complementary patches: dead Gameloft hosts rewritten to .invalid, jailbreak
detection paths and function neutralised. Every edit preserves string and
instruction lengths exactly, so no Mach-O offset is ever shifted.
"""
import re
import struct
import sys
import hashlib

EXPECTED_SHA1 = "b3d322a788bbeeb1a006ba0da23a28300a5b7105"
EXPECTED_SIZE = 33375152

HOSTS = [
    b"livewebapp.gameloft.com",     # autologin.php - main blocker
    b"ingameads.gameloft.com",      # ads / iphoneloading.php
    b"201205igp.gameloft.com",      # IGP / freemium
    b"pjsmmm-legacy.gameloft.com",  # legacy backend
    b"eve.gameloft.com",            # profile services
]

# Jailbreak detection paths (obfuscated in the binary).
JB_PATHS = [
    b"/Ljbrbrz/MpbjlfSvbstrbtf/MobileSubstrate.dylib",
    b"/Applications/Czdjb.bpp",
    b"/var/lib/czdjb",
    b"/var/tmp/czdjb.log",
    b"/ftc/bpt",
    b"/var/lib/apt",
]


def macho_info(data):
    """Return the list of FAT slices as (label, offset, size, filetype)."""
    out = []
    magic = struct.unpack(">I", data[:4])[0]
    if magic != 0xCAFEBABE:
        return out
    n = struct.unpack(">I", data[4:8])[0]
    for i in range(n):
        cpu, sub, off, size, align = struct.unpack(">iiIII", data[8 + i * 20:28 + i * 20])
        label = {12: "armv7", 16777228: "arm64"}.get(cpu, f"cpu{cpu}")
        ft = struct.unpack("<I", data[off + 12:off + 16])[0]
        out.append((label, off, size, ft))
    return out


def arm64_slice_off(data):
    """Offset (within the FAT binary) of the arm64 slice, or None."""
    for label, off, size, ft in macho_info(data):
        if label == "arm64":
            return off, size
    return None, None


def arm64_sections(data, base):
    """Return {section_name: (vmaddr, file_offset, size)} for the arm64 slice."""
    out = {}
    ncmds = struct.unpack("<I", data[base + 16:base + 20])[0]
    p = base + 32
    for _ in range(ncmds):
        cmd, csize = struct.unpack("<II", data[p:p + 8])
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack("<I", data[p + 64:p + 68])[0]
            q = p + 72
            for _s in range(nsects):
                sectname = data[q:q + 16].split(b"\x00")[0].decode()
                addr, size = struct.unpack("<QQ", data[q + 32:q + 48])
                offset = struct.unpack("<I", data[q + 48:q + 52])[0]
                out[sectname] = (addr, base + offset, size)
                q += 80
        p += csize
    return out


def patch_profile_skip(m):
    """
    Main patch. Just before displaying UI_DOWNLOADING_PROFILE, the update loop
    calls a shared predicate ("do we need to download the profile?"). We replace
    that `bl` with `mov w0, #0`, so the following `cbz w0` is always taken and
    the game emits UI_FIRST_CHECK instead (its native "nothing to download"
    path) and carries on.

    Only this one call site is touched; the shared predicate itself is called
    from ~50 other places and is left untouched.

    Self-locating through the single reference to the UI_DOWNLOADING_PROFILE
    string, hence robust. Returns (ok, file_offset) or (False, None).
    """
    base, size = arm64_slice_off(m)
    if base is None:
        return False, None
    sects = arm64_sections(m, base)
    if "__cstring" not in sects or "__text" not in sects:
        return False, None
    cs_addr, cs_off, cs_size = sects["__cstring"]
    tx_addr, tx_off, tx_size = sects["__text"]

    # 1) virtual address of the string
    blob = m[cs_off:cs_off + cs_size]
    i = blob.find(b"UI_DOWNLOADING_PROFILE\x00")
    if i < 0 or (i != 0 and blob[i - 1] != 0):
        return False, None
    sva = cs_addr + i

    # 2) scan __text for the ADRP+ADD pair that forms that address
    text = m[tx_off:tx_off + tx_size]
    n = tx_size // 4
    insns = struct.unpack_from("<%dI" % n, text, 0)
    regpage = {}
    add_addr = None
    for k in range(n):
        insn = insns[k]
        pc = tx_addr + k * 4
        if (insn & 0x9F000000) == 0x90000000:  # ADRP
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7FFFF
            imm = (immhi << 2 | immlo)
            if imm & (1 << 20):
                imm -= (1 << 21)
            regpage[insn & 0x1F] = (pc & ~0xFFF) + (imm << 12)
        elif (insn & 0xFF000000) == 0x91000000:  # ADD immediate
            rn = (insn >> 5) & 0x1F
            if rn in regpage:
                imm = (insn >> 10) & 0xFFF
                if (insn >> 22) & 1:
                    imm <<= 12
                if regpage[rn] + imm == sva:
                    add_addr = pc
                    break
    if add_addr is None:
        return False, None

    # 3) the predicate `bl` sits 0x24 before that ADD; make sure it is a BL
    call_pc = add_addr - 0x24
    call_off = tx_off + (call_pc - tx_addr)
    old = struct.unpack("<I", m[call_off:call_off + 4])[0]
    if (old & 0xFC000000) != 0x94000000:  # not a BL -> write nothing
        return False, None

    # 4) mov w0, #0
    m[call_off:call_off + 4] = struct.pack("<I", 0x52800000)
    return True, call_off


# --- local save -------------------------------------------------------------
#
# Every save object carries a byte at +0x25: "persist me to a local
# ud_<Name>.sav file". The manager's constructor sets +0x24 = 1
# ("server-persisted") on all seventeen and +0x25 = 1 on only five of them --
# the settings. Everything else, story progress included, travelled inside the
# Gameloft profile blob, which is why it evaporates offline.
#
# The five that have the flag work perfectly: their files are written, read
# back and applied on every launch. So the fix is not to bypass the seven
# branches that read the flag -- an earlier build did that, and produced
# objects that were "armed" but still not local, a state the rest of the
# machine never expects; on device it let a path overwrite a good
# ud_Tutorial.sav with a regressed one.
#
# The faithful fix is to set the flag itself. CSaveMgr::ReloadAll already
# walks all seventeen objects at session start, and already holds the constant
# 1 in w25 (set at 0x10021bc64) with the object pointer in x20. Its first
# instruction after loading the object is the very branch that skips
# non-local objects:
#
#     0x10021bc78   ldrb w8, [x20, #0x25]
#     0x10021bc7c   cbz  w8, <next object>      ->  strb w25, [x20, #0x25]
#
# Replacing that one branch with the store makes every object genuinely local
# from session start onwards, so all seven original gates then pass on their
# own -- including the one in SaveObj::Save at 0x1002126a4 that no NOP could
# have fixed safely. Twelve objects become byte-for-byte equivalent in
# treatment to the five that already work.
#
# The eight bytes of `ldrb` + `cbz` are unique in the whole __text section, so
# the patch self-locates.

LOCAL_SAVE_SITE = ("mark every save object local (CSaveMgr::ReloadAll)",
                   bytes.fromhex("88964039a8040034"))
# strb w25, [x20, #0x25]  -- w25 is 1 throughout the loop, x20 is the object
LOCAL_SAVE_STORE = struct.pack("<I", 0x39009699)


def patch_local_save(m):
    """
    Turn ReloadAll's "skip non-local objects" branch into a store that marks
    them local.

    Returns (sites, error): `sites` is a list of (label, file_offset), `error`
    is None on success or a message when the site could not be located
    unambiguously, in which case nothing is written.
    """
    base, size = arm64_slice_off(m)
    if base is None:
        return [], "no arm64 slice"
    sects = arm64_sections(m, base)
    if "__text" not in sects:
        return [], "no __text section"
    tx_addr, tx_off, tx_size = sects["__text"]
    text = bytes(m[tx_off:tx_off + tx_size])

    label, sig = LOCAL_SAVE_SITE
    hits, i = [], 0
    while True:
        i = text.find(sig, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
    if len(hits) != 1:
        return [], f"{label}: expected 1 match, found {len(hits)}"

    off = tx_off + hits[0] + 4
    if (struct.unpack("<I", m[off:off + 4])[0] & 0xFF000000) != 0x34000000:
        return [], f"{label}: second instruction is not a CBZ"
    m[off:off + 4] = LOCAL_SAVE_STORE
    return [(label, off)], None


def verify_local_save(data):
    """
    Check an already-patched binary: the original branch must be gone and the
    store must be present exactly once. Run against the binary that actually
    ships, after it has been copied back into the bundle and rezipped.
    """
    base, size = arm64_slice_off(data)
    if base is None:
        return ["no arm64 slice"]
    sects = arm64_sections(data, base)
    tx_addr, tx_off, tx_size = sects["__text"]
    text = bytes(data[tx_off:tx_off + tx_size])
    label, sig = LOCAL_SAVE_SITE
    problems = []
    if sig in text:
        problems.append(f"{label}: original cbz still present")
    n = text.count(sig[:4] + LOCAL_SAVE_STORE)
    if n != 1:
        problems.append(f"{label}: expected 1 patched site, found {n}")
    return problems


def patch(data, local_save=True):
    m = bytearray(data)
    patches = []
    pat = re.compile(rb"[\x20-\x7e]{6,130}")
    for mt in pat.finditer(bytes(m)):
        s = mt.group()
        off = mt.start()
        if b"gameloft.com" not in s:
            continue
        # skip build paths and placeholders
        if b"/Users/gameloft" in s or b"<your_gl" in s:
            continue
        new = s
        for host in HOSTS:
            if host in new:
                base = b".invalid"
                pad = b"x" * (len(host) - len(base))
                new = new.replace(host, pad + base)
        if new != s:
            if len(new) != len(s):
                raise RuntimeError(f"length changed: {len(s)} -> {len(new)}")
            patches.append((off, s, new))
    for off, s, new in patches:
        m[off:off + len(s)] = new

    # --- jailbreak detection paths ---
    jb = []
    for p in JB_PATHS:
        i = 0
        while True:
            i = bytes(m).find(p, i)
            if i < 0:
                break
            repl = b"/zz" + b"z" * (len(p) - 3)
            if len(repl) != len(p):
                raise RuntimeError("jailbreak path length changed")
            m[i:i + len(p)] = repl
            jb.append((i, p))
            i += 1

    # --- jailbreak detection function (arm64) ---
    JB_FUNC_FILEOFF = 19016508
    JB_FUNC_ORIG = bytes.fromhex("ff0303d1f44f0aa9")
    JB_FUNC_PATCH = struct.pack("<II", 0x52800000, 0xD65F03C0)  # mov w0,#0 ; ret
    fn_ok = False
    if m[JB_FUNC_FILEOFF:JB_FUNC_FILEOFF + 8] == JB_FUNC_ORIG:
        m[JB_FUNC_FILEOFF:JB_FUNC_FILEOFF + 8] = JB_FUNC_PATCH
        fn_ok = True

    # --- MAIN PATCH: skip the profile download ---
    skip_ok, skip_off = patch_profile_skip(m)

    # --- LOCAL SAVE: persist every save object to ud_<Name>.sav ---
    ls_sites, ls_err = patch_local_save(m) if local_save else ([], None)

    return bytes(m), patches, jb, fn_ok, skip_ok, skip_off, ls_sites, ls_err


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}

    if "--verify-local-save" in flags:
        if len(args) != 1:
            print("usage: patch_tasm2.py --verify-local-save <patched_binary>")
            return 1
        problems = verify_local_save(open(args[0], "rb").read())
        for p in problems:
            print(f"FAIL: {p}")
        if problems:
            return 1
        print(f"local save verified: {LOCAL_SAVE_SITE[0]} in {args[0]}")
        return 0

    if len(args) != 2:
        print("usage: patch_tasm2.py [--no-local-save] <input_binary> <output_binary>")
        print("       patch_tasm2.py --verify-local-save <patched_binary>")
        return 1
    local_save = "--no-local-save" not in flags

    data = open(args[0], "rb").read()

    print(f"size : {len(data)} bytes")
    sha1 = hashlib.sha1(data).hexdigest()
    print(f"sha1 : {sha1}")

    if len(data) != EXPECTED_SIZE:
        print(f"WARNING: unexpected size (expected {EXPECTED_SIZE})")
    if sha1 != EXPECTED_SHA1:
        print(f"WARNING: unexpected sha1 (expected {EXPECTED_SHA1})")
        print("         this may not be the 1.3.1 build that was analysed")

    print("\nMach-O slices:")
    for label, off, size, ft in macho_info(data):
        name = {2: "MH_EXECUTE", 6: "MH_DYLIB"}.get(ft, str(ft))
        print(f"  {label:6} off={off:<10} size={size:<10} filetype={name}")

    out, patches, jb, fn_ok, skip_ok, skip_off, ls_sites, ls_err = \
        patch(data, local_save=local_save)

    if local_save:
        if ls_err:
            print(f"\n>>> ERROR: local save patch INCOMPLETE: {ls_err}")
            for label, off in ls_sites:
                print(f"    (applied) {label} @ {off}")
        else:
            print("\n>>> LOCAL SAVE patched: every save object is now marked "
                  "locally-persisted")
            for label, off in ls_sites:
                print(f"    patched   @ file offset {off:<10} {label}")
    else:
        print("\n>>> local save patch skipped (--no-local-save)")

    if skip_ok:
        print(f"\n>>> MAIN PATCH applied: skip UI_DOWNLOADING_PROFILE "
              f"-> UI_FIRST_CHECK (call site @ file offset {skip_off}, mov w0,#0)")
    else:
        print("\n>>> ERROR: main patch (profile skip) NOT applied "
              "(call site not found) -- the game would stay blocked")

    print(f"\n{len(jb)} jailbreak detection paths neutralised")
    if fn_ok:
        print("jailbreak detection function (arm64) patched: mov w0,#0 ; ret")
    else:
        print("WARNING: jailbreak function not found at expected offset -- NOT patched")
    print(f"\n{len(patches)} strings patched:")
    for off, s, new in patches:
        print(f"  off={off:<10} {s.decode()[:58]}")
        print(f"  {'':14} -> {new.decode()[:58]}")

    if len(out) != len(data):
        print("ERROR: size changed, aborting")
        return 1

    remaining = re.findall(rb"https?://[a-z0-9.-]*gameloft\.com", out)
    if remaining:
        print(f"ERROR: {len(remaining)} Gameloft hosts still live")
        return 1

    if not skip_ok:
        # the profile skip is the whole point of this build: refuse to ship a
        # binary that would not unblock anything.
        print("ERROR: main patch missing, aborting")
        return 1

    if local_save and ls_err:
        # A half-applied local save is worse than none: objects would write
        # files nobody reads back, or be reloaded from files nobody writes.
        print("ERROR: local save patch incomplete, aborting")
        return 1

    open(args[1], "wb").write(out)
    print(f"\nOK -> {args[1]} ({len(out)} bytes)")
    print("No live Gameloft host left. Profile: skipped -> UI_FIRST_CHECK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
