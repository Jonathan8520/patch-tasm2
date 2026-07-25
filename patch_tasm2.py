#!/usr/bin/env python3
"""
Patch TASM2 (1.3.1): unblocks the infinite "Downloading profile" spinner
(UI_DOWNLOADING_PROFILE) so the game can be launched and played offline.

Main patch (derived from arm64 disassembly, not from guesswork): neutralises
the "do we need to download the profile?" decision at the single call site
that leads to the spinner, routing the game to its own native UI_FIRST_CHECK
state ("no profile to download") instead.

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


def patch(data):
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

    return bytes(m), patches, jb, fn_ok, skip_ok, skip_off


def main():
    if len(sys.argv) != 3:
        print("usage: patch_tasm2.py <input_binary> <output_binary>")
        return 1

    data = open(sys.argv[1], "rb").read()

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

    out, patches, jb, fn_ok, skip_ok, skip_off = patch(data)

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

    open(sys.argv[2], "wb").write(out)
    print(f"\nOK -> {sys.argv[2]} ({len(out)} bytes)")
    print("No live Gameloft host left. Profile: skipped -> UI_FIRST_CHECK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
