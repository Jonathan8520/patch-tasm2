#!/usr/bin/env python3
"""
Command-line front end for machoscan.

    ./scan.py dis 0x10021cef8 60      disassemble
    ./scan.py fn  0x10021cef8         disassemble the whole enclosing function
    ./scan.py str userdata            C strings containing a substring
    ./scan.py sref userdata           where an exact C string is referenced
    ./scan.py xref 0x1006e0000        who forms this address (ADRP+ADD/LDR)
    ./scan.py callers 0x10021cef8     who BL/B here
    ./scan.py info                    sections, segments, symbol count
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from machoscan import Bin  # noqa: E402

BINARY = os.environ.get("TASM2_BIN", "/home/user/AmazingSpiderMan2")


def fn_range(b, va):
    return b.func_range(va)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    b = Bin(BINARY)
    cmd = sys.argv[1]

    if cmd == "info":
        print(f"arm64 slice at file offset {b.base:#x}")
        print(f"symbols: {len(b.symbols)}")
        print("\nsegments:")
        for n, va, vs, fo, fs in b.segments:
            print(f"  {n:<12} vaddr={va:#012x} vmsize={vs:#x} fileoff={fo:#x}")
        print("\nsections:")
        for n, (va, fo, sz) in b.sections.items():
            print(f"  {n:<20} vaddr={va:#012x} size={sz:#x}")

    elif cmd == "dis":
        va = int(sys.argv[2], 0)
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 40
        print(b.disasm_text(va, n))

    elif cmd == "fn":
        va = int(sys.argv[2], 0)
        s, e = fn_range(b, va)
        print(f"; function {s:#x} .. {e:#x}  ({(e - s) // 4} insns)")
        print(b.disasm_text(s, (e - s) // 4))

    elif cmd == "str":
        for va, s in b.grep_cstrings(sys.argv[2]):
            print(f"{va:#012x}  {s!r}")

    elif cmd == "sref":
        for va in b.find_cstring(sys.argv[2]):
            refs = b.xrefs_to(va)
            print(f'{va:#012x} "{sys.argv[2]}"  refs={[hex(r) for r in refs]}')

    elif cmd == "xref":
        va = int(sys.argv[2], 0)
        print([hex(r) for r in b.xrefs_to(va)])

    elif cmd == "callers":
        va = int(sys.argv[2], 0)
        print([hex(r) for r in b.callers_of(va)])

    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
