#!/usr/bin/env python3
"""
Dense overview of a function: the strings it references, the functions it
calls, and the structure offsets it touches. Far more readable than raw
disassembly when triaging a 600-instruction function.

    ./summary.py 0x10021cef8
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from machoscan import Bin  # noqa: E402

BINARY = os.environ.get("TASM2_BIN", "/home/user/AmazingSpiderMan2")


def summarise(b, va, show_offsets=True):
    start, end = b.func_range(va)
    n = (end - start) // 4
    print(f"; function {start:#x} .. {end:#x}  ({n} insns)")
    print(f"; callers: {[hex(c) for c in b.callers_of(start)][:12]}")

    page = {}
    strings, calls, offsets = [], {}, {}
    md = b.md
    off = b.va_to_off(start)
    code = b.data[off:off + (end - start)]
    for ins in md.disasm(code, start):
        m, ops = ins.mnemonic, ins.op_str
        try:
            if m == "adrp":
                reg, imm = [x.strip() for x in ops.split(",")]
                page[reg] = int(imm.lstrip("#"), 0)
            elif m == "add" and "#" in ops:
                p = [x.strip() for x in ops.split(",")]
                if len(p) >= 3 and p[1] in page and p[2].startswith("#"):
                    tgt = page[p[1]] + int(p[2][1:], 0)
                    s = b.cstring_at(tgt)
                    if s and s.isprintable() and len(s) > 1:
                        strings.append((ins.address, tgt, s))
            elif m in ("bl",) and ops.startswith("#"):
                t = int(ops[1:], 0)
                calls.setdefault(t, []).append(ins.address)
            elif m in ("ldr", "ldrb", "ldrh", "ldrsw", "ldrsb", "str",
                       "strb", "strh") and "[" in ops:
                inner = ops[ops.index("[") + 1:ops.index("]")]
                p = [x.strip() for x in inner.split(",")]
                if len(p) > 1 and p[1].startswith("#") and p[0] not in ("sp",):
                    if p[0] in page:
                        continue  # global, not a struct field
                    offsets.setdefault(int(p[1][1:], 0), 0)
                    offsets[int(p[1][1:], 0)] += 1
        except (ValueError, IndexError, KeyError):
            pass

    if strings:
        print("\n; strings referenced")
        for pc, tgt, s in strings:
            print(f";   {pc:#x}  {tgt:#x}  {s!r}")

    print("\n; calls")
    for t in sorted(calls):
        label = b.stub_name(t) or ""
        if not label:
            sym = b.sym_for(t)
            if sym and sym[1] == 0:
                label = sym[0]
        s, e = b.func_range(t)
        note = "" if (s == t or label) else f"  (mid-function of {s:#x})"
        print(f";   {t:#x} x{len(calls[t]):<3} {label}{note}")

    if show_offsets and offsets:
        top = sorted(offsets.items(), key=lambda kv: -kv[1])[:25]
        print("\n; struct offsets touched (offset x count)")
        print(";   " + "  ".join(f"{o:#x}x{c}" for o, c in top))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    b = Bin(BINARY)
    for a in sys.argv[1:]:
        summarise(b, int(a, 0))
        print("\n" + "=" * 70 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
