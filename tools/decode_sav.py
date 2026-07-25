#!/usr/bin/env python3
"""
Decode a ud_<Name>.sav file written by the game.

Layout, from the writer at 0x1002115f0:

    [0..4)      uint32 little-endian, = payload_length ^ 0x2a
    [4..4+N)    payload XORed byte-wise with (i + 42) % 127
    [4+N..4+2N) the same buffer XORed again with (7*i) % 23

The reader only ever consumes the first copy; the second is written but never
read back, almost certainly a copy-paste slip in the original code. Every file
is therefore exactly 4 + 2*N bytes, which is a cheap integrity check.

    ./decode_sav.py ud_QuestManager.sav
    ./decode_sav.py ud_*.sav --raw > dump.txt
"""
import struct
import sys


def decode(blob):
    """Return (payload, notes). Raises ValueError on a malformed file."""
    if len(blob) < 4:
        raise ValueError("shorter than the 4-byte header")
    n = struct.unpack("<I", blob[:4])[0] ^ 0x2A
    notes = []
    expected = 4 + 2 * n
    if len(blob) != expected:
        notes.append(f"size {len(blob)}, expected {expected} for N={n}")
    if n <= 0 or 4 + n > len(blob):
        raise ValueError(f"implausible payload length {n}")

    first = bytearray(blob[4:4 + n])
    plain = bytes(b ^ ((i + 42) % 127) for i, b in enumerate(first))

    # If the second copy is present, check it really is the first one XORed
    # again -- that confirms the format rather than assuming it.
    if len(blob) >= 4 + 2 * n:
        second = blob[4 + n:4 + 2 * n]
        rebuilt = bytes(b ^ ((7 * i) % 23) for i, b in enumerate(first))
        notes.append("second copy matches" if second == rebuilt
                     else "second copy does NOT match the expected pattern")
    return plain, n, notes


def main():
    paths = [a for a in sys.argv[1:] if not a.startswith("--")]
    raw = "--raw" in sys.argv
    if not paths:
        print(__doc__)
        return 1
    for p in paths:
        blob = open(p, "rb").read()
        print(f"=== {p}  ({len(blob)} bytes) ===")
        try:
            plain, n, notes = decode(blob)
        except ValueError as e:
            print(f"  not a ud_*.sav: {e}\n")
            continue
        for note in notes:
            print(f"  {note}")
        print(f"  payload: {n} bytes")
        if raw:
            print(plain.decode("utf-8", "replace"))
        else:
            text = plain.decode("utf-8", "replace")
            printable = sum(c.isprintable() or c in "\n\t" for c in text)
            print(f"  printable: {printable}/{len(text)}")
            print("  " + repr(text[:400]))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
