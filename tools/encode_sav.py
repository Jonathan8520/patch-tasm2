#!/usr/bin/env python3
"""
Write a ud_<Name>.sav file the game will accept.

The exact inverse of decode_sav.py: zlib-deflate the payload, append its
crc32, pad to a multiple of 4, XXTEA-encrypt with the key derived from the
lengths and the timestamp, base64 it into the {"b","t","v"} envelope, then
apply the file obfuscation and its duplicate copy.

    ./encode_sav.py ud_QuestManager.sav 250454 -1      # rewrite as two ints

Reads the version and timestamp from the file being replaced, so the key
derivation and the envelope stay consistent with what the game wrote.
"""
import base64
import binascii
import json
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decode_sav import decode, DELTA, MASK  # noqa: E402


def xxtea_encrypt(words, key):
    n = len(words)
    if n < 2:
        return list(words)
    v = list(words)
    rounds = 6 + 52 // n
    total = 0
    z = v[n - 1]
    while rounds:
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            mx = (((z >> 5 ^ (y << 2) & MASK) + (y >> 3 ^ (z << 4) & MASK)) ^
                  (((total ^ y) + (key[(p & 3) ^ e] ^ z)) & MASK)) & MASK
            v[p] = (v[p] + mx) & MASK
            z = v[p]
        y = v[0]
        p = n - 1
        mx = (((z >> 5 ^ (y << 2) & MASK) + (y >> 3 ^ (z << 4) & MASK)) ^
              (((total ^ y) + (key[(p & 3) ^ e] ^ z)) & MASK)) & MASK
        v[n - 1] = (v[n - 1] + mx) & MASK
        z = v[n - 1]
        rounds -= 1
    return v


def encode(plain, version, timestr, stamp):
    """Bytes of a complete ud_*.sav carrying `plain`."""
    comp = zlib.compress(plain, 9)
    clear = comp + struct.pack("<I", binascii.crc32(plain) & MASK)
    comp_len = len(clear)
    pad_len = (comp_len + 3) & ~3
    clear += b"\0" * (pad_len - comp_len)

    key = [(stamp & 0xFF000000) ^ comp_len,
           (stamp & 0x00FF0000) ^ comp_len,
           (stamp & 0x0000FF00) ^ len(plain),
           (stamp & 0x000000FF) ^ len(plain)]
    words = struct.unpack("<%dI" % (pad_len // 4), clear)
    body = struct.pack("<%dI" % len(words), *xxtea_encrypt(words, key))

    blob = body + struct.pack("<4I", len(plain), comp_len, pad_len, stamp)
    text = json.dumps({"b": base64.b64encode(blob).decode(),
                       "t": timestr, "v": version},
                      separators=(",", ":")) + "\n"
    raw = text.encode()
    first = bytes(c ^ ((i + 42) % 127) for i, c in enumerate(raw))
    second = bytes(c ^ ((7 * i) % 23) for i, c in enumerate(first))
    return struct.pack("<I", len(raw) ^ 0x2A) + first + second


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    path = sys.argv[1]
    values = [int(a, 0) for a in sys.argv[2:]]

    old, info = decode(open(path, "rb").read())
    if len(old) != 4 * len(values):
        print(f"refusing: {path} holds {len(old)} bytes, "
              f"{len(values)} ints would be {4 * len(values)}")
        return 1

    plain = struct.pack("<%di" % len(values), *values)
    out = encode(plain, info["version"], info["time"], info["stamp"])

    back, check = decode(out)          # never ship what we cannot read back
    if back != plain:
        print("refusing: the encoder did not round-trip")
        return 1
    print(f"{path}: {struct.unpack('<%di' % len(values), old)} "
          f"-> {tuple(values)}  ({'; '.join(check['notes'])})")
    open(path, "wb").write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
