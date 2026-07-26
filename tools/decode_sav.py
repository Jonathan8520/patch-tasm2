#!/usr/bin/env python3
"""
Decode a ud_<Name>.sav file written by the game, all the way to plain bytes.

Four layers, each recovered from the disassembly and confirmed against real
files pulled off a device:

1. File obfuscation (writer at 0x1002115f0)

       [0..4)      uint32 little-endian, = payload_length ^ 0x2a
       [4..4+N)    payload XORed byte-wise with (i + 42) % 127
       [4+N..4+2N) the same buffer XORed again with (7*i) % 23

   The reader only consumes the first copy; the second is written but never
   read back, almost certainly a copy-paste slip. Every file is therefore
   exactly 4 + 2*N bytes, which is a cheap integrity check.

2. JSON envelope: {"b": <base64 blob>, "t": <GMT timestamp>, "v": <format>}
   "v" is a per-object format version taken from mgr[index*0x30 + 0xb54]; it
   does not change when the same object is written again.

3. The blob (decoder at 0x100211224 / 0x1002113a8):

       [body (padded to a multiple of 4)][origLen][compLen][padLen][unix ts]

   The body is XXTEA-encrypted with a 128-bit key built from the file's own
   trailer -- no device secret involved unless the object sets its +0x26 flag:

       key[0] = (ts & 0xff000000) ^ compLen
       key[1] = (ts & 0x00ff0000) ^ compLen
       key[2] = (ts & 0x0000ff00) ^ origLen
       key[3] = (ts & 0x000000ff) ^ origLen

4. Inside, zlib: bytes [0 .. compLen-4) deflate to origLen bytes, and the
   four bytes at compLen-4 are a crc32 of the result.

    ./decode_sav.py ud_QuestManager.sav
    ./decode_sav.py ud_*.sav --hex
"""
import base64
import binascii
import json
import struct
import sys
import zlib

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF


def deobfuscate(blob):
    """Layer 1. Returns (json_text, payload_len, notes)."""
    if len(blob) < 4:
        raise ValueError("shorter than the 4-byte header")
    n = struct.unpack("<I", blob[:4])[0] ^ 0x2A
    notes = []
    if len(blob) != 4 + 2 * n:
        notes.append(f"size {len(blob)}, expected {4 + 2 * n} for N={n}")
    if n <= 0 or 4 + n > len(blob):
        raise ValueError(f"implausible payload length {n}")

    first = bytes(blob[4:4 + n])
    plain = bytes(b ^ ((i + 42) % 127) for i, b in enumerate(first))
    if len(blob) >= 4 + 2 * n:
        rebuilt = bytes(b ^ ((7 * i) % 23) for i, b in enumerate(first))
        notes.append("second copy matches" if blob[4 + n:4 + 2 * n] == rebuilt
                     else "second copy does NOT match")
    return plain, n, notes


def xxtea_decrypt(words, key):
    """Layer 3. Standard XXTEA decoding round, 6 + 52/n rounds."""
    n = len(words)
    if n < 2:
        return list(words)
    v = list(words)
    rounds = 6 + 52 // n
    total = (rounds * DELTA) & MASK
    y = v[0]
    while rounds:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = (((z >> 5 ^ (y << 2) & MASK) + (y >> 3 ^ (z << 4) & MASK)) ^
                  (((total ^ y) + (key[(p & 3) ^ e] ^ z)) & MASK)) & MASK
            v[p] = (v[p] - mx) & MASK
            y = v[p]
        z = v[n - 1]
        mx = (((z >> 5 ^ (y << 2) & MASK) + (y >> 3 ^ (z << 4) & MASK)) ^
              (((total ^ y) + (key[e] ^ z)) & MASK)) & MASK
        v[0] = (v[0] - mx) & MASK
        y = v[0]
        total = (total - DELTA) & MASK
        rounds -= 1
    return v


def decode(blob):
    """Full chain. Returns (plain_bytes, info dict)."""
    text, _, notes = deobfuscate(blob)
    env = json.loads(text)
    raw = base64.b64decode(env["b"])
    if len(raw) < 16:
        raise ValueError("blob shorter than its 16-byte trailer")
    body = raw[:-16]
    orig_len, comp_len, pad_len, ts = struct.unpack("<4I", raw[-16:])
    if pad_len != len(body):
        notes.append(f"padded length {pad_len} != body {len(body)}")
    if len(body) % 4:
        raise ValueError("body is not a whole number of 32-bit words")

    key = [(ts & 0xFF000000) ^ comp_len,
           (ts & 0x00FF0000) ^ comp_len,
           (ts & 0x0000FF00) ^ orig_len,
           (ts & 0x000000FF) ^ orig_len]
    words = struct.unpack("<%dI" % (len(body) // 4), body)
    clear = struct.pack("<%dI" % len(words), *xxtea_decrypt(words, key))

    stored_crc = struct.unpack("<I", clear[comp_len - 4:comp_len])[0]
    plain = zlib.decompress(clear[:comp_len - 4])
    if len(plain) != orig_len:
        notes.append(f"inflated to {len(plain)}, header says {orig_len}")
    actual = binascii.crc32(plain) & MASK
    notes.append("crc32 ok" if actual == stored_crc
                 else f"crc32 MISMATCH {actual:#x} != {stored_crc:#x}")

    return plain, {"version": env["v"], "time": env["t"], "orig": orig_len,
                   "comp": comp_len, "pad": pad_len, "stamp": ts,
                   "notes": notes}


def main():
    paths = [a for a in sys.argv[1:] if not a.startswith("--")]
    want_hex = "--hex" in sys.argv
    if not paths:
        print(__doc__)
        return 1
    for p in paths:
        blob = open(p, "rb").read()
        print(f"=== {p}  ({len(blob)} bytes)")
        try:
            plain, info = decode(blob)
        except Exception as e:
            print(f"    not a ud_*.sav in this format: {e}\n")
            continue
        print(f"    v={info['version']}  {info['time']}  "
              f"orig={info['orig']} comp={info['comp']} pad={info['pad']}")
        print(f"    {'; '.join(info['notes'])}")
        print(f"    {len(plain)} bytes of state")
        if want_hex or len(plain) <= 64:
            print(f"    hex: {plain.hex(' ')}")
        if len(plain) % 4 == 0 and len(plain) <= 64:
            print(f"    u32: {struct.unpack('<%dI' % (len(plain) // 4), plain)}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
