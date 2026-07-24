#!/usr/bin/env python3
"""
Patch TASM2 (1.3.1) : neutralise les hosts Gameloft morts pour forcer
le fallback offline et permettre la sauvegarde locale (ud_Spider2.sav).

Remplace les hostnames par des noms en .invalid (RFC 6761 : ne resolvent
jamais) en preservant strictement la longueur de chaque chaine, donc
aucun offset du Mach-O n'est decale.
"""
import re
import struct
import sys
import hashlib

SHA1_ATTENDU = "b3d322a788bbeeb1a006ba0da23a28300a5b7105"
TAILLE_ATTENDUE = 33375152

HOSTS = [
    b"livewebapp.gameloft.com",     # autologin.php - bloqueur principal
    b"ingameads.gameloft.com",      # pub / iphoneloading.php
    b"201205igp.gameloft.com",      # IGP / freemium
    b"pjsmmm-legacy.gameloft.com",  # backend legacy
    b"eve.gameloft.com",            # services profil
]


def info_macho(data):
    """Retourne la liste des slices (label, offset, filetype)."""
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


def patcher(data):
    m = bytearray(data)
    patches = []
    pat = re.compile(rb"[\x20-\x7e]{6,130}")
    for mt in pat.finditer(bytes(m)):
        s = mt.group()
        off = mt.start()
        if b"gameloft.com" not in s:
            continue
        # ignorer les chemins de build et les placeholders
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
                raise RuntimeError(f"longueur modifiee: {len(s)} -> {len(new)}")
            patches.append((off, s, new))
    for off, s, new in patches:
        m[off:off + len(s)] = new
    return bytes(m), patches


def main():
    if len(sys.argv) != 3:
        print("usage: patch_tasm2.py <binaire_entree> <binaire_sortie>")
        return 1

    data = open(sys.argv[1], "rb").read()

    print(f"taille   : {len(data)} octets")
    sha1 = hashlib.sha1(data).hexdigest()
    print(f"sha1     : {sha1}")

    if len(data) != TAILLE_ATTENDUE:
        print(f"ATTENTION: taille inattendue (attendu {TAILLE_ATTENDUE})")
    if sha1 != SHA1_ATTENDU:
        print(f"ATTENTION: sha1 inattendu (attendu {SHA1_ATTENDU})")
        print("           le binaire n'est peut-etre pas la 1.3.1 analysee")

    print("\nslices Mach-O:")
    for label, off, size, ft in info_macho(data):
        nom = {2: "MH_EXECUTE", 6: "MH_DYLIB"}.get(ft, str(ft))
        print(f"  {label:6} off={off:<10} size={size:<10} filetype={nom}")

    out, patches = patcher(data)

    print(f"\n{len(patches)} chaines patchees:")
    for off, s, new in patches:
        print(f"  off={off:<10} {s.decode()[:58]}")
        print(f"  {'':14} -> {new.decode()[:58]}")

    if len(out) != len(data):
        print("ERREUR: taille modifiee, abandon")
        return 1

    # verification: plus aucun host actif
    restants = re.findall(rb"https?://[a-z0-9.-]*gameloft\.com", out)
    if restants:
        print(f"ERREUR: {len(restants)} hosts gameloft encore actifs")
        return 1

    open(sys.argv[2], "wb").write(out)
    print(f"\nOK -> {sys.argv[2]} ({len(out)} octets)")
    print("Aucun host gameloft actif restant.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
