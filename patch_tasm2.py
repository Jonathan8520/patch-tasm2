#!/usr/bin/env python3
"""
Patch TASM2 (1.3.1) : debloque l'ecran "Telechargement du profil"
(UI_DOWNLOADING_PROFILE) pour permettre le jeu offline.

Le patch principal (issu du desassemblage arm64, pas d'une hypothese) :
neutralise la DECISION "faut-il telecharger le profil en ligne" au seul
site d'appel concerne, pour router le jeu vers son etat natif UI_FIRST_CHECK
("pas de profil a telecharger") au lieu du spinner infini.

Patchs complementaires historiques (hosts Gameloft morts -> .invalid,
chemins et fonction de detection jailbreak). Tout est fait a longueur
strictement preservee : aucun offset du Mach-O n'est decale.
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

# Chemins de detection de jailbreak (obfusques dans le binaire).
JB_PATHS = [
    b"/Ljbrbrz/MpbjlfSvbstrbtf/MobileSubstrate.dylib",
    b"/Applications/Czdjb.bpp",
    b"/var/lib/czdjb",
    b"/var/tmp/czdjb.log",
    b"/ftc/bpt",
    b"/var/lib/apt",
]


def info_macho(data):
    """Retourne la liste des slices (label, offset, size, filetype)."""
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
    """Offset (dans le FAT) du slice arm64, ou None."""
    for label, off, size, ft in info_macho(data):
        if label == "arm64":
            return off, size
    return None, None


def arm64_sections(data, base):
    """Retourne {sectname: (vmaddr, fileoff, size)} pour le slice arm64 @ base."""
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
    Patch principal : au site d'appel qui, juste avant d'afficher
    UI_DOWNLOADING_PROFILE, appelle le predicat "download profile ?"
    (BL 0x100346c10), on remplace ce BL par `mov w0, #0`. Le `cbz w0`
    qui suit est alors toujours pris -> le jeu emet UI_FIRST_CHECK
    (chemin natif "pas de profil a telecharger") et poursuit la boucle.

    Auto-localise via la reference unique a la chaine UI_DOWNLOADING_PROFILE,
    donc robuste. Renvoie (ok, file_off) ou (False, None).
    """
    base, size = arm64_slice_off(m)
    if base is None:
        return False, None
    sects = arm64_sections(m, base)
    if "__cstring" not in sects or "__text" not in sects:
        return False, None
    cs_addr, cs_off, cs_size = sects["__cstring"]
    tx_addr, tx_off, tx_size = sects["__text"]

    # 1) adresse virtuelle de la chaine
    blob = m[cs_off:cs_off + cs_size]
    i = blob.find(b"UI_DOWNLOADING_PROFILE\x00")
    if i < 0 or (i != 0 and blob[i - 1] != 0):
        return False, None
    sva = cs_addr + i

    # 2) scanner __text pour l'ADRP+ADD formant sva
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
        elif (insn & 0xFF000000) == 0x91000000:  # ADD imm
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

    # 3) le BL predicat est 0x24 avant l'ADD ; verifier que c'est bien un BL
    call_pc = add_addr - 0x24
    call_off = tx_off + (call_pc - tx_addr)
    old = struct.unpack("<I", m[call_off:call_off + 4])[0]
    if (old & 0xFC000000) != 0x94000000:  # pas un BL -> on n'ecrit rien
        return False, None

    # 4) mov w0, #0
    m[call_off:call_off + 4] = struct.pack("<I", 0x52800000)
    return True, call_off


def patch_save_on_flush(m):
    """
    Patch sauvegarde locale (v2, evenementiel).

    Le flag "dirty" du save-manager n'est cable qu'au flux UI_HardReset :
    en jeu, la progression n'etait committee qu'au travers du profil serveur
    (mort) -> plus rien n'est sauvegarde en local.

    On NE touche PAS au writer (v1 forcait l'ecriture a chaque frame ->
    tempete d'I/O -> blocage a 45 %). On agit sur le "flush save" event-driven,
    reconnaissable a son double appel du writer avec dt=0 :

        ldr x0, [x21, #0x560]   ; save manager
        mov w1, #0              ; dt = 0
        bl  writer              ; <- 1er appel (redondant)
        ldr x0, [x21, #0x560]
        mov w1, #0
        bl  writer              ; <- 2e appel

    Le 1er appel est remplace par la pose du flag dirty, de sorte que le 2e
    appel (inchange) effectue reellement la sauvegarde :

        mov  w8, #1
        strb w8, [x0, #0xfa8]   ; dirty = 1

    Cette fonction n'est pas la boucle par frame (celle-ci appelle le writer
    avec le vrai dt), donc pas d'I/O par frame. 8 octets, longueur preservee.
    Renvoie (ok, file_off) ou (False, None).
    """
    base, size = arm64_slice_off(m)
    if base is None:
        return False, None
    sects = arm64_sections(m, base)
    if "__cstring" not in sects or "__text" not in sects:
        return False, None
    cs_addr, cs_off, cs_size = sects["__cstring"]
    tx_addr, tx_off, tx_size = sects["__text"]

    # 1) localiser le writer via la chaine "%s/ud_Spider2.sav"
    blob = m[cs_off:cs_off + cs_size]
    i = blob.find(b"%s/ud_Spider2.sav\x00")
    if i < 0:
        return False, None
    sva = cs_addr + i

    text = m[tx_off:tx_off + tx_size]
    n = tx_size // 4
    insns = struct.unpack_from("<%dI" % n, text, 0)
    regpage = {}
    add_pc = None
    for k in range(n):
        insn = insns[k]
        pc = tx_addr + k * 4
        if (insn & 0x9F000000) == 0x90000000:
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7FFFF
            imm = (immhi << 2 | immlo)
            if imm & (1 << 20):
                imm -= (1 << 21)
            regpage[insn & 0x1F] = (pc & ~0xFFF) + (imm << 12)
        elif (insn & 0xFF000000) == 0x91000000:
            rn = (insn >> 5) & 0x1F
            if rn in regpage:
                im = (insn >> 10) & 0xFFF
                if (insn >> 22) & 1:
                    im <<= 12
                if regpage[rn] + im == sva:
                    add_pc = pc
                    break
    if add_pc is None:
        return False, None

    # le writer commence apres le RET precedent ; quelques `b` de thunk peuvent
    # trainer avant le vrai prologue, donc on accepte une cible dans la plage
    # [debut_bloc .. ref_chaine].
    RET = 0xD65F03C0
    a = add_pc
    while a > tx_addr and struct.unpack_from("<I", text, a - 4 - tx_addr)[0] != RET:
        a -= 4
    lo, hi = a, add_pc

    # 2) trouver le double appel writer(dt=0) : BL a X et X+0xC, meme cible,
    #    chacun precede de `mov w1, #0`
    MOV_W1_0 = 0x52800001
    site = None
    for k in range(1, n - 3):
        insn = insns[k]
        if (insn & 0xFC000000) != 0x94000000:
            continue
        pc = tx_addr + k * 4
        off = insn & 0x03FFFFFF
        if off & (1 << 25):
            off -= (1 << 26)
        tgt = pc + off * 4
        if not (lo <= tgt <= hi):
            continue
        insn2 = insns[k + 3]
        if (insn2 & 0xFC000000) != 0x94000000:
            continue
        off2 = insn2 & 0x03FFFFFF
        if off2 & (1 << 25):
            off2 -= (1 << 26)
        if (pc + 0xC) + off2 * 4 != tgt:   # les deux appels visent le meme writer
            continue
        # les deux appels doivent etre precedes de `mov w1, #0`
        if insns[k - 1] != MOV_W1_0 or insns[k + 2] != MOV_W1_0:
            continue
        site = pc
        break
    if site is None:
        return False, None

    # 3) `mov w1,#0` -> `mov w8,#1` ; `bl writer` -> `strb w8,[x0,#0xfa8]`
    off_mov = tx_off + (site - 4 - tx_addr)
    off_bl = tx_off + (site - tx_addr)
    m[off_mov:off_mov + 4] = struct.pack("<I", 0x52800028)   # mov  w8, #1
    m[off_bl:off_bl + 4] = struct.pack("<I", 0x393EA008)     # strb w8, [x0, #0xfa8]
    return True, off_mov


def patch_save_all_objects(m):
    """
    Patch sauvegarde locale (v3) : persister TOUS les objets de sauvegarde.

    Le save-manager gere 17 objets (slots +0xa40..+0xac0). Dans le writer,
    chaque objet est ignore si son drapeau "persistable" est nul :

        ldr  x22, [x19, x23]      ; objet (toujours valide)
        ldrb w8,  [x22, #0x25]    ; drapeau "a persister"
        cbz  w8, <objet suivant>  ; ==0 -> jamais ecrit sur disque
        ...  serialisation + ecriture ud_<Nom>.sav

    Seuls 6 objets sur 17 sont ecrits (Sound, Control, InitPos, Economy, Item,
    FriendList) : le reste etait persiste via le profil serveur, mort. On
    neutralise ce filtre (`cbz` -> `nop`) pour que les 17 objets soient
    serialises et ecrits localement. Le pointeur objet est deref juste avant
    le test, donc tous les slots contiennent bien un objet valide.

    Le filtre est dans la partie deja protegee par le flag dirty : pas d'I/O
    par frame. 4 octets, longueur preservee.
    Renvoie (ok, file_off) ou (False, None).
    """
    base, size = arm64_slice_off(m)
    if base is None:
        return False, None
    sects = arm64_sections(m, base)
    if "__cstring" not in sects or "__text" not in sects:
        return False, None
    cs_addr, cs_off, cs_size = sects["__cstring"]
    tx_addr, tx_off, tx_size = sects["__text"]

    blob = m[cs_off:cs_off + cs_size]
    i = blob.find(b"%s/ud_Spider2.sav\x00")
    if i < 0:
        return False, None
    sva = cs_addr + i

    text = m[tx_off:tx_off + tx_size]
    n = tx_size // 4
    insns = struct.unpack_from("<%dI" % n, text, 0)
    regpage = {}
    add_pc = None
    for k in range(n):
        insn = insns[k]
        pc = tx_addr + k * 4
        if (insn & 0x9F000000) == 0x90000000:
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7FFFF
            imm = (immhi << 2 | immlo)
            if imm & (1 << 20):
                imm -= (1 << 21)
            regpage[insn & 0x1F] = (pc & ~0xFFF) + (imm << 12)
        elif (insn & 0xFF000000) == 0x91000000:
            rn = (insn >> 5) & 0x1F
            if rn in regpage:
                im = (insn >> 10) & 0xFFF
                if (insn >> 22) & 1:
                    im <<= 12
                if regpage[rn] + im == sva:
                    add_pc = pc
                    break
    if add_pc is None:
        return False, None

    # debut de la fonction writer
    RET = 0xD65F03C0
    a = add_pc
    while a > tx_addr and struct.unpack_from("<I", text, a - 4 - tx_addr)[0] != RET:
        a -= 4
    fstart = a

    # chercher `ldrb w?, [x?, #0x25]` suivi d'un `cbz`
    site = None
    for pc in range(fstart, add_pc, 4):
        w = struct.unpack_from("<I", text, pc - tx_addr)[0]
        if (w & 0xFFC00000) == 0x39400000 and ((w >> 10) & 0xFFF) == 0x25:
            w2 = struct.unpack_from("<I", text, pc + 4 - tx_addr)[0]
            if (w2 & 0x7F000000) == 0x34000000:  # CBZ
                site = pc + 4
                break
    if site is None:
        return False, None

    off_cbz = tx_off + (site - tx_addr)
    m[off_cbz:off_cbz + 4] = struct.pack("<I", 0xD503201F)  # NOP
    return True, off_cbz


def patcher(data):
    m = bytearray(data)
    patches = []
    pat = re.compile(rb"[\x20-\x7e]{6,130}")
    for mt in pat.finditer(bytes(m)):
        s = mt.group()
        off = mt.start()
        if b"gameloft.com" not in s:
            continue
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

    # --- chemins de detection de jailbreak ---
    jb = []
    for p in JB_PATHS:
        i = 0
        while True:
            i = bytes(m).find(p, i)
            if i < 0:
                break
            repl = b"/zz" + b"z" * (len(p) - 3)
            if len(repl) != len(p):
                raise RuntimeError("longueur JB modifiee")
            m[i:i + len(p)] = repl
            jb.append((i, p))
            i += 1

    # --- fonction de detection de jailbreak (arm64) ---
    JB_FUNC_FILEOFF = 19016508
    JB_FUNC_ORIG = bytes.fromhex("ff0303d1f44f0aa9")
    JB_FUNC_PATCH = struct.pack("<II", 0x52800000, 0xD65F03C0)  # mov w0,#0 ; ret
    fn_ok = False
    if m[JB_FUNC_FILEOFF:JB_FUNC_FILEOFF + 8] == JB_FUNC_ORIG:
        m[JB_FUNC_FILEOFF:JB_FUNC_FILEOFF + 8] = JB_FUNC_PATCH
        fn_ok = True

    # --- PATCH PRINCIPAL : skip du telechargement de profil ---
    skip_ok, skip_off = patch_profile_skip(m)

    # --- PATCH SAUVEGARDE (v2) : sauvegarde locale au flush evenementiel ---
    save_ok, save_off = patch_save_on_flush(m)

    # --- PATCH SAUVEGARDE (v3) : persister tous les objets ---
    all_ok, all_off = patch_save_all_objects(m)

    return bytes(m), patches, jb, fn_ok, skip_ok, skip_off, save_ok, save_off, all_ok, all_off


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

    out, patches, jb, fn_ok, skip_ok, skip_off, save_ok, save_off, all_ok, all_off = patcher(data)

    if skip_ok:
        print(f"\n>>> PATCH PRINCIPAL applique: skip UI_DOWNLOADING_PROFILE "
              f"-> UI_FIRST_CHECK (site d'appel @ file_off {skip_off}, mov w0,#0)")
    else:
        print("\n>>> ERREUR: patch principal (skip profil) NON applique "
              "(site d'appel introuvable) -- le blocage ne sera pas leve")

    if save_ok:
        print(f">>> PATCH SAUVEGARDE (v2) applique: dirty force au flush "
              f"evenementiel (@ file_off {save_off})")
    else:
        print(">>> ATTENTION: patch sauvegarde v2 NON applique (site introuvable)")

    if all_ok:
        print(f">>> PATCH SAUVEGARDE (v3) applique: persistance des 17 objets "
              f"(filtre @ file_off {all_off} -> nop)")
    else:
        print(">>> ATTENTION: patch sauvegarde v3 NON applique (filtre introuvable)")

    print(f"\n{len(jb)} chemins de detection jailbreak neutralises")
    if fn_ok:
        print("fonction de detection JB (arm64) patchee: mov w0,#0 ; ret")
    else:
        print("ATTENTION: fonction JB non trouvee a l'offset attendu -- NON patchee")
    print(f"\n{len(patches)} chaines patchees:")
    for off, s, new in patches:
        print(f"  off={off:<10} {s.decode()[:58]}")
        print(f"  {'':14} -> {new.decode()[:58]}")

    if len(out) != len(data):
        print("ERREUR: taille modifiee, abandon")
        return 1

    restants = re.findall(rb"https?://[a-z0-9.-]*gameloft\.com", out)
    if restants:
        print(f"ERREUR: {len(restants)} hosts gameloft encore actifs")
        return 1

    if not skip_ok:
        # le patch principal est la raison d'etre de cette version : on refuse
        # de produire un binaire qui ne debloque rien.
        print("ERREUR: patch principal absent, abandon")
        return 1

    open(sys.argv[2], "wb").write(out)
    print(f"\nOK -> {sys.argv[2]} ({len(out)} octets)")
    print("Aucun host gameloft actif restant. Profil: skip -> UI_FIRST_CHECK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
