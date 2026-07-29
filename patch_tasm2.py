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
the five settings objects already use. Disable with --no-local-save.

Chapter patch: ud_QuestManager's second persisted int is the pending-mission
id, which is always the constructor's own -1 and therefore worth nothing. It
carries the story chapter instead. Disable with --no-persist-chapter.

Tutorial guards: the tutorial bitmask is never wiped, on either of the two
paths that used to discard it. Disable with --no-force-prologue-skip.

Profile save: save object 16 -- the local mission server's profile document,
and the whole story cursor with it -- was the one object the writer refused to
write, behind a gate that could never unlock itself. One nop opens it, and the
story then advances offline on its own. Disable with --no-profile-save.
See LOCAL_SAVE_DESIGN.md.

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


def verify_chapter(data):
    """
    Same, for the chapter patch: both original words must be gone and both
    rewritten words present exactly once, in the same instruction pair.
    """
    base, size = arm64_slice_off(data)
    if base is None:
        return ["no arm64 slice"]
    sects = arm64_sections(data, base)
    tx_addr, tx_off, tx_size = sects["__text"]
    text = bytes(data[tx_off:tx_off + tx_size])
    problems = []
    sites = list(CHAPTER_SITES) + [
        (CHAPTER_LOCAL_SITE[0], CHAPTER_LOCAL_SITE[1], 0,
         struct.unpack("<I", CHAPTER_LOCAL_STORE)[0]),
    ]
    for label, sig, idx, word in sites:
        if sig in text:
            problems.append(f"{label}: original instruction still present")
        patched = bytearray(sig)
        patched[idx * 4:idx * 4 + 4] = struct.pack("<I", word)
        n = text.count(bytes(patched))
        if n != 1:
            problems.append(f"{label}: expected 1 patched site, found {n}")
    return problems


# --- chapter persistence ----------------------------------------------------
#
# This is what makes the tutorial replay on every launch, and no amount of
# save-object restoring can fix it, because the value is not in a save object.
#
# `chapter` is progressMgr+0x2a4 (the manager at [0x101074a30]); 0 means the
# prologue and 1..8 the story chapters (0x1001f2ac0 bounds `chapter - 1` to
# 0..7; the profile mirrors it as the string "ch<N>"; the progress UI picks
# UI_prologue_progress_2 when it is 0 and UI_chapter_progress otherwise).
#
# The launch decision is at 0x1001fc844:
#
#     ldr  w8, [progressMgr, #0x2a4]     ; chapter
#     cbnz w8, <normal flow>
#     ...  "story01_mission01"           ; the prologue -- i.e. the tutorial
#
# Exactly one gameplay path writes it: 0x1001edd54, at mission completion,
# from the finished mission's own "chapter" entry (0x1001ed644). The only
# other writers are the two profile appliers (0x10021bf84, 0x10021d134), both
# behind HasMember("_ca"), which offline is never true. So the value is
# produced locally and correctly during play -- it simply has nowhere to live
# between two launches, and every launch starts again from 0.
#
# ud_QuestManager is where it can live. That object persists exactly two ints
# through a helper pair called from nowhere else in the binary:
#
#     0x1001ff4a8  serialise    writes progressMgr+0x2d8, then +0x2dc
#     0x1001ff4dc  deserialise  version 3 reads them back into the same two
#
# and a real device file confirms version 3 with an 8-byte payload.
#
# The second slot is worth nothing. +0x2dc is the pending-mission id; its only
# producer (0x10020a1dc) copies it out of a field it immediately resets to -1,
# and the constructor already initialises +0x2dc to -1 (0x1001f6910-0x1001f6914).
# Every save therefore stored -1 -- the constructor default. Not restoring it
# leaves it at exactly the value it was being restored to.
#
# So the second slot carries `chapter` on both sides instead. Two four-byte
# edits, still two ints at version 3: file format, length and version all
# unchanged, with the game's own serialiser on both ends.
#
# One-time caveat: a ud_QuestManager.sav written by an earlier build holds the
# old -1 in that slot, which would land in `chapter`. Delete that one file
# before the first launch of a build carrying this patch.

# The serialiser writes a constant rather than reading the field, and that is
# deliberate. Offline the chapter can only ever be 0 or 1 -- nothing produces
# anything else -- so `mov w1, #1` is exactly `max(chapter, 1)` with one
# instruction, and unlike a read it cannot lose a race with the flush. The
# object is written when the save manager next sees it dirty, which need not be
# after the mission-completion store; storing the constant removes that ordering
# question entirely. Revisit if a real chapter advance ever exists.

CHAPTER_SITES = [
    ("serialise at least chapter 1 instead of the pending mission (0x1001ff4c8)",
     bytes.fromhex("81de42b9e00313aa"), 0, 0x52800021),   # mov w1,#1
    ("restore chapter instead of pending mission (0x1001ff594)",
     bytes.fromhex("60de02b910000014"), 0, 0xB902A660),   # str w0,[x19,#0x2a4]
]


# --- producing the chapter locally ------------------------------------------
#
# Persisting the chapter was necessary and not sufficient: a device run with the
# patch above completed the prologue and stored (250454, 0). The chapter really
# was written and read back -- it was just 0, and 0 is what makes 0x1001fc844
# request "story01_mission01" all over again.
#
# The reason is that nothing offline ever produces a chapter. An exhaustive
# sweep of __text -- every store form whose byte range covers +0x2a4, not merely
# those whose immediate equals it -- finds five writers: the constructor
# (0x1001f68ec, an 8-byte `str d1` writing 0), the deserialiser, the two profile
# appliers behind HasMember("_ca"), and 0x1001edd54. The `chapter >= 8 ? 0 :
# chapter + 1` at 0x1001f25d8 is never stored back; it feeds the "BossComing"
# HUD banner.
#
# And 0x1001edd54 does not compute the chapter either. It reads it out of the
# mission-result map at missionObj+0x320, whose only wholesale writer is
# 0x1001f129c -- the JSON callback of the "mission finished" HTTP request. That
# request cannot complete offline, so the map stays empty and
# `map["chapter"]` default-inserts 0 (`str wzr,[x24,#0x38]` at 0x1001ed694),
# which is then stored straight into the chapter. The story cursor was
# server-computed, exactly as the device file shows.
#
# One field, three symptoms: the prologue relaunching, chapter-gated content
# staying locked, and -- through 0x1003cc5d0, whose tutorial deserialiser calls
# 0x1001f9388 (`chapter != 0`) and does `str wzr,[x19,#4]` when it is 0 -- the
# tutorial bitmask being wiped on every launch. That is why ud_Tutorial.sav
# regressed from 132926 to 54 on device while every other object round-tripped.
#
# So the value has to be produced locally. The load that feeds the store is
#
#     0x1001edd28   ldr w20, [sp, #0x10]      ; the 0 the empty map handed back
#     ...                                     ; w20 untouched through here
#     0x1001edd54   str w20, [progressMgr, #0x2a4]
#
# and w20 is read nowhere else in between, so replacing that one load with
# `mov w20, #1` makes a completed mission set the chapter to 1 instead of 0.
# Nothing else offline writes the field, so it stays 1: monotone, never
# regressing, and never above what the game itself would have unlocked first.
#
# Deliberately conservative. Incrementing per completed mission would run to 8
# in eight missions, side missions included, because which mission belongs to
# which chapter lives in the data paks that only the server response resolved.
# Setting 1 cannot unlock content out of order; if the story turns out to be
# gated beyond chapter 1, that is the next thing to measure, and it needs a
# code cave rather than an in-place edit.

CHAPTER_LOCAL_SITE = ("produce the chapter locally at mission completion "
                      "(0x1001edd28)",
                      bytes.fromhex("f41340b968740090"))
# mov w20, #1  -- replaces `ldr w20, [sp, #0x10]`, the empty map's 0
CHAPTER_LOCAL_STORE = struct.pack("<I", 0x52800034)


def patch_chapter_persist(m):
    """
    Make ud_QuestManager carry progressMgr+0x2a4 (chapter) in place of +0x2dc
    (current mission). Returns (sites, error); nothing is written on error.
    """
    base, size = arm64_slice_off(m)
    if base is None:
        return [], "no arm64 slice"
    sects = arm64_sections(m, base)
    tx_addr, tx_off, tx_size = sects["__text"]
    text = bytes(m[tx_off:tx_off + tx_size])

    sites = list(CHAPTER_SITES) + [
        (CHAPTER_LOCAL_SITE[0], CHAPTER_LOCAL_SITE[1], 0,
         struct.unpack("<I", CHAPTER_LOCAL_STORE)[0]),
    ]

    planned = []
    for label, sig, idx, word in sites:
        hits, i = [], 0
        while True:
            i = text.find(sig, i)
            if i < 0:
                break
            hits.append(i)
            i += 1
        if len(hits) != 1:
            return [], f"{label}: expected 1 match, found {len(hits)}"
        planned.append((label, tx_off + hits[0] + idx * 4, word))

    done = []
    for label, off, word in planned:
        m[off:off + 4] = struct.pack("<I", word)
        done.append((label, off))
    return done, None


# --- overriding the prologue, when restoring the chapter is not enough --------
#
# Device data, third run: ud_QuestManager.sav holds (250454, 1). The chapter is
# written correctly now. The prologue still replays and ud_Tutorial.sav still
# regresses, which means the value is not reaching progressMgr+0x2a4 on the way
# back in.
#
# The restore order is not the explanation. The manager's object array
# (mgr+0xa40, walked in order by ReloadAll) is filled at 0x100218d00 from stack
# spills, and resolving those gives position 8 = the quest object (mgr+0x568,
# the one that carries the chapter) and position 10 = the tutorial object
# (mgr+0x6c8). The chapter is restored two objects *before* the tutorial reads
# it, so a working restore would have spared the bitmask. It did not.
#
# Why the restore does not land is still open. What can be closed is the
# behaviour, by taking the chapter out of both decisions:
#
#     0x1001fc868   cbnz w8, +0xc   ->  b +0xc
#         the launch check stops asking whether the chapter is 0, so
#         "story01_mission01" is never requested again.
#
#     0x1003cc5f4   cbz w0, +0x14   ->  nop
#         the tutorial deserialiser stops branching to its `str wzr,[x19,#4]`,
#         so the saved bitmask is read back whatever the chapter says.
#
# This is an override, not a restoration: a genuinely fresh install will start
# in the open world instead of the prologue. That is a deliberate trade -- the
# prologue replaying forever is the bug being fixed, and the game has no other
# way to know it has already been played. Disable with --no-force-prologue-skip
# to get the faithful behaviour back.

# The "never re-request the prologue" edit that used to live here
# (0x1001fc868 cbnz -> b) has been REMOVED. It was a stopgap from before the
# profile save patch, and it cost the game its opening cinematic, which is the
# first thing story01_mission01 plays. It is no longer needed: on a fresh
# install the chapter is 0, the prologue runs exactly once, and completing it
# writes 1 through 0x1001edd54, which ud_QuestManager.sav then restores on
# every later launch. The two tutorial-bitmask guards below stay -- they are
# what stops earned progress being thrown away.

PROLOGUE_SITES = [
    ("never wipe the tutorial bitmask on restore (0x1003cc5f4)",
     bytes.fromhex("66b3f897a0000034e00314aa"), 1, 0xD503201F),  # nop
    # CTutorialMgr::Reset is `str wzr,[x0,#4] ; ret` -- it zeroes the whole
    # bitmask. Its single caller is the tail of the script dispatcher at
    # 0x1001205ec, i.e. the game's own scripts ask for it, and one of them runs
    # every time the opening sequence plays: the restore puts 137022 back and
    # the script wipes it to 0 seconds later, which is exactly the 137022 -> 62
    # seen on device with the deserialiser already patched. Neutralise the
    # store and the method becomes a no-op, so nothing can discard tutorial
    # progress once it is earned.
    ("neuter CTutorialMgr::Reset (0x1003cc5b8)",
     bytes.fromhex("c0035fd61f0400b9c0035fd6080440b9"), 1, 0xD503201F),  # nop
]


def _apply_sites(m, sites, what):
    """Apply a list of (label, signature, word_index, replacement) sites."""
    base, size = arm64_slice_off(m)
    if base is None:
        return [], "no arm64 slice"
    sects = arm64_sections(m, base)
    tx_addr, tx_off, tx_size = sects["__text"]
    text = bytes(m[tx_off:tx_off + tx_size])

    planned = []
    for label, sig, idx, word in sites:
        hits, i = [], 0
        while True:
            i = text.find(sig, i)
            if i < 0:
                break
            hits.append(i)
            i += 1
        if len(hits) != 1:
            return [], f"{label}: expected 1 match, found {len(hits)}"
        planned.append((label, tx_off + hits[0] + idx * 4, word))

    done = []
    for label, off, word in planned:
        m[off:off + 4] = struct.pack("<I", word)
        done.append((label, off))
    return done, None


def _verify_sites(data, sites):
    base, size = arm64_slice_off(data)
    if base is None:
        return ["no arm64 slice"]
    sects = arm64_sections(data, base)
    tx_addr, tx_off, tx_size = sects["__text"]
    text = bytes(data[tx_off:tx_off + tx_size])
    problems = []
    for label, sig, idx, word in sites:
        if sig in text:
            problems.append(f"{label}: original instruction still present")
        patched = bytearray(sig)
        patched[idx * 4:idx * 4 + 4] = struct.pack("<I", word)
        n = text.count(bytes(patched))
        if n != 1:
            problems.append(f"{label}: expected 1 patched site, found {n}")
    return problems


# --- letting the local profile reach disk ----------------------------------
#
# This is the one that matters, and the game already contains the machinery.
#
# progressMgr+0x50 is not an HTTP client in this build: it is a local mission
# server (0x100416000..0x100422000) that reads the bundled ch0.json..ch8.json
# and synthesises the very answers Gameloft's server used to send. Request 0x16
# fills the whole RAM mission cursor -- progressMgr+0x110, a
# std::map<std::string,std::vector<int>> keyed "mm"/"sm"/"prm"/"rm" -- by
# reading profile["_ca"] == "chN" and indexing chapters[N] (0x100417cb4 ..
# 0x100417cf4). Request 0x15 ("mission finished") advances profile["_ca"] to
# chapterDoc["nc"] at 0x10041b308. The whole story cursor is computed offline.
#
# Its state lives in save object 16 (mgr+0x970, SaveIndex 16, version 2, ctor
# 0x1002157bc): the profile document itself. And that one object is the only
# one in the binary the writer refuses to write:
#
#     0x100211620   ldr  w8, [x19, #0x1c]      ; SaveIndex
#     0x100211624   cmp  w8, #0x10             ; == 16 ?
#     0x100211628   b.ne <normal write>
#     0x100211634   ldr  w8, [saveMgr, #0xfc8]
#     0x100211638   and  w8, w8, #0xff00ff     ; bytes +0xfc8 and +0xfca
#     0x10021163c   cbz  w8, <exit without writing anything>
#
# +0xfc8 is "did this file already exist when the manager was constructed"
# (0x100218e28 fopen "rb" -> 0x100218e34 / 0x100218e40), and +0xfca is
# "the cloud profile was touched", set only at 0x10021d878 and 0x10021da18,
# both dead offline. So on a clean install both are 0, the file is never
# written, and because it is never written it never exists: a closed loop.
#
# The consequence is exactly the symptom. Object 16's Reset (0x100215948)
# rebuilds a default profile whose chapter is the literal "ch0" (0x100215b10),
# ReloadAll then finds no file to override it, request 0x16 loads ch0.json, and
# the opening story mission is offered again. Every launch. Forever.
#
# One instruction opens the loop. The read-back side already runs for object 16
# unconditionally (0x10021a9c4 at boot, 0x10021bce8 in ReloadAll; 0x1002119ac
# has no SaveIndex gate), so nothing new is enabled -- the file simply starts
# existing, after which +0xfc8 is set at construction and the gate would pass on
# its own.
#
# Measured on this binary: the `cbz` word alone occurs 7 times in __text, the
# `and`+`cbz` pair exactly once.

PROFILE_SAVE_SITES = [
    ("let the local profile object reach disk (0x10021163c)",
     bytes.fromhex("089d0012a8100034"), 1, 0xD503201F),   # nop
]


def patch_profile_save(m):
    return _apply_sites(m, PROFILE_SAVE_SITES, "profile save")


def verify_profile_save(data):
    return _verify_sites(data, PROFILE_SAVE_SITES)


# --- the waiting spinner ------------------------------------------------------
#
# A spinner can sit on screen forever -- on the home menu, the skills page, and
# worst of all in the shop after a purchase fails. It is driven by a mask of
# reasons at progressMgr+0x330: 0x1001e7b94 sets bit N and shows the widget,
# 0x1001e7f3c clears bit N and hides it once the mask reaches 0. Offline some
# requests never answer, so their bit is never cleared and the widget never
# goes away. 65 show sites, 66 hide sites -- there is no single request to fix.
#
# So stop showing it. The function is void: its epilogue returns whatever a
# destructor left in w0, and several callers reach it by `b` rather than `bl`,
# which only compiles for a void tail call. Turning its first instruction into
# `ret` therefore satisfies every caller, including the tail-callers, for whom
# it becomes an immediate return.
#
# What this costs: the widget also puts up an input-blocking mask, so taps are
# no longer swallowed while one of these requests is pending. That is a real
# trade, and it is acceptable here because this widget is the *network* wait --
# level loading has its own full-screen loading screen, which is untouched.
# Offline, every wait this thing reports is a request that can never succeed.
#
# The prologue is a common one (9 identical copies in __text), so the signature
# runs seven words deep, to the distinctive `mov w20, #0x17fffff`.

SPINNER_SITES = [
    ("never show the network waiting spinner (0x1001e7b94)",
     bytes.fromhex("ffc304d1f65710a9f44f11a9fd7b12a9fd830491f30300aa14d0bf12"),
     0, 0xD65F03C0),   # ret
]


def patch_spinner(m):
    return _apply_sites(m, SPINNER_SITES, "spinner")


def verify_spinner(data):
    return _verify_sites(data, SPINNER_SITES)


def patch_prologue(m):
    return _apply_sites(m, PROLOGUE_SITES, "prologue override")


def verify_prologue(data):
    return _verify_sites(data, PROLOGUE_SITES)


def patch(data, local_save=True, chapter=True, prologue=True,
          profile_save=True, spinner=True):
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

    # --- optional: carry the story chapter in the local save ---
    ch_sites, ch_err = patch_chapter_persist(m) if chapter else ([], None)

    # --- optional: override the prologue decision outright ---
    pr_sites, pr_err = patch_prologue(m) if prologue else ([], None)

    # --- optional: let the local profile object reach disk ---
    ps_sites, ps_err = patch_profile_save(m) if profile_save else ([], None)

    # --- optional: never show the network waiting spinner ---
    sp_sites, sp_err = patch_spinner(m) if spinner else ([], None)

    return (bytes(m), patches, jb, fn_ok, skip_ok, skip_off, ls_sites, ls_err,
            ch_sites, ch_err, pr_sites, pr_err, ps_sites, ps_err,
            sp_sites, sp_err)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}

    local_save = "--no-local-save" not in flags
    chapter = "--no-persist-chapter" not in flags
    prologue = "--no-force-prologue-skip" not in flags
    profile_save = "--no-profile-save" not in flags
    spinner = "--keep-spinner" not in flags

    if flags & {"--verify", "--verify-local-save"}:
        if len(args) != 1:
            print("usage: patch_tasm2.py --verify [--no-local-save] "
                  "[--no-persist-chapter] <patched_binary>")
            return 1
        data = open(args[0], "rb").read()
        problems, checked = [], []
        if local_save:
            problems += verify_local_save(data)
            checked.append(LOCAL_SAVE_SITE[0])
        if chapter and "--verify-local-save" not in flags:
            problems += verify_chapter(data)
            checked += [label for label, _s, _i, _w in CHAPTER_SITES]
            checked.append(CHAPTER_LOCAL_SITE[0])
        if prologue and "--verify-local-save" not in flags:
            problems += verify_prologue(data)
            checked += [label for label, _s, _i, _w in PROLOGUE_SITES]
        if profile_save and "--verify-local-save" not in flags:
            problems += verify_profile_save(data)
            checked += [label for label, _s, _i, _w in PROFILE_SAVE_SITES]
        if spinner and "--verify-local-save" not in flags:
            problems += verify_spinner(data)
            checked += [label for label, _s, _i, _w in SPINNER_SITES]
        for p in problems:
            print(f"FAIL: {p}")
        if problems:
            return 1
        print(f"verified in {args[0]}:")
        for c in checked:
            print(f"  ok  {c}")
        return 0

    if len(args) != 2:
        print("usage: patch_tasm2.py [--no-local-save] [--no-persist-chapter] "
              "[--no-force-prologue-skip] [--no-profile-save] [--keep-spinner] "
              "<input_binary> <output_binary>")
        print("       patch_tasm2.py --verify <patched_binary>")
        return 1

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

    out, patches, jb, fn_ok, skip_ok, skip_off, ls_sites, ls_err, ch_sites, \
        ch_err, pr_sites, pr_err, ps_sites, ps_err, sp_sites, sp_err = \
        patch(data, local_save=local_save, chapter=chapter, prologue=prologue,
              profile_save=profile_save, spinner=spinner)

    if spinner:
        if sp_err:
            print(f"\n>>> ERROR: spinner patch NOT applied: {sp_err}")
        else:
            print("\n>>> SPINNER patched: the network waiting spinner is never shown")
            for label, off in sp_sites:
                print(f"    patched   @ file offset {off:<10} {label}")
    else:
        print("\n>>> spinner left in place (--keep-spinner)")

    if profile_save:
        if ps_err:
            print(f"\n>>> ERROR: profile save NOT applied: {ps_err}")
        else:
            print("\n>>> PROFILE SAVE patched: the local mission server's profile "
                  "is now written to disk")
            for label, off in ps_sites:
                print(f"    patched   @ file offset {off:<10} {label}")
    else:
        print("\n>>> profile save skipped (--no-profile-save)")

    if prologue:
        if pr_err:
            print(f"\n>>> ERROR: prologue override NOT applied: {pr_err}")
        else:
            print("\n>>> PROLOGUE override patched: the prologue is never "
                  "re-requested, the tutorial bitmask is never wiped")
            for label, off in pr_sites:
                print(f"    patched   @ file offset {off:<10} {label}")
    else:
        print("\n>>> tutorial guards skipped (--no-force-prologue-skip)")

    if chapter:
        if ch_err:
            print(f"\n>>> ERROR: chapter persistence NOT applied: {ch_err}")
        else:
            print("\n>>> CHAPTER patched: ud_QuestManager now carries "
                  "progressMgr+0x2a4 (story chapter)")
            for label, off in ch_sites:
                print(f"    patched   @ file offset {off:<10} {label}")
    else:
        print("\n>>> chapter patch skipped (--no-persist-chapter): the prologue "
              "will replay on every launch")

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

    if chapter and ch_err:
        print("ERROR: chapter persistence incomplete, aborting")
        return 1

    if prologue and pr_err:
        print("ERROR: prologue override incomplete, aborting")
        return 1

    if profile_save and ps_err:
        print("ERROR: profile save incomplete, aborting")
        return 1

    if spinner and sp_err:
        print("ERROR: spinner patch incomplete, aborting")
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
