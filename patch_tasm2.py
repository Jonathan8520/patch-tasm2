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
paths that used to discard it. Disable with --no-tutorial-guards.

Profile save: save object 16 -- the local mission server's profile document,
and the whole story cursor with it -- was the one object the writer refused to
write, behind a gate that could never unlock itself. One nop opens it, and the
story then advances offline on its own. Disable with --no-profile-save.
See LOCAL_SAVE_DESIGN.md.

Boot spinner: the main patch takes the branch that leaves the home menu's
waiting widget with both of its hides disarmed, so it stayed on screen for
good. The offline branch now arms them exactly as the online one does.
Disable with --no-boot-spinner-fix.

Network failure (opt-in, --fail-network): the shared reachability predicate
returns "unreachable" at all fifty of its call sites, so every request that
would have hung until its timeout takes the game's own offline branch instead.
This is what shortens the waiting spinner rather than deleting it.

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

# The jailbreak detector is the one edit that cannot self-locate: its prologue
# (`sub sp,sp,#0xc0 ; stp x20,x19,[sp,#0xa0]`) is a generic one that recurs all
# over __text, so there is no unique signature to anchor to. The file offset
# below is therefore exact-or-nothing -- the eight bytes are compared before
# anything is written, and the offset is now checked to fall inside the arm64
# __text section first, which the raw offset never was.
#
# Unlike the other eight edits this one is complementary rather than
# load-bearing: without it the game still launches, plays and saves, so a
# mismatch warns instead of aborting.
JB_FUNC_FILEOFF = 19016508
JB_FUNC_ORIG = bytes.fromhex("ff0303d1f44f0aa9")
JB_FUNC_PATCH = struct.pack("<II", 0x52800000, 0xD65F03C0)  # mov w0,#0 ; ret
JB_FUNC_LABEL = "neutralise the jailbreak detection function (arm64)"

KNOWN_FLAGS = {
    "--no-local-save",
    "--no-persist-chapter",
    "--no-tutorial-guards",
    "--no-profile-save",
    "--no-boot-spinner-fix",
    "--kill-spinner",
    "--fail-network",
    "--verify",
    "--verify-local-save",
    "--no-force-prologue-skip",   # former name of --no-tutorial-guards
    "--help",
}

USAGE = """usage: patch_tasm2.py [flags] <input_binary> <output_binary>
       patch_tasm2.py --verify [flags] <patched_binary>

flags:
  --no-local-save          leave the 17 save objects server-persisted
  --no-persist-chapter     do not carry the story chapter in ud_QuestManager
  --no-tutorial-guards     let the tutorial bitmask be wiped on restore
  --no-profile-save        leave save object 16 unwritable
  --no-boot-spinner-fix    leave the home-menu spinner with no way to be hidden
  --kill-spinner           remove the waiting spinner (BREAKS the skills menu)
  --fail-network           report the network as unreachable at all 50 call
                           sites, so every request fails at once instead of
                           waiting for a timeout (not yet device-tested)
  --verify                 re-check every edit on an already-patched binary
  --verify-local-save      re-check the local-save edit only
  --help, -h               this text

  --no-force-prologue-skip is accepted as the former name of
  --no-tutorial-guards. Any other unknown flag is an error, so a typo cannot
  silently drop an edit."""


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


def text_section(data):
    """
    (vmaddr, file_offset, size) of the arm64 __text, or (None, None, None).

    Every site lookup goes through this rather than indexing the section dict,
    so a slice without __text produces the same clean message as every other
    malformed input instead of a KeyError traceback.
    """
    base, _size = arm64_slice_off(data)
    if base is None:
        return None, None, None
    sects = arm64_sections(data, base)
    if "__text" not in sects:
        return None, None, None
    return sects["__text"]


def aligned_hits(text, sig):
    """
    Every 4-byte-aligned occurrence of `sig` in `text`.

    arm64 instructions are all four bytes and __text starts aligned, so a match
    at an odd offset is not an instruction sequence -- it is the tail of one
    instruction plus the head of the next. Writing there corrupts both, and a
    plain `find` loop would have reported that as a successful patch and let
    --verify confirm it.
    """
    hits, i = [], 0
    while True:
        i = text.find(sig, i)
        if i < 0:
            break
        if i % 4 == 0:
            hits.append(i)
        i += 1
    return hits


PROFILE_SKIP_WORD = 0x52800000          # mov w0, #0
# The predicate `bl` sits this far before the ADD that forms the string address.
PROFILE_SKIP_BACK = 0x24
# An ADRP and the ADD that completes it are emitted together. Anything further
# apart is a stale page left in the register table by an unrelated function,
# not a reference -- and __cstring packs many strings onto one page, so a stale
# entry plus a coincidental immediate can form the right address by accident.
# Eight instructions is generous for this compiler.
ADRP_ADD_WINDOW = 8 * 4


def find_profile_skip_site(data, accept_patched=False):
    """
    Locate the `bl <predicate>` that guards UI_DOWNLOADING_PROFILE, through the
    single reference to the string. Returns (file_offset, error).

    On the 1.3.1 binary this resolves to 0x1000ab7b8.

    Candidates are collected rather than taken first-come, and exactly one must
    survive both filters -- the ADRP/ADD proximity window and "the word 0x24
    earlier really is a BL". Taking the first match would patch a wrong call
    site in silence if a stale register value ever produced one.

    `accept_patched` widens the second filter to also accept a site already
    holding `mov w0, #0`, so verification can re-locate a patched binary. It is
    off while patching on purpose: `mov w0, #0` is one of the commonest words
    in an arm64 image and is not a call, so accepting it there would let a
    coincidence count as a rival call site and abort a build that the old
    first-match locator patched correctly.
    """
    base, size = arm64_slice_off(data)
    if base is None:
        return None, "no arm64 slice"
    sects = arm64_sections(data, base)
    if "__cstring" not in sects or "__text" not in sects:
        return None, "missing __cstring or __text"
    cs_addr, cs_off, cs_size = sects["__cstring"]
    tx_addr, tx_off, tx_size = sects["__text"]

    # 1) virtual address of the string, which must be unique and start-aligned
    blob = bytes(data[cs_off:cs_off + cs_size])
    i = blob.find(b"UI_DOWNLOADING_PROFILE\x00")
    if i < 0:
        return None, "UI_DOWNLOADING_PROFILE not found in __cstring"
    if i != 0 and blob[i - 1] != 0:
        return None, "UI_DOWNLOADING_PROFILE is not at a string boundary"
    if blob.find(b"UI_DOWNLOADING_PROFILE\x00", i + 1) >= 0:
        return None, "UI_DOWNLOADING_PROFILE occurs more than once in __cstring"
    sva = cs_addr + i

    # 2) every ADRP+ADD pair in __text that forms that address
    text = bytes(data[tx_off:tx_off + tx_size])
    n = tx_size // 4
    insns = struct.unpack_from("<%dI" % n, text, 0)
    regpage = {}        # reg -> (page, pc of the ADRP that set it)
    adds = []
    for k in range(n):
        insn = insns[k]
        pc = tx_addr + k * 4
        if (insn & 0x9F000000) == 0x90000000:  # ADRP
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7FFFF
            imm = (immhi << 2 | immlo)
            if imm & (1 << 20):
                imm -= (1 << 21)
            regpage[insn & 0x1F] = ((pc & ~0xFFF) + (imm << 12), pc)
        elif (insn & 0xFF000000) == 0x91000000:  # ADD immediate
            rn = (insn >> 5) & 0x1F
            if rn in regpage:
                page, adrp_pc = regpage[rn]
                imm = (insn >> 10) & 0xFFF
                if (insn >> 22) & 1:
                    imm <<= 12
                if page + imm == sva and pc - adrp_pc <= ADRP_ADD_WINDOW:
                    adds.append(pc)

    # 3) the predicate `bl` sits PROFILE_SKIP_BACK before that ADD
    sites = []
    for add_pc in adds:
        call_off = tx_off + (add_pc - PROFILE_SKIP_BACK - tx_addr)
        if call_off < tx_off or call_off + 4 > tx_off + tx_size:
            continue
        word = struct.unpack("<I", data[call_off:call_off + 4])[0]
        if ((word & 0xFC000000) == 0x94000000
                or (accept_patched and word == PROFILE_SKIP_WORD)):
            sites.append(call_off)
    if len(sites) != 1:
        return None, (f"expected 1 call site, found {len(sites)} "
                      f"(from {len(adds)} string references)")
    return sites[0], None


def patch_profile_skip(m):
    """
    Main patch. Just before displaying UI_DOWNLOADING_PROFILE, the update loop
    calls a shared predicate ("do we need to download the profile?"). We replace
    that `bl` with `mov w0, #0`, so the following `cbz w0` is always taken and
    the game emits UI_FIRST_CHECK instead (its native "nothing to download"
    path) and carries on.

    Only this one call site is touched; the shared predicate itself is called
    from ~50 other places and is left untouched.

    Returns (ok, file_offset, error); nothing is written on error.
    """
    off, err = find_profile_skip_site(m)
    if err:
        return False, None, err
    m[off:off + 4] = struct.pack("<I", PROFILE_SKIP_WORD)
    return True, off, None


def verify_profile_skip(data):
    """
    Check the main patch on an already-patched binary: the call site must
    re-locate and hold `mov w0, #0` instead of the original `bl`.

    Without this the one edit whose absence aborts the build was also the one
    edit never re-checked on the binary that ships.
    """
    off, err = find_profile_skip_site(data, accept_patched=True)
    if err:
        return [f"profile skip: {err}"]
    word = struct.unpack("<I", data[off:off + 4])[0]
    if word != PROFILE_SKIP_WORD:
        return [f"profile skip: call site holds {word:#010x}, expected "
                f"{PROFILE_SKIP_WORD:#010x} (mov w0,#0)"]
    return []


def jb_func_in_text(data):
    """True when JB_FUNC_FILEOFF lands inside the arm64 __text section."""
    base, size = arm64_slice_off(data)
    if base is None:
        return False
    sects = arm64_sections(data, base)
    if "__text" not in sects:
        return False
    _tx_addr, tx_off, tx_size = sects["__text"]
    return tx_off <= JB_FUNC_FILEOFF and JB_FUNC_FILEOFF + 8 <= tx_off + tx_size


def verify_jb_func(data):
    """Informational: the jailbreak edit is complementary, so this never
    aborts a build on its own -- see the note next to JB_FUNC_FILEOFF."""
    if not jb_func_in_text(data):
        return [f"{JB_FUNC_LABEL}: offset {JB_FUNC_FILEOFF} is outside the "
                f"arm64 __text section"]
    if bytes(data[JB_FUNC_FILEOFF:JB_FUNC_FILEOFF + 8]) != JB_FUNC_PATCH:
        return [f"{JB_FUNC_LABEL}: not patched at the expected offset"]
    return []


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
    tx_addr, tx_off, tx_size = text_section(m)
    if tx_off is None:
        return [], "no arm64 __text section"
    text = bytes(m[tx_off:tx_off + tx_size])

    label, sig = LOCAL_SAVE_SITE
    hits = aligned_hits(text, sig)
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
    tx_addr, tx_off, tx_size = text_section(data)
    if tx_off is None:
        return ["no arm64 __text section"]
    text = bytes(data[tx_off:tx_off + tx_size])
    label, sig = LOCAL_SAVE_SITE
    problems = []
    if aligned_hits(text, sig):
        problems.append(f"{label}: original cbz still present")
    n = len(aligned_hits(text, sig[:4] + LOCAL_SAVE_STORE))
    if n != 1:
        problems.append(f"{label}: expected 1 patched site, found {n}")
    return problems


def verify_chapter(data):
    """
    Same, for the chapter patch: both original words must be gone and both
    rewritten words present exactly once, in the same instruction pair.
    """
    tx_addr, tx_off, tx_size = text_section(data)
    if tx_off is None:
        return ["no arm64 __text section"]
    text = bytes(data[tx_off:tx_off + tx_size])
    problems = []
    sites = list(CHAPTER_SITES) + [
        (CHAPTER_LOCAL_SITE[0], CHAPTER_LOCAL_SITE[1], 0,
         struct.unpack("<I", CHAPTER_LOCAL_STORE)[0]),
    ]
    for label, sig, idx, word in sites:
        if aligned_hits(text, sig):
            problems.append(f"{label}: original instruction still present")
        patched = bytearray(sig)
        patched[idx * 4:idx * 4 + 4] = struct.pack("<I", word)
        n = len(aligned_hits(text, bytes(patched)))
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
# regressed from 132926 to 62 on device while every other object round-tripped.
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
    tx_addr, tx_off, tx_size = text_section(m)
    if tx_off is None:
        return [], "no arm64 __text section"
    text = bytes(m[tx_off:tx_off + tx_size])

    sites = list(CHAPTER_SITES) + [
        (CHAPTER_LOCAL_SITE[0], CHAPTER_LOCAL_SITE[1], 0,
         struct.unpack("<I", CHAPTER_LOCAL_STORE)[0]),
    ]

    planned = []
    for label, sig, idx, word in sites:
        hits = aligned_hits(text, sig)
        if len(hits) != 1:
            return [], f"{label}: expected 1 match, found {len(hits)}"
        planned.append((label, tx_off + hits[0] + idx * 4, word))

    done = []
    for label, off, word in planned:
        m[off:off + 4] = struct.pack("<I", word)
        done.append((label, off))
    return done, None


# --- the tutorial-bitmask guards --------------------------------------------
#
# Two paths threw the restored bitmask away, and device data caught both.
#
#     0x1003cc5f4   cbz w0, +0x14      ->  nop
#         The tutorial deserialiser calls 0x1001f9388 ("chapter != 0") and,
#         when the chapter is 0, branches to its own `str wzr,[x19,#4]`. On a
#         fresh install the chapter is 0, so the saved value was read back and
#         discarded in the same breath.
#
#     0x1003cc5b8   str wzr, [x0, #4]  ->  nop
#         CTutorialMgr::Reset is `str wzr,[x0,#4] ; ret` -- it zeroes the whole
#         bitmask. Its single caller is the tail of the script dispatcher at
#         0x1001205ec, i.e. the game's own scripts ask for it, and one of them
#         runs every time the opening sequence plays: the restore puts 137022
#         back and the script wipes it to 0 seconds later, which is exactly the
#         137022 -> 62 seen on device with the deserialiser already patched.
#         Neutralise the store and the method becomes a no-op, so nothing can
#         discard tutorial progress once it is earned.
#
# Measured on device: 132926 -> 62 before, 132926 -> 153406 -> 161790 after.
# The two "before" values in this block are two different runs -- 132926
# (0x2073e, nine steps) and 137022 (0x2173e, ten) -- and both fall to the same
# 62 (0x3e, five), because after a wipe the tutorial re-earns the same first
# five steps whatever had been banked.
#
# These guards do NOT skip the prologue, and nothing here does. A third edit
# that did (0x1001fc868 cbnz -> b) shipped for a while and has been REMOVED: it
# cost the game its opening cinematic, the first thing story01_mission01 plays,
# and the profile save patch made it unnecessary. On a fresh install the
# chapter is 0, so the prologue runs exactly once; completing it writes 1
# through 0x1001edd54, and ud_QuestManager.sav restores that on every later
# launch, so the request never fires again.
#
# Disable with --no-tutorial-guards.

TUTORIAL_GUARD_SITES = [
    ("never wipe the tutorial bitmask on restore (0x1003cc5f4)",
     bytes.fromhex("66b3f897a0000034e00314aa"), 1, 0xD503201F),  # nop
    ("neuter CTutorialMgr::Reset (0x1003cc5b8)",
     bytes.fromhex("c0035fd61f0400b9c0035fd6080440b9"), 1, 0xD503201F),  # nop
]


def _apply_sites(m, sites, what):
    """Apply a list of (label, signature, word_index, replacement) sites."""
    tx_addr, tx_off, tx_size = text_section(m)
    if tx_off is None:
        return [], "no arm64 __text section"
    text = bytes(m[tx_off:tx_off + tx_size])

    planned = []
    for label, sig, idx, word in sites:
        hits = aligned_hits(text, sig)
        if len(hits) != 1:
            return [], f"{label}: expected 1 match, found {len(hits)}"
        planned.append((label, tx_off + hits[0] + idx * 4, word))

    done = []
    for label, off, word in planned:
        m[off:off + 4] = struct.pack("<I", word)
        done.append((label, off))
    return done, None


def _verify_sites(data, sites):
    tx_addr, tx_off, tx_size = text_section(data)
    if tx_off is None:
        return ["no arm64 __text section"]
    text = bytes(data[tx_off:tx_off + tx_size])
    problems = []
    for label, sig, idx, word in sites:
        if aligned_hits(text, sig):
            problems.append(f"{label}: original instruction still present")
        patched = bytearray(sig)
        patched[idx * 4:idx * 4 + 4] = struct.pack("<I", word)
        n = len(aligned_hits(text, bytes(patched)))
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


# --- the waiting spinner: TRIED, HARMFUL, OFF BY DEFAULT ---------------------
#
# The spinner can sit on screen forever offline -- home menu, skills page, and
# worst in the shop after a failed purchase. It is driven by a mask of reasons
# at progressMgr+0x330: 0x1001e7b94 sets bit N and shows the widget,
# 0x1001e7f3c clears bit N and hides it once the mask reaches 0. Some requests
# never answer offline, so their bit is never cleared.
#
# Turning 0x1001e7b94 into `ret` removes the spinner -- and breaks the menus.
# Device report: the skills page no longer loads its content at all.
#
# The reasoning that shipped it was wrong in a specific, instructive way. It
# checked the *calling convention* -- the function returns nothing meaningful
# and several callers reach it by `b`, so no caller is left holding a bogus
# value -- and concluded "safe to skip". That is a proof about the return
# value, not about the body. The body opens with
#
#     0x1001e7bc4   bl 0x1001e78b0
#
# a 185-instruction routine that touches the managers at 0x1010740c0,
# 0x101074100 and 0x101074210. Whatever that does, the menus need it. "Void" is
# not the same as "no side effects", and the spinner was carrying real
# information: those pages genuinely are still loading.
#
# Kept here because the analysis is sound and the site is right, should anyone
# want to work on the widget rather than delete it -- the promising direction
# is the mask, not the spinner: 0x1001e7d80 (`ldr w8,[x19,#0x32c]; cbz w8`)
# guards the "Waiting.Mask" input blocker separately from the spinner itself,
# so the feedback could stay while taps pass through. Not attempted.
#
# --kill-spinner enables it. Do not, unless you are re-testing this.

SPINNER_SITES = [
    ("never show the network waiting spinner (0x1001e7b94) -- BREAKS MENUS",
     bytes.fromhex("ffc304d1f65710a9f44f11a9fd7b12a9fd830491f30300aa14d0bf12"),
     0, 0xD65F03C0),   # ret
]


def patch_spinner(m):
    return _apply_sites(m, SPINNER_SITES, "spinner")


def verify_spinner(data):
    return _verify_sites(data, SPINNER_SITES)


# --- telling the game the network is down ------------------------------------
#
# The spinner is a symptom, not the disease. What raises it is a request that
# was sent and never answered, and what answers a request offline is the HTTP
# layer giving up on a host that no longer resolves -- slowly. Deleting the
# widget hides the wait; refusing to start the wait removes it.
#
# The game already knows how to be offline. 0x100346c10 is its reachability
# predicate: it asks Reachability for the current status, treats 1 and 2
# (wifi, wwan) as reachable, caches the answer in the byte at 0x10107a2c8 for
# 1000 ms, and returns it:
#
#     0x100346cc8   strb w8, [x9, #0x2c8]     ; cache
#     0x100346ccc   cmp  w8, #0
#     0x100346cd0   cset w0, ne               ->  mov w0, #0
#     0x100346cd4   ldp  x29, x30, [sp, #0x30]
#
# Fifty call sites reach it, and forty-four branch on w0 within three
# instructions. The other six keep it in a callee-saved register across an
# ObjC release and then branch on it; none does arithmetic with it. Every one
# of the twenty-eight containing functions is a network feature -- login and
# datacentre selection, the shop and IAP, leaderboards, friends and mail,
# analytics, the news/forum/support buttons, the cloud-profile upload in the
# save manager. Nothing in the local mission server (0x100416000..0x100422000)
# and nothing on the save/restore path calls it, so the edit cannot reach what
# took eleven builds to get right.
#
# The predicate is already how this patcher unblocks the game: the main edit
# at 0x1000ab7b8 replaces one `bl` to this very function with `mov w0, #0`, and
# the menu it lands in is Gameloft's own no-network path. This edit is that
# one, generalised from a single call site to all fifty.
#
# What it buys, concretely, is the skills screen. SP_ShowSkillTree
# (0x1003eafe8) calls 0x1000bf130, which asks whether goods categories 6, 7 and
# 10 are loaded, raises the spinner (reason 3) when they are not, starts the
# fetch, and then:
#
#     0x1000bf21c   bl   0x100346c10
#     0x1000bf220   tbz  w0, #0, 0x1000bf2b8   ; unreachable -> state 3
#     0x1000bf224   mov  w8, #1                ; reachable   -> state 1
#
# State 1 is "waiting for the answer", and offline the answer is a timeout.
# State 3 is the offline branch: the manager's update (0x1000b1cd0, a jump
# table on the state at +0x88) runs 3 -> 4 -> -3 without any I/O, and the
# handlers for states -5, -4 and -3 all call 0x1000b1c0c, which is the only
# code in the binary that clears spinner reason 3. So the same screen, the same
# widget, the same clearing path -- reached in a frame instead of a timeout.
#
# One visible change beyond the waits. The boot flow at 0x10006fad0 reads
# "network available OR the profile file existed at startup"; with neither, it
# shows UI_cloud_data_reminder and its OK button sets the state the other
# branch jumped to (0x100071108: `mov w8,#0xd ; str w8,[x1,#0xb4]`). So a
# genuinely first launch gets one extra dialog, and no launch after that, since
# the profile save patch makes the file exist.
#
# Measured on this binary: the cached byte at 0x10107a2c8 is read and written
# only inside this function (0x100346c44, 0x100346cb4, 0x100346cc8), so forcing
# the return value cannot desynchronise anything from it, and the three-word
# anchor below occurs exactly once in __text (the first two words alone: 63
# times).
#
# Opt-in with --fail-network until it has been through a device run.

NETWORK_FAIL_SITES = [
    ("report the network as unreachable everywhere (0x100346cd0)",
     bytes.fromhex("1f010071e0079f1afd7b43a9"), 1, 0x52800000),   # mov w0,#0
]


def patch_network_fail(m):
    return _apply_sites(m, NETWORK_FAIL_SITES, "network failure")


def verify_network_fail(data):
    return _verify_sites(data, NETWORK_FAIL_SITES)


# --- the boot spinner the main patch left standing ---------------------------
#
# The waiting widget on the home menu, the one that is still there when you
# press Start, is not one of the fifty network-gated ones. It is reason 12, and
# this patcher is why it never goes away.
#
# The main-menu state machine shows it once, from a single block:
#
#     0x1000ab780   ldrb w9,  [x8, #0xb9]      ; already showing? then skip
#     0x1000ab788   ldrb w10, [x8, #0xba]
#     0x1000ab7b0   mov  w20, #1
#     0x1000ab7b4   strb w20, [x8, #0xba]      ; flag A := "the spinner is up"
#     0x1000ab7b8   bl   0x100346c10           ; -> mov w0,#0   (the main patch)
#     0x1000ab7c0   cbz  w0, 0x1000abc1c       ;   offline branch
#     0x1000ab7c4   strb w20, [x8, #0xbb]      ; flag B := 1, then
#                                              ;   UI_DOWNLOADING_PROFILE
#     0x1000abc1c   strb wzr, [x8, #0xbb]      ; flag B := 0, then UI_FIRST_CHECK
#
# Both branches then fall into the same `ShowWaiting(12)` at 0x1000abce4 with
# their own label. So offline the spinner goes up with flag B at zero -- and
# flag B is what both of its hides are gated on:
#
#     0x1000ab600   ldrb w9, [x8, #0xba] ; cbz -> skip      (state machine)
#     0x1000ab60c   ldrb w9, [x9, #0xbb] ; cbz -> skip
#     0x1000ab614   strb wzr, [x8, #0xba] ... HideWaiting(12) at 0x1000ab62c
#
#     0x1000a8a60   ldrb w9, [x8, #0xba] ; cbz -> skip      (menu destructor)
#     0x1000a8a68   strb wzr, [x8, #0xba]                   ; clears flag A
#     0x1000a8a70   ldrb w8, [x8, #0xbb] ; cbz -> skip
#     0x1000a8a8c   HideWaiting(12)
#
# Neither can fire. Worse, the destructor clears flag A on its way past the
# second test, so once the menu is torn down the widget is orphaned: the show
# block will not show it again (flag A is 0) and nothing will ever take it
# down. The only two unconditional `HideWaiting(12)` sites in the binary are
# 0x1000cea78 and 0x10028fb94, both inside functions with no direct caller --
# response callbacks that offline never run.
#
# The fix is to make the offline branch arm the hide exactly as the online one
# does: store w20 instead of wzr. `strb w20,[x8,#0xbb]` is the word already at
# 0x1000ab7c4 (0x3902ed14), the same base register and the same offset, so this
# writes the instruction the other branch already carries.
#
# w20 is 1 with no path in which it is not: `mov w20,#1` at 0x1000ab7b0 is four
# instructions earlier, and 0x1000ab7c0 is the *only* branch anywhere in __text
# that lands on 0x1000abc1c.
#
# Measured on this binary: the byte at 0x10110b0bb is written at 0x1000ab7c4
# and 0x1000abc1c and read at 0x1000ab60c and 0x1000a8a70 -- nowhere else. That
# is from scanning every one of the 952 functions that reference the page for
# any byte access at 0xb9, 0xba or 0xbb, not from a signature match, because a
# linear register sweep misses 0x1000abc1c: its ADRP is 0x460 bytes back, on
# the other side of the branch. Setting the flag can therefore do one thing
# and one thing only -- let the game's own hide run.
#
# On by default: it repairs an invariant the main patch broke. --no-boot-
# spinner-fix restores the v1.0 behaviour.

# Seven words, not the two it takes to be unique before the edit. The two
# branches emit the same four instructions -- `strb`, `adrp x8,0x101074000`,
# `ldr x0,[x8,#0x340]`, `adrp x1,0x100e1d000` -- and both ADRPs sit on the same
# 4 KiB page, so they encode identically. A shorter signature locates the site
# correctly and then makes --verify count two patched sites, because the edit
# turns this block into a copy of the other one. The seventh word is the label:
# `add x2,x2,#0x917` (UI_FIRST_CHECK) against #0x900 (UI_DOWNLOADING_PROFILE).
BOOT_SPINNER_SITES = [
    ("let the offline branch arm the boot spinner's own hide (0x1000abc1c)",
     bytes.fromhex("1fed0239487e00b000a141f9816b00d0"
                   "21081f91a26b0090425c2491"), 0, 0x3902ED14),
]


def patch_boot_spinner(m):
    return _apply_sites(m, BOOT_SPINNER_SITES, "boot spinner")


def verify_boot_spinner(data):
    return _verify_sites(data, BOOT_SPINNER_SITES)


# --- an edit that must NOT be there -----------------------------------------
#
# 0x1001fc868 cbnz -> b shipped for a while and was removed (see the tutorial
# guards above): it cost the game its opening cinematic. Every check in this
# file asserts that an expected edit is *present*, so none of them could tell a
# binary built by this patcher from one built by the version that still carried
# that edit. This one asserts the absence.
#
# On the 1.3.1 binary the word at 0x1001fc868 is 0x35000068 (`cbnz w8, +0xc`),
# unchanged in the shipped v1.0 release. Only a `b` there is a failure; any
# other word means this is not the analysed build and there is nothing to
# assert, so the check cannot raise a false alarm.
PROLOGUE_SKIP_VA = 0x1001fc868
PROLOGUE_SKIP_LABEL = "the removed prologue-skip edit is absent (0x1001fc868)"


def verify_hosts(data):
    """
    No live Gameloft host left. Three checks, because each catches what the
    others miss: the URL form finds any gameloft.com host carrying a scheme,
    the HOSTS list finds the ones we know about with or without one, and the
    bare form finds a host nobody listed appearing without a scheme.

    Two things legitimately survive on the 1.3.1 binary and must not be
    reported, which is why a plain `grep gameloft\\.com` cannot do this job:
    the obfuscated `jngbmfbds_gameloft.com` (an underscore, not a dot, so it
    is not a hostname as written) and the `<your_gl_account>@gameloft.com`
    placeholder. Build paths are excluded the same way the rewriter excludes
    them.

    Shared by the patch path and --verify, so the check that gates the release
    is the same code that gated the build.
    """
    problems = []
    urls = re.findall(rb"https?://[a-z0-9.-]*gameloft\.com", data)
    known = [h for h in HOSTS if h in data]
    bare = []
    for mt in re.finditer(rb"[a-z0-9][a-z0-9.-]*\.gameloft\.com", data):
        ctx = data[max(0, mt.start() - 130):mt.end() + 130]
        if b"/Users/gameloft" in ctx or b"<your_gl" in ctx:
            continue
        bare.append(mt.group())
    if urls or known or bare:
        problems.append(f"{len(urls)} Gameloft URLs, {len(known)} known "
                        f"hostnames and {len(bare)} unlisted hostnames "
                        f"still live")
        for h in dict.fromkeys(known + bare):
            problems.append(f"  still present: {h.decode()}")
    return problems


def verify_prologue_not_skipped(data):
    tx_addr, tx_off, tx_size = text_section(data)
    if tx_off is None:
        return ["no arm64 __text section"]
    off = tx_off + (PROLOGUE_SKIP_VA - tx_addr)
    if off < tx_off or off + 4 > tx_off + tx_size:
        return []
    word = struct.unpack("<I", data[off:off + 4])[0]
    if (word & 0xFC000000) == 0x14000000:      # B -- the removed edit is in
        return [f"{PROLOGUE_SKIP_LABEL}: found `b` ({word:#010x}), so this "
                f"binary carries the prologue-skip edit and has lost its "
                f"opening cinematic"]
    return []


def patch_tutorial_guards(m):
    return _apply_sites(m, TUTORIAL_GUARD_SITES, "tutorial guards")


def verify_tutorial_guards(data):
    return _verify_sites(data, TUTORIAL_GUARD_SITES)


def patch(data, local_save=True, chapter=True, tutorial_guards=True,
          profile_save=True, boot_spinner=True, spinner=False,
          network_fail=False):
    """
    Apply the edits and return (patched_bytes, report).

    `report` is a dict rather than a positional tuple: there are eleven
    independent results to carry, and threading a twelfth through a tuple is
    how a caller ends up silently reading the wrong one.
    """
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

    # Second pass. The scan above bounds a printable run at 130 characters, so
    # a host straddling a run boundary is never offered to it. Match the host
    # bytes directly to catch those: same bytes, same length, same in-place
    # write, so this is a safety net rather than a different edit -- and it is
    # what makes the "no live host left" check at the end of main() honest for
    # bare hostnames as well as full URLs.
    #
    # One snapshot is enough: every replacement is the same length as what it
    # replaces and contains no host bytes, so no earlier write can create or
    # destroy a later occurrence.
    snapshot = bytes(m)
    for host in HOSTS:
        repl = b"x" * (len(host) - len(b".invalid")) + b".invalid"
        if len(repl) != len(host):
            # The first pass raises on a length change; this one must too. A
            # replacement shorter than what it replaces RESIZES the bytearray
            # and shifts every Mach-O offset after it -- main()'s size check
            # would only notice long after the signature edits had run against
            # a shifted buffer.
            raise RuntimeError(f"host replacement length changed: "
                               f"{len(host)} -> {len(repl)}")
        i = 0
        while True:
            i = snapshot.find(host, i)
            if i < 0:
                break
            ctx = snapshot[max(0, i - 130):i + len(host) + 130]
            if b"/Users/gameloft" in ctx or b"<your_gl" in ctx:
                i += len(host)
                continue
            m[i:i + len(host)] = repl
            patches.append((i, host, repl))
            i += len(host)

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
    fn_ok = False
    if (jb_func_in_text(m)
            and bytes(m[JB_FUNC_FILEOFF:JB_FUNC_FILEOFF + 8]) == JB_FUNC_ORIG):
        m[JB_FUNC_FILEOFF:JB_FUNC_FILEOFF + 8] = JB_FUNC_PATCH
        fn_ok = True

    # --- MAIN PATCH: skip the profile download ---
    skip_ok, skip_off, skip_err = patch_profile_skip(m)

    # --- LOCAL SAVE: persist every save object to ud_<Name>.sav ---
    ls_sites, ls_err = patch_local_save(m) if local_save else ([], None)

    # --- optional: carry the story chapter in the local save ---
    ch_sites, ch_err = patch_chapter_persist(m) if chapter else ([], None)

    # --- optional: keep the tutorial bitmask from being wiped ---
    tg_sites, tg_err = (patch_tutorial_guards(m) if tutorial_guards
                        else ([], None))

    # --- optional: let the local profile object reach disk ---
    ps_sites, ps_err = patch_profile_save(m) if profile_save else ([], None)

    # --- let the home-menu spinner be hidden again ---
    bs_sites, bs_err = patch_boot_spinner(m) if boot_spinner else ([], None)

    # --- optional: never show the network waiting spinner ---
    sp_sites, sp_err = patch_spinner(m) if spinner else ([], None)

    # --- optional: answer "no network" everywhere instead of timing out ---
    nf_sites, nf_err = patch_network_fail(m) if network_fail else ([], None)

    return bytes(m), {
        "strings": patches,
        "jb_paths": jb,
        "jb_func": fn_ok,
        "skip": (skip_ok, skip_off, skip_err),
        "local_save": (ls_sites, ls_err),
        "chapter": (ch_sites, ch_err),
        "tutorial_guards": (tg_sites, tg_err),
        "profile_save": (ps_sites, ps_err),
        "boot_spinner": (bs_sites, bs_err),
        "spinner": (sp_sites, sp_err),
        "network_fail": (nf_sites, nf_err),
    }


def main():
    argv = sys.argv[1:]
    if {"--help", "-h"} & set(argv):
        print(USAGE)
        return 0

    args = [a for a in argv if not a.startswith("-")]
    flags = {a for a in argv if a.startswith("-")}

    unknown = sorted(flags - KNOWN_FLAGS)
    if unknown:
        # A silently ignored typo yields a binary missing an edit nobody asked
        # to skip -- exactly the failure the rest of this script is built to
        # make impossible.
        print(f"ERROR: unknown flag(s): {' '.join(unknown)}")
        print(f"known flags: {' '.join(sorted(KNOWN_FLAGS))}")
        return 1

    local_save = "--no-local-save" not in flags
    chapter = "--no-persist-chapter" not in flags
    # --no-force-prologue-skip was this flag's name while it also carried an
    # edit that skipped the prologue. That edit is gone; the old name keeps
    # working so an existing workflow input does not silently change meaning.
    tutorial_guards = not (flags & {"--no-tutorial-guards",
                                    "--no-force-prologue-skip"})
    profile_save = "--no-profile-save" not in flags
    boot_spinner = "--no-boot-spinner-fix" not in flags
    spinner = "--kill-spinner" in flags
    network_fail = "--fail-network" in flags

    if flags & {"--verify", "--verify-local-save"}:
        if len(args) != 1:
            print(USAGE)
            return 1
        data = open(args[0], "rb").read()
        problems, checked, notes = [], [], []
        full = "--verify-local-save" not in flags
        if full:
            problems += verify_profile_skip(data)
            checked.append("skip UI_DOWNLOADING_PROFILE -> UI_FIRST_CHECK")
            problems += verify_prologue_not_skipped(data)
            checked.append(PROLOGUE_SKIP_LABEL)
            problems += verify_hosts(data)
            checked.append("no live Gameloft host left")
        if local_save:
            problems += verify_local_save(data)
            checked.append(LOCAL_SAVE_SITE[0])
        if chapter and full:
            problems += verify_chapter(data)
            checked += [label for label, _s, _i, _w in CHAPTER_SITES]
            checked.append(CHAPTER_LOCAL_SITE[0])
        if tutorial_guards and full:
            problems += verify_tutorial_guards(data)
            checked += [label for label, _s, _i, _w in TUTORIAL_GUARD_SITES]
        if profile_save and full:
            problems += verify_profile_save(data)
            checked += [label for label, _s, _i, _w in PROFILE_SAVE_SITES]
        if boot_spinner and full:
            problems += verify_boot_spinner(data)
            checked += [label for label, _s, _i, _w in BOOT_SPINNER_SITES]
        if spinner and full:
            problems += verify_spinner(data)
            checked += [label for label, _s, _i, _w in SPINNER_SITES]
        if network_fail and full:
            problems += verify_network_fail(data)
            checked += [label for label, _s, _i, _w in NETWORK_FAIL_SITES]
        if full:
            # Complementary, so it is reported and never fatal.
            notes += verify_jb_func(data)
            if not notes:
                checked.append(JB_FUNC_LABEL)
        for p in problems:
            print(f"FAIL: {p}")
        for n in notes:
            print(f"warn: {n}")
        if problems:
            return 1
        print(f"verified in {args[0]}:")
        for c in checked:
            print(f"  ok  {c}")
        return 0

    if len(args) != 2:
        print(USAGE)
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

    out, report = patch(data, local_save=local_save, chapter=chapter,
                        tutorial_guards=tutorial_guards,
                        profile_save=profile_save, boot_spinner=boot_spinner,
                        spinner=spinner, network_fail=network_fail)
    patches = report["strings"]
    jb = report["jb_paths"]
    fn_ok = report["jb_func"]
    skip_ok, skip_off, skip_err = report["skip"]
    ls_sites, ls_err = report["local_save"]
    ch_sites, ch_err = report["chapter"]
    tg_sites, tg_err = report["tutorial_guards"]
    ps_sites, ps_err = report["profile_save"]
    sp_sites, sp_err = report["spinner"]
    bs_sites, bs_err = report["boot_spinner"]
    nf_sites, nf_err = report["network_fail"]

    if boot_spinner:
        if bs_err:
            print(f"\n>>> ERROR: boot spinner fix NOT applied: {bs_err}")
        else:
            print("\n>>> BOOT SPINNER patched: the home-menu spinner can be "
                  "hidden again by the game's own code")
            for label, off in bs_sites:
                print(f"    patched   @ file offset {off:<10} {label}")
    else:
        print("\n>>> boot spinner fix skipped (--no-boot-spinner-fix): the "
              "home-menu spinner will stay up for good")

    if network_fail:
        if nf_err:
            print(f"\n>>> ERROR: network failure patch NOT applied: {nf_err}")
        else:
            print("\n>>> NETWORK reported unreachable: every request now fails "
                  "at once instead of waiting for a timeout")
            for label, off in nf_sites:
                print(f"    patched   @ file offset {off:<10} {label}")
    else:
        print("\n>>> network left as the device reports it (--fail-network to "
              "force 'no network' everywhere)")

    if spinner:
        if sp_err:
            print(f"\n>>> ERROR: spinner patch NOT applied: {sp_err}")
        else:
            print("\n>>> SPINNER patched: never shown -- WARNING, this breaks "
                  "the skills menu; see the comment in this file")
            for label, off in sp_sites:
                print(f"    patched   @ file offset {off:<10} {label}")
    else:
        print("\n>>> spinner left in place (it is load feedback, not noise)")

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

    if tutorial_guards:
        if tg_err:
            print(f"\n>>> ERROR: tutorial guards NOT applied: {tg_err}")
        else:
            print("\n>>> TUTORIAL GUARDS patched: the tutorial bitmask is "
                  "never wiped, on either path that used to discard it")
            print("    (the prologue still plays once on a fresh install, "
                  "cinematic included)")
            for label, off in tg_sites:
                print(f"    patched   @ file offset {off:<10} {label}")
    else:
        print("\n>>> tutorial guards skipped (--no-tutorial-guards): earned "
              "tutorial progress can be discarded on restore")

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
        print(f"\n>>> ERROR: main patch (profile skip) NOT applied: {skip_err}"
              " -- the game would stay blocked")

    print(f"\n{len(jb)} jailbreak detection paths neutralised")
    if fn_ok:
        print(f"{JB_FUNC_LABEL}: patched (mov w0,#0 ; ret)")
    else:
        why = ("that offset falls outside the arm64 __text section"
               if not jb_func_in_text(data) else
               "the 8 bytes there are not the expected prologue")
        print(f"WARNING: {JB_FUNC_LABEL}: {why} (offset {JB_FUNC_FILEOFF})"
              " -- NOT patched.")
        print("         Jailbreak detection stays live; everything else is "
              "unaffected. This edit is the one that cannot self-locate, so a "
              "binary other than the analysed 1.3.1 will miss it.")
    print(f"\n{len(patches)} strings patched:")
    for off, s, new in patches:
        print(f"  off={off:<10} {s.decode()[:58]}")
        print(f"  {'':14} -> {new.decode()[:58]}")

    if len(out) != len(data):
        print("ERROR: size changed, aborting")
        return 1

    host_problems = verify_hosts(out)
    if host_problems:
        for p in host_problems:
            print(f"ERROR: {p}")
        return 1

    if not skip_ok:
        # the profile skip is the whole point of this build: refuse to ship a
        # binary that would not unblock anything.
        print("ERROR: main patch missing, aborting")
        return 1

    if chapter and ch_err:
        print("ERROR: chapter persistence incomplete, aborting")
        return 1

    if tutorial_guards and tg_err:
        print("ERROR: tutorial guards incomplete, aborting")
        return 1

    if profile_save and ps_err:
        print("ERROR: profile save incomplete, aborting")
        return 1

    if spinner and sp_err:
        print("ERROR: spinner patch incomplete, aborting")
        return 1

    if boot_spinner and bs_err:
        print("ERROR: boot spinner fix incomplete, aborting")
        return 1

    if network_fail and nf_err:
        print("ERROR: network failure patch incomplete, aborting")
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
