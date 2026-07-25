#!/usr/bin/env python3
"""
Minimal Mach-O / arm64 analysis toolkit for the TASM2 binary.

Deliberately dependency-light: struct + capstone. Everything is expressed in
*virtual addresses* (the arm64 slice is linked at 0x100000000), which is what
the notes in LOCAL_SAVE_DESIGN.md use.

    from machoscan import Bin
    b = Bin("AmazingSpiderMan2")
    b.find_cstring("userdata")        -> [vaddr, ...]
    b.xrefs_to(vaddr)                 -> [pc, ...]   (ADRP+ADD / ADRP+LDR)
    b.callers_of(vaddr)               -> [pc, ...]   (BL / B)
    print(b.disasm_text(vaddr, 40))
"""
import bisect
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_FUNCTION_STARTS = 0x26


class Bin:
    def __init__(self, path, arch="arm64"):
        self.path = path
        self.data = open(path, "rb").read()
        self.base = self._slice_offset(arch)
        self.sections = {}          # name -> (vaddr, fileoff, size)
        self.segments = []          # (name, vaddr, vmsize, fileoff, filesize)
        self.symbols = []           # (vaddr, name)
        self.func_starts = []       # exact, from LC_FUNCTION_STARTS
        self._indirect = None
        self._symtab_raw = None
        self._stubs = None
        self._section_reserved1 = {}
        self._parse_load_commands()
        self.text_addr, self.text_off, self.text_size = self.sections["__text"]
        self.text = self.data[self.text_off:self.text_off + self.text_size]
        self._insns = None
        self._xref_index = None
        self._call_index = None
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = False

    # ---------------------------------------------------------------- layout

    def _slice_offset(self, arch):
        magic = struct.unpack(">I", self.data[:4])[0]
        if magic != 0xCAFEBABE:
            return 0
        want = {"armv7": 12, "arm64": 16777228}[arch]
        n = struct.unpack(">I", self.data[4:8])[0]
        for i in range(n):
            cpu, sub, off, size, align = struct.unpack(
                ">iiIII", self.data[8 + i * 20:28 + i * 20])
            if cpu == want:
                return off
        raise RuntimeError(f"no {arch} slice")

    def _parse_load_commands(self):
        b = self.base
        ncmds = struct.unpack("<I", self.data[b + 16:b + 20])[0]
        p = b + 32
        for _ in range(ncmds):
            cmd, csize = struct.unpack("<II", self.data[p:p + 8])
            if cmd == LC_SEGMENT_64:
                segname = self.data[p + 8:p + 24].split(b"\0")[0].decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack(
                    "<QQQQ", self.data[p + 24:p + 56])
                self.segments.append(
                    (segname, vmaddr, vmsize, b + fileoff, filesize))
                nsects = struct.unpack("<I", self.data[p + 64:p + 68])[0]
                q = p + 72
                for _s in range(nsects):
                    name = self.data[q:q + 16].split(b"\0")[0].decode()
                    addr, size = struct.unpack("<QQ", self.data[q + 32:q + 48])
                    off = struct.unpack("<I", self.data[q + 48:q + 52])[0]
                    res1 = struct.unpack("<I", self.data[q + 60:q + 64])[0]
                    self.sections.setdefault(name, (addr, b + off, size))
                    self._section_reserved1.setdefault(name, res1)
                    q += 80
            elif cmd == LC_FUNCTION_STARTS:
                dataoff, datasize = struct.unpack("<II", self.data[p + 8:p + 16])
                self._parse_function_starts(b + dataoff, datasize)
            elif cmd == LC_DYSYMTAB:
                self._parse_dysymtab(p)
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack(
                    "<IIII", self.data[p + 8:p + 24])
                self._parse_symtab(b + symoff, nsyms, b + stroff, strsize)
            p += csize

    def _parse_function_starts(self, off, size):
        """LC_FUNCTION_STARTS: ULEB128 deltas from the image base. Exact."""
        blob = self.data[off:off + size]
        addr = self.segments[0][1] if self.segments else 0
        # __TEXT is the image base; __PAGEZERO is segment 0 in an executable.
        for name, vmaddr, vmsize, fileoff, filesize in self.segments:
            if name == "__TEXT":
                addr = vmaddr
                break
        i = 0
        out = []
        while i < len(blob):
            shift = 0
            delta = 0
            while True:
                if i >= len(blob):
                    break
                byte = blob[i]
                i += 1
                delta |= (byte & 0x7F) << shift
                shift += 7
                if not (byte & 0x80):
                    break
            if delta == 0:
                break
            addr += delta
            out.append(addr)
        self.func_starts = out

    def _parse_dysymtab(self, p):
        (ilocalsym, nlocalsym, iextdefsym, nextdefsym, iundefsym, nundefsym,
         tocoff, ntoc, modtaboff, nmodtab, extrefsymoff, nextrefsyms,
         indirectsymoff, nindirectsyms) = struct.unpack(
            "<14I", self.data[p + 8:p + 64])
        self._indirect = (self.base + indirectsymoff, nindirectsyms)

    def _build_stub_map(self):
        """__stubs entry -> imported symbol name, via the indirect symbol table."""
        if self._stubs is not None:
            return
        self._stubs = {}
        if "__stubs" not in self.sections or not self._indirect or not self._symtab_raw:
            return
        indoff, indn = self._indirect
        symoff, nsyms, stroff, strsize = self._symtab_raw
        strtab = self.data[stroff:stroff + strsize]
        addr, off, size = self.sections["__stubs"]
        # reserved1 of __stubs = index into the indirect symbol table. Recover it
        # by re-reading the section header.
        r1 = self._section_reserved1.get("__stubs", 0)
        entry = 12  # arm64 stub: adrp / ldr / br
        for i in range(size // entry):
            k = r1 + i
            if k >= indn:
                break
            symidx = struct.unpack(
                "<I", self.data[indoff + k * 4:indoff + k * 4 + 4])[0]
            if symidx & 0xC0000000 or symidx >= nsyms:
                continue
            n_strx = struct.unpack(
                "<I", self.data[symoff + symidx * 16:symoff + symidx * 16 + 4])[0]
            end = strtab.find(b"\0", n_strx)
            self._stubs[addr + i * entry] = \
                strtab[n_strx:end].decode("utf-8", "replace")

    def stub_name(self, va):
        self._build_stub_map()
        return self._stubs.get(va)

    def _parse_symtab(self, symoff, nsyms, stroff, strsize):
        self._symtab_raw = (symoff, nsyms, stroff, strsize)
        strtab = self.data[stroff:stroff + strsize]
        for i in range(nsyms):
            e = symoff + i * 16
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack(
                "<IBBHQ", self.data[e:e + 16])
            if n_strx == 0 or n_value == 0:
                continue
            end = strtab.find(b"\0", n_strx)
            name = strtab[n_strx:end].decode("utf-8", "replace")
            self.symbols.append((n_value, name))
        self.symbols.sort()
        self._sym_addrs = [a for a, _ in self.symbols]

    # ------------------------------------------------------------ addressing

    def va_to_off(self, va):
        for name, vmaddr, vmsize, fileoff, filesize in self.segments:
            if vmaddr <= va < vmaddr + vmsize and filesize:
                d = va - vmaddr
                if d < filesize:
                    return fileoff + d
        return None

    def read(self, va, n):
        off = self.va_to_off(va)
        return None if off is None else self.data[off:off + n]

    def qword(self, va):
        r = self.read(va, 8)
        return None if r is None else struct.unpack("<Q", r)[0]

    def cstring_at(self, va):
        off = self.va_to_off(va)
        if off is None:
            return None
        end = self.data.find(b"\0", off, off + 4096)
        if end < 0:
            return None
        return self.data[off:end].decode("utf-8", "replace")

    def sym_for(self, va):
        """Nearest preceding symbol, or None."""
        if not self.symbols:
            return None
        i = bisect.bisect_right(self._sym_addrs, va) - 1
        if i < 0:
            return None
        a, n = self.symbols[i]
        return (n, va - a)

    # --------------------------------------------------------------- strings

    def find_cstring(self, s, exact=True, section="__cstring"):
        """Virtual addresses of a C string. exact -> NUL-delimited on both ends."""
        if section not in self.sections:
            return []
        addr, off, size = self.sections[section]
        blob = self.data[off:off + size]
        needle = s.encode() if isinstance(s, str) else s
        out, i = [], 0
        while True:
            i = blob.find(needle, i)
            if i < 0:
                break
            ok = True
            if exact:
                ok = (i == 0 or blob[i - 1] == 0) and \
                     (i + len(needle) < size and blob[i + len(needle)] == 0)
            if ok:
                out.append(addr + i)
            i += 1
        return out

    def grep_cstrings(self, substr, section="__cstring"):
        """[(vaddr, full string)] for every C string containing substr."""
        addr, off, size = self.sections[section]
        blob = self.data[off:off + size]
        needle = substr.encode() if isinstance(substr, str) else substr
        out, i = [], 0
        while True:
            i = blob.find(needle, i)
            if i < 0:
                break
            start = blob.rfind(b"\0", 0, i) + 1
            end = blob.find(b"\0", i)
            out.append((addr + start,
                        blob[start:end].decode("utf-8", "replace")))
            i = end + 1 if end > 0 else i + 1
        return out

    # ----------------------------------------------------------- instructions

    @property
    def insns(self):
        if self._insns is None:
            n = self.text_size // 4
            self._insns = struct.unpack_from("<%dI" % n, self.text, 0)
        return self._insns

    def at(self, va):
        i = (va - self.text_addr) // 4
        return self.insns[i] if 0 <= i < len(self.insns) else None

    def _build_indexes(self):
        """One linear pass: resolve ADRP+{ADD,LDR,STR} pairs and collect BL/B."""
        if self._xref_index is not None:
            return
        xref = {}
        call = {}
        insns = self.insns
        base = self.text_addr
        page = {}
        for k, insn in enumerate(insns):
            pc = base + k * 4
            top = insn & 0x9F000000
            if top == 0x90000000:                       # ADRP
                immlo = (insn >> 29) & 3
                immhi = (insn >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= (1 << 21)
                page[insn & 0x1F] = (pc & ~0xFFF) + (imm << 12)
                continue
            if (insn & 0xFF000000) == 0x91000000:       # ADD imm (64-bit)
                rn = (insn >> 5) & 0x1F
                p = page.get(rn)
                if p is not None:
                    imm = (insn >> 10) & 0xFFF
                    if (insn >> 22) & 1:
                        imm <<= 12
                    xref.setdefault(p + imm, []).append(pc)
                continue
            # LDR/STR (unsigned offset), 32- and 64-bit
            if (insn & 0x3B000000) == 0x39000000:
                rn = (insn >> 5) & 0x1F
                p = page.get(rn)
                if p is not None:
                    sz = (insn >> 30) & 3
                    imm = ((insn >> 10) & 0xFFF) << sz
                    xref.setdefault(p + imm, []).append(pc)
                continue
            if (insn & 0xFC000000) == 0x94000000:       # BL
                off = insn & 0x03FFFFFF
                if off & (1 << 25):
                    off -= (1 << 26)
                call.setdefault(pc + off * 4, []).append(pc)
                continue
            if (insn & 0xFC000000) == 0x14000000:       # B
                off = insn & 0x03FFFFFF
                if off & (1 << 25):
                    off -= (1 << 26)
                call.setdefault(pc + off * 4, []).append(pc)
        self._xref_index = xref
        self._call_index = call

    def xrefs_to(self, va):
        self._build_indexes()
        return sorted(self._xref_index.get(va, []))

    def callers_of(self, va):
        self._build_indexes()
        return sorted(self._call_index.get(va, []))

    def all_refs_in_range(self, lo, hi):
        """{target: [pc,...]} for every ADRP-formed address inside [lo, hi)."""
        self._build_indexes()
        return {t: v for t, v in self._xref_index.items() if lo <= t < hi}

    # -------------------------------------------------------------- functions

    def func_range(self, va):
        """(start, end) of the function containing va, from LC_FUNCTION_STARTS."""
        fs = self.func_starts
        if not fs:
            s = self.func_start(va)
            return s, s + 0x400
        i = bisect.bisect_right(fs, va) - 1
        if i < 0:
            return va, va
        start = fs[i]
        end = fs[i + 1] if i + 1 < len(fs) else self.text_addr + self.text_size
        return start, end

    def func_start_exact(self, va):
        return self.func_range(va)[0]

    def func_start(self, va, limit=0x4000):
        """
        Walk back to the most plausible function entry.

        Two markers, whichever comes first: an instruction that cannot fall
        through (RET / unconditional B / BR), or a classic frame prologue
        (SUB sp,sp,#imm  /  STP x29,x30,[sp,...]  /  STP with pre-index).
        """
        pc = va
        for _ in range(limit // 4):
            prev = self.at(pc - 4)
            if prev is None:
                return pc
            if prev == 0xD65F03C0:                          # RET
                return pc
            if (prev & 0xFC000000) == 0x14000000:           # B
                return pc
            if (prev & 0xFFFFFC1F) == 0xD61F0000:           # BR
                return pc
            cur = self.at(pc)
            if cur is not None and self._is_prologue_head(cur):
                # Walk back over the rest of the register-saving prologue:
                # stp pairs, `add x29, sp, #imm`, `sub sp, sp, #imm`.
                while True:
                    p = self.at(pc - 4)
                    if p is None or not self._is_prologue_body(p):
                        return pc
                    pc -= 4
            pc -= 4
        return pc

    @staticmethod
    def _is_prologue_head(insn):
        return ((insn & 0xFFC003FF) == 0xD10003FF or        # sub sp, sp, #imm
                (insn & 0xFFC003E0) == 0xA98003E0 or        # stp .., [sp, #-imm]!
                (insn & 0xFFC003E0) == 0xA90003E0)          # stp .., [sp, #imm]

    @staticmethod
    def _is_prologue_body(insn):
        return ((insn & 0xFFC003E0) == 0xA98003E0 or        # stp .., [sp, #-imm]!
                (insn & 0xFFC003E0) == 0xA90003E0 or        # stp .., [sp, #imm]
                (insn & 0xFFC003FF) == 0xD10003FF or        # sub sp, sp, #imm
                insn == 0x910003FD or                       # mov x29, sp
                (insn & 0xFFC003FF) == 0x910003FD)          # add x29, sp, #imm

    def disasm_text(self, va, count=40, annotate=True):
        off = self.va_to_off(va)
        if off is None:
            return f"<unmapped {va:#x}>"
        code = self.data[off:off + count * 4]
        lines = []
        page = {}
        for ins in self.md.disasm(code, va):
            line = f"{ins.address:#011x}  {ins.mnemonic:<8} {ins.op_str}"
            if annotate:
                note = self._annotate(ins, page)
                if note:
                    line = f"{line:<58} ; {note}"
            lines.append(line)
        return "\n".join(lines)

    def _annotate(self, ins, page):
        m, ops = ins.mnemonic, ins.op_str
        try:
            if m == "adrp":
                reg, imm = [x.strip() for x in ops.split(",")]
                page[reg] = int(imm.lstrip("#"), 0)
                return None
            if m == "add" and "#" in ops:
                parts = [x.strip() for x in ops.split(",")]
                if len(parts) >= 3 and parts[1] in page and parts[2].startswith("#"):
                    tgt = page[parts[1]] + int(parts[2][1:], 0)
                    page[parts[0]] = tgt   # chained adds build one address
                    s = self.cstring_at(tgt)
                    return f'{tgt:#x} "{s}"' if s else f"{tgt:#x}"
                page.pop(parts[0], None)
            if m in ("ldr", "ldrb", "ldrsw", "str") and "[" in ops:
                inner = ops[ops.index("[") + 1:ops.index("]")]
                parts = [x.strip() for x in inner.split(",")]
                if parts[0] in page:
                    imm = int(parts[1][1:], 0) if len(parts) > 1 else 0
                    return f"{page[parts[0]] + imm:#x}"
            if m in ("bl", "b") and ops.startswith("#"):
                tgt = int(ops[1:], 0)
                stub = self.stub_name(tgt)
                if stub:
                    return stub
                sym = self.sym_for(tgt)
                if sym and sym[1] == 0:
                    return sym[0]
        except (ValueError, IndexError, KeyError):
            pass
        return None
