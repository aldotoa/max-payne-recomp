#!/usr/bin/env python3
"""Function inventory for one x86-32 PE module (M5 lifter spike).

Usage: functions.py <module.dll> [--base HEX] [-o lift-out/<module>_functions.json]

--base maps the image at that base (default: the emulator's load base, see modbases.py).
Seeds function entries from exports, the PE entry point, RTTI vtable slots (same
scan as tools/vtables.py) and direct call targets, then recursive-descent
disassembles each one with capstone (x86-32, same approach as tools/disasm.py).
Writes per-function blocks, calls, imports, jump tables and oddities as JSON and
prints a summary. Addresses in the JSON are hex strings.
"""
import bisect
import json
import os
import re
import struct
import sys
from collections import Counter

import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_FS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modbases import IMAGE_REL_BASED_HIGHLOW, highlow_fixups, target_base  # noqa: E402

IMAGE_SCN_MEM_EXECUTE = 0x20000000
# Imports that never return (bare names, DLL prefix stripped).
NORETURN = {"_CxxThrowException", "exit", "_exit", "abort", "ExitProcess", "RaiseException"}
TERMINATORS = {"ret", "retf", "retn", "iret", "iretd", "hlt", "int3", "ud2"}
ODD_MNEMONICS = {"cpuid", "rdtsc", "pushal", "pushad", "popal", "popad", "pushfd", "popfd",
                 "pushf", "popf", "emms", "movq", "movd", "int", "in", "out", "cli", "sti",
                 "bound", "into"}
MAX_RUN = 4000  # safety bound on instructions walked per function
# Instructions walked back from a switch's `jmp [R*4+T]` to find its `cmp R, N; ja`. MSVC puts
# x87-only code between them (grphmfc 0x10001fb0: ~20 instructions with no integer flag writer).
SWITCH_WINDOW = 40
# Plain `mov r32, r32` copies followed back from a switch's index register (_resolve_copies).
COPY_DEPTH = 4
# Callee-saved registers: a bound loaded into one of them before a call sequence still holds at the
# switch jump (find_switch, register bound). MSVC6 keeps the bound of a switch there (exe 0x10104280).
BOUND_REGS = ("ebx", "esi", "edi", "ebp")
_STRING_OPS = {"movsb", "movsw", "movsd", "stosb", "stosw", "stosd", "lodsb", "lodsw", "lodsd",
               "cmpsb", "cmpsw", "cmpsd", "scasb", "scasw", "scasd"}
MAX_ROUNDS = 20  # seed rounds in inventory() before giving up on convergence
SEG_REGS = {"es", "cs", "ss", "ds", "fs", "gs"}
# Switch index values find_switch cannot prove locally, keyed by the jump's address (an unrelocated module only).
# MSVCRT.DLL memmove (VC6 memcpy.asm), whose dispatch jumps sit behind other switches' dispatches or are entered by a
# jb from outside the linear sweep, where the local proofs stop:
#   TrailUpVec/TrailDownVec[edx]: edx is `len & 3` on every path (`and edx, 3`, or `mov edx, 3` then `and edx, ecx`
#     on the leading-byte paths) and not written after: 0..3.
#   UnwindUpVec[ecx] (0x7801077d): entered only by `cmp ecx, 8; jb`: 0..7.
#   ByteCopyUp, TrailUpVec[ecx + 4] (0x78010776): entered only by `sub ecx, 4; jb` with ecx in 0..3: -4..-1.
#   ByteCopyDown, TrailDownVec[ecx] (0x780108d5): entered only by `cmp ecx, 4; jb`: 0..3.
#   LeadUpVec/LeadDownVec[eax] (0x7801076f, 0x780108ce): eax = edi & 3 on a path entered by `test edi, 3; jne`, so
#     1..3; the `and eax, 3` alone would allow 0, whose "entry" is the neighbouring table (data decoded as code).
SWITCH_HINTS = {va: list(range(4)) for va in (0x7800586D, 0x780107B2, 0x780107D5, 0x780107EE, 0x7801085B, 0x780108B6,
                                              0x780108D5, 0x78010902, 0x7801092D, 0x7801095E)}
SWITCH_HINTS[0x7801077D] = list(range(8))
SWITCH_HINTS[0x78010776] = [(-k) & 0xFFFFFFFF for k in (4, 3, 2, 1)]
SWITCH_HINTS[0x7801076F] = SWITCH_HINTS[0x780108CE] = [1, 2, 3]
# MSVCRT.DLL memcpy (the same memcpy.asm without the MEMMOVE overlap test; up copy 0x7800161d, down copy 0x78010f71),
# by the same reasoning as memmove's, site for site: TrailUpVec/TrailDownVec[edx] 0..3; UnwindUpVec[ecx] (0x78001630,
# also entered by `cmp ecx, 8; jb` from the lead cases) 0..7; UnwindDownVec[-ecx] (0x78010f99, entered only through
# the `neg ecx` at 0x78010f97 after `cmp ecx, 8; jb`) 0, -1, ..., -7; ByteCopyDown, TrailDownVec[ecx] (0x78010fb8,
# entered only by `cmp ecx, 4; jb`) 0..3; LeadUpVec/LeadDownVec[eax] (0x78001651, 0x78010fb1) 1..3.
SWITCH_HINTS.update({va: list(range(4)) for va in (0x78001639, 0x7800167B, 0x780016C5, 0x78010F2B, 0x78010F48, 0x78010FB8,
                                                   0x78010FE2, 0x78011009, 0x7801103A, 0x780110A7)})
SWITCH_HINTS[0x78001630] = list(range(8))
SWITCH_HINTS[0x78010F99] = [(-k) & 0xFFFFFFFF for k in range(8)]
SWITCH_HINTS[0x78001651] = SWITCH_HINTS[0x78010FB1] = [1, 2, 3]
# Non-code sections scanned for code pointers when the image has no base relocations (data_pointer_entries).
# Resources and the stxt*/.MGD32 sections (copy-protection leftovers) are never scanned.
DATA_SECTIONS = (".rdata", ".data")
NONFLAT_PREFIXES = {0x26, 0x2E, 0x36, 0x3E, 0x65}   # es, cs, ss, ds, gs override bytes (fs is SEH)
# A gap-scan candidate (see gap_scan) containing one of these is data decoded as code: MSVC never
# emits port I/O, debug/trap, interrupt or privileged instructions in game code, and such a
# function is never a real entry (exports, vtables and call/tail targets are not gap candidates).
JUNK_MNEMONICS = {"in", "out", "insb", "insw", "insd", "outsb", "outsw", "outsd", "int1", "int",
                  "hlt", "cli", "sti", "iret", "iretd", "lgdt", "lidt", "sgdt", "sidt", "lldt",
                  "ltr", "rdmsr", "wrmsr", "invlpg"}


def load(path, base=None):
    """Parse the PE and map it at `base` (see modbases.target_base). The raw file bytes are
    patched with the base relocations for that base, so every read sees the relocated image."""
    pe = pefile.PE(path)
    preferred = pe.OPTIONAL_HEADER.ImageBase
    base = target_base(path, preferred, base)
    buf = bytearray(open(path, "rb").read())
    if base != preferred:
        for rva, val in highlow_fixups(pe, base - preferred):
            off = pe.get_offset_from_rva(rva)
            struct.pack_into("<I", buf, off, val)
    data = bytes(buf)
    secs = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("latin1")
        code = bool(s.Characteristics & IMAGE_SCN_MEM_EXECUTE) or name == ".text"
        secs.append({"name": name, "lo": base + s.VirtualAddress,
                     "hi": base + s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData),
                     "raw": s.PointerToRawData, "rsize": s.SizeOfRawData, "code": code})
    return pe, data, base, secs


def import_names(pe, base=None):
    """IAT slot VA -> 'DLL!name' (ordinal imports as '#n'), with the image mapped at `base`
    (default: the preferred ImageBase; pefile computes imp.address from that)."""
    preferred = pe.OPTIONAL_HEADER.ImageBase
    base = preferred if base is None else base
    iat = {}
    for ent in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = ent.dll.decode("latin1")
        for imp in ent.imports:
            nm = imp.name.decode("latin1") if imp.name else "#%d" % imp.ordinal
            iat[base + imp.address - preferred] = "%s!%s" % (dll, nm)
    return iat


def delay_imports(pe, base=None):
    """MSVC delay imports (MFC42.DLL has 14 descriptors, 361 slots): (slots, stubs). slots = {delay IAT slot VA:
    'DLL!name'}, the slots the loader binds at load like ordinary imports (emu/mpemu.py resolve_imports), so they are
    import slots here too. stubs = {VA: 'DLL!name'} for the per-import resolver stubs the slots hold in the file
    (`push ...; call __delayLoadHelper; ...; jmp eax`): with the slots bound nothing reaches them, so they are never
    lifted (lift/build.py split_thunks). With the image mapped at `base` (default: the preferred ImageBase)."""
    preferred = pe.OPTIONAL_HEADER.ImageBase
    base = preferred if base is None else base
    lo, hi = preferred, preferred + pe.OPTIONAL_HEADER.SizeOfImage
    slots, stubs = {}, {}
    for ent in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        dll = ent.dll.decode("latin1")
        for imp in ent.imports:
            nm = "%s!%s" % (dll, imp.name.decode("latin1") if imp.name else "#%d" % imp.ordinal)
            slots[base + imp.address - preferred] = nm
            v = pe.get_dword_at_rva(imp.address - preferred)
            if v is not None and lo <= v < hi:
                stubs[base + v - preferred] = nm
    return slots, stubs


class Image:
    def __init__(self, path, base=None):
        self.path = path
        self.pe, self.data, self.base, self.secs = load(path, base)
        # Unrelocated file bytes: gap_scan's byte tests read these so that its answer does not
        # depend on the load base (relocation rewrites the pointer dwords it looks at).
        self.file_data = open(path, "rb").read()
        self.iat = import_names(self.pe, self.base)
        self.iat.update(delay_imports(self.pe, self.base)[0])
        self.thunks = self._find_thunks()  # VA of `jmp [iat]` stub -> 'DLL!name'

    def sec(self, va):
        for s in self.secs:
            if s["lo"] <= va < s["hi"]:
                return s
        return None

    def is_code(self, va):
        s = self.sec(va)
        return bool(s and s["code"])

    def read(self, va, n):
        s = self.sec(va)
        if s is None or va - s["lo"] + n > s["rsize"]:
            return None
        o = s["raw"] + va - s["lo"]
        return self.data[o:o + n]

    def off_to_va(self, off):
        for s in self.secs:
            if s["raw"] <= off < s["raw"] + s["rsize"]:
                return s["lo"] + (off - s["raw"])
        return None

    def _find_thunks(self):
        thunks = {}
        for s in self.secs:
            if not s["code"]:
                continue
            blob = self.data[s["raw"]:s["raw"] + s["rsize"]]
            for m in re.finditer(rb"\xff\x25", blob):
                i = m.start()
                if i + 6 > len(blob):
                    continue
                slot = struct.unpack_from("<I", blob, i + 2)[0]
                if slot in self.iat:
                    thunks[s["lo"] + i] = self.iat[slot]
        return thunks

    def export_entries(self):
        out = []
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for sym in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if sym.forwarder:
                    continue
                name = sym.name.decode("latin1") if sym.name else None
                out.append((sym.ordinal, name or "#%d" % sym.ordinal, self.base + sym.address))
        return out


def demangle_class(td_name):
    """'.?AVChunk@R_MemoryFile@@' -> 'R_MemoryFile::Chunk'."""
    body = td_name[4:-2]
    return "::".join(reversed(body.split("@")))


def rtti_vtable_slots(img):
    """Same RTTI walk as tools/vtables.py. Returns [(class_label, slot_index, target_va)]."""
    data = img.data
    tds = {}
    for m in re.finditer(rb"\.\?A[VU][A-Za-z0-9_@?$]+@@\x00", data):
        name = m.group(0)[:-1].decode("latin1")
        td_off = m.start() - 8
        if td_off < 0:
            continue
        va = img.off_to_va(td_off)
        if va is None or struct.unpack_from("<I", data, td_off + 4)[0] != 0:
            continue
        tds[va] = name
    td_ptr = {struct.pack("<I", va): va for va in tds}

    cols = {}  # COL va -> (type descriptor va, offset)
    for pat, td_va in td_ptr.items():
        i = 0
        while True:
            i = data.find(pat, i)
            if i < 0:
                break
            col_off = i - 12
            if col_off >= 0:
                sig, offs, cdoff = struct.unpack_from("<III", data, col_off)
                if sig == 0 and offs < 0x10000 and cdoff < 0x10000:
                    cva = img.off_to_va(col_off)
                    if cva is not None:
                        cols[cva] = (td_va, offs)
            i += 1

    out = []
    col_bytes = {struct.pack("<I", c): c for c in cols}
    for pat, cva in col_bytes.items():
        i = 0
        while True:
            i = data.find(pat, i)
            if i < 0:
                break
            va = img.off_to_va(i)
            if va is not None and va % 4 == 0:
                td_va, _ = cols[cva]
                cls = demangle_class(tds[td_va])
                o, idx = i + 4, 0
                while o + 4 <= len(data) and idx <= 400:
                    p = struct.unpack_from("<I", data, o)[0]
                    if not img.is_code(p):
                        break
                    out.append((cls, idx, p))
                    o += 4
                    idx += 1
            i += 1
    return out


def _falls_through(ins, noret):
    m = ins.mnemonic
    if m in TERMINATORS or m == "jmp" or ins.address in noret:
        return False
    return True


# Register families: every name that aliases the same 32-bit register maps to one key.
_FAMILY = {}
for _b in "abcd":
    for _n in ("e%sx" % _b, "%sx" % _b, "%sl" % _b, "%sh" % _b):
        _FAMILY[_n] = "e%sx" % _b
for _fam in ("si", "di", "bp", "sp"):
    for _n in ("e" + _fam, _fam, _fam + "l"):
        _FAMILY[_n] = "e" + _fam
# Instructions that write registers they do not name as an operand (conservative: count as writers).
_IMPLICIT_WRITERS = {"cdq", "cwde", "cdqe", "cbw", "cwd", "mul", "imul", "div", "idiv", "lodsb",
                     "lodsw", "lodsd", "cpuid", "rdtsc", "popad", "popal", "lahf", "in", "xlatb",
                     "cmpxchg"}   # writes eax (the accumulator) as well as its register operand
_XCHG_LIKE = {"xchg", "xadd", "cmpxchg"}


def _family(name):
    return _FAMILY.get(name)


def _writes(ins, fam):
    """True if ins may write the 32-bit register family fam (conservative)."""
    m = _bm(ins)
    if m in ("cmp", "test") or m.startswith("j"):
        return False
    if m in _IMPLICIT_WRITERS:
        return True
    for i, op in enumerate(ins.operands):
        if op.type == X86_OP_REG and (i == 0 or m in _XCHG_LIKE) \
                and _family(ins.reg_name(op.reg)) == fam:
            return True
    return False


def _walk_back(ins, prev_of, limit):
    """Instructions before ins in linear order, nearest first. Stops at a call, ret or jmp."""
    out, p = [], prev_of(ins)
    while p is not None and len(out) < limit:
        if p.mnemonic in TERMINATORS or p.mnemonic in ("call", "jmp"):
            break
        out.append(p)
        p = prev_of(p)
    return out


def _copy_src(ins, fam):
    """Family of the source register if ins is `mov R32, R32` writing fam, else None."""
    if ins.mnemonic != "mov" or len(ins.operands) != 2:
        return None
    dst, src = ins.operands
    if dst.type != X86_OP_REG or src.type != X86_OP_REG:
        return None
    dn, sn = ins.reg_name(dst.reg), ins.reg_name(src.reg)
    if not (dn.startswith("e") and sn.startswith("e")) or _family(dn) != fam:
        return None
    return _family(sn)


def _resolve_copies(seq, fam):
    """Follow plain register copies back from the index register fam (MSVC puts `mov edx, eax`
    between the bound compare and the dispatch jump). seq is nearest first. While the nearest writer
    of fam (within 8 instructions) is such a copy, fam becomes its source and the search continues
    before the copy. Returns (fam, seq, writer): seq starts after the last copy followed, and writer
    is the nearest instruction in seq that writes fam (None if there is none within 8)."""
    for _ in range(COPY_DEPTH + 1):
        k = next((k for k, p in enumerate(seq[:8]) if _writes(p, fam)), None)
        if k is None:
            return fam, seq, None
        src = _copy_src(seq[k], fam)
        if src is None:
            return fam, seq, seq[k]
        fam, seq = src, seq[k + 1:]
    return fam, seq, None


def _bound(seq, fam):
    """Unsigned bound N from `cmp fam, N` that a ja/jnbe guards, searching seq (nearest first).
    None if the register is written before such a compare, or no guarded compare is found."""
    guard = None
    for p in seq:
        if p.mnemonic in _JA_GUARDS or p.mnemonic in _JAE_GUARDS:
            if guard is None:
                guard = p.mnemonic
            continue
        if p.mnemonic == "cmp" and len(p.operands) == 2 and p.operands[0].type == X86_OP_REG \
                and _family(p.reg_name(p.operands[0].reg)) == fam \
                and p.operands[1].type == X86_OP_IMM:
            n = p.operands[1].imm & 0xFFFFFFFF
            if guard in _JA_GUARDS:
                return n
            if guard in _JAE_GUARDS and n > 0:
                return n - 1
            return None
        if _writes(p, fam):
            return None
    return None


def _pushpop_bound(seq, fam):
    """Bound N of a guarded `cmp fam, R` where R was set by `push N ; ... ; pop R` (MSVC's short
    form of mov R, N: MSVCRT _output 0x780020bf, MFC42 0x5f44fb10, the driver's 0x10449d66). seq is
    nearest first. Between the push and the pop nothing may push, pop or call, and R is not written
    between the pop and the compare. None if the pattern does not match."""
    guard, k = None, None
    for i, p in enumerate(seq):
        if p.mnemonic in _JA_GUARDS or p.mnemonic in _JAE_GUARDS:
            if guard is None:
                guard = p.mnemonic
            continue
        if p.mnemonic == "cmp" and len(p.operands) == 2 and p.operands[0].type == X86_OP_REG \
                and _family(p.reg_name(p.operands[0].reg)) == fam:
            if guard is None or p.operands[1].type != X86_OP_REG:
                return None
            reg, k = _family(p.reg_name(p.operands[1].reg)), i
            break
        if _writes(p, fam):
            return None
    if k is None or reg is None or reg == fam:
        return None
    rest = seq[k + 1:]
    j = next((j for j, p in enumerate(rest) if _writes_reg(p, reg)), None)
    if j is None or _bm(rest[j]) != "pop" or rest[j].operands[0].type != X86_OP_REG:
        return None
    for p in rest[j + 1:]:
        m = _bm(p)
        if m == "push":
            if p.operands[0].type != X86_OP_IMM:
                return None
            n = p.operands[0].imm & 0xFFFFFFFF
            if guard in _JA_GUARDS:
                return n
            return n - 1 if n > 0 else None
        if m in ("pop", "call", "pushal", "popal", "pushfd", "popfd", "leave", "enter") or _writes_reg(p, "esp"):
            return None
    return None


def _mem_key(ins, op):
    """(segment, base, index, scale, disp) of a memory operand, register names as families."""
    m = op.mem
    return (m.segment, _family(ins.reg_name(m.base)) if m.base else None,
            _family(ins.reg_name(m.index)) if m.index else None, m.scale, m.disp & 0xFFFFFFFF)


def _mem_bound(writer, fam, seq):
    """Bound for an index loaded from a memory slot: `cmp dword ptr [M], N ; ja default ; ... ;
    mov R, dword ptr [M] ; jmp [R*4 + T]` (MaxPayne.exe 0x776e5a, M a stack local). writer is the
    `mov R, [M]`; seq the instructions before it, nearest first. Between the compare and the load
    nothing may write M's base or index register, and no instruction may store to the same operand
    M (stores to other locals are assumed not to alias it, as MSVC addresses locals by fixed offsets
    from esp/ebp). None if the pattern does not match."""
    if writer.mnemonic != "mov" or len(writer.operands) != 2:
        return None
    dst, src = writer.operands
    if dst.type != X86_OP_REG or _family(writer.reg_name(dst.reg)) != fam \
            or src.type != X86_OP_MEM or src.size != 4:
        return None
    key = _mem_key(writer, src)
    regs = [r for r in key[1:3] if r is not None]
    guard = None
    for p in seq:
        if p.mnemonic in _JA_GUARDS or p.mnemonic in _JAE_GUARDS:
            if guard is None:
                guard = p.mnemonic
            continue
        ops = p.operands
        if p.mnemonic == "cmp" and len(ops) == 2 and ops[0].type == X86_OP_MEM and ops[0].size == 4 \
                and _mem_key(p, ops[0]) == key and ops[1].type == X86_OP_IMM:
            n = ops[1].imm & 0xFFFFFFFF
            if guard in _JA_GUARDS:
                return n
            if guard in _JAE_GUARDS and n > 0:
                return n - 1
            return None
        if any(_writes_reg(p, r) for r in regs) or _bm(p) in ("push", "pop"):
            return None
        if ops and ops[0].type == X86_OP_MEM and _bm(p) not in ("cmp", "test") \
                and _mem_key(p, ops[0]) == key:
            return None
    return None


def _writes_reg(ins, fam):
    """True if ins may write the 32-bit register family fam (conservative): _writes, plus the
    implicit writers esi/edi (string operations) and ebp (leave, enter)."""
    if _writes(ins, fam):
        return True
    m = ins.mnemonic.split()[-1]          # "rep stosd" -> "stosd"
    if fam in ("esi", "edi") and m in _STRING_OPS:
        return True
    return fam == "ebp" and m in ("leave", "enter")


def _bound_reg(seq, fam):
    """Callee-saved register R (BOUND_REGS) of the guarded `cmp fam, R` in seq (nearest first), or None.
    The nearest compare of fam decides: if it is not such a compare, None, and _bound runs as before
    (so every switch that is not register-bounded is handled exactly as before)."""
    guarded = False
    for p in seq:
        if p.mnemonic in ("ja", "jnbe"):
            guarded = True
            continue
        if p.mnemonic == "cmp" and len(p.operands) == 2 and p.operands[0].type == X86_OP_REG \
                and _family(p.reg_name(p.operands[0].reg)) == fam:
            if guarded and p.operands[1].type == X86_OP_REG:
                r = p.reg_name(p.operands[1].reg)
                if r in BOUND_REGS:
                    return r
            return None
        if _writes(p, fam):
            return None
    return None


def _linear(read, start, end):
    """Instructions from start up to end, decoded linearly. None if one fails to decode or the
    sweep does not land exactly on end."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    out, a = [], start
    while a < end:
        if len(out) > MAX_RUN:
            return None
        raw = read(a, 16) or read(a, min(16, end - a))
        ins = next(md.disasm(raw, a), None) if raw else None
        if ins is None:
            return None
        out.append(ins)
        a += ins.size
    return out if a == end else None


def _reg_bound(read, entry, jmp_addr, reg):
    """Constant held in callee-saved register reg at the switch jump at jmp_addr, or None.
    Only a linear sweep of [entry, jmp_addr) is used (no CFG). It must hold that:
      - exactly one instruction writes reg (`push reg` in the prologue does not count),
      - that instruction is `mov reg, imm32`,
      - no direct jump before the mov lands in (mov, jmp_addr], so every path from entry that
        reaches the jump has passed the mov.
    Calls in between do not clobber reg (callee-saved). Limit: the sweep does not see code placed
    after jmp_addr, so a jump back into the range from there is not checked."""
    insns = _linear(read, entry, jmp_addr)
    if insns is None:
        return None
    defs = [i for i in insns if i.mnemonic != "push" and _writes_reg(i, reg)]
    if len(defs) != 1:
        return None
    d = defs[0]
    if d.mnemonic != "mov" or len(d.operands) != 2:
        return None
    dst, src = d.operands
    if dst.type != X86_OP_REG or d.reg_name(dst.reg) != reg or src.type != X86_OP_IMM:
        return None
    for i in insns:
        if i.address >= d.address:
            break
        if (i.mnemonic.startswith("j") or i.mnemonic.startswith("loop")) and i.operands \
                and i.operands[0].type == X86_OP_IMM and d.address < i.operands[0].imm <= jmp_addr:
            return None
    return src.imm & 0xFFFFFFFF


_JA_GUARDS = ("ja", "jnbe")             # default taken above N: the switch takes 0..N
_JAE_GUARDS = ("jae", "jnb")            # default taken at or above N: the switch takes 0..N-1
_JB_GUARDS = ("jb", "jnae", "jc")       # taken below N: the switch is reached only when R < N


def _bm(ins):
    """Mnemonic without a lock prefix (`lock inc` is `inc`)."""
    m = ins.mnemonic
    return m[5:] if m.startswith("lock ") else m


def _is_and_mask(ins, fam):
    """m = 2^k-1 if ins is `and R32, m` with R32 the 32-bit register of family fam, else None."""
    if _bm(ins) != "and" or len(ins.operands) != 2:
        return None
    dst, src = ins.operands
    if dst.type != X86_OP_REG or src.type != X86_OP_IMM:
        return None
    dn = ins.reg_name(dst.reg)
    if not dn.startswith("e") or _family(dn) != fam:
        return None
    m = src.imm & 0xFFFFFFFF
    return m if (m & (m + 1)) == 0 else None


def _is_neg_of(ins, fam):
    """True if ins is `neg R32` with R32 of family fam."""
    if _bm(ins) != "neg" or len(ins.operands) != 1:
        return False
    op = ins.operands[0]
    return op.type == X86_OP_REG and ins.reg_name(op.reg).startswith("e") \
        and _family(ins.reg_name(op.reg)) == fam


def _and_mask_linear(seq, fam):
    """Mask m if the nearest writer of fam in seq (nearest first) is `and fam, m`, else None."""
    for p in seq:
        if _writes(p, fam):
            return _is_and_mask(p, fam)
    return None


def _jb_values(read, entry, jmp, fam):
    """Index values of a switch whose only way in is a `jb` that skips to it, MSVC's memcpy tail:
      cmp R, N ; jb J      J sees R in 0..N-1                 (values 0..N-1)
      sub R, N ; jb J      J sees R-N, R in 0..N-1           (values (k-N) mod 2^32)
    J is the jump. Proven over the linear sweep from entry (as _reg_bound is): the instruction
    before J is an unconditional transfer, so nothing falls into J; the only jump in the sweep to J
    is one jb; and the instruction before that jb is the guard on fam. A jump from after J into J
    is not seen, the limit of every linear proof here. Returns the values or None."""
    if entry is None:
        return None
    lin = _linear(read, entry, jmp.address)
    if not lin or _bm(lin[-1]) not in ("jmp", "ret", "retn", "retf"):
        return None
    hits = [i for i in lin if i.mnemonic[0] == "j" and i.operands
            and i.operands[0].type == X86_OP_IMM and (i.operands[0].imm & 0xFFFFFFFF) == jmp.address]
    if len(hits) != 1 or _bm(hits[0]) not in _JB_GUARDS:
        return None
    k = next(k for k, i in enumerate(lin) if i is hits[0])
    guard = lin[k - 1] if k >= 1 else None
    if guard is None or _bm(guard) not in ("cmp", "sub") or len(guard.operands) != 2 \
            or guard.operands[0].type != X86_OP_REG or guard.operands[1].type != X86_OP_IMM \
            or _family(guard.reg_name(guard.operands[0].reg)) != fam:
        return None
    n = guard.operands[1].imm & 0xFFFFFFFF
    if n == 0 or n > 0x100:
        return None
    if _bm(guard) == "cmp":
        return list(range(n))
    return [(k - n) & 0xFFFFFFFF for k in range(n)]


def find_switch(read, is_code, jmp, prev_of, entry=None):
    """Recover an MSVC6 switch dispatched by the indirect jump `jmp` (a capstone instruction).

    One level:  cmp R, N ; ja default ; jmp dword ptr [R*4 + T]          (N+1 dword entries)
    One level, `jae`:  cmp R, N ; jae default ; jmp ...                 (N dword entries)
    Two level:  cmp B, N ; ja default ; mov/movzx R8, byte ptr [B + BT] ; jmp dword ptr [R*4 + T]
                (byte table BT has N+1 entries; dword entries = max byte value + 1)
    Either form may copy the index first: `mov R, X` (X a 32-bit register) between the compare and
    the jump is followed back to X (_resolve_copies), e.g. MaxPayne.exe 0x5aa170.
    Negated index:  cmp R, N ; jae default ; neg R ; jmp ...   (index -R for R in 0..N-1)
    Masked index:   and R, 2^k-1 ; jmp ...   (2^k entries; the and is the nearest writer of R)
    Jump-only entry: cmp R, N ; jb J  or  sub R, N ; jb J, J the jump (see _jb_values).
    One-level form with a register bound: cmp R, B ; ja default ; jmp ... where B is ebx, esi, edi
    or ebp. N is the imm of the single `mov B, imm32` in the function (see _reg_bound), which needs
    entry (the function's first address). Without entry such a switch is not recovered.
    Bound on a memory slot: cmp dword ptr [M], N ; ja default ; ... ; mov R, [M] ; jmp ... (_mem_bound).
    Bound pushed and popped: push N ; ... ; pop B ; cmp R, B ; ja default ; jmp ... (_pushpop_bound).

    read(va, n) -> bytes or None; is_code(va) -> bool; prev_of(ins) -> the instruction before ins
    in linear order, or None. Returns {"targets", "values", "table", "byte_table", "byte_count"}:
    targets[i] is the case target for index values[i] (the value of R at the jump). Only the
    negated and jb forms have values other than 0..len-1.
    A jump in SWITCH_HINTS takes its index values from there.
    Every dword entry must be code: a partial table is not a switch we can translate."""
    if jmp.mnemonic != "jmp" or len(jmp.operands) != 1:
        return None
    op = jmp.operands[0]
    if op.type != X86_OP_MEM or op.mem.base != 0 or op.mem.index == 0 or op.mem.scale != 4 \
            or op.mem.segment:
        return None
    table = op.mem.disp & 0xFFFFFFFF
    fam = _family(jmp.reg_name(op.mem.index))
    if fam is None:
        return None
    if jmp.address in SWITCH_HINTS:
        return _switch_targets(read, is_code, table, SWITCH_HINTS[jmp.address], None, 0)
    before = _walk_back(jmp, prev_of, SWITCH_WINDOW)
    fam, before, writer = _resolve_copies(before, fam)
    byte_table, byte_base, bound = None, None, None
    values, byte_count = None, 0
    if writer is not None and writer.mnemonic in ("mov", "movzx") and len(writer.operands) == 2:
        dst, src = writer.operands
        if dst.type == X86_OP_REG and _family(writer.reg_name(dst.reg)) == fam \
                and src.type == X86_OP_MEM and src.size == 1 and src.mem.base != 0 \
                and src.mem.index == 0 and not src.mem.segment:
            byte_table = src.mem.disp & 0xFFFFFFFF
            byte_base = _family(writer.reg_name(src.mem.base))
            bound = _bound(_walk_back(writer, prev_of, 12), byte_base)
            if bound is None or bound > 0xFF:
                return None
            raw = read(byte_table, bound + 1)
            if raw is None or len(raw) != bound + 1:
                return None
            values = list(range(max(raw) + 1))
            byte_count = bound + 1
    if byte_table is None:
        if writer is not None and _is_neg_of(writer, fam):
            k = next(i for i, p in enumerate(before) if p is writer)
            bound = _bound(before[k + 1:], fam)
            if bound is not None and bound <= 0x1000:
                values = [(-x) & 0xFFFFFFFF for x in range(bound + 1)]
        else:
            bound = _pushpop_bound(before, fam)
            reg = _bound_reg(before, fam) if bound is None else None
            if bound is not None:
                pass
            elif reg is not None:
                bound = _reg_bound(read, entry, jmp.address, reg) if entry is not None else None
            else:
                bound = _bound(before, fam)
                if bound is None:
                    bound = _and_mask_linear(before, fam)
                if bound is None and writer is not None:
                    k = next(i for i, p in enumerate(before) if p is writer)
                    bound = _mem_bound(writer, fam, before[k + 1:])
                if bound is None and not before:
                    values = _jb_values(read, entry, jmp, fam)
            if values is None and bound is not None and bound <= 0x1000:
                values = list(range(bound + 1))
        if values is None:
            return None
    return _switch_targets(read, is_code, table, values, byte_table, byte_count)


def _switch_targets(read, is_code, table, values, byte_table, byte_count):
    """find_switch's result for these index values, or None if an entry is unreadable or not code."""
    targets = []
    for v in values:
        raw = read((table + 4 * v) & 0xFFFFFFFF, 4)
        if raw is None or len(raw) != 4:
            return None
        t = struct.unpack("<I", raw)[0]
        if not is_code(t):
            return None
        targets.append(t)
    return {"targets": targets, "values": values, "table": table, "byte_table": byte_table,
            "byte_count": byte_count}


def _switch(img, a, insns, prev, leaders, todo, jtables, unresolved, entry):
    """Record a switch dispatched by the indirect jump at a (see find_switch). Returns True if it was
    recovered; otherwise a is added to unresolved (when that is not None)."""
    sw = find_switch(img.read, img.is_code, insns[a], lambda ins: insns.get(prev.get(ins.address)),
                     entry)
    if sw is None:
        if unresolved is not None:
            unresolved.add(a)
        return False
    for t in sw["targets"]:
        leaders.add(t)
        todo.append(t)
    jtables.append({"at": a, "table": sw["table"], "targets": sw["targets"],
                    "values": sw["values"],
                    "byte_table": sw["byte_table"], "byte_count": sw["byte_count"]})
    return True


def analyze(img, entry, known, queried=None):
    """Recursive-descent disassembly of the function at `entry`.

    Returns (record, new_entries): record is None if nothing decodes at entry.
    `known` is the set of function entries so far; a `jmp` to another known entry
    is a tail call, anything else is followed as part of this function. If `queried` is a
    dict, it receives {target: target in known} for every such membership test, so a caller
    can tell when a cached result is stale (see fixed_point).
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    insns = {}          # addr -> CsInsn for every instruction walked
    prev = {}           # addr after an instruction -> addr of that instruction
    leaders = {entry}
    bad = set()         # addresses that failed to read or decode
    calls, tails, ind_calls, imports, unresolved = set(), set(), set(), set(), set()
    new_entries = set()
    jtables = []
    noret = set()       # addresses of calls into no-return imports
    todo = [entry]

    while True:
        while todo:
            a = todo.pop()
            steps = 0
            while a not in insns:
                steps += 1
                if steps > MAX_RUN:
                    break
                raw = img.read(a, 16)
                ins = next(md.disasm(raw, a), None) if raw else None
                if ins is None:
                    bad.add(a)
                    break
                insns[a] = ins
                m = ins.mnemonic
                nxt = a + ins.size
                ops = ins.operands
                if m in TERMINATORS:
                    break
                if m == "call":
                    op = ops[0]
                    if op.type == X86_OP_IMM:
                        t = op.imm
                        calls.add(t)
                        name = img.thunks.get(t)
                        if name:
                            imports.add(name)
                        if img.is_code(t):
                            new_entries.add(t)
                        if name and name.split("!", 1)[1] in NORETURN:
                            noret.add(a)
                            break
                    elif op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0 \
                            and op.mem.disp in img.iat:
                        name = img.iat[op.mem.disp]
                        imports.add(name)
                        if name.split("!", 1)[1] in NORETURN:
                            noret.add(a)
                            break
                    else:
                        ind_calls.add(a)
                elif m == "jmp":
                    op = ops[0]
                    if op.type == X86_OP_IMM:
                        t = op.imm
                        name = img.thunks.get(t)
                        if queried is not None and not name and img.is_code(t):
                            queried[t] = t in known
                        if name or not img.is_code(t) or (t in known and t != entry):
                            tails.add(t)
                            if name:
                                imports.add(name)
                            if img.is_code(t):
                                new_entries.add(t)
                        else:
                            leaders.add(t)
                            todo.append(t)
                        break
                    if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0 \
                            and op.mem.disp in img.iat:
                        imports.add(img.iat[op.mem.disp])
                        break
                    if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index != 0 \
                            and op.mem.scale == 4:
                        _switch(img, a, insns, prev, leaders, todo, jtables, unresolved, entry)
                        break
                    unresolved.add(a)
                    break
                elif m.startswith("j") or m.startswith("loop"):
                    # conditional branch: both edges are part of this function
                    if ops and ops[0].type == X86_OP_IMM and img.is_code(ops[0].imm):
                        leaders.add(ops[0].imm)
                        todo.append(ops[0].imm)
                    leaders.add(nxt)
                prev[nxt] = a
                a = nxt
        # A switch jump decoded before the instructions that bound its index (its block is also a branch target,
        # reached first) has no history at that point: retry the unresolved ones on the finished decode, and decode
        # what a recovered table adds (MaxPayne.exe 0x776e5a).
        late = [x for x in sorted(unresolved) if _switch(img, x, insns, prev, leaders, todo, jtables, None, entry)]
        unresolved.difference_update(late)
        if not todo:
            break

    # Blocks: start at a leader and run the linear chain until a terminator
    # (no fall-through) or the next leader.
    blocks, covered = [], []
    for L in sorted(leaders):
        if L not in insns:
            continue
        a = L
        while True:
            ins = insns[a]
            nxt = a + ins.size
            covered.append(a)
            if not _falls_through(ins, noret) or nxt in leaders or nxt not in insns:
                end = nxt
                break
            a = nxt
        blocks.append((L, end))
    if not blocks:
        return None, []
    blocks.sort()
    overlap = any(blocks[i][1] > blocks[i + 1][0] for i in range(len(blocks) - 1))

    hist = Counter()
    odd = set()
    has_seh = False
    imms = set()        # code addresses taken as immediates by non-branch instructions
    for a in sorted(set(covered)):
        ins = insns[a]
        hist[ins.mnemonic] += 1
        if not (ins.mnemonic.startswith("j") or ins.mnemonic in ("call", "loop", "loope", "loopne",
                                                                  "jmp")):
            for op in ins.operands:
                if op.type == X86_OP_IMM and img.is_code(op.imm):
                    imms.add(op.imm)
        if ins.mnemonic in ODD_MNEMONICS:
            odd.add(ins.mnemonic)
        if ins.mnemonic in ("push", "pop") and ins.operands and ins.operands[0].type == X86_OP_REG \
                and ins.reg_name(ins.operands[0].reg) in SEG_REGS:
            odd.add("segment-override")
        if any(p in NONFLAT_PREFIXES for p in ins.prefix):
            odd.add("segment-override")          # es/cs/ss/ds/gs prefix: not in flat-model code
        if any(p == 0xF0 for p in ins.prefix):
            odd.add("lock")
        for op in ins.operands:
            if op.type == X86_OP_REG:
                rn = ins.reg_name(op.reg) or ""
                if rn.startswith("mm") or rn.startswith("xmm"):
                    odd.add("mmx/sse")
            elif op.type == X86_OP_MEM and op.mem.segment == X86_REG_FS and op.mem.disp == 0:
                has_seh = True  # touches fs:[0], the SEH chain head
            elif op.type == X86_OP_IMM:
                n = img.thunks.get(op.imm) or img.iat.get(op.imm) or ""
                if "_except_handler" in n:
                    has_seh = True
    if any("_except_handler" in n for n in imports):
        has_seh = True
    if bad:
        odd.add("undecodable")
    if overlap:
        odd.add("overlapping-blocks")

    rec = {
        "entry": entry,
        "blocks": [{"start": s, "end": e} for s, e in blocks],
        "size": sum(e - s for s, e in blocks),
        "mnemonics": sorted(hist),
        "calls": sorted(calls),
        "tail_calls": sorted(tails),
        "indirect_calls": sorted(ind_calls),
        "imports_called": sorted(imports),
        "jump_tables": jtables,
        "unresolved_indirect_jumps": sorted(unresolved),
        "has_seh": has_seh,
        "odd": sorted(odd),
        "_hist": hist,
        "_overlap": overlap,
        "_imms": imms,
    }
    return rec, sorted(new_entries)


def inventory(path, base=None):
    img = Image(path, base)
    exports = img.export_entries()
    slots = rtti_vtable_slots(img)
    entry_va = img.base + img.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    labels = {}  # function entry VA -> names
    for _, name, va in exports:
        labels.setdefault(va, []).append(name)
    for cls, idx, va in slots:
        labels.setdefault(va, []).append("%s::slot%d" % (cls, idx))
    if img.is_code(entry_va):
        labels.setdefault(entry_va, []).append("<entry point>")

    seeds = {va for va in labels if img.is_code(va)}
    # Entries grow from the seeds through direct call / tail targets (fixed_point). Address-taken
    # code pointers (address_taken_entries) are seeded too. Their set is recomputed from scratch
    # each round, since a seed that a later round shows to be a switch label (a jump-table target)
    # must be dropped. Gap-scan finds (code bytes no function reaches, starting right after padding
    # or a ret) are added only once the address-taken set is stable. They accumulate, as before:
    # their presence changes tail-call detection, so they are never dropped. After each batch the
    # address-taken set is re-converged.
    at_all, gap_found = set(), set()
    cache = {}  # analyze_cached results, shared by every round
    for _ in range(MAX_ROUNDS):
        known = seeds | at_all | gap_found
        recs = fixed_point(img, known, cache)
        if has_base_relocs(img.pe):
            new_at = address_taken_entries(img, recs)
        else:
            new_at = no_reloc_seeds(img, recs, known, cache)
        if new_at != at_all:
            at_all = new_at
            continue
        strict = not has_base_relocs(img.pe)
        anchors = sorted(e for e in recs if e not in gap_found) if strict else ()
        gaps = gap_scan(img, recs, known, cache, strict, anchors) - seeds - at_all - gap_found
        if not gaps:
            break
        gap_found |= gaps
    else:
        raise RuntimeError("function inventory did not converge in %d rounds" % MAX_ROUNDS)

    functions = []
    for e in sorted(recs):
        r = recs[e]
        r["names"] = sorted(labels.get(e, []))
        r["gap_scan"] = e in gap_found
        r["address_taken"] = e in at_all
        functions.append(r)
    return img, exports, functions, slots, entry_va


def code_pointer_sites(img):
    """[(site_va, value)] for every IMAGE_REL_BASED_HIGHLOW relocation whose dword, at the mapped
    base, points into an executable section. The bytes are read from img.data, which is already
    relocated for img.base, so this also works when base == preferred (delta 0, sites unchanged)."""
    out = []
    for blk in getattr(img.pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for ent in blk.entries:
            if ent.type != IMAGE_REL_BASED_HIGHLOW:
                continue
            off = img.pe.get_offset_from_rva(ent.rva)
            v = struct.unpack_from("<I", img.data, off)[0]
            if img.is_code(v):
                out.append((img.base + ent.rva, v))
    return out


def _is_switch_disp(img, site):
    """True if the dword at site is the displacement of `jmp dword ptr [R*4 + disp32]` (FF 24 SIB,
    SIB = scale 4, no base, disp32). That relocation holds the switch table's address, which can
    lie in .text; it is data, not a function."""
    b = img.read(site - 3, 3)
    return b is not None and len(b) == 3 and b[0] == 0xFF and b[1] == 0x24 \
        and (b[2] >> 6) == 2 and (b[2] & 7) == 5


def has_base_relocs(pe):
    return hasattr(pe, "DIRECTORY_ENTRY_BASERELOC")


def _table_facts(recs):
    """(targets, spans, tables) of the recovered jump tables: switch label targets, (start, length)
    byte spans of the tables, and the table addresses."""
    targets, spans, tables = set(), [], set()
    for r in recs.values():
        for jt in r["jump_tables"]:
            targets.update(jt["targets"])
            spans.append((jt["table"], 4 * len(jt["targets"])))
            tables.add(jt["table"])
            if jt["byte_table"] is not None:
                spans.append((jt["byte_table"], jt["byte_count"]))
                tables.add(jt["byte_table"])
    return targets, spans, tables


def address_taken_entries(img, recs):
    """Set of code addresses taken by the image: targets of code_pointer_sites, except
    - the targets of recovered jump tables, and any site lying inside a recovered jump table
      (those relocations are switch labels, not functions);
    - the table addresses of switches (recovered, or the disp32 of any switch-style jmp), which
      are data that can sit in .text."""
    targets, spans, tables = _table_facts(recs)
    out = set()
    for site, v in code_pointer_sites(img):
        if v in targets or v in tables or _is_switch_disp(img, site) \
                or any(lo <= site < lo + n for lo, n in spans):
            continue
        out.add(v)
    return out


def _block_cover(recs):
    """(starts, max_ends) over every analysed block, sorted by start: max_ends[i] is the largest
    end among the first i+1 blocks, so a point strictly inside some block is found by one bisect."""
    spans = sorted((b["start"], b["end"]) for r in recs.values() for b in r["blocks"])
    starts = [s for s, _ in spans]
    max_ends, top = [], 0
    for _, e in spans:
        top = max(top, e)
        max_ends.append(top)
    return starts, max_ends


def _in_cover(cover, va):
    """True if va lies strictly inside an analysed block (a block start is not inside it)."""
    starts, max_ends = cover
    i = bisect.bisect_left(starts, va) - 1
    return i >= 0 and max_ends[i] > va


def _accepted_code_pointer(img, v, recs, cover, known, cache, anchors):
    """The acceptance rule shared by the no-relocation seeds: v is a function entry or lies in no
    analysed block strictly (a label inside one is not a function), analyze() gives a record that
    is neither junk nor overlapping (is_junk), and its first block (the straight run from v to its
    first branch) does not run over an analysed entry. Returns the record, or None. The caller has
    checked that v is in code."""
    if v not in recs and _in_cover(cover, v) and not _shadowed(img, v, anchors):
        return None
    if img.read(v, 1) in (b"\x90", b"\xcc"):      # nop / int3 padding is never a function's first byte
        return None
    rec, _ = analyze_cached(img, v, known, cache)
    if rec is None or rec["_overlap"] or is_junk(rec) or _entry_inside(rec, anchors, v, first=True):
        return None
    return rec


def _after_padding(img, a, b):
    """True if decoding from a reaches b on an instruction boundary right after a nop or int3: b starts a function
    after alignment padding, and a is a value that decodes through the end of the previous function and the padding
    into it (maxpayne.exe 0x4d4554 into the atexit thunk 0x4d4560)."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    last = None
    for ins in md.disasm(img.read(a, b - a), a):
        last = ins
    return last is not None and last.address + last.size == b and last.mnemonic in ("nop", "int3")


def _shadowed(img, v, anchors, reach=32):
    """True if an entry at most `reach` bytes before v decodes through padding into v (_after_padding): the block
    that covers v is that entry's, a value accepted in an earlier round, so v stays a candidate and
    _drop_inside_first decides between the two."""
    i = bisect.bisect_left(anchors, v)
    while i > 0 and anchors[i - 1] >= v - reach:
        i -= 1
        if _after_padding(img, anchors[i], v):
            return True
    return False


def _drop_inside_first(cands, img=None):
    """cands: {va: record} of seed candidates. Drops every candidate that lies strictly inside the
    first block of another candidate: a mid-instruction value inside a real function's first block
    is not a function, so only the real one is kept. With img, a candidate whose first block runs
    through nop/int3 padding into another candidate (_after_padding) is the one dropped instead.
    Returns the surviving set."""
    starts = sorted(cands)
    out = set(cands)
    for va, rec in cands.items():
        first = next((b for b in rec["blocks"] if b["start"] == va), None)
        if first is None:
            continue
        i = bisect.bisect_right(starts, first["start"])
        while i < len(starts) and starts[i] < first["end"]:
            if img is not None and _after_padding(img, va, starts[i]):
                out.discard(va)            # the inner candidate's own pass drops what lies inside its first block
                break
            out.discard(starts[i])
            i += 1
    return out


def _data_candidates(img, recs, known, cache):
    """{va: record}: code pointers in DATA_SECTIONS dwords (see data_pointer_entries)."""
    targets, spans, tables = _table_facts(recs)
    cover = _block_cover(recs)
    anchors = sorted(recs)
    out = {}
    for s in img.secs:
        if s["name"] not in DATA_SECTIONS:
            continue
        blob = img.data[s["raw"]:s["raw"] + s["rsize"]]
        for off in range(0, len(blob) - 3, 4):
            v = struct.unpack_from("<I", blob, off)[0]
            site = s["lo"] + off
            if not img.is_code(v) or v in targets or v in tables or _is_switch_disp(img, site) \
                    or any(lo <= site < lo + n for lo, n in spans):
                continue
            rec = _accepted_code_pointer(img, v, recs, cover, known, cache, anchors)
            if rec is not None:
                out[v] = rec
    return out


def _imm_candidates(img, recs, known, cache):
    """{va: record}: code pointers taken as instruction immediates (see immediate_entries)."""
    targets, _, tables = _table_facts(recs)
    cover = _block_cover(recs)
    anchors = sorted(recs)
    out = {}
    for r in recs.values():
        for v in r["_imms"]:
            if v in targets or v in tables or v in out:
                continue
            rec = _accepted_code_pointer(img, v, recs, cover, known, cache, anchors)
            if rec is not None:
                out[v] = rec
    return out


def data_pointer_entries(img, recs, known, cache):
    """Address-taken code pointers of an image with no base relocations (no sites for
    code_pointer_sites to read): every 4-byte-aligned dword in a DATA_SECTIONS section whose
    value points into code. The table exclusions are those of address_taken_entries."""
    return _drop_inside_first(_data_candidates(img, recs, known, cache), img)


def immediate_entries(img, recs, known, cache):
    """Address-taken code pointers of an image with no base relocations, taken as instruction
    immediates: `push offset fn`, `mov reg, offset fn`, `mov [m], offset fn` in analysed code
    (the rec's `_imms`, branch targets excluded). Same acceptance as data_pointer_entries."""
    return _drop_inside_first(_imm_candidates(img, recs, known, cache), img)


def no_reloc_seeds(img, recs, known, cache):
    """All address-taken seeds of an image with no base relocations: data and immediate
    candidates together, so that a candidate inside another's first block is dropped whichever
    source it came from."""
    cands = _data_candidates(img, recs, known, cache)
    cands.update(_imm_candidates(img, recs, known, cache))
    return _drop_inside_first(cands, img)


def analyze_cached(img, entry, known, cache):
    """analyze(img, entry, known), reusing cache[entry] = (record, new_entries, membership) while
    every membership test the analysis made still gives the same answer. An analysis depends on
    `known` only through those tests, so the result equals a fresh analyze() call."""
    hit = cache.get(entry)
    if hit is None or any((t in known) != v for t, v in hit[2].items()):
        queried = {}
        rec, new = analyze(img, entry, known, queried)
        hit = cache[entry] = (rec, new, queried)
    return hit[0], hit[1]


def fixed_point(img, known, cache=None):
    """Analyse every entry in `known`, adding call/tail targets until stable.
    `cache` (see analyze_cached) lets analyses survive across calls."""
    known = set(known)
    cache = {} if cache is None else cache
    while True:
        recs, new_all = {}, set()
        for e in sorted(known):
            rec, new = analyze_cached(img, e, known, cache)
            if rec is not None:
                recs[e] = rec
                new_all |= set(new)
        added = new_all - known
        if not added:
            return recs
        known |= added


def _entry_inside(rec, entries, own, first=False):
    """True if some entry other than `own` lies strictly inside a block of rec (only the block
    that starts at `own` when `first`). `entries` is sorted."""
    for b in rec["blocks"]:
        if first and b["start"] != own:
            continue
        i = bisect.bisect_right(entries, b["start"])
        while i < len(entries) and entries[i] < b["end"]:
            if entries[i] != own:
                return True
            i += 1
    return False


def gap_scan(img, recs, known, cache=None, strict=False, anchors=()):
    """Entry candidates in code that no analysed block covers (see inventory).

    A candidate starts right after padding or a ret, is not nop padding, and must
    decode to at least 6 bytes of straight-line-or-branching code of its own.
    With `strict` (images without base relocations), it must also start on a 16-byte boundary
    (MSVC aligns functions) and its blocks must not run over the start of an entry in `anchors`
    (a sorted list of the non-gap entries): such a candidate decodes through another function.
    """
    cache = {} if cache is None else cache
    cands = set()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for s in img.secs:
        if not s["code"]:
            continue
        blob = img.data[s["raw"]:s["raw"] + s["rsize"]]
        pad = img.file_data[s["raw"]:s["raw"] + s["rsize"]]   # byte tests: base-independent
        cov = bytearray(len(blob))
        for r in recs.values():
            for b in r["blocks"]:
                lo, hi = b["start"] - s["lo"], b["end"] - s["lo"]
                if 0 <= lo < len(cov):
                    for k in range(lo, min(hi, len(cov))):
                        cov[k] = 1
            # switch tables sit in .text right after their function: their bytes are data
            for jt in r["jump_tables"]:
                spans = [(jt["table"], 4 * len(jt["targets"]))]
                if jt["byte_table"] is not None:
                    spans.append((jt["byte_table"], jt["byte_count"]))
                for start, n in spans:
                    lo = start - s["lo"]
                    for k in range(max(lo, 0), min(lo + n, len(cov))):
                        cov[k] = 1
        for i in range(1, len(blob)):
            if cov[i] or pad[i] in (0x00, 0x90, 0xCC):
                continue
            if pad[i - 1] not in (0x00, 0xCC, 0xC3, 0xC2):
                continue
            va = s["lo"] + i
            ins = next(md.disasm(pad[i:i + 16], va), None)
            if ins is None or ins.mnemonic in TERMINATORS or ins.mnemonic == "nop":
                continue
            rec, _ = analyze_cached(img, va, known, cache)
            if rec is not None and rec["size"] >= 6 and not rec["_overlap"] \
                    and not is_junk(rec):
                if strict and (va % 16 or _entry_inside(rec, anchors, va)):
                    continue
                cands.add(va)
    return cands


def is_junk(rec):
    """A gap-scan candidate that decodes to something MSVC never emits in game code: port I/O,
    interrupts or privileged instructions, a segment register push/pop, or an undecodable byte."""
    return bool(set(rec["mnemonics"]) & JUNK_MNEMONICS) or "segment-override" in rec["odd"] \
        or "undecodable" in rec["odd"]


def _jump_table_json(j):
    """A jump table record for the output. "values" (the index of each target) is written only when
    it is not 0..n-1, so tables of every other form keep their output unchanged."""
    out = {"at": "0x%x" % j["at"], "table": "0x%x" % j["table"],
           "targets": ["0x%x" % t for t in j["targets"]],
           "byte_table": None if j["byte_table"] is None else "0x%x" % j["byte_table"],
           "byte_count": j["byte_count"]}
    if j["values"] != list(range(len(j["targets"]))):
        out["values"] = ["0x%x" % v for v in j["values"]]
    return out


def build_output(img, exports, functions, slots, entry_va):
    fentries = {f["entry"] for f in functions}
    hist = Counter()
    out_funcs = []
    for f in functions:
        hist.update(f.pop("_hist"))
        f.pop("_overlap")
        f.pop("_imms")
        g = dict(f)
        g["entry"] = "0x%x" % f["entry"]
        g["blocks"] = [{"start": "0x%x" % b["start"], "end": "0x%x" % b["end"]}
                       for b in f["blocks"]]
        g["calls"] = ["0x%x" % t for t in f["calls"]]
        g["tail_calls"] = ["0x%x" % t for t in f["tail_calls"]]
        g["indirect_calls"] = ["0x%x" % t for t in f["indirect_calls"]]
        g["unresolved_indirect_jumps"] = ["0x%x" % t for t in f["unresolved_indirect_jumps"]]
        g["jump_tables"] = [_jump_table_json(j) for j in f["jump_tables"]]
        out_funcs.append(g)
    summary = {
        "function_count": len(functions),
        "total_bytes": sum(f["size"] for f in functions),
        "has_seh_count": sum(1 for f in functions if f["has_seh"]),
        "odd_count": sum(1 for f in functions if f["odd"]),
        "mnemonic_histogram": dict(hist.most_common()),
        "unresolved_indirect_jumps": sum(len(f["unresolved_indirect_jumps"]) for f in functions),
        "jump_table_count": sum(len(f["jump_tables"]) for f in functions),
        "export_count": len(exports),
        "exports_that_are_function_entries": sum(1 for _, _, va in exports if va in fentries),
        "address_taken_count": sum(1 for f in functions if f["address_taken"]),
        "vtable_slot_count": len(slots),
        "entry_point": "0x%x" % entry_va,
    }
    return {"module": os.path.basename(img.path), "base": "0x%x" % img.base,
            "functions": out_funcs, "summary": summary}


def main():
    args = sys.argv[1:]
    if not args or args[0].startswith("-"):
        print(__doc__)
        sys.exit(2)
    path = args[0]
    base = int(args[args.index("--base") + 1], 16) if "--base" in args else None
    stem = os.path.splitext(os.path.basename(path))[0].lower()
    out = "lift-out/%s_functions.json" % stem
    if "-o" in args:
        out = args[args.index("-o") + 1]
    img, exports, functions, slots, entry_va = inventory(path, base)
    result = build_output(img, exports, functions, slots, entry_va)
    d = os.path.dirname(out)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(out, "w") as fh:
        json.dump(result, fh, indent=1)
    s = result["summary"]
    print("%s: %d functions, %d bytes" % (result["module"], s["function_count"], s["total_bytes"]))
    print("  has_seh: %d   odd: %d   unresolved indirect jumps: %d   jump tables: %d" %
          (s["has_seh_count"], s["odd_count"], s["unresolved_indirect_jumps"],
           s["jump_table_count"]))
    print("  exports: %d (function entries: %d)   vtable slots: %d" %
          (s["export_count"], s["exports_that_are_function_entries"], s["vtable_slot_count"]))
    top = list(s["mnemonic_histogram"].items())[:12]
    print("  top mnemonics: " + ", ".join("%s=%d" % kv for kv in top))
    print("wrote " + out)


if __name__ == "__main__":
    main()
