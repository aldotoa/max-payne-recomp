#!/usr/bin/env python3
"""x86-32 -> C translator (M5 skeleton). One C function per x86 function.

Usage: x86c.py <dll> <hex entry> [...]    prints the C for each entry to stdout, unsupported
                                           instructions to stderr.

Design (later chunks must keep these):
  - Guest memory is host memory at mem + guest_va. Lifted code reads and writes it with rdN/wrN.
  - Register and flag state lives in CPU (lift/runtime/cpu.h). Flags are computed eagerly with the
    helpers in lift/runtime/flags.h.
  - Instructions are translated by handlers registered in HANDLERS via @handler(mnemonic...).
    A handler gets (ctx, insn) and returns a list of C statement lines, or raises Reject to make the
    translator emit UNSUPPORTED for that instruction.
  - Operand helpers ea/get/put are the only place that knows about registers, memory and segments.
  - Control flow: blocks come from discover_blocks (recursive descent). Jumps inside the function
    become goto L_xxxxxxxx. Jumps and calls to other known entries are real calls.
  - Calls: a direct call to a known entry pushes the return address and calls f_xxx. Any other
    direct call goes to c->call_guest (no push). Indirect calls use lift_call_ret, which pushes the real
    return address only when the target is lifted.
    Calls to IAT imports go through lift_call_ret (lift_jump for a tail jump): the import may be a lifted
    function of another module, which then runs natively; anything else goes to c->call_guest.
"""
import os
import re
import struct
import sys
from dataclasses import dataclass, field

import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from functions import NORETURN, delay_imports, find_switch  # noqa: E402  (shared with the inventory)
from modbases import highlow_fixups, target_base  # noqa: E402

RUNTIME = os.path.join(HERE, "runtime")

_MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
_MD.detail = True


class Reject(Exception):
    """The instruction or operand form is not handled. The translator emits UNSUPPORTED."""


# The six arithmetic flags as bits of a mask, at their EFLAGS positions. DF is not among them: it is
# never dead-flag eliminated.
F_CF, F_PF, F_AF, F_ZF, F_SF, F_OF = 0x001, 0x004, 0x010, 0x040, 0x080, 0x800
F_ALL = F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF
_F_BIT = {"cf": F_CF, "pf": F_PF, "af": F_AF, "zf": F_ZF, "sf": F_SF, "of": F_OF}

# Dead-flag elimination (see "dead flags" below). build.py --no-dead-flags turns it off for A/B runs.
DEAD_FLAGS = True

# Native non-local transfers (E3, docs/m6-emu-removal.md): a guest longjmp, catch continuation or __except transfer
# sets ESP/EBP and jumps into the middle of a function whose frame is further up. With DEAD_FRAMES the transfer is a
# lift_jump to a continuation entry (an aux entry, lift/build.py) that runs on top of the host stack, and each lifted
# function returns at once from a call after which the guest ESP is above its entry ESP: the guest has discarded its
# frame (a live frame's ESP after a call is at or below its entry ESP). The host frames between the transfer and the
# frame the guest returns to unwind themselves that way, with no host longjmp. `jmp reg` (MSVCRT _JumpToContinuation,
# _CallMemberFunction0..2) becomes lift_jump too. build.py --dead-frames turns it on.
DEAD_FRAMES = False

# x87 registers in C locals within a basic block (X87Cache below). build.py --no-x87-locals turns it off for A/B runs.
X87_LOCALS = True

# The x87 control word in a C local (xcw) for the arithmetic helpers (x87_addw ...): read at entry and again after every
# instruction that can change c->cw (X87_CW_CHANGERS: calls run other code; fldcw, fldenv, frstor, fninit load it).
# Reading c->cw at each op instead costs a reload after every guest store (H54: -10% native time in the e2mfc vertex
# code). build.py --no-x87-cw-local turns it off for A/B runs.
X87_CW_LOCAL = True

# Functions that call lift_entry_hook(c, va) at entry (runtime.c: a host callback, if one is set). E4: the frame
# function, so the harness (emu/run_init.py --real-entry) runs once per frame when the lifted Run calls it.
# build.py --entry-hook sets it.
ENTRY_HOOKS = frozenset()
# Functions that call lift_exit_hook(c, va) at every ret, with ESP still at the return address and the guest's memory
# and registers as the function leaves them (runtime.c: a host callback, if one is set). M7: P_Camera::validate, whose
# view tangents the host widens for Hor+. build.py --exit-hook sets it.
EXIT_HOOKS = frozenset()
# Instructions (VAs) before which the lifted code calls lift_insn_hook(c, va), with the x87 cache flushed so st[], top
# and tag are in the CPU struct (runtime.c: a host callback, if one is set). M7: the exe's portal code, which computes
# its own 4:3 view tangent; mphost widens it on the x87 stack for Hor+. build.py --insn-hook sets it.
INSN_HOOKS = frozenset()
X87_CW_CHANGERS = {"call", "fldcw", "fldenv", "fnldenv", "frstor", "fnrstor", "fninit", "finit", "fxrstor",
                   "fnsave", "fsave"}


# ---------------------------------------------------------------- PE image

class PEImage:
    """A PE file mapped at `base` (default: the emulator's load base, modbases.target_base).
    Sections are copied to their virtual addresses; base relocations are applied when `base`
    differs from the preferred ImageBase."""

    def __init__(self, path, base=None):
        pe = pefile.PE(path)
        self.path = path
        preferred = pe.OPTIONAL_HEADER.ImageBase
        self.base = target_base(path, preferred, base)
        delta = self.base - preferred
        spans, code = [], []
        for s in pe.sections:
            size = max(s.Misc_VirtualSize, s.SizeOfRawData)
            buf = bytearray(size)
            raw = s.get_data()[:size]
            buf[:len(raw)] = raw
            spans.append((self.base + s.VirtualAddress, buf))
            # IMAGE_SCN_MEM_EXECUTE. MaxPayne.exe's .text has no execute flag (characteristics 0xc0000040), so .text
            # counts as code by name too; the emulator maps every section executable and runs it.
            if s.Characteristics & 0x20000000 or s.Name.rstrip(b"\0") == b".text":
                code.append((self.base + s.VirtualAddress, self.base + s.VirtualAddress + size))
        if delta:
            for rva, val in highlow_fixups(pe, delta):
                va = self.base + rva
                for lo, buf in spans:
                    if lo <= va and va + 4 <= lo + len(buf):
                        struct.pack_into("<I", buf, va - lo, val)
                        break
        self._spans = sorted(spans, key=lambda t: t[0])
        self._code = code
        self.iat = {}                      # {iat slot va: "DLL!name"}
        for ent in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in ent.imports:
                nm = imp.name.decode() if imp.name else "#%d" % imp.ordinal
                self.iat[self.base + imp.address - preferred] = "%s!%s" % (ent.dll.decode(), nm)
        # delay-import slots are bound at load like the IAT (functions.delay_imports); their resolver stubs never run
        slots, self.delay_stubs = delay_imports(pe, self.base)
        self.iat.update(slots)
        self.exports = []                  # [(va, name)], forwarders skipped
        exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        for sym in (exp.symbols if exp else []):
            if sym.address is None or sym.forwarder:
                continue
            nm = sym.name.decode() if sym.name else "#%d" % sym.ordinal
            self.exports.append((self.base + sym.address, nm))     # sym.address is an RVA

    def read(self, va, n):
        """Up to n bytes starting at va (clipped to the mapped section). ValueError if unmapped."""
        for lo, buf in self._spans:
            if lo <= va < lo + len(buf):
                off = va - lo
                return bytes(buf[off:off + n])
        raise ValueError("unmapped %08x" % va)

    def is_code(self, va):
        return any(lo <= va < hi for lo, hi in self._code)


def _reader(image):
    """read(va, n) -> exactly n bytes or None, the form functions.find_switch takes."""
    def read(va, n):
        try:
            b = image.read(va, n)
        except ValueError:
            return None
        return b if len(b) == n else None
    return read


# ---------------------------------------------------------------- registers and operands

_CN = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
_REG32 = {"eax": 0, "ecx": 1, "edx": 2, "ebx": 3, "esp": 4, "ebp": 5, "esi": 6, "edi": 7}
_REG16 = {"ax": 0, "cx": 1, "dx": 2, "bx": 3, "sp": 4, "bp": 5, "si": 6, "di": 7}
_REG8L = {"al": 0, "cl": 1, "dl": 2, "bl": 3}
_REG8H = {"ah": 0, "ch": 1, "dh": 2, "bh": 3}


def _regi(reg_id):
    """(index into c->r, width in bytes, bit shift) for a capstone register id."""
    name = _MD.reg_name(reg_id)
    if name in _REG32:
        return _REG32[name], 4, 0
    if name in _REG16:
        return _REG16[name], 2, 0
    if name in _REG8L:
        return _REG8L[name], 1, 0
    if name in _REG8H:
        return _REG8H[name], 1, 8
    raise Reject("register %s" % name)


def _mask(size):
    return (1 << (8 * size)) - 1


def _bits(size):
    return 8 * size


def _check_size(have, want):
    if have != want:
        raise Reject("operand size %d used as %d" % (have, want))


def ea(op, seg=True):
    """C expression (uint32_t) for the effective address of a memory operand.
    seg=False ignores the segment override (lea)."""
    m = op.mem
    parts = []
    if m.base:
        bi, bs, _ = _regi(m.base)
        _check_size(bs, 4)
        parts.append("c->r[%s]" % _CN[bi])
    if m.index:
        ii, isz, _ = _regi(m.index)
        _check_size(isz, 4)
        term = "c->r[%s]" % _CN[ii]
        if m.scale != 1:
            term += " * %d" % m.scale
        parts.append(term)
    if m.disp or not parts:
        parts.append("0x%xu" % (m.disp & 0xffffffff))
    expr = " + ".join(parts)
    segname = _MD.reg_name(m.segment) if m.segment else None
    if segname == "fs" and seg:
        expr = "c->fs_base + (%s)" % expr
    elif segname not in (None, "ds", "ss", "es", "cs", "fs"):
        raise Reject("segment %s" % segname)
    return "(uint32_t)(%s)" % expr


def get(op, size, addr=None):
    """C rvalue, zero-extended to uint32_t. addr: precomputed address for a memory operand."""
    if op.type == X86_OP_REG:
        i, rs, sh = _regi(op.reg)
        _check_size(rs, size)
        if sh:
            return "((c->r[%s] >> 8) & 0xffu)" % _CN[i]
        if rs == 4:
            return "c->r[%s]" % _CN[i]
        return "(c->r[%s] & 0x%xu)" % (_CN[i], _mask(rs))
    if op.type == X86_OP_IMM:
        return "0x%xu" % (op.imm & _mask(size))
    if op.type == X86_OP_MEM:
        a = addr if addr is not None else ea(op)
        return "((uint32_t)rd%d(c, %s))" % (_bits(size), a)
    raise Reject("operand type %d" % op.type)


def put(op, size, expr, addr=None):
    """C statement storing expr (any integer C expression) into an operand of the given size.
    8/16-bit register writes keep the other bits. addr: precomputed address for memory."""
    if op.type == X86_OP_REG:
        i, rs, sh = _regi(op.reg)
        _check_size(rs, size)
        r = "c->r[%s]" % _CN[i]
        if rs == 4:
            return "%s = (uint32_t)(%s);" % (r, expr)
        if rs == 2:
            return "%s = (%s & 0xffff0000u) | (((uint32_t)(%s)) & 0xffffu);" % (r, r, expr)
        if sh == 0:
            return "%s = (%s & 0xffffff00u) | (((uint32_t)(%s)) & 0xffu);" % (r, r, expr)
        return "%s = (%s & 0xffff00ffu) | ((((uint32_t)(%s)) & 0xffu) << 8);" % (r, r, expr)
    if op.type == X86_OP_MEM:
        a = addr if addr is not None else ea(op)
        return "wr%d(c, %s, (uint32_t)(%s));" % (_bits(size), a, expr)
    raise Reject("cannot store to operand type %d" % op.type)


def _opsize(op):
    """Operand width in bytes, or None for an immediate (which takes its size from the other operand)."""
    if op.type == X86_OP_REG:
        return _regi(op.reg)[1]
    if op.type == X86_OP_MEM:
        if not op.size:
            raise Reject("memory operand without size")
        return op.size
    return None


def _size2(a, b):
    sizes = {s for s in (_opsize(a), _opsize(b)) if s}
    if len(sizes) != 1:
        raise Reject("operand sizes")
    return sizes.pop()


def _ops(ins, n):
    if len(ins.operands) != n:
        raise Reject("expected %d operands" % n)
    return ins.operands


def _mem_iat_slot(image, op):
    """Absolute memory operand [slot] whose address is an IAT slot: returns the slot, else None."""
    if op.type != X86_OP_MEM:
        return None
    m = op.mem
    if m.base or m.index or m.segment:
        return None
    slot = m.disp & 0xffffffff
    return slot if slot in image.iat else None


def _thunk_slot(image, va):
    """If va holds `jmp dword ptr [slot]` with slot an IAT entry, return slot."""
    try:
        b = image.read(va, 6)
    except ValueError:
        return None
    if len(b) == 6 and b[:2] == b"\xff\x25":
        slot = struct.unpack("<I", b[2:6])[0]
        if slot in image.iat:
            return slot
    return None


# ---------------------------------------------------------------- handlers

HANDLERS = {}


def handler(*names):
    def deco(fn):
        for n in names:
            HANDLERS[n] = fn
        return fn
    return deco


# Instructions a `lock` prefix may precede. The emulation is single-threaded, so the locked form
# with a memory operand is the unlocked instruction. Anything else with the prefix is rejected.
# `neg` is left out: Unicorn's locked neg leaves the flags of the previous operation (the reference
# disagrees with the Intel definition on every state, see test_ops_alu.py), so it stays unsupported.
LOCKABLE = {"add", "adc", "sub", "sbb", "and", "or", "xor", "inc", "dec", "not", "xadd",
            "cmpxchg", "xchg"}


class _Unlocked:
    """A lock-prefixed instruction as its unlocked form: the handlers see that mnemonic and the
    same operands."""

    def __init__(self, ins, mnemonic):
        self._ins = ins
        self.mnemonic = mnemonic

    def __getattr__(self, name):
        return getattr(self._ins, name)


def _handler_for(ins):
    """(handler, instruction to translate) for ins, or (None, ins) when there is no handler."""
    m = ins.mnemonic
    if not m.startswith("lock "):
        return HANDLERS.get(m), ins
    base = m[5:]
    if base in LOCKABLE and any(op.type == X86_OP_MEM for op in ins.operands):
        return HANDLERS.get(base), _Unlocked(ins, base)
    return None, ins


# ---------------------------------------------------------------- x87 registers in locals (H49)
#
# Without the cache every x87 instruction works on c->st[(c->top + i) & 7], c->top and c->tag, and the compiler reloads
# them after every store. With it, inside one basic block, ST(i) is the local xs<r>, where r = (d + i) & 7 is the slot
# relative to the TOP read when the block's first x87 instruction ran (xt), and d is the pushes and pops since then,
# known at translation time. A slot is loaded from c->st on its first read; push, pop, ffree and fxch are bookkeeping.
# flush writes back the slots written, the tags pushes and pops changed, and TOP; it runs before any instruction that
# may look at or change the x87 state in the CPU struct (anything not in X87_NEUTRAL or X87_CACHED: calls, jumps, MMX,
# the x87 instructions without a cached form) and at the end of the block. The CPU struct then holds exactly what the
# uncached code leaves there, stale values of popped registers included.

# Instructions that never read or write the x87 stack, TOP or the tags, and do not leave the block's straight-line code.
X87_NEUTRAL = {
    "mov", "movzx", "movsx", "lea", "push", "pop", "xchg", "nop", "cdq", "cwd", "cwde", "cbw", "leave",
    "add", "adc", "sub", "sbb", "and", "or", "xor", "not", "neg", "inc", "dec", "cmp", "test",
    "shl", "sal", "shr", "sar", "shld", "shrd", "rol", "ror", "rcl", "rcr", "mul", "imul", "div", "idiv",
    "bt", "bts", "btr", "btc", "bsf", "bsr", "bswap", "xadd", "cmpxchg",
    "lahf", "sahf", "clc", "stc", "cmc", "cld", "std", "pushfd", "popfd", "pushal", "pushad", "popal", "popad",
    "movsb", "movsw", "movsd", "stosb", "stosw", "stosd",
    "fnstcw", "fstcw", "fldcw", "fwait", "wait",
} | {p + cc for p in ("set", "cmov") for cc in ("o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np",
                                                  "l", "ge", "le", "g")}
X87_CACHED = set()        # filled by lift/ops_x87.py: the x87 instructions whose handlers use ctx.x87


class X87Cache:
    """One function's x87 locals (see above). Methods append C statements to out and return expressions."""

    def __init__(self):
        self.used = False
        self.reset()

    def reset(self):
        self.anchored = False
        self.d = 0
        self.loaded, self.dirty = set(), set()
        self.tags = {}                     # relative slot -> "v" (pushed: valid) or "e" (popped or freed: empty)

    def snapshot(self):
        return (self.anchored, self.d, set(self.loaded), set(self.dirty), dict(self.tags), self.used)

    def restore(self, snap):
        self.anchored, self.d, self.loaded, self.dirty, self.tags, self.used = snap

    def _anchor(self, out):
        if not self.anchored:
            out.append("xt = c->top;")
            self.anchored = True
            self.used = True

    def _slot(self, i):
        return (self.d + i) & 7

    def rd(self, i, out):
        """ST(i) as an expression."""
        self._anchor(out)
        r = self._slot(i)
        if r not in self.loaded:
            out.append("xs%d = c->st[(xt + %du) & 7u];" % (r, r))
            self.loaded.add(r)
        return "xs%d" % r

    def wr(self, i, expr, out):
        """ST(i) = expr (the tag is not changed, as x87_wr)."""
        self._anchor(out)
        r = self._slot(i)
        out.append("xs%d = %s;" % (r, expr))
        self.loaded.add(r)
        self.dirty.add(r)

    def push(self, expr, out):
        self._anchor(out)
        r = (self.d - 1) & 7
        out.append("xs%d = %s;" % (r, expr))
        self.d -= 1
        self.loaded.add(r)
        self.dirty.add(r)
        self.tags[r] = "v"

    def pop(self, out):
        self._anchor(out)
        self.tags[self._slot(0)] = "e"
        self.d += 1

    def free(self, i, out):
        self._anchor(out)
        self.tags[self._slot(i)] = "e"

    def xch(self, i, out):
        a, b = self.rd(0, out), self.rd(i, out)
        if a != b:
            out.append("{ double t = %s; %s = %s; %s = t; }" % (a, a, b, b))
            self.dirty.update((self._slot(0), self._slot(i)))

    def status(self, out):
        """fnstsw's value: TOP is xt + d while the block has run x87 code."""
        if not self.anchored:
            return "x87_status(c)"
        return "x87_status_top(c, (xt + %du) & 7u)" % (self.d & 7)

    def flush(self, out):
        if not self.anchored:
            return
        for r in sorted(self.dirty):
            out.append("c->st[(xt + %du) & 7u] = xs%d;" % (r, r))
        valid = sum(1 << r for r, t in self.tags.items() if t == "v")
        empty = sum(1 << r for r, t in self.tags.items() if t == "e")
        if valid or empty:
            out.append("c->tag = x87_tag_update(c->tag, xt, 0x%02xu, 0x%02xu);" % (valid, empty))
        if self.d & 7:
            out.append("c->top = (xt + %du) & 7u;" % (self.d & 7))
        self.reset()


@dataclass
class Ctx:
    image: object
    entry: int
    known: frozenset
    n_insns: int
    callees: set = field(default_factory=set)      # every direct call/tail-jump target
    lifted: set = field(default_factory=set)       # targets that are C functions in this file
    switches: dict = field(default_factory=dict)   # {jump va: [(index value, case target va)]}
    flags_live: int = F_ALL          # flags live just after the instruction being translated
    flags_skipped: bool = False      # set by flags_wanted when it drops the current instruction's flag code
    flags_checked: int = 0           # instructions whose flag code went through flags_wanted
    flags_removed: int = 0           # ... and had it dropped
    x87: object = None               # X87Cache while emitting with x87 locals; None: the handlers use c->st directly
    cw_local: bool = False           # the x87 arithmetic handlers pass xcw (X87_CW_LOCAL)
    dead_frames: bool = False        # DEAD_FRAMES: return after a call that left ESP above the entry ESP

    def is_tail(self, target):
        """A jump to another known entry is a tail call, not an inline block."""
        return target in self.known and target != self.entry


def _direct_call(ctx, target, ret_va):
    slot = _thunk_slot(ctx.image, target)
    if slot is not None:
        return ["lift_call_ret(c, rd32(c, 0x%xu), 0x%xu);" % (slot, ret_va)]
    ctx.callees.add(target)
    if target in ctx.lifted:
        return ["push32(c, 0x%xu);" % ret_va, "f_%08x(c);" % target]
    return ["lift_guest(c, 0x%xu, 0x%xu);" % (target, ret_va)]


@handler("mov")
def h_mov(ctx, ins):
    dst, src = _ops(ins, 2)
    s = _size2(dst, src)
    return [put(dst, s, get(src, s))]


@handler("movzx")
def h_movzx(ctx, ins):
    dst, src = _ops(ins, 2)
    if dst.type != X86_OP_REG:
        raise Reject("movzx dst")
    dsz, ssz = _opsize(dst), _opsize(src)
    if ssz >= dsz:
        raise Reject("movzx sizes")
    return [put(dst, dsz, get(src, ssz))]


@handler("movsx")
def h_movsx(ctx, ins):
    dst, src = _ops(ins, 2)
    if dst.type != X86_OP_REG:
        raise Reject("movsx dst")
    dsz, ssz = _opsize(dst), _opsize(src)
    if ssz >= dsz:
        raise Reject("movsx sizes")
    ctype = {1: "int8_t", 2: "int16_t"}[ssz]
    return [put(dst, dsz, "(uint32_t)(int32_t)(%s)(%s)" % (ctype, get(src, ssz)))]


@handler("lea")
def h_lea(ctx, ins):
    dst, src = _ops(ins, 2)
    if src.type != X86_OP_MEM or dst.type != X86_OP_REG:
        raise Reject("lea forms")
    return [put(dst, _opsize(dst), ea(src, seg=False))]


@handler("push")
def h_push(ctx, ins):
    (op,) = _ops(ins, 1)
    if op.type == X86_OP_IMM:
        return ["push32(c, %s);" % get(op, 4)]
    if op.type == X86_OP_REG:
        _check_size(_opsize(op), 4)
        # push esp pushes the old value: the argument is evaluated before push32 changes esp
        return ["push32(c, %s);" % get(op, 4)]
    if op.type == X86_OP_MEM:
        _check_size(_opsize(op), 4)
        return ["{ uint32_t v = %s; push32(c, v); }" % get(op, 4)]
    raise Reject("push operand")


@handler("pop")
def h_pop(ctx, ins):
    (op,) = _ops(ins, 1)
    if op.type not in (X86_OP_REG, X86_OP_MEM):
        raise Reject("pop operand")
    _check_size(_opsize(op), 4)
    # esp is incremented before the destination is written, so [esp+x] uses the new esp and
    # pop esp ends with the popped value.
    return ["{ uint32_t v = rd32(c, c->r[ESP]); c->r[ESP] += 4; %s }" % put(op, 4, "v")]


@handler("xchg")
def h_xchg(ctx, ins):
    a, b = _ops(ins, 2)
    s = _size2(a, b)
    pre, addr = [], {}
    for i, op in ((0, a), (1, b)):
        if op.type == X86_OP_MEM:
            addr[i] = "m%d" % i
            pre.append("uint32_t m%d = %s;" % (i, ea(op)))
    # memory addresses are computed before either side is written (xchg eax, [eax])
    return ["{"] + ["    " + p for p in pre] + [
        "    uint32_t t = %s;" % get(a, s, addr.get(0)),
        "    " + put(a, s, get(b, s, addr.get(1)), addr.get(0)),
        "    " + put(b, s, "t", addr.get(1)),
        "}",
    ]


@handler("nop")
def h_nop(ctx, ins):
    return []                  # every nop form, including multi-byte nop with a memory operand


_JCC = {
    "jo": "c->of", "jno": "!c->of",
    "jb": "c->cf", "jnae": "c->cf", "jc": "c->cf",
    "jae": "!c->cf", "jnb": "!c->cf", "jnc": "!c->cf",
    "je": "c->zf", "jz": "c->zf", "jne": "!c->zf", "jnz": "!c->zf",
    "jbe": "c->cf || c->zf", "jna": "c->cf || c->zf",
    "ja": "!c->cf && !c->zf", "jnbe": "!c->cf && !c->zf",
    "js": "c->sf", "jns": "!c->sf",
    "jp": "c->pf", "jpe": "c->pf", "jnp": "!c->pf", "jpo": "!c->pf",
    "jl": "c->sf != c->of", "jnge": "c->sf != c->of",
    "jge": "c->sf == c->of", "jnl": "c->sf == c->of",
    "jle": "c->zf || c->sf != c->of", "jng": "c->zf || c->sf != c->of",
    "jg": "!c->zf && c->sf == c->of", "jnle": "!c->zf && c->sf == c->of",
    "jecxz": "c->r[ECX] == 0",
}


def _jump_stmt(ctx, cond, target):
    if ctx.is_tail(target):
        ctx.callees.add(target)
        if target in ctx.lifted:
            return "if (%s) { f_%08x(c); return; }" % (cond, target)
    return "if (%s) goto L_%08x;" % (cond, target)


@handler(*_JCC)
def h_jcc(ctx, ins):
    (op,) = _ops(ins, 1)
    if op.type != X86_OP_IMM:
        raise Reject("indirect conditional jump")
    return [_jump_stmt(ctx, _JCC[ins.mnemonic], op.imm & 0xffffffff)]


@handler("jmp")
def h_jmp(ctx, ins):
    (op,) = _ops(ins, 1)
    if op.type == X86_OP_IMM:
        t = op.imm & 0xffffffff
        if ctx.is_tail(t):
            ctx.callees.add(t)
            return ["f_%08x(c);" % t, "return;"]      # caller's return address is still at [esp]
        return ["goto L_%08x;" % t]
    slot = _mem_iat_slot(ctx.image, op)
    if slot is not None:
        # A tail jump to an import (a whole-function thunk, or the end of a body): [esp] is our
        # caller's return address with the import's args above it. lift_jump enters a lifted target
        # as is; otherwise it pops the return address and lets call_guest push its own slot: the
        # import finds its args right above that slot, and its `ret N` leaves esp exactly where our
        # caller expects. The bridge never pops args itself.
        return ["lift_jump(c, rd32(c, 0x%xu));" % slot, "return;"]
    if ins.address in ctx.switches:
        return _switch_stmts(ctx, ins)
    if op.type == X86_OP_MEM and op.mem.base and not op.mem.index and not op.mem.segment:
        # `jmp [reg+disp]` is how MSVC compiles a virtual tail call (`mov edx,[ecx]; jmp [edx+N]`):
        # the frame is gone and [esp] is our caller's return address, as for an import tail jump. A
        # switch always has an index register, so it never takes this path.
        _check_size(_opsize(op), 4)
        return ["lift_jump(c, %s);" % get(op, 4), "return;"]
    if op.type == X86_OP_REG and ctx.dead_frames:
        # a transfer (DEAD_FRAMES): to a function, or to a continuation entry with a new ESP/EBP
        _check_size(_opsize(op), 4)
        return ["lift_jump(c, %s);" % get(op, 4), "return;"]
    raise Reject("indirect jump")


def _case_value(v):
    """C case label for an index value; the values of a negated index are at or above 2^31."""
    return "%du" % v if v >= 0x80000000 else "%d" % v


def _switch_stmts(ctx, ins):
    """C switch on the dispatch register: `jmp dword ptr [R*4 + T]` with R holding the case index
    (for the two-level form the byte-table load before the jump already put the dword index in R).
    An index outside the recovered table means the recovery was wrong, so default is a hard stop."""
    op = ins.operands[0]
    ri, rs, _ = _regi(op.mem.index)
    _check_size(rs, 4)
    lines = ["switch (c->r[%s]) {" % _CN[ri]]
    for v, t in ctx.switches[ins.address]:
        lines.append("    case %s: goto L_%08x;" % (_case_value(v), t))
    lines.append('    default: UNSUPPORTED(c, 0x%08xu, "%s"); return;' % (ins.address, _cstr(_text(ins))))
    lines.append("}")
    return lines


@handler("call")
def h_call(ctx, ins):
    (op,) = _ops(ins, 1)
    if op.type == X86_OP_IMM:
        return _direct_call(ctx, op.imm & 0xffffffff, ins.address + ins.size)
    ret_va = ins.address + ins.size
    slot = _mem_iat_slot(ctx.image, op)
    if slot is not None:
        return ["lift_call_ret(c, rd32(c, 0x%xu), 0x%xu);" % (slot, ret_va)]
    if op.type in (X86_OP_REG, X86_OP_MEM):
        _check_size(_opsize(op), 4)
        # the target is computed before anything else runs (call [esp+4] reads the old esp)
        return ["{ uint32_t t = %s; lift_call_ret(c, t, 0x%xu); }" % (get(op, 4), ret_va)]
    raise Reject("call operand")


@handler("ret")
def h_ret(ctx, ins):
    imm = 0
    if ins.operands:
        (op,) = _ops(ins, 1)
        if op.type != X86_OP_IMM:
            raise Reject("ret operand")
        imm = op.imm
    hook = ["lift_exit_hook(c, 0x%08xu);" % ctx.entry] if ctx.entry in EXIT_HOOKS else []
    return hook + ["c->r[ESP] += %du;" % (4 + imm), "return;"]


@handler("leave")
def h_leave(ctx, ins):
    return ["c->r[ESP] = c->r[EBP];", "c->r[EBP] = pop32(c);"]


@handler("cdq")
def h_cdq(ctx, ins):
    return ["c->r[EDX] = (c->r[EAX] & 0x80000000u) ? 0xffffffffu : 0u;"]


@handler("cwde")
def h_cwde(ctx, ins):
    return ["c->r[EAX] = (uint32_t)(int32_t)(int16_t)(c->r[EAX] & 0xffffu);"]


@handler("cmp")
def h_cmp(ctx, ins):
    a, b = _ops(ins, 2)
    s = _size2(a, b)
    # the helper stays even when dead: its operands are the memory reads of the instruction
    on = flags_wanted(ctx, F_ALL)
    return ["flags_sub%d(%s, %s, %s);" % (_bits(s), fl_arg(on), get(a, s), get(b, s))]


@handler("test")
def h_test(ctx, ins):
    a, b = _ops(ins, 2)
    s = _size2(a, b)
    on = flags_wanted(ctx, F_ALL)
    return ["flags_logic%d(%s, %s & %s);" % (_bits(s), fl_arg(on), get(a, s), get(b, s))]


# ---------------------------------------------------------------- dead flags

# Within one basic block the flags are computed only where a later instruction can still read them.
# Backward liveness: all six flags are live at the end of every block (the successors, a return, a tail
# jump and a call all may read them), and an instruction's own flag code is dropped only when none of the
# flags it sets is live after it. A dropped flag helper that returns a value gets FL_DEAD(c) in place of c
# (flags.h): its operand reads and its result stay, and the stores go to a throwaway block.

def flags_wanted(ctx, writes):
    """True when the flag code of the current instruction, which sets the flags in writes, must be emitted
    (some flag in it is live after the instruction). False: none is, the handler drops that code, and
    the helpers that return a value take fl_arg(False)."""
    ctx.flags_checked += 1
    if ctx.flags_live & writes:
        return True
    ctx.flags_skipped = True
    return False


def fl_arg(on):
    """First argument of a flag helper: the CPU, or the throwaway block when the flags are dead."""
    return "c" if on else "FL_DEAD(c)"


_NO_FLAGS = {"mov", "movzx", "movsx", "lea", "push", "pop", "xchg", "nop", "cdq", "cwd", "cwde", "cbw",
             "bswap", "not", "leave", "pushad", "pushal", "popad", "popal", "pushaw", "popaw", "movq",
             "emms", "cld", "std"}
_ALU_KILL = {"add", "sub", "cmp", "test", "and", "or", "xor", "neg", "xadd", "cmpxchg", "bsf", "bsr",
             "mul", "imul"}
_SHIFTS = {"shl", "sal", "shr", "sar", "shld", "shrd", "rol", "ror", "rcl", "rcr"}
_X87_CMP = {"fcomi", "fcomip", "fucomi", "fucomip", "fcompi", "fucompi"}     # capstone spells some compi
_UNKNOWN = (F_ALL, 0)                                                        # reads all, kills none


def _cond_reads(expr):
    """The flags a condition reads, from its C expression in _JCC."""
    return sum(_F_BIT[f] for f in set(re.findall(r"c->(cf|pf|af|zf|sf|of)\b", expr)))


def _shift_effect(ins):
    """Shifts and rotates. A count of zero changes nothing, so only an immediate count can kill."""
    m = ins.mnemonic
    cnt = ins.operands[-1]
    if cnt.type != X86_OP_IMM:                       # count in CL: may be zero at run time
        return (F_CF if m in ("rcl", "rcr") else 0), 0
    n = cnt.imm & 31
    if n == 0:
        return 0, 0
    if m in ("rol", "ror"):
        return 0, F_CF | F_OF
    if m in ("rcl", "rcr"):
        width = 8 * _opsize(ins.operands[0])
        return F_CF, (0 if n % (width + 1) == 0 else F_CF | F_OF)     # a whole turn of the ring: no change
    return 0, F_ALL


def flag_effect(ins):
    """(reads, kill) for the six flags around one instruction the translator emits as its handler does.
    reads: flags whose value before the instruction can matter to it, or that it leaves to code that may
    read them (calls, returns, jumps, division faults). kill: flags it always overwrites, so their value
    before it is dead. kill must be a subset of what the handler's flag code writes on every run.
    Anything not listed reads every flag and kills none."""
    m = ins.mnemonic
    if m in _JCC:
        return _cond_reads(_JCC[m]), 0
    if m.startswith("set") and "j" + m[3:] in _JCC:
        return _cond_reads(_JCC["j" + m[3:]]), 0
    if m.startswith("cmov") and "j" + m[4:] in _JCC:
        return _cond_reads(_JCC["j" + m[4:]]), 0
    if m in _NO_FLAGS:
        return 0, 0
    if m in _ALU_KILL:
        return 0, F_ALL
    if m in ("adc", "sbb"):
        return F_CF, F_ALL
    if m in ("inc", "dec"):
        return 0, F_PF | F_AF | F_ZF | F_SF | F_OF                   # inc and dec keep CF
    if m in _SHIFTS:
        return _shift_effect(ins)
    if m in ("bt", "bts", "btr", "btc"):
        return 0, F_CF
    if m == "lahf":
        return F_CF | F_PF | F_AF | F_ZF | F_SF, 0
    if m == "sahf":
        return 0, F_CF | F_PF | F_AF | F_ZF | F_SF                  # OF is kept
    if m in ("clc", "stc"):
        return 0, F_CF
    if m == "cmc":
        return F_CF, F_CF
    if m in ("div", "idiv", "call", "jmp", "ret", "pushfd"):
        return F_ALL, 0
    if m in _X87_CMP:
        return 0, F_ALL                                              # x87_comi writes all six
    if m.startswith("f") and not m.startswith("fcmov"):
        return 0, 0                                                  # other x87: no EFLAGS
    parts = m.split()                                                # "rep movsb", "repe cmpsb"
    kind = parts[-1][:4]
    if len(parts) <= 2 and kind in ("movs", "stos", "lods", "cmps", "scas"):
        if kind in ("cmps", "scas"):
            # without a prefix the helper sets all six (flags_sub); with a repeat it reads ZF per element
            return (0, F_ALL) if len(parts) == 1 else (F_ALL, 0)
        return 0, 0
    return _UNKNOWN


def _translate(ctx, ins):
    """(lines or None, reason, insn): the handler's output for one instruction, the lock prefix stripped.
    lines is None when the instruction is not translated."""
    h, ins = _handler_for(ins)
    if h is None:
        return None, "no handler", ins
    try:
        return h(ctx, ins), None, ins
    except Reject as e:
        return None, str(e), ins


def _live_after(ctx, insns, blocks):
    """{va: flags live just after the instruction at va}. Pass 1 translates every instruction with all flags
    live: an instruction the translator rejects leaves the function as UNSUPPORTED and reads every flag.
    Pass 2 (the caller) emits. Backward over each block, from all-live at its end."""
    effects = {}
    ctx.flags_live = F_ALL
    for blk in blocks:
        for a in blk:
            ins = insns[a]
            if ins is None:
                effects[a] = _UNKNOWN
                continue
            lines, _, wins = _translate(ctx, ins)
            effects[a] = flag_effect(wins) if lines is not None else _UNKNOWN
    live_after = {}
    for blk in blocks:
        live = F_ALL
        for a in reversed(blk):
            live_after[a] = live
            reads, kill = effects[a]
            live = reads | (live & ~kill)
    return live_after


# ---------------------------------------------------------------- block discovery

_UNCOND = {"jmp", "ret", "retf", "int3", "hlt", "ud2", "int", "iret", "iretd"}


def _is_jcc(mnem):
    return mnem in _JCC


def _is_uncond(ins):
    return ins is None or ins.mnemonic in _UNCOND


def _decode(image, va):
    try:
        b = image.read(va, 16)
    except ValueError:
        return None
    if not b:
        return None
    return next(_MD.disasm(b, va), None)


def _is_noreturn_call(image, ins):
    """A call through an import that never returns (exit, _CxxThrowException, ...): either a
    direct call to its `jmp [iat]` thunk or an indirect call through the IAT slot."""
    if ins.mnemonic != "call" or not ins.operands:
        return False
    op = ins.operands[0]
    if op.type == X86_OP_IMM:
        slot = _thunk_slot(image, op.imm & 0xffffffff)
    else:
        slot = _mem_iat_slot(image, op)
    return slot is not None and image.iat[slot].split("!", 1)[-1] in NORETURN


def _scan(image, entry, known):
    """Recursive descent. Returns ({va: CsInsn or None (undecodable)}, leaders, switches, noret).

    switches: {va of an indirect jmp: [(index value, case target va)]} for every MSVC switch that
    functions.find_switch recovers. Its targets are walked like jump targets. A switch needs the
    instructions before its jump (the bound compare sits behind a ja), so the jumps are resolved
    after the linear walks, and the targets they add are walked in another round.
    noret: va of each call to a no-return import. Nothing after it is walked: the bytes behind it
    are the next function or data, not this function's code."""
    insns, leaders, prev = {}, {entry}, {}     # prev: va -> va of the instruction falling into it
    work, started = [entry], set()
    pending, switches, noret = [], {}, set()
    read = _reader(image)

    def prev_of(ins):
        return insns.get(prev.get(ins.address))

    while True:
        while work:
            a = work.pop()
            if a in started:
                continue
            started.add(a)
            leaders.add(a)
            while True:
                if a in insns:                 # walked into code decoded earlier
                    leaders.add(a)
                    break
                ins = _decode(image, a)
                insns[a] = ins
                if ins is None:
                    break
                m = ins.mnemonic
                if m in _UNCOND:
                    if m == "jmp" and ins.operands[0].type == X86_OP_IMM:
                        t = ins.operands[0].imm & 0xffffffff
                        if not (t != entry and t in known):
                            work.append(t)
                    elif m == "jmp" and ins.operands[0].type == X86_OP_MEM:
                        pending.append(a)
                    break
                if m == "call" and _is_noreturn_call(image, ins):
                    noret.add(a)
                    break
                if _is_jcc(m):
                    nxt = a + ins.size
                    prev[nxt] = a
                    leaders.add(nxt)
                    work.append(nxt)
                    t = ins.operands[0].imm & 0xffffffff if ins.operands[0].type == X86_OP_IMM else None
                    if t is not None and not (t != entry and t in known):
                        work.append(t)
                    break
                prev[a + ins.size] = a
                a += ins.size
        jumps, pending = pending, []
        for a in jumps:
            sw = find_switch(read, image.is_code, insns[a], prev_of, entry)
            if sw is not None:
                switches[a] = list(zip(sw["values"], sw["targets"]))
                leaders.update(sw["targets"])
                work.extend(sw["targets"])
        if not work:
            break
    return insns, leaders, switches, noret


def _blocks(insns, leaders, noret=frozenset()):
    """Split the decoded instructions into basic blocks: lists of instruction addresses.
    A call to a no-return import ends its block."""
    blocks, cur, prev_end = [], [], None
    for a in sorted(insns):
        ins = insns[a]
        if cur and (a in leaders or a != prev_end):
            blocks.append(cur)
            cur = []
        cur.append(a)
        prev_end = a + (ins.size if ins is not None else 1)
        if _is_uncond(ins) or _is_jcc(ins.mnemonic) or a in noret:
            blocks.append(cur)
            cur = []
    if cur:
        blocks.append(cur)
    return blocks


def discover_blocks(image, entry, known_entries=frozenset()):
    """Basic blocks of the function at entry as [(start, end)] (end exclusive), in address order.
    Jumps to other known entries are not followed (they are tail calls)."""
    insns, leaders, _, noret = _scan(image, entry, frozenset(known_entries))
    out = []
    for blk in _blocks(insns, leaders, noret):
        last = blk[-1]
        ins = insns[last]
        out.append((blk[0], last + (ins.size if ins is not None else 1)))
    return out


# ---------------------------------------------------------------- translation

@dataclass
class LiftResult:
    name: str
    entry: int
    c: str
    unsupported: list
    callees: list
    ok: bool
    flags_checked: int = 0      # instructions whose flag code was a candidate for dead-flag elimination
    flags_removed: int = 0      # ... and whose flag code was dropped


def _cstr(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _text(ins):
    return ("%s %s" % (ins.mnemonic, ins.op_str)).strip()


def lift_function(image, entry, known_entries=frozenset(), iat=None, dead_flags=None, x87_locals=None,
                  x87_cw_local=None, dead_frames=None, aux=False):
    """Translate the function at entry. known_entries: VAs of functions that are lifted too
    (direct calls to them become f_xxx calls). iat: overrides image.iat for import detection.
    dead_flags: drop the flag code no later instruction of the block reads (default: DEAD_FLAGS).
    x87_locals: keep the x87 registers in locals within a block (X87Cache; default: X87_LOCALS).
    x87_cw_local: keep the control word in a local for the arithmetic helpers (default: X87_CW_LOCAL).
    dead_frames: native non-local transfers (default: DEAD_FRAMES).
    aux: entry is a continuation entry (build.lift_set aux): see the frame bound below."""
    if dead_frames is None:
        dead_frames = DEAD_FRAMES
    if iat is not None:
        image = _IATOverride(image, iat)
    if dead_flags is None:
        dead_flags = DEAD_FLAGS
    if x87_locals is None:
        x87_locals = X87_LOCALS
    if x87_cw_local is None:
        x87_cw_local = X87_CW_LOCAL
    known = frozenset(known_entries)
    insns, leaders, switches, noret = _scan(image, entry, known)
    blocks = _blocks(insns, leaders, noret)
    n_real = sum(1 for v in insns.values() if v is not None)
    ctx = Ctx(image=image, entry=entry, known=known, n_insns=n_real,
              lifted=set(known) | {entry}, switches=switches)
    live_after = _live_after(ctx, insns, blocks) if dead_flags else {}
    ctx.flags_checked = 0
    unsupported, body = [], []
    xc = ctx.x87 = X87Cache() if x87_locals else None
    ctx.cw_local = x87_cw_local
    ctx.dead_frames = dead_frames

    def x87_flush():
        out = []
        xc.flush(out)
        body.extend("    " + ln for ln in out)

    for bi, blk in enumerate(blocks):
        body.append("L_%08x: ;" % blk[0])
        for a in blk:
            ins = insns[a]
            if xc is not None:
                m = _handler_for(ins)[1].mnemonic if ins is not None else ""
                if m not in X87_NEUTRAL and m not in X87_CACHED or a in INSN_HOOKS:
                    x87_flush()
            if a in INSN_HOOKS:
                body.append("    lift_insn_hook(c, 0x%08xu);" % a)
            if ins is None:
                unsupported.append((a, "(bad)"))
                body.append("    /* %08x: (undecodable) */" % a)
                body.append('    UNSUPPORTED(c, 0x%08xu, "(bad)");' % a)
                body.append("    return;")
                break
            text = _text(ins)
            body.append("    /* %08x: %s */" % (a, text))
            ctx.flags_live = live_after.get(a, F_ALL)
            ctx.flags_skipped = False
            snap = xc.snapshot() if xc is not None else None
            lines, reason, _ = _translate(ctx, ins)
            if lines is None and xc is not None:
                xc.restore(snap)                       # a handler that rejected may have touched the cache
                x87_flush()
            if ctx.flags_skipped and lines is not None:
                ctx.flags_removed += 1
            if lines is None:
                unsupported.append((a, text))
                body.append("    /* not translated: %s */" % reason)
                body.append('    UNSUPPORTED(c, 0x%08xu, "%s");' % (a, _cstr(text)))
                if _is_uncond(ins):
                    body.append("    return;")
            else:
                for ln in lines:
                    body.append("    " + ln)
            if dead_frames and lines is not None and _sets_esp(ins):
                # An explicit ESP load (an __except body's `mov esp, [ebp-18h]`, `mov esp, ebp`, `lea esp, [ebp-N]`) may
                # move this code into its owner's frame, above the ESP this C function was entered with: the frame
                # bound becomes the owner's entry ESP, EBP + 4 (MSVC's EBP frames, _EH_prolog's too).
                body.append("    if (c->r[EBP] + 4u > xesp0) xesp0 = c->r[EBP] + 4u;")
            if dead_frames and lines is not None and ins.mnemonic == "call":
                body.append("    if (__builtin_expect(c->r[ESP] > xesp0, 0)) return;   /* frame discarded */")
                if a in noret:
                    # a no-return import came back (RaiseException after ExceptionContinueExecution): the code after
                    # the call was never decoded, so stop rather than return to our caller with the wrong stack
                    body.append('    lift_unsupported(c, 0x%08xu, "a no-return import returned");' % a)
            if x87_cw_local and lines is not None and ins.mnemonic in X87_CW_CHANGERS:
                body.append("    xcw = c->cw;")
            if a in noret:
                body.append("    return;")          # the import does not return
        if xc is not None:
            x87_flush()                                # a block that falls through (or ends in a neutral instruction)
        last = blk[-1]
        ins = insns[last]
        if ins is not None and not _is_uncond(ins) and last not in noret:
            nxt = last + ins.size
            if bi + 1 >= len(blocks) or blocks[bi + 1][0] != nxt:
                body.append("    goto L_%08x;" % nxt)
    if blocks[0][0] != entry:
        # The blocks are emitted in address order, but execution starts at the top of the C function.
        # A jump to a lower address that is not a known entry puts the entry block after lower code.
        body.insert(0, "    goto L_%08x;" % entry)

    name = "f_%08x" % entry
    decls = sorted(t for t in ctx.callees if t in ctx.lifted)
    out = ['#include "lift.h"', ""]
    out += ["void f_%08x(CPU *c);" % t for t in decls]
    head = []
    if xc is not None and xc.used:
        head = ["    uint32_t xt = 0;",
                "    double xs0 = 0, xs1 = 0, xs2 = 0, xs3 = 0, xs4 = 0, xs5 = 0, xs6 = 0, xs7 = 0;"]
    if x87_cw_local and any("xcw" in ln for ln in body):
        head = head + ["    uint16_t xcw = c->cw;"]
    if dead_frames and any("xesp0" in ln for ln in body):
        # The frame bound: the entry ESP; for a continuation entry, which runs in its owner's frame after a transfer set
        # ESP/EBP (and may pop above the ESP it was entered with, e.g. `add esp, 8` after a setjmp call), the owner's
        # entry ESP, EBP + 4, when that is higher.
        if aux:
            head = head + ["    uint32_t xesp0 = c->r[ESP];",
                           "    if (c->r[EBP] + 4u > xesp0) xesp0 = c->r[EBP] + 4u;"]
        else:
            head = head + ["    uint32_t xesp0 = c->r[ESP];"]
    if entry in ENTRY_HOOKS:
        head = head + ["    lift_entry_hook(c, 0x%08xu);" % entry]
    out +=["", "void %s(CPU *c)" % name, "{"] + head + body + ["}", ""]
    return LiftResult(name=name, entry=entry, c="\n".join(out), unsupported=unsupported,
                      callees=sorted(ctx.callees), ok=not unsupported,
                      flags_checked=ctx.flags_checked, flags_removed=ctx.flags_removed)


def _sets_esp(ins):
    """mov/lea/xchg with ESP as the destination (or either operand of xchg): ESP loaded from elsewhere."""
    m = ins.mnemonic
    if m not in ("mov", "lea", "xchg") or not ins.operands:
        return False
    ops = ins.operands if m == "xchg" else ins.operands[:1]
    return any(op.type == X86_OP_REG and ins.reg_name(op.reg) == "esp" for op in ops)


class _IATOverride:
    """Wraps an image with a different import map (lift_function's iat argument)."""

    def __init__(self, image, iat):
        self._image = image
        self.iat = iat
        self.base = getattr(image, "base", 0)

    def read(self, va, n):
        return self._image.read(va, n)

    def is_code(self, va):
        return self._image.is_code(va)


# ---------------------------------------------------------------- instruction families

def _load_ops():
    """Each instruction family lives in lift/ops_<family>.py and registers its handlers with
    `from x86c import handler, ...`. Loading them here keeps families out of each other's files."""
    import glob
    import importlib
    sys.modules.setdefault("x86c", sys.modules[__name__])     # when run as a script
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    for path in sorted(glob.glob(os.path.join(HERE, "ops_*.py"))):
        importlib.import_module(os.path.splitext(os.path.basename(path))[0])


_load_ops()


# ---------------------------------------------------------------- CLI

def main(argv):
    if len(argv) < 3:
        print("usage: x86c.py <dll> <hex entry> [...]", file=sys.stderr)
        return 2
    img = PEImage(argv[1])
    entries = [int(x, 16) for x in argv[2:]]
    known = set(entries) | {va for va, _ in img.exports}
    for e in entries:
        res = lift_function(img, e, known)
        print(res.c)
        for va, text in res.unsupported:
            print("unsupported %s: %08x %s" % (res.name, va, text), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
