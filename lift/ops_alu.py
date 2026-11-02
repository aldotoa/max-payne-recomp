"""Integer ALU instruction handlers with exact flags (M5).

Covers add/sub/adc/sbb/and/or/xor, inc/dec/neg/not, the shifts and rotates, shld/shrd, mul/imul,
div/idiv (#DE through lift_div_fault), setcc/cmovcc, bt/bts/btr/btc, bsf/bsr, bswap, cbw/cwd,
lahf/sahf, clc/stc/cmc/cld/std, xadd and cmpxchg. Flag helpers live in lift/runtime/flags.h.

Memory destinations compute the effective address once (`ad`) and read-modify-write through it.
Flags the Intel manual leaves undefined are left alone, or set to the common hardware value where
the helper needs a value (see flags.h).
"""
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from x86c import (_JCC, _MD, _opsize, _ops, _size2, Reject, ea, get, put, handler,
                  F_ALL, F_CF, F_PF, F_AF, F_ZF, F_SF, F_OF, fl_arg, flags_wanted)

W = {1: 8, 2: 16, 4: 32}                  # operand size in bytes -> width in bits
_ACC = {1: "(c->r[EAX] & 0xffu)", 2: "(c->r[EAX] & 0xffffu)", 4: "c->r[EAX]"}


def _block(lines):
    return ["{"] + ["    " + ln for ln in lines] + ["}"]


def _addr(op):
    """(declarations, address name) for a memory operand, computed once; ([], None) for a register."""
    if op.type == X86_OP_MEM:
        return ["uint32_t ad = %s;" % ea(op)], "ad"
    return [], None


def _acc_put(size, expr):
    """Store expr into the accumulator (AL, AX or EAX), keeping the bits above it."""
    if size == 1:
        return "c->r[EAX] = (c->r[EAX] & 0xffffff00u) | ((%s) & 0xffu);" % expr
    if size == 2:
        return "c->r[EAX] = (c->r[EAX] & 0xffff0000u) | ((%s) & 0xffffu);" % expr
    return "c->r[EAX] = (%s);" % expr


def _fault(ins):
    return ["lift_div_fault(c, 0x%08xu);" % ins.address, "return;"]


# ---------------------------------------------------------------- add sub adc sbb and or xor

_ARITH = {
    # mnemonic: (width -> statements that set the flags from x and y,
    #            (width, first helper argument) -> C expression for the result r; adc/sbb set the flags
    #            inside it, so they pass fl_arg, which is FL_DEAD(c) when the flags are dead)
    "add": (lambda w: ["fl_add(c, x, y, %d);" % w], lambda w, fc: "x + y"),
    "sub": (lambda w: ["fl_sub(c, x, y, %d);" % w], lambda w, fc: "x - y"),
    "adc": (lambda w: [], lambda w, fc: "flags_adc(%s, x, y, %d)" % (fc, w)),
    "sbb": (lambda w: [], lambda w, fc: "flags_sbb(%s, x, y, %d)" % (fc, w)),
    "and": (lambda w: ["fl_logic(c, r, %d);" % w], lambda w, fc: "x & y"),
    "or": (lambda w: ["fl_logic(c, r, %d);" % w], lambda w, fc: "x | y"),
    "xor": (lambda w: ["fl_logic(c, r, %d);" % w], lambda w, fc: "x ^ y"),
}


@handler(*_ARITH)
def h_arith(ctx, ins):
    dst, src = _ops(ins, 2)
    s = _size2(dst, src)
    flags, expr = _ARITH[ins.mnemonic]
    decl, ad = _addr(dst)
    on = flags_wanted(ctx, F_ALL)
    body = decl + [
        "uint32_t x = %s, y = %s;" % (get(dst, s, ad), get(src, s)),
        "uint32_t r = %s;" % expr(W[s], fl_arg(on)),
    ] + (flags(W[s]) if on else []) + [put(dst, s, "r", ad)]
    return _block(body)


@handler("inc", "dec")
def h_incdec(ctx, ins):
    (op,) = _ops(ins, 1)
    s = _opsize(op)
    decl, ad = _addr(op)
    fn = "flags_inc" if ins.mnemonic == "inc" else "flags_dec"
    on = flags_wanted(ctx, F_PF | F_AF | F_ZF | F_SF | F_OF)      # CF is kept, not written
    return _block(decl + ["uint32_t x = %s;" % get(op, s, ad),
                          "uint32_t r = %s(%s, x, %d);" % (fn, fl_arg(on), W[s]),
                          put(op, s, "r", ad)])


@handler("neg")
def h_neg(ctx, ins):
    (op,) = _ops(ins, 1)
    s = _opsize(op)
    decl, ad = _addr(op)
    on = flags_wanted(ctx, F_ALL)
    # neg is 0 - x: CF is set when x is nonzero, which the subtraction flags give directly
    return _block(decl + ["uint32_t x = %s;" % get(op, s, ad),
                          "uint32_t r = 0u - x;"] + (["fl_sub(c, 0, x, %d);" % W[s]] if on else []) +
                  [put(op, s, "r", ad)])


@handler("not")
def h_not(ctx, ins):
    (op,) = _ops(ins, 1)
    s = _opsize(op)
    decl, ad = _addr(op)
    return _block(decl + ["uint32_t x = %s;" % get(op, s, ad),
                          put(op, s, "~x", ad)])


# ---------------------------------------------------------------- shifts, rotates, double shifts

_SHIFT_FN = {"shl": "flags_shl", "sal": "flags_shl", "shr": "flags_shr", "sar": "flags_sar",
             "rol": "flags_rol", "ror": "flags_ror", "rcl": "flags_rcl", "rcr": "flags_rcr"}


def _count(op):
    """A shift count: an immediate or CL. The helpers mask it to 5 bits."""
    if op.type == X86_OP_IMM:
        return get(op, 1)
    if op.type == X86_OP_REG and _MD.reg_name(op.reg) == "cl":
        return get(op, 1)
    raise Reject("shift count operand")


_SHIFT_WRITES = {"rol": F_CF | F_OF, "ror": F_CF | F_OF, "rcl": F_CF | F_OF, "rcr": F_CF | F_OF}


@handler(*_SHIFT_FN)
def h_shift(ctx, ins):
    dst, cnt = _ops(ins, 2)
    s = _opsize(dst)
    decl, ad = _addr(dst)
    fn = _SHIFT_FN[ins.mnemonic]
    on = flags_wanted(ctx, _SHIFT_WRITES.get(ins.mnemonic, F_ALL))
    return _block(decl + ["uint32_t r = %s(%s, %s, %s, %d);" % (fn, fl_arg(on), get(dst, s, ad), _count(cnt), W[s]),
                          put(dst, s, "r", ad)])


@handler("shld", "shrd")
def h_double_shift(ctx, ins):
    dst, src, cnt = _ops(ins, 3)
    s = _size2(dst, src)
    if s == 1 or src.type != X86_OP_REG:
        raise Reject("double shift operands")
    decl, ad = _addr(dst)
    fn = "flags_shld" if ins.mnemonic == "shld" else "flags_shrd"
    on = flags_wanted(ctx, F_ALL)
    return _block(decl + ["uint32_t r = %s(%s, %s, %s, %s, %d);" % (
        fn, fl_arg(on), get(dst, s, ad), get(src, s), _count(cnt), W[s]), put(dst, s, "r", ad)])


# ---------------------------------------------------------------- multiply and divide

def _mul_one(ctx, ins, op):
    """mul / imul with one operand: the product goes to AX, DX:AX or EDX:EAX. Flags: all six, from the
    product (see the comments in flags.h); their lines are dropped when none is live."""
    s = _opsize(op)
    decl, ad = _addr(op)
    x = get(op, s, ad)
    signed = ins.mnemonic == "imul"
    on = flags_wanted(ctx, F_ALL)

    def fl(*lines):
        return list(lines) if on else []

    if s == 1:
        body = ["uint32_t x = %s;" % x]
        if signed:
            body += ["int32_t p = (int8_t)(c->r[EAX] & 0xffu) * (int8_t)x;",
                     "c->r[EAX] = (c->r[EAX] & 0xffff0000u) | ((uint32_t)p & 0xffffu);"] + \
                    fl("c->cf = c->of = p != (int8_t)p;", "fl_szp(c, (uint32_t)p, 8);", "c->af = 0;")
        else:
            body += ["uint32_t p = (c->r[EAX] & 0xffu) * x;",
                     "c->r[EAX] = (c->r[EAX] & 0xffff0000u) | (p & 0xffffu);"] + \
                    fl("c->cf = c->of = (p >> 8) != 0;", "fl_szp(c, p, 8);", "c->af = 0;")
    elif s == 2:
        body = ["uint32_t x = %s;" % x]
        if signed:
            body += ["int32_t p = (int16_t)(c->r[EAX] & 0xffffu) * (int16_t)x;",
                     "c->r[EAX] = (c->r[EAX] & 0xffff0000u) | ((uint32_t)p & 0xffffu);",
                     "c->r[EDX] = (c->r[EDX] & 0xffff0000u) | (((uint32_t)p >> 16) & 0xffffu);"] + \
                    fl("c->cf = c->of = p != (int16_t)p;", "fl_szp(c, (uint32_t)p, 16);", "c->af = 0;")
        else:
            body += ["uint32_t p = (c->r[EAX] & 0xffffu) * x;",
                     "c->r[EAX] = (c->r[EAX] & 0xffff0000u) | (p & 0xffffu);",
                     "c->r[EDX] = (c->r[EDX] & 0xffff0000u) | (p >> 16);"] + \
                    fl("c->cf = c->of = (p >> 16) != 0;", "fl_szp(c, p, 16);", "c->af = 0;")
    else:
        body = ["uint32_t x = %s;" % x]
        if signed:
            body += ["int64_t p = (int64_t)(int32_t)c->r[EAX] * (int64_t)(int32_t)x;",
                     "c->r[EAX] = (uint32_t)p;",
                     "c->r[EDX] = (uint32_t)((uint64_t)p >> 32);"] + \
                    fl("c->cf = c->of = p != (int32_t)p;", "fl_szp(c, (uint32_t)p, 32);", "c->af = 0;")
        else:
            body += ["uint64_t p = (uint64_t)c->r[EAX] * x;",
                     "c->r[EAX] = (uint32_t)p;",
                     "c->r[EDX] = (uint32_t)(p >> 32);"] + \
                    fl("c->cf = c->of = (p >> 32) != 0;", "fl_szp(c, (uint32_t)p, 32);", "c->af = 0;")
    return _block(decl + body)


def _imul_two(ctx, dst, a_op, b_op):
    """imul r, r/m and imul r, r/m, imm: dst = a * b truncated; CF = OF = product does not fit."""
    s = _size2(dst, a_op)
    if s == 1 or dst.type != X86_OP_REG:
        raise Reject("imul destination")
    sx = "(int16_t)" if s == 2 else "(int32_t)"
    decl, ad = _addr(a_op)
    on = flags_wanted(ctx, F_ALL)
    body = decl + [
        "int64_t p = (int64_t)%s(%s) * (int64_t)%s(%s);" % (sx, get(a_op, s, ad), sx, get(b_op, s)),
        put(dst, s, "(uint32_t)p"),
    ] + ([
        "c->cf = c->of = p != (int64_t)%s(p);" % sx,
        "fl_szp(c, (uint32_t)p, %d);" % (8 * s),
        "c->af = 0;",
    ] if on else [])
    return _block(body)


def _div(ins, op):
    """div (unsigned) and idiv (signed) with one operand. #DE on a zero divisor or a quotient that
    does not fit; flags are left unchanged (undefined by the manual)."""
    s = _opsize(op)
    decl, ad = _addr(op)
    signed = ins.mnemonic == "idiv"
    body = decl + ["uint32_t x = %s;" % get(op, s, ad)]
    if not signed and s == 1:
        body += ["uint32_t n = c->r[EAX] & 0xffffu;",
                 "if (x == 0 || n / x > 0xffu) {"] + ["    " + f for f in _fault(ins)] + ["}",
                 "c->r[EAX] = (c->r[EAX] & 0xffff0000u) | ((n % x) << 8) | (n / x);"]
    elif not signed and s == 2:
        body += ["uint32_t n = ((c->r[EDX] & 0xffffu) << 16) | (c->r[EAX] & 0xffffu);",
                 "if (x == 0 || n / x > 0xffffu) {"] + ["    " + f for f in _fault(ins)] + ["}",
                 "uint32_t q = n / x, rm = n % x;",
                 "c->r[EAX] = (c->r[EAX] & 0xffff0000u) | q;",
                 "c->r[EDX] = (c->r[EDX] & 0xffff0000u) | rm;"]
    elif not signed:
        body += ["uint64_t n = ((uint64_t)c->r[EDX] << 32) | c->r[EAX];",
                 "uint64_t d = x;",
                 "if (d == 0 || n / d > 0xffffffffu) {"] + ["    " + f for f in _fault(ins)] + ["}",
                 "c->r[EAX] = (uint32_t)(n / d);",
                 "c->r[EDX] = (uint32_t)(n % d);"]
    elif s == 1:
        body += ["int64_t n = (int16_t)(c->r[EAX] & 0xffffu);",
                 "int64_t d = (int8_t)x;",
                 "if (d == 0) {"] + ["    " + f for f in _fault(ins)] + ["}",
                 "int64_t q = n / d, rm = n % d;",
                 "if (q < -128 || q > 127) {"] + ["    " + f for f in _fault(ins)] + ["}",
                 "c->r[EAX] = (c->r[EAX] & 0xffff0000u) | (((uint32_t)rm & 0xffu) << 8) | ((uint32_t)q & 0xffu);"]
    elif s == 2:
        body += ["int64_t n = (int32_t)(((c->r[EDX] & 0xffffu) << 16) | (c->r[EAX] & 0xffffu));",
                 "int64_t d = (int16_t)x;",
                 "if (d == 0) {"] + ["    " + f for f in _fault(ins)] + ["}",
                 "int64_t q = n / d, rm = n % d;",
                 "if (q < -32768 || q > 32767) {"] + ["    " + f for f in _fault(ins)] + ["}",
                 "c->r[EAX] = (c->r[EAX] & 0xffff0000u) | ((uint32_t)q & 0xffffu);",
                 "c->r[EDX] = (c->r[EDX] & 0xffff0000u) | ((uint32_t)rm & 0xffffu);"]
    else:
        body += ["int64_t n = (int64_t)(((uint64_t)c->r[EDX] << 32) | c->r[EAX]);",
                 "int64_t d = (int32_t)x;",
                 "if (d == 0 || (d == -1 && n == INT64_MIN)) {"] + ["    " + f for f in _fault(ins)] + ["}",
                 "int64_t q = n / d, rm = n % d;",
                 "if (q < INT32_MIN || q > INT32_MAX) {"] + ["    " + f for f in _fault(ins)] + ["}",
                 "c->r[EAX] = (uint32_t)q;",
                 "c->r[EDX] = (uint32_t)rm;"]
    return _block(body)


@handler("mul", "imul")
def h_mul(ctx, ins):
    ops = ins.operands
    if len(ops) == 1:
        return _mul_one(ctx, ins, ops[0])
    if ins.mnemonic != "imul":
        raise Reject("mul with %d operands" % len(ops))
    if len(ops) == 2:
        return _imul_two(ctx, ops[0], ops[0], ops[1])
    if len(ops) == 3:
        return _imul_two(ctx, ops[0], ops[1], ops[2])
    raise Reject("imul operands")


@handler("div", "idiv")
def h_div(ctx, ins):
    (op,) = _ops(ins, 1)
    if _opsize(op) is None:
        raise Reject("div immediate")
    return _div(ins, op)


# ---------------------------------------------------------------- setcc and cmovcc

_COND = {name[1:]: expr for name, expr in _JCC.items() if name.startswith("j") and name != "jecxz"}


@handler(*["set" + cc for cc in _COND], *["cmov" + cc for cc in _COND])
def h_cc(ctx, ins):
    if ins.mnemonic.startswith("set"):
        (op,) = _ops(ins, 1)
        return [put(op, 1, "((%s) ? 1u : 0u)" % _COND[ins.mnemonic[3:]])]
    dst, src = _ops(ins, 2)
    s = _size2(dst, src)
    return ["if (%s) {" % _COND[ins.mnemonic[4:]], "    " + put(dst, s, get(src, s)), "}"]


# ---------------------------------------------------------------- bit tests and scans

@handler("bt", "bts", "btr", "btc")
def h_bt(ctx, ins):
    dst, src = _ops(ins, 2)
    s = _opsize(dst)
    if s not in (2, 4):
        raise Reject("bit test size")
    width = W[s]
    m = ins.mnemonic
    decl, ad = _addr(dst)
    write = {"bt": None, "bts": "(v | bm)", "btr": "(v & ~bm)", "btc": "(v ^ bm)"}[m]
    on = flags_wanted(ctx, F_CF)
    cf_line = ["c->cf = (v & bm) != 0;"] if on else []       # the only flag bit a bit test writes

    if src.type == X86_OP_IMM:
        # bit number is the immediate modulo the operand width; the address is the operand's own
        bit = src.imm & (width - 1)
        body = decl + ["uint32_t v = %s;" % get(dst, s, ad), "uint32_t bm = 1u << %d;" % bit] + cf_line
        if write:
            body.append(put(dst, s, write, ad))
        return _block(body)

    if src.type != X86_OP_REG or _opsize(src) != s:
        raise Reject("bit offset operand")
    if dst.type == X86_OP_REG:
        # bit number is the register modulo the operand width
        body = decl + ["uint32_t v = %s;" % get(dst, s, ad),
                       "uint32_t bm = 1u << (%s & %du);" % (get(src, s), width - 1)] + cf_line
        if write:
            body.append(put(dst, s, write, ad))
        return _block(body)

    # memory with a register bit offset: the offset is signed and can address outside the operand.
    # The byte at base + (offset >> 3) holds the bit; bit (offset & 7) of that byte is the one tested.
    off = "(int16_t)" if s == 2 else "(int32_t)"
    body = ["int32_t o = %s%s;" % (off, get(src, s)),
            "uint32_t a = %s + (uint32_t)(o >> 3);" % ea(dst),
            "uint8_t v = rd8(c, a);",
            "uint8_t bm = (uint8_t)(1u << (o & 7));"] + cf_line
    if write:
        body.append("wr8(c, a, (uint8_t)%s);" % write)
    return _block(body)


@handler("bsf", "bsr")
def h_bsf(ctx, ins):
    dst, src = _ops(ins, 2)
    if dst.type != X86_OP_REG:
        raise Reject("bsf destination")
    s = _size2(dst, src)
    decl, ad = _addr(src)
    if ins.mnemonic == "bsf":
        idx = "(uint32_t)__builtin_ctz(v)"
    else:
        idx = "(uint32_t)(31 - __builtin_clz(v))"
    on = flags_wanted(ctx, F_ALL)
    # a zero source leaves the destination unchanged. Flags: ZF = (source == 0) is defined; the rest
    # are undefined, and qemu gives the logic-op flags of the source (CF = OF = AF = 0).
    return _block(decl + ["uint32_t v = %s;" % get(src, s, ad)] +
                  (["fl_logic(c, v, %d);" % (8 * s)] if on else []) +
                  ["if (v != 0) {", "    " + put(dst, s, idx), "}"])


# ---------------------------------------------------------------- byte swap, sign extension

@handler("bswap")
def h_bswap(ctx, ins):
    (op,) = _ops(ins, 1)
    if op.type != X86_OP_REG or _opsize(op) != 4:
        raise Reject("bswap operand")
    return [put(op, 4, "__builtin_bswap32(%s)" % get(op, 4))]


@handler("cbw")
def h_cbw(ctx, ins):
    return ["c->r[EAX] = (c->r[EAX] & 0xffff0000u) | ((c->r[EAX] & 0x80u) ? 0xff00u : 0u)"
            " | (c->r[EAX] & 0xffu);"]


@handler("cwd")
def h_cwd(ctx, ins):
    return ["c->r[EDX] = (c->r[EDX] & 0xffff0000u) | ((c->r[EAX] & 0x8000u) ? 0xffffu : 0u);"]


# ---------------------------------------------------------------- flag register access

@handler("lahf")
def h_lahf(ctx, ins):
    return ["c->r[EAX] = (c->r[EAX] & 0xffff00ffu) | ((uint32_t)(c->sf << 7 | c->zf << 6 | c->af << 4"
            " | c->pf << 2 | c->cf | 0x02u) << 8);"]


@handler("sahf")
def h_sahf(ctx, ins):
    if not flags_wanted(ctx, F_CF | F_PF | F_AF | F_ZF | F_SF):
        return []                               # reads AH only, so nothing else is needed
    return _block(["uint32_t ah = (c->r[EAX] >> 8) & 0xffu;",
                   "c->sf = (ah >> 7) & 1u;", "c->zf = (ah >> 6) & 1u;",
                   "c->af = (ah >> 4) & 1u;", "c->pf = (ah >> 2) & 1u;",
                   "c->cf = ah & 1u;"])


@handler("clc")
def h_clc(ctx, ins):
    return ["c->cf = 0;"] if flags_wanted(ctx, F_CF) else []


@handler("stc")
def h_stc(ctx, ins):
    return ["c->cf = 1;"] if flags_wanted(ctx, F_CF) else []


@handler("cmc")
def h_cmc(ctx, ins):
    return ["c->cf = !c->cf;"] if flags_wanted(ctx, F_CF) else []


@handler("cld")
def h_cld(ctx, ins):
    return ["c->df = 0;"]


@handler("std")
def h_std(ctx, ins):
    return ["c->df = 1;"]


# ---------------------------------------------------------------- exchange and compare-exchange

@handler("xadd")
def h_xadd(ctx, ins):
    dst, src = _ops(ins, 2)
    s = _size2(dst, src)
    decl, ad = _addr(dst)
    on = flags_wanted(ctx, F_ALL)
    # TEMP = SRC + DEST; SRC = DEST; DEST = TEMP. With dst == src the destination's write wins.
    return _block(decl + ["uint32_t x = %s, y = %s;" % (get(dst, s, ad), get(src, s)),
                          "uint32_t r = x + y;"] +
                  (["fl_add(c, x, y, %d);" % W[s]] if on else []) +
                  [put(src, s, "x"),
                   put(dst, s, "r", ad)])


@handler("cmpxchg")
def h_cmpxchg(ctx, ins):
    dst, src = _ops(ins, 2)
    s = _size2(dst, src)
    decl, ad = _addr(dst)
    # compare the accumulator with DEST: equal -> DEST = SRC, else the accumulator = DEST
    return _block(decl + ["uint32_t a = %s;" % _ACC[s],
                          "uint32_t d = %s;" % get(dst, s, ad),
                          "fl_sub(c, a, d, %d);" % W[s],
                          "if (c->zf) {",
                          "    " + put(dst, s, get(src, s), ad),
                          "} else {",
                          "    " + _acc_put(s, "d"),
                          "}"])
