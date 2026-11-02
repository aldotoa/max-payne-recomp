"""x87 instruction handlers (M5): the stack is modelled on C doubles, see lift/runtime/x87.h.

Operand conventions from capstone (x86c._MD, detail on):
  - D8 register forms print one operand, the source: `fadd st(1)` is ST(0) = ST(0) + ST(1).
  - DC register forms print both operands in Intel order: `fsub st(1), st(0)`.
  - The popping DE forms print the destination only: `faddp st(1)` is ST(1) = ST(1) + ST(0), pop.
  - The compares print the register compared with ST(0) (`fcomi st(1)` compares ST(0) with ST(1)).
  - `fcompi`/`fucompi` are capstone's spelling of fcomip/fucomip.
  - `wait` (9Bh) is a separate instruction before fnstsw, fnstcw, fninit: a no-op here.
"""
from capstone.x86 import X86_OP_MEM, X86_OP_REG

from x86c import F_ALL, X87_CACHED, Reject, _MD, ea, flags_wanted, get, handler, put


class _Direct:
    """The stack in the CPU struct (no x87 locals): the X87Cache interface, emitting the x87.h stack helpers."""

    def rd(self, i, out):
        return "x87_rd(c, %d)" % i

    def wr(self, i, expr, out):
        out.append("x87_wr(c, %d, %s);" % (i, expr))

    def push(self, expr, out):
        out.append("x87_push(c, %s);" % expr)

    def pop(self, out):
        out.append("x87_pop(c);")

    def free(self, i, out):
        out.append("x87_free(c, %d);" % i)

    def xch(self, i, out):
        out.append("x87_xch(c, %d);" % i)

    def status(self, out):
        return "x87_status(c)"


_DIRECT = _Direct()


def _st(ctx):
    """The stack model for this instruction: ctx.x87 (x86c.X87Cache) when the function keeps x87 registers in locals."""
    return ctx.x87 if ctx.x87 is not None else _DIRECT


def cached(*names):
    """handler(*names) for a handler that goes through _st(ctx): x86c does not flush the x87 locals before it."""
    X87_CACHED.update(names)
    return handler(*names)


# ---------------------------------------------------------------- operand helpers

def _sti(op):
    """Stack index of a register operand: st(i) -> i, st -> 0."""
    if op.type != X86_OP_REG:
        raise Reject("x87 operand is not a register")
    name = _MD.reg_name(op.reg)
    if name == "st":
        return 0
    if name.startswith("st(") and name.endswith(")"):
        return int(name[3:-1])
    raise Reject("x87 register %s" % name)


def _mem(op, sizes):
    """Address expression of a memory operand whose width is in sizes."""
    if op.type != X86_OP_MEM:
        raise Reject("expected a memory operand")
    if op.size not in sizes:
        raise Reject("memory width %d" % op.size)
    return ea(op)


def _reg_src(ins):
    """Stack index of the operand of a one-operand register form (none means st(1))."""
    ops = ins.operands
    if not ops:
        return 1
    if len(ops) != 1:
        raise Reject("expected one register operand")
    return _sti(ops[0])


# ---------------------------------------------------------------- arithmetic

# mnemonic -> C helper, applied as helper(c, x, y) with x = destination value, y = source value.
# Intel semantics: fsub is x - y, fsubr is y - x (the mnemonic says which operand is subtracted).
_ARITH = {
    "fadd": "x87_add", "fsub": "x87_sub", "fsubr": "x87_subr",
    "fmul": "x87_mul", "fdiv": "x87_div", "fdivr": "x87_divr",
}
# integer forms: the same helpers with an integer memory source
_IARITH = {
    "fiadd": "x87_add", "fisub": "x87_sub", "fisubr": "x87_subr",
    "fimul": "x87_mul", "fidiv": "x87_div", "fidivr": "x87_divr",
}


def _call(ctx, fn, *args):
    """An arithmetic helper call: fn(c, args) or, with the control word in a local (x86c.X87_CW_LOCAL), fnw(c, xcw, args)."""
    if ctx.cw_local:
        return "%sw(c, xcw, %s)" % (fn, ", ".join(args))
    return "%s(c, %s)" % (fn, ", ".join(args))


def _register_arith(ctx, name, ins, fn, pop):
    """Register forms. Two operands: dst, src (DC, DE with a second operand). One operand: D8
    (dst ST(0), src ST(i)) or the popping DE form (dst ST(i), src ST(0), then pop)."""
    ops = ins.operands
    if len(ops) == 2:
        d, s = _sti(ops[0]), _sti(ops[1])
    elif len(ops) == 1 and pop:
        d, s = _sti(ops[0]), 0
    elif len(ops) == 1:
        d, s = 0, _sti(ops[0])
    elif len(ops) == 0 and pop:
        d, s = 1, 0                      # faddp, fmulp, ... with no operand: st(1), st(0)
    else:
        raise Reject("%s operand count" % name)
    st, out = _st(ctx), []
    x, y = st.rd(d, out), st.rd(s, out)
    st.wr(d, _call(ctx, fn, x, y), out)
    if pop:
        st.pop(out)
    return out


def _mk_arith(name):
    fn = _ARITH[name]

    @cached(name)
    def h_reg_or_mem(ctx, ins):
        ops = ins.operands
        if len(ops) == 1 and ops[0].type == X86_OP_MEM:
            if ops[0].size == 4:
                src = "x87_ld_f32(c, %s)" % ea(ops[0])
            elif ops[0].size == 8:
                src = "x87_ld_f64(c, %s)" % ea(ops[0])
            else:
                raise Reject("memory width %d" % ops[0].size)
            st, out = _st(ctx), []
            st.wr(0, _call(ctx, fn, st.rd(0, out), src), out)
            return out
        return _register_arith(ctx, name, ins, fn, pop=False)

    @cached(name + "p")
    def h_pop(ctx, ins):
        return _register_arith(ctx, name + "p", ins, fn, pop=True)

    return h_reg_or_mem, h_pop


for _n in _ARITH:
    _mk_arith(_n)


def _mk_iarith(name):
    fn = _IARITH[name]

    @cached(name)
    def h_int(ctx, ins):
        (op,) = ins.operands
        a = _mem(op, (2, 4))
        st, out = _st(ctx), []
        st.wr(0, _call(ctx, fn, st.rd(0, out), "x87_ild(c, %s, %d)" % (a, op.size)), out)
        return out

    return h_int


for _n in _IARITH:
    _mk_iarith(_n)


# ---------------------------------------------------------------- compares

def _mk_compare(name, pop, unordered):
    """fcom/fcomp/fucom/fucomp: C3 C2 C0 against ST(i) (default ST(1) with no operand) or m32/m64."""

    @cached(name)
    def h_cmp(ctx, ins):
        ops = ins.operands
        st, out = _st(ctx), []
        if len(ops) == 1 and ops[0].type == X86_OP_MEM:
            if ops[0].size == 4:
                src = "x87_ld_f32(c, %s)" % ea(ops[0])
            elif ops[0].size == 8:
                src = "x87_ld_f64(c, %s)" % ea(ops[0])
            else:
                raise Reject("memory width %d" % ops[0].size)
        else:
            src = st.rd(_reg_src(ins), out)
        out.append("x87_compare(c, %s, %s);" % (st.rd(0, out), src))
        if pop:
            st.pop(out)
        return out

    return h_cmp


_mk_compare("fcom", False, False)
_mk_compare("fcomp", True, False)
_mk_compare("fucom", False, True)
_mk_compare("fucomp", True, True)


@cached("ficom", "ficomp")
def h_ficom(ctx, ins):
    (op,) = ins.operands
    a = _mem(op, (2, 4))
    st, out = _st(ctx), []
    out.append("x87_compare(c, %s, x87_ild(c, %s, %d));" % (st.rd(0, out), a, op.size))
    if ins.mnemonic == "ficomp":
        st.pop(out)
    return out


@cached("fcompp", "fucompp")
def h_compp(ctx, ins):
    if ins.operands:
        raise Reject("fcompp operands")
    st, out = _st(ctx), []
    a, b = st.rd(0, out), st.rd(1, out)
    out.append("x87_compare(c, %s, %s);" % (a, b))
    st.pop(out)
    st.pop(out)
    return out


def _mk_comi(name, pop):
    @cached(name)
    def h_comi(ctx, ins):
        ops = ins.operands
        if len(ops) == 2:
            s = _sti(ops[1])
        else:
            s = _reg_src(ins)
        on = flags_wanted(ctx, F_ALL)
        st, out = _st(ctx), []
        if on:
            a, b = st.rd(0, out), st.rd(s, out)
            out.append("x87_comi(c, %s, %s);" % (a, b))
        if pop:
            st.pop(out)
        return out

    return h_comi


# capstone prints DF F0+i (FCOMIP) as fcompi and DF E8+i (FUCOMIP) as fucompi
_mk_comi("fcomi", False)
_mk_comi("fcomip", True)
_mk_comi("fcompi", True)
_mk_comi("fucomi", False)
_mk_comi("fucomip", True)
_mk_comi("fucompi", True)


@cached("ftst")
def h_ftst(ctx, ins):
    if ins.operands:
        raise Reject("ftst operands")
    st, out = _st(ctx), []
    out.append("x87_compare(c, %s, 0.0);" % st.rd(0, out))
    return out


@handler("fxam")
def h_fxam(ctx, ins):
    if ins.operands:
        raise Reject("fxam operands")
    return ["x87_fxam(c);"]


# Transcendentals: see the comment on x87_fsin in lift/runtime/x87.h (the emulator's model).
_TRIG = {"fsin": "x87_fsin", "fcos": "x87_fcos", "fptan": "x87_fptan", "fsincos": "x87_fsincos",
         "fpatan": "x87_fpatan", "fyl2x": "x87_fyl2x",
         # not transcendentals, but the same shape: no operands, one runtime helper on the stack in the CPU struct
         "frndint": "x87_frndint", "fscale": "x87_fscale", "fprem": "x87_fprem", "fprem1": "x87_fprem1",
         "f2xm1": "x87_f2xm1"}


def _mk_trig(name, fn):
    @handler(name)
    def h_trig(ctx, ins):
        if ins.operands:
            raise Reject("%s operands" % name)
        return ["%s(c);" % fn]

    return h_trig


for _n, _f in _TRIG.items():
    _mk_trig(_n, _f)


# ---------------------------------------------------------------- loads and stores

@cached("fld")
def h_fld(ctx, ins):
    (op,) = ins.operands
    st, out = _st(ctx), []
    if op.type == X86_OP_REG:
        st.push(st.rd(_sti(op), out), out)
        return out
    if op.type != X86_OP_MEM:
        raise Reject("fld operand")
    a = ea(op)
    fn = {4: "x87_ld_f32", 8: "x87_ld_f64", 10: "x87_ld_f80"}.get(op.size)
    if fn is None:
        raise Reject("fld width %d" % op.size)
    st.push("%s(c, %s)" % (fn, a), out)
    return out


@cached("fst")
def h_fst(ctx, ins):
    (op,) = ins.operands
    st, out = _st(ctx), []
    if op.type == X86_OP_REG:
        st.wr(_sti(op), st.rd(0, out), out)
        return out
    a = ea(op)
    fn = {4: "x87_st_f32", 8: "x87_st_f64"}.get(op.size)
    if fn is None:
        raise Reject("fst width %d" % op.size)        # there is no fst m80
    out.append("%s(c, %s, %s);" % (fn, a, st.rd(0, out)))
    return out


@cached("fstp")
def h_fstp(ctx, ins):
    (op,) = ins.operands
    st, out = _st(ctx), []
    if op.type == X86_OP_REG:
        i = _sti(op)
        st.wr(i, st.rd(0, out), out)
        st.pop(out)
        return out
    a = ea(op)
    fn = {4: "x87_st_f32", 8: "x87_st_f64", 10: "x87_st_f80"}.get(op.size)
    if fn is None:
        raise Reject("fstp width %d" % op.size)
    out.append("%s(c, %s, %s);" % (fn, a, st.rd(0, out)))
    st.pop(out)
    return out


@cached("fild")
def h_fild(ctx, ins):
    (op,) = ins.operands
    a = _mem(op, (2, 4, 8))
    st, out = _st(ctx), []
    st.push("x87_ild(c, %s, %d)" % (a, op.size), out)
    return out


@cached("fist", "fistp")
def h_fist(ctx, ins):
    (op,) = ins.operands
    pop = ins.mnemonic == "fistp"
    sizes = (2, 4, 8) if pop else (2, 4)
    a = _mem(op, sizes)
    st, out = _st(ctx), []
    out.append("x87_ist(c, %s, %s, %d);" % (a, st.rd(0, out), op.size))
    if pop:
        st.pop(out)
    return out


@cached("fxch")
def h_fxch(ctx, ins):
    ops = ins.operands
    i = _sti(ops[-1]) if ops else 1
    st, out = _st(ctx), []
    st.xch(i, out)
    return out


@cached("ffree")
def h_ffree(ctx, ins):
    i = _reg_src(ins)
    st, out = _st(ctx), []
    st.free(i, out)
    return out


# ---------------------------------------------------------------- unary and constants

@cached("fchs")
def h_fchs(ctx, ins):
    st, out = _st(ctx), []
    st.wr(0, "-%s" % st.rd(0, out), out)
    return out


@cached("fabs")
def h_fabs(ctx, ins):
    st, out = _st(ctx), []
    st.wr(0, "fabs(%s)" % st.rd(0, out), out)
    return out


@cached("fsqrt")
def h_fsqrt(ctx, ins):
    st, out = _st(ctx), []
    st.wr(0, _call(ctx, "x87_sqrtv", st.rd(0, out)), out)
    return out


@cached("fld1")
def h_fld1(ctx, ins):
    st, out = _st(ctx), []
    st.push("1.0", out)
    return out


@cached("fldz")
def h_fldz(ctx, ins):
    st, out = _st(ctx), []
    st.push("0.0", out)
    return out


# Nearest double to each constant and whether it lies above the true value (see x87_konst).
_KONST = {
    "fldpi": ("0x1.921fb54442d18p+1", False),
    "fldl2e": ("0x1.71547652b82fep+0", False),
    "fldln2": ("0x1.62e42fefa39efp-1", False),
    "fldlg2": ("0x1.34413509f79ffp-2", True),
    "fldl2t": ("0x1.a934f0979a371p+1", False),
}


def _mk_konst(name, lit, above):
    @cached(name)
    def h_konst(ctx, ins):
        st, out = _st(ctx), []
        st.push("x87_konst(c, %s, %d)" % (lit, 1 if above else 0), out)
        return out

    return h_konst


for _n, (_lit, _above) in _KONST.items():
    _mk_konst(_n, _lit, _above)


# ---------------------------------------------------------------- control

@cached("fnstsw")
def h_fnstsw(ctx, ins):
    (op,) = ins.operands
    if op.type == X86_OP_REG or (op.type == X86_OP_MEM and op.size == 2):
        out = []
        out.append(put(op, 2, _st(ctx).status(out)))
        return out
    raise Reject("fnstsw operand")


@handler("fnstcw", "fstcw")
def h_fnstcw(ctx, ins):
    (op,) = ins.operands
    if op.type == X86_OP_MEM and op.size == 2:
        return [put(op, 2, "c->cw")]
    raise Reject("fnstcw operand")


@handler("fldcw")
def h_fldcw(ctx, ins):
    (op,) = ins.operands
    if op.type == X86_OP_MEM and op.size == 2:
        return ["x87_ldcw(c, (uint16_t)%s);" % get(op, 2)]
    raise Reject("fldcw operand")


@handler("fnsave", "fsave")
def h_fnsave(ctx, ins):
    (op,) = ins.operands
    if op.type != X86_OP_MEM or ins.prefix[2] == 0x66:
        raise Reject("fnsave operand")
    return ["x87_fnsave(c, %s);" % ea(op)]


@handler("frstor")
def h_frstor(ctx, ins):
    (op,) = ins.operands
    if op.type != X86_OP_MEM or ins.prefix[2] == 0x66:
        raise Reject("frstor operand")
    return ["x87_frstor(c, %s);" % ea(op)]


@handler("fnstenv", "fstenv")
def h_fnstenv(ctx, ins):
    (op,) = ins.operands
    if op.type != X86_OP_MEM or ins.prefix[2] == 0x66:
        raise Reject("fnstenv operand")
    return ["x87_fnstenv(c, %s);" % ea(op)]


@handler("fldenv")
def h_fldenv(ctx, ins):
    (op,) = ins.operands
    if op.type != X86_OP_MEM or ins.prefix[2] == 0x66:
        raise Reject("fldenv operand")
    return ["x87_fldenv(c, %s);" % ea(op)]


@handler("fninit", "finit")
def h_fninit(ctx, ins):
    return ["x87_init(c);"]


@handler("fnclex", "fclex")
def h_fnclex(ctx, ins):
    return ["x87_clex(c);"]


@handler("fwait", "wait")
def h_fwait(ctx, ins):
    return []
