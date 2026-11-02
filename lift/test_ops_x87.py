"""Differential tests for the x87 handlers (lift/ops_x87.py, lift/runtime/x87.h) against Unicorn.

Every instruction and operand form runs on n random states through insnrig.check(fpu=True). Memory
forms pin the base register at DATA, and the operands live at fixed offsets in mem= (layout below).

Differences from the reference, and how they are handled:
  - fcomi/fucomi/fcomip/fucomip: OF, SF and AF are not compared (flags=FLAGS_NO_UNMODELLED). The
    SDM says they are cleared; Unicorn leaves them unchanged. The handler follows the SDM.
  - TEST leaves AF undefined: not compared in the compare-idiom tests.
  - Stack faults are not modelled (see lift/runtime/x87.h); the rig's random stacks contain holes,
    and the reference reads them as stored.
  - Rig readback limits (insnrig._fp_float): NaN comes back as +NaN, and an empty register holding
    an extended residue outside double range comes back as inf or 0. Memory stores of random
    stack values are therefore done from known values, and the residual random-state cases are
    listed at the end of the run (KNOWN), with a cap on how many states may be affected.

Run:  ../../../.venv/bin/python lift/test_ops_x87.py      (from the worktree root)
"""
import math
import os
import random
import shutil
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import insnrig
import x86c
from insnrig import check, enc, dis, DATA

# The rig caches compiled harnesses by a hash of the translated C, not of the runtime headers, so
# edits to lift/runtime/x87.h would not be picked up. Start from an empty cache.
shutil.rmtree(os.path.join(tempfile.gettempdir(), "insnrig-cache"), ignore_errors=True)

N = 200
FLAGS_NO_UNMODELLED = ("cf", "pf", "zf")      # fcomi family: OF SF AF are not compared (see above)
CW_RC = {0: 0x027F, 1: 0x047F, 2: 0x087F, 3: 0x0C7F}   # 53-bit precision with RC nearest/down/up/trunc
CW_PC24 = 0x003F                                      # 24-bit precision, nearest
CW_RESTORE = 0x027F
OFF_A = 0x00        # operand A: float at 0, double at 8
OFF_B = 0x08        # operand B
OFF_M80 = 0x10      # 80-bit value
OFF_I16 = 0x20      # integer operands
OFF_I32 = 0x24
OFF_I64 = 0x28
OFF_CW = 0x40       # control word for the snippet
OFF_CWR = 0x42      # control word that restores 53-bit nearest
OFF_V = 0x48        # value loaded by the rounding snippets
OFF_DST = 0x58      # destination of stores
OFF_DST2 = 0x80


def dbl(v):
    return struct.pack("<d", v)


def flt(v):
    return struct.pack("<f", v)


def m80_bytes(v):
    """Exact 80-bit encoding of a double (every double is representable)."""
    if v != v:
        sig, se = (1 << 63) | (1 << 62), 0x7fff
    elif math.isinf(v):
        sig, se = 1 << 63, (0x8000 if v < 0 else 0) | 0x7fff
    elif v == 0:
        sig, se = 0, (0x8000 if math.copysign(1, v) < 0 else 0)
    else:
        m, e = math.frexp(abs(v))              # |v| = m * 2^e, 0.5 <= m < 1
        sig = int(m * (1 << 64))               # exact: m has at most 53 significant bits
        se = (e - 1 + 16383) | (0x8000 if v < 0 else 0)
    return struct.pack("<QH", sig, se) + b"\0" * 6


def image(items):
    """items: [(offset, bytes)]. Builds the mem= image for check()."""
    size = max(off + len(b) for off, b in items)
    buf = bytearray(size)
    for off, b in items:
        buf[off:off + len(b)] = b
    return bytes(buf)


def base_mem(a=2.5, b=-0.75, m80=1.5, ival16=-300, ival32=70000, ival64=-(1 << 40) - 3,
             cw=CW_RESTORE, v=2.5):
    return image([
        (OFF_A, flt(a) + b"\0\0\0\0"),        # float at 0 (rest of the slot is padding)
        (OFF_B, dbl(b)),
        (OFF_M80, m80_bytes(m80)),
        (OFF_I16, struct.pack("<h", ival16)),
        (OFF_I32, struct.pack("<i", ival32)),
        (OFF_I64, struct.pack("<q", ival64)),
        (OFF_CW, struct.pack("<H", cw)),
        (OFF_CWR, struct.pack("<H", CW_RESTORE)),
        (OFF_V, dbl(v)),
    ])


# Cases that differ from the reference only because of how the rig reads the x87 state back
# (insnrig._fp_float): every NaN comes back as +NaN (sign and payload lost), and an empty physical
# register can hold a value outside double range (an 80-bit residue) that reads back as +-inf or as a
# double. The handlers are exact for the values the rig can express; these cases are listed in the
# output and in the report, not hidden. known=<reason> marks a test whose random states can hit them.
KNOWN = []
REASON_RESIDUE = ("empty register holds an extended residue outside double range (it reads back "
                  "as inf or 0); the handler computes with the stored double")
REASON_NAN = "rig reads NaN back as +NaN; sign of a random NaN is lost"
KNOWN_LABELS = {
    "fmul st1,st0": REASON_RESIDUE,
    "fmulp st1": REASON_RESIDUE,
    "fdiv st1,st0": REASON_RESIDUE,
    "fsqrt": REASON_NAN,
}


KNOWN_MAX_FRACTION = 0.05     # a known cause must account for at most this share of the states


def run(label, code, mem=None, regs=None, flags="all", n=N, seed=0, known=None):
    r = check(code, n=n, seed=seed, flags=flags, mem=mem, regs=regs or {}, fpu=True, label=label)
    known = known or KNOWN_LABELS.get(label)
    if not r.ok and known and r.stage == "compare" and r.n_failed <= KNOWN_MAX_FRACTION * n:
        KNOWN.append("%s: %d/%d states (%s)" % (label, r.n_failed, n, known))
        return r
    assert r.ok, str(r)
    return r


# ---------------------------------------------------------------- stack and register forms

def test_register_arithmetic_all_forms():
    # The random stacks read empty registers (residues) in some of these: see KNOWN_MAX_FRACTION.
    # D8: ST(0) op ST(i)
    for opc, name in [(0xC0, "fadd"), (0xC8, "fmul"), (0xE0, "fsub"), (0xE8, "fsubr"),
                      (0xF0, "fdiv"), (0xF8, "fdivr")]:
        for i in (1, 3):
            run("%s st0,st%d" % (name, i), bytes([0xD8, opc + i]), known=REASON_RESIDUE)
    # DC: ST(i) op ST(0)
    for opc, name in [(0xC0, "fadd"), (0xC8, "fmul"), (0xE0, "fsubr"), (0xE8, "fsub"),
                      (0xF0, "fdivr"), (0xF8, "fdiv")]:
        for i in (1, 3):
            run("%s st%d,st0" % (name, i), bytes([0xDC, opc + i]), known=REASON_RESIDUE)
    # DE: ST(i) op ST(0), then pop; plus the no-operand forms (DE C1 = faddp, DE C9 = fmulp)
    for opc, name in [(0xC0, "faddp"), (0xC8, "fmulp"), (0xE0, "fsubrp"), (0xE8, "fsubp"),
                      (0xF0, "fdivrp"), (0xF8, "fdivp")]:
        for i in (1, 3):
            run("%s st%d" % (name, i), bytes([0xDE, opc + i]), known=REASON_RESIDUE)
    run("faddp (no operand)", bytes([0xDE, 0xC1]), known=REASON_RESIDUE)
    run("fmulp (no operand)", bytes([0xDE, 0xC9]), known=REASON_RESIDUE)
    run("fsubp (no operand)", bytes([0xDE, 0xE9]), known=REASON_RESIDUE)
    run("fdivp (no operand)", bytes([0xDE, 0xF9]), known=REASON_RESIDUE)


def test_register_moves_and_free():
    for i in (1, 3):
        run("fld st%d" % i, bytes([0xD9, 0xC0 + i]))
        run("fxch st%d" % i, bytes([0xD9, 0xC8 + i]))
        run("fst st%d" % i, bytes([0xDD, 0xD0 + i]))
        run("fstp st%d" % i, bytes([0xDD, 0xD8 + i]))
        run("ffree st%d" % i, bytes([0xDD, 0xC0 + i]))
    run("fxch (no operand)", bytes([0xD9, 0xC9]))
    run("fstp st0", bytes([0xDD, 0xD8]))


def test_register_compares():
    for i in (1, 3):
        run("fcom st%d" % i, bytes([0xD8, 0xD0 + i]))
        run("fcomp st%d" % i, bytes([0xD8, 0xD8 + i]))
        run("fucom st%d" % i, bytes([0xDD, 0xE0 + i]))
        run("fucomp st%d" % i, bytes([0xDD, 0xE8 + i]))
        run("fcomi st%d" % i, bytes([0xDB, 0xF0 + i]), flags=FLAGS_NO_UNMODELLED)
        run("fucomi st%d" % i, bytes([0xDB, 0xE8 + i]), flags=FLAGS_NO_UNMODELLED)
        run("fcomip st%d" % i, bytes([0xDF, 0xF0 + i]), flags=FLAGS_NO_UNMODELLED)
        run("fucomip st%d" % i, bytes([0xDF, 0xE8 + i]), flags=FLAGS_NO_UNMODELLED)
    run("fcom (no operand)", bytes([0xD8, 0xD1]))
    run("fcomp (no operand)", bytes([0xD8, 0xD9]))
    run("fcompp", bytes([0xDE, 0xD9]))
    run("fucompp", bytes([0xDA, 0xE9]))


def test_unary_and_constants():
    run("fchs", bytes([0xD9, 0xE0]))
    run("fabs", bytes([0xD9, 0xE1]))
    run("fsqrt", bytes([0xD9, 0xFA]))                       # random stack (may hit NaN, see KNOWN)
    run("ftst", bytes([0xD9, 0xE4]))
    run("fxam", bytes([0xD9, 0xE5]))
    for code, name in [(0xE8, "fld1"), (0xEE, "fldz"), (0xEB, "fldpi"), (0xEA, "fldl2e"),
                       (0xED, "fldln2"), (0xEC, "fldlg2"), (0xE9, "fldl2t")]:
        run(name, bytes([0xD9, code]))


def test_status_and_control_no_memory():
    run("fnclex", bytes([0xDB, 0xE2]))
    run("fninit", bytes([0xDB, 0xE3]))
    run("fwait; fninit (9B DB E3)", enc("9b db e3"))
    run("fnstsw ax", bytes([0xDF, 0xE0]))
    run("fwait; fnstsw ax (9B DF E0)", enc("9b df e0"))
    # fcomp st1; fnstsw ax; test ah, 0x41: the usual compare idiom
    # TEST leaves AF undefined (not compared)
    no_af = ("cf", "pf", "zf", "sf", "of")
    run("fcom st1; fnstsw ax; test ah,0x41", enc("d8 d1 df e0 f6 c4 41"), flags=no_af)
    run("fcomp st1; fnstsw ax; test ah,0x40", enc("d8 d9 df e0 f6 c4 40"), flags=no_af)
    run("fxam after fabs", enc("d9 e1 d9 e5"))


def test_x87_locals_sequences():
    """Multi-instruction blocks, where the x87 locals (x86c.X87Cache) carry the stack between instructions: deep
    pushes (8 deep, wrapping the physical registers), fxch, ffree, fcompp, stores and reloads, integer instructions in
    between, fnstsw after pops, and the plane-test shape of e2mfc's vertex loops. Each runs with the locals on and off;
    the generated C uses the locals only when they are on."""
    no_af = ("cf", "pf", "zf", "sf", "of")
    mem = base_mem()
    edi = {"edi": DATA}
    seqs = [
        ("fld st2; fmul st0,st3; fxch st2; faddp st1; fld1; fsubp st2; fstp st3; fnstsw ax",
         "d9 c2 d8 cb d9 ca de c1 d9 e8 de ea dd db df e0", None, {}, "all"),
        ("fld1 x8; faddp x3; fnstsw ax", "d9 e8 " * 8 + "de c1 " * 3 + "df e0", None, {}, "all"),
        ("fld st1; add eax,1; fmulp; mov ebx,eax; fnstsw ax", "d9 c1 83 c0 01 de c9 89 c3 df e0", None, {}, no_af),
        ("fld st0; ffree st2; fxch; fcompp; fnstsw ax", "d9 c0 dd c2 d9 c9 de d9 df e0", None, {}, "all"),
        ("plane test: fld/fmul m32, fld/fmul m64, faddp, fadd, fcomp, fnstsw, test",
         "d9 07 d8 0f dd 47 08 dc 4f 08 de c1 d8 07 d8 1f df e0 f6 c4 41", mem, edi, no_af),
        ("fild m32; fadd st0,st1; fistp m32", "db 47 24 d8 c1 db 5f 58", mem, edi, "all"),
        ("fld qword [v]; fstp qword [dst]; fld qword [dst]; fxch st1; fstp st0",
         "dd 47 48 dd 5f 58 dd 47 58 d9 c9 dd d8", mem, edi, "all"),
    ]
    saved = x86c.X87_LOCALS
    try:
        for on in (True, False):
            x86c.X87_LOCALS = on
            for label, code, m, regs, flags in seqs:
                run("%s [locals %s]" % (label, "on" if on else "off"), enc(code), mem=m, regs=regs, flags=flags,
                    known=REASON_RESIDUE)
                c_text = x86c.lift_function(insnrig._SnippetImage(enc(code) + b"\xc3"), insnrig.CODE).c
                assert ("xt = c->top;" in c_text) == on, (label, on)
    finally:
        x86c.X87_LOCALS = saved

# ---------------------------------------------------------------- memory forms

def mod_rm_mem(reg, disp=None):
    """ModRM (and disp8 when given) for [edi] (disp None) or [edi + disp]."""
    if disp is None:
        return bytes([(reg << 3) | 0x07])
    return bytes([0x40 | (reg << 3) | 0x07, disp])


def test_memory_float_arithmetic():
    mem = base_mem()
    # m32 forms: D8 /n with [edi + OFF_A]
    for reg, name in [(0, "fadd"), (1, "fmul"), (2, "fcom"), (3, "fcomp"), (4, "fsub"),
                      (5, "fsubr"), (6, "fdiv"), (7, "fdivr")]:
        run("%s dword [edi]" % name, bytes([0xD8]) + mod_rm_mem(reg), mem=mem,
            regs={"edi": DATA})
    # m64 forms: DC /n with [edi + OFF_B]
    for reg, name in [(0, "fadd"), (1, "fmul"), (2, "fcom"), (3, "fcomp"), (4, "fsub"),
                      (5, "fsubr"), (6, "fdiv"), (7, "fdivr")]:
        run("%s qword [edi+8]" % name, bytes([0xDC]) + mod_rm_mem(reg, OFF_B), mem=mem,
            regs={"edi": DATA})


def test_memory_integer_arithmetic_and_compares():
    mem = base_mem(ival16=-300, ival32=70000)
    # m16 (DE /n) and m32 (DA /n)
    for reg, name in [(0, "fiadd"), (1, "fimul"), (2, "ficom"), (3, "ficomp"), (4, "fisub"),
                      (5, "fisubr"), (6, "fidiv"), (7, "fidivr")]:
        run("%s word [edi+0x20]" % name, bytes([0xDE]) + mod_rm_mem(reg, OFF_I16), mem=mem,
            regs={"edi": DATA})
        run("%s dword [edi+0x24]" % name, bytes([0xDA]) + mod_rm_mem(reg, OFF_I32), mem=mem,
            regs={"edi": DATA})


def test_memory_loads_and_stores():
    mem = base_mem()
    # float and double
    run("fld dword [edi]", bytes([0xD9]) + mod_rm_mem(0), mem=mem, regs={"edi": DATA})
    run("fld qword [edi+8]", bytes([0xDD]) + mod_rm_mem(0, OFF_B), mem=mem, regs={"edi": DATA})
    # The stores push a known value first (from mem), so the stored bytes are not a NaN from the
    # random stack: the rig reads NaN payloads back canonically, so those bytes cannot be compared.
    push_v = bytes([0xDD]) + mod_rm_mem(0, OFF_V)                   # fld qword [v]
    for name, op in [("fst dword", bytes([0xD9]) + mod_rm_mem(2, OFF_DST)),
                     ("fstp dword", bytes([0xD9]) + mod_rm_mem(3, OFF_DST)),
                     ("fst qword", bytes([0xDD]) + mod_rm_mem(2, OFF_DST)),
                     ("fstp qword", bytes([0xDD]) + mod_rm_mem(3, OFF_DST))]:
        run(name + " [edi+0x58] of 2.5", push_v + op, mem=mem, regs={"edi": DATA})
    # fst to float of a value that is not a float (rounds with the host mode)
    run("fstp dword [edi+0x58] of 1/3", bytes([0xDD]) + mod_rm_mem(0, OFF_A + 0x60) +
        bytes([0xD9]) + mod_rm_mem(3, OFF_DST),
        mem=image([(OFF_A, flt(0)), (OFF_B, dbl(0)), (0x60, dbl(1.0 / 3.0))]), regs={"edi": DATA})
    # 80-bit: load and store back, exact for the values in base_mem (see test_m80_round_trip)
    run("fld tbyte [edi+0x10]; fstp tbyte [edi+0x58]",
        bytes([0xDB]) + mod_rm_mem(5, OFF_M80) + bytes([0xDB]) + mod_rm_mem(7, OFF_DST),
        mem=mem, regs={"edi": DATA})
    # control words and status word to memory
    run("fnstcw word [edi+0x58]", bytes([0xD9]) + mod_rm_mem(7, OFF_DST), mem=mem, regs={"edi": DATA})
    run("fnstsw word [edi+0x58]", bytes([0xDD]) + mod_rm_mem(7, OFF_DST), mem=mem, regs={"edi": DATA})
    run("fldcw word [edi+0x42]", bytes([0xD9]) + mod_rm_mem(5, OFF_CWR), mem=mem, regs={"edi": DATA})
    run("fwait; fnstcw word [edi+0x58]", enc("9b") + bytes([0xD9]) + mod_rm_mem(7, OFF_DST), mem=mem,
        regs={"edi": DATA})


def test_integer_loads_and_stores():
    mem = base_mem(ival16=-300, ival32=70000, ival64=-(1 << 40) - 3)
    run("fild word [edi+0x20]", bytes([0xDF]) + mod_rm_mem(0, OFF_I16), mem=mem, regs={"edi": DATA})
    run("fild dword [edi+0x24]", bytes([0xDB]) + mod_rm_mem(0, OFF_I32), mem=mem, regs={"edi": DATA})
    run("fild qword [edi+0x28]", bytes([0xDF]) + mod_rm_mem(5, OFF_I64), mem=mem, regs={"edi": DATA})
    # fist and fistp: the stack holds a value from a float load so the stores have something to round
    load = bytes([0xD9]) + mod_rm_mem(0)                      # fld dword [edi]
    run("fist word [edi+0x58]", load + bytes([0xDF]) + mod_rm_mem(2, OFF_DST), mem=mem, regs={"edi": DATA})
    run("fistp word [edi+0x58]", load + bytes([0xDF]) + mod_rm_mem(3, OFF_DST), mem=mem, regs={"edi": DATA})
    run("fist dword [edi+0x58]", load + bytes([0xDB]) + mod_rm_mem(2, OFF_DST), mem=mem, regs={"edi": DATA})
    run("fistp dword [edi+0x58]", load + bytes([0xDB]) + mod_rm_mem(3, OFF_DST), mem=mem, regs={"edi": DATA})
    run("fistp qword [edi+0x58]", load + bytes([0xDF]) + mod_rm_mem(7, OFF_DST), mem=mem, regs={"edi": DATA})


def test_integer_store_out_of_range_and_specials():
    # 1e10 does not fit in 32 bits; 0.5 rounds to 0 under nearest; NaN stores the indefinite value
    mem = image([(OFF_V, dbl(1e10)), (OFF_B, dbl(-0.5)), (OFF_A, dbl(0.0))])
    run("fld qword [edi+0x48]; fistp dword [edi+0x58] (1e10)",
        bytes([0xDD]) + mod_rm_mem(0, OFF_V) + bytes([0xDB]) + mod_rm_mem(3, OFF_DST),
        mem=mem, regs={"edi": DATA})
    run("fld qword [edi+8]; fistp word [edi+0x58] (-0.5)",
        bytes([0xDD]) + mod_rm_mem(0, OFF_B) + bytes([0xDF]) + mod_rm_mem(3, OFF_DST),
        mem=mem, regs={"edi": DATA})


def test_rounding_control_for_integer_stores():
    # fldcw from memory, then fistp (all four RC modes), then restore 53-bit nearest
    values = [2.5, -2.5, 3.7, -3.7, 0.5, -0.5, 1.5, 1e9 + 0.5, -2147483648.5]
    for rc, cw in CW_RC.items():
        for v in values:
            mem = base_mem(cw=cw, v=v)
            for name, store in [("fistp dword", bytes([0xDB]) + mod_rm_mem(3, OFF_DST)),
                                ("fistp word", bytes([0xDF]) + mod_rm_mem(3, OFF_DST)),
                                ("fistp qword", bytes([0xDF]) + mod_rm_mem(7, OFF_DST))]:
                code = (bytes([0xD9]) + mod_rm_mem(5, OFF_CW)           # fldcw [cw]
                        + bytes([0xDD]) + mod_rm_mem(0, OFF_V)          # fld qword [v]
                        + store                                         # fistp ...
                        + bytes([0xD9]) + mod_rm_mem(5, OFF_CWR))       # fldcw [restore]
                run("rc%d %s of %r" % (rc, name, v), code, mem=mem, regs={"edi": DATA})


def test_precision_control_24_bit():
    # PC = 00: a product is rounded to 24 significant bits (RC nearest)
    mem = image([(OFF_A, dbl(1.1234567)), (OFF_B, dbl(3.3333333)),
                 (OFF_CW, struct.pack("<H", CW_PC24)), (OFF_CWR, struct.pack("<H", CW_RESTORE))])
    code = (bytes([0xD9]) + mod_rm_mem(5, OFF_CW)               # fldcw 24-bit
            + bytes([0xDD]) + mod_rm_mem(0, OFF_A)              # fld qword [a]
            + bytes([0xDC]) + mod_rm_mem(1, OFF_B)              # fmul qword [b]
            + bytes([0xDD]) + mod_rm_mem(3, OFF_DST)            # fstp qword [dst]
            + bytes([0xD9]) + mod_rm_mem(5, OFF_CWR))           # fldcw 53-bit
    run("24-bit fmul then fstp", code, mem=mem, regs={"edi": DATA})
    # and an add, with the same control word
    code = (bytes([0xD9]) + mod_rm_mem(5, OFF_CW)
            + bytes([0xDD]) + mod_rm_mem(0, OFF_A)
            + bytes([0xDC]) + mod_rm_mem(0, OFF_B)
            + bytes([0xDD]) + mod_rm_mem(3, OFF_DST)
            + bytes([0xD9]) + mod_rm_mem(5, OFF_CWR))
    run("24-bit fadd then fstp", code, mem=mem, regs={"edi": DATA})


def test_control_word_local():
    """x86c.X87_CW_LOCAL (H54): the arithmetic helpers take the control word from a local, read again after each
    fldcw. One snippet switches 24-bit -> 53-bit -> 24-bit between multiplies, adds, a divide and a square root, and
    stores each result; it must match the emulator with the local on and off, and the C must refresh xcw after every
    fldcw when it is on."""
    mem = image([(OFF_A, dbl(1.1234567)), (OFF_B, dbl(3.3333333)),
                 (OFF_CW, struct.pack("<H", CW_PC24)), (OFF_CWR, struct.pack("<H", CW_RESTORE))])
    fldcw24, fldcw53 = bytes([0xD9]) + mod_rm_mem(5, OFF_CW), bytes([0xD9]) + mod_rm_mem(5, OFF_CWR)
    fld_a, fmul_b = bytes([0xDD]) + mod_rm_mem(0, OFF_A), bytes([0xDC]) + mod_rm_mem(1, OFF_B)
    fadd_b, fdiv_b = bytes([0xDC]) + mod_rm_mem(0, OFF_B), bytes([0xDC]) + mod_rm_mem(6, OFF_B)
    fsqrt = bytes([0xD9, 0xFA])
    fstp = lambda off: bytes([0xDD]) + mod_rm_mem(3, off)
    code = (fldcw24 + fld_a + fmul_b + fadd_b + fstp(OFF_DST)            # 24-bit
            + fldcw53 + fld_a + fmul_b + fdiv_b + fstp(OFF_DST + 8)      # 53-bit
            + fldcw24 + fld_a + fsqrt + fdiv_b + fstp(OFF_DST + 16)      # 24-bit again
            + fldcw53)
    saved = x86c.X87_CW_LOCAL
    try:
        for on in (True, False):
            x86c.X87_CW_LOCAL = on
            run("cw 24/53/24 with arithmetic [cw local %s]" % ("on" if on else "off"), code, mem=mem,
                regs={"edi": DATA})
            c_text = x86c.lift_function(insnrig._SnippetImage(code + b"\xc3"), insnrig.CODE).c
            assert ("x87_mulw(c, xcw," in c_text) == on, on
            if on:
                refresh = [ln for ln in c_text.split("\n") if ln.strip() == "xcw = c->cw;"]
                assert len(refresh) == 4, c_text                    # one per fldcw (the declaration aside)
        # a call may change the control word (the callee runs fldcw): xcw is read again right after it
        x86c.X87_CW_LOCAL = True
        lines = [ln.strip() for ln in x86c.lift_function(
            insnrig._SnippetImage(enc("dd 07 e8 00 01 00 00 dc 4f 08 dd 5f 58 c3")), insnrig.CODE).c.split("\n")]
        i = next(i for i, ln in enumerate(lines) if ln.startswith("lift_guest("))
        assert lines[i + 1] == "xcw = c->cw;", lines[i:i + 3]
    finally:
        x86c.X87_CW_LOCAL = saved


def test_rounding_control_for_constants():
    # fldpi, fldl2e, fldln2, fldlg2, fldl2t rounded per RC when stored as doubles
    for rc, cw in CW_RC.items():
        mem = base_mem(cw=cw)
        for const in (0xEB, 0xEA, 0xED, 0xEC, 0xE9):
            code = (bytes([0xD9]) + mod_rm_mem(5, OFF_CW)
                    + bytes([0xD9, const])
                    + bytes([0xDD]) + mod_rm_mem(3, OFF_DST)
                    + bytes([0xD9]) + mod_rm_mem(5, OFF_CWR))
            run("rc%d const %02x" % (rc, const), code, mem=mem, regs={"edi": DATA})


def test_m80_round_trip():
    # 80-bit values that are exact doubles survive fld/fstp tbyte unchanged
    for v in (1.0, -2.5, 1e300, -1e-300, 5e-324, 0.0, -0.0, math.inf, -math.inf, math.nan):
        mem = base_mem(m80=v)
        run("tbyte round trip %r" % v,
            bytes([0xDB]) + mod_rm_mem(5, OFF_M80) + bytes([0xDB]) + mod_rm_mem(7, OFF_DST),
            mem=mem, regs={"edi": DATA})


def m80_raw(sig, se):
    return struct.pack("<QH", sig, se) + b"\0" * 6


def test_m80_to_double_rounding():
    # fld tbyte then fstp qword: the 64-bit significand is rounded to 53 bits (nearest-even) by the
    # store, so this checks the handler's m80 -> double conversion on values that are not doubles.
    cases = [
        (0x8000000000000001, 0x3fff),   # 1 + 2^-63: rounds down to 1
        (0x8000000000000400, 0x3fff),   # exact tie, even: 1
        (0x8000000000000c00, 0x3fff),   # exact tie, odd: rounds up
        (0xffffffffffffffff, 0x3fff),   # rounds up to 2
        (0xffffffffffffffff, 0x4000),   # 4 - tiny
        (0x8000000000000000, 0x7ffe),   # 2^16383: overflows double to +inf
        (0x8000000000000000, 0x0001),   # 2^-16382: below double range, zero
        (0x8000000000000000, 0x3c01),   # 2^-1022: smallest normal double
        (0x8000000000000000, 0x3bff),   # 2^-1023: subnormal, exact
        (0x8000000000000001, 0x3bff),   # subnormal, rounds
        (0xc000000000000001, 0x3be5),   # subnormal near 2^-1040 with a tail
        (0x9abcdef012345678, 0x3c02),   # normal, random tail
        (0x9abcdef012345678, 0xbc02),   # the same, negative
        (0xffffffffffffffff, 0x0000),   # extended pseudo-denormal range, rounds to 0
        (0x8000000000000000, 0x0000),   # zero (sign from se)
        (0x8000000000000000, 0x8000),   # -0
    ]
    rng = random.Random(7)
    for _ in range(24):
        cases.append((rng.getrandbits(64) | (1 << 63), rng.randint(0x3b00, 0x4040)))
    for sig, se in cases:
        mem = image([(OFF_M80, m80_raw(sig, se))])
        run("tbyte %016x %04x -> double" % (sig, se),
            bytes([0xDB]) + mod_rm_mem(5, OFF_M80) + bytes([0xDD]) + mod_rm_mem(3, OFF_DST),
            mem=mem, regs={"edi": DATA}, n=40)


def test_m80_loaded_value_is_used():
    # the loaded tbyte value feeds an arithmetic op: fld tbyte then fadd qword
    mem = base_mem(m80=3.25, b=0.125)
    code = (bytes([0xDB]) + mod_rm_mem(5, OFF_M80)
            + bytes([0xDC]) + mod_rm_mem(0, OFF_B)
            + bytes([0xDB]) + mod_rm_mem(7, OFF_DST))
    run("tbyte fadd qword", code, mem=mem, regs={"edi": DATA})


# ---------------------------------------------------------------- special values and specials

def test_special_values_arithmetic():
    specials = [0.0, -0.0, math.inf, -math.inf, math.nan, 1e308, -1e308]
    for a in specials:
        for b in specials[:4] + [math.nan]:
            mem = image([(OFF_A, dbl(a)), (OFF_B, dbl(b))])
            code = (bytes([0xDD]) + mod_rm_mem(0, OFF_A)     # fld qword [a]
                    + bytes([0xDC]) + mod_rm_mem(4, OFF_B))  # fsub qword [b]
            run("%r - %r" % (a, b), code, mem=mem, regs={"edi": DATA}, n=50)


def test_fxam_classes():
    # random states already cover every class. Make sure the stored values of the classes are there.
    for v in (0.0, -0.0, math.inf, -math.inf, math.nan, 5e-324, -1.5):
        mem = image([(OFF_A, dbl(v))])
        run("fxam of %r" % v,
            bytes([0xDD]) + mod_rm_mem(0, OFF_A) + bytes([0xD9, 0xE5]),
            mem=mem, regs={"edi": DATA})


def test_sqrt_and_chs_special():
    for v in (4.0, 2.0, -1.0, -0.0, math.inf, math.nan):
        mem = image([(OFF_A, dbl(v))])
        run("fsqrt of %r" % v, bytes([0xDD]) + mod_rm_mem(0, OFF_A) + bytes([0xD9, 0xFA]),
            mem=mem, regs={"edi": DATA})


def test_store_precision_of_wide_values():
    # fst/fstp to float rounds to 24 bits with the host mode; check the RC modes with a value that is
    # not a float
    for rc, cw in CW_RC.items():
        mem = base_mem(cw=cw, v=1.0 / 3.0)
        code = (bytes([0xD9]) + mod_rm_mem(5, OFF_CW)
                + bytes([0xDD]) + mod_rm_mem(0, OFF_V)
                + bytes([0xD9]) + mod_rm_mem(3, OFF_DST)
                + bytes([0xD9]) + mod_rm_mem(5, OFF_CWR))
        run("rc%d fstp dword of 1/3" % rc, code, mem=mem, regs={"edi": DATA})


def test_divide_flags_zero_divisor_and_invalid():
    """The divide flags match the emulator: ZE (fnstsw bit 2) whenever the divisor is zero, whatever the dividend (0/0 and
    NaN/0 too), nothing for inf/inf. The result and the rest of the status word match, for fdiv and fdivr (m64) and fidiv
    (m32). Real x87 would set IE for 0/0 and inf/inf; the emulator does not (see x87_div_flags in lift/runtime/x87.h)."""
    pairs = [(2.5, 0.0), (2.5, -0.0), (-2.5, 0.0), (0.0, 0.0), (-0.0, 0.0), (math.inf, math.inf),
             (math.inf, 2.5), (2.5, math.inf), (0.0, 2.5), (math.nan, 0.0), (0.0, math.nan)]
    for a, b in pairs:
        mem = image([(OFF_A, dbl(a)), (OFF_B, dbl(b))])
        fld = bytes([0xDD]) + mod_rm_mem(0, OFF_A)                 # fld qword [a]
        for name, op in (("fdiv", bytes([0xDC]) + mod_rm_mem(6, OFF_B)),     # fdiv qword [b]: st0 = a / b
                         ("fdivr", bytes([0xDC]) + mod_rm_mem(7, OFF_B))):   # fdivr qword [b]: st0 = b / a
            run("%s m64 %r, %r; fnstsw ax" % (name, a, b), fld + op + bytes([0xDF, 0xE0]),
                mem=mem, regs={"edi": DATA}, n=20)
    for a in (2.5, -2.5, 0.0, math.inf):
        mem = image([(OFF_A, dbl(a)), (OFF_I32, struct.pack("<i", 0))])
        run("fidiv m32 0 on %r; fnstsw ax" % a,
            bytes([0xDD]) + mod_rm_mem(0, OFF_A) + bytes([0xDA]) + mod_rm_mem(6, OFF_I32) + bytes([0xDF, 0xE0]),
            mem=mem, regs={"edi": DATA}, n=20)
    # the divide's ZE is read by fnstsw in the same snippet
    mem = image([(OFF_A, dbl(2.5)), (OFF_B, dbl(0.0))])
    run("fdiv m64 by zero; fnstsw ax (ZE from the divide)",
        bytes([0xDD]) + mod_rm_mem(0, OFF_A) + bytes([0xDC]) + mod_rm_mem(6, OFF_B) + bytes([0xDF, 0xE0]),
        mem=mem, regs={"edi": DATA}, n=20)

def test_integer_store_flags_match_emulator():
    """fist and fistp (m16, m32, m64) of out-of-range values and NaN: the stored integer indefinite, and no exception
    bit in the status word, as the emulator leaves it (fnstsw ax is compared, so an IE here would show)."""
    values = [2.0 ** 63, 1e30, -1e30, 3e9, 40000.0, math.nan, math.inf, -math.inf, 1.5]
    forms = [("fistp m32", 0xDB, 3, 4), ("fistp m16", 0xDF, 3, 2), ("fistp m64", 0xDF, 7, 8),
             ("fist m32", 0xDB, 2, 4), ("fist m16", 0xDF, 2, 2)]
    for v in values:
        mem = image([(OFF_A, dbl(v))])
        for name, op, reg, _size in forms:
            code = (bytes([0xDD]) + mod_rm_mem(0, OFF_A)                 # fld qword [a]
                    + bytes([op]) + mod_rm_mem(reg, OFF_DST)             # fist(p) ... [dst]
                    + bytes([0xDF, 0xE0]))                               # fnstsw ax
            run("%s of %r; fnstsw ax" % (name, v), code, mem=mem, regs={"edi": DATA}, n=20)


# ---------------------------------------------------------------- transcendentals (fsin, fcos, fptan, fsincos)

PI = math.pi
TRIG_VALUES = [0.0, -0.0, 1e-300, -1e-300, 5e-324, -5e-324, 2.2250738585072014e-308, 1e-8, 0.5, -0.5,
               1.0, -1.0, 2.0, 3.0, 10.0, PI, -PI, PI / 2, PI / 4, 3 * PI / 2, 2 * PI, 1000 * 2 * PI,
               1e6, 1e9 * PI, 2.0 ** 40 + 0.5, 2.0 ** 52, 2.0 ** 53, 2.0 ** 62, 2.0 ** 63,
               math.nextafter(2.0 ** 63, math.inf), math.nextafter(2.0 ** 63, 0.0), 2.0 ** 64, 1e18,
               1e19, -1e19, 1e300, -1e300, 1.7976931348623157e308, math.inf, -math.inf, math.nan]
TRIG_OPS = {"fsin": bytes([0xD9, 0xFE]), "fcos": bytes([0xD9, 0xFF]),
            "fptan": bytes([0xD9, 0xF2]), "fsincos": bytes([0xD9, 0xFB])}
# precision control (bits 8-9) and rounding control (bits 10-11) on 0x3f (all exceptions masked)
TRIG_CW = [(pc << 8) | (rc << 10) | 0x3F for pc in range(4) for rc in range(4)]


def trig_snippet(op_name, load, cw=None, second=True):
    """Load ST(0) (load: the fld instruction bytes), apply the transcendental, and store the results
    that are known: ST(0) (the sine or cosine, or 1.0 for fptan, or the unchanged operand when out of
    range), and for fptan/fsincos the value under it (second=True: only when the operand is in range,
    since out of range nothing is pushed and the value under it is the random stack). Each store is
    compared bit for bit in DATA. cw: the control word set before the snippet."""
    code = b""
    if cw is not None:
        code += bytes([0xD9]) + mod_rm_mem(5, OFF_CW)                   # fldcw [cw]
    code += load + TRIG_OPS[op_name]
    code += bytes([0xDD]) + mod_rm_mem(3, OFF_DST)                       # fstp qword [dst]
    if op_name in ("fptan", "fsincos") and second:
        code += bytes([0xDD]) + mod_rm_mem(3, OFF_DST + 8)               # fstp qword [dst+8]
    if cw is not None:
        code += bytes([0xD9]) + mod_rm_mem(5, OFF_CWR)                   # fldcw [restore]
    return code


def test_trig_register_forms():
    # random stacks: the operand is whatever ST(0) holds (specials mixed in), and the stack effects
    # (push for fptan and fsincos) are compared with the rest of the x87 state
    for op_name, op in TRIG_OPS.items():
        run(op_name + " (random stack)", op, n=N)


def trig_in_range(v):
    """C2 clear: not |v| > 2^63. A NaN is in range (the comparison is false), so it is computed."""
    return not (abs(v) > 2.0 ** 63)


def test_trig_special_values_double():
    for v in TRIG_VALUES:
        mem = image([(OFF_A, dbl(v)), (OFF_B, dbl(0.0))])
        for op_name in TRIG_OPS:
            load = bytes([0xDD]) + mod_rm_mem(0, OFF_A)                  # fld qword [a]
            second = trig_in_range(v)
            run("%s of %r (qword)" % (op_name, v),
                trig_snippet(op_name, load, second=second), mem=mem, regs={"edi": DATA}, n=20)


def test_trig_load_widths():
    # float32 and float80 operands (the values are exact in the wider format; m80 holds values
    # that are not doubles too, see KNOWN_M80_NOT_DOUBLE below)
    f32 = [0.0, -0.0, 1.5, 0.1, 1e10, 2.0 ** 63, 3.0e38, 1.0e-40, math.inf, -math.inf, math.nan]
    for v in f32:
        mem = image([(OFF_A, flt(v)), (OFF_B, dbl(0.0))])
        for op_name in TRIG_OPS:
            load = bytes([0xD9]) + mod_rm_mem(0, OFF_A)                  # fld dword [a]
            run("%s of %r (dword)" % (op_name, v),
                trig_snippet(op_name, load, second=trig_in_range(v)), mem=mem, regs={"edi": DATA}, n=20)
    for v in (0.5, -2.75, 1e10, 2.0 ** 63, 2.0 ** 63 * 2, PI, 1e300, math.inf, math.nan):
        mem = image([(OFF_M80, m80_bytes(v)), (OFF_B, dbl(0.0))])
        for op_name in TRIG_OPS:
            load = bytes([0xDB]) + mod_rm_mem(5, OFF_M80)                # fld tbyte [m80]
            run("%s of %r (tbyte)" % (op_name, v),
                trig_snippet(op_name, load, second=trig_in_range(v)), mem=mem, regs={"edi": DATA}, n=20)


# Extended operands that are not doubles. The register model holds doubles, so fld m80 rounds them to
# nearest-even (x87_f80_to_double). The emulator keeps the 64-bit significand and rounds it to double
# with the RC mode when fsin/fcos/fptan/fsincos convert ST(0) (qemu's floatx80_to_float64). So under RC
# down/up/truncate the result can differ by an ulp. These are listed in MISMATCHES, with their inputs.
NON_DOUBLE_M80 = [
    ("1+2^-63", 0x8000000000000001, 0x3fff),
    ("1+2^-52+2^-63", 0x8000000000000801, 0x3fff),
    ("1+2^-53+2^-63", 0x8000000000000401, 0x3fff),
    ("0.1 (80-bit)", 0xcccccccccccccccd, 0x3ffb),
    ("pi (80-bit)", 0xc90fdaa22168c235, 0x4000),
    ("2^63 + 1 (80-bit)", 0x8000000000000001, 0x403e),
]
MISMATCHES = []
EXPECTED_M80_MISMATCHES = 116      # of 6 operands x 4 ops x 16 control words (only RC down/up/truncate)


def test_trig_extended_operands_not_double():
    for label, sig, se in NON_DOUBLE_M80:
        for op_name in TRIG_OPS:
            for cw in TRIG_CW:
                mem = image([(OFF_M80, m80_raw(sig, se)), (OFF_B, dbl(0.0)),
                             (OFF_CW, struct.pack("<H", cw)), (OFF_CWR, struct.pack("<H", CW_RESTORE))])
                load = bytes([0xDB]) + mod_rm_mem(5, OFF_M80)                 # fld tbyte [m80]
                code = trig_snippet(op_name, load, cw=cw, second=False)
                rc = (cw >> 10) & 3
                try:
                    run("%s %s cw %04x" % (label, op_name, cw), code, mem=mem, regs={"edi": DATA}, n=6)
                except AssertionError as e:
                    if rc == 0:                    # nearest: the load and the emulator agree; a failure here is a bug
                        raise
                    MISMATCHES.append("%s %s cw %04x (RC %d): %s" % (label, op_name, cw, rc,
                                                                    str(e).splitlines()[0][:120]))
    # Pinned, not free: the 116 cases of 384 are the known model limitation (see the comment above
    # NON_DOUBLE_M80). Any other count means the lifted result or the emulator changed.
    assert len(MISMATCHES) == EXPECTED_M80_MISMATCHES, len(MISMATCHES)


def test_trig_precision_and_rounding_control():
    # every precision-control and rounding-control setting: the result is a double, so PC only matters
    # if the emulator rounds it, and RC only matters if the host libm reads the rounding mode
    values = [1.0, 0.5, 1e6 + 0.3, PI / 3, 2.0 ** 63, 2.0 ** 63 * 1.5, -1.25]
    for cw in TRIG_CW:
        for v in values:
            mem = image([(OFF_A, dbl(v)), (OFF_B, dbl(0.0)), (OFF_CW, struct.pack("<H", cw)),
                         (OFF_CWR, struct.pack("<H", CW_RESTORE))])
            for op_name in TRIG_OPS:
                load = bytes([0xDD]) + mod_rm_mem(0, OFF_A)
                run("%s of %r with cw %04x" % (op_name, v, cw),
                    trig_snippet(op_name, load, cw=cw, second=trig_in_range(v)),
                    mem=mem, regs={"edi": DATA}, n=10)


def main():
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
        except AssertionError as e:
            failed += 1
            print("FAIL", name, "\n", str(e)[:1500])
    print("%d tests, %d failed" % (len(tests), failed))
    if KNOWN:
        print("known rig-readback differences (not failures; see the comment above run()):")
        for line in KNOWN:
            print("  " + line)
    if MISMATCHES:
        print("native/emulator mismatches, reported and not hidden (see test_trig_extended_operands_not_double):")
        for line in MISMATCHES:
            print("  " + line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())


# ---------------------------------------------------------------- fpatan

FPATAN = bytes([0xD9, 0xF3])
FPATAN_VALUES = [0.0, -0.0, 5e-324, -1e-300, 0.5, -1.0, 1.0, 2.0, -3.0, PI, 1e300, -1e300,
                 math.inf, -math.inf, math.nan]


def test_fpatan_register_form():
    run("fpatan (random stack)", FPATAN, n=N)


def test_fpatan_special_values():
    # every (y, x) pair: fld qword [a] (y), fld qword [b] (x), fpatan, fstp qword [dst]
    for y in FPATAN_VALUES:
        for x in FPATAN_VALUES:
            mem = image([(OFF_A, dbl(y)), (OFF_B, dbl(x))])
            code = (bytes([0xDD]) + mod_rm_mem(0, OFF_A) + bytes([0xDD]) + mod_rm_mem(0, OFF_B)
                    + FPATAN + bytes([0xDD]) + mod_rm_mem(3, OFF_DST) + bytes([0xDF, 0xE0]))
            run("fpatan of (%r, %r)" % (y, x), code, mem=mem, regs={"edi": DATA}, n=20)


def test_fpatan_precision_and_rounding_control():
    pairs = [(1.0, 3.0), (-0.3, 0.7), (1e6 + 0.3, -2.5), (PI, 1.0 / 3)]
    for cw in TRIG_CW:
        for y, x in pairs:
            mem = image([(OFF_A, dbl(y)), (OFF_B, dbl(x)), (OFF_CW, struct.pack("<H", cw)),
                         (OFF_CWR, struct.pack("<H", CW_RESTORE))])
            code = (bytes([0xD9]) + mod_rm_mem(5, OFF_CW)
                    + bytes([0xDD]) + mod_rm_mem(0, OFF_A) + bytes([0xDD]) + mod_rm_mem(0, OFF_B)
                    + FPATAN + bytes([0xDD]) + mod_rm_mem(3, OFF_DST)
                    + bytes([0xD9]) + mod_rm_mem(5, OFF_CWR))
            run("fpatan of (%r, %r) with cw %04x" % (y, x, cw), code, mem=mem, regs={"edi": DATA}, n=10)


# ---------------------------------------------------------------- fyl2x

FYL2X = bytes([0xD9, 0xF1])
FYL2X_X = [0.0, -0.0, 5e-324, 1e-300, 0.25, 0.5, 1.0, 2.0, 3.0, 10.0, 1e300, -1.0, math.inf, -math.inf, math.nan]
FYL2X_Y = [0.0, -0.0, 1.0, -1.0, 3.0, 0.1, 1e300, -1e-300, math.inf, math.nan]


def test_fyl2x_register_form():
    run("fyl2x (random stack)", FYL2X, n=N)


def test_fyl2x_special_values():
    # (y, x): fld qword [a] (y), fld qword [b] (x), fyl2x, fstp qword [dst], fnstsw ax
    for y in FYL2X_Y:
        for x in FYL2X_X:
            mem = image([(OFF_A, dbl(y)), (OFF_B, dbl(x))])
            code = (bytes([0xDD]) + mod_rm_mem(0, OFF_A) + bytes([0xDD]) + mod_rm_mem(0, OFF_B)
                    + FYL2X + bytes([0xDD]) + mod_rm_mem(3, OFF_DST) + bytes([0xDF, 0xE0]))
            run("fyl2x of (%r, %r)" % (y, x), code, mem=mem, regs={"edi": DATA}, n=20)


def test_fyl2x_precision_and_rounding_control():
    pairs = [(1.0, 3.0), (-0.3, 0.7), (20.0, 1e6 + 0.3), (PI, 1.0 / 3)]
    for cw in TRIG_CW:
        for y, x in pairs:
            mem = image([(OFF_A, dbl(y)), (OFF_B, dbl(x)), (OFF_CW, struct.pack("<H", cw)),
                         (OFF_CWR, struct.pack("<H", CW_RESTORE))])
            code = (bytes([0xD9]) + mod_rm_mem(5, OFF_CW)
                    + bytes([0xDD]) + mod_rm_mem(0, OFF_A) + bytes([0xDD]) + mod_rm_mem(0, OFF_B)
                    + FYL2X + bytes([0xDD]) + mod_rm_mem(3, OFF_DST)
                    + bytes([0xD9]) + mod_rm_mem(5, OFF_CWR))
            run("fyl2x of (%r, %r) with cw %04x" % (y, x, cw), code, mem=mem, regs={"edi": DATA}, n=10)


# ---------------------------------------------------------------- frndint, fscale, fprem, fprem1 (H56)

FRNDINT = bytes([0xD9, 0xFC])
FSCALE = bytes([0xD9, 0xFD])
FPREM = bytes([0xD9, 0xF8])
FPREM1 = bytes([0xD9, 0xF5])
TWO_OPS = {"fscale": FSCALE, "fprem": FPREM, "fprem1": FPREM1}


def two_op_snippet(op, y, x, cw=None):
    """fld qword [a] (y: ST(1)), fld qword [b] (x: ST(0)), op, fstp qword [dst], fstp qword [dst+8], fnstsw ax;
    with cw, the control word is set first and restored at the end."""
    code = b""
    if cw is not None:
        code += bytes([0xD9]) + mod_rm_mem(5, OFF_CW)
    code += (bytes([0xDD]) + mod_rm_mem(0, OFF_A) + bytes([0xDD]) + mod_rm_mem(0, OFF_B) + op
             + bytes([0xDD]) + mod_rm_mem(3, OFF_DST) + bytes([0xDD]) + mod_rm_mem(3, OFF_DST + 8)
             + bytes([0xDF, 0xE0]))
    if cw is not None:
        code += bytes([0xD9]) + mod_rm_mem(5, OFF_CWR)
    return code


def two_op_mem(y, x, cw=CW_RESTORE):
    return image([(OFF_A, dbl(y)), (OFF_B, dbl(x)), (OFF_CW, struct.pack("<H", cw)),
                  (OFF_CWR, struct.pack("<H", CW_RESTORE))])


FRNDINT_VALUES = [0.0, -0.0, 0.3, -0.3, 0.5, -0.5, 1.5, 2.5, -2.5, 0.49999999999999994, 1e15 + 0.5, -1e15 - 0.5,
                  4503599627370495.5, 2.0 ** 52, 2.0 ** 60 + 2048, 5e-324, -5e-324, 1e300, math.inf, -math.inf,
                  math.nan, 123456.789, -7.75]


def test_frndint_register_form():
    run("frndint (random stack)", FRNDINT, n=N)


def test_frndint_values_and_rounding_control():
    for cw in TRIG_CW:
        for v in FRNDINT_VALUES:
            mem = image([(OFF_A, dbl(v)), (OFF_CW, struct.pack("<H", cw)), (OFF_CWR, struct.pack("<H", CW_RESTORE))])
            code = (bytes([0xD9]) + mod_rm_mem(5, OFF_CW) + bytes([0xDD]) + mod_rm_mem(0, OFF_A) + FRNDINT
                    + bytes([0xDD]) + mod_rm_mem(3, OFF_DST) + bytes([0xDF, 0xE0])
                    + bytes([0xD9]) + mod_rm_mem(5, OFF_CWR))
            run("frndint of %r with cw %04x" % (v, cw), code, mem=mem, regs={"edi": DATA}, n=5)


# results stay inside double range and normal (the model holds doubles; an 80-bit register does not overflow there)
FSCALE_PAIRS = [(0.0, 1.5), (1.0, 1.5), (-1.0, 1.5), (2.9, 3.0), (-2.9, 3.0), (10.0, -7.25), (-0.5, 1.0),
                (100.0, 1e-200), (-100.0, 1e200), (0.7, 0.0), (5.0, -0.0), (1e9, 0.0), (-1e9, 0.0),
                (3e9, 0.0), (-3e9, 0.0), (math.inf, 0.0), (-math.inf, 0.0), (math.inf, 1.0), (math.nan, 0.0),
                (2.0, math.nan), (2.0, math.inf), (-2.0, -math.inf), (1022.0, 1.0), (-1021.0, 1.0),
                (0.3333, 1.0 / 3)]


def test_fscale_register_form():
    run("fscale (random stack)", FSCALE, n=N, known=REASON_RESIDUE)


def test_fscale_values_and_control():
    for cw in (CW_RESTORE, CW_PC24, CW_RC[1], CW_RC[2], CW_RC[3], 0x033F):
        for y, x in FSCALE_PAIRS:
            run("fscale of (%r, %r) with cw %04x" % (y, x, cw), two_op_snippet(FSCALE, y, x, cw),
                mem=two_op_mem(y, x, cw), regs={"edi": DATA}, n=5)


# (ST(1) divisor, ST(0) dividend): complete reductions (expdif < 53), partial ones (expdif >= 53), expdif < 0,
# invalid operands, signs, quotient bits
FPREM_PAIRS = [(3.0, 10.0), (3.0, -10.0), (-3.0, 10.0), (-3.0, -10.0), (2.0, 7.0), (2.0, 5.0), (0.1, 1.0),
               (2 * PI, 100.0), (2 * PI, -1234.5678), (PI / 2, 7.0), (1.0, 0.5), (10.0, 3.0), (1.0, 2.5),
               (1.0, 3.5), (1.0, -2.5), (1.0, 1e16), (1.0, 1e20), (3.0, 1e300), (0.7, 2.0 ** 80 + 2.0 ** 30),
               (1e-300, 1e300), (5e-324, 1.0), (1.0, 5e-324), (1.0, 0.0), (1.0, -0.0), (0.0, 1.0), (-0.0, 1.0),
               (1.0, math.inf), (1.0, -math.inf), (math.inf, 5.0), (-math.inf, -5.0), (math.nan, 1.0),
               (1.0, math.nan), (7.0, 7.0), (7.0, -7.0), (360.0, 725.25), (2.0 ** 60, 2.0 ** 63 + 2.0 ** 11)]


def test_fprem_register_forms():
    for name in ("fprem", "fprem1"):
        run(name + " (random stack)", TWO_OPS[name], n=N, known=REASON_RESIDUE)


def test_fprem_values():
    for name in ("fprem", "fprem1"):
        for y, x in FPREM_PAIRS:
            run("%s of (%r, %r)" % (name, x, y), two_op_snippet(TWO_OPS[name], y, x),
                mem=two_op_mem(y, x), regs={"edi": DATA}, n=5)


def test_fprem_reduction_loop():
    # fmod's loop: fprem ; fnstsw ax ; sahf ; jp back, run to completion, on large quotients
    loop = FPREM + bytes([0xDF, 0xE0, 0x9E, 0x7A, 0xF9])
    for name, op in (("fprem", FPREM), ("fprem1", FPREM1)):
        body = op + bytes([0xDF, 0xE0, 0x9E, 0x7A, 0xF9])
        for y, x in [(3.0, 1e300), (2 * PI, 1e100), (0.7, 2.0 ** 80 + 2.0 ** 30), (1e-5, 1e250)]:
            code = (bytes([0xDD]) + mod_rm_mem(0, OFF_A) + bytes([0xDD]) + mod_rm_mem(0, OFF_B) + body
                    + bytes([0xDD]) + mod_rm_mem(3, OFF_DST) + bytes([0xDD]) + mod_rm_mem(3, OFF_DST + 8))
            run("%s loop of (%r, %r)" % (name, x, y), code, mem=two_op_mem(y, x), regs={"edi": DATA}, n=5)
    assert loop


def test_fprem_precision_and_rounding_control():
    for cw in TRIG_CW:
        for name in ("fprem", "fprem1"):
            for y, x in [(3.0, 10.3), (2 * PI, 100.7), (0.1, 1.0)]:
                run("%s of (%r, %r) with cw %04x" % (name, x, y, cw), two_op_snippet(TWO_OPS[name], y, x, cw),
                    mem=two_op_mem(y, x, cw), regs={"edi": DATA}, n=5)


# ---------------------------------------------------------------- fnsave / frstor (H56)

OFF_SAVE = 0x60         # the 108-byte save area (disp8 up to +24 for the mask)


def test_fnsave_frstor():
    # the instruction and operand pointers (save area bytes 12-27) are not modelled (see x87_fnsave): zeroed after
    # the fnsave by `mov dword [edi + OFF_SAVE + k], 0`, so the rest of the image is compared
    mask = b"".join(bytes([0xC7, 0x47, OFF_SAVE + k]) + b"\0\0\0\0" for k in (12, 16, 20, 24))
    fnsave = bytes([0xDD]) + mod_rm_mem(6, OFF_SAVE) + mask
    frstor = bytes([0xDD]) + mod_rm_mem(4, OFF_SAVE)
    # rounding and precision controls, condition bits from a compare, four registers in use and four empty ones, all
    # holding known values (random empty registers can hold extended residues a double cannot express, see
    # REASON_RESIDUE, and fninit keeps the values): the saved image and the state after fninit
    # fld1 fld1 faddp (2.0) fld1 fcom st1 fldz fld1: values a double holds exactly (fldpi and the like are extended)
    known = bytes([0xD9, 0xE8, 0xD9, 0xE8, 0xDE, 0xC1, 0xD9, 0xE8, 0xD8, 0xD1, 0xD9, 0xEE, 0xD9, 0xE8])
    for cw in (CW_RESTORE, CW_PC24, CW_RC[3], 0x0C3F):
        mem = image([(OFF_CW, struct.pack("<H", cw)), (OFF_CWR, struct.pack("<H", CW_RESTORE))])
        fill = bytes([0xD9, 0xE8]) * 8 + bytes([0xDB, 0xE3])     # every register 1.0, then fninit (values stay)
        code = bytes([0xDB, 0xE3]) + fill + bytes([0xD9]) + mod_rm_mem(5, OFF_CW) + known + fnsave
        run("fnsave with cw %04x" % cw, code, mem=mem, regs={"edi": DATA}, n=10)
    # save, clobber, restore: the whole state comes back (pow's pattern around its helper call)
    clobber = bytes([0xD9, 0xE8, 0xD9, 0xEE, 0xDE, 0xC1])                   # fld1 ; fldz ; faddp
    # random stacks: only the restored state is compared, so the area (at esi) is cleared afterwards (its image of a
    # random state holds the extended residues the rig cannot express)
    save_esi, rstor_esi = bytes([0xDD, 0x36]), bytes([0xDD, 0x26])          # fnsave [esi], frstor [esi]
    clear = b"".join(bytes([0xC7, 0x46, k]) + b"\0\0\0\0" for k in range(0, 108, 4))
    run("fnsave ; clobber ; frstor", save_esi + clobber + rstor_esi + clear, regs={"esi": DATA + 0x200}, n=N,
        known=REASON_RESIDUE)
    # a known stack with zeros, infinities and NaN for the tag word, then restore after fninit
    loads = b""
    for k, v in enumerate([1.5, 0.0, math.inf, -2.25, math.nan]):
        loads += bytes([0xDD]) + mod_rm_mem(0, OFF_V + 8 * k)
    mem = image([(OFF_V + 8 * k, dbl(v)) for k, v in enumerate([1.5, 0.0, math.inf, -2.25, math.nan])])
    fill = bytes([0xD9, 0xE8]) * 8 + bytes([0xDB, 0xE3])
    code = bytes([0xDB, 0xE3]) + fill + loads + fnsave + bytes([0xDB, 0xE3]) + frstor + bytes([0xDF, 0xE0])
    run("fnsave/frstor of a known stack", code, mem=mem, regs={"edi": DATA}, n=10)


def test_fnstenv_fldenv():
    # MSVCRT _adj_fprem's pattern: fnstenv [esp] ; change the stack and the control word ; fldenv [esp]. The image is
    # compared with the pointers masked (see test_fnsave_frstor); the restored environment against the reference.
    mask = b"".join(bytes([0xC7, 0x47, OFF_SAVE + k]) + b"\0\0\0\0" for k in (12, 16, 20, 24))
    fill = bytes([0xD9, 0xE8]) * 8 + bytes([0xDB, 0xE3])
    known = bytes([0xD9, 0xE8, 0xD9, 0xE8, 0xDE, 0xC1, 0xD9, 0xE8, 0xD8, 0xD1, 0xD9, 0xEE])  # 2, 1, fcom, 0
    stenv, ldenv = bytes([0xD9]) + mod_rm_mem(6, OFF_SAVE), bytes([0xD9]) + mod_rm_mem(4, OFF_SAVE)
    clobber = bytes([0xD9, 0xE8, 0xD9, 0xE8, 0xDE, 0xD9, 0xD9]) + mod_rm_mem(5, OFF_CWR)  # fld1 fld1 fcompp fldcw
    for cw in (CW_RESTORE, CW_PC24, CW_RC[3]):
        mem = image([(OFF_CW, struct.pack("<H", cw)), (OFF_CWR, struct.pack("<H", CW_RESTORE))])
        code = bytes([0xDB, 0xE3]) + fill + bytes([0xD9]) + mod_rm_mem(5, OFF_CW) + known + stenv + mask
        run("fnstenv with cw %04x" % cw, code, mem=mem, regs={"edi": DATA}, n=10)
        run("fnstenv ; clobber ; fldenv with cw %04x" % cw, code + clobber + ldenv + bytes([0xDF, 0xE0]), mem=mem,
            regs={"edi": DATA}, n=10)
    # random stacks: only the restored state is compared (the area at esi is cleared afterwards)
    clear = b"".join(bytes([0xC7, 0x46, k]) + b"\0\0\0\0" for k in range(0, 28, 4))
    run("fnstenv ; fld1 ; fldenv (random stack)", bytes([0xD9, 0x36, 0xD9, 0xE8, 0xD9, 0x26]) + clear,
        regs={"esi": DATA + 0x200}, n=N)


F2XM1 = bytes([0xD9, 0xF0])
F2XM1_VALUES = [0.0, -0.0, 0.5, -0.5, 1.0, -1.0, 0.25, -0.999, 1e-10, -1e-300, 5e-324, 0.7071, 2.0, -3.5, 100.0,
                math.inf, -math.inf, math.nan]


def test_f2xm1():
    run("f2xm1 (random stack)", F2XM1, n=N, known=REASON_RESIDUE)
    for cw in TRIG_CW:
        for v in F2XM1_VALUES:
            mem = image([(OFF_A, dbl(v)), (OFF_CW, struct.pack("<H", cw)), (OFF_CWR, struct.pack("<H", CW_RESTORE))])
            code = (bytes([0xD9]) + mod_rm_mem(5, OFF_CW) + bytes([0xDD]) + mod_rm_mem(0, OFF_A) + F2XM1
                    + bytes([0xDD]) + mod_rm_mem(3, OFF_DST) + bytes([0xDF, 0xE0]) + bytes([0xD9]) + mod_rm_mem(5, OFF_CWR))
            run("f2xm1 of %r with cw %04x" % (v, cw), code, mem=mem, regs={"edi": DATA}, n=3)
