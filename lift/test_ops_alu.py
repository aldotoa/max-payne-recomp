"""Differential tests for the integer ALU handlers (lift/ops_alu.py).

Every instruction form is run on n=200 random states through insnrig.check (Unicorn against the
translated C). `undefined=` lists exactly the flags the Intel manual leaves undefined for that
form; everything else, including CF/OF for counts the manual defines, is compared.

The divide-error (#DE) path is covered two ways: random tests pin the operands so the quotient fits
(no fault), and test_div_fault compiles the translated code on its own and checks that a fault
calls lift_div_fault at the instruction address and returns.

Plain asserts, no pytest.
Run:  ../../../.venv/bin/python lift/test_ops_alu.py      (from the worktree root)
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# The rig caches compiled snippets under the temp dir. A cache shared with other runs was seen to
# get binaries killed by macOS (AMFI signature check, SIGKILL), so this run gets a private one.
import atexit
import tempfile
tempfile.tempdir = tempfile.mkdtemp(prefix="ops-alu-")
atexit.register(shutil.rmtree, tempfile.tempdir, True)

import insnrig
import x86c
from insnrig import check, enc, DATA, CODE

STATS = {"checks": 0, "states": 0}
DEST = {"edi": DATA + 0x100}                  # a memory operand at [edi] inside the data region
ALL = ()                                      # nothing undefined
LOGIC_UNDEF = ("af",)                         # and/or/xor: AF undefined
SHIFT_UNDEF = ("af",)                         # shifts: AF undefined
MUL_UNDEF = ("sf", "zf", "af", "pf")          # mul/imul: SF ZF AF PF undefined
DIV_UNDEF = ("cf", "of", "sf", "zf", "af", "pf")
BIT_UNDEF = ("sf", "zf", "of", "af", "pf")    # bt family: only CF is defined
SCAN_UNDEF = ("cf", "of", "sf", "af", "pf")   # bsf/bsr: only ZF is defined


def ok(code, n=200, **kw):
    """One check; asserts it passes and counts it."""
    r = check(enc(code), n=n, **kw)
    STATS["checks"] += 1
    STATS["states"] += r.n
    assert r.ok, str(r)


# ---------------------------------------------------------------- add sub adc sbb and or xor

def test_binary_alu_forms():
    # base opcode (r/m8, r8 form) and the /ext of the 80/81/83 group
    table = [("add", 0x00, 0, ALL), ("or", 0x08, 1, LOGIC_UNDEF), ("adc", 0x10, 2, ALL),
             ("sbb", 0x18, 3, ALL), ("and", 0x20, 4, LOGIC_UNDEF), ("sub", 0x28, 5, ALL),
             ("xor", 0x30, 6, LOGIC_UNDEF)]
    for _mn, b, ext, und in table:
        mod_reg = 0xc0 | (ext << 3) | 1       # group form on ecx
        mod_mem = 0x07 | (ext << 3)           # group form on [edi]
        forms = [
            "%02x d8" % (b + 1),                 # op eax, ebx
            "%02x 07" % (b + 3),                 # op eax, [edi]
            "%02x 07" % (b + 1),                 # op [edi], eax
            "%02x e7" % b,                       # op bh, ah (high-byte registers)
            "%02x 0f" % (b + 2),                 # op cl, [edi]
            "%02x 0f" % b,                       # op [edi], cl
            "66 %02x d8" % (b + 1),              # op ax, bx
            "66 %02x 07" % (b + 1),              # op [edi], ax
            "%02x 7f" % (b + 4),                 # op al, imm8
            "%02x 78 56 34 12" % (b + 5),        # op eax, imm32
            "66 %02x 34 12" % (b + 5),           # op ax, imm16
            "81 %02x 78 56 34 12" % mod_reg,     # op ecx, imm32
            "83 %02x ff" % mod_reg,              # op ecx, -1 (imm8 sign-extended)
            "80 %02x 7f" % mod_reg,              # op cl, imm8
            "83 %02x 05" % mod_mem,              # op dword ptr [edi], 5
            "81 %02x 78 56 34 12" % mod_mem,     # op dword ptr [edi], imm32
            "80 %02x 80" % mod_mem,              # op byte ptr [edi], 0x80
            "66 83 %02x ff" % mod_mem,           # op word ptr [edi], -1
        ]
        for f in forms:
            ok(f, undefined=und, regs=DEST)


def test_inc_dec_keep_cf():
    for f in ["40", "48", "66 40", "66 48", "fe c1", "fe c9", "fe c4", "fe cc", "ff c0", "ff c8",
              "ff 07", "ff 0f", "fe 07", "fe 0f", "66 ff 07", "66 ff 0f"]:
        ok(f, regs=DEST)                  # CF is compared: it must be unchanged


def test_neg_not():
    for f in ["f7 d8", "f6 d8", "66 f7 d8", "f6 dc", "f7 1f", "f6 1f", "66 f7 1f",
              "f7 d0", "f6 d3", "f6 d4", "66 f7 d1", "f7 17", "f6 17", "66 f7 17"]:
        ok(f, regs=DEST)


def test_neg_cf_is_nonzero_source():
    # neg sets CF from the source being nonzero; a zero source is the edge that matters
    ok("f7 d8", regs={"eax": [0, 1, 0x80000000, 0x12345678]})
    ok("f6 d8", regs={"eax": [0, 1, 0x80, 0x12]})


# ---------------------------------------------------------------- shifts and rotates

ROTATES = {"rol": 0, "ror": 1, "rcl": 2, "rcr": 3}
SHIFTS = {"shl": 4, "shr": 5, "sar": 7}


def _shift_undef(name, count):
    """Flags the manual leaves undefined for a shift or rotate by a fixed count."""
    if name in ROTATES:
        return () if count == 1 else ("of",)
    if count == 1:
        return ("af",)
    return ("af", "of")


def test_shifts_fixed_count():
    for name, ext in list({**ROTATES, **SHIFTS}.items()):
        mod_al, mod_eax = 0xc0 | (ext << 3), 0xc0 | (ext << 3)
        mod_mem = 0x07 | (ext << 3)
        # count 1: the one-bit forms, OF is defined
        for f in ["d0 %02x" % mod_al, "d1 %02x" % mod_eax, "66 d1 %02x" % mod_eax,
                  "d0 %02x" % mod_mem, "d1 %02x" % mod_mem, "66 d1 %02x" % mod_mem]:
            ok(f, undefined=_shift_undef(name, 1), regs=DEST)
        # immediate counts, 8/16/32 bit and memory; 8, 16 and 31 cross the operand widths
        for count in (1, 2, 7, 8, 9, 16, 17, 31):
            und = _shift_undef(name, count)
            ok("c0 %02x %02x" % (mod_al, count), undefined=und)
            ok("66 c1 %02x %02x" % (mod_eax, count), undefined=und)
            ok("c1 %02x %02x" % (mod_eax, count), undefined=und)
            ok("c0 %02x %02x" % (mod_mem, count), undefined=und, regs=DEST)
            ok("c1 %02x %02x" % (mod_mem, count), undefined=und, regs=DEST)
            ok("66 c1 %02x %02x" % (mod_mem, count), undefined=und, regs=DEST)


def test_shifts_by_cl():
    for name, ext in list({**ROTATES, **SHIFTS}.items()):
        mod_al = 0xc0 | (ext << 3)
        mod_eax = 0xc0 | (ext << 3)
        mod_mem = 0x07 | (ext << 3)
        # CL random over 0..63: counts 0, 1, 2..31 and 32+ (masked to 0..31)
        und = ("of", "af") if name in SHIFTS else ("of",)
        ok("d2 %02x" % mod_al, regs={"ecx": range(0, 64)}, undefined=und)
        ok("d3 %02x" % mod_eax, regs={"ecx": range(0, 64)}, undefined=und)
        ok("66 d3 %02x" % mod_eax, regs={"ecx": range(0, 64)}, undefined=und)
        ok("d3 %02x" % mod_mem, regs={**DEST, "ecx": range(0, 64)}, undefined=und)
        ok("d2 %02x" % mod_mem, regs={**DEST, "ecx": range(0, 64)}, undefined=und)
        # CL = 1 exactly (also with high ECX bits set): OF is defined here
        ok("d3 %02x" % mod_eax, regs={"ecx": [1, 0x21, 0xffffff41]}, undefined=("af",)
           if name in SHIFTS else ())


def test_shift_count_zero_changes_no_flags():
    for name, ext in list({**ROTATES, **SHIFTS}.items()):
        mod_eax = 0xc0 | (ext << 3)
        mod_mem = 0x07 | (ext << 3)
        ok("d3 %02x" % mod_eax, regs={"ecx": [0, 32, 64, 0xffffffe0]})   # count 0 masked
        ok("c1 %02x 00" % mod_eax)                                       # imm 0
        ok("c1 %02x 20" % mod_mem, regs=DEST)                            # imm 32 masks to 0


def test_shift_fixed_cl_with_high_bits():
    # only CL counts, so high ECX bits must be ignored: 0xdeadbe21 shifts by 0x21 & 31 = 1
    ok("d3 e0", regs={"ecx": 0xdeadbe21}, undefined=("af",))
    ok("d3 e8", regs={"ecx": 0xdeadbe00})           # count 0: no flag changes


def test_double_shifts():
    und_imm = lambda c: ("af",) if c == 1 else ("af", "of")
    for c in (1, 2, 5, 16, 31):
        ok("0f a4 d8 %02x" % c, undefined=und_imm(c))          # shld eax, ebx, imm
        ok("0f ac d8 %02x" % c, undefined=und_imm(c))          # shrd eax, ebx, imm
        ok("0f a4 1f %02x" % c, undefined=und_imm(c), regs=DEST)   # shld [edi], ebx, imm
    for c in (1, 2, 9, 16):
        ok("66 0f a4 d8 %02x" % c, undefined=und_imm(c))       # shld ax, bx, imm
        ok("66 0f ac d8 %02x" % c, undefined=und_imm(c))       # shrd ax, bx, imm
    ok("0f a5 d8", regs={"ecx": range(0, 32)}, undefined=("of", "af"))
    ok("0f ad d8", regs={"ecx": range(0, 32)}, undefined=("of", "af"))
    ok("0f a5 1f", regs={**DEST, "ecx": range(0, 32)}, undefined=("of", "af"))
    ok("0f ad 1f", regs={**DEST, "ecx": range(0, 32)}, undefined=("of", "af"))
    ok("66 0f a5 d8", regs={"ecx": range(0, 17)}, undefined=("of", "af"))
    ok("66 0f ad d8", regs={"ecx": range(0, 17)}, undefined=("of", "af"))
    ok("0f a5 d8", regs={"ecx": 1}, undefined=("af",))         # count 1: OF defined
    ok("0f ad d8", regs={"ecx": 1}, undefined=("af",))
    ok("0f a5 d8", regs={"ecx": 0})                             # count 0: nothing changes
    ok("0f ad d8", regs={"ecx": 0})


# ---------------------------------------------------------------- multiply and divide

def test_mul_one_operand():
    for f in ["f6 e3", "f6 e4", "f7 e1", "66 f7 e1", "f7 27", "f6 27", "66 f7 27",
              "f7 e9", "f6 eb", "66 f7 e9", "f7 2f", "f6 2f", "66 f7 2f"]:
        ok(f, undefined=MUL_UNDEF, regs=DEST)


def test_imul_two_and_three_operand():
    for f in ["0f af c3", "66 0f af c3", "0f af 07", "66 0f af 07",
              "6b c3 05", "6b c3 ff", "69 c3 78 56 34 12", "66 6b c3 05", "66 69 c3 34 12",
              "6b 07 fe", "69 07 78 56 34 12"]:
        ok(f, undefined=MUL_UNDEF, regs=DEST)


def test_div_idiv_no_fault():
    # operands pinned so the quotient always fits and no #DE can happen
    ok("f6 f3", regs={"eax": range(0, 256), "ebx": range(1, 256)}, undefined=DIV_UNDEF)     # div bl
    ok("f7 f1", regs={"edx": 0, "ecx": range(1, 2 ** 32)}, undefined=DIV_UNDEF)             # div ecx
    ok("66 f7 f1", regs={"edx": 0, "ecx": range(1, 65536)}, undefined=DIV_UNDEF)           # div cx
    ok("f6 37", regs={**DEST, "eax": range(0, 256)}, undefined=DIV_UNDEF,
       mem=b"\x00" * 0x100 + b"\x07")                                                       # div byte [edi]
    ok("f7 37", regs={**DEST, "edx": 0}, undefined=DIV_UNDEF,
       mem=b"\x00" * 0x100 + b"\x07\x00\x00\x00")                                           # div dword [edi]
    ok("66 f7 37", regs={**DEST, "edx": 0}, undefined=DIV_UNDEF,
       mem=b"\x00" * 0x100 + b"\x07\x00")                                                   # div word [edi]
    # idiv: the dividend is kept positive (sign-extended with edx = 0) so the quotient fits
    ok("f6 fb", regs={"eax": range(0, 128), "ebx": range(1, 256)}, undefined=DIV_UNDEF)     # idiv bl
    ok("f7 f9", regs={"edx": 0, "eax": range(0, 2 ** 31), "ecx": range(1, 2 ** 32)},
       undefined=DIV_UNDEF)                                                                 # idiv ecx
    ok("66 f7 f9", regs={"edx": 0, "eax": range(0, 32768), "ecx": range(1, 65536)},
       undefined=DIV_UNDEF)                                                                 # idiv cx
    ok("f6 3f", regs={**DEST, "eax": range(0, 128)}, undefined=DIV_UNDEF,
       mem=b"\x00" * 0x100 + b"\x07")                                                       # idiv byte [edi]
    ok("f7 3f", regs={**DEST, "edx": 0, "eax": range(0, 2 ** 31)}, undefined=DIV_UNDEF,
       mem=b"\x00" * 0x100 + b"\xf9\xff\xff\xff")                                           # idiv dword [edi] = -7
    ok("66 f7 3f", regs={**DEST, "edx": 0, "eax": range(0, 32768)}, undefined=DIV_UNDEF,
       mem=b"\x00" * 0x100 + b"\x07\x00")                                                   # idiv word [edi]
    # negative dividend (edx = -1) and divisors that keep the quotient in range
    ok("f7 f9", regs={"edx": 0xffffffff, "eax": range(2 ** 31, 2 ** 32),
                      "ecx": range(2, 2 ** 32 - 1)}, undefined=DIV_UNDEF)


# ---------------------------------------------------------------- setcc cmovcc

CC = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"]


def test_setcc_cmovcc_all_conditions():
    for i, _cc in enumerate(CC):
        ok("0f %02x c0" % (0x90 + i))                          # set<cc> al
        ok("0f %02x 07" % (0x90 + i), regs=DEST)               # set<cc> byte ptr [edi]
        ok("0f %02x c3" % (0x40 + i))                          # cmov<cc> eax, ebx
        ok("66 0f %02x c3" % (0x40 + i))                       # cmov<cc> ax, bx
        ok("0f %02x 07" % (0x40 + i), regs=DEST)               # cmov<cc> eax, [edi]


# ---------------------------------------------------------------- bit tests and scans

def test_bit_test_family():
    for ext, rr in [(4, 0xa3), (5, 0xab), (6, 0xb3), (7, 0xbb)]:       # bt bts btr btc
        ok("0f %02x d8" % rr, undefined=BIT_UNDEF)                      # reg, reg (bit = ebx mod 32)
        ok("66 0f %02x d8" % rr, undefined=BIT_UNDEF)                   # 16-bit
        for imm in (0, 5, 31, 0x21):                                    # imm mod width
            ok("0f ba %02x %02x" % (0xc0 | (ext << 3), imm), undefined=BIT_UNDEF)
            ok("66 0f ba %02x %02x" % (0xc0 | (ext << 3), imm), undefined=BIT_UNDEF)
            ok("0f ba %02x %02x" % (0x07 | (ext << 3), imm), undefined=BIT_UNDEF, regs=DEST)
        # memory with a signed register bit offset that reaches outside the dword
        ok("0f %02x 0f" % rr, undefined=BIT_UNDEF,
           regs={"edi": DATA + 0x8000, "ecx": range(-0x20000, 0x20000)})
        ok("66 0f %02x 0f" % rr, undefined=BIT_UNDEF,
           regs={"edi": DATA + 0x8000, "ecx": range(-0x8000, 0x8000)})


def test_bit_scan():
    for op in (0xbc, 0xbd):                                             # bsf, bsr
        ok("0f %02x c3" % op, undefined=SCAN_UNDEF,
           regs={"ebx": [0, 1, 0x80000000, 0x00120000, 0x12345678]})   # zero source is covered
        ok("66 0f %02x c3" % op, undefined=SCAN_UNDEF,
           regs={"ebx": [0, 0x100, 0x8000, 0x12345678]})
        ok("0f %02x 07" % op, undefined=SCAN_UNDEF, regs=DEST,
           mem=b"\x00" * 0x100 + b"\x00\x00\x00\x00")                    # zero memory source
        ok("0f %02x 07" % op, undefined=SCAN_UNDEF, regs=DEST)


# ---------------------------------------------------------------- byte swap, extension, flags

def test_bswap_cbw_cwd():
    for f in ["0f c8", "0f cb", "0f cf"]:
        ok(f)
    ok("66 98")                                  # cbw
    ok("66 99")                                  # cwd


def test_flag_register_and_flag_ops():
    ok("9f")                                     # lahf
    ok("9e")                                     # sahf (OF untouched: compared)
    ok("f8")                                     # clc
    ok("f9")                                     # stc
    ok("f5")                                     # cmc
    ok("fc", random_df=True)                     # cld
    ok("fd", random_df=True)                     # std


# ---------------------------------------------------------------- exchange and compare-exchange

def test_xadd():
    for f in ["0f c1 d8", "0f c0 d8", "66 0f c1 d8", "0f c1 c0"]:
        ok(f)
    ok("0f c1 07", regs=DEST)                    # xadd [edi], eax
    ok("0f c0 07", regs=DEST)                    # xadd [edi], al


def test_cmpxchg_both_paths():
    # eax and the destination are drawn from the same two values, so both ZF outcomes occur
    same = {"eax": [0, 5], "ecx": [0, 5], "ebx": [0, 5]}
    ok("0f b1 d9", regs=same)                    # cmpxchg ecx, ebx
    ok("0f b0 d9", regs=same)                    # cmpxchg cl, bl
    ok("66 0f b1 d9", regs=same)                 # cmpxchg cx, bx
    zero_mem = {**DEST, "eax": [0, 5]}
    ok("0f b1 0f", regs=zero_mem, mem=b"\x00" * 0x100 + b"\x00" * 4)   # cmpxchg [edi], ecx
    ok("0f b0 0f", regs=zero_mem, mem=b"\x00" * 0x100 + b"\x00" * 4)   # cmpxchg [edi], cl
    ok("0f b1 0f", regs=DEST)                                          # random memory
    ok("66 0f b1 0f", regs=DEST)                                       # cmpxchg [edi], cx


# ---------------------------------------------------------------- divide error

_DIV_C = r"""
#include "lift.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void f_00401000(CPU *c);
static int faults;
static uint32_t fault_va;
static uint8_t mem[4096];

void lift_div_fault(CPU *c, uint32_t va) { (void)c; faults++; fault_va = va; }
void lift_call(CPU *c, uint32_t t) { (void)c; (void)t; exit(3); }
void lift_call_ret(CPU *c, uint32_t t, uint32_t r) { (void)c; (void)t; (void)r; exit(3); }
void lift_jump(CPU *c, uint32_t t) { (void)c; (void)t; exit(3); }
int lift_is_bridge_ret(uint32_t v) { (void)v; exit(3); }
void lift_unsupported(CPU *c, uint32_t va, const char *what) { (void)c; (void)va; (void)what; exit(3); }

int main(int argc, char **argv)
{
    CPU c;
    memset(&c, 0, sizeof c);
    c.mem = mem;
    c.r[ESP] = 2048;
    c.r[EAX] = (uint32_t)strtoul(argv[1], 0, 16);
    c.r[EDX] = (uint32_t)strtoul(argv[2], 0, 16);
    c.r[ECX] = (uint32_t)strtoul(argv[3], 0, 16);
    push32(&c, 0x00401800u);
    f_00401000(&c);
    printf("%d %08x %08x %08x\n", faults, fault_va, c.r[EAX], c.r[EDX]);
    return 0;
}
"""


def _run_div_case(code, eax, edx, ecx):
    """Translate the snippet (code + ret), compile it with a direct harness and run it once.
    Returns (faulted, fault_va, eax, edx)."""
    snippet = enc(code) + b"\xc3"
    res = x86c.lift_function(insnrig._SnippetImage(snippet), CODE)
    assert res.ok, res.unsupported
    assert "lift_div_fault(c, 0x00401000u);" in res.c, res.c
    d = tempfile.mkdtemp(prefix="ops_alu_de_")
    try:
        src = os.path.join(d, "snippet.c")
        main = os.path.join(d, "main.c")
        exe = os.path.join(d, "a.out")
        with open(src, "w") as f:
            f.write(res.c)
        with open(main, "w") as f:
            f.write(_DIV_C)
        cc = subprocess.run(["clang", "-std=gnu11", "-Wall", "-Wno-unused-label", "-O1", "-I",
                             x86c.RUNTIME, "-o", exe, main, src], capture_output=True, text=True)
        assert cc.returncode == 0, cc.stderr[:1500]
        run = subprocess.run([exe, "%x" % eax, "%x" % edx, "%x" % ecx], capture_output=True,
                             text=True, timeout=30)
        assert run.returncode == 0, run.stderr
        faults, va, ra, rd = run.stdout.split()
        return int(faults) == 1, int(va, 16), int(ra, 16), int(rd, 16)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_div_fault():
    # zero divisor: #DE, the handler is called with the instruction address and the function returns
    faulted, va, ra, rd = _run_div_case("f7 f1", 10, 0, 0)            # div ecx, ecx = 0
    assert faulted and va == CODE, (faulted, va)
    assert (ra, rd) == (10, 0), (ra, rd)                              # registers untouched
    # quotient does not fit (edx:eax = 2^32 divided by 1): #DE
    faulted, va, _, _ = _run_div_case("f7 f1", 0, 1, 1)
    assert faulted and va == CODE
    # normal division: no fault, quotient in eax, remainder in edx
    faulted, _, ra, rd = _run_div_case("f7 f1", 10, 0, 3)
    assert not faulted and (ra, rd) == (3, 1), (faulted, ra, rd)
    # idiv: INT32_MIN / -1 does not fit: #DE
    faulted, va, _, _ = _run_div_case("f7 f9", 0x80000000, 0xffffffff, 0xffffffff)
    assert faulted and va == CODE
    # idiv by zero
    faulted, _, _, _ = _run_div_case("f6 fb", 0x0010, 0, 0)            # idiv bl with bl = 0
    assert faulted


def test_lock_prefix_memory_forms():
    # `lock` on a read-modify-write form with a memory operand runs as the unlocked instruction
    # (single-threaded emulation). Same checks as the unlocked forms above.
    # `lock neg` is not tested: the reference (Unicorn) computes its flags wrong, and it is not
    # in LOCKABLE (see x86c.py).
    for f in ["f0 ff 07", "f0 ff 0f", "66 f0 ff 07", "f0 f7 17",                    # inc dec not
              "f0 01 07", "f0 29 07", "f0 11 07", "f0 19 07",                       # add sub adc sbb
              "f0 83 07 05", "f0 83 2f 05", "f0 81 07 78 56 34 12"]:                # group 80/81/83
        ok(f, regs=DEST)
    for f in ["f0 21 07", "f0 09 07", "f0 31 07"]:                                  # and or xor
        ok(f, undefined=LOGIC_UNDEF, regs=DEST)
    ok("f0 0f c1 07", regs=DEST)                   # lock xadd [edi], eax
    ok("f0 0f c0 07", regs=DEST)                   # lock xadd [edi], al
    ok("f0 0f b1 0f", regs={**DEST, "eax": range(0, 16)})   # lock cmpxchg [edi], ecx
    ok("f0 87 07", regs=DEST)                      # lock xchg [edi], eax




TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]

if __name__ == "__main__":
    t0 = time.time()
    for t in TESTS:
        print(t.__name__)
        t()
    print("all %d ALU tests passed: %d checks, %d random states, %.1f s"
          % (len(TESTS), STATS["checks"], STATS["states"], time.time() - t0))
