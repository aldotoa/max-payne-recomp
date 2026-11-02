"""Self-test for the odd-instruction family (lift/ops_misc.py, lift/runtime/misc.c).

1. Differential (insnrig.check, Unicorn vs translated C): pushad/popad, pushaw/popaw (16-bit),
   pushfd, popfd. These run n random states each and compare registers, flags and the stack.
2. Rejected instructions (movq xmm, orps of two registers, int) must give a clean failed Result that names
   them as emulator-only. MMX movq (mm forms) and emms are checked against Unicorn with mmx=True, and a
   deliberately wrong movq handler must be reported (negative control for the rig).
3. cpuid: the C table in misc.c must match Unicorn for every leaf/subleaf it covers, including the
   out-of-range leaves. Compiled from a translated `cpuid; ret` snippet, linked with misc.c.
4. rdtsc: translated `rdtsc; ret` is monotonic, and advances with wall time.
5. Real DLL (skipped when the game file is missing): readTickCount lifts with lift_rdtsc, and
   determineProcessorCaps lifts (popfd, cpuid, its orps xmm7, xmm7 probe).

Plain asserts, no pytest.
Run:  ../../../.venv/bin/python lift/test_ops_misc.py      (from the worktree root)
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import capstone
import x86c
from x86c import PEImage, RUNTIME, lift_function
import insnrig
from insnrig import CODE, DATA as DATA_ADDR, _SnippetImage, check, dis, enc

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                               UC_X86_REG_ESP)

CLANG = shutil.which("clang") or "/usr/bin/clang"
CFLAGS = ["-O1", "-std=gnu11", "-Wall", "-Wno-unused-label", "-Wno-unused-variable",
          "-Wno-unused-function", "-I", RUNTIME]
DLL = os.environ.get("MP_DLL", os.path.normpath(os.path.join(
    HERE, "..", "..", "..", "..", "Max Payne", "rlmfc.dll")))

# (leaf, subleaf) pairs compared against Unicorn: every table entry, both subleaves for the
# leaves whose table entries ignore ecx, and the out-of-range / zero leaves.
CPUID_PAIRS = [
    (0x0, 0), (0x0, 1), (0x1, 0), (0x1, 7), (0x2, 0), (0x2, 1),
    (0x4, 0), (0x4, 1), (0x4, 2), (0x7, 0), (0xd, 0),
    (0x80000000, 0), (0x80000000, 1), (0x80000001, 0), (0x80000001, 5),
    (0x80000002, 0), (0x80000003, 0), (0x80000005, 0), (0x80000005, 1),
    (0x80000006, 0), (0x80000008, 0),
    # zeros in the emulator and in the table
    (0x4, 3), (0x80000004, 0), (0x80000007, 0), (0xb, 0), (0xb, 1),
    # out of range: the emulator returns leaf 0xd
    (0xe, 0), (0x14, 0), (0x1f, 0), (0x80000009, 0), (0x80000010, 0),
]


def expect_text(code, text):
    got = dis(enc(code))
    assert got == text, "decode mismatch for %s:\n  got  %r\n  want %r" % (code, got, text)


def assert_ok(r):
    assert r.ok, str(r)


# ---------------------------------------------------------------- differential: pushad family

# The rig's trailing `ret` must find the return address, so each snippet moves esp back to the
# entry value with lea (add/sub are not translated yet): lea esp,[esp+d] is 8d 64 24 dd.

def test_xlatb():
    # al = byte [ebx + al] over a random table at DATA, every flag kept (MSVCRT's _ctrlfp/_fpieee table lookups)
    from insnrig import DATA
    assert_ok(check(enc("d7"), n=200, regs={"ebx": DATA + 0x100}, flags="all"))
    assert_ok(check(enc("d7 d7"), n=50, regs={"ebx": DATA}, flags="all"))


def test_pushad_decodes_and_matches():
    expect_text("60", "pushal")
    assert_ok(check(enc("60 8d 64 24 20"), n=200))           # pushad; esp += 32: stack contents
    assert_ok(check(enc("8d 64 24 e0 61"), n=200))           # esp -= 32; popad reads the stack


def test_pushad_popad_round_trip():
    assert_ok(check(enc("60 61"), n=200))                    # esp and regs restored
    assert_ok(check(enc("8d 64 24 fc 60 61 8d 64 24 04"), n=200))   # round trip, offset esp


def test_pushaw_popaw_16bit_forms():
    expect_text("66 60", "pushaw")
    expect_text("66 61", "popaw")
    assert_ok(check(enc("66 60 8d 64 24 10"), n=200))        # 16-bit pusha, then esp += 16
    assert_ok(check(enc("8d 64 24 f0 66 61"), n=200))        # 16-bit popa: high halves kept
    assert_ok(check(enc("66 60 66 61"), n=200))              # round trip


def test_pushfd_flags_all():
    expect_text("9c", "pushfd")
    assert_ok(check(enc("9c 8d 64 24 04"), n=200, flags="all"))          # state is read only
    assert_ok(check(enc("39 d8 9c 8d 64 24 04"), n=200, flags="all"))    # pushes flags a cmp set
    assert_ok(check(enc("83 f8 01 9c 8d 64 24 04"), n=200, flags="all"))  # cmp eax, 1 then pushfd


# ---------------------------------------------------------------- rejected: clean failures

def test_popfd_matches_unicorn():
    """popfd sets the flag bytes and keeps TF/IF/IOPL/NT/AC/ID for the next pushfd, as Unicorn does (E5)."""
    expect_text("9d", "popfd")
    # push imm; popfd; pushfd; pop eax: every kept bit, the arithmetic flags, DF
    for imm in (0x00200000, 0x00040000, 0x00004000, 0x00000200, 0x00003000, 0x00000ad5, 0x00000400, 0x0024f6d7):
        code = "68 %s 9d 9c 58" % " ".join("%02x" % b for b in struct.pack("<I", imm))
        assert_ok(check(enc(code), n=20, flags="all"))
    # determineProcessorCaps' cpuid test: toggle ID through popfd and read it back (eax = 0x200000)
    assert_ok(check(enc("9c 58 89 c3 35 00 00 20 00 50 9d 9c 58 31 d8 53 9d"), n=20, flags="all"))


def test_orps_same_register_is_nothing():
    expect_text("0f 56 ff", "orps xmm7, xmm7")
    res = _translate_snippet("0f 56 ff")
    assert res.ok and "orps x, x" in res.c, res.unsupported


def test_rejected_are_clean_emulator_only():
    expect_text("f3 0f 7e c1", "movq xmm0, xmm1")
    cases = [("f3 0f 7e c1", "movq"), ("0f 56 f9", "orps"), ("cd 01", "int")]
    for code, mnem in cases:
        r = check(enc(code), n=10)
        assert not r.ok and r.n_failed == 1, str(r)
        assert any("emulator-only" in f and mnem in f for f in r.failures), (mnem, r.failures)


# ---------------------------------------------------------------- differential: MMX

def test_mmx_movq_emms_match_unicorn():
    """movq mm,m64 / m64,mm / mm,mm and emms: registers, TOP, tags and the eight mm values (physical FP
    mantissas) match Unicorn from random x87 states with random mm values."""
    expect_text("0f 6f 06", "movq mm0, qword ptr [esi]")
    expect_text("0f 7f 0f", "movq qword ptr [edi], mm1")
    expect_text("0f 6f d5", "movq mm2, mm5")
    expect_text("0f 77", "emms")
    esi = {"esi": DATA_ADDR}
    edi = {"edi": DATA_ADDR + 0x800}
    assert_ok(check(enc("0f 6f 06"), regs=esi, mmx=True, n=100, undefined=()))           # load mm0
    assert_ok(check(enc("0f 6f 5e 08"), regs=esi, mmx=True, n=100, undefined=()))        # load mm3, [esi+8]
    assert_ok(check(enc("0f 7f 0f"), regs=edi, mmx=True, n=100, undefined=()))           # store mm1
    assert_ok(check(enc("0f 6f d5"), mmx=True, n=100, undefined=()))                    # mm2 <- mm5
    assert_ok(check(enc("0f 6f 06 0f 7f 0f 0f 77"), regs={**esi, **edi}, mmx=True, n=100,
                    undefined=()))                                                       # load, store, emms
    assert_ok(check(enc("0f 77"), mmx=True, n=100, undefined=()))                       # emms alone


def test_mmx_check_detects_a_wrong_handler():
    """Negative control for the rig: a movq handler that loads the wrong bits must be reported."""
    real = x86c.HANDLERS["movq"]

    def broken(ctx, ins):
        lines = real(ctx, ins)
        return [ln.replace("rd64(c,", "rd64(c, 0u + 1u +") if "rd64" in ln else ln for ln in lines]

    x86c.HANDLERS["movq"] = broken
    try:
        r = check(enc("0f 6f 06"), regs={"esi": DATA_ADDR}, mmx=True, n=20, undefined=())
    finally:
        x86c.HANDLERS["movq"] = real
    assert not r.ok and r.n_failed > 0, "a wrong movq was not detected: %s" % r


# ---------------------------------------------------------------- C build helpers

_WORK_DIRS = []


def _build_run(snippet_c_src, harness_src, extra_sources, name):
    """Compile harness + translated snippet + runtime sources; returns the exe path. The work
    directory is removed at exit."""
    work = tempfile.mkdtemp(prefix="ops-misc-%s-" % name)
    _WORK_DIRS.append(work)
    srcs = []
    for fname, text in [("snippet.c", snippet_c_src), ("main.c", harness_src)]:
        p = os.path.join(work, fname)
        with open(p, "w") as f:
            f.write(text)
        srcs.append(p)
    srcs += extra_sources
    exe = os.path.join(work, "a.out")
    cc = subprocess.run([CLANG] + CFLAGS + ["-o", exe] + srcs, capture_output=True, text=True)
    assert cc.returncode == 0, "clang failed:\n" + cc.stderr + "\n" + snippet_c_src
    return exe


import atexit
atexit.register(lambda: [shutil.rmtree(d, ignore_errors=True) for d in _WORK_DIRS])


# The harness reads "leaf sub" pairs on stdin and prints the four result registers for each call
# of the translated function at CODE. The CPU struct starts zeroed, with esp at 0x8000.
HARNESS = r'''
#include <stdio.h>
#include <string.h>
#include "lift.h"
void f_%08x(CPU *c);
int main(void)
{
    static uint8_t mem[65536];
    unsigned leaf, sub;
    while (scanf("%%u %%u", &leaf, &sub) == 2) {
        CPU c;
        memset(&c, 0, sizeof c);
        c.mem = mem;
        c.r[ESP] = 0x8000;
        c.r[EAX] = leaf;
        c.r[ECX] = sub;
        f_%08x(&c);
        printf("%%08x %%08x %%08x %%08x\n", c.r[EAX], c.r[EBX], c.r[ECX], c.r[EDX]);
    }
    return 0;
}
'''


def _translate_snippet(code_hex):
    """C for `code; ret` at CODE (the same wrapper the insnrig uses) and the entry name."""
    snippet = enc(code_hex) + b"\xc3"
    res = lift_function(_SnippetImage(snippet), CODE)
    assert res.ok, "translate failed: %s" % res.unsupported
    return res


def _run_harness(exe, pairs):
    inp = "".join("%d %d\n" % (leaf, sub) for leaf, sub in pairs)
    proc = subprocess.run([exe], input=inp, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    rows = [tuple(int(x, 16) for x in line.split()) for line in proc.stdout.splitlines()]
    assert len(rows) == len(pairs), (len(rows), len(pairs))
    return rows


# ---------------------------------------------------------------- cpuid against Unicorn

def uc_cpuid(leaf, sub):
    """(eax, ebx, ecx, edx) that Unicorn returns for cpuid with eax=leaf, ecx=sub."""
    code = b"\xb8" + struct.pack("<I", leaf) + b"\xb9" + struct.pack("<I", sub) + b"\x0f\xa2"
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(CODE, 0x1000, UC_PROT_ALL)
    uc.mem_map(0x10000, 0x10000, UC_PROT_ALL)
    uc.mem_write(CODE, code)
    uc.reg_write(UC_X86_REG_ESP, 0x18000)
    uc.emu_start(CODE, CODE + len(code))
    return tuple(uc.reg_read(r) for r in (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX))


def test_cpuid_matches_unicorn():
    res = _translate_snippet("0f a2")
    assert "lift_cpuid(c);" in res.c, res.c
    exe = _build_run(res.c, HARNESS % (CODE, CODE), [os.path.join(RUNTIME, "misc.c")], "cpuid")
    got = _run_harness(exe, CPUID_PAIRS)
    for (leaf, sub), g in zip(CPUID_PAIRS, got):
        want = uc_cpuid(leaf, sub)
        assert g == want, "cpuid leaf %08x sub %d: lifted %s, unicorn %s" % (
            leaf, sub, ["%08x" % x for x in g], ["%08x" % x for x in want])


# ---------------------------------------------------------------- rdtsc

def _rdtsc_once(exe):
    rows = _run_harness(exe, [(0, 0)])
    eax, _, _, edx = rows[0]
    return (edx << 32) | eax


def test_rdtsc_monotonic():
    res = _translate_snippet("0f 31")
    assert "lift_rdtsc(c);" in res.c, res.c
    exe = _build_run(res.c, HARNESS % (CODE, CODE), [os.path.join(RUNTIME, "misc.c")], "rdtsc")
    pairs = [(0, 0)] * 2000
    rows = _run_harness(exe, pairs)
    vals = [(edx << 32) | eax for (eax, _, _, edx) in rows]
    assert all(b >= a for a, b in zip(vals, vals[1:])), "rdtsc went backwards"
    # across processes too: after 50 ms of wall time the counter moved by at least 40 ms at 1 GHz
    first = _rdtsc_once(exe)
    time.sleep(0.05)
    second = _rdtsc_once(exe)
    assert second - first >= 40_000_000, (first, second)


# ---------------------------------------------------------------- real DLL

def test_real_dll_readtickcount_and_caps():
    if not os.path.exists(DLL):
        print("  (skipped: game file not found at %s)" % DLL)
        return
    img = PEImage(DLL)
    res = lift_function(img, 0x1001ab90)                     # R_Profile::readTickCount
    assert res.ok and "lift_rdtsc(c);" in res.c, res.unsupported
    caps = lift_function(img, 0x100255d0)                    # R_System::determineProcessorCaps (E5: lifts)
    assert caps.ok, caps.unsupported
    assert "lift_eflags_sys = f & LIFT_EFLAGS_SYS;" in caps.c and "lift_cpuid(c);" in caps.c


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]

if __name__ == "__main__":
    t0 = time.time()
    for t in TESTS:
        print(t.__name__)
        t()
    print("all %d ops_misc tests passed in %.2f s" % (len(TESTS), time.time() - t0))
