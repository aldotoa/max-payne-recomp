#!/usr/bin/env python3
"""Lifted rlmfc code against the emulator on the same work (M5 performance evidence).

Usage: bench_native.py <game dir> <lifted rlmfc dylib>

Runs two real rlmfc functions on large buffers, emulated and then native (fast path), from the same
inputs, checks the outputs are identical and prints the time per call:
  R_Memory::copy (fastcall dst, src, n): the memcpy, taking its MMX path when the caps say so
  R_CPUReference::multiply(M_Vector3Array &, const M_Vector3Array &, const M_Matrix3 &): x87 loop
Few calls with a lot of work each, so the bridge's per-call cost is negligible here."""
import os
import random
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "emu"))
import mpemu                                                  # noqa: E402
from native import Native                                     # noqa: E402
from unicorn.x86_const import UC_X86_REG_EDX                  # noqa: E402

COPY = 0x10016730            # ?copy@R_Memory@@SIPAXPAXPBXI@Z
MUL3 = 0x1000cab0            # ?multiply@R_CPUReference@@UBEXAAVM_Vector3Array@@ABV2@ABV?$M_Matrix3Template@M@@@Z


def timed(fn, reps):
    best = None
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        dt = time.perf_counter() - t0
        best = dt if best is None or dt < best else best
    return best


def main(game, lib):
    e = mpemu.boot(game, verbose=False)
    mpemu.run_dll_mains(e, verbose=False)
    n = Native(e, lib)
    rng = random.Random(1)
    rows = []

    # memcpy of 4 MB, misaligned by 3
    size = 4 << 20
    src, dst = e.alloc(size + 64), e.alloc(size + 64)
    e.wr(src, bytes(rng.getrandbits(8) for _ in range(4096)) * (size // 4096 + 1))

    def copy():
        e.uc.reg_write(UC_X86_REG_EDX, src + 3)
        e.call(COPY, size, ecx=dst + 1, max_insns=0)
        assert not e.fatal, e.fatal
    t_emu = timed(copy, 3)
    out_emu = bytes(e.rd(dst + 1, size))          # exactly the bytes the copy writes
    e.wr(dst + 1, b"\0" * size)
    n.install_fast([COPY])
    t_nat = timed(copy, 3)
    out_nat = bytes(e.rd(dst + 1, size))
    n.uninstall(COPY)
    rows.append(("R_Memory::copy 4 MB", t_emu, t_nat, out_emu == out_nat))

    # 3x3 matrix times 200,000 vectors (x87)
    count = 200000
    def arr(ptr):
        a = e.alloc(16)
        e.wr(a, struct.pack("<III", 0, count, ptr))
        return a
    vin, vout = e.alloc(count * 12 + 64), e.alloc(count * 12 + 64)
    e.wr(vin, struct.pack("<%df" % (count * 3), *[rng.uniform(-100, 100) for _ in range(count * 3)]))
    a_in, a_out = arr(vin), arr(vout)
    mat = e.alloc(64)
    e.wr(mat, struct.pack("<9f", *[rng.uniform(-2, 2) for _ in range(9)]))
    this = e.alloc(64)

    def mul():
        e.call(MUL3, a_out, a_in, mat, ecx=this, max_insns=0)
        assert not e.fatal, e.fatal
    t_emu = timed(mul, 3)
    out_emu = bytes(e.rd(vout, count * 12))
    e.wr(vout, b"\0" * (count * 12))
    n.install_fast([MUL3])
    t_nat = timed(mul, 3)
    out_nat = bytes(e.rd(vout, count * 12))
    n.uninstall(MUL3)
    rows.append(("Matrix3 x 200k Vector3 (x87)", t_emu, t_nat, out_emu == out_nat))

    print("%-30s %12s %12s %8s  %s" % ("work", "emulated", "native", "speedup", "outputs"))
    for name, te, tn, same in rows:
        print("%-30s %10.2f ms %10.2f ms %7.1fx  %s" % (name, te * 1e3, tn * 1e3, te / tn,
                                                       "identical" if same else "DIFFER"))
    return 0 if all(r[3] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
