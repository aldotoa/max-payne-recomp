"""Unit tests for the emulator undo log (Emu.undo_begin / undo_end / undo_rollback).
Hand-assembled guest code (encodings checked with capstone); no game files needed.

Run:  .venv/bin/python emu/test_undo.py
"""
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import mpemu
from unicorn.x86_const import UC_X86_REG_FP0, UC_X86_REG_FPCW

DATA = mpemu.HEAP_BASE + 0x100000          # page-aligned scratch area well away from the allocator's blocks


def _regs(e):
    return {r: e.uc.reg_read(r) for r in mpemu._UNDO_REGS}


def _assert_regs_equal(before, after):
    diff = {r: (before[r], after[r]) for r in before if before[r] != after[r]}
    assert not diff, {hex(k): v for k, v in diff.items()}


def _code(e, body):
    p = e.alloc(len(body) + 16)
    e.wr(p, body)
    return p


def _store_dword(addr, v):
    return b"\xc7\x05" + struct.pack("<I", addr) + struct.pack("<I", v)     # mov dword ptr [addr], v


def test_stores_and_rollback():
    """(a) 32/16/8-bit stores, an unaligned store across a page boundary, rep stosd over 1 KB, GPR/EFLAGS changes.
    Rollback restores the guest bytes and the registers exactly."""
    e = mpemu.Emu(".")
    D = DATA
    P = D + 0x1000                         # page boundary inside the scratch area
    S = D + 0x2000                         # rep stosd target
    body = (
        _store_dword(D + 0, 0x11223344) +                     # mov dword ptr [D], 0x11223344
        b"\x66\xc7\x05" + struct.pack("<I", D + 5) + b"\xef\xbe" +  # mov word ptr [D+5], 0xbeef
        b"\xc6\x05" + struct.pack("<I", D + 7) + b"\x5a" +        # mov byte ptr [D+7], 0x5a
        _store_dword(P - 2, 0xAABBCCDD) +                     # mov dword ptr [P-2], ... (crosses P)
        b"\xbf" + struct.pack("<I", S) +                      # mov edi, S
        b"\xb9" + struct.pack("<I", 256) +                    # mov ecx, 256
        b"\xb8" + struct.pack("<I", 0x41424344) +             # mov eax, 0x41424344
        b"\xf3\xab" +                                         # rep stosd
        b"\xbb" + struct.pack("<I", 0x12345678) +             # mov ebx, 0x12345678
        b"\x01\xd8" +                                         # add eax, ebx  (changes EFLAGS)
        b"\xc3")                                              # ret
    code = _code(e, body)
    e.wr(D, b"\x90" * 0x3000)                                 # known contents (NOPs) in the scratch area
    before_mem = bytes(e.rd(D, 0x3000))
    before_regs = _regs(e)
    log = e.undo_begin()
    e.call(code)
    assert not e.fatal, e.fatal
    assert e.rd32(D) == 0x11223344 and e.rd32(P - 2) == 0xAABBCCDD and e.rd(S, 4) == b"\x44\x43\x42\x41"
    e.undo_end(log)
    assert bytes(e.rd(D, 0x3000)) != before_mem
    e.undo_rollback(log)
    assert bytes(e.rd(D, 0x3000)) == before_mem, "memory differs after rollback"
    _assert_regs_equal(before_regs, _regs(e))
    print("ok  guest stores (8/16/32, page crossing, rep stosd) and registers/EFLAGS roll back exactly")


def test_x87_rollback():
    """(b) x87 work: fld1; fldpi; faddp; fldcw. Rollback restores FPCW, FPSW (TOP), FPTAG and FP0-7 (raw 80-bit)."""
    e = mpemu.Emu(".")
    cw_addr = DATA + 0x40
    e.wr(cw_addr, struct.pack("<H", 0x037F))                  # a different control word (64-bit precision)
    body = (
        b"\xd9\xe8" +                                         # fld1
        b"\xd9\xeb" +                                         # fldpi
        b"\xde\xc1" +                                         # faddp st(1), st(0)   -> 1 + pi on the stack
        b"\xd9\xee" +                                         # fldz
        b"\xd9\x2d" + struct.pack("<I", cw_addr) +            # fldcw word ptr [cw_addr]
        b"\xc3")
    code = _code(e, body)
    before = _regs(e)
    log = e.undo_begin()
    e.call(code)
    assert not e.fatal, e.fatal
    assert e.uc.reg_read(UC_X86_REG_FPCW) == 0x037F
    assert e.uc.reg_read(UC_X86_REG_FP0 + 7) != before[UC_X86_REG_FP0 + 7]
    e.undo_end(log)
    e.undo_rollback(log)
    _assert_regs_equal(before, _regs(e))
    print("ok  x87: FPCW, FPSW/TOP, FPTAG and FP0-7 (80-bit) roll back exactly")


def test_context_covers_x87():
    """(b') proves that uc.context_save/context_restore alone restores the x87 unit and FS (the explicit copy in
    undo_rollback is only a fallback that the tests check is never needed)."""
    e = mpemu.Emu(".")
    uc = e.uc
    code = _code(e, b"\xd9\xe8\xd9\xeb\xde\xc1\xd9\xee\xb8\x01\x00\x00\x00\xc3")   # fld1; fldpi; faddp; fldz; mov eax,1
    before = _regs(e)
    ctx = uc.context_save()
    e.call(code)
    assert _regs(e) != before                             # the guest really changed the x87 state
    uc.context_restore(ctx)
    _assert_regs_equal(before, _regs(e))
    print("ok  uc.context_save covers the x87 unit (FPCW/FPSW/FPTAG/FP0-7), FS and GDTR")


def test_fs_rollback():
    """FS (the TEB selector) and the GDT register come back after a guest changes FS."""
    e = mpemu.Emu(".")
    code = _code(e, b"\x31\xc0" + b"\x8e\xe0" + b"\xc3")     # xor eax, eax; mov fs, ax (null selector); ret
    before = _regs(e)
    log = e.undo_begin()
    e.call(code)
    assert e.uc.reg_read(mpemu.UC_X86_REG_FS) == 0, "guest should have changed FS"
    e.undo_end(log)
    e.undo_rollback(log)
    _assert_regs_equal(before, _regs(e))
    assert e.uc.reg_read(mpemu.UC_X86_REG_FS) == 0x18
    print("ok  FS (and GDTR) roll back")


def test_host_writes():
    """(c) e.wr and e.wr32 host writes (and the alloc zeroing path) are rolled back."""
    e = mpemu.Emu(".")
    p = DATA + 0x200
    e.wr(p, b"ORIGINAL-BYTES!!")
    before = bytes(e.rd(p, 16))
    log = e.undo_begin()
    e.wr(p, b"new")
    e.wr32(p + 8, 0xDEADBEEF)
    q = e.alloc(64)                                       # a block that was zero-filled by the host
    e.wr(q, b"\x55" * 64)
    e.undo_end(log)
    assert e.rd(p, 3) == b"new"
    e.undo_rollback(log)
    assert bytes(e.rd(p, 16)) == before
    print("ok  host writes (wr, wr32, alloc zeroing) roll back")


def test_writes_exact():
    """(d) writes() is exactly the set of bytes written, with their final values."""
    e = mpemu.Emu(".")
    Q = DATA + 0x300
    e.wr(Q, b"\x00" * 16)
    body = (
        _store_dword(Q, 0x11223344) +                     # bytes Q..Q+3 = 44 33 22 11
        b"\xc6\x05" + struct.pack("<I", Q + 1) + b"\x99" +  # byte Q+1 = 99 (overwrites a byte already written)
        b"\xc3")
    code = _code(e, body)
    log = e.undo_begin()
    e.call(code)
    e.wr(Q + 8, b"\x01\x02")                             # host write, after the guest ran
    e.undo_end(log)
    w = log.writes()
    expect = {Q + 0: 0x44, Q + 1: 0x99, Q + 2: 0x22, Q + 3: 0x11, Q + 8: 0x01, Q + 9: 0x02}
    # e.call itself writes the return address and the SEH head (stack and TEB); those are real writes too
    mine = {a: v for a, v in w.items() if Q <= a < Q + 16}
    assert mine == expect, {hex(k): v for k, v in mine.items()}
    rest = [a for a in w if not Q <= a < Q + 16]
    stack = mpemu.STACK_TOP - mpemu.STACK_SIZE
    assert all(stack <= a < mpemu.STACK_TOP or mpemu.TEB <= a < mpemu.TEB + 8 for a in rest), \
        [hex(a) for a in rest]
    print("ok  writes() lists exactly the bytes written, with final values")


def test_nesting():
    """(e) inner and outer logs: each records its own old bytes; inner rollback leaves the outer log exact."""
    e = mpemu.Emu(".")
    A, B = DATA + 0x400, DATA + 0x404
    e.wr(A, b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19")
    base = bytes(e.rd(A, 10))
    store_a = _code(e, _store_dword(A, 0xA1A1A1A1) + b"\xc3")               # guest store to A
    store_ab = _code(e, _store_dword(A, 0xA2A2A2A2) + _store_dword(B, 0xB2B2B2B2) + b"\xc3")
    outer = e.undo_begin()
    e.call(store_a)                                       # A = A1 (outer records A's old bytes)
    mid = bytes(e.rd(A, 10))
    inner = e.undo_begin()
    e.call(store_ab)                                      # A = A2, B = B2 (both logs record)
    e.undo_end(inner)
    in_data = lambda w: {a for a in w if DATA <= a < DATA + 0x1000}    # skip e.call's stack and TEB writes
    assert in_data(inner.writes()) == {A, A + 1, A + 2, A + 3, B, B + 1, B + 2, B + 3}
    assert set(outer.writes()) >= set(inner.writes())      # the outer log keeps recording while the inner is active
    e.undo_rollback(inner)
    assert bytes(e.rd(A, 10)) == mid, "inner rollback must return to the state at its undo_begin"
    assert e.rd(B, 4) == base[4:8], "inner rollback must restore B to its value before the inner log"
    e.undo_end(outer)
    assert not e._undo_stack
    e.undo_rollback(outer)
    assert bytes(e.rd(A, 10)) == base, "outer rollback must restore the state at its undo_begin"
    print("ok  nested logs: inner and outer both exact; inner rollback restores the inner begin state")


def test_call_with_hle_import():
    """(g) a guest function that calls an HLE import (which writes guest memory) then writes too: all rolled back."""
    seen = []

    @mpemu.hle("TEST.DLL", "UndoWrite", 1)
    def _undo_write(e, p):
        seen.append(p)
        e.wr32(p, 0xCAFE)
        e.wr(p + 8, b"hi")
        return 3

    e = mpemu.Emu(".")
    buf = DATA + 0x500
    e.wr(buf, b"\xaa" * 16)
    stub = e.stub_for("TEST.DLL", "UndoWrite")
    body = (b"\x68" + struct.pack("<I", buf) +            # push buf
            b"\xb8" + struct.pack("<I", stub) +           # mov eax, stub
            b"\xff\xd0" +                                 # call eax   (stdcall: the HLE pops buf)
            _store_dword(buf + 4, 7) +                    # mov dword ptr [buf+4], 7
            b"\xc3")
    code = _code(e, body)
    before_mem = bytes(e.rd(buf, 16))
    before = _regs(e)
    log = e.undo_begin()
    r = e.call(code)
    assert not e.fatal and r == 3 and seen == [buf], (e.fatal, r, seen)
    assert e.rd32(buf) == 0xCAFE and e.rd32(buf + 4) == 7
    e.undo_end(log)
    e.undo_rollback(log)
    assert bytes(e.rd(buf, 16)) == before_mem
    _assert_regs_equal(before, _regs(e))
    print("ok  e.call of guest code calling an HLE import: guest and host writes roll back")


def _store_loop(e, n=300000):
    """A guest loop of n 4-byte stores into a 64 KB region (same shape as the benchmark)."""
    buf = DATA + 0x10000
    code = _code(e, b"\xbe" + struct.pack("<I", buf) + b"\xbb" + struct.pack("<I", n) +
                 b"\x89\xda\xc1\xe2\x02\x81\xe2\xfc\xff\x00\x00\x89\x1c\x16\x4b\x75\xef\xc3")
    return code


def _best_time(e, code, runs=3):
    best = None
    for _ in range(runs):
        t = time.perf_counter()
        e.call(code)
        dt = time.perf_counter() - t
        best = dt if best is None else min(best, dt)
    return best


def test_hook_removed_after_end():
    """(f) after the outermost undo_end the write hook is gone, later stores are not recorded, and stores run at
    full speed again (the best of three runs is within 2x of the run before the log: a leftover hook is ~6x)."""
    e = mpemu.Emu(".")
    p = DATA + 0x600
    e.wr(p, b"\x00" * 8)
    code = _code(e, _store_dword(p, 0x01020304) + b"\xc3")
    loop = _store_loop(e)
    fast_before = _best_time(e, loop)
    log = e.undo_begin()
    assert e._undo_hook is not None
    e.call(code)
    e.undo_end(log)
    assert e._undo_hook is None and not e._undo_stack
    n = len(log.pages)
    e.call(code)                                          # runs without the hook: nothing new is recorded
    assert len(log.pages) == n and log.ended
    fast_after = _best_time(e, loop)
    assert fast_after < 2 * fast_before + 0.01, (fast_before, fast_after)
    log2 = e.undo_begin()                                 # begin again: a fresh hook, a fresh log
    e.call(code)
    e.undo_end(log2)
    assert e._undo_hook is None and log2.writes()
    print("ok  the write hook exists only while a log is active; stores run at full speed after undo_end "
          "(%.4f s before, %.4f s after)" % (fast_before, fast_after))


def test_undo_end_order():
    """Logs end innermost-first; rollback needs an ended log."""
    e = mpemu.Emu(".")
    a = e.undo_begin()
    b = e.undo_begin()
    try:
        e.undo_end(a)
        raise AssertionError("ending the outer log first must fail")
    except RuntimeError:
        pass
    e.undo_end(b)
    e.undo_end(a)
    try:
        e.undo_rollback(a)
        assert True
    except RuntimeError:
        raise AssertionError("ended log must roll back")
    print("ok  undo_end must be innermost-first; rollback works on ended logs")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("all undo tests passed")
