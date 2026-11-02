"""Tests for the in-situ differential mode (emu/native.py Native.run_diff, emu/mpemu.py HLE record/replay, lift/runtime
write log): lifted code checked against the emulator from the same state, inside a running emulator (M5).

Synthetic cases (a-d, plus the budget and write-log checks) hand-assemble a small module at SYN_D and check, for each
diffed call, that the result and the complete guest state (registers, flags, every written byte) equal a pure
emulator run from the same state, and that wrong lifted code is reported and does not change the result.
The real-DLL case (e) runs rlmfc.dll's getters under diff mode. Its mismatches are DATA: they are printed, not
asserted; the test fails only on crashes and on the synthetic cases.

Run:  ../../../.venv/bin/python lift/test_diff.py          (plain asserts, no pytest)
"""
import ctypes
import json
import os
import random
import shutil
import struct
import sys
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "emu"))

import build as liftbuild                                   # noqa: E402
import mpemu                                                # noqa: E402
import x86c                                                 # noqa: E402
from native import CPU, LiftLoader, Native, NativeError, function_entries  # noqa: E402
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX,  # noqa: E402
                               UC_X86_REG_ECX, UC_X86_REG_EDI, UC_X86_REG_EDX,
                               UC_X86_REG_EFLAGS, UC_X86_REG_ESI, UC_X86_REG_ESP,
                               UC_X86_REG_FP0, UC_X86_REG_FPCW, UC_X86_REG_FPSW, UC_X86_REG_FPTAG)

BUILD = os.path.join(ROOT, "build-lift", "test_diff")
GAME = os.path.join(ROOT, "Max Payne")

# ---------------------------------------------------------------- synthetic module
SYN_D = 0x00520000                  # guest address of the synthetic code (mapped by each test emulator)
SYN_D_SIZE = 0x4000
SLOT_TID = SYN_D + 0x3000           # IAT-style slots holding the addresses of HLE stubs
SLOT_LEN = SYN_D + 0x3004
SLOT_HEAP = SYN_D + 0x3008
SCRATCH = SYN_D + 0x3100            # data the test functions write
SPIN_N = SCRATCH + 0xA0             # spin: the count it was given (the loop's result)
SPIN_I = SCRATCH + 0xA4             # spin: the loop counter, stored on every iteration
SPIN_CALLS = SCRATCH + 0xA8         # spin: incremented on entry (how many times the function ran)
SPINH_CALLS = SCRATCH + 0xAC        # spinhle: incremented on entry
SPINH_TID = SCRATCH + 0xB0          # spinhle: the HLE result, stored after the loop
FN = {"hc_emu": SYN_D + 0x000,      # emulated only: calls GetCurrentThreadId (HLE), returns it + 1
      "hc": SYN_D + 0x100,          # lifted, stdcall hc(x) = x + hc_emu(): an emulated helper that calls an import
      "hlen": SYN_D + 0x200,        # lifted, stdcall hlen(p) = lstrlenA(p) (HLE import with an argument)
      "halloc": SYN_D + 0x300,      # lifted, stdcall halloc(n) = HeapAlloc(h, 0, n) (HLE allocator)
      "leafsub": SYN_D + 0x400,     # lifted, stdcall leafsub(a, b) = a - b (flags)
      "wmem": SYN_D + 0x500,        # lifted, stdcall wmem(p, v): [p] = v, [p+4] = v, returns p + 8 (memory)
      "cnt_emu": SYN_D + 0x600,     # emulated only: returns [SCRATCH+0x80] after decrementing it (a loop counter)
      "loopcall": SYN_D + 0x700,    # lifted, cdecl: calls cnt_emu until it returns 0 (a guest call in a loop)
      "spin": SYN_D + 0x800,        # lifted, stdcall spin(n): n iterations of a store (a long loop: the budget case)
      "spinhle": SYN_D + 0x900}     # lifted, stdcall spinhle(n): spin(n), then GetCurrentThreadId (an HLE call after the loop)
LIFTED_D = ["hc", "hlen", "halloc", "leafsub", "wmem", "loopcall", "spin", "spinhle"]
CC = {"hc_emu": "cdecl", "hc": "stdcall", "hlen": "stdcall", "halloc": "stdcall", "leafsub": "stdcall",
      "wmem": "stdcall", "cnt_emu": "cdecl", "loopcall": "cdecl", "spin": "stdcall",
      "spinhle": "stdcall"}


def _rel(at, target):
    """rel32 of an E8/E9 whose opcode is at address `at`."""
    return struct.pack("<i", target - (at + 5))


def _code(name):
    A = FN
    if name == "hc_emu":
        return bytes.fromhex("ff15") + struct.pack("<I", SLOT_TID) + bytes.fromhex("40 c3")
    if name == "hc":
        return bytes.fromhex("8b442404 50 e8") + _rel(A["hc"] + 5, A["hc_emu"]) + bytes.fromhex("59 8d0408 c20400")
    if name == "hlen":
        return bytes.fromhex("ff742404 ff15") + struct.pack("<I", SLOT_LEN) + bytes.fromhex("c20400")
    if name == "halloc":
        return (bytes.fromhex("ff742404 6a00 6a10 ff15") + struct.pack("<I", SLOT_HEAP) + bytes.fromhex("c20400"))
    if name == "leafsub":
        return bytes.fromhex("8b442404 2b442408 c20800")
    if name == "wmem":
        return bytes.fromhex("8b442404 8b4c2408 8908 894804 83c008 c20800")
    if name == "cnt_emu":
        return bytes.fromhex("ff0d") + struct.pack("<I", SCRATCH + 0x80) + bytes.fromhex("a1") + \
            struct.pack("<I", SCRATCH + 0x80) + bytes.fromhex("c3")
    if name == "loopcall":
        # L: call cnt_emu; test eax, eax; jnz L; ret
        return bytes.fromhex("e8") + _rel(A["loopcall"], A["cnt_emu"]) + bytes.fromhex("85c0 75f7 c3")
    if name == "spin":
        # [SPIN_CALLS]++; ecx = n; [SPIN_N] = n; L: [SPIN_I] = ecx; dec ecx; jnz L; return [SPIN_N]
        # (about 4n instructions)
        return (bytes.fromhex("ff05") + struct.pack("<I", SPIN_CALLS) +
                bytes.fromhex("8b4c2404 890d") + struct.pack("<I", SPIN_N) + bytes.fromhex("890d") +
                struct.pack("<I", SPIN_I) + bytes.fromhex("49 75f7 a1") + struct.pack("<I", SPIN_N) +
                bytes.fromhex("c20400"))
    if name == "spinhle":
        # [SPINH_CALLS]++; ecx = n; [SPIN_N] = n; L: [SPIN_I] = ecx; dec ecx; jnz L;
        # eax = GetCurrentThreadId() (through SLOT_TID); [SPINH_TID] = eax; return [SPINH_TID]
        return (bytes.fromhex("ff05") + struct.pack("<I", SPINH_CALLS) +
                bytes.fromhex("8b4c2404 890d") + struct.pack("<I", SPIN_N) + bytes.fromhex("890d") +
                struct.pack("<I", SPIN_I) + bytes.fromhex("49 75f7") +
                bytes.fromhex("ff15") + struct.pack("<I", SLOT_TID) + bytes.fromhex("a3") +
                struct.pack("<I", SPINH_TID) + bytes.fromhex("a1") + struct.pack("<I", SPINH_TID) +
                bytes.fromhex("c20400"))
    raise KeyError(name)


def _blob():
    return {FN[n]: _code(n) for n in FN}


class SynImage:
    """The translator's view of the synthetic module (same interface as x86c.PEImage)."""

    def __init__(self):
        self.base = SYN_D
        self.path = "<synthetic-diff>"
        self.iat = {SLOT_TID: "KERNEL32.DLL!GetCurrentThreadId"}
        self._mem = bytearray(SYN_D_SIZE)
        for va, b in _blob().items():
            off = va - SYN_D
            self._mem[off:off + len(b)] = b

    def read(self, va, n):
        off = va - SYN_D
        if 0 <= off < SYN_D_SIZE:
            return bytes(self._mem[off:off + n])
        raise ValueError("unmapped %08x" % va)


def build_synthetic(out_dir, lib):
    res = liftbuild.build(SynImage(), sorted(FN[n] for n in LIFTED_D), out_dir, lib, module="synthetic-diff",
                          write_log=True)
    assert not res["dropped"], res["dropped"]
    assert len(res["lifted"]) == len(LIFTED_D), res
    return lib


_LIB = None


def synthetic_lib():
    global _LIB
    if _LIB is None:
        _LIB = build_synthetic(os.path.join(BUILD, "c"), os.path.join(BUILD, "libdiff_synthetic.dylib"))
    return _LIB


def variant_lib(name, insert, va_name):
    """A copy of the synthetic library in which the C of one function has `insert` as its first statement. The
    generated C is edited, so the lifted code really computes something different from the emulated bytes."""
    src = os.path.join(BUILD, "variant_" + name)
    if os.path.isdir(src):
        shutil.rmtree(src)
    shutil.copytree(os.path.join(BUILD, "c"), src)
    path = os.path.join(src, "f_%08x.c" % FN[va_name])
    text = open(path).read()
    head = "void f_%08x(CPU *c)" % FN[va_name]
    i = text.index(head)
    j = text.index("{", i) + 1
    text = text[:j] + "\n    " + insert + text[j:]
    open(path, "w").write(text)
    lib = os.path.join(BUILD, "libdiff_%s.dylib" % name)
    sources = sorted(os.path.join(src, f) for f in os.listdir(src) if f.endswith(".c")) + liftbuild.runtime_sources()
    liftbuild.compile_and_link(sources, lib, write_log=True)
    return lib


def new_emu(lib, k=20, budget=None):
    """An emulator with the synthetic module mapped, its import slots set, and the diff mode on (k diffs per function;
    budget instructions per reference run, None: the default)."""
    e = mpemu.Emu(".")
    e.map(SYN_D, SYN_D_SIZE)
    for va, b in _blob().items():
        e.wr(va, b)
    e.wr32(SLOT_TID, e.stub_for("KERNEL32.DLL", "GetCurrentThreadId"))
    e.wr32(SLOT_LEN, e.stub_for("KERNEL32.DLL", "lstrlenA"))
    e.wr32(SLOT_HEAP, e.stub_for("KERNEL32.DLL", "HeapAlloc"))
    n = Native(e, lib)
    kw = {} if budget is None else {"budget": budget}
    n.enable_diff(k=k, names={FN[x]: x for x in FN}, **kw)
    return e, n


REG_IDS = dict(eax=UC_X86_REG_EAX, ecx=UC_X86_REG_ECX, edx=UC_X86_REG_EDX, ebx=UC_X86_REG_EBX,
               esp=UC_X86_REG_ESP, ebp=UC_X86_REG_EBP, esi=UC_X86_REG_ESI, edi=UC_X86_REG_EDI,
               eflags=UC_X86_REG_EFLAGS)


def _regs(e):
    uc = e.uc
    out = {k: uc.reg_read(v) for k, v in REG_IDS.items()}
    out["fpcw"] = uc.reg_read(UC_X86_REG_FPCW)
    out["fpsw"] = uc.reg_read(UC_X86_REG_FPSW)
    out["fptag"] = uc.reg_read(UC_X86_REG_FPTAG)
    for p in range(8):
        out["fp%d" % p] = uc.reg_read(UC_X86_REG_FP0 + p)
    return out


def net(log):
    """The net effect of a logged run: {addr: final value} for the bytes whose value changed. A byte written and put
    back to its value is not part of it."""
    out = {}
    for a, v in log.writes().items():
        if log.pages[a >> 12].old[a & 0xFFF] != v:
            out[a] = v
    return out


def pure(e, n, va, args, cc):
    """The emulator alone, from the current state: diff mode off for the call. Returns (eax, regs, writes); the state
    is rolled back afterwards."""
    n.diffing = False
    try:
        log = e.undo_begin()
        r = e.call(va, *args, cc=cc)
        assert not e.fatal, e.fatal
        e.undo_end(log)
        out = (r, _regs(e), net(log))
        e.undo_rollback(log)
        return out
    finally:
        n.diffing = True


def diffed(e, n, va, args, cc):
    """The same call with diff mode on. Returns (eax, regs, writes) like pure()."""
    log = e.undo_begin()
    r = e.call(va, *args, cc=cc)
    assert not e.fatal, e.fatal
    e.undo_end(log)
    out = (r, _regs(e), net(log))
    e.undo_rollback(log)
    return out


def _same_run(e, n, va, args, cc, name):
    """Diff the call, and check it against the emulator from the same state: eax, all registers and every written
    byte. Asserts a match. Leaves the state as the call left it (the same as a pure run would have)."""
    st = n.dstats[va]
    m0, mm0, dv0 = st["matches"], st["mismatches"], st["divergences"]
    r_pure, regs_pure, w_pure = pure(e, n, va, args, cc)
    log = e.undo_begin()
    r_diff = e.call(va, *args, cc=cc)
    assert not e.fatal, (name, e.fatal)
    e.undo_end(log)
    regs_diff = _regs(e)
    w_diff = net(log)
    assert st["matches"] == m0 + 1 and st["mismatches"] == mm0 and st["divergences"] == dv0, (
        name, st["mismatch_examples"], st["divergence_examples"])
    assert r_diff == r_pure, (name, hex(r_diff), hex(r_pure))
    assert regs_diff == regs_pure, (name, [k for k in regs_pure if regs_pure[k] != regs_diff[k]])
    assert w_diff == w_pure, (name, sorted(set(w_diff) ^ set(w_pure))[:4])
    return r_diff


# ---------------------------------------------------------------- tests

def test_matches_lifted_calls_with_hle_and_emulated_helper():
    """Lifted functions that call an import (hlen), an emulated helper that calls an import (hc), arithmetic with flags
    (leafsub) and memory writes (wmem): every diffed call matches the emulator in eax, registers, flags and bytes."""
    e, n = new_emu(synthetic_lib())
    e.wr(SCRATCH + 0x40, b"hello world\0")
    r = _same_run(e, n, FN["leafsub"], (10, 20), "stdcall", "leafsub")
    assert r == (10 - 20) & 0xFFFFFFFF
    assert _same_run(e, n, FN["leafsub"], (0x80000000, 1), "stdcall", "leafsub(min)") == 0x7FFFFFFF
    _same_run(e, n, FN["wmem"], (SCRATCH, 0x11223344), "stdcall", "wmem")
    _same_run(e, n, FN["hc"], (100,), "stdcall", "hc")
    assert _same_run(e, n, FN["hlen"], (SCRATCH + 0x40,), "stdcall", "hlen") == 11
    assert n.dstats[FN["hc"]]["calls"] == 1 and n.dstats[FN["hc"]]["matches"] == 1
    print("  leafsub, wmem, hc (emulated helper with an import) and hlen (import with an argument): all match")


def test_heap_allocator_replayed_once():
    """halloc: the native run gets the reference's pointer (HLE calls are replayed, not run), the allocator advanced
    exactly once, and the guest result is the one the emulator computed."""
    e, n = new_emu(synthetic_lib())
    blocks0 = len(e.heap_blocks)
    next0 = e.heap_next
    log = e.undo_begin()
    r = e.call(FN["halloc"], 40, cc="stdcall")
    assert not e.fatal, e.fatal
    e.undo_end(log)
    st = n.dstats[FN["halloc"]]
    assert st["calls"] == 1 and st["matches"] == 1, (st["mismatch_examples"], st["divergence_examples"])
    assert len(e.heap_blocks) == blocks0 + 1, "the allocator did not advance exactly once"
    assert r in e.heap_blocks and e.heap_blocks[r] >= 40, (hex(r), e.heap_blocks.get(r))
    print("  HeapAlloc replayed: pointer 0x%08x, one block more, native result matches the reference" % r)


def test_loop_of_guest_calls_matches_the_emulator():
    """loopcall calls an emulated helper until it returns 0: the lifted loop runs the same number of guest calls as the
    emulator, and the result and state match."""
    e, n = new_emu(synthetic_lib())
    e.wr32(SCRATCH + 0x80, 3)
    assert _same_run(e, n, FN["loopcall"], (), "cdecl", "loopcall") == 0
    assert n.dstats[FN["loopcall"]]["matches"] == 1
    print("  loopcall (a lifted loop of guest calls) matches the emulator")


def test_divergence_aborts_a_loop_of_guest_calls():
    """A divergence in the replay (here forced: e._hle_div is set before the native run) makes every later guest call
    from native code return at once. Without the abort, loopcall would loop forever (its guest call never runs and eax
    stays nonzero). With it, lift_invoke_checked returns 2 after the first guest call, and the state is discarded."""
    e, n = new_emu(synthetic_lib())
    e.wr32(SCRATCH + 0x80, 3)
    cpu, addr = n._take()
    try:
        n._pull(addr, False)
        e._hle_div = "forced by test_divergence_aborts_a_loop_of_guest_calls"
        status = n.lib.lift_invoke_checked(addr, n.table[FN["loopcall"]], 0)
        assert status == 2, status
        n._push(addr, False)
    finally:
        n._pool.append((cpu, addr))
        e._hle_div = None
        e.fatal = None
    assert e.rd32(SCRATCH + 0x80) == 3, "the guest helper ran although the replay had diverged"
    print("  forced divergence in a lifted loop of guest calls: lift_invoke_checked returned 2 at once")


def test_wrong_lifted_memory_is_reported_and_reverted():
    """A lifted wmem that also writes one byte it should not (C edited). The diff reports the byte and the lifted
    result; the guest state after the call is the emulator's result, not the lifted one."""
    lib = variant_lib("wmem", "wr8(c, 0x%08x, 0x5a);" % (SCRATCH + 0x20), "wmem")
    e, n = new_emu(lib)
    args = (SCRATCH, 0x11223344)
    r_pure, regs_pure, w_pure = pure(e, n, FN["wmem"], args, "stdcall")
    log = e.undo_begin()
    r = e.call(FN["wmem"], *args, cc="stdcall")
    assert not e.fatal, e.fatal
    e.undo_end(log)
    st = n.dstats[FN["wmem"]]
    assert st["mismatches"] == 1 and st["matches"] == 0 and not st["divergences"], st
    assert any("0x%08x" % (SCRATCH + 0x20) in x for x in st["mismatch_examples"]), st["mismatch_examples"]
    assert FN["wmem"] in n._retired, "a mismatching function must stop being diffed"
    assert r == r_pure and _regs(e) == regs_pure and net(log) == w_pure, "the reference result was not restored"
    assert e.rd(SCRATCH + 0x20, 1) == b"\x00", "the lifted function's byte survived"
    print("  wrong C for wmem: reported as %r; the emulator's result is in place" % st["mismatch_examples"][0])


def test_wrong_lifted_argument_is_divergence_and_reverted():
    """A lifted hlen that changes its argument before calling lstrlenA: the HLE call does not match the record, so the
    comparison is a divergence (not a memory mismatch), and the reference result is restored."""
    lib = variant_lib("hlen", "wr32(c, c->r[ESP] + 4, 0x12345678);", "hlen")
    e, n = new_emu(lib)
    e.wr(SCRATCH + 0x40, b"hello world\0")
    args = (SCRATCH + 0x40,)
    r_pure, regs_pure, w_pure = pure(e, n, FN["hlen"], args, "stdcall")
    log = e.undo_begin()
    r = e.call(FN["hlen"], *args, cc="stdcall")
    assert not e.fatal, e.fatal
    e.undo_end(log)
    st = n.dstats[FN["hlen"]]
    assert st["divergences"] == 1 and st["matches"] == 0, st
    assert "KERNEL32.DLL" not in st["divergence_examples"][0] or "lstrlenA" in st["divergence_examples"][0], st
    assert r == r_pure == 11 and _regs(e) == regs_pure and net(log) == w_pure, "reference result not restored"
    print("  wrong argument to lstrlenA: divergence %r; reference result restored" % st["divergence_examples"][0])


def test_budget_stops_diffing_and_unhooks():
    """With k = 2, the third call of a function runs emulated with no diff (its hook is gone), and it still gives the
    emulator's result."""
    e, n = new_emu(synthetic_lib(), k=2)
    va = FN["leafsub"]
    for i in range(4):
        r = e.call(va, 100 + i, 3, cc="stdcall")
        assert not e.fatal and r == 97 + i
    st = n.dstats[va]
    assert st["calls"] == 2 and st["matches"] == 2, st
    assert va in n._retired and va not in n._diff_hooks
    print("  k = 2: two diffs, then the function runs emulated (hook removed)")


def test_long_function_over_budget_is_retired_and_rolled_back():
    """spin(5000) under a budget of 1000 instructions: the reference is cut off and NOT rolled back. The emulator goes
    on with the same run, so the function runs once (SPIN_CALLS = 1) and the guest has exactly the emulator's result:
    eax, registers, flags and every byte the loop stored. The function is retired as too long (no comparison). A
    later call runs emulated (no diff), and the report counts the retirement."""
    e, n = new_emu(synthetic_lib(), k=20, budget=1000)
    va = FN["spin"]
    r_pure, regs_pure, w_pure = pure(e, n, va, (5000,), "stdcall")
    log = e.undo_begin()
    r = e.call(va, 5000, cc="stdcall")
    assert not e.fatal, e.fatal
    e.undo_end(log)
    st = n.dstats[va]
    assert st["too_long"] == 1 and st["calls"] == 1, st
    assert st["matches"] == 0 and st["mismatches"] == 0 and st["divergences"] == 0 and not st["bad"], st
    assert va in n._retired and va not in n._diff_hooks, "a function over budget must stop being diffed"
    assert r == r_pure == 5000, (r, r_pure)
    assert _regs(e) == regs_pure, [k for k in regs_pure if regs_pure[k] != _regs(e)[k]]
    assert net(log) == w_pure and w_pure, "guest memory differs from the emulator run"
    assert e.rd32(SPIN_N) == 5000 and e.rd32(SPIN_I) == 1
    assert e.rd32(SPIN_CALLS) == 1, "the function ran more than once"
    assert e._hle_mode is None and e._hle_rec is None and not e._diff_active, "diff state not cleaned up"
    # later calls: emulated, not diffed
    r2 = e.call(va, 7, cc="stdcall")
    assert not e.fatal and r2 == 7 and e.rd32(SPIN_N) == 7 and st["calls"] == 1 and e.rd32(SPIN_CALLS) == 2
    rep = n.report()
    assert rep["totals"]["functions_too_long"] == 1 and rep["totals"]["functions_retired"] >= 1, rep["totals"]
    assert rep["functions"]["0x%08x" % va]["too_long"] == 1 and rep["functions"]["0x%08x" % va]["retired"]
    assert any("spin" in x and "retired too long" in x for x in n.summary_lines()), n.summary_lines()
    print("  spin(5000), budget 1000: retired too long, ran once (eax, registers, %d bytes equal the emulator)" % len(
        w_pure))


def test_over_budget_then_hle_call_runs_normally():
    """spinhle(5000) under a budget of 1000: the budget runs out in the loop, and the GetCurrentThreadId call after the
    loop is made by the emulator from the same run (not recorded, not replayed). The function runs once, and its
    result and every byte equal a pure emulator run from the same state."""
    e, n = new_emu(synthetic_lib(), k=20, budget=1000)
    va = FN["spinhle"]
    r_pure, regs_pure, w_pure = pure(e, n, va, (5000,), "stdcall")
    assert r_pure and w_pure, (r_pure, w_pure)
    log = e.undo_begin()
    r = e.call(va, 5000, cc="stdcall")
    assert not e.fatal, e.fatal
    e.undo_end(log)
    st = n.dstats[va]
    assert st["too_long"] == 1 and st["calls"] == 1 and st["matches"] == 0 and not st["bad"], st
    assert va in n._retired and va not in n._diff_hooks
    assert e.rd32(SPINH_CALLS) == 1, "the function ran more than once"
    assert r == r_pure, (hex(r), hex(r_pure))
    assert _regs(e) == regs_pure, [k for k in regs_pure if regs_pure[k] != _regs(e)[k]]
    assert net(log) == w_pure, sorted(set(net(log)) ^ set(w_pure))[:4]
    assert e._hle_mode is None and e._hle_rec is None and not e._diff_active
    print("  spinhle(5000), budget 1000: HLE call after the budget point ran normally; %d bytes equal the emulator"
          % len(w_pure))


def test_short_function_under_budget_still_diffs():
    """Under the same budget of 1000, short calls still diff and match: leafsub, and spin(20) (about 80 instructions,
    with its stores compared byte for byte). Budget 0 (no budget) diffs spin(5000) to a match as well."""
    e, n = new_emu(synthetic_lib(), k=20, budget=1000)
    _same_run(e, n, FN["leafsub"], (10, 20), "stdcall", "leafsub")
    assert _same_run(e, n, FN["spin"], (20,), "stdcall", "spin(20)") == 20
    st = n.dstats[FN["spin"]]
    assert st["too_long"] == 0 and FN["spin"] not in n._retired, st
    e2, n2 = new_emu(synthetic_lib(), k=20, budget=0)
    assert _same_run(e2, n2, FN["spin"], (5000,), "stdcall", "spin(5000) unlimited") == 5000
    assert n2.dstats[FN["spin"]]["too_long"] == 0
    try:
        n2.enable_diff(budget=-1)
        raise AssertionError("a negative budget was accepted")
    except NativeError:
        pass
    print("  spin(20) under budget 1000: diffed and matched; budget 0: spin(5000) diffed and matched")


def test_write_log_records_old_bytes():
    """The C write log: a write made by lifted code is recorded with the bytes it replaced; export and rollback
    restore them."""
    e, n = new_emu(synthetic_lib())
    lib = n.lib
    old = bytes(range(16))
    e.wr(SCRATCH + 0x80, old)
    lib.lift_wlog_begin()
    cpu = CPU()
    cpu.mem = e.mem_base
    lib.lift_note_write(ctypes.byref(cpu), SCRATCH + 0x80, 16)
    e.wr(SCRATCH + 0x80, b"\xee" * 16)
    n_bytes = lib.lift_wlog_export(None, 0)
    buf = ctypes.create_string_buffer(n_bytes)
    assert lib.lift_wlog_export(buf, n_bytes) == n_bytes
    addr, ln = struct.unpack_from("<II", buf.raw, 0)
    assert (addr, ln) == (SCRATCH + 0x80, 16) and buf.raw[8:24] == old, (hex(addr), ln, buf.raw[8:24])
    lib.lift_wlog_rollback(ctypes.c_void_p(e.mem_base))
    assert e.rd(SCRATCH + 0x80, 16) == old
    lib.lift_wlog_end()


def _rlmfc_lib(img):
    """The write-log library of rlmfc (every exported code function that translates). Rebuilt every run so it follows
    runtime changes; build() reuses the object files whose sources did not change."""
    lib = os.path.join(BUILD, "librlmfc_wlog.dylib")
    entries = sorted({va for va, _ in img.exports})
    res = liftbuild.build(img, entries, os.path.join(BUILD, "rlmfc"), lib, module="rlmfc.dll", write_log=True)
    print("  rlmfc: %d entries requested, %d lifted, %d dropped" % (
        len(entries), len(res["lifted"]), len(res["dropped"])))
    return lib


def _getter_picks(img, want=40):
    """Exported small getters that translate fully on their own (as test_bridge's real-DLL test picks them). They read
    their object, so they run from random object memory without faulting."""
    picks = []
    for va, name in sorted(img.exports, key=lambda t: t[1]):
        if not (name.startswith("?get") or name.startswith("?is") or name.startswith("?Get")):
            continue
        res = x86c.lift_function(img, va, frozenset([va]))
        if not res.ok or len(res.c) > 3000:
            continue
        picks.append((len(res.c), va, name))
    picks.sort()
    return [(va, name) for _, va, name in picks[:want]]


def test_real_dll_diff():
    """rlmfc.dll under diff mode. Script: the smoke sequence of emu/smoke_timer.py (R_RemedyInit, then an R_Timer built
    and sampled, getAge, getDelta), then the small getters from random object memory. Matches and mismatches are
    printed as data; the test fails only on a crash."""
    rlmfc = os.path.join(GAME, "rlmfc.dll")
    if not os.path.exists(rlmfc):
        print("  skipped: game folder not found (%s)" % GAME)
        return
    img = x86c.PEImage(rlmfc)
    lib = _rlmfc_lib(img)
    e = mpemu.boot(GAME, verbose=False)
    assert mpemu.run_dll_mains(e, verbose=False), "DllMain failed"
    rl = e.modules["rlmfc.dll"]
    names = {va: name for name, va in rl.exports.items()}
    inventory = os.path.join(ROOT, "lift-out", "rlmfc_functions.json")
    only = function_entries(inventory) if os.path.exists(inventory) else None
    n = Native(e, lib)
    n.enable_diff(k=20, names=names, only=only)
    t0 = time.time()
    calls = 0

    def run(va, label, **kw):
        nonlocal calls
        r = e.call(va, timeout=600, **kw)
        calls += 1
        if e.fatal:
            print("  %s: stopped: %s" % (label, e.fatal))
            e.fatal = None
        return r
    init = e.alloc(64)
    run(rl.exports["??0R_RemedyInit@@QAE@XZ"], "R_RemedyInit", ecx=init)
    obj = e.alloc(64)
    run(rl.exports["??0R_Timer@@QAE@XZ"], "R_Timer ctor", ecx=obj)
    run(rl.exports["?sample@R_Timer@@QAEMXZ"], "R_Timer::sample", ecx=obj)
    run(rl.exports["?sample@R_Timer@@QAEMXZ"], "R_Timer::sample", ecx=obj)
    run(rl.exports["?getAge@R_Timer@@QBEMXZ"], "R_Timer::getAge", ecx=obj)
    run(rl.exports["?getDelta@R_Timer@@QBEMXZ"], "R_Timer::getDelta", ecx=obj)
    rng = random.Random(7)
    for va, name in _getter_picks(img):
        dobj = e.alloc(256)
        e.wr(dobj, bytes(rng.getrandbits(8) for _ in range(256)))
        run(rl.base + (va - img.base), name[:50], ecx=dobj)
    rep = n.report()
    print("  %d rlmfc calls in %.1fs" % (calls, time.time() - t0))
    for line in n.summary_lines():
        print("  " + line)
    for key, st in rep["functions"].items():
        if st["mismatches"] or st["divergences"]:
            detail = (st["mismatch_examples"] or st["divergence_examples"])[0]
            print("  %-48s %s  mismatches %d divergences %d  first: %s" % (
                st["name"][:48], key, st["mismatches"], st["divergences"], detail[:150]))


def test_deferred_module_diff_hooks():
    """Diff mode with a deferred module: enable_diff(only=set()) hooks nothing; the module's load (LiftLoader's hook,
    as load_library calls it) hooks its entries, limited to diff_only, with the names from its exports. diff_add
    refuses before enable_diff and for a va that is not a lifted entry."""
    lib = synthetic_lib()
    e = mpemu.Emu(".")
    e.map(SYN_D, SYN_D_SIZE)
    n = Native(e, lib)
    try:
        n.diff_add([FN["hc"]])
        raise AssertionError("diff_add before enable_diff was accepted")
    except NativeError:
        pass
    n.enable_diff(k=5, only=set())
    assert n._diff_hooks == {}, n._diff_hooks
    only = {FN["hc"], FN["hlen"]}
    loader = LiftLoader(n, "diff", diff_only=only)
    inv = os.path.join(BUILD, "inv_synthetic_diff.json")
    with open(inv, "w") as fh:
        json.dump({"module": "synthetic-diff.dll", "base": "0x%x" % SYN_D,
                   "functions": [{"entry": "0x%08x" % FN[x], "name": x} for x in LIFTED_D]}, fh)
    loader.add(inv)                                   # deferred
    assert n._diff_hooks == {} and loader.count == 0
    pe = types.SimpleNamespace(OPTIONAL_HEADER=types.SimpleNamespace(SizeOfImage=SYN_D_SIZE, AddressOfEntryPoint=0))
    mod = mpemu.Module("synthetic-diff.dll", "synthetic-diff.dll", SYN_D, pe, b"")
    mod.exports = {x: FN[x] for x in LIFTED_D}
    loader.on_loaded(mod)
    assert set(n._diff_hooks) == only, sorted(hex(v) for v in n._diff_hooks)
    assert loader.count == 2 and not loader.deferred
    assert n.dstats[FN["hc"]]["name"] == "hc" and n.dstats[FN["hlen"]]["name"] == "hlen"
    try:
        n.diff_add([0x1234])
        raise AssertionError("diff_add accepted a va that is not lifted")
    except NativeError:
        pass
    n.diff_add([FN["hc"]])                            # already hooked: skipped
    assert len(n._diff_hooks) == 2


TESTS = [test_matches_lifted_calls_with_hle_and_emulated_helper, test_heap_allocator_replayed_once,
         test_loop_of_guest_calls_matches_the_emulator, test_divergence_aborts_a_loop_of_guest_calls,
         test_wrong_lifted_memory_is_reported_and_reverted, test_wrong_lifted_argument_is_divergence_and_reverted,
         test_budget_stops_diffing_and_unhooks, test_long_function_over_budget_is_retired_and_rolled_back,
         test_over_budget_then_hle_call_runs_normally,
         test_short_function_under_budget_still_diffs, test_write_log_records_old_bytes,
         test_deferred_module_diff_hooks, test_real_dll_diff]


if __name__ == "__main__":
    os.makedirs(BUILD, exist_ok=True)
    failed = 0
    for fn in TESTS:
        t0 = time.time()
        try:
            fn()
            print("PASS %s (%.1fs)" % (fn.__name__, time.time() - t0))
        except Exception as ex:          # report and carry on
            failed += 1
            import traceback
            traceback.print_exc()
            print("FAIL %s: %s" % (fn.__name__, ex))
    print("%d failed" % failed if failed else "all diff tests passed")
    sys.exit(1 if failed else 0)
