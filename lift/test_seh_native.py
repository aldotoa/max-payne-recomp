"""E3: RaiseException and RtlUnwind in C (lift/runtime/seh.c) with every guest function lifted (x86c.DEAD_FRAMES).

emu/test_seh.py's scenarios, with the raise and the unwind reached the way the game reaches them (`call [slot]`
through an IAT-style slot holding the stub), so they are direct HLE calls served by seh.c, and the handlers are lifted:
  - continue execution: the handler returns ExceptionContinueExecution, RaiseException returns to its caller;
  - two-pass unwind: the inner handler searches, the outer one calls RtlUnwind to its own frame, then switches ESP
    to that frame and returns from it (the raising function's frame and the dispatcher are discarded natively);
  - catch: an MSVC-shaped transfer, the outer handler unwinds and jumps through a register to a continuation inside
    the raising function (an aux entry), which returns from there;
  - unhandled: no handler takes it; C hands it to Python, which walks the chain again and reports it (the handler
    runs once in C and once in Python);
  - the depth counter and the guest stack: after each scenario fs:[0] is back at the end of the chain.

Run: .venv/bin/python lift/test_seh_native.py   (or pytest)
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "emu"))

import build as liftbuild                                   # noqa: E402
import mpemu                                                # noqa: E402
import x86c                                                 # noqa: E402
from native import Native                                   # noqa: E402
from test_dead_frames import Asm                            # noqa: E402

SH = 0x00520000
SH_SIZE = 0x10000
DATA = SH + 0x8000
SLOT_RAISE = DATA + 0x00
SLOT_UNWIND = DATA + 0x04
MARK = DATA + 0x10              # handler call counter
ARR = DATA + 0x20               # ExceptionFlags seen by each handler call
CONT_MARK = DATA + 0x60         # the catch continuation ran
BUILD = os.path.join(ROOT, "build-lift", "test_seh_native")


def install_frame(a, handler):
    a.imm_label("68", handler)                      # push handler
    a.b("64ff3500000000")                           # push dword ptr fs:[0]
    a.b("64892500000000")                           # mov fs:[0], esp


def raise_call(a, code=0xE0000001):
    a.b("6a00 6a00 6a00 68"); a.u32(code)           # RaiseException(code, 0, 0, 0)
    a.b("ff15"); a.u32(SLOT_RAISE)


def record_handler(a, label, ret_value):
    """cdecl: ARR[MARK++] = record->ExceptionFlags; return ret_value."""
    a.label(label)
    a.b("8b442404 8b4004 8b0d"); a.u32(MARK)
    a.b("89048d"); a.u32(ARR)
    a.b("41 890d"); a.u32(MARK)
    a.b("b8"); a.u32(ret_value)
    a.b("c3")


def pad(a):
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)


def assemble():
    a = Asm(SH)
    # continue execution
    # (through `call eax`: a `call [RaiseException slot]` is a no-return import to the lifter, which decodes nothing
    # after it, so a handler that continues execution needs a call the lifter does not know)
    a.label("ce"); install_frame(a, "ce_h")
    a.b("6a00 6a00 6a00 68"); a.u32(0xE0000001); a.b("a1"); a.u32(SLOT_RAISE); a.b("ffd0")
    a.b("b834120000 648f0500000000 83c404 c3"); pad(a)
    record_handler(a, "ce_h", 0); pad(a)
    # two-pass unwind
    a.label("tp"); install_frame(a, "tp_outer"); install_frame(a, "tp_inner"); raise_call(a)
    a.b("b8ad0b0000 c3"); pad(a)                     # must not run
    record_handler(a, "tp_inner", 1); pad(a)
    a.label("tp_outer")
    a.b("8b5c2408 8b4c2404 6a55 51")                 # ebx = frame, ecx = record; push 0x55; push ecx
    a.imm_label("68", "tp_cont"); a.b("53")          # push TargetIp; push TargetFrame
    a.b("ff15"); a.u32(SLOT_UNWIND)
    a.label("tp_cont")
    a.b("89dc 648f0500000000 83c404 c3"); pad(a)     # esp = frame; pop fs:[0]; add esp, 4; ret
    # catch: the outer handler unwinds to its frame, restores esp/ebp the frame recorded, and jumps to cc_cont inside
    # cc (MSVC's _JumpToContinuation shape)
    a.label("cc")
    a.b("55 8bec"); install_frame(a, "cc_h")         # push ebp; mov ebp, esp; frame at ebp - 8
    raise_call(a)
    a.b("b8ad0b0000 8be5 5d c3")                     # must not run
    a.label("cc_cont")                               # aux entry: only the transfer reaches it
    a.b("c705"); a.u32(CONT_MARK); a.u32(1)
    a.b("648b0d00000000 8b09 64890d00000000")        # fs:[0] = [fs:[0]] (pop the frame left by the unwind)
    a.b("b866000000 8be5 5d c3"); pad(a)             # return 0x66
    a.label("cc_h")
    a.b("8b5c2408 8b4c2404 6a00 51")                 # ebx = frame; push 0; push record
    a.imm_label("68", "cc_back"); a.b("53")
    a.b("ff15"); a.u32(SLOT_UNWIND)
    a.label("cc_back")
    a.b("8d6b08 8d63f8")                             # ebp = frame + 8 (cc's ebp); esp = frame - 8 (cc's esp)
    a.imm_label("b8", "cc_cont"); a.b("ffe0"); pad(a)  # jmp eax
    # unhandled
    a.label("uh"); install_frame(a, "uh_h"); raise_call(a, 0xE0001234)
    a.b("c3"); pad(a)
    record_handler(a, "uh_h", 1); pad(a)
    return a.finish(), a.labels


CODE, L = assemble()
LIFTED = ["ce", "ce_h", "tp", "tp_inner", "tp_outer", "cc", "cc_h", "uh", "uh_h"]
AUX = ["cc_cont"]


class ShImage:
    def __init__(self):
        self.base = SH
        self.path = "<seh>"
        self.exports = []
        self.delay_stubs = {}
        self.iat = {SLOT_RAISE: "KERNEL32.DLL!RaiseException", SLOT_UNWIND: "KERNEL32.DLL!RtlUnwind"}

    def read(self, va, n):
        if SH <= va and va + n <= SH + len(CODE):
            return CODE[va - SH:va - SH + n]
        return bytes(n) if DATA <= va < SH + SH_SIZE else None

    def is_code(self, va):
        return SH <= va < SH + len(CODE)


_LIB = None


def library():
    global _LIB
    if _LIB is None:
        saved = x86c.DEAD_FRAMES
        x86c.DEAD_FRAMES = True
        try:
            res = liftbuild.build(ShImage(), sorted(L[n] for n in LIFTED), os.path.join(BUILD, "c"),
                                  os.path.join(BUILD, "libseh.dylib"), module="seh", aux=[L[n] for n in AUX])
        finally:
            x86c.DEAD_FRAMES = saved
        assert not res["dropped"], res["dropped"]
        _LIB = res["lib"]
    return _LIB


def fresh(native=True):
    e = mpemu.Emu(".")
    e.map(SH, SH_SIZE)
    e.wr(SH, CODE)
    e.wr32(SLOT_RAISE, e.stub_for("KERNEL32.DLL", "RaiseException"))
    e.wr32(SLOT_UNWIND, e.stub_for("KERNEL32.DLL", "RtlUnwind"))
    n = None
    if native:
        n = Native(e, library())
        n.install_fast([L[x] for x in LIFTED])
        idx = [(e.stub_for("KERNEL32.DLL", k) - mpemu.STUB_BASE) // mpemu.STUB_STRIDE
               for k in ("RaiseException", "RtlUnwind")]
        n.lib.lift_seh_bind(idx[0], idx[1], e.stub_for("NTDLL.DLL", "ExceptionNestedHandler"), mpemu.TEB,
                            mpemu.STACK_TOP - mpemu.STACK_SIZE, mpemu.STACK_TOP)
    return e, n


def run(entry, native=True):
    e, n = fresh(native)
    e.wr32(MARK, 0)
    sp = e.uc.reg_read(mpemu.UC_X86_REG_ESP)
    s0 = n.seh_stats() if n else None
    eax = e.call(L[entry])
    cnt = e.rd32(MARK)
    flags = [e.rd32(ARR + 4 * i) for i in range(cnt)]
    st = None
    if n:
        s1 = n.seh_stats()
        st = {k: s1[k] - s0[k] for k in ("raises", "unwinds", "handled")}
        st["guest_calls"] = n.fast_stats()["guest_calls"]
    return dict(eax=eax, flags=flags, fatal=e.fatal, teb=e.rd32(mpemu.TEB), sp=e.uc.reg_read(mpemu.UC_X86_REG_ESP) - sp,
                cont=e.rd32(CONT_MARK)), st


def test_continue_execution():
    ref, _ = run("ce", native=False)
    got, st = run("ce")
    assert got == ref and got["eax"] == 0x1234 and got["flags"] == [0] and got["teb"] == 0xFFFFFFFF, (got, ref)
    assert st == {"raises": 1, "unwinds": 0, "handled": 1, "guest_calls": 0}, st


def test_two_pass_unwind():
    ref, _ = run("tp", native=False)
    got, st = run("tp")
    assert got == ref and got["eax"] == 0x55 and got["flags"] == [0, mpemu.EH_UNWINDING], (got, ref)
    assert got["teb"] == 0xFFFFFFFF and not got["fatal"], got
    assert st == {"raises": 1, "unwinds": 1, "handled": 1, "guest_calls": 0}, st


def test_catch_transfer():
    ref, _ = run("cc", native=False)
    got, st = run("cc")
    assert got == ref and got["eax"] == 0x66 and got["cont"] == 1 and got["teb"] == 0xFFFFFFFF, (got, ref)
    assert st == {"raises": 1, "unwinds": 1, "handled": 1, "guest_calls": 0}, st


def test_unhandled_goes_to_python():
    # Python walks the chain again and reports it; reached from native code, the stop surfaces as a NativeError from
    # the outermost call (the fast path's fatal-stop rule)
    from native import NativeError
    e, n = fresh()
    e.wr32(MARK, 0)
    s0 = n.seh_stats()
    try:
        e.call(L["uh"])
        raise AssertionError("an unhandled exception was not reported")
    except NativeError as ex:
        assert "unhandled exception 0xe0001234" in str(ex), ex
    assert [e.rd32(ARR + 4 * i) for i in range(e.rd32(MARK))] == [0, 0]   # once in C, once more in Python's walk
    s1 = n.seh_stats()
    assert s1["raises"] - s0["raises"] == 1 and s1["handled"] == s0["handled"], (s0, s1)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok ", name)
