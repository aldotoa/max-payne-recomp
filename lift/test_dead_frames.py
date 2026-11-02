"""E3 spike: native non-local transfers (x86c.DEAD_FRAMES, docs/m6-emu-removal.md).

A synthetic module where every function is lifted, so a transfer never meets the emulator:
  - nx_*: a catch-like transfer. nx_jump restores ESP/EBP saved by nx_top and jumps through a register to nx_cont, a
    label inside nx_top that only the transfer reaches (an aux entry). nx_mid's frame is discarded: its code after
    the call must not run, and nx_outer gets nx_cont's result.
  - sj_*: setjmp/longjmp three times over. The longjmp target is the return point of the setjmp call (an aux entry
    inside sj_top that normal flow also reaches); each longjmp discards sj_mid and sj_deep and resumes there with the
    longjmp value, until a counter stops the loop. The continuation nests on the host stack each time.
Each runs once fully emulated (the reference) and once natively from the entry, and must agree on the result, the
markers, the guest stack pointer and the stores.

Run: .venv/bin/python lift/test_dead_frames.py   (or pytest)
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
from unicorn.x86_const import UC_X86_REG_ESP                # noqa: E402

NX = 0x00510000
NX_SIZE = 0x10000
DATA = NX + 0x8000
JB = DATA + 0x00                 # nx: saved esp, ebp
JB2 = DATA + 0x10                # sj: ebp, esp, eip (the setjmp buffer)
MARK_MID = DATA + 0x20           # nx_mid ran on after its call (must stay 0)
MARK_TOP = DATA + 0x24           # nx_cont ran
MARK_SJ = DATA + 0x28            # sj_mid ran on after its call (must stay 0)
CNT = DATA + 0x2C                # sj: longjmp count
SUM = DATA + 0x30                # sj: sum of the values setjmp returned
BUILD = os.path.join(ROOT, "build-lift", "test_dead_frames")


class Asm:
    def __init__(self, base):
        self.base, self.buf, self.labels, self.fix = base, bytearray(), {}, []

    def here(self):
        return self.base + len(self.buf)

    def label(self, n):
        self.labels[n] = self.here()

    def b(self, h):
        self.buf += bytes.fromhex(h)

    def u32(self, v):
        self.buf += struct.pack("<I", v & 0xFFFFFFFF)

    def rel(self, op, n):                       # e8/e9 rel32 to a label
        self.b(op)
        self.fix.append((len(self.buf), n, "rel"))
        self.u32(0)

    def imm_label(self, op, n):                 # op imm32 = a label's address
        self.b(op)
        self.fix.append((len(self.buf), n, "abs"))
        self.u32(0)

    def finish(self):
        for off, n, kind in self.fix:
            v = self.labels[n] - (self.base + off + 4) if kind == "rel" else self.labels[n]
            struct.pack_into("<I", self.buf, off, v & 0xFFFFFFFF)
        return bytes(self.buf)


def assemble():
    a = Asm(NX)
    # nx_outer: return nx_top() + 1
    a.label("nx_outer"); a.rel("e8", "nx_top"); a.b("40 c3")
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)
    # nx_top: push ebp; mov ebp, esp; [JB] = esp; [JB+4] = ebp; nx_mid(); return 1 (not reached)
    a.label("nx_top"); a.b("55 8bec 8925"); a.u32(JB); a.b("892d"); a.u32(JB + 4)
    a.rel("e8", "nx_mid"); a.b("b801000000 5d c3")
    # nx_cont (inside nx_top, after its ret: only the transfer reaches it): [MARK_TOP] = 1; return 0x55
    a.label("nx_cont"); a.b("c705"); a.u32(MARK_TOP); a.u32(1); a.b("b855000000 5d c3")
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)
    # nx_mid: nx_jump(); [MARK_MID] = 1; return 0x99
    a.label("nx_mid"); a.rel("e8", "nx_jump"); a.b("c705"); a.u32(MARK_MID); a.u32(1); a.b("b899000000 c3")
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)
    # nx_jump: esp = [JB]; ebp = [JB+4]; ecx = nx_cont; jmp ecx
    a.label("nx_jump"); a.b("8b25"); a.u32(JB); a.b("8b2d"); a.u32(JB + 4); a.imm_label("b9", "nx_cont"); a.b("ffe1")
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)

    # sj_set(buf), cdecl: buf = {ebp, esp after the return, return address}; return 0
    a.label("sj_set"); a.b("8b542404 892a 8b0424 894208 8d442404 894204 33c0 c3")
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)
    # sj_long(buf, val), cdecl: eax = val; ebp = buf[0]; esp = buf[1]; jmp buf[2]
    a.label("sj_long"); a.b("8b542404 8b442408 8b2a 8b6204 ff6208")
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)
    # sj_top: [CNT] = [SUM] = 0; r = sj_set(JB2); (sj_ret:) [SUM] += r; if (++[CNT] < 4) sj_mid(); return [CNT]
    a.label("sj_top"); a.b("55 8bec c705"); a.u32(CNT); a.u32(0); a.b("c705"); a.u32(SUM); a.u32(0)
    a.b("68"); a.u32(JB2); a.rel("e8", "sj_set")
    # (sj_ret pops setjmp's argument, then makes an ordinary call: the continuation's ESP is then above the ESP it
    # was entered with, which must not count as a discarded frame)
    a.label("sj_ret"); a.b("83c404 0105"); a.u32(SUM); a.rel("e8", "sj_leaf")
    a.b("ff05"); a.u32(CNT); a.b("833d"); a.u32(CNT); a.b("04")
    a.b("7305")                                  # jae done (over the 5-byte call)
    a.rel("e8", "sj_mid")
    a.b("a1"); a.u32(CNT); a.b("5d c3")          # done: return [CNT]
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)
    # sj_mid: sj_deep(); [MARK_SJ] = 1; ret
    a.label("sj_mid"); a.rel("e8", "sj_deep"); a.b("c705"); a.u32(MARK_SJ); a.u32(1); a.b("c3")
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)
    # sj_deep: sj_long(JB2, 7)
    a.label("sj_deep"); a.b("6a07 68"); a.u32(JB2); a.rel("e8", "sj_long"); a.b("83c408 c3")
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)
    # sj_leaf: ret (keeps eax)
    a.label("sj_leaf"); a.b("c3")
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)
    # sj_outer: return sj_top()
    a.label("sj_outer"); a.rel("e8", "sj_top"); a.b("c3")
    a.buf += b"\xcc" * (0x40 - len(a.buf) % 0x40)
    code = a.finish()
    return code, a.labels


CODE, L = assemble()
LIFTED = ["nx_outer", "nx_top", "nx_mid", "nx_jump", "sj_set", "sj_long", "sj_top", "sj_mid", "sj_deep", "sj_leaf",
          "sj_outer"]
AUX = ["nx_cont", "sj_ret"]


class NxImage:
    """The translator's view of the synthetic module (x86c.PEImage's interface)."""

    def __init__(self):
        self.base = NX
        self.path = "<nx>"
        self.iat = {}
        self.exports = []
        self.delay_stubs = {}

    def read(self, va, n):
        if NX <= va and va + n <= NX + len(CODE):
            return CODE[va - NX:va - NX + n]
        return bytes(n) if DATA <= va < NX + NX_SIZE else None

    def is_code(self, va):
        return NX <= va < NX + len(CODE)


_LIB = None


def library():
    global _LIB
    if _LIB is None:
        saved = x86c.DEAD_FRAMES
        x86c.DEAD_FRAMES = True
        try:
            res = liftbuild.build(NxImage(), sorted(L[n] for n in LIFTED), os.path.join(BUILD, "c"),
                                  os.path.join(BUILD, "libnx.dylib"), module="nx", aux=[L[n] for n in AUX])
        finally:
            x86c.DEAD_FRAMES = saved
        assert not res["dropped"], res["dropped"]
        assert len(res["lifted"]) == len(LIFTED) + len(AUX), res["lifted"]
        _LIB = res["lib"]
    return _LIB


def fresh():
    e = mpemu.Emu(".")
    e.map(NX, NX_SIZE)
    e.wr(NX, CODE)
    return e


def run(entry, native):
    e = fresh()
    n = None
    if native:
        n = Native(e, library())
        n.install_fast([L[x] for x in LIFTED])     # aux entries are in the table, never patched
    got = e.call(L[entry])
    marks = {k: e.rd32(v) for k, v in (("mid", MARK_MID), ("top", MARK_TOP), ("sj", MARK_SJ), ("cnt", CNT),
                                       ("sum", SUM))}
    out = (got, marks, e.uc.reg_read(UC_X86_REG_ESP), e.fatal)
    stats = n.fast_stats() if n else None
    return out, stats


def test_catch_like_transfer():
    ref, _ = run("nx_outer", native=False)
    assert ref[0] == 0x56 and ref[1]["mid"] == 0 and ref[1]["top"] == 1 and not ref[3], ref
    got, st = run("nx_outer", native=True)
    assert got == ref, (got, ref)
    # one fast-path entry; the transfer and the discarded frames stayed native (no guest call)
    assert st["guest_calls"] == 0 and st["calls"] == 1, st


def test_setjmp_longjmp_loop():
    ref, _ = run("sj_outer", native=False)
    assert ref[0] == 4 and ref[1]["cnt"] == 4 and ref[1]["sum"] == 21 and ref[1]["sj"] == 0 and not ref[3], ref
    got, st = run("sj_outer", native=True)
    assert got == ref, (got, ref)
    assert st["guest_calls"] == 0 and st["calls"] == 1, st


def test_check_is_emitted_only_with_dead_frames():
    img = NxImage()
    known = frozenset(L[n] for n in LIFTED)
    on = x86c.lift_function(img, L["nx_mid"], known, dead_frames=True)
    off = x86c.lift_function(img, L["nx_mid"], known, dead_frames=False)
    assert "xesp0" in on.c and "xesp0" not in off.c
    assert x86c.lift_function(img, L["nx_jump"], known, dead_frames=True).ok
    assert not x86c.lift_function(img, L["nx_jump"], known, dead_frames=False).ok   # jmp ecx needs DEAD_FRAMES


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok ", name)
