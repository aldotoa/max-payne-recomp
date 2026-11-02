"""Unit tests for the emulator core: run budgets (timeout / resume) and the fast host-call path.
Hand-assembled guest code; no game files needed.

Run:  .venv/bin/python emu/test_emu.py
"""
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import mpemu
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP


def test_timeout_and_resume():
    e = mpemu.Emu(".")
    loop = e.alloc(16)
    e.wr(loop, b"\xeb\xfe")                               # jmp $
    t = time.time()
    e.call(loop, timeout=0.2)
    assert e.budget_exhausted and not e.fatal, e.fatal
    assert e.uc.reg_read(UC_X86_REG_EIP) == loop
    assert 0.15 < time.time() - t < 2.0
    e.resume(timeout=0.1)
    assert e.budget_exhausted
    # a call that finishes before its timeout returns normally, and the timer does not stop a later call
    ret = e.alloc(16)
    e.wr(ret, b"\xb8\x2a\x00\x00\x00\xc3")                # mov eax, 42; ret
    assert e.call(ret, timeout=0.05) == 42 and not e.budget_exhausted
    time.sleep(0.1)
    assert e.call(ret) == 42 and not e.budget_exhausted
    print("ok  timeout stops a runaway call; resume() continues; finished calls are unaffected")


def test_host_call_args():
    """An HLE stdcall with several arguments: arguments, return value and stack cleanup through FastUc."""
    seen = []

    @mpemu.hle("TEST.DLL", "Sum4", 4)
    def _sum4(e, a, b, c, d):
        seen.append((a, b, c, d))
        return a + b + c + d

    e = mpemu.Emu(".")
    code = e.alloc(64)
    stub = e.stub_for("TEST.DLL", "Sum4")
    # push 4; push 3; push 2; push 0xFFFFFFFF; mov eax, stub; call eax; ret   (stdcall: callee pops the args)
    body = b"\x6a\x04\x6a\x03\x6a\x02\x68\xff\xff\xff\xff\xb8" + struct.pack("<I", stub) + b"\xff\xd0\xc3"
    e.wr(code, body)
    r = e.call(code)
    assert seen == [(0xFFFFFFFF, 2, 3, 4)], seen
    assert r == (0xFFFFFFFF + 9) & 0xFFFFFFFF, hex(r)
    assert e.fast.read(code, 2) == body[:2] and e.rd(code, 300)[:2] == body[:2]
    e.fast.set(UC_X86_REG_EAX, -1)
    assert e.fast.get(UC_X86_REG_EAX) == 0xFFFFFFFF
    print("ok  HLE stdcall arguments, return value and stack cleanup")


def test_unmapped_access():
    """Unmapped reads, writes and fetches stop the guest with a diagnosis."""
    e = mpemu.Emu(".")
    for code, kind in ((b"\xa1\x00\x00\x00\x00\xc3", "read"),           # mov eax, [0]
                       (b"\xa3\x10\x00\x00\x00\xc3", "write"),          # mov [0x10], eax
                       (b"\xb8\x00\x00\x00\x00\xff\xe0", "fetch")):    # mov eax, 0; jmp eax
        p = e.alloc(16)
        e.wr(p, code)
        e.call(p)
        assert e.fatal and "unmapped access" in e.fatal, (kind, e.fatal)
    # a store followed by a load sees the stored value
    p, d = e.alloc(32), e.alloc(16)
    e.wr(p, b"\xb8\x78\x56\x34\x12\xa3" + struct.pack("<I", d) + b"\x31\xc0\xa1" + struct.pack("<I", d) + b"\xc3")
    assert e.call(p) == 0x12345678 and e.rd32(d) == 0x12345678
    print("ok  unmapped read/write/fetch are reported; stores and loads agree")


def test_self_modifying_code():
    """Guest stores into code that has run must still be seen (the patched Unicorn, tools/build_unicorn.sh,
    lets stores to pages without translated code skip the slow path; stores to code pages must not)."""
    e = mpemu.Emu(".")
    PAGE = 0x1000

    def store(addr, val):                                   # a guest routine: mov dword [addr], val; ret
        w = e.alloc(16)
        e.wr(w, b"\xc7\x05" + struct.pack("<II", addr, val & 0xFFFFFFFF) + b"\xc3")
        e.call(w)

    def write_mov_eax_ret(at, imm):                         # mov eax, imm; ret -- written by guest stores
        store(at, 0xB8 | (imm & 0xFFFFFF) << 8)
        store(at + 4, imm >> 24 | 0xC3 << 8)

    # code patched from another page, often enough that QEMU switches to its per-page code bitmap
    f = e.alloc(16)
    e.wr(f, b"\xb8\x01\x00\x00\x00\xc3")
    for i in range(1, 30):
        assert e.call(f) == i, i
        store(f + 1, i + 1)
    # a page written as data first (its TLB entry goes fast), then filled with code, run, and rewritten
    big = e.alloc(3 * PAGE)
    pg = (big + PAGE - 1) & ~(PAGE - 1)
    for i in range(0, PAGE, 64):
        store(pg + i, 0xDEADBEEF)
    for i in range(20):
        write_mov_eax_ret(pg + 0x100, 1000 + i)
        assert e.call(pg + 0x100) == 1000 + i, i
        store(pg + 0x800, i)                                # data store into the same page between runs
    # an instruction that rewrites the next instruction in its own block
    c = e.alloc(32)
    e.wr(c, b"\xc7\x05" + struct.pack("<II", c + 11, 7) + b"\xb8\x05\x00\x00\x00\xc3")
    assert e.call(c) == 7
    print("ok  self-modifying code: patched code, code written into a dirty page, same-block rewrite")


def test_heap_reuse():
    """The guest heap reuses freed blocks (it used to be a bump allocator that never freed, and ran out of its
    512 MB in the graphic novel after the first level load)."""
    e = mpemu.Emu(".")
    heap_alloc, heap_free = mpemu.HLE[("KERNEL32.DLL", "HeapAlloc")][0], mpemu.HLE[("KERNEL32.DLL", "HeapFree")][0]
    realloc = mpemu.HLE[("KERNEL32.DLL", "HeapReAlloc")][0]
    a, b, c = e.alloc(100), e.alloc(100), e.alloc(100)
    e.wr(b, b"\xaa" * 100)
    e.free(b)
    assert e.alloc(64) == b                                 # first fit in the freed block
    assert e.rd(b, 64) == bytes(64)                         # reused memory comes back zeroed
    e.free(a); e.free(b); e.free(c)
    assert e.alloc(300) == a                                # neighbours coalesce into one block
    e.free(a)
    heap_free(e, 0, 0, heap_alloc(e, 0, 0, 4096))
    top = e.heap_next
    for _ in range(10000):                                  # alloc/free churn does not grow the heap
        heap_free(e, 0, 0, heap_alloc(e, 0, 0, 4096))
    assert e.heap_next == top, hex(e.heap_next - top)
    p = heap_alloc(e, 0, 0, 40)
    e.wr(p, b"x" * 40)
    assert realloc(e, 0, 0, p, 44) == p                     # fits its 48-byte block: stays in place
    q = realloc(e, 0, 0, p, 1000)
    assert q != p and e.rd(q, 40) == b"x" * 40 and e.heap_blocks.get(p) is None
    assert realloc(e, 0, 0x10, q, 5000) == 0                # HEAP_REALLOC_IN_PLACE_ONLY that cannot grow
    assert not e.free(0x12345678) and not e.free(0)         # unknown pointers are ignored
    print("ok  guest heap: freed blocks reused, zeroed, coalesced; realloc in place; churn does not grow it")


def test_device_caps_vertex_alpha():
    """GetDeviceCaps advertises D3DPSHADECAPS_ALPHAGOURAUDBLEND: the game's D3D8 driver only keeps VERTEX_ALPHA
    layers (the graphic novel's fading cover quads) when that bit is set."""
    import d3d8
    d3d8.install(mpemu)
    e = mpemu.Emu(".")
    this = e.call(e.stub_for("D3D8.DLL", "Direct3DCreate8"), 220)
    p = e.alloc(53 * 4)
    e.call(e.stub_for("D3D8.DLL", "IDirect3D8::GetDeviceCaps"), this, 0, 1, p)
    raw = e.rd(p, 53 * 4)
    shade = struct.unpack_from("<I", raw, 0x38)[0]          # ShadeCaps is dword 14 (byte 0x38)
    assert shade & 0x4000 and shade & 0x8 and shade & 0x80000, hex(shade)
    print("ok  GetDeviceCaps ShadeCaps has ALPHAGOURAUDBLEND, COLORGOURAUDRGB and FOGGOURAUD")


def test_handles_not_reused_while_open():
    """Closing one handle must not make the next CreateFile/CreateEvent reuse the number of one still open."""
    e = mpemu.Emu(".")
    a, b, c = e.new_handle("file", "a"), e.new_handle("file", "b"), e.new_handle("file", "c")
    e.call(e.stub_for("KERNEL32.DLL", "CloseHandle"), a)
    d = e.new_handle("event")
    assert d not in (b, c) and e.handles[c] == ("file", "c") and e.handles[b] == ("file", "b"), (hex(d), e.handles)
    print("ok  kernel handles: a new handle never replaces one still open")


def test_apilog_lazy():
    """ApiLog keeps an HLE call as its record and formats it when read; string-argument calls are formatted at once
    (their text is in guest memory). Reads give the same lines as the eager log did: iteration, index, slice, list."""
    e = mpemu.Emu(".")
    h = e.new_handle("file", "a")
    e.apilog.clear()
    e.call(e.stub_for("KERNEL32.DLL", "CloseHandle"), h)
    name = e.alloc(16)
    e.wr(name, b"nofile.txt\0")
    e.call(e.stub_for("KERNEL32.DLL", "GetFileAttributesA"), name)
    e.apilog.append("SEH note")
    raw = list(e.apilog._d)
    assert raw[0].__class__ is tuple and raw[1].__class__ is str, raw
    want = ["KERNEL32.DLL!CloseHandle(0x%x) -> 0x1" % h]
    assert list(e.apilog)[:1] == want and e.apilog[0] == want[0] and e.apilog[-1] == "SEH note", list(e.apilog)
    assert e.apilog[1] == "KERNEL32.DLL!GetFileAttributesA(0x%x  ['nofile.txt']) -> 0xffffffff" % name, e.apilog[1]
    assert e.apilog[-2:] == list(e.apilog)[-2:] and len(e.apilog) == 3
    small = mpemu.ApiLog(maxlen=2)
    for i in range(5):
        small.append(("D", "F", (i,), i))
    assert list(small) == ["D!F(0x3) -> 0x3", "D!F(0x4) -> 0x4"] and small.maxlen == 2, list(small)
    print("ok  API log: records formatted on read, same lines as before")


if __name__ == "__main__":
    test_timeout_and_resume()
    test_host_call_args()
    test_unmapped_access()
    test_self_modifying_code()
    test_heap_reuse()
    test_device_caps_vertex_alpha()
    test_handles_not_reused_while_open()
    test_apilog_lazy()
    print("all emulator core tests passed")
