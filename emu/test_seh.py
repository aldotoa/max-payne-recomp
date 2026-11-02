"""Unit tests for the emulator's SEH dispatcher (RaiseException / RtlUnwind), using hand-assembled
guest code so no game files are needed beyond what Emu() maps.

Run:  .venv/bin/python emu/test_seh.py
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
import mpemu
from unicorn.x86_const import UC_X86_REG_ESP

BASE = 0x00A00000          # free region (exe is at 0x400000..0x8d7000)
MARK = BASE + 0x800        # scratch data: markers written by handlers
ARR = MARK + 0x10


class Asm:
    def __init__(self, base):
        self.base, self.buf, self.labels, self.fix = base, bytearray(), {}, []

    def here(self): return self.base + len(self.buf)
    def label(self, n): self.labels[n] = self.here()
    def emit(self, *bs): self.buf += bytes(bs)
    def u32(self, v): self.buf += struct.pack("<I", v & 0xFFFFFFFF)

    def push_imm(self, v): self.emit(0x68); self.u32(v)
    def push_label(self, n): self.emit(0x68); self.fix.append((len(self.buf), n, "abs")); self.u32(0)
    def call_abs(self, addr): self.emit(0xE8); self.u32(addr - (self.here() + 4))
    def mov_eax_imm(self, v): self.emit(0xB8); self.u32(v)

    def finish(self):
        for off, n, kind in self.fix:
            struct.pack_into("<I", self.buf, off, self.labels[n])
        return bytes(self.buf)


def fresh():
    e = mpemu.Emu(os.path.join(os.path.dirname(__file__), "..", "Max Payne"))
    e.map(BASE, 0x2000)
    return e


def install_frame(a, handler_label):
    a.push_label(handler_label)
    a.emit(0x64, 0xFF, 0x35); a.u32(0)              # push dword ptr fs:[0]
    a.emit(0x64, 0x89, 0x25); a.u32(0)              # mov fs:[0], esp


def raise_call(a, e, code=0xE0000001, flags=0):
    for v in (0, 0, flags):
        a.push_imm(v)
    a.push_imm(code)
    a.call_abs(e.stub_for("KERNEL32.DLL", "RaiseException"))


def record_handler(a, label, ret_value):
    """cdecl handler: append record->ExceptionFlags to ARR, bump the counter, return ret_value."""
    a.label(label)
    a.emit(0x8B, 0x44, 0x24, 0x04)                  # mov eax,[esp+4]   (EXCEPTION_RECORD*)
    a.emit(0x8B, 0x40, 0x04)                        # mov eax,[eax+4]   (ExceptionFlags)
    a.emit(0x8B, 0x0D); a.u32(MARK)                 # mov ecx,[MARK]    (counter)
    a.emit(0x89, 0x04, 0x8D); a.u32(ARR)            # mov [ARR+ecx*4],eax
    a.emit(0x41)                                    # inc ecx
    a.emit(0x89, 0x0D); a.u32(MARK)                 # mov [MARK],ecx
    a.mov_eax_imm(ret_value)
    a.emit(0xC3)


def run(e, code_bytes):
    e.wr(BASE, code_bytes)
    e.wr32(MARK, 0)
    e.call(BASE)
    n = e.rd32(MARK)
    return n, [e.rd32(ARR + 4 * i) for i in range(n)], e.uc.reg_read(mpemu.UC_X86_REG_EAX)


def test_continue_execution():
    """A handler that returns ExceptionContinueExecution: RaiseException returns to its caller."""
    e = fresh()
    a = Asm(BASE)
    install_frame(a, "h")
    raise_call(a, e)
    a.mov_eax_imm(0x1234)                           # reached only if RaiseException returned
    a.emit(0x64, 0x8F, 0x05); a.u32(0)              # pop dword ptr fs:[0]
    a.emit(0x83, 0xC4, 0x04)                        # add esp,4
    a.emit(0xC3)
    record_handler(a, "h", 0)                       # ExceptionContinueExecution
    n, flags, eax = run(e, a.finish())
    assert (n, flags, eax) == (1, [0], 0x1234), (n, flags, hex(eax), e.fatal)
    assert e.rd32(mpemu.TEB) == 0xFFFFFFFF
    print("ok  continue execution: handler called once (flags=0), RaiseException returned, eax=0x1234")


def test_unhandled():
    """No handler takes it: the dispatcher reports an unhandled exception instead of running on."""
    e = fresh()
    a = Asm(BASE)
    install_frame(a, "h")
    raise_call(a, e, code=0xE0001234)
    a.emit(0xC3)
    record_handler(a, "h", 1)                       # ExceptionContinueSearch
    n, flags, eax = run(e, a.finish())
    assert n == 1 and e.fatal and "unhandled exception 0xe0001234" in e.fatal, (n, e.fatal)
    print("ok  unhandled: %s" % e.fatal.split(" (called")[0])


def test_two_pass_unwind():
    """Inner frame says 'continue search', outer frame unwinds to itself with RtlUnwind and resumes."""
    e = fresh()
    a = Asm(BASE)
    install_frame(a, "outer")                       # F1 (the unwind target)
    install_frame(a, "inner")                       # F2
    raise_call(a, e)
    a.mov_eax_imm(0xBAD)                            # must NOT run: unwinding resumes elsewhere
    a.emit(0xC3)
    record_handler(a, "inner", 1)                   # logs flags each call; ContinueSearch
    # outer handler: RtlUnwind(target=F1, ip=cont, record, retval=0x55), then continue at `cont`
    a.label("outer")
    a.emit(0x8B, 0x5C, 0x24, 0x08)                  # mov ebx,[esp+8]   (EstablisherFrame = F1)
    a.emit(0x8B, 0x4C, 0x24, 0x04)                  # mov ecx,[esp+4]   (ExceptionRecord)
    a.emit(0x6A, 0x55)                              # push 0x55
    a.emit(0x51)                                    # push ecx
    a.push_label("cont")                            # push TargetIp
    a.emit(0x53)                                    # push ebx          (TargetFrame)
    a.call_abs(e.stub_for("KERNEL32.DLL", "RtlUnwind"))
    a.label("cont")
    a.emit(0x89, 0xDC)                              # mov esp,ebx       (back to F1's registration record)
    a.emit(0x64, 0x8F, 0x05); a.u32(0)              # pop dword ptr fs:[0]
    a.emit(0x83, 0xC4, 0x04)                        # add esp,4
    a.emit(0xC3)
    n, flags, eax = run(e, a.finish())
    assert n == 2 and flags == [0, mpemu.EH_UNWINDING], (n, flags, e.fatal)
    assert eax == 0x55, hex(eax)
    assert e.rd32(mpemu.TEB) == 0xFFFFFFFF
    # The RaiseException frame was abandoned by the unwind; it is reaped on the next entry into the host.
    assert len(e.coros) == 1
    e.call(e.stub_for("KERNEL32.DLL", "GetLastError"))
    assert not e.coros, "stale coroutines left behind: %d" % len(e.coros)
    print("ok  two-pass unwind: inner handler saw flags %s (search, then EH_UNWINDING), resumed at target with eax=0x55" % flags)


def test_stale_chain_from_earlier_call():
    """A host call left fs:[0] at a record on stack it no longer owns (the CRT entry stopped at AfxWinMain), and
    that record is now garbage. The next host call must not hand the exception to a handler read from it."""
    e = fresh()
    sp = e.uc.reg_read(mpemu.UC_X86_REG_ESP)
    stale = sp - 0x18
    e.wr32(stale, stale - 8)                        # next: points down the stack (overwritten by later locals)
    e.wr32(stale + 4, 1)                            # handler: garbage
    e.wr32(mpemu.TEB, stale)
    a = Asm(BASE)
    install_frame(a, "h")
    raise_call(a, e, code=0xE0001234)
    a.emit(0xC3)
    record_handler(a, "h", 1)                       # ExceptionContinueSearch
    n, flags, eax = run(e, a.finish())
    assert n == 1 and e.fatal and "unhandled exception 0xe0001234" in e.fatal, (n, e.fatal)
    print("ok  stale SEH records below a host call's stack are unlinked; the exception is reported unhandled")


if __name__ == "__main__":
    test_continue_execution()
    test_unhandled()
    test_two_pass_unwind()
    test_stale_chain_from_earlier_call()
    print("all SEH tests passed")
