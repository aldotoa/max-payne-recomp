"""Load MaxPayne.exe and run its real CRT start-up + C++ static constructors until AfxWinMain."""
import struct, sys, time, collections
sys.path.insert(0, __import__("os").path.dirname(__file__))
import mpemu

game = sys.argv[1] if len(sys.argv) > 1 else "Max Payne"
e = mpemu.boot(game, with_exe=True)
exe = e.modules["maxpayne.exe"]
e.mfc_lenient = True
assert mpemu.run_dll_mains(e, verbose=False), "DLL init failed"
print("DLLs initialised; exe at 0x%x, entry %s" % (exe.base, e.module_at(exe.entry)))

# The exe's WinMain stub jumps through an MFC42 import to AfxWinMain: find that stub and stop there.
thunk = 0x7838b8
assert e.rd(thunk, 2) == b"\xff\x25"
slot = struct.unpack("<I", e.rd(thunk + 2, 4))[0]
stub_va = e.rd32(slot)
afx = e.stubs[(stub_va - mpemu.STUB_BASE) // mpemu.STUB_STRIDE]
print("AfxWinMain is imported as", afx)
e.stop_stubs.add(afx)

t = time.time()
e.call(exe.entry, timeout=600)
print("run took %.1fs" % (time.time() - t))
print("result:", e.fatal or "returned")
print("at:", e.where(), "->", e.module_at(e.uc.reg_read(mpemu.UC_X86_REG_EIP)))
print("MFC calls made during start-up (lenient, returned 0):")
for (n, frm), c in sorted(e.mfc_calls.items(), key=lambda kv: -kv[1])[:40]:
    print("  %-8s x%-3d from %s" % (n, c, frm))
print("last API calls:")
for l in list(e.apilog)[-12:]:
    print("  ", l)
