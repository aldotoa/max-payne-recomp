"""Smoke test: construct rlmfc's R_Timer and sample it, entirely inside the emulator."""
import struct, sys, time
sys.path.insert(0, __import__("os").path.dirname(__file__))
import mpemu
from unicorn.x86_const import UC_X86_REG_ST0

e = mpemu.boot(sys.argv[1] if len(sys.argv) > 1 else "Max Payne")
assert mpemu.run_dll_mains(e, verbose=False), "DllMain failed"
rl = e.modules["rlmfc.dll"]

def st0():
    return e.fp_return()

# The engine's global R_System ('Sys') is created by R_RemedyInit; the game does this at start-up.
init = e.alloc(64)
t0 = time.time()
e.call(rl.exports["??0R_RemedyInit@@QAE@XZ"], ecx=init, timeout=600)
print("R_RemedyInit: %s (%.1fs)" % (e.fatal or "ok", time.time() - t0))
print("Sys pointer:", hex(e.rd32(rl.exports["?Sys@@3PAVR_System@@A"])))
obj = e.alloc(64)
ctor = rl.exports["??0R_Timer@@QAE@XZ"]
sample = rl.exports["?sample@R_Timer@@QAEMXZ"]
getdelta = rl.exports["?getDelta@R_Timer@@QBEMXZ"]
getage = rl.exports["?getAge@R_Timer@@QBEMXZ"]
e.call(ctor, ecx=obj); print("ctor ok" if not e.fatal else e.fatal)
e.call(sample, ecx=obj); d1 = st0(); print("sample #1 ->", d1, e.fatal or "")
time.sleep(0.05)
e.call(sample, ecx=obj); d2 = st0(); print("sample #2 ->", d2, e.fatal or "")
e.call(getage, ecx=obj); print("getAge ->", st0(), e.fatal or "")
print("FPU control word the guest sees:", hex(e.uc.reg_read(__import__("unicorn.x86_const",fromlist=["x"]).UC_X86_REG_FPCW)))
