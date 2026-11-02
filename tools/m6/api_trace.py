"""API traces of the emulator and of the native host (E5/E6), and their call-by-call comparison.

  api_trace.py py OUT [run_init.py arguments...]   run emu/run_init.py with an API log that is never cleared or
                                                    trimmed (DLL entry points included) and write it to OUT at exit
  api_trace.py cmp PY HOST                          compare a Python trace with an mphost --trace file
  (diffs(PY, HOST) lists every difference, for a comparison past the first)

The comparison keeps the HLE call lines (DLL!Name(args) -> result) of both, drops the calls the runtime serves in C in a
native run (heap.c, seh.c, hle_fast.c: the Python run makes the first of each through Python before the stub is bound,
the host none), drops the string part the emulator appends to some calls ("  ['...']"), and compares a coroutine line
(Python: "... [coroutine]", no result) and a clock (timeGetTime, GetTickCount) by its call alone. It prints the first difference with the lines around it, or
that the shorter trace is a prefix of the longer one."""
import os
import re
import runpy
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
# served by the runtime in a native run (emu/native.py HEAP_DIRECT, HLE_FAST_KINDS, seh.c); the host serves the D3D8,
# DINPUT and DSOUND kinds from the first call, the emulator from the second (the first binds them)
IN_C = {"HeapAlloc", "HeapFree", "RaiseException", "RtlUnwind", "QueryPerformanceCounter", "TlsGetValue",
        "TlsSetValue", "GetLastError", "SetLastError", "InitializeCriticalSection", "EnterCriticalSection",
        "LeaveCriticalSection", "DeleteCriticalSection",
        "IDirect3DDevice8::SetRenderState", "IDirect3DDevice8::SetTextureStageState", "IDirect3DDevice8::SetTexture",
        "IDirect3DDevice8::SetStreamSource", "IDirect3DDevice8::SetIndices", "IDirect3DVertexBuffer8::Lock",
        "IDirect3DIndexBuffer8::Lock", "IDirect3DVertexBuffer8::Unlock", "IDirect3DIndexBuffer8::Unlock",
        "IDirect3DDevice8::DrawIndexedPrimitive", "IDirect3DDevice8::SetVertexShader", "IDirect3DDevice8::SetTransform",
        "IDirect3DDevice8::SetViewport", "IDirect3DDevice8::Clear",
        "IDirectSoundBuffer::Lock", "IDirectSoundBuffer::Unlock", "IDirectSoundBuffer::GetCurrentPosition",
        "IDirectSoundBuffer::SetVolume", "IDirectInputDevice7A::Acquire", "IDirectInputDevice7A::GetDeviceState",
        "IDirectInputDevice7A::GetDeviceData"}
# clocks: compared by the call alone (the result is the time)
VOLATILE = {"timeGetTime", "GetTickCount"}
CALL = re.compile(r"^([A-Z0-9_]+\.DLL)!([^(]+)\((.*)\)( \[coroutine\]| -> (0x[0-9a-f]+))$")
STRING = re.compile(r"  \[.*\]$")         # the emulator's string part, inside the parentheses


def record(out, argv):
    sys.path.insert(0, os.path.join(ROOT, "emu"))
    import atexit
    import collections
    import mpemu
    shared = collections.deque()

    def _init(self, maxlen=20000):
        self._d = shared
        self.append = shared.append
        self.clear = lambda: None
    mpemu.ApiLog.__init__ = _init

    def _dump():
        with open(out, "w") as fh:
            for x in list(shared):
                fh.write(mpemu.ApiLog.line(x) + "\n")
        print("api_trace: %d lines -> %s" % (len(shared), out))
    atexit.register(_dump)
    sys.argv = [os.path.join(ROOT, "emu", "run_init.py")] + argv
    runpy.run_path(sys.argv[0], run_name="__main__")


def calls(path):
    """[(dll!name(args), result or None for a coroutine, line number)] of the trace's HLE calls."""
    out = []
    for n, line in enumerate(open(path, errors="replace"), 1):
        m = CALL.match(line.rstrip("\n"))
        if not m or m.group(2) in IN_C:
            continue
        coro = m.group(4) == " [coroutine]" or m.group(2) in VOLATILE
        out.append(("%s!%s(%s)" % (m.group(1), m.group(2), STRING.sub("", m.group(3))), None if coro else m.group(5), n))
    return out


def compare(py, host):
    a, b = calls(py), calls(host)
    n = min(len(a), len(b))
    for i in range(n):
        ca, ra, la = a[i]
        cb, rb, lb = b[i]
        if ca == cb and (ra is None or rb is None or ra == rb):
            continue
        print("first difference at call %d (python line %d, host line %d):" % (i + 1, la, lb))
        for j in range(max(0, i - 6), min(n, i + 4)):
            mark = ">>" if j == i else "  "
            print("%s py   %s -> %s" % (mark, a[j][0], a[j][1]))
            print("%s host %s -> %s" % (mark, b[j][0], b[j][1]))
        return 1
    print("the first %d calls agree (python %d, host %d calls compared)" % (n, len(a), len(b)))
    if len(b) < len(a):
        print("python goes on with: %s -> %s" % a[n][:2])
    return 0


def diffs(py, host):
    """Every call where the traces differ, as (call number, python call, host call): a different call, or the same call
    with another result (coroutines and clocks compared by the call alone, as in compare)."""
    a, b = calls(py), calls(host)
    out = []
    for i in range(min(len(a), len(b))):
        (ca, ra, _), (cb, rb, _) = a[i], b[i]
        if ca != cb or (ra is not None and rb is not None and ra != rb):
            out.append((i + 1, a[i][:2], b[i][:2]))
    return out


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "py":
        record(sys.argv[2], sys.argv[3:])
    elif len(sys.argv) == 4 and sys.argv[1] == "cmp":
        sys.exit(compare(sys.argv[2], sys.argv[3]))
    else:
        sys.exit(__doc__)
