"""Checks of the native host (E5): build/mphost against the emulator (emu/mpemu.py, emu/run_init.py).

1. The loader: every module image mphost links (mapped, relocated, imports bound, MFC42's delay imports included) is
   byte for byte the image mpemu.boot(with_exe=True) builds.
2. The run: mphost from the DLL entry points through the exe's start-up, the intro and one frame to ExitProcess
   (--frames 1), with --trace, against an API trace of the same library under run_init.py --real-entry --frames 1
   (tools/m6/api_trace.py): every call the host made is the emulator's call, in order, and up to the first difference
   with the same arguments and results (heap addresses, handles, guest pointers); the host exits with code 0 (or, while
   E6 ports the rest, stops at a call with no C handler, exit code 3). After the first difference the only differences
   allowed are SetFilePointer offsets: the streaming sound reads the file as far as the buffer's play cursor has gone,
   and that cursor runs on the clock (two emulator runs differ there as well).

   The same scripted input (--input, as run_init.py's) given to both over six frames: the input's path through the
   game (DINPUT, USER32's key and message calls, the window procedure's messages) is the emulator's, call by call.

3. The rendering: the MPD3 command streams (emu/d3dcap.py) of frames 0-2 of a three-frame run, mphost --capture
   against run_init.py --capture: byte for byte the same (the host's records come partly from hle_fast.c's C sink, the
   emulator's all from Python, CAP_PYTHON), so the renderer (libmprender) gets the same stream in both live views.
   The host runs with --view stretch: the emulator has no Hor+ (M7), which changes the camera-placed menu's vertices.

4. The sound: the mixer's voice operations (libmpaudio's MPA_LOG: voices made and freed, gains and rates as hex
   floats, writes, plays, stops, positions) of the three-frame run with --audio null, mphost against run_init.py. They
   must agree line for line but for three things known to differ between runs: the movie soundtrack's length
   (AVFoundation's decoder returns a few ms more or less from one open to the next), the bytes of a write (the
   streaming sound reads its file as far as the play cursor has gone, on the clock), and the rate the emulator sets
   again at the first SetVolume (that call runs in Python, which binds hle_fast.c's kind; the host serves every one in
   C, which sets the gain alone; the rate is unchanged).

Needs the game folder and a lifted library built with lift_host_init (H64 or later):
  .venv/bin/python host/test_host.py [LIB]        (default build-lift/liblifted_game.dylib, else liblifted_full_h79.dylib)
MP_GAME_DIR overrides the game folder; PY_TRACE=FILE reuses an emulator trace instead of recording one (about a
minute), PY_CAPTURE=DIR an emulator capture of frames 0-2 (about two minutes), PY_AUDIO_LOG=FILE an emulator MPA_LOG of
the three-frame run with --audio null (about two minutes)."""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "emu"))
sys.path.insert(0, os.path.join(ROOT, "tools", "m6"))
GAME = os.environ.get("MP_GAME_DIR", os.path.join(ROOT, "Max Payne"))
LIB = sys.argv[1] if len(sys.argv) > 1 else next(
    (p for p in (os.path.join(ROOT, "build-lift", n) for n in ("liblifted_game.dylib", "liblifted_full_h79.dylib"))
     if os.path.exists(p)), os.path.join(ROOT, "build-lift", "liblifted_game.dylib"))
HOST = os.path.join(ROOT, "build", "mphost")
MODULES = "rlmfc.dll,grphmfc.dll,e2mfc.dll,sndmfc.dll,e2_d3d8_driver_mfc.dll,maxpayne.exe,msvcrt.dll,mfc42.dll," \
          "msvcp60.dll,msvcirt.dll"


def test_images_match_mpemu(work):
    import mpemu
    out = os.path.join(work, "img")
    os.makedirs(out)
    subprocess.run([HOST, GAME, "--lib", LIB, "--dump-images", out], check=True, capture_output=True)
    e = mpemu.boot(GAME, verbose=False, with_exe=True)
    for m in e.modules.values():
        ref = e.rd(m.base, m.size)
        got = open(os.path.join(out, m.name + ".bin"), "rb").read()
        assert got == ref, "%s: the host's image differs from mpemu's at 0x%x" % (
            m.name, next(i for i in range(len(ref)) if got[i:i + 1] != ref[i:i + 1]))
    print("  %d images identical" % len(e.modules))


def test_trace_matches_emulator(work):
    import api_trace
    host_trace = os.path.join(work, "host.txt")
    r = subprocess.run([HOST, GAME, "--lib", LIB, "--trace", host_trace, "--data-dir", os.path.join(work, "data"),
                        "--frames", "1"], capture_output=True, text=True)
    fatal = [l for l in r.stderr.splitlines() if "fatal:" in l]
    assert r.returncode == 0 or (r.returncode == 3 and fatal and "unimplemented import" in fatal[0]), \
        "mphost exited with %d:\n%s" % (r.returncode, r.stderr[-3000:])
    py_trace = os.environ.get("PY_TRACE")
    if not py_trace:
        py_trace = os.path.join(work, "py.txt")
        subprocess.run([sys.executable, os.path.join(ROOT, "tools", "m6", "api_trace.py"), "py", py_trace, GAME,
                        "--native-lift", LIB, "--lift-modules", MODULES, "--real-entry", "--frames", "1",
                        "--audio", "off", "--intro", "skip", "--data-dir", os.path.join(work, "data_py")],
                       check=True, capture_output=True)
    a, b = api_trace.calls(py_trace), api_trace.calls(host_trace)
    assert len(b) <= len(a), "the host made more calls (%d) than the emulator (%d)" % (len(b), len(a))
    d = api_trace.diffs(py_trace, host_trace)
    bad = [x for x in d if x[1][0].split("(")[0] != x[2][0].split("(")[0] or "!SetFilePointer(" not in x[1][0]]
    if bad:
        api_trace.compare(py_trace, host_trace)
        raise AssertionError("call %d: python %s, host %s" % bad[0])
    if r.returncode == 0:
        assert len(b) == len(a), "the host exited after %d calls, the emulator after %d" % (len(b), len(a))
    print("  %d calls agree (the first %d exactly; then %d stream offset(s) differ, the first at call %d); the host %s" % (
        len(b), d[0][0] - 1 if d else len(b), len(d), d[0][0] if d else 0,
        "exited with code 0" if r.returncode == 0 else "stopped with: " + fatal[0]))


# --input: down, down and Enter on the main menu, the mouse moved and clicked, the wheel, the app's focus lost and
# regained, over six frames. Past the first frame the clock decides how often the streaming sound takes its mutex, so
# the whole traces differ in order; the input's path through the game must not: DINPUT's calls the host does not
# serve in C, the key and message calls of USER32 and the window procedure's messages, in order, arguments and results
INPUT = "1:key=d0,2:keyup=d0,2:move=40;-25,3:key=d0,3:button=0,4:keyup=d0,4:buttonup=0,4:wheel=120,4:focus=0," \
        "5:focus=1,5:key=1c"
INPUT_CALLS = re.compile(r"^(DINPUT\.DLL!|USER32\.DLL!(ToAscii|GetKeyboardState|GetAsyncKeyState|GetKeyState|"
                         r"GetKeyNameTextA|TranslateMessage|DispatchMessageA|PeekMessageA|GetMessageA|CallWindowProcA|"
                         r"SetCursorPos|GetCursorPos|ShowCursor|ClipCursor)\()")


def test_input_matches_emulator(work):
    import api_trace
    args = ["--frames", "6", "--input", INPUT]
    host_trace, py_trace = os.path.join(work, "host_input.txt"), os.path.join(work, "py_input.txt")
    r = subprocess.run([HOST, GAME, "--lib", LIB, "--trace", host_trace, "--data-dir",
                        os.path.join(work, "data_input")] + args, capture_output=True, text=True)
    assert r.returncode == 0, "mphost exited with %d:\n%s" % (r.returncode, r.stderr[-3000:])
    assert r.stdout.count("input before frame") == INPUT.count(":"), "the host applied %d of %d actions" % (
        r.stdout.count("input before frame"), INPUT.count(":"))
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "m6", "api_trace.py"), "py", py_trace, GAME,
                    "--native-lift", LIB, "--lift-modules", MODULES, "--real-entry"] + args +
                   ["--audio", "off", "--intro", "skip", "--data-dir", os.path.join(work, "data_input_py")],
                   check=True, capture_output=True)
    a, b = ([c[:2] for c in api_trace.calls(t) if INPUT_CALLS.match(c[0])] for t in (py_trace, host_trace))
    for i, (x, y) in enumerate(zip(a + [("(end)", None)], b + [("(end)", None)])):
        assert x == y, "input call %d: python %s, host %s" % (i, x, y)
    keys = sum("ToAscii(" in c[0] for c in b)
    assert keys and any("Unacquire" in c[0] for c in b), "the input never reached the game"
    print("  %d input calls agree (%d key translations, focus lost and regained); the host exited with code 0" % (
        len(b), keys))


def test_capture_matches_emulator(work):
    frames = ("000", "001", "002")
    host_dir = os.path.join(work, "cap_host")
    subprocess.run([HOST, GAME, "--lib", LIB, "--data-dir", os.path.join(work, "data_cap"), "--frames", "3",
                    "--capture", host_dir, "--capture-frames", "0,1,2", "--view", "stretch"], check=True,
                   capture_output=True)
    py_dir = os.environ.get("PY_CAPTURE")
    if not py_dir:
        py_dir = os.path.join(work, "cap_py")
        subprocess.run([sys.executable, os.path.join(ROOT, "emu", "run_init.py"), GAME, "--native-lift", LIB,
                        "--lift-modules", MODULES, "--real-entry", "--frames", "3", "--audio", "off", "--intro", "skip",
                        "--data-dir", os.path.join(work, "data_cap_py"), "--capture", py_dir, "--capture-frames",
                        "0,1,2"], check=True, capture_output=True)
    sizes = []
    for f in frames:
        a = open(os.path.join(py_dir, "frame_%s.mpd3" % f), "rb").read()
        b = open(os.path.join(host_dir, "frame_%s.mpd3" % f), "rb").read()
        assert a == b, "frame %s: the host's capture differs from the emulator's at byte %d" % (
            f, next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), min(len(a), len(b))))
        sizes.append(len(a))
    print("  frames %s: the same MPD3 streams (%s bytes)" % (", ".join(frames), ", ".join(map(str, sizes))))


def _audio_ops(path):
    """The MPA_LOG lines, with what differs between runs blanked: a write's hash, the soundtrack voice's size (the one
    48 kHz voice) and its write's length; and the rate lines dropped (compared apart)."""
    ops, rates = [], []
    for line in open(path):
        f = line.split()
        if f[0] == "freq":
            rates.append(line)
            continue
        if f[0] == "new" and f[3] == "48000":
            f[4] = "*"
        if f[0] == "write":
            f[4] = "*"
            if f[3] in sizes_48k(path):
                f[3] = "*"
        ops.append(" ".join(f))
    return ops, rates


def sizes_48k(path, _cache={}):
    if path not in _cache:
        _cache[path] = {l.split()[4] for l in open(path) if l.startswith("new ") and l.split()[3] == "48000"}
    return _cache[path]


def test_audio_matches_emulator(work):
    host_log = os.path.join(work, "mpa_host.log")
    env = dict(os.environ, MPA_LOG=host_log)
    subprocess.run([HOST, GAME, "--lib", LIB, "--data-dir", os.path.join(work, "data_audio"), "--frames", "3",
                    "--audio", "null"], check=True, capture_output=True, env=env)
    py_log = os.environ.get("PY_AUDIO_LOG")
    if not py_log:
        py_log = os.path.join(work, "mpa_py.log")
        subprocess.run([sys.executable, os.path.join(ROOT, "emu", "run_init.py"), GAME, "--native-lift", LIB,
                        "--lift-modules", MODULES, "--real-entry", "--frames", "3", "--audio", "null", "--intro", "skip",
                        "--data-dir", os.path.join(work, "data_audio_py")], check=True, capture_output=True,
                       env=dict(os.environ, MPA_LOG=py_log))
    (a, ra), (b, rb) = _audio_ops(py_log), _audio_ops(host_log)
    assert a == b, "the voice operations differ at line %d: python %r, host %r" % next(
        (i + 1, x, y) for i, (x, y) in enumerate(zip(a + ["(end)"], b + ["(end)"])) if x != y)
    extra = list(ra)
    for r in rb:                                 # every rate the host set, the emulator set too, in the same order
        assert r in extra, "the host set a rate the emulator did not: %r" % r
        extra = extra[extra.index(r) + 1:]
    assert len(ra) - len(rb) <= 1, "the emulator set %d more rates than the host" % (len(ra) - len(rb))
    print("  %d voice operations agree, gains bit for bit; %d rates (the emulator's first SetVolume sets %d more)" % (
        len(a), len(rb), len(ra) - len(rb)))


if __name__ == "__main__":
    if not os.path.isdir(GAME) or not os.path.exists(LIB) or not os.path.exists(HOST):
        sys.exit("needs %s, %s and %s (make -C host)" % (GAME, LIB, HOST))
    work = tempfile.mkdtemp(prefix="mphost-test-")
    for t in (test_images_match_mpemu, test_trace_matches_emulator, test_input_matches_emulator,
              test_capture_matches_emulator, test_audio_matches_emulator):
        print(t.__name__)
        t(work)
    print("all host tests passed")
