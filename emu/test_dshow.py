"""Unit tests for the DirectShow layer (emu/dshow.py) and libmpmovie (movie/): the game's own call sequence for the
intro (maxpayne.exe+0x409ac0) through the COM interfaces, its Sleep(50) polling loop, frame timing, seeking, the
movie's audio in the mixer, the headless skip, and failures the game turns into exceptions.

Needs the game's movies/intro.mpg. Run:  make -C movie -C audio && .venv/bin/python emu/test_dshow.py
"""
import ctypes
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import mpemu
import dinput
import dshow
import dsound
import winsys

dsound.install(mpemu)
dinput.install(mpemu)
winsys.install(mpemu)
dshow.install(mpemu)
GAME = os.path.join(os.path.dirname(__file__), "..", "Max Payne")
INTRO = "movies\\intro.mpg"


class FakeLive:
    """Stands in for the live window: counts the frames shown and the event pumps."""
    def __init__(self):
        self.shown, self.pumps, self.last = [], 0, None

    def show_bgra(self, pixels, w, h):
        self.shown.append(time.perf_counter())
        self.last = (w, h, pixels.raw[:16])

    def pump(self, deliver_input=True):
        self.pumps += 1


def fresh(audio=None, live=None, intro="play"):
    e = mpemu.Emu(GAME)
    e.audio, e.intro = audio, intro
    if live:
        e.live = live
    return e


def guid_ptr(e, g):
    p = e.alloc(16)
    e.wr(p, g)
    return p


def vcall(e, this, iface, name, *args):
    """Call through the object's vtable, as the game does (`call [eax+slot*4]`)."""
    slot = [n for n, _ in dshow.INTERFACES[iface]].index(name)
    return e.call(e.rd32(e.rd32(this) + 4 * slot), this, *args) & 0xFFFFFFFF


def wide(e, s):
    p = e.alloc(2 * len(s) + 2)
    e.wr(p, s.encode("utf-16-le") + b"\0\0")
    return p


def f64(e, p): return struct.unpack("<d", e.rd(p, 8))[0]


def open_graph(e, path=INTRO):
    """The game's sequence up to (not including) Run; returns the interface pointers."""
    pp = e.alloc(4)
    hr = e.call(e.stub_for("OLE32.DLL", "CoCreateInstance"), guid_ptr(e, dshow.CLSID_FILTERGRAPH), 0, 1,
                guid_ptr(e, dshow.IID["IGraphBuilder"]), pp) & 0xFFFFFFFF
    assert hr == 0, hex(hr)
    gb = e.rd32(pp)
    faces = {"IGraphBuilder": gb}
    for name in ("IMediaControl", "IMediaSeeking", "IMediaPosition", "IVideoWindow", "IBasicVideo"):
        assert vcall(e, gb, "IGraphBuilder", "QueryInterface", guid_ptr(e, dshow.IID[name]), pp) == 0
        faces[name] = e.rd32(pp)
    return faces, vcall(e, gb, "IGraphBuilder", "RenderFile", wide(e, path), 0)


def test_movie_library():
    mv = dshow.Movie(os.path.join(GAME, "movies", "intro.mpg"))
    assert (mv.width, mv.height, round(mv.fps)) == (640, 480, 25) and 36 < mv.duration < 38
    assert (mv.audio_rate, mv.audio_channels) == (48000, 2)
    assert mv.advance(0.0) and mv.frame_pts == 0.0
    assert not mv.advance(0.039)                      # the next frame is due at 0.04
    assert mv.advance(1.0) and abs(mv.frame_pts - 1.0) < 1e-6
    mv.seek(0.0)
    assert mv.advance(0.0) and mv.frame_pts == 0.0
    mv.seek(20.0)                                     # the first frame after a seek is the one due then
    assert mv.advance(20.0) and abs(mv.frame_pts - 20.0) < 0.041, mv.frame_pts
    audio = mv.audio()
    assert abs(len(audio) / 4 / 48000 - mv.duration) < 0.1
    mv.close()
    print("ok  libmpmovie: format, frame timing, seeking, audio track")


def test_game_sequence():
    live = FakeLive()
    e = fresh(audio="none", live=live)
    f, hr = open_graph(e)
    assert hr == 0, hex(hr)
    p = e.alloc(16)
    VW, BV = f["IVideoWindow"], f["IBasicVideo"]
    assert vcall(e, VW, "IVideoWindow", "get_Visible", p) == 0      # the game throws if this fails
    assert vcall(e, VW, "IVideoWindow", "put_Owner", 0x10014) == 0
    assert vcall(e, VW, "IVideoWindow", "put_WindowStyle", 0x46000000) == 0
    assert vcall(e, VW, "IVideoWindow", "put_MessageDrain", 0x10014) == 0
    assert vcall(e, BV, "IBasicVideo", "GetVideoSize", p, p + 4) == 0
    assert struct.unpack("<2I", e.rd(p, 8)) == (640, 480)
    assert vcall(e, VW, "IVideoWindow", "SetWindowPosition", 0, 0, 640, 480) == 0
    assert vcall(e, VW, "IVideoWindow", "put_FullScreenMode", 0xFFFFFFFF) == 0
    e.wr(p, struct.pack("<q", 0))
    assert vcall(e, f["IMediaSeeking"], "IMediaSeeking", "SetPositions", p, 1, 0, 0) == 0
    assert vcall(e, f["IMediaControl"], "IMediaControl", "Run") == 0
    assert vcall(e, f["IMediaPosition"], "IMediaPosition", "get_Duration", p) == 0
    duration = f64(e, p)
    assert 36 < duration < 38
    # the game's loop: get_CurrentPosition, Sleep(50), for a second
    sleep = e.stub_for("KERNEL32.DLL", "Sleep")
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < 1.0:
        vcall(e, f["IMediaPosition"], "IMediaPosition", "get_CurrentPosition", p)
        e.call(sleep, 50)
    pos = f64(e, p)
    assert 0.9 < pos < 1.1, pos
    assert 23 <= len(live.shown) <= 27, len(live.shown)                    # 25 fps, frames shown on time
    gaps = [b - a for a, b in zip(live.shown, live.shown[1:])]
    assert max(gaps) < 0.06, max(gaps)                                      # no stalls from the 50 ms sleeps
    assert live.pumps >= 20                                                 # window events pumped throughout
    assert live.last[:2] == (640, 480)
    # the movie's audio is playing in the mixer (pulled here: it starts at the movie's start, silent for 0.18 s)
    mx = dsound.mixer(e)
    out = (ctypes.c_float * (2 * 22050))()
    mx.lib.mpa_render(mx.m, out, 22050)
    assert max(abs(x) for x in out[2 * 11025:]) > 0.05
    # Stop freezes the clock; seeking forward lands on the right frame
    assert vcall(e, f["IMediaControl"], "IMediaControl", "Stop") == 0
    vcall(e, f["IMediaPosition"], "IMediaPosition", "get_CurrentPosition", p)
    stopped = f64(e, p)
    time.sleep(0.1)
    vcall(e, f["IMediaPosition"], "IMediaPosition", "get_CurrentPosition", p)
    assert f64(e, p) == stopped
    lo, hi = struct.unpack("<II", struct.pack("<d", 30.0))
    assert vcall(e, f["IMediaPosition"], "IMediaPosition", "put_CurrentPosition", lo, hi) == 0
    vcall(e, f["IMediaControl"], "IMediaControl", "Run")
    vcall(e, f["IMediaPosition"], "IMediaPosition", "get_CurrentPosition", p)
    g = e.dshow.objs[f["IGraphBuilder"]]
    assert 30.0 <= g["movie"].frame_pts < 30.1 and 30.0 <= f64(e, p) < 30.1
    # GetState, IMediaSeeking times in 100 ns units
    assert vcall(e, f["IMediaControl"], "IMediaControl", "GetState", 0, p) == 0 and e.rd32(p) == dshow.STATE_RUNNING
    vcall(e, f["IMediaSeeking"], "IMediaSeeking", "GetDuration", p)
    assert struct.unpack("<q", e.rd(p, 8))[0] == int(duration * dshow.UNITS)
    # an interface the filter graph does not have here
    assert vcall(e, f["IGraphBuilder"], "IGraphBuilder", "QueryInterface",
                 guid_ptr(e, dshow.guid("56A868C0-0AD4-11CE-B03A-0020AF0BA770")), p) == dshow.E_NOINTERFACE
    # teardown as the game does it: everything released, the voice and the file closed
    vcall(e, VW, "IVideoWindow", "put_Visible", 0)
    vcall(e, f["IMediaControl"], "IMediaControl", "Stop")
    for name in ("IMediaSeeking", "IMediaPosition", "IMediaControl", "IBasicVideo", "IVideoWindow"):
        vcall(e, f[name], name, "Release")
    assert vcall(e, f["IGraphBuilder"], "IGraphBuilder", "Release") == 0
    assert g["movie"] is None and g["voice"] is None and not e.dshow.active
    print("ok  the game's sequence: setup, Run, Sleep(50) loop at 25 fps, audio, Stop, seek, GetState, release")


def test_runs_to_the_end():
    """Near the end the position reaches the duration and stays there: the game's loop exit condition."""
    e = fresh()
    f, hr = open_graph(e)
    p = e.alloc(16)
    lo, hi = struct.unpack("<II", struct.pack("<d", 36.8))
    vcall(e, f["IMediaPosition"], "IMediaPosition", "put_CurrentPosition", lo, hi)
    vcall(e, f["IMediaControl"], "IMediaControl", "Run")
    vcall(e, f["IMediaPosition"], "IMediaPosition", "get_Duration", p)
    duration = f64(e, p)
    sleep = e.stub_for("KERNEL32.DLL", "Sleep")
    for _ in range(10):
        e.call(sleep, 50)
    vcall(e, f["IMediaPosition"], "IMediaPosition", "get_CurrentPosition", p)
    assert f64(e, p) == duration
    print("ok  position stops at the duration")


def test_headless_skip():
    e = fresh(intro="skip")
    winsys.host_set_app_active(e, True)
    f, hr = open_graph(e)
    vcall(e, f["IMediaControl"], "IMediaControl", "Run")
    di = dinput.input_state(e)
    assert di.keys[dshow.SKIP_KEY] and di.keymsgs and di.keymsgs[-1][3]       # Space down, a WM_KEYDOWN queued
    vcall(e, f["IMediaControl"], "IMediaControl", "Stop")
    assert not di.keys[dshow.SKIP_KEY]
    print("ok  headless skip: a key press when the movie starts, released at Stop")


def test_failures():
    e = fresh()
    f, hr = open_graph(e, "movies\\missing.mpg")
    assert hr == dshow.VFW_E_NOT_FOUND
    p = e.alloc(4)
    assert vcall(e, f["IVideoWindow"], "IVideoWindow", "get_Visible", p) != 0     # no video: the game throws
    assert vcall(e, f["IMediaControl"], "IMediaControl", "Run") != 0
    print("ok  missing file: RenderFile and the video window fail as the game expects")


if __name__ == "__main__":
    test_movie_library()
    test_game_sequence()
    test_runs_to_the_end()
    test_headless_skip()
    test_failures()
    print("all DirectShow tests passed")
