"""DirectShow (quartz.dll filter graph) for the emulator: plays the game's movies.

The game plays its intro (movies/intro.mpg) in maxpayne.exe+0x409ac0, called from InitInstance unless
-skipstartup or the parental lock is set. The sequence:
  CoCreateInstance(CLSID_FilterGraph, IID_IGraphBuilder); QueryInterface for IMediaControl, IMediaSeeking,
  IMediaPosition, IVideoWindow, IBasicVideo (any missing one throws); IGraphBuilder::RenderFile;
  IVideoWindow::get_Visible (fails without a video stream, which also throws); put_Owner(its own window),
  put_WindowStyle(WS_CHILD|WS_CLIPSIBLINGS|WS_CLIPCHILDREN), put_MessageDrain, IBasicVideo::GetVideoSize,
  SetWindowPosition, put_FullScreenMode(OATRUE); IMediaSeeking::SetPositions(0); IMediaControl::Run;
  IMediaPosition::get_Duration; then until get_CurrentPosition reaches the duration: PeekMessage (WM_KEYDOWN or
  WM_SYSKEYDOWN skips the movie), Sleep(50); finally put_Visible(OAFALSE), Stop, put_Owner(0), Release all.

So the game never touches a frame: DirectShow draws into the window it is given. Here the filter graph is one
object with all six interfaces. RenderFile opens the file with libmpmovie (movie/, AVFoundation: MPEG-1 video and
MPEG audio layer II); the whole audio track becomes one mixer voice (emu/dsound.py, audio/) started by Run. The
movie clock is the host clock from Run. While the movie runs, every get_CurrentPosition and every guest Sleep
decodes up to the current time and shows the newest frame in the live window (emu/live.py), whose events are
pumped so a key press reaches the game as WM_KEYDOWN.

Headless (no live window), the emulator's `intro` attribute decides: "play" runs the movie in real time (37 s for
the intro, silent unless a mixer is on), "skip" presses a key when the movie starts, as a player would.

Usage: dshow.install(mpemu_module) once, before running guest code (mpemu.boot does this).
"""
import collections
import ctypes
import os
import struct
import time
import uuid

import dsound

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def guid(s): return uuid.UUID(s).bytes_le


CLSID_FILTERGRAPH = guid("E436EBB3-524F-11CE-9F53-0020AF0BA770")
IID = {
    "IUnknown": guid("00000000-0000-0000-C000-000000000046"),
    "IDispatch": guid("00020400-0000-0000-C000-000000000046"),
    "IGraphBuilder": guid("56A868A9-0AD4-11CE-B03A-0020AF0BA770"),
    "IFilterGraph": guid("56A8689F-0AD4-11CE-B03A-0020AF0BA770"),
    "IMediaControl": guid("56A868B1-0AD4-11CE-B03A-0020AF0BA770"),
    "IMediaSeeking": guid("36B73880-C2C8-11CF-8B46-00805F6CEF60"),
    "IMediaPosition": guid("56A868B2-0AD4-11CE-B03A-0020AF0BA770"),
    "IVideoWindow": guid("56A868B4-0AD4-11CE-B03A-0020AF0BA770"),
    "IBasicVideo": guid("56A868B5-0AD4-11CE-B03A-0020AF0BA770"),
    "IBasicAudio": guid("56A868B3-0AD4-11CE-B03A-0020AF0BA770"),
}
ALIASES = {"IUnknown": "IGraphBuilder", "IFilterGraph": "IGraphBuilder", "IDispatch": "IMediaControl"}

_IUNKNOWN = [("QueryInterface", 2), ("AddRef", 0), ("Release", 0)]
_IDISPATCH = _IUNKNOWN + [("GetTypeInfoCount", 1), ("GetTypeInfo", 3), ("GetIDsOfNames", 5), ("Invoke", 8)]
INTERFACES = {
    "IGraphBuilder": _IUNKNOWN + [
        ("AddFilter", 2), ("RemoveFilter", 1), ("EnumFilters", 1), ("FindFilterByName", 2), ("ConnectDirect", 3),
        ("Reconnect", 1), ("Disconnect", 1), ("SetDefaultSyncSource", 0), ("Connect", 2), ("Render", 1),
        ("RenderFile", 2), ("AddSourceFilter", 3), ("SetLogFile", 1), ("Abort", 0), ("ShouldOperationContinue", 0)],
    "IMediaControl": _IDISPATCH + [
        ("Run", 0), ("Pause", 0), ("Stop", 0), ("GetState", 2), ("RenderFile", 1), ("AddSourceFilter", 2),
        ("get_FilterCollection", 1), ("get_RegFilterCollection", 1), ("StopWhenReady", 0)],
    "IMediaPosition": _IDISPATCH + [          # REFTIME is a double: two stack slots when passed by value
        ("get_Duration", 1), ("put_CurrentPosition", 2), ("get_CurrentPosition", 1), ("get_StopTime", 1),
        ("put_StopTime", 2), ("get_PrerollTime", 1), ("put_PrerollTime", 2), ("put_Rate", 2), ("get_Rate", 1),
        ("CanSeekForward", 1), ("CanSeekBackward", 1)],
    "IMediaSeeking": _IUNKNOWN + [            # LONGLONG by value: two stack slots
        ("GetCapabilities", 1), ("CheckCapabilities", 1), ("IsFormatSupported", 1), ("QueryPreferredFormat", 1),
        ("GetTimeFormat", 1), ("IsUsingTimeFormat", 1), ("SetTimeFormat", 1), ("GetDuration", 1),
        ("GetStopPosition", 1), ("GetCurrentPosition", 1), ("ConvertTimeFormat", 5), ("SetPositions", 4),
        ("GetPositions", 2), ("GetAvailable", 2), ("SetRate", 2), ("GetRate", 1), ("GetPreroll", 1)],
    "IVideoWindow": _IDISPATCH + [
        ("put_Caption", 1), ("get_Caption", 1), ("put_WindowStyle", 1), ("get_WindowStyle", 1),
        ("put_WindowStyleEx", 1), ("get_WindowStyleEx", 1), ("put_AutoShow", 1), ("get_AutoShow", 1),
        ("put_WindowState", 1), ("get_WindowState", 1), ("put_BackgroundPalette", 1), ("get_BackgroundPalette", 1),
        ("put_Visible", 1), ("get_Visible", 1), ("put_Left", 1), ("get_Left", 1), ("put_Width", 1), ("get_Width", 1),
        ("put_Top", 1), ("get_Top", 1), ("put_Height", 1), ("get_Height", 1), ("put_Owner", 1), ("get_Owner", 1),
        ("put_MessageDrain", 1), ("get_MessageDrain", 1), ("get_BorderColor", 1), ("put_BorderColor", 1),
        ("get_FullScreenMode", 1), ("put_FullScreenMode", 1), ("SetWindowForeground", 1),
        ("NotifyOwnerMessage", 4), ("SetWindowPosition", 4), ("GetWindowPosition", 4),
        ("GetMinIdealImageSize", 2), ("GetMaxIdealImageSize", 2), ("GetRestorePosition", 4), ("HideCursor", 1),
        ("IsCursorHidden", 1)],
    "IBasicVideo": _IDISPATCH + [
        ("get_AvgTimePerFrame", 1), ("get_BitRate", 1), ("get_BitErrorRate", 1), ("get_VideoWidth", 1),
        ("get_VideoHeight", 1), ("put_SourceLeft", 1), ("get_SourceLeft", 1), ("put_SourceWidth", 1),
        ("get_SourceWidth", 1), ("put_SourceTop", 1), ("get_SourceTop", 1), ("put_SourceHeight", 1),
        ("get_SourceHeight", 1), ("put_DestinationLeft", 1), ("get_DestinationLeft", 1),
        ("put_DestinationWidth", 1), ("get_DestinationWidth", 1), ("put_DestinationTop", 1),
        ("get_DestinationTop", 1), ("put_DestinationHeight", 1), ("get_DestinationHeight", 1),
        ("SetSourcePosition", 4), ("GetSourcePosition", 4), ("SetDefaultSourcePosition", 0),
        ("SetDestinationPosition", 4), ("GetDestinationPosition", 4), ("SetDefaultDestinationPosition", 0),
        ("GetVideoSize", 2), ("GetVideoPaletteEntries", 4), ("GetCurrentImage", 2), ("IsUsingDefaultSource", 0),
        ("IsUsingDefaultDestination", 0)],
    "IBasicAudio": _IDISPATCH + [("put_Volume", 1), ("get_Volume", 1), ("put_Balance", 1), ("get_Balance", 1)],
}

S_OK, S_FALSE = 0, 1
E_NOTIMPL, E_NOINTERFACE, E_POINTER, E_FAIL = 0x80004001, 0x80004002, 0x80004003, 0x80004005
VFW_E_NOT_FOUND, VFW_E_NO_AUDIO_HARDWARE = 0x80040216, 0x80040256
CLASS_E_NOAGGREGATION = 0x80040110
OATRUE, OAFALSE = 0xFFFFFFFF, 0
STATE_STOPPED, STATE_PAUSED, STATE_RUNNING = 0, 1, 2
AM_SEEKING_POSITIONING_MASK, AM_SEEKING_ABSOLUTE = 0x3, 0x1
UNITS = 10_000_000                      # REFERENCE_TIME: 100 ns
SKIP_KEY = 0x39                         # DIK_SPACE: the key a headless run "presses" to skip the intro


class Movie:
    """ctypes wrapper of libmpmovie for one open file."""
    lib = None

    @classmethod
    def load(cls):
        if cls.lib is None:
            lib = ctypes.CDLL(os.path.join(ROOT, "build", "libmpmovie.dylib"))
            V, I = ctypes.c_void_p, ctypes.c_int
            for name, args, res in (
                    ("mpm_open", [ctypes.c_char_p], V), ("mpm_info", [V] + [V] * 6, None),
                    ("mpm_next_frame", [V, ctypes.c_char_p, ctypes.POINTER(ctypes.c_double)], I),
                    ("mpm_seek", [V, ctypes.c_double], I), ("mpm_read_audio", [V, V, V], I), ("mpm_free", [V], None),
                    ("mpm_close", [V], None), ("mpm_present_bgra", [V, ctypes.c_char_p, I, I], I),
                    ("mpm_last_error", [], ctypes.c_char_p)):
                f = getattr(lib, name)
                f.argtypes, f.restype = args, res
            cls.lib = lib
        return cls.lib

    def __init__(self, path):
        lib = self.load()
        self.h = lib.mpm_open(path.encode())
        if not self.h:
            raise OSError(lib.mpm_last_error().decode())
        w, h, ar, ac = (ctypes.c_int() for _ in range(4))
        dur, fps = ctypes.c_double(), ctypes.c_double()
        lib.mpm_info(self.h, *(ctypes.byref(x) for x in (w, h, dur, fps, ar, ac)))
        self.width, self.height, self.duration, self.fps = w.value, h.value, dur.value, fps.value
        self.audio_rate, self.audio_channels = ar.value, ac.value
        self.frame = ctypes.create_string_buffer(max(self.width * self.height * 4, 4))
        self.ahead = ctypes.create_string_buffer(max(self.width * self.height * 4, 4))
        self.ahead_pts = None              # the next decoded frame, not yet due
        self.frame_pts = None              # pts of the frame in self.frame
        self.ended = False

    def audio(self):
        """The whole audio track as interleaved s16 bytes (b"" without audio)."""
        p, n = ctypes.c_void_p(), ctypes.c_uint32()
        if self.lib.mpm_read_audio(self.h, ctypes.byref(p), ctypes.byref(n)):
            raise OSError(self.lib.mpm_last_error().decode())
        if not p.value:
            return b""
        data = ctypes.string_at(p, n.value * 2 * self.audio_channels)
        self.lib.mpm_free(p)
        return data

    def advance(self, t):
        """Decode up to time t; True if self.frame changed."""
        changed = False
        while not self.ended:
            if self.ahead_pts is None:
                pts = ctypes.c_double()
                r = self.lib.mpm_next_frame(self.h, self.ahead, ctypes.byref(pts))
                if r <= 0:
                    self.ended = True
                    break
                self.ahead_pts = pts.value
            if self.ahead_pts > t:
                break
            self.frame, self.ahead = self.ahead, self.frame
            self.frame_pts, self.ahead_pts = self.ahead_pts, None
            changed = True
        return changed

    def seek(self, t):
        """Restart decoding at t: the next advance() shows the frame due at t."""
        self.lib.mpm_seek(self.h, t)
        self.ahead_pts = self.frame_pts = None
        self.ended = False

    def close(self):
        if self.h:
            self.lib.mpm_close(self.h)
            self.h = None


class Recorder:
    def __init__(self):
        self.calls = collections.Counter()
        self.events = []
        self.objs = {}           # interface object address -> graph state
        self.active = []         # running graphs

    def report(self):
        L = ["# DirectShow usage recorded from Max Payne (emulated run)", "",
             "Generated by `emu/dshow.py`.", "", "## Events"]
        L += ["- " + x for x in self.events]
        L.append("\n## Methods called (%d distinct)" % len(self.calls))
        L += ["- `%s` x%d" % (k, v) for k, v in sorted(self.calls.items(), key=lambda kv: (-kv[1], kv[0]))]
        return "\n".join(L) + "\n"


def recorder(e):
    if not hasattr(e, "dshow"):
        e.dshow = Recorder()
    return e.dshow


def install(m):
    if getattr(m, "_dshow_installed", False):
        return
    m._dshow_installed = True
    hle = m.hle
    DLL = "QUARTZ.DLL"

    def rec(e): return recorder(e)

    def out32(e, p, v):
        if p:
            e.wr32(p, v & 0xFFFFFFFF)

    def outf64(e, p, v):
        if p:
            e.wr(p, struct.pack("<d", v))

    def out64(e, p, v):
        if p:
            e.wr(p, struct.pack("<q", int(v)))

    def vtable(e, iface):
        vt = e.__dict__.setdefault("_vtables_" + DLL, {})
        if iface not in vt:
            methods = INTERFACES[iface]
            p = e.alloc(4 * len(methods))
            for i, (name, _) in enumerate(methods):
                e.wr32(p + 4 * i, e.stub_for(DLL, "%s::%s" % (iface, name)))
            vt[iface] = p
        return vt[iface]

    def new_graph(e):
        g = dict(refs=0, faces={}, movie=None, voice=None, state=STATE_STOPPED, pos=0.0, started=0.0,
                 visible=False, autoshow=True, owner=0, drain=0, style=0, fullscreen=False, rect=(0, 0, 0, 0),
                 file=None, skip_pressed=False, shown=0)
        for iface in INTERFACES:
            a = e.alloc(8)
            e.wr32(a, vtable(e, iface))
            g["faces"][iface] = a
            rec(e).objs[a] = g
        return g

    def graph(e, this): return rec(e).objs[this]

    def method(iface, name, fn=None, ret=E_NOTIMPL):
        n = dict(INTERFACES[iface])[name]

        def wrapped(e, this, *a):
            rec(e).calls["%s::%s" % (iface, name)] += 1
            if fn is None:
                return ret
            r = fn(e, graph(e, this), *a)
            return S_OK if r is None else r
        hle(DLL, "%s::%s" % (iface, name), 1 + n)(wrapped)

    # ------------------------------------------------------------ creation, IUnknown on every interface
    def create(e, outer, iid, ppv):
        if outer:
            out32(e, ppv, 0)
            return CLASS_E_NOAGGREGATION
        name = next((n for n, g in IID.items() if g == iid), None)
        name = ALIASES.get(name, name)
        g = new_graph(e)
        rec(e).events.append("CoCreateInstance(FilterGraph, %s)" % (name or uuid.UUID(bytes_le=iid)))
        if name not in INTERFACES:
            out32(e, ppv, 0)
            return E_NOINTERFACE
        g["refs"] = 1
        out32(e, ppv, g["faces"][name])
        return S_OK
    m.COM_CLASSES[CLSID_FILTERGRAPH] = ("FilterGraph", create)

    def qi(e, g, riid, ppv):
        want = e.rd(riid, 16)
        name = next((n for n, x in IID.items() if x == want), None)
        name = ALIASES.get(name, name)
        if name not in INTERFACES:
            rec(e).events.append("QueryInterface(%s) -> E_NOINTERFACE" % (name or uuid.UUID(bytes_le=want)))
            out32(e, ppv, 0)
            return E_NOINTERFACE
        g["refs"] += 1
        out32(e, ppv, g["faces"][name])

    def addref(e, g):
        g["refs"] += 1
        return g["refs"]

    def release(e, g):
        g["refs"] = max(g["refs"] - 1, 0)
        if g["refs"] == 0:
            stop(e, g)
            if g["voice"] is not None:
                mx = dsound.mixer(e)
                mx.lib.mpa_voice_free(mx.m, g["voice"])
                g["voice"] = None
            if g["movie"]:
                g["movie"].close()
                g["movie"] = None
        return g["refs"]

    for iface in INTERFACES:
        method(iface, "QueryInterface", qi)
        method(iface, "AddRef", addref)
        method(iface, "Release", release)

    # ------------------------------------------------------------ IGraphBuilder
    def render_file(e, g, pwfile, reserved):
        name = e.wstr(pwfile)
        path = e.host_path(name)
        try:
            mv = Movie(path)
        except OSError as ex:
            rec(e).events.append("RenderFile(%r) -> VFW_E_NOT_FOUND (%s)" % (name, ex))
            return VFW_E_NOT_FOUND
        g["movie"], g["file"] = mv, name
        audio = b""
        mx = dsound.mixer(e)
        if mv.audio_rate and mx:
            audio = mv.audio()
            if audio:
                v = mx.lib.mpa_voice_new(mx.m, mv.audio_channels, 16, mv.audio_rate, len(audio))
                if v >= 0:
                    mx.lib.mpa_voice_write(mx.m, v, 0, audio, len(audio))
                    g["voice"] = v
        rec(e).events.append("RenderFile(%r): %dx%d %.2f s %.2f fps, audio %d Hz %d ch%s" % (
            name, mv.width, mv.height, mv.duration, mv.fps, mv.audio_rate, mv.audio_channels,
            "" if g["voice"] is not None else " (not played: no mixer)" if mv.audio_rate else ""))
    method("IGraphBuilder", "RenderFile", render_file)
    for nm in ("AddFilter", "RemoveFilter", "EnumFilters", "FindFilterByName", "ConnectDirect", "Reconnect",
               "Disconnect", "SetDefaultSyncSource", "Connect", "Render", "AddSourceFilter", "SetLogFile",
               "Abort", "ShouldOperationContinue"):
        method("IGraphBuilder", nm)

    # ------------------------------------------------------------ the clock, video and audio
    def position(g):
        if g["state"] == STATE_RUNNING:
            return g["pos"] + time.perf_counter() - g["started"]
        return g["pos"]

    def run(e, g):
        if not g["movie"]:
            return VFW_E_NOT_FOUND
        if g["state"] != STATE_RUNNING:
            g["started"] = time.perf_counter()
            g["state"] = STATE_RUNNING
            if g["autoshow"]:
                g["visible"] = True
            if g["voice"] is not None:
                mx = dsound.mixer(e)
                mx.lib.mpa_voice_set_pos(mx.m, g["voice"], int(g["pos"] * g["movie"].audio_rate) * 2 * g["movie"].audio_channels)
                mx.lib.mpa_voice_play(mx.m, g["voice"], 0)
            if g not in rec(e).active:
                rec(e).active.append(g)
            rec(e).events.append("Run %r at %.2f s" % (g["file"], g["pos"]))
            live = getattr(e, "live", None)
            if not live and getattr(e, "intro", "play") == "skip" and not g["skip_pressed"]:
                import dinput
                dinput.input_state(e).key(SKIP_KEY, True)      # a player pressing a key: WM_KEYDOWN
                g["skip_pressed"] = True
                rec(e).events.append("headless run: pressed Space to skip %r" % g["file"])
            tick(e, g)

    def stop(e, g, new_state=STATE_STOPPED):
        if g["state"] == STATE_RUNNING:
            g["pos"] = min(position(g), g["movie"].duration if g["movie"] else 0)
            rec(e).events.append("%s %r at %.2f s (%d frames shown)" % (
                "Pause" if new_state == STATE_PAUSED else "Stop", g["file"], g["pos"], g["shown"]))
        g["state"] = new_state
        if g["voice"] is not None:
            mx = dsound.mixer(e)
            mx.lib.mpa_voice_stop(mx.m, g["voice"])
        if g in rec(e).active:
            rec(e).active.remove(g)
        if g["skip_pressed"]:
            import dinput
            dinput.input_state(e).key(SKIP_KEY, False)
            g["skip_pressed"] = False

    def tick(e, g):
        """Decode up to the clock; show the newest frame if the video window is visible."""
        mv = g["movie"]
        if not mv:
            return
        if mv.advance(position(g)) and g["visible"]:
            g["shown"] += 1
            live = getattr(e, "live", None)
            if live:
                live.show_bgra(mv.frame, mv.width, mv.height)
        live = getattr(e, "live", None)
        if live:
            live.pump()

    def on_sleep(e, ms):
        """Guest Sleep while a movie runs: wait for real, decoding and showing frames on time."""
        end = time.perf_counter() + ms / 1000.0
        while rec(e).active:
            for g in list(rec(e).active):
                tick(e, g)
            now = time.perf_counter()
            if now >= end:
                break
            nxt = min((g["movie"].ahead_pts - position(g) for g in rec(e).active
                       if g["movie"] and g["movie"].ahead_pts is not None), default=0.01)
            time.sleep(max(0.001, min(end - now, nxt, 0.02)))
    m.SLEEP_HOOKS.append(lambda e, ms: on_sleep(e, ms) if hasattr(e, "dshow") and e.dshow.active else None)

    # ------------------------------------------------------------ IMediaControl
    method("IMediaControl", "Run", run)
    method("IMediaControl", "Pause", lambda e, g: stop(e, g, STATE_PAUSED))
    method("IMediaControl", "Stop", stop)
    method("IMediaControl", "StopWhenReady", stop)
    method("IMediaControl", "GetState", lambda e, g, timeout, p: out32(e, p, g["state"]))
    for nm in ("GetTypeInfoCount", "GetTypeInfo", "GetIDsOfNames", "Invoke"):
        for iface in ("IMediaControl", "IMediaPosition", "IVideoWindow", "IBasicVideo", "IBasicAudio"):
            method(iface, nm)
    for nm in ("RenderFile", "AddSourceFilter", "get_FilterCollection", "get_RegFilterCollection"):
        method("IMediaControl", nm)

    # ------------------------------------------------------------ IMediaPosition (seconds, double)
    def duration(g): return g["movie"].duration if g["movie"] else 0.0

    def get_current(e, g, p):
        tick(e, g)
        outf64(e, p, min(position(g), duration(g)))

    def seek(e, g, t):
        t = max(0.0, min(t, duration(g)))
        mv = g["movie"]
        if mv and not (mv.frame_pts is not None and mv.frame_pts <= t < mv.frame_pts + 1.0):
            mv.seek(t)                                   # backwards or far ahead: restart decoding there
        g["pos"], g["started"] = t, time.perf_counter()
        if g["voice"] is not None and mv:
            mx = dsound.mixer(e)
            mx.lib.mpa_voice_set_pos(mx.m, g["voice"], int(t * mv.audio_rate) * 2 * mv.audio_channels)

    def f64(lo, hi): return struct.unpack("<d", struct.pack("<II", lo, hi))[0]

    method("IMediaPosition", "get_Duration", lambda e, g, p: outf64(e, p, duration(g)))
    method("IMediaPosition", "get_CurrentPosition", get_current)
    method("IMediaPosition", "put_CurrentPosition", lambda e, g, lo, hi: seek(e, g, f64(lo, hi)))
    method("IMediaPosition", "get_StopTime", lambda e, g, p: outf64(e, p, duration(g)))
    method("IMediaPosition", "get_PrerollTime", lambda e, g, p: outf64(e, p, 0.0))
    method("IMediaPosition", "get_Rate", lambda e, g, p: outf64(e, p, 1.0))
    method("IMediaPosition", "CanSeekForward", lambda e, g, p: out32(e, p, OATRUE))
    method("IMediaPosition", "CanSeekBackward", lambda e, g, p: out32(e, p, OATRUE))
    for nm in ("put_StopTime", "put_PrerollTime", "put_Rate"):
        method("IMediaPosition", nm)

    # ------------------------------------------------------------ IMediaSeeking (REFERENCE_TIME, 100 ns)
    def set_positions(e, g, pcur, cur_flags, pstop, stop_flags):
        if pcur and cur_flags & AM_SEEKING_POSITIONING_MASK == AM_SEEKING_ABSOLUTE:
            seek(e, g, struct.unpack("<q", e.rd(pcur, 8))[0] / UNITS)
        elif pcur and cur_flags & AM_SEEKING_POSITIONING_MASK:             # relative / incremental
            seek(e, g, position(g) + struct.unpack("<q", e.rd(pcur, 8))[0] / UNITS)
        rec(e).events.append("SetPositions -> %.2f s" % g["pos"])

    method("IMediaSeeking", "SetPositions", set_positions)
    method("IMediaSeeking", "GetDuration", lambda e, g, p: out64(e, p, duration(g) * UNITS))
    method("IMediaSeeking", "GetStopPosition", lambda e, g, p: out64(e, p, duration(g) * UNITS))
    method("IMediaSeeking", "GetCurrentPosition", lambda e, g, p: (tick(e, g), out64(e, p, min(position(g), duration(g)) * UNITS))[-1])

    def get_positions(e, g, pcur, pstop):
        out64(e, pcur, min(position(g), duration(g)) * UNITS)
        out64(e, pstop, duration(g) * UNITS)
    method("IMediaSeeking", "GetPositions", get_positions)
    method("IMediaSeeking", "GetCapabilities", lambda e, g, p: out32(e, p, 0x1 | 0x2 | 0x4 | 0x8 | 0x100))
    method("IMediaSeeking", "GetTimeFormat", lambda e, g, p: e.wr(p, guid("7B785574-8C82-11CF-BC0C-00AA00AC74F6")) if p else None)
    method("IMediaSeeking", "GetRate", lambda e, g, p: outf64(e, p, 1.0))
    for nm in ("CheckCapabilities", "IsFormatSupported", "QueryPreferredFormat", "IsUsingTimeFormat",
               "SetTimeFormat", "ConvertTimeFormat", "GetAvailable", "SetRate", "GetPreroll"):
        method("IMediaSeeking", nm)

    # ------------------------------------------------------------ IVideoWindow (the frames go to the live window)
    V = "IVideoWindow"

    def needs_video(fn):
        def f(e, g, *a):
            if not g["movie"] or not g["movie"].width:
                return E_NOINTERFACE                     # no video stream rendered: VFW_E_NOT_CONNECTED-like
            return fn(e, g, *a)
        return f

    def put(key, conv=lambda v: v, log=False):
        def f(e, g, v):
            g[key] = conv(v)
            if log:
                rec(e).events.append("IVideoWindow::put_%s(0x%x)" % (key, v))
        return needs_video(f)

    method(V, "put_Visible", put("visible", lambda v: v != OAFALSE))
    method(V, "get_Visible", needs_video(lambda e, g, p: out32(e, p, OATRUE if g["visible"] else OAFALSE)))
    method(V, "put_AutoShow", put("autoshow", lambda v: v != OAFALSE))
    method(V, "get_AutoShow", needs_video(lambda e, g, p: out32(e, p, OATRUE if g["autoshow"] else OAFALSE)))
    method(V, "put_Owner", put("owner", log=True))
    method(V, "get_Owner", needs_video(lambda e, g, p: out32(e, p, g["owner"])))
    method(V, "put_MessageDrain", put("drain"))
    method(V, "get_MessageDrain", needs_video(lambda e, g, p: out32(e, p, g["drain"])))
    method(V, "put_WindowStyle", put("style", log=True))
    method(V, "get_WindowStyle", needs_video(lambda e, g, p: out32(e, p, g["style"])))
    method(V, "put_FullScreenMode", put("fullscreen", lambda v: v != OAFALSE, log=True))
    method(V, "get_FullScreenMode", needs_video(lambda e, g, p: out32(e, p, OATRUE if g["fullscreen"] else OAFALSE)))

    def set_window_pos(e, g, x, y, w, h):
        g["rect"] = (x, y, w, h)
    method(V, "SetWindowPosition", needs_video(set_window_pos))

    def get_window_pos(e, g, px, py, pw, ph):
        for p, v in zip((px, py, pw, ph), g["rect"]):
            out32(e, p, v)
    method(V, "GetWindowPosition", needs_video(get_window_pos))
    method(V, "HideCursor", needs_video(lambda e, g, v: None))
    method(V, "SetWindowForeground", needs_video(lambda e, g, v: None))
    method(V, "NotifyOwnerMessage", needs_video(lambda e, g, *a: None))
    done = {"put_Visible", "get_Visible", "put_AutoShow", "get_AutoShow", "put_Owner", "get_Owner", "put_MessageDrain",
            "get_MessageDrain", "put_WindowStyle", "get_WindowStyle", "put_FullScreenMode", "get_FullScreenMode",
            "SetWindowPosition", "GetWindowPosition", "HideCursor", "SetWindowForeground", "NotifyOwnerMessage"}
    for nm, _ in INTERFACES[V][len(_IDISPATCH):]:
        if nm not in done:           # setters (captions, borders, size...) accepted and ignored; getters unsupported
            method(V, nm, needs_video(lambda e, g, *a: None) if not nm.startswith(("get_", "Get", "Is")) else None)

    # ------------------------------------------------------------ IBasicVideo / IBasicAudio
    BV = "IBasicVideo"

    def video_size(e, g, pw, ph):
        out32(e, pw, g["movie"].width)
        out32(e, ph, g["movie"].height)
    method(BV, "GetVideoSize", needs_video(video_size))
    method(BV, "get_VideoWidth", needs_video(lambda e, g, p: out32(e, p, g["movie"].width)))
    method(BV, "get_VideoHeight", needs_video(lambda e, g, p: out32(e, p, g["movie"].height)))
    method(BV, "get_AvgTimePerFrame", needs_video(lambda e, g, p: outf64(e, p, 1.0 / (g["movie"].fps or 25))))
    for nm, _ in INTERFACES[BV][len(_IDISPATCH):]:
        if nm not in ("GetVideoSize", "get_VideoWidth", "get_VideoHeight", "get_AvgTimePerFrame"):
            method(BV, nm, needs_video(lambda e, g, *a: None) if not nm.startswith(("get_", "Get", "Is")) else None)
    for nm in ("put_Volume", "get_Volume", "put_Balance", "get_Balance"):
        method("IBasicAudio", nm)
