"""DirectSound (DirectX 8-era dsound.dll) for the emulator.

What the game's sound library (sndmfc.dll) needs: DirectSoundEnumerateA (DSOUND ordinal 2) to list devices, then a
DirectSound object (created through COM or DirectSoundCreate), a primary buffer with a 3D listener, and secondary
buffers (static and streaming) with optional 3D control. This module provides all of it as fake COM objects in
guest memory with correct vtable layouts and stdcall argument counts, and records everything the game does.

Sound comes out through libmpaudio (audio/, `make -C audio`), a software mixer: each secondary buffer is a mixer
voice, Unlock copies the written regions to it, and the voice's position is the buffer's play cursor. Volume, pan,
frequency and the DS3D model (distance rolloff, cones, listener-relative pan, doppler, deferred settings) are
computed here and handed to the voice as left/right gains and a playback rate. The mixer is used when the
emulator's `audio` attribute is "device" (the default playback device) or "null" (consumed at the real-time rate,
silent); `audio_record` names a WAV file for the mixed output. Without a mixer the play cursor advances with the
host clock and nothing is heard.

Once lifted code runs natively (emu/native.py HleFast, H62), lift/runtime/hle_fast.c serves IDirectSoundBuffer Lock,
Unlock, GetCurrentPosition and SetVolume: the buffers' run state lives there (the buffer dicts become _FastBuf views)
and C calls the mixer itself (attach_fast).

Usage: dsound.install(mpemu_module) once, before running guest code (mpemu.boot does this).
"""
import collections
import ctypes
import math
import os
import struct
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_IUNKNOWN = [("QueryInterface", 2), ("AddRef", 0), ("Release", 0)]

IDIRECTSOUND = _IUNKNOWN + [
    ("CreateSoundBuffer", 3), ("GetCaps", 1), ("DuplicateSoundBuffer", 2), ("SetCooperativeLevel", 2),
    ("Compact", 0), ("GetSpeakerConfig", 1), ("SetSpeakerConfig", 1), ("Initialize", 1)]
IDIRECTSOUNDBUFFER = _IUNKNOWN + [
    ("GetCaps", 1), ("GetCurrentPosition", 2), ("GetFormat", 3), ("GetVolume", 1), ("GetPan", 1),
    ("GetFrequency", 1), ("GetStatus", 1), ("Initialize", 2), ("Lock", 7), ("Play", 3),
    ("SetCurrentPosition", 1), ("SetFormat", 1), ("SetVolume", 1), ("SetPan", 1), ("SetFrequency", 1),
    ("Stop", 0), ("Unlock", 4), ("Restore", 0)]
IDIRECTSOUND3DLISTENER = _IUNKNOWN + [
    ("GetAllParameters", 1), ("GetDistanceFactor", 1), ("GetDopplerFactor", 1), ("GetOrientation", 2),
    ("GetPosition", 1), ("GetRolloffFactor", 1), ("GetVelocity", 1), ("SetAllParameters", 2),
    ("SetDistanceFactor", 2), ("SetDopplerFactor", 2), ("SetOrientation", 7), ("SetPosition", 4),
    ("SetRolloffFactor", 2), ("SetVelocity", 4), ("CommitDeferredSettings", 0)]
IDIRECTSOUND3DBUFFER = _IUNKNOWN + [
    ("GetAllParameters", 1), ("GetConeAngles", 2), ("GetConeOrientation", 1), ("GetConeOutsideVolume", 1),
    ("GetMaxDistance", 1), ("GetMinDistance", 1), ("GetMode", 1), ("GetPosition", 1), ("GetVelocity", 1),
    ("SetAllParameters", 2), ("SetConeAngles", 3), ("SetConeOrientation", 4), ("SetConeOutsideVolume", 2),
    ("SetMaxDistance", 2), ("SetMinDistance", 2), ("SetMode", 2), ("SetPosition", 4), ("SetVelocity", 4)]
IDIRECTSOUNDNOTIFY = _IUNKNOWN + [("SetNotificationPositions", 2)]

INTERFACES = {
    "IDirectSound": IDIRECTSOUND, "IDirectSoundBuffer": IDIRECTSOUNDBUFFER,
    "IDirectSound3DListener": IDIRECTSOUND3DLISTENER, "IDirectSound3DBuffer": IDIRECTSOUND3DBUFFER,
    "IDirectSoundNotify": IDIRECTSOUNDNOTIFY,
}


def guid(s): return uuid.UUID(s).bytes_le


IID = {
    "IUnknown": guid("00000000-0000-0000-C000-000000000046"),
    "IDirectSound": guid("279AFA83-4981-11CE-A521-0020AF0BE560"),
    "IDirectSoundBuffer": guid("279AFA85-4981-11CE-A521-0020AF0BE560"),
    "IDirectSound3DListener": guid("279AFA84-4981-11CE-A521-0020AF0BE560"),
    "IDirectSound3DBuffer": guid("279AFA86-4981-11CE-A521-0020AF0BE560"),
    "IDirectSoundNotify": guid("B0210783-89CD-11D0-AF08-00A0C925CD16"),
}
CLSID_DIRECTSOUND = guid("47D4D946-62E8-11CF-93BC-444553540000")
CLSID_DIRECTSOUND8 = guid("3901CC3F-84B5-4FA4-BA35-AA8172B8A09B")

DS_OK = 0
E_NOINTERFACE = 0x80004002
DSERR_INVALIDPARAM = 0x80070057
DSERR_UNSUPPORTED = 0x80004001
DSERR_NOAGGREGATION = 0x80040110
REGDB_E_CLASSNOTREG = 0x80040154

DSBCAPS = {0x1: "PRIMARYBUFFER", 0x2: "STATIC", 0x4: "LOCHARDWARE", 0x8: "LOCSOFTWARE", 0x10: "CTRL3D",
           0x20: "CTRLFREQUENCY", 0x40: "CTRLPAN", 0x80: "CTRLVOLUME", 0x100: "CTRLPOSITIONNOTIFY",
           0x200: "CTRLFX", 0x10000: "STICKYFOCUS", 0x20000: "GLOBALFOCUS", 0x40000: "GETCURRENTPOSITION2",
           0x80000: "MUTE3DATMAXDISTANCE"}
COOP_LEVELS = {1: "NORMAL", 2: "PRIORITY", 3: "EXCLUSIVE", 4: "WRITEPRIMARY"}
DSBSTATUS_PLAYING, DSBSTATUS_BUFFERLOST, DSBSTATUS_LOOPING = 0x1, 0x2, 0x4
DSBPLAY_LOOPING = 0x1
DSBLOCK_FROMWRITECURSOR, DSBLOCK_ENTIREBUFFER = 0x1, 0x2
DS3D_DEFERRED = 0x1
DS3DMODE_NORMAL, DS3DMODE_HEADRELATIVE, DS3DMODE_DISABLE = 0, 1, 2
WRITE_LEAD_FRAMES = 768          # write cursor ahead of the play cursor (about 17 ms at 44.1 kHz)
SPEED_OF_SOUND = 343.3           # m/s; DirectSound units are metres times the listener's distance factor
FAR_EAR_DB = -12.0               # 3D pan: attenuation of the far ear for a source straight to the side
MIX_RATE = 44100


def s32(v): return v - (1 << 32) if v & 0x80000000 else v


def db_gain(hundredths):
    """DirectSound volume (hundredths of a decibel, 0 = full, -10000 = silent) as a linear gain."""
    return 0.0 if hundredths <= -10000 else 10.0 ** (min(hundredths, 0) / 2000.0)


def pan_gains(pan):
    """DirectSound pan (-10000 left .. 10000 right) attenuates the opposite channel."""
    return db_gain(-pan) if pan > 0 else 1.0, db_gain(pan) if pan < 0 else 1.0


def _sub(a, b): return (a[0] - b[0], a[1] - b[1], a[2] - b[2])
def _dot(a, b): return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
def _cross(a, b): return (a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0])


def _unit(a):
    n = math.sqrt(_dot(a, a))
    return (a[0] / n, a[1] / n, a[2] / n) if n > 1e-9 else (0.0, 0.0, 0.0)


def gains_3d(lst, q):
    """Left gain, right gain and doppler frequency ratio of a 3D buffer (parameters q) heard by listener lst.

    Distance: full volume up to the minimum distance, then min / (min + rolloff * (d - min)), no further change
    past the maximum distance (DirectSound's model). Cone: full inside the inner angle, the outside volume beyond
    the outer angle, interpolated in decibels between. Pan: the far ear is attenuated by up to FAR_EAR_DB as the
    source moves to the side (DirectSound's software 3D panning, approximated; no HRTF). Coordinates are
    left-handed (x right, y up, z forward), so the listener's right is top x front."""
    if q["mode"] == DS3DMODE_HEADRELATIVE:
        rel = q["position"]
        right, front, top = (1.0, 0.0, 0.0), (0.0, 0.0, 1.0), (0.0, 1.0, 0.0)
        lvel = (0.0, 0.0, 0.0)
    else:
        rel = _sub(q["position"], lst["position"])
        front, top = _unit(lst["front"]), _unit(lst["top"])
        right = _unit(_cross(top, front))
        lvel = lst["velocity"]
    d = math.sqrt(_dot(rel, rel))
    mn, mx = max(q["min_distance"], 1e-6), max(q["max_distance"], q["min_distance"])
    dd = min(d, mx)
    gain = 1.0 if dd <= mn else mn / (mn + lst["rolloff_factor"] * (dd - mn))
    inside, outside = q["inside_angle"], q["outside_angle"]
    if d > 1e-6 and inside < 360 and _dot(q["cone_orientation"], q["cone_orientation"]) > 0:
        to_listener = (-rel[0] / d, -rel[1] / d, -rel[2] / d)
        c = max(-1.0, min(1.0, _dot(_unit(q["cone_orientation"]), to_listener)))
        angle = math.degrees(math.acos(c)) * 2         # compared with the full cone angles
        if angle > inside:
            t = 1.0 if angle >= outside or outside <= inside else (angle - inside) / (outside - inside)
            gain *= db_gain(int(q["outside_volume"] * t))
    gl = gr = gain
    if d > 1e-6:
        x = _dot(rel, right) / d                       # -1 left .. 1 right
        far = 10.0 ** (FAR_EAR_DB * abs(x) / 20.0)
        if x > 0:
            gl *= far
        else:
            gr *= far
    ratio = 1.0
    if d > 1e-6 and lst["doppler_factor"] > 0:
        c_units = SPEED_OF_SOUND / max(lst["distance_factor"], 1e-6)
        u = (-rel[0] / d, -rel[1] / d, -rel[2] / d)    # source -> listener
        k = lst["doppler_factor"]
        num = c_units - k * _dot(lvel, u)
        den = c_units - k * _dot(q["velocity"], u)
        if den > 1e-6 and num > 0:
            ratio = max(0.5, min(2.0, num / den))
    return gl, gr, ratio


class Mixer:
    """ctypes wrapper of libmpaudio. device: "device" (default playback device) or "null" (silent, real-time)."""

    def __init__(self, device="device", record=None):
        lib = self.lib = ctypes.CDLL(os.path.join(ROOT, "build", "libmpaudio.dylib"))
        V, I, U = ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32
        for name, args, res in (
                ("mpa_create", [I, I], V), ("mpa_destroy", [V], None), ("mpa_record", [V, ctypes.c_char_p], I),
                ("mpa_render", [V, ctypes.POINTER(ctypes.c_float), I], None),
                ("mpa_voice_new", [V, I, I, I, U], I), ("mpa_voice_free", [V, I], None),
                ("mpa_voice_write", [V, I, U, ctypes.c_char_p, U], None), ("mpa_voice_play", [V, I, I], None),
                ("mpa_voice_stop", [V, I], None), ("mpa_voice_set_pos", [V, I, U], None),
                ("mpa_voice_get_pos", [V, I, ctypes.POINTER(I)], U), ("mpa_voice_set_freq", [V, I, ctypes.c_double], None),
                ("mpa_voice_set_gain", [V, I, ctypes.c_float, ctypes.c_float, I], None),
                ("mpa_frames_out", [V], ctypes.c_uint64), ("mpa_voice_stale", [V, I], ctypes.c_uint64), ("mpa_last_error", [], ctypes.c_char_p)):
            f = getattr(lib, name)
            f.argtypes, f.restype = args, res
        self.m = lib.mpa_create(MIX_RATE, {"device": 1, "null": 0, "none": -1}[device])
        if not self.m and device == "device":
            print("[dsound] no audio device (%s); mixing silently" % lib.mpa_last_error().decode())
            self.m = lib.mpa_create(MIX_RATE, 0)
        self.device = device
        if record:
            if lib.mpa_record(self.m, record.encode()):
                raise RuntimeError(lib.mpa_last_error().decode())

    def close(self):
        if self.m:
            if self.fast:                                 # hle_fast.c must not call a destroyed mixer
                self.fast.ds_mixer(None)
            self.lib.mpa_destroy(self.m)
            self.m = None

    fast = None                                           # native.HleFast that calls this mixer (H62)


def mixer(e):
    """The emulator's mixer, created on first use when e.audio asks for one (None otherwise)."""
    mx = getattr(e, "_ds_mixer", False)
    if mx is False:
        mx = None
        mode = getattr(e, "audio", None)
        if mode:
            try:
                mx = Mixer(mode, getattr(e, "audio_record", None))
            except OSError as ex:
                print("[dsound] libmpaudio not available (%s; run make -C audio): no sound" % ex)
        e._ds_mixer = mx
        if hasattr(e, "ds"):
            e.ds.mixer = mx
            if mx and e.ds._fast:
                mx.fast = e.ds._fast
                mx.fast.ds_mixer(mx)
    return mx


def _voice(v): return None if v < 0 else int(v)


class _FastBuf(dict):
    """A buffer's state once hle_fast.c serves its Lock, Unlock, GetCurrentPosition and SetVolume (H62): the run-state
    keys live in C (field numbers of lift_hle_fast_ds_field), the rest here; the layout keys are copied to C when they
    change, and update_voice copies the voice's gains (set_gains)."""
    RUN = {"volume": (0, int), "playing": (1, bool), "looping": (2, bool), "pos": (3, int), "started": (4, float),
           "unlocks": (5, int), "written": (6, int), "voice": (7, _voice)}
    LAYOUT = ("ptr", "size", "wfx")

    def attach(self, fast, this):
        self.fast, self.slot = fast, fast.ds_new(this)
        self._push_cfg()
        for k in self.RUN:
            if dict.__contains__(self, k):
                self[k] = dict.pop(self, k)

    def _push_cfg(self):
        self.fast.ds_cfg(self.slot, self.get("ptr", 0), self.get("size", 0), self.get("wfx"))

    def set_gains(self, gl, gr, downmix):
        self.fast.ds_gains(self.slot, gl, gr, downmix)

    def __getitem__(self, k):
        f = self.RUN.get(k)
        return f[1](self.fast.ds_field(self.slot, f[0])) if f else dict.__getitem__(self, k)

    def get(self, k, default=None):
        return self[k] if k in self else default

    def __contains__(self, k):
        return k in self.RUN or dict.__contains__(self, k)

    def __setitem__(self, k, v):
        f = self.RUN.get(k)
        if f:
            self.fast.ds_field(self.slot, f[0], -1 if v is None and k == "voice" else v)
            return
        dict.__setitem__(self, k, v)
        if k in self.LAYOUT:
            self._push_cfg()


_update_voice = None                                      # install's update_voice (for attach_fast)


def attach_fast(e, fast):
    """Move the buffers' run state into lift/runtime/hle_fast.c (native.HleFast, H62), which then serves Lock, Unlock,
    GetCurrentPosition and SetVolume from lifted code; buffers created later go there when created."""
    if not hasattr(e, "ds"):
        e.ds = Recorder()
    r = e.ds
    r._fast = fast
    for a, o in list(r.objs.items()):
        if o.get("iface") != "IDirectSoundBuffer":
            continue
        f = r.objs[a] = _FastBuf(o)
        f.attach(fast, a)
        if "p3" in f:
            f["p3"]["buffer_obj"] = f
        _update_voice(e, f)
    mx = getattr(e, "_ds_mixer", None)
    if mx:
        mx.fast = fast
        fast.ds_mixer(mx)


def wfx_text(w): return "%dch %dHz %d-bit tag=%d avg=%dB/s" % (w["channels"], w["rate"], w["bits"], w["tag"], w["avg"])


def flag_text(flags, table):
    return "|".join(n for b, n in sorted(table.items()) if flags & b) or "0"


class Recorder:
    _fast = None                               # native.HleFast once the buffer calls are served in C (H62)

    def __init__(self):
        self.calls = collections.Counter()
        self.buffers = []            # descriptions of created buffers
        self.formats = collections.Counter()
        self.events = []             # cooperative level, speaker config, enumeration, etc.
        self.com = []                # CoCreateInstance requests (clsid, iid, result)
        self.plays = collections.Counter()
        self.listener_sets = collections.Counter()
        self.objs = {}

    def report(self):
        if self._fast:
            self._fast.merge()                 # what the C handlers counted
        L = ["# DirectSound usage recorded from Max Payne (emulated run)", ""]
        L.append("Generated by `emu/dsound.py`. Capabilities the game was *given* (devices, caps) are chosen by the emulator.\n")
        L.append("## Events")
        L += ["- " + x for x in self.events]
        L.append("\n## COM creation requests")
        L += ["- " + x for x in self.com]
        L.append("\n## Methods called (%d distinct)" % len(self.calls))
        L += ["- `%s` x%d" % (k, v) for k, v in sorted(self.calls.items(), key=lambda kv: (-kv[1], kv[0]))]
        L.append("\n## Sound buffers created (%d)" % len(self.buffers))
        L += ["- " + x for x in self.buffers[:60]]
        L.append("\n## Wave formats requested")
        L += ["- %s x%d" % (k, v) for k, v in self.formats.most_common()]
        L.append("\n## 3D listener/buffer parameters set")
        L += ["- %s x%d" % (k, v) for k, v in sorted(self.listener_sets.items())]
        L.append("\n## Secondary buffers at the end of the run")
        L.append("| buffer | format | flags | unlocks | bytes written | plays | 3D sets | 3D position | released | stale data played (ms) |")
        L.append("|---|---|---|---|---|---|---|---|---|---|")
        mx = getattr(self, "mixer", None)
        for a, o in sorted(self.objs.items()):
            if o.get("iface") != "IDirectSoundBuffer" or o["flags"] & 1:
                continue
            if mx and mx.m and o.get("voice") is not None:
                o["stale"] = mx.lib.mpa_voice_stale(mx.m, o["voice"])
            q = o.get("p3")
            L.append("| 0x%x | %s | %s | %d | %d | %d | %s | %s | %s | %s |" % (
                a, wfx_text(o["wfx"]).split(" tag")[0], "3D" if q else "-", o.get("unlocks", 0), o.get("written", 0),
                o.get("plays", 0), q.get("sets", 0) if q else "-",
                "(%.1f, %.1f, %.1f)" % q["position"] if q else "-", "yes" if o.get("released") else "",
                "%.0f" % (1000.0 * o["stale"] / o["wfx"]["rate"]) if o.get("stale") else ""))
        if hasattr(self, "listener"):
            L.append("\nListener at the end: position (%.1f, %.1f, %.1f), front (%.2f, %.2f, %.2f), rolloff %g" % (
                *self.listener["position"], *self.listener["front"], self.listener["rolloff_factor"]))
        return "\n".join(L) + "\n"


def install(m):
    if getattr(m, "_dsound_installed", False):
        return
    m._dsound_installed = True
    hle, GuestCall = m.hle, m.GuestCall
    DLL = "DSOUND.DLL"

    def rec(e):
        if not hasattr(e, "ds"):
            e.ds = Recorder()
        return e.ds

    def vtable(e, iface):
        vtables = e.__dict__.setdefault("_vtables_" + DLL, {})    # per emulator (id(e) gets reused)
        if iface not in vtables:
            methods = INTERFACES[iface]
            p = e.alloc(4 * len(methods))
            for i, (name, _) in enumerate(methods):
                e.wr32(p + 4 * i, e.stub_for(DLL, "%s::%s" % (iface, name)))
            vtables[iface] = p
        return vtables[iface]

    def new_obj(e, iface, **state):
        a = e.alloc(16)
        e.wr32(a, vtable(e, iface))
        e.wr32(a + 4, 1)
        state["iface"] = iface
        if iface == "IDirectSoundBuffer" and rec(e)._fast:
            state = _FastBuf(state)
            state.attach(rec(e)._fast, a)
        rec(e).objs[a] = state
        return a

    def obj(e, this): return rec(e).objs.get(this, {})

    def out32(e, p, v):
        if p:
            e.wr32(p, v)

    def reg_method(iface, name, nparams, fn):
        hle(DLL, "%s::%s" % (iface, name), 1 + nparams)(fn)

    def logged(iface, name, extra=None, ret=DS_OK):
        key = "%s::%s" % (iface, name)

        def fn(e, this, *a):
            rec(e).calls[key] += 1
            if extra:
                r = extra(e, this, *a)
                return ret if r is None else r
            return ret
        return fn

    def f32(v): return struct.unpack("<f", struct.pack("<I", v))[0]

    def sub_obj(e, o, key, iface, buffer):
        """The interface object a buffer hands out through QueryInterface (one per buffer, created unreferenced)."""
        if key not in o:
            o[key] = new_obj(e, iface, buffer=buffer)
            e.wr32(o[key] + 4, 0)
        return o[key]

    # ------------------------------------------------------------ IUnknown for every interface
    def make_qi(iface):
        def qi(e, this, riid, ppv):
            r = rec(e)
            r.calls["%s::QueryInterface" % iface] += 1
            want = e.rd(riid, 16)
            name = next((n for n, g in IID.items() if g == want), None)
            o = obj(e, this)
            result = None
            if name in ("IUnknown", iface):
                result = this
            elif iface == "IDirectSoundBuffer" and name == "IDirectSound3DBuffer" and o.get("flags", 0) & 0x10:
                result = sub_obj(e, o, "_3d", "IDirectSound3DBuffer", this)
            elif iface == "IDirectSoundBuffer" and name == "IDirectSound3DListener" and o.get("flags", 0) & 0x1 \
                    and o.get("flags", 0) & 0x10:
                result = sub_obj(e, o, "_listener", "IDirectSound3DListener", this)
            elif iface == "IDirectSoundBuffer" and name == "IDirectSoundNotify" and o.get("flags", 0) & 0x100:
                result = sub_obj(e, o, "_notify", "IDirectSoundNotify", this)
            r.events.append("QueryInterface(%s) on %s -> %s" % (name or uuid.UUID(bytes_le=want), iface,
                                                                 "ok" if result else "E_NOINTERFACE"))
            if result is None:
                out32(e, ppv, 0)
                return E_NOINTERFACE
            e.wr32(result + 4, e.rd32(result + 4) + 1)
            out32(e, ppv, result)
            return DS_OK
        return qi

    for iface in INTERFACES:
        def addref(e, this, _i=iface):
            n = e.rd32(this + 4) + 1
            e.wr32(this + 4, n)
            rec(e).calls["%s::AddRef" % _i] += 1
            return n

        def release(e, this, _i=iface):
            n = max(e.rd32(this + 4) - 1, 0)
            e.wr32(this + 4, n)
            rec(e).calls["%s::Release" % _i] += 1
            if n == 0:
                released(e, this, _i)
            return n
        reg_method(iface, "AddRef", 0, addref)
        reg_method(iface, "Release", 0, release)
        reg_method(iface, "QueryInterface", 2, make_qi(iface))

    def released(e, this, iface):
        """Last reference gone: a buffer stops sounding (once its 3D interface is released too); releasing the
        DirectSound object frees all of its buffers, as DirectSound does."""
        o = obj(e, this)
        if iface == "IDirectSound3DBuffer":
            this, o = o["buffer"], obj(e, o["buffer"])
            iface = "IDirectSoundBuffer"
        if iface == "IDirectSoundBuffer":
            o["released"] = e.rd32(this + 4) == 0
            if e.rd32(this + 4) == 0 and not ("_3d" in o and e.rd32(o["_3d"] + 4)):
                free_voice(e, o)
        elif iface == "IDirectSound":
            for b in rec(e).objs.values():
                if b.get("iface") == "IDirectSoundBuffer" and b.get("ds") == this:
                    free_voice(e, b)

    # ------------------------------------------------------------ enumeration and creation
    @hle(DLL, "#2", 2)
    @hle(DLL, "DirectSoundEnumerateA", 2)
    def enumerate_a(e, callback, context):
        """DirectSoundEnumerateA(callback, context): call back once for the default device (NULL guid) and
        once for the named device, stopping if the callback returns FALSE."""
        r = rec(e)
        r.calls["DirectSoundEnumerateA"] += 1
        dev_guid = e.alloc(16)
        e.wr(dev_guid, guid("A5E2F6C3-1B1D-4C8E-9F3A-6D1F4E7B2C90"))
        devices = [(0, b"Primary Sound Driver", b""),
                   (dev_guid, b"Apple CoreAudio (emulated)", b"coreaudio.drv")]
        for g, desc, mod in devices:
            pd, pm = e.alloc(len(desc) + 1), e.alloc(len(mod) + 1)
            e.wr(pd, desc + b"\0")
            e.wr(pm, mod + b"\0")
            cont = yield GuestCall(callback, (g, pd, pm, context), "stdcall")
            r.events.append("enumerated %r (callback returned %d)" % (desc.decode(), cont & 0xFFFFFFFF))
            if not (cont & 0xFFFFFFFF):
                break
        return DS_OK

    def create_ds(e, pguid, ppds, outer):
        r = rec(e)
        r.calls["DirectSoundCreate"] += 1
        if outer:
            return DSERR_NOAGGREGATION
        ds = new_obj(e, "IDirectSound", coop=0, primary=0, buffers=[])
        r.events.append("DirectSoundCreate(guid=%s)" % ("default" if not pguid else uuid.UUID(bytes_le=e.rd(pguid, 16))))
        out32(e, ppds, ds)
        return DS_OK
    hle(DLL, "#1", 3)(create_ds)
    hle(DLL, "DirectSoundCreate", 3)(create_ds)

    def co_create(e, outer, iid, ppv, _name=None):
        r = rec(e)
        iid_name = next((n for n, g in IID.items() if g == iid), str(uuid.UUID(bytes_le=iid)))
        if outer:
            out32(e, ppv, 0)
            return DSERR_NOAGGREGATION
        ds = new_obj(e, "IDirectSound", coop=0, primary=0, buffers=[], uninitialized=True)
        r.com.append("CoCreateInstance(%s, %s) -> object" % (_name, iid_name))
        out32(e, ppv, ds)
        return DS_OK
    for clsid, name in ((CLSID_DIRECTSOUND, "DirectSound"), (CLSID_DIRECTSOUND8, "DirectSound8")):
        m.COM_CLASSES[clsid] = (name, lambda e, outer, iid, ppv, _n=name: co_create(e, outer, iid, ppv, _n))

    # ------------------------------------------------------------ IDirectSound
    D = "IDirectSound"

    def caps(e, this, p):
        size = e.rd32(p)
        c = [0] * 24
        c[0] = size or 96
        c[1] = 0x2 | 0x8 | 0x10 | 0x200 | 0x800       # primary stereo/16-bit, continuous rate, secondary stereo/16-bit
        c[2], c[3] = 4000, 96000                      # secondary sample rate range
        c[4] = 1                                      # primary buffers
        # no hardware mixing or hardware 3D buffers: everything is software
        c[17], c[18], c[19] = 0, 0, 0
        c[20] = 100000                                # unlock transfer rate (KB/s)
        c[21] = 0                                     # CPU overhead of software buffers
        e.wr(p, struct.pack("<24I", *c)[:max(min(size, 96), 4) if size else 96])
    reg_method(D, "GetCaps", 1, logged(D, "GetCaps", caps))

    def set_coop(e, this, hwnd, level):
        obj(e, this)["coop"] = level
        rec(e).events.append("SetCooperativeLevel(hwnd=0x%x, %s)" % (hwnd, COOP_LEVELS.get(level, level)))
    reg_method(D, "SetCooperativeLevel", 2, logged(D, "SetCooperativeLevel", set_coop))

    def init_ds(e, this, pguid):
        o = obj(e, this)
        if not o.get("uninitialized"):
            return 0x88780082                          # DSERR_ALREADYINITIALIZED
        o["uninitialized"] = False
        rec(e).events.append("IDirectSound::Initialize(guid=%s)" % ("default" if not pguid else uuid.UUID(bytes_le=e.rd(pguid, 16))))
    reg_method(D, "Initialize", 1, logged(D, "Initialize", init_ds))
    reg_method(D, "Compact", 0, logged(D, "Compact"))
    reg_method(D, "GetSpeakerConfig", 1, logged(D, "GetSpeakerConfig", lambda e, this, p: out32(e, p, 0x4 | (0 << 16))))  # STEREO
    reg_method(D, "SetSpeakerConfig", 1, logged(D, "SetSpeakerConfig", lambda e, this, v: rec(e).events.append("SetSpeakerConfig(0x%x)" % v)))

    def read_wfx(e, p):
        tag, ch, rate, avg, align, bits = struct.unpack("<HHIIHH", e.rd(p, 16))
        return dict(tag=tag, channels=ch, rate=rate, avg=avg, align=align, bits=bits)

    def new_buffer(e, flags, nbytes, wfx, ds=0):
        size = max(nbytes, 16)
        buf = new_obj(e, "IDirectSoundBuffer", flags=flags, size=size, ptr=e.alloc(size), wfx=wfx, playing=False,
                      looping=False, pos=0, started=0.0, volume=0, pan=0, freq=0, ds=ds, voice=None)
        o = obj(e, buf)
        if wfx and not flags & 0x1 and mixer(e):
            v = mixer(e).lib.mpa_voice_new(mixer(e).m, wfx["channels"], wfx["bits"], wfx["rate"], size)
            if v < 0:
                rec(e).events.append("no mixer voice: " + mixer(e).lib.mpa_last_error().decode())
            else:
                o["voice"] = v
        if flags & 0x10 and not flags & 0x1:
            o["p3"] = dict(position=(0.0, 0.0, 0.0), velocity=(0.0, 0.0, 0.0), inside_angle=360, outside_angle=360,
                           cone_orientation=(0.0, 0.0, 1.0), outside_volume=0, min_distance=1.0,
                           max_distance=1e9, mode=DS3DMODE_NORMAL, buffer_obj=o)
        update_voice(e, o)
        return buf

    def free_voice(e, o):
        if o.get("voice") is not None:
            o["stale"] = mixer(e).lib.mpa_voice_stale(mixer(e).m, o["voice"])
            mixer(e).lib.mpa_voice_free(mixer(e).m, o["voice"])
            o["voice"] = None

    def create_buffer(e, this, pdesc, ppbuf, outer):
        r = rec(e)
        if outer:
            return DSERR_NOAGGREGATION
        size, flags, nbytes, _, pwfx, _g = struct.unpack("<IIIIII", e.rd(pdesc, 24)) if e.rd32(pdesc) >= 24 else \
            (e.rd32(pdesc), e.rd32(pdesc + 4), e.rd32(pdesc + 8), 0, e.rd32(pdesc + 16), 0)
        wfx = read_wfx(e, pwfx) if pwfx else None
        if flags & 0x1:                                 # primary buffer: no format, no size
            buf = new_buffer(e, flags, 4096, None)
            obj(e, this)["primary"] = buf
        else:
            if wfx is None:
                return DSERR_INVALIDPARAM
            buf = new_buffer(e, flags, nbytes, wfx, this)
            r.formats[wfx_text(wfx)] += 1
        r.buffers.append("%s size=%d format=%s flags=0x%x [%s]" % (
            "PRIMARY" if flags & 0x1 else "secondary", nbytes, wfx_text(wfx) if wfx else "-", flags, flag_text(flags, DSBCAPS)))
        out32(e, ppbuf, buf)
    reg_method(D, "CreateSoundBuffer", 3, logged(D, "CreateSoundBuffer", create_buffer))

    def duplicate(e, this, psrc, ppdup):
        s = obj(e, psrc)
        if not s:
            return DSERR_INVALIDPARAM
        buf = new_buffer(e, s["flags"], s["size"], s["wfx"], this)
        d = obj(e, buf)
        data = e.rd(s["ptr"], s["size"])
        e.wr(d["ptr"], data)
        if d["voice"] is not None:
            mixer(e).lib.mpa_voice_write(mixer(e).m, d["voice"], 0, data, len(data))
        for k in ("volume", "pan", "freq"):
            d[k] = s[k]
        update_voice(e, d)
        rec(e).buffers.append("duplicate of 0x%x size=%d" % (psrc, s["size"]))
        out32(e, ppdup, buf)
    reg_method(D, "DuplicateSoundBuffer", 2, logged(D, "DuplicateSoundBuffer", duplicate))

    # ------------------------------------------------------------ IDirectSoundBuffer
    B = "IDirectSoundBuffer"

    def play_cursor(e, o):
        """Where the play cursor is, and whether the buffer is still playing. With a mixer the cursor is the
        voice's real position; without one it advances with the host clock."""
        if o.get("voice") is not None:
            playing = ctypes.c_int()
            pos = mixer(e).lib.mpa_voice_get_pos(mixer(e).m, o["voice"], ctypes.byref(playing))
            o["playing"] = bool(playing.value)
            return pos, o["playing"]
        if not o["playing"]:
            return o["pos"], False
        rate = (o["wfx"] or {}).get("avg", 0) or 44100 * 4
        pos = o["pos"] + int((time.perf_counter() - o["started"]) * rate)
        if o["looping"]:
            return pos % o["size"], True
        if pos >= o["size"]:
            o["playing"], o["pos"] = False, 0
            return 0, False
        return pos, True

    def write_cursor(e, o):
        p, playing = play_cursor(e, o)
        if not playing or not o["wfx"]:
            return p, p
        return p, (p + WRITE_LEAD_FRAMES * o["wfx"]["align"]) % o["size"]

    def get_pos(e, this, pplay, pwrite):
        o = obj(e, this)
        p, w = write_cursor(e, o)
        out32(e, pplay, p)
        out32(e, pwrite, w)
    reg_method(B, "GetCurrentPosition", 2, logged(B, "GetCurrentPosition", get_pos))

    def get_status(e, this, p):
        o = obj(e, this)
        _, playing = play_cursor(e, o)
        out32(e, p, (DSBSTATUS_PLAYING if playing else 0) | (DSBSTATUS_LOOPING if playing and o["looping"] else 0))
    reg_method(B, "GetStatus", 1, logged(B, "GetStatus", get_status))

    def play(e, this, r1, r2, flags):
        o = obj(e, this)
        o["playing"], o["looping"], o["started"] = True, bool(flags & DSBPLAY_LOOPING), time.perf_counter()
        o["plays"] = o.get("plays", 0) + 1
        if o.get("voice") is not None:
            mixer(e).lib.mpa_voice_play(mixer(e).m, o["voice"], int(o["looping"]))
        rec(e).plays["primary" if o["flags"] & 1 else ("looping" if o["looping"] else "one-shot")] += 1
    reg_method(B, "Play", 3, logged(B, "Play", play))

    def stop(e, this):
        o = obj(e, this)
        o["pos"], _ = play_cursor(e, o)
        o["playing"] = False
        if o.get("voice") is not None:
            mixer(e).lib.mpa_voice_stop(mixer(e).m, o["voice"])
    reg_method(B, "Stop", 0, logged(B, "Stop", stop))

    def set_cur(e, this, pos):
        o = obj(e, this)
        o["pos"] = pos % o["size"]
        o["started"] = time.perf_counter()
        if o.get("voice") is not None:
            mixer(e).lib.mpa_voice_set_pos(mixer(e).m, o["voice"], o["pos"])
    reg_method(B, "SetCurrentPosition", 1, logged(B, "SetCurrentPosition", set_cur))

    def lock(e, this, off, nbytes, pp1, pcb1, pp2, pcb2, flags):
        o = obj(e, this)
        if flags & DSBLOCK_ENTIREBUFFER:
            off, nbytes = 0, o["size"]
        elif flags & DSBLOCK_FROMWRITECURSOR:
            off = write_cursor(e, o)[1]
        if off >= o["size"] or nbytes > o["size"]:
            return DSERR_INVALIDPARAM
        first = min(nbytes, o["size"] - off)
        out32(e, pp1, o["ptr"] + off)
        out32(e, pcb1, first)
        if nbytes > first:                                # wrap-around: second region at the start
            out32(e, pp2, o["ptr"])
            out32(e, pcb2, nbytes - first)
        else:
            out32(e, pp2, 0)
            out32(e, pcb2, 0)
    reg_method(B, "Lock", 7, logged(B, "Lock", lock))

    def unlock(e, this, p1, n1, p2, n2):
        """The game has written the locked regions: hand them to the mixer."""
        o = obj(e, this)
        o["unlocks"] = o.get("unlocks", 0) + 1
        o["written"] = o.get("written", 0) + n1 + n2
        if o.get("voice") is None:
            return
        for p, n in ((p1, n1), (p2, n2)):
            off = p - o["ptr"]
            if p and n and 0 <= off < o["size"]:
                n = min(n, o["size"] - off)
                mixer(e).lib.mpa_voice_write(mixer(e).m, o["voice"], off, e.rd(p, n), n)
    reg_method(B, "Unlock", 4, logged(B, "Unlock", unlock))
    reg_method(B, "Restore", 0, logged(B, "Restore"))
    reg_method(B, "Initialize", 2, logged(B, "Initialize", ret=0x88780082))

    def b_format(e, this, p):
        o = obj(e, this)
        if o["wfx"] is None:                              # primary buffer: remember the requested format
            rec(e).events.append("primary SetFormat: " + wfx_text(read_wfx(e, p)))
            o["wfx"] = read_wfx(e, p)
        else:
            return DSERR_UNSUPPORTED
    reg_method(B, "SetFormat", 1, logged(B, "SetFormat", b_format))

    def get_fmt(e, this, pwfx, size, pwritten):
        o = obj(e, this)
        w = o["wfx"] or dict(tag=1, channels=2, rate=22050, avg=88200, align=4, bits=16)
        if pwfx:
            e.wr(pwfx, struct.pack("<HHIIHH", w["tag"], w["channels"], w["rate"], w["avg"], w["align"], w["bits"]) + b"\0\0")
        out32(e, pwritten, 18)
    reg_method(B, "GetFormat", 3, logged(B, "GetFormat", get_fmt))

    def b_caps(e, this, p):
        o = obj(e, this)
        e.wr(p, struct.pack("<5I", 20, o["flags"], o["size"], 0, 0))
    reg_method(B, "GetCaps", 1, logged(B, "GetCaps", b_caps))

    for nm, key in (("GetVolume", "volume"), ("GetPan", "pan"), ("GetFrequency", "freq")):
        reg_method(B, nm, 1, logged(B, nm, lambda e, this, p, _k=key: out32(e, p, obj(e, this)[_k] & 0xFFFFFFFF)))
    for nm, key in (("SetVolume", "volume"), ("SetPan", "pan"), ("SetFrequency", "freq")):
        def setter(e, this, v, _k=key):
            o = obj(e, this)
            o[_k] = v if _k == "freq" else (v - (1 << 32) if v & 0x80000000 else v)
            update_voice(e, o)
        reg_method(B, nm, 1, logged(B, nm, setter))

    # ------------------------------------------------------------ 3D listener / 3D buffer / notify
    # Parameters are kept as DirectSound has them; DS3D_DEFERRED changes wait for CommitDeferredSettings.
    # Every applied change recomputes the affected voices' gains and frequency (gains_3d below).
    def listener(e):
        r = rec(e)
        if not hasattr(r, "listener"):
            r.listener = dict(position=(0.0, 0.0, 0.0), velocity=(0.0, 0.0, 0.0), front=(0.0, 0.0, 1.0),
                              top=(0.0, 1.0, 0.0), distance_factor=1.0, rolloff_factor=1.0, doppler_factor=1.0)
            r.deferred = []
        return r.listener

    def apply_param(e, target, changes, flag):
        listener(e)
        if flag & DS3D_DEFERRED:
            rec(e).deferred.append((target, changes))
            return
        target.update(changes)
        target["sets"] = target.get("sets", 0) + 1
        refresh_3d(e, target)

    def refresh_3d(e, target):
        if target is rec(e).listener:
            for o in list(rec(e).objs.values()):
                if o.get("iface") == "IDirectSoundBuffer" and "p3" in o:
                    update_voice(e, o)
        else:
            update_voice(e, target["buffer_obj"])

    def commit(e, this):
        listener(e)
        pending, rec(e).deferred = rec(e).deferred, []
        for target, changes in pending:
            target.update(changes)
            target["sets"] = target.get("sets", 0) + 1
        touched = {id(t): t for t, _ in pending}
        if any(t is rec(e).listener for t in touched.values()):
            refresh_3d(e, rec(e).listener)
        else:
            for t in touched.values():
                refresh_3d(e, t)

    def vec(e, p): return struct.unpack("<3f", e.rd(p, 12))

    def put_vec(e, p, v):
        if p:
            e.wr(p, struct.pack("<3f", *v))

    L = "IDirectSound3DListener"
    LISTENER_SETTERS = {
        "SetPosition": (3, lambda a: dict(position=tuple(map(f32, a[:3])))),
        "SetVelocity": (3, lambda a: dict(velocity=tuple(map(f32, a[:3])))),
        "SetOrientation": (6, lambda a: dict(front=tuple(map(f32, a[:3])), top=tuple(map(f32, a[3:6])))),
        "SetDistanceFactor": (1, lambda a: dict(distance_factor=f32(a[0]))),
        "SetDopplerFactor": (1, lambda a: dict(doppler_factor=f32(a[0]))),
        "SetRolloffFactor": (1, lambda a: dict(rolloff_factor=f32(a[0]))),
    }
    for nm, (n, conv) in LISTENER_SETTERS.items():
        def lset(e, this, *a, _n=nm, _c=conv, _k=n):
            rec(e).listener_sets["listener " + _n] += 1
            apply_param(e, listener(e), _c(a), a[_k])
        reg_method(L, nm, n + 1, logged(L, nm, lset))

    def l_set_all(e, this, p, flag):
        rec(e).listener_sets["listener SetAllParameters"] += 1
        v = struct.unpack("<I12f3f", e.rd(p, 64))[1:]
        apply_param(e, listener(e), dict(position=v[0:3], velocity=v[3:6], front=v[6:9], top=v[9:12],
                                         distance_factor=v[12], rolloff_factor=v[13], doppler_factor=v[14]), flag)
    reg_method(L, "SetAllParameters", 2, logged(L, "SetAllParameters", l_set_all))

    def l_get_all(e, this, p):
        l = listener(e)
        e.wr(p + 4, struct.pack("<12f3f", *l["position"], *l["velocity"], *l["front"], *l["top"],
                                l["distance_factor"], l["rolloff_factor"], l["doppler_factor"]))
    reg_method(L, "GetAllParameters", 1, logged(L, "GetAllParameters", l_get_all))
    reg_method(L, "GetPosition", 1, logged(L, "GetPosition", lambda e, this, p: put_vec(e, p, listener(e)["position"])))
    reg_method(L, "GetVelocity", 1, logged(L, "GetVelocity", lambda e, this, p: put_vec(e, p, listener(e)["velocity"])))

    def l_get_orient(e, this, pf, pt):
        put_vec(e, pf, listener(e)["front"])
        put_vec(e, pt, listener(e)["top"])
    reg_method(L, "GetOrientation", 2, logged(L, "GetOrientation", l_get_orient))
    for nm, key in (("GetDistanceFactor", "distance_factor"), ("GetDopplerFactor", "doppler_factor"),
                    ("GetRolloffFactor", "rolloff_factor")):
        reg_method(L, nm, 1, logged(L, nm, lambda e, this, p, _k=key: e.wr(p, struct.pack("<f", listener(e)[_k]))))
    reg_method(L, "CommitDeferredSettings", 0, logged(L, "CommitDeferredSettings", commit))

    T = "IDirectSound3DBuffer"

    def p3(e, this):
        """The 3D parameters of the buffer behind a 3D-buffer interface."""
        return obj(e, obj(e, this)["buffer"])["p3"]

    BUFFER_SETTERS = {
        "SetPosition": (3, lambda a: dict(position=tuple(map(f32, a[:3])))),
        "SetVelocity": (3, lambda a: dict(velocity=tuple(map(f32, a[:3])))),
        "SetConeOrientation": (3, lambda a: dict(cone_orientation=tuple(map(f32, a[:3])))),
        "SetConeAngles": (2, lambda a: dict(inside_angle=a[0], outside_angle=a[1])),
        "SetConeOutsideVolume": (1, lambda a: dict(outside_volume=s32(a[0]))),
        "SetMinDistance": (1, lambda a: dict(min_distance=f32(a[0]))),
        "SetMaxDistance": (1, lambda a: dict(max_distance=f32(a[0]))),
        "SetMode": (1, lambda a: dict(mode=a[0])),
    }
    for nm, (n, conv) in BUFFER_SETTERS.items():
        def bset(e, this, *a, _n=nm, _c=conv, _k=n):
            rec(e).listener_sets["3D buffer " + _n] += 1
            apply_param(e, p3(e, this), _c(a), a[_k])
        reg_method(T, nm, n + 1, logged(T, nm, bset))

    def b_set_all(e, this, p, flag):
        rec(e).listener_sets["3D buffer SetAllParameters"] += 1
        v = struct.unpack("<I3f3fII3fiffI", e.rd(p, 64))[1:]
        apply_param(e, p3(e, this), dict(position=v[0:3], velocity=v[3:6], inside_angle=v[6], outside_angle=v[7],
                                          cone_orientation=v[8:11], outside_volume=v[11], min_distance=v[12],
                                          max_distance=v[13], mode=v[14]), flag)
    reg_method(T, "SetAllParameters", 2, logged(T, "SetAllParameters", b_set_all))

    def b_get_all(e, this, p):
        q = p3(e, this)
        e.wr(p + 4, struct.pack("<3f3fII3fiffI", *q["position"], *q["velocity"], q["inside_angle"], q["outside_angle"],
                                *q["cone_orientation"], q["outside_volume"], q["min_distance"], q["max_distance"], q["mode"]))
    reg_method(T, "GetAllParameters", 1, logged(T, "GetAllParameters", b_get_all))
    for nm, key in (("GetPosition", "position"), ("GetVelocity", "velocity"), ("GetConeOrientation", "cone_orientation")):
        reg_method(T, nm, 1, logged(T, nm, lambda e, this, p, _k=key: put_vec(e, p, p3(e, this)[_k])))
    for nm, key, fmt in (("GetMinDistance", "min_distance", "<f"), ("GetMaxDistance", "max_distance", "<f"),
                         ("GetConeOutsideVolume", "outside_volume", "<i"), ("GetMode", "mode", "<I")):
        reg_method(T, nm, 1, logged(T, nm, lambda e, this, p, _k=key, _f=fmt: e.wr(p, struct.pack(_f, p3(e, this)[_k]))))

    def b_get_cone(e, this, pin, pout):
        out32(e, pin, p3(e, this)["inside_angle"])
        out32(e, pout, p3(e, this)["outside_angle"])
    reg_method(T, "GetConeAngles", 2, logged(T, "GetConeAngles", b_get_cone))
    reg_method("IDirectSoundNotify", "SetNotificationPositions", 2, logged("IDirectSoundNotify", "SetNotificationPositions"))

    # ------------------------------------------------------------ gains
    def update_voice(e, o):
        """Push a buffer's volume, pan, frequency and 3D state to its mixer voice."""
        if o.get("voice") is None:
            return
        vol = db_gain(o["volume"])
        freq = o["freq"] or o["wfx"]["rate"]
        q = o.get("p3")
        if q is not None and q["mode"] != DS3DMODE_DISABLE:
            gl, gr, doppler = gains_3d(listener(e), q)
            downmix = 1
            freq *= doppler
        else:
            gl, gr = pan_gains(o["pan"])
            downmix = 0
        if isinstance(o, _FastBuf):                       # hle_fast.c's SetVolume applies them
            o.set_gains(gl, gr, downmix)
        lib, m = mixer(e).lib, mixer(e).m
        lib.mpa_voice_set_gain(m, o["voice"], vol * gl, vol * gr, downmix)
        lib.mpa_voice_set_freq(m, o["voice"], float(freq))

    # DSOUND handlers are ordinary except DirectSoundEnumerateA (a coroutine, which the direct path declines): lifted
    # code calls them without the emulator (mpemu.HLE_DIRECT, runtime.c hle_direct)
    m.HLE_DIRECT.update(k for k in m.HLE if k[0] == DLL)
    global _update_voice
    _update_voice = update_voice
