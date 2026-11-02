"""Unit tests for the DirectSound layer (emu/dsound.py) and its mixer (audio/, libmpaudio): buffers driven through
their COM methods as the game drives them, mixed on demand (no audio device) and checked sample by sample.

Run:  make -C audio && .venv/bin/python emu/test_dsound.py
"""
import ctypes
import math
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
import mpemu
import dsound

dsound.install(mpemu)
DLL = "DSOUND.DLL"
RATE = dsound.MIX_RATE


def fresh():
    e = mpemu.Emu(os.path.join(os.path.dirname(__file__), "..", "Max Payne"))
    e.audio = "none"                 # mixer without a device: the test pulls the output
    return e


def method(e, this, iface, name, *args):
    return e.call(e.stub_for(DLL, "%s::%s" % (iface, name)), this, *args) & 0xFFFFFFFF


def vcall(e, this, slot, *args):
    """Call through the object's vtable, as the game does (`call [ecx+slot*4]`)."""
    return e.call(e.rd32(e.rd32(this) + 4 * slot), this, *args) & 0xFFFFFFFF


def fbits(x): return struct.unpack("<I", struct.pack("<f", x))[0]
def u32(v): return v & 0xFFFFFFFF


def create_ds(e):
    pp = e.alloc(4)
    assert e.call(e.stub_for(DLL, "DirectSoundCreate"), 0, pp, 0) & 0xFFFFFFFF == 0
    return e.rd32(pp)


def create_buffer(e, ds, channels, bits, rate, nbytes, flags=0xE0):
    align = channels * bits // 8
    wfx = e.alloc(18)
    e.wr(wfx, struct.pack("<HHIIHHH", 1, channels, rate, rate * align, align, bits, 0))
    desc = e.alloc(20)
    e.wr(desc, struct.pack("<5I", 20, flags, nbytes, 0, wfx))
    pp = e.alloc(4)
    assert vcall(e, ds, 3, desc, pp, 0) == 0          # IDirectSound::CreateSoundBuffer
    return e.rd32(pp)


def fill(e, buf, data, offset=0, flags=0):
    """Lock, write, Unlock, as the game does; returns the locked offset."""
    p = e.alloc(16)
    B = "IDirectSoundBuffer"
    assert method(e, buf, B, "Lock", offset, len(data), p, p + 4, p + 8, p + 12, flags) == 0
    p1, n1, p2, n2 = struct.unpack("<4I", e.rd(p, 16))
    e.wr(p1, data[:n1])
    if n2:
        e.wr(p2, data[n1:n1 + n2])
    method(e, buf, B, "Unlock", p1, n1, p2, n2)
    return p1


def render(e, n):
    mx = dsound.mixer(e)
    out = (ctypes.c_float * (2 * n))()
    mx.lib.mpa_render(mx.m, out, n)
    return out[0::2], out[1::2]


def cursor(e, buf):
    p = e.alloc(8)
    method(e, buf, "IDirectSoundBuffer", "GetCurrentPosition", p, p + 4)
    return struct.unpack("<2I", e.rd(p, 8))


def status(e, buf):
    p = e.alloc(4)
    method(e, buf, "IDirectSoundBuffer", "GetStatus", p)
    return e.rd32(p)


def close(a, b, tol=1e-3): return abs(a - b) <= tol


def test_gain_math():
    assert dsound.db_gain(0) == 1.0 and close(dsound.db_gain(-2000), 0.1, 1e-9) and dsound.db_gain(-10000) == 0.0
    assert dsound.pan_gains(0) == (1.0, 1.0)
    l, r = dsound.pan_gains(2000)
    assert close(l, 0.1, 1e-9) and r == 1.0
    l, r = dsound.pan_gains(-4000)
    assert l == 1.0 and close(r, 0.01, 1e-9)
    print("ok  volume and pan gains")


def test_3d_model():
    lst = dict(position=(0.0, 0.0, 0.0), velocity=(0.0, 0.0, 0.0), front=(0.0, 0.0, 1.0), top=(0.0, 1.0, 0.0),
               distance_factor=1.0, rolloff_factor=1.0, doppler_factor=1.0)

    def src(**kw):
        q = dict(position=(0.0, 0.0, 0.0), velocity=(0.0, 0.0, 0.0), inside_angle=360, outside_angle=360,
                 cone_orientation=(0.0, 0.0, 1.0), outside_volume=0, min_distance=1.0, max_distance=1e9,
                 mode=dsound.DS3DMODE_NORMAL)
        q.update(kw)
        return q
    gl, gr, d = dsound.gains_3d(lst, src(position=(0.0, 0.0, 0.5)))      # inside the minimum distance
    assert (gl, gr, d) == (1.0, 1.0, 1.0)
    gl, gr, _ = dsound.gains_3d(lst, src(position=(0.0, 0.0, 4.0)))      # 4x the minimum distance: 1/4
    assert close(gl, 0.25) and close(gr, 0.25)
    gl, gr, _ = dsound.gains_3d(dict(lst, rolloff_factor=2.0), src(position=(0.0, 0.0, 4.0)))
    assert close(gl, 1 / 7.0)                                           # min / (min + 2 * (4 - min))
    gl, gr, _ = dsound.gains_3d(lst, src(position=(0.0, 0.0, 100.0), max_distance=10.0))
    assert close(gl, 0.1)                                               # no further rolloff past the maximum
    gl, gr, _ = dsound.gains_3d(lst, src(position=(3.0, 0.0, 0.0), min_distance=3.0))   # straight to the right
    assert close(gr, 1.0) and close(gl, 10 ** (dsound.FAR_EAR_DB / 20))
    gl, gr, _ = dsound.gains_3d(lst, src(position=(-3.0, 0.0, 0.0), min_distance=3.0))
    assert close(gl, 1.0) and gr < 0.3
    # listener turned to face +x: a source at +x is now straight ahead, one at +z is on the left
    turned = dict(lst, front=(1.0, 0.0, 0.0))
    gl, gr, _ = dsound.gains_3d(turned, src(position=(5.0, 0.0, 0.0), min_distance=5.0))
    assert close(gl, 1.0) and close(gr, 1.0)
    gl, gr, _ = dsound.gains_3d(turned, src(position=(0.0, 0.0, 5.0), min_distance=5.0))
    assert close(gl, 1.0) and gr < 0.3
    # head-relative: the position is already in listener space, the listener's own position is ignored
    gl, gr, _ = dsound.gains_3d(dict(lst, position=(50.0, 0.0, 0.0)), src(position=(0.0, 0.0, 1.0),
                                                                          mode=dsound.DS3DMODE_HEADRELATIVE))
    assert (gl, gr) == (1.0, 1.0)
    # cone: source at +z facing away from the listener gets the outside volume (-20 dB)
    q = src(position=(0.0, 0.0, 1.0), inside_angle=90, outside_angle=180, cone_orientation=(0.0, 0.0, 1.0),
            outside_volume=-2000)
    assert close(dsound.gains_3d(lst, q)[0], 0.1)
    q["cone_orientation"] = (0.0, 0.0, -1.0)                            # facing the listener: full volume
    assert close(dsound.gains_3d(lst, q)[0], 1.0)
    a = math.radians(67.5)                                             # 135 deg full cone: half-way, -10 dB
    q["cone_orientation"] = (math.sin(a), 0.0, -math.cos(a))
    assert close(dsound.gains_3d(lst, q)[0], 10 ** (-1000 / 2000), 1e-3)
    # doppler: a source approaching at a tenth of the speed of sound
    v = dsound.SPEED_OF_SOUND / 10
    _, _, ratio = dsound.gains_3d(lst, src(position=(0.0, 0.0, 10.0), velocity=(0.0, 0.0, -v)))
    assert close(ratio, 1 / 0.9)
    _, _, ratio = dsound.gains_3d(lst, src(position=(0.0, 0.0, 10.0), velocity=(0.0, 0.0, v)))
    assert close(ratio, 1 / 1.1)
    print("ok  DS3D model: distance, max distance, rolloff, pan, orientation, head-relative, cones, doppler")


def test_play_volume_and_cursor():
    e = fresh()
    ds = create_ds(e)
    buf = create_buffer(e, ds, 1, 16, 22050, 22050 * 2)                # 1 s, mono 16-bit
    fill(e, buf, struct.pack("<h", 16384) * 22050, flags=dsound.DSBLOCK_ENTIREBUFFER)
    B = "IDirectSoundBuffer"
    method(e, buf, B, "SetVolume", u32(-2000))
    assert status(e, buf) == 0
    method(e, buf, B, "Play", 0, 0, dsound.DSBPLAY_LOOPING)
    assert status(e, buf) == dsound.DSBSTATUS_PLAYING | dsound.DSBSTATUS_LOOPING
    l, r = render(e, 4410)
    assert all(close(x, 0.05, 1e-4) for x in l) and all(close(x, 0.05, 1e-4) for x in r)
    play, write = cursor(e, buf)
    assert play == 4410, play                                          # 0.1 s of 22.05 kHz, 2 bytes a frame
    assert write == play + 2 * dsound.WRITE_LEAD_FRAMES
    # frequency: twice the rate plays twice as fast
    method(e, buf, B, "SetFrequency", 44100)
    render(e, 4410)
    assert cursor(e, buf)[0] == 4410 + 8820
    method(e, buf, B, "SetFrequency", 0)                               # DSBFREQUENCY_ORIGINAL
    method(e, buf, B, "Stop")
    assert status(e, buf) == 0 and cursor(e, buf) == (13230, 13230)    # a stopped buffer keeps its cursor
    l, _ = render(e, 100)
    assert max(map(abs, l)) == 0.0
    method(e, buf, B, "SetCurrentPosition", 2000)
    assert cursor(e, buf)[0] == 2000
    print("ok  volume, play/stop, play and write cursors, frequency")


def test_8bit_stereo_pan_and_one_shot():
    e = fresh()
    ds = create_ds(e)
    buf = create_buffer(e, ds, 2, 8, 44100, 2 * 441)                   # 10 ms, stereo 8-bit
    fill(e, buf, b"\xff\x80" * 441)                                    # left near full scale, right silent
    B = "IDirectSoundBuffer"
    method(e, buf, B, "Play", 0, 0, 0)
    l, r = render(e, 200)
    assert all(close(x, 127 / 128) for x in l) and all(x == 0 for x in r)
    method(e, buf, B, "SetPan", 10000)                                 # full right: left silenced
    l, r = render(e, 200)
    assert all(close(x, 0.0) for x in l)
    l, r = render(e, 200)                                              # runs past the end: one-shot stops
    assert status(e, buf) == 0 and cursor(e, buf)[0] == 0
    assert max(map(abs, render(e, 100)[0])) == 0.0
    print("ok  8-bit stereo, pan, one-shot end")


def test_streaming_and_stale_data():
    e = fresh()
    ds = create_ds(e)
    n = 4410                                                           # frames: 0.1 s at 44.1 kHz mono 16-bit
    stream = create_buffer(e, ds, 1, 16, 44100, 2 * n)
    fill(e, stream, b"\0\0" * n, flags=dsound.DSBLOCK_ENTIREBUFFER)
    B = "IDirectSoundBuffer"
    method(e, stream, B, "Play", 0, 0, dsound.DSBPLAY_LOOPING)
    lib, m = dsound.mixer(e).lib, dsound.mixer(e).m
    voice = e.ds.objs[stream]["voice"]
    # the game's streaming loop: each "frame", write from its write position up to the play cursor
    wpos = 0
    for _ in range(40):                                                # 4 laps
        render(e, 441)
        play, _ = cursor(e, stream)
        nbytes = (play - wpos) % (2 * n)
        if nbytes:
            fill(e, stream, b"\1\0" * (nbytes // 2), offset=wpos)
            wpos = (wpos + nbytes) % (2 * n)
    assert lib.mpa_voice_stale(m, voice) == 0
    # stop feeding it: the second lap from now replays old data, once per lap
    render(e, n)
    render(e, n // 2)
    stale = lib.mpa_voice_stale(m, voice)
    assert n // 2 - 64 <= stale <= n // 2 + 128, stale
    # FROMWRITECURSOR locks at the write cursor
    p1 = fill(e, stream, b"\0\0" * 10, flags=dsound.DSBLOCK_FROMWRITECURSOR)
    assert p1 - e.ds.objs[stream]["ptr"] == cursor(e, stream)[1]
    print("ok  streaming keeps up (no stale data); starvation counted; FROMWRITECURSOR")


def test_3d_buffer_deferred_and_release():
    e = fresh()
    ds = create_ds(e)
    # primary buffer with a listener
    desc = e.alloc(20)
    e.wr(desc, struct.pack("<5I", 20, 0x11, 0, 0, 0))
    pp = e.alloc(4)
    assert vcall(e, ds, 3, desc, pp, 0) == 0
    primary = e.rd32(pp)
    iid = e.alloc(16)
    e.wr(iid, dsound.IID["IDirectSound3DListener"])
    assert vcall(e, primary, 0, iid, pp) == 0
    lst = e.rd32(pp)
    buf = create_buffer(e, ds, 2, 16, 44100, 4 * 4410, flags=0x100F0 | 0x10)       # stereo 3D, as the game's pool
    fill(e, buf, struct.pack("<hh", 16384, 0) * 4410)                  # left only: a 3D voice mixes it to mono
    e.wr(iid, dsound.IID["IDirectSound3DBuffer"])
    assert vcall(e, buf, 0, iid, pp) == 0
    b3 = e.rd32(pp)
    method(e, buf, "IDirectSoundBuffer", "Play", 0, 0, dsound.DSBPLAY_LOOPING)
    l, r = render(e, 10)
    assert close(l[5], 0.25) and close(r[5], 0.25)                     # at the listener: centred, downmixed
    # deferred: nothing changes until CommitDeferredSettings
    vcall(e, b3, 19, fbits(2.0), 0, 0, dsound.DS3D_DEFERRED)          # SetPosition(2, 0, 0)
    l, r = render(e, 10)
    assert close(l[5], 0.25) and close(r[5], 0.25)
    vcall(e, lst, 17)                                                  # CommitDeferredSettings
    l, r = render(e, 10)
    assert close(r[5], 0.125) and close(l[5], 0.125 * 10 ** (dsound.FAR_EAR_DB / 20))
    # immediate listener move to (3, 0, 0): the source is now 1 unit to the left, within the minimum distance
    vcall(e, lst, 14, fbits(3.0), 0, 0, 0)                             # SetPosition, DS3D_IMMEDIATE
    l, r = render(e, 10)
    assert close(l[5], 0.25) and r[5] < 0.1
    # GetPosition returns what was set
    v = e.alloc(12)
    vcall(e, b3, 10, v)
    assert struct.unpack("<3f", e.rd(v, 12)) == (2.0, 0.0, 0.0)
    # releasing the buffer while its 3D interface is still held keeps it playing; releasing both stops it
    assert vcall(e, buf, 2) == 0
    assert max(map(abs, render(e, 10)[0])) > 0
    assert vcall(e, b3, 2) == 0
    assert max(map(abs, render(e, 10)[0])) == 0
    print("ok  3D buffer: downmix, deferred settings, listener moves, getters, release")


def test_duplicate_and_ds_release():
    e = fresh()
    ds = create_ds(e)
    buf = create_buffer(e, ds, 1, 16, 44100, 2 * 441)
    fill(e, buf, struct.pack("<h", 8192) * 441)
    pp = e.alloc(4)
    assert vcall(e, ds, 5, buf, pp) == 0                               # DuplicateSoundBuffer
    dup = e.rd32(pp)
    method(e, buf, "IDirectSoundBuffer", "Play", 0, 0, dsound.DSBPLAY_LOOPING)
    method(e, dup, "IDirectSoundBuffer", "Play", 0, 0, dsound.DSBPLAY_LOOPING)
    l, _ = render(e, 10)
    assert close(l[5], 0.5)                                            # both voices: 0.25 each
    assert vcall(e, ds, 2) == 0                                        # releasing DirectSound frees its buffers
    assert max(map(abs, render(e, 10)[0])) == 0
    print("ok  DuplicateSoundBuffer shares the data; releasing DirectSound frees its buffers")


def test_wav_record(tmp):
    e = fresh()
    e.audio_record = tmp
    ds = create_ds(e)
    buf = create_buffer(e, ds, 1, 16, 44100, 2 * 441)
    fill(e, buf, struct.pack("<h", -16384) * 441)
    method(e, buf, "IDirectSoundBuffer", "Play", 0, 0, dsound.DSBPLAY_LOOPING)
    render(e, 1000)
    dsound.mixer(e).close()
    import wave
    w = wave.open(tmp)
    assert (w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()) == (2, 2, RATE, 1000)
    assert struct.unpack("<2h", w.readframes(1)) == (-16384, -16384)
    os.unlink(tmp)
    print("ok  WAV recording")


if __name__ == "__main__":
    test_gain_math()
    test_3d_model()
    test_play_volume_and_cursor()
    test_8bit_stereo_pan_and_one_shot()
    test_streaming_and_stale_data()
    test_3d_buffer_deferred_and_release()
    test_duplicate_and_ds_release()
    test_wav_record(os.path.join(os.environ.get("TMPDIR", "/tmp"), "test_dsound.wav"))
    print("all DirectSound tests passed")
