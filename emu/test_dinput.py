"""Unit tests for the DirectInput layer (emu/dinput.py): the call sequence the game uses (maxpayne.exe+0x517e70
keyboard, +0x518c40 mouse), host input injection, immediate and buffered reads, and the USER32 key queries.

Run:  .venv/bin/python emu/test_dinput.py
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
import mpemu
import dinput
import winsys

dinput.install(mpemu)
winsys.install(mpemu)
BASE = 0x00A00000          # free region (exe is at 0x400000..0x8d7000)
MARK = BASE + 0x800


def fresh():
    e = mpemu.Emu(os.path.join(os.path.dirname(__file__), "..", "Max Payne"))
    e.map(BASE, 0x2000)
    return e


def method(e, this, iface, name, *args):
    return e.call(e.stub_for("DINPUT.DLL", "%s::%s" % (iface, name)), this, *args) & 0xFFFFFFFF


def vcall(e, this, slot, *args):
    """Call through the object's vtable, as the game does (`call [ecx+slot*4]`)."""
    return e.call(e.rd32(e.rd32(this) + 4 * slot), this, *args) & 0xFFFFFFFF


def put_guid(e, g):
    p = e.alloc(16)
    e.wr(p, g)
    return p


def data_format(e, entries, datasize):
    """DIDATAFORMAT {24, 16, DIDF_RELAXIS, datasize, n, rgodf} with entries (guid|None, ofs, type)."""
    rg = e.alloc(16 * len(entries))
    for i, (g, ofs, typ) in enumerate(entries):
        e.wr(rg + 16 * i, struct.pack("<4I", put_guid(e, g) if g else 0, ofs, typ, 0))
    p = e.alloc(24)
    e.wr(p, struct.pack("<6I", 24, 16, 2, datasize, len(entries), rg))
    return p


def c_dfDIKeyboard(e):
    return data_format(e, [(dinput.GUID_KEY, i, 0x8000000C | (i << 8)) for i in range(256)], 256)


def c_dfDIMouse2(e):
    any_axis, any_btn = 0x00FFFF03, 0x80FFFF0C
    ents = [(dinput.GUID_XAXIS, 0, any_axis), (dinput.GUID_YAXIS, 4, any_axis),
            (dinput.GUID_ZAXIS, 8, any_axis | 0x80000000)] + [(None, 12 + i, any_btn) for i in range(8)]
    return data_format(e, ents, 20)


def dword_prop(e, obj, how, value=0):
    p = e.alloc(20)
    e.wr(p, struct.pack("<5I", 20, 16, obj, how, value))
    return p


def setup(e):
    """What the game does: DirectInputCreateA(hinst, 0x700), keyboard and mouse, buffer 16, acquire."""
    pp = e.alloc(4)
    assert e.call(e.stub_for("DINPUT.DLL", "DirectInputCreateA"), 0x400000, 0x700, pp, 0) == 0
    di = e.rd32(pp)
    devs = {}
    for name, g, fmt in (("kbd", dinput.GUID_SYSKEYBOARD, c_dfDIKeyboard(e)), ("mouse", dinput.GUID_SYSMOUSE, c_dfDIMouse2(e))):
        assert vcall(e, di, 3, put_guid(e, g), pp, 0) == 0, name            # CreateDevice
        d = e.rd32(pp)
        assert vcall(e, d, 11, fmt) == 0, name                              # SetDataFormat
        assert vcall(e, d, 13, 0x10010, 0x16) == 0                          # SetCooperativeLevel
        assert vcall(e, d, 6, 1, dword_prop(e, 0, 0, 16)) == 0              # SetProperty(BUFFERSIZE, 16)
        assert vcall(e, d, 7) == 0                                          # Acquire
        assert vcall(e, d, 7) == dinput.DI_NOEFFECT                         # already acquired
        devs[name] = d
    return di, devs


def read_events(e, d, n=16):
    buf, pn = e.alloc(16 * n), e.alloc(4)
    e.wr32(pn, n)
    r = vcall(e, d, 10, 16, buf, pn, 0)                                     # GetDeviceData
    got = e.rd32(pn)
    return r, [struct.unpack("<4I", e.rd(buf + 16 * i, 16)) for i in range(got)]


def test_keyboard():
    e = fresh()
    _, devs = setup(e)
    kb, inp = devs["kbd"], e.dinput
    inp.key(dinput.DIK_W, True)
    inp.key(dinput.DIK_LSHIFT, True)
    inp.key(dinput.DIK_W, False)
    st = e.alloc(256)
    assert vcall(e, kb, 9, 256, st) == 0                                    # GetDeviceState
    s = e.rd(st, 256)
    assert s[dinput.DIK_LSHIFT] == 0x80 and s[dinput.DIK_W] == 0, s[:0x30]
    assert vcall(e, kb, 9, 255, st) == dinput.DIERR_INVALIDPARAM            # wrong size
    r, ev = read_events(e, kb)
    assert r == 0 and [(o, d) for o, d, _, _ in ev] == [(0x11, 0x80), (0x2A, 0x80), (0x11, 0)], ev
    assert ev[0][3] < ev[1][3] < ev[2][3]                                   # sequence numbers increase
    assert read_events(e, kb) == (0, [])                                    # drained
    for i in range(20):                                                     # overflow the 16-entry buffer
        inp.key(dinput.DIK_A, i % 2 == 0)
    r, ev = read_events(e, kb, 32)
    assert r == dinput.DI_BUFFEROVERFLOW and len(ev) == 16, (r, len(ev))
    print("ok  keyboard: state, buffered events, overflow")


def test_mouse():
    e = fresh()
    _, devs = setup(e)
    m, inp = devs["mouse"], e.dinput
    caps = e.alloc(44)
    e.wr32(caps, 44)
    assert vcall(e, m, 3, caps) == 0                                        # GetCapabilities
    assert struct.unpack("<11I", e.rd(caps, 44))[3:5] == (3, dinput.MOUSE_BUTTONS)
    gp = dword_prop(e, 8, 1)                                                # GRANULARITY of offset 8 (wheel)
    assert vcall(e, m, 5, 3, gp) == 0 and e.rd32(gp + 16) == 120
    inp.mouse_move(5, -3)
    inp.mouse_move(2, 0)
    inp.mouse_wheel(-120)
    inp.mouse_button(1, True)
    st = e.alloc(20)
    assert vcall(e, m, 9, 20, st) == 0
    x, y, z = struct.unpack("<3i", e.rd(st, 12))
    assert (x, y, z) == (7, -3, -120) and e.rd(st + 12, 8) == b"\x00\x80" + bytes(6), (x, y, z, e.rd(st + 12, 8))
    assert vcall(e, m, 9, 20, st) == 0 and struct.unpack("<3i", e.rd(st, 12)) == (0, 0, 0)   # deltas reset
    r, ev = read_events(e, m)
    assert [(o, d) for o, d, _, _ in ev] == [(0, 5), (4, 0xFFFFFFFD), (0, 2), (8, 0xFFFFFF88), (13, 0x80)], ev
    print("ok  mouse: caps, wheel granularity, relative state, buffered events")


def test_focus_and_acquire():
    e = fresh()
    _, devs = setup(e)
    kb = devs["kbd"]
    e.dinput.key(dinput.DIK_SPACE, True)
    e.dinput.focus_lost()
    st = e.alloc(256)
    assert vcall(e, kb, 9, 256, st) == dinput.DIERR_INPUTLOST
    assert vcall(e, kb, 7) == 0 and vcall(e, kb, 9, 256, st) == 0 and e.rd(st, 256) == bytes(256)
    assert vcall(e, kb, 8) == 0 and vcall(e, kb, 9, 256, st) == dinput.DIERR_NOTACQUIRED
    e.dinput.key(dinput.DIK_A, True)                                        # not buffered while unacquired
    vcall(e, kb, 7)
    assert read_events(e, kb) == (0, [])
    print("ok  focus loss, acquire/unacquire")


def test_enum_devices():
    e = fresh()
    di, _ = setup(e)
    # stdcall BOOL cb(const DIDEVICEINSTANCEA*, void*): store dwDevType of each, return TRUE
    code = bytes([0x8B, 0x44, 0x24, 0x04,             # mov eax,[esp+4]
                  0x8B, 0x40, 0x24,                   # mov eax,[eax+0x24]   (dwDevType)
                  0x8B, 0x0D]) + struct.pack("<I", MARK) + bytes([   # mov ecx,[MARK]
                  0x89, 0x04, 0x8D]) + struct.pack("<I", MARK + 4) + bytes([   # mov [MARK+4+ecx*4],eax
                  0x41, 0x89, 0x0D]) + struct.pack("<I", MARK) + bytes([      # inc ecx; mov [MARK],ecx
                  0xB8, 1, 0, 0, 0, 0xC2, 8, 0])     # mov eax,1; ret 8
    e.wr(BASE, code)
    e.wr32(MARK, 0)
    assert vcall(e, di, 4, 0, BASE, 0, 0) == 0, e.fatal                    # EnumDevices(all)
    n = e.rd32(MARK)
    assert [e.rd32(MARK + 4 + 4 * i) for i in range(n)] == [0x202, 0x403], [hex(e.rd32(MARK + 4 + 4 * i)) for i in range(n)]
    pp = e.alloc(4)
    assert vcall(e, di, 3, put_guid(e, b"\x11" * 16), pp, 0) == dinput.DIERR_DEVICENOTREG
    print("ok  EnumDevices callback, unknown device")


def test_user32_queries():
    e = fresh()
    setup(e)
    U = "USER32.DLL"
    e.dinput.key(dinput.DIK_ESCAPE, True)
    e.dinput.key(dinput.DIK_LCONTROL, True)
    assert e.call(e.stub_for(U, "GetAsyncKeyState"), 0x1B) & 0xFFFF == 0x8001
    assert e.call(e.stub_for(U, "GetAsyncKeyState"), 0x1B) & 0xFFFF == 0x8000      # "pressed" bit is one-shot
    assert e.call(e.stub_for(U, "GetAsyncKeyState"), 0x11) & 0x8000
    assert e.call(e.stub_for(U, "GetAsyncKeyState"), 0x41) & 0xFFFF == 0
    buf = e.alloc(64)
    n = e.call(e.stub_for(U, "GetKeyNameTextA"), 0x39 << 16, buf, 64)
    assert e.cstr(buf) == "Space" and n == 5
    e.call(e.stub_for(U, "GetKeyNameTextA"), (0x48 << 16) | (1 << 24), buf, 64)
    assert e.cstr(buf) == "Up"
    ks, ch = e.alloc(256), e.alloc(4)
    ks_bytes = bytearray(256)
    ks_bytes[0x10] = 0x80                                                   # shift held
    e.wr(ks, bytes(ks_bytes))
    assert e.call(e.stub_for(U, "ToAscii"), 0x41, 0x1E, ks, ch, 0) == 1 and e.rd(ch, 1) == b"A"
    e.wr(ks, bytes(256))
    assert e.call(e.stub_for(U, "ToAscii"), 0x31, 0x02, ks, ch, 0) == 1 and e.rd(ch, 1) == b"1"
    print("ok  GetAsyncKeyState / GetKeyNameTextA / ToAscii")


def test_key_messages_and_hook():
    """Host key presses reach the message queue as WM_KEYDOWN/WM_KEYUP, pass the WH_KEYBOARD hook (as the game's
    typed-text hook at maxpayne.exe+0x518360 needs), and TranslateMessage adds WM_CHAR."""
    e = fresh()
    setup(e)
    U = "USER32.DLL"
    # stdcall LRESULT hook(code, wParam, lParam): store (code, wParam) pairs at MARK+4.., return 0
    code = bytes([0x8B, 0x0D]) + struct.pack("<I", MARK) + bytes([               # mov ecx,[MARK]
                  0x8B, 0x44, 0x24, 0x04,                                          # mov eax,[esp+4]
                  0x89, 0x04, 0xCD]) + struct.pack("<I", MARK + 4) + bytes([       # mov [MARK+4+ecx*8],eax
                  0x8B, 0x44, 0x24, 0x08,                                          # mov eax,[esp+8]
                  0x89, 0x04, 0xCD]) + struct.pack("<I", MARK + 8) + bytes([       # mov [MARK+8+ecx*8],eax
                  0x41, 0x89, 0x0D]) + struct.pack("<I", MARK) + bytes([           # inc ecx; mov [MARK],ecx
                  0x31, 0xC0, 0xC2, 12, 0])                                        # xor eax,eax; ret 12
    e.wr(BASE, code)
    e.wr32(MARK, 0)
    assert e.call(e.stub_for(U, "SetWindowsHookExA"), 2, BASE, 0x400000, 1)
    e.win.focus = 0x10010                                    # the game window has the keyboard focus
    e.dinput.key(0x1E, True)                                 # A
    e.dinput.key(0x1E, False)
    msg = e.alloc(28)
    seen = []
    while e.call(e.stub_for(U, "PeekMessageA"), msg, 0, 0, 0, 1):
        assert not e.fatal, e.fatal
        h, m, w, l = struct.unpack("<4I", e.rd(msg, 16))
        seen.append((h, m, w, l >> 16 & 0xFF, l >> 31))
        e.call(e.stub_for(U, "TranslateMessage"), msg)
    assert seen == [(0x10010, 0x100, 0x41, 0x1E, 0), (0x10010, 0x102, ord("a"), 0x1E, 0),
                    (0x10010, 0x101, 0x41, 0x1E, 1)], seen
    hooked = [(e.rd32(MARK + 4 + 8 * i), e.rd32(MARK + 8 + 8 * i)) for i in range(e.rd32(MARK))]
    assert hooked == [(0, 0x41), (0, 0x41)], hooked          # HC_ACTION for the down and up messages
    print("ok  WM_KEYDOWN/WM_CHAR/WM_KEYUP and the WH_KEYBOARD hook")


if __name__ == "__main__":
    for t in (test_keyboard, test_mouse, test_focus_and_acquire, test_enum_devices, test_user32_queries,
              test_key_messages_and_hook):
        t()
    print("all DirectInput tests passed")
