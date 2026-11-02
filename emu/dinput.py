"""DirectInput 7 (dinput.dll) for the emulator.

What the game (maxpayne.exe+0x517e70 keyboard, +0x518c40 mouse) needs: DirectInputCreateA(hinst, 0x0700, ...),
then a keyboard (GUID_SysKeyboard, c_dfDIKeyboard, NONEXCLUSIVE|FOREGROUND|NOWINKEY) and a mouse (GUID_SysMouse,
c_dfDIMouse2), each with a 16-entry event buffer, polled every frame with both GetDeviceState (immediate state)
and GetDeviceData (buffered events). The mouse also asks for its capabilities and the wheel granularity.

This module provides those objects (IDirectInput7A / IDirectInputDevice7A vtables, real stdcall argument counts),
one shared input state fed by the host, and records everything the game does. The same key state also answers
USER32's GetAsyncKeyState / GetKeyboardState / ToAscii / GetKeyNameTextA, so all of the game's keyboard paths agree.

Host side (window layer, tests, scripted runs):
    di = e.dinput                    # created on install's first use
    di.key(DIK_ESCAPE, True)         # DirectInput scan code down/up
    di.mouse_move(dx, dy); di.mouse_wheel(+120); di.mouse_button(0, True)
    di.focus_lost()                  # FOREGROUND devices become unacquired (DIERR_INPUTLOST on the next poll)
    winsys.host_set_app_active(e, b) # the real window gained/lost focus (WM_ACTIVATEAPP; losing it also
                                     # calls focus_lost)
    di.on_poll = fn(e, device_name)  # called before every GetDeviceState/GetDeviceData: feed scripted input here

Key presses also become WM_KEYDOWN/WM_KEYUP messages (queued in `keymsgs`, posted by winsys on the next message
pump, where the game's WH_KEYBOARD hook sees them; TranslateMessage makes WM_CHAR). Joysticks and force feedback
are not provided.

Usage: dinput.install(mpemu_module) once, before running guest code (mpemu.boot does this).
"""
import collections
import struct
import time
import uuid

_IUNKNOWN = [("QueryInterface", 2), ("AddRef", 0), ("Release", 0)]

IDIRECTINPUT7 = _IUNKNOWN + [
    ("CreateDevice", 3), ("EnumDevices", 4), ("GetDeviceStatus", 1), ("RunControlPanel", 2), ("Initialize", 2),
    ("FindDevice", 3),                                                    # IDirectInput2
    ("CreateDeviceEx", 4)]                                                # IDirectInput7
IDIRECTINPUTDEVICE7 = _IUNKNOWN + [
    ("GetCapabilities", 1), ("EnumObjects", 3), ("GetProperty", 2), ("SetProperty", 2), ("Acquire", 0),
    ("Unacquire", 0), ("GetDeviceState", 2), ("GetDeviceData", 4), ("SetDataFormat", 1),
    ("SetEventNotification", 1), ("SetCooperativeLevel", 2), ("GetObjectInfo", 3), ("GetDeviceInfo", 1),
    ("RunControlPanel", 2), ("Initialize", 3),
    ("CreateEffect", 4), ("EnumEffects", 3), ("GetEffectInfo", 2), ("GetForceFeedbackState", 1),  # Device2
    ("SendForceFeedbackCommand", 1), ("EnumCreatedEffectObjects", 3), ("Escape", 1), ("Poll", 0),
    ("SendDeviceData", 4),
    ("EnumEffectsInFile", 4), ("WriteEffectToFile", 4)]                   # Device7

INTERFACES = {"IDirectInput7A": IDIRECTINPUT7, "IDirectInputDevice7A": IDIRECTINPUTDEVICE7}


def guid(s): return uuid.UUID(s).bytes_le


IID = {
    "IUnknown": guid("00000000-0000-0000-C000-000000000046"),
    "IDirectInputA": guid("89521360-AA8A-11CF-BFC7-444553540000"),
    "IDirectInput2A": guid("5944E662-AA8A-11CF-BFC7-444553540000"),
    "IDirectInput7A": guid("9A4CB684-236D-11D3-8E9D-00C04F6844AE"),
    "IDirectInputDeviceA": guid("5944E680-C92E-11CF-BFC7-444553540000"),
    "IDirectInputDevice2A": guid("5944E682-C92E-11CF-BFC7-444553540000"),
    "IDirectInputDevice7A": guid("57D7C6BC-2356-11D3-8E9D-00C04F6844AE"),
}
DI_IIDS = ("IUnknown", "IDirectInputA", "IDirectInput2A", "IDirectInput7A")
DEV_IIDS = ("IUnknown", "IDirectInputDeviceA", "IDirectInputDevice2A", "IDirectInputDevice7A")
GUID_SYSMOUSE = guid("6F1D2B60-D5A0-11CF-BFC7-444553540000")
GUID_SYSKEYBOARD = guid("6F1D2B61-D5A0-11CF-BFC7-444553540000")
GUID_XAXIS = guid("A36D02E0-C9F3-11CF-BFC7-444553540000")
GUID_YAXIS = guid("A36D02E1-C9F3-11CF-BFC7-444553540000")
GUID_ZAXIS = guid("A36D02E2-C9F3-11CF-BFC7-444553540000")
GUID_BUTTON = guid("A36D02F0-C9F3-11CF-BFC7-444553540000")
GUID_KEY = guid("55728220-D33C-11CF-BFC7-444553540000")
# Product GUIDs are arbitrary but stable, so the game's saved bindings keep matching across runs.
PRODUCT = {"keyboard": guid("6F1D2B61-D5A0-11CF-BFC7-444553540001"),
           "mouse": guid("6F1D2B60-D5A0-11CF-BFC7-444553540001")}

DI_OK, DI_NOEFFECT, DI_BUFFEROVERFLOW = 0, 1, 1
E_NOINTERFACE = 0x80004002
DIERR_INVALIDPARAM = 0x80070057
DIERR_NOAGGREGATION = 0x80040110
DIERR_DEVICENOTREG = 0x80040154
DIERR_UNSUPPORTED = 0x80004001
DIERR_NOTACQUIRED = 0x8007000C
DIERR_INPUTLOST = 0x8007001E
DIERR_ACQUIRED = 0x800700AA
DIERR_NOTBUFFERED = 0x80040207
DIERR_OLDDIRECTINPUTVERSION = 0x8007047E
DIERR_BETADIRECTINPUTVERSION = 0x80070481
DIERR_NOTFOUND = 0x80070002
INFINITE = 0xFFFFFFFF
DIGDD_PEEK = 1

DISCL = {0x1: "EXCLUSIVE", 0x2: "NONEXCLUSIVE", 0x4: "FOREGROUND", 0x8: "BACKGROUND", 0x10: "NOWINKEY"}
DIPROP = {1: "BUFFERSIZE", 2: "AXISMODE", 3: "GRANULARITY", 4: "RANGE", 5: "DEADZONE", 6: "SATURATION",
          7: "FFGAIN", 8: "FFLOAD", 9: "AUTOCENTER", 10: "CALIBRATIONMODE"}
DIPH = {0: "DEVICE", 1: "BYOFFSET", 2: "BYID"}
DIDFT_RELAXIS, DIDFT_ABSAXIS, DIDFT_AXIS, DIDFT_PSHBUTTON, DIDFT_BUTTON = 0x1, 0x2, 0x3, 0x4, 0xC
DIDFT_ANYINSTANCE = 0xFFFF00
WHEEL_DELTA = 120
MOUSE_BUTTONS = 5           # left, right, middle, X1, X2

# DirectInput keyboard scan codes (DIK_*) with the names GetKeyNameTextA returns for them on a US layout.
DIK_NAMES = {
    0x01: "Esc", 0x02: "1", 0x03: "2", 0x04: "3", 0x05: "4", 0x06: "5", 0x07: "6", 0x08: "7", 0x09: "8",
    0x0A: "9", 0x0B: "0", 0x0C: "-", 0x0D: "=", 0x0E: "Backspace", 0x0F: "Tab", 0x10: "Q", 0x11: "W",
    0x12: "E", 0x13: "R", 0x14: "T", 0x15: "Y", 0x16: "U", 0x17: "I", 0x18: "O", 0x19: "P", 0x1A: "[",
    0x1B: "]", 0x1C: "Enter", 0x1D: "Ctrl", 0x1E: "A", 0x1F: "S", 0x20: "D", 0x21: "F", 0x22: "G", 0x23: "H",
    0x24: "J", 0x25: "K", 0x26: "L", 0x27: ";", 0x28: "'", 0x29: "`", 0x2A: "Shift", 0x2B: "\\", 0x2C: "Z",
    0x2D: "X", 0x2E: "C", 0x2F: "V", 0x30: "B", 0x31: "N", 0x32: "M", 0x33: ",", 0x34: ".", 0x35: "/",
    0x36: "Right Shift", 0x37: "Num *", 0x38: "Alt", 0x39: "Space", 0x3A: "Caps Lock", 0x3B: "F1", 0x3C: "F2",
    0x3D: "F3", 0x3E: "F4", 0x3F: "F5", 0x40: "F6", 0x41: "F7", 0x42: "F8", 0x43: "F9", 0x44: "F10",
    0x45: "Pause", 0x46: "Scroll Lock", 0x47: "Num 7", 0x48: "Num 8", 0x49: "Num 9", 0x4A: "Num -",
    0x4B: "Num 4", 0x4C: "Num 5", 0x4D: "Num 6", 0x4E: "Num +", 0x4F: "Num 1", 0x50: "Num 2", 0x51: "Num 3",
    0x52: "Num 0", 0x53: "Num Del", 0x57: "F11", 0x58: "F12",
    0x9C: "Num Enter", 0x9D: "Right Ctrl", 0xB5: "Num /", 0xB7: "Prnt Scrn", 0xB8: "Right Alt",
    0xC5: "Num Lock", 0xC7: "Home", 0xC8: "Up", 0xC9: "Page Up", 0xCB: "Left", 0xCD: "Right", 0xCF: "End",
    0xD0: "Down", 0xD1: "Page Down", 0xD2: "Insert", 0xD3: "Delete", 0xDB: "Left Windows",
    0xDC: "Right Windows", 0xDD: "Application",
}
DIK_ESCAPE, DIK_RETURN, DIK_LCONTROL, DIK_LSHIFT, DIK_SPACE, DIK_W, DIK_A, DIK_S, DIK_D = \
    0x01, 0x1C, 0x1D, 0x2A, 0x39, 0x11, 0x1E, 0x1F, 0x20

# Windows virtual-key code -> DIK scan code(s), for GetAsyncKeyState / GetKeyboardState.
VK_TO_DIK = {0x08: (0x0E,), 0x09: (0x0F,), 0x0D: (0x1C, 0x9C), 0x10: (0x2A, 0x36), 0x11: (0x1D, 0x9D),
             0x12: (0x38, 0xB8), 0x13: (0x45,), 0x14: (0x3A,), 0x1B: (0x01,), 0x20: (0x39,), 0x21: (0xC9,),
             0x22: (0xD1,), 0x23: (0xCF,), 0x24: (0xC7,), 0x25: (0xCB,), 0x26: (0xC8,), 0x27: (0xCD,),
             0x28: (0xD0,), 0x2D: (0xD2,), 0x2E: (0xD3,), 0x5B: (0xDB,), 0x5C: (0xDC,), 0x5D: (0xDD,),
             0xA0: (0x2A,), 0xA1: (0x36,), 0xA2: (0x1D,), 0xA3: (0x9D,), 0xA4: (0x38,), 0xA5: (0xB8,),
             0x6A: (0x37,), 0x6B: (0x4E,), 0x6D: (0x4A,), 0x6E: (0x53,), 0x6F: (0xB5,), 0x90: (0xC5,),
             0x91: (0x46,), 0xBA: (0x27,), 0xBB: (0x0D,), 0xBC: (0x33,), 0xBD: (0x0C,), 0xBE: (0x34,),
             0xBF: (0x35,), 0xC0: (0x29,), 0xDB: (0x1A,), 0xDC: (0x2B,), 0xDD: (0x1B,), 0xDE: (0x28,)}
VK_TO_DIK.update({0x30 + i: (0x0B if i == 0 else 0x01 + i,) for i in range(10)})                 # '0'..'9'
VK_TO_DIK.update({ord(c): (k,) for k, c in ((k, DIK_NAMES[k]) for k in DIK_NAMES) if len(c) == 1 and c.isalpha()})
VK_TO_DIK.update({0x70 + i: (0x3B + i,) for i in range(10)})                                      # F1..F10
VK_TO_DIK.update({0x7A: (0x57,), 0x7B: (0x58,)})
VK_TO_DIK.update({0x60 + i: (k,) for i, k in enumerate((0x52, 0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49))})
VK_MOUSE = {0x01: 0, 0x02: 1, 0x04: 2, 0x05: 3, 0x06: 4}                                         # VK_LBUTTON..

# US-layout characters for ToAscii: DIK -> (plain, shifted)
_US = dict(zip(range(0x02, 0x0E), zip("1234567890-=", "!@#$%^&*()_+")))
_US.update(zip(range(0x10, 0x1C), zip("qwertyuiop[]", "QWERTYUIOP{}")))
_US.update(zip(range(0x1E, 0x2A), zip("asdfghjkl;'`", 'ASDFGHJKL:"~')))
_US.update(zip(range(0x2B, 0x36), zip("\\zxcvbnm,./", "|ZXCVBNM<>?")))
_US.update({0x39: (" ", " "), 0x1C: ("\r", "\r"), 0x0E: ("\b", "\b"), 0x0F: ("\t", "\t"), 0x01: ("\x1b", "\x1b"),
            0x9C: ("\r", "\r"), 0x37: ("*", "*"), 0x4A: ("-", "-"), 0x4E: ("+", "+"), 0xB5: ("/", "/")})


# DIK -> the virtual key Windows puts in WM_KEYDOWN (generic VK_SHIFT/VK_CONTROL/VK_MENU, not the L/R ones).
DIK_TO_VK = {}
for _vk, _diks in sorted(VK_TO_DIK.items(), key=lambda kv: -kv[0]):
    for _d in _diks:
        DIK_TO_VK[_d] = _vk


def char_for(state, dik):
    """The character a key produces on a US layout given the current Shift/Ctrl/Alt/Caps Lock state, or None."""
    ch = _US.get(dik)
    keys = state.keys
    if not ch or keys[0x1D] or keys[0x9D] or keys[0x38] or keys[0xB8]:
        return None
    shift = bool(keys[0x2A] or keys[0x36])
    if ch[0].isalpha() and 0x3A in state.toggles:
        shift = not shift
    return ch[1 if shift else 0]


def flag_text(flags, table):
    return "|".join(n for b, n in sorted(table.items()) if flags & b) or "0"


def now_ms():
    """Same clock as the emulator's GetTickCount, so event timestamps compare with the game's own timers."""
    return (time.perf_counter_ns() // 1_000_000) & 0xFFFFFFFF


def _run_field(name, i, conv):
    """A Device run-state attribute: in the instance, or in hle_fast.c once the device is there (field i)."""
    def get(self):
        return conv(self._fast.di_field(self._slot, i)) if self._fast else self.__dict__[name]

    def set(self, v):
        if self._fast:
            self._fast.di_field(self._slot, i, v)
        else:
            self.__dict__[name] = v
    return property(get, set)


def _cfg_field(name):
    """A Device configuration attribute: kept here, and copied to hle_fast.c when it changes."""
    def get(self):
        return self.__dict__[name]

    def set(self, v):
        self.__dict__[name] = v
        if self._fast:
            self._push_cfg()
    return property(get, set)


OBJ_KINDS = {"key": 0, "button": 1, "axis": 2}     # hle_fast.c DIO_*


class _FastQueue:
    """Device.queue once it lives in hle_fast.c: the deque operations dinput uses, on (ofs, data, stamp, seq)."""

    def __init__(self, fast, slot):
        self.fast, self.slot = fast, slot

    def __len__(self):
        return self.fast.di_queue(self.slot, 0)

    def append(self, ev):
        self.fast.di_queue(self.slot, 1, ev=ev)

    def popleft(self):
        ev = self[0]
        self.fast.di_queue(self.slot, 2)
        return ev

    def clear(self):
        self.fast.di_queue(self.slot, 3)

    def __getitem__(self, i):
        if i < 0:
            i += len(self)
        ev = self.fast.di_queue(self.slot, 4, i)
        if ev is None:
            raise IndexError(i)
        return ev

    def __iter__(self):
        return iter([self[i] for i in range(len(self))])


class Device:
    """One keyboard or mouse device object, with its data format, buffer and acquisition state. Once the fast path
    starts (attach_fast, H61) the run state lives in lift/runtime/hle_fast.c, which serves Acquire, GetDeviceState
    and GetDeviceData; these attributes are then views of it."""
    _fast = None                           # native.HleFast once the run state lives in C
    _slot = -1
    acquired = _run_field("acquired", 0, bool)
    lost = _run_field("lost", 1, bool)     # unacquired by focus loss: next poll reports DIERR_INPUTLOST
    overflow = _run_field("overflow", 2, bool)
    dx = _run_field("dx", 3, int)          # relative motion since the last GetDeviceState
    dy = _run_field("dy", 4, int)
    dz = _run_field("dz", 5, int)
    coop = _cfg_field("coop")
    fmt = _cfg_field("fmt")                # dict(size, flags, objs={("axis"|"button"|"key", instance): offset})
    bufsize = _cfg_field("bufsize")

    def __init__(self, kind):
        self.kind = kind                   # "keyboard" | "mouse"
        self.acquired = False
        self.lost = False
        self.coop = 0
        self.fmt = None
        self.bufsize = 0
        self.queue = collections.deque()
        self.overflow = False
        self.axis_mode = 1                 # DIPROPAXISMODE_REL
        self.dx = self.dy = self.dz = 0
        self.event = 0

    def attach_fast(self, fast, this):
        """Move the run state into hle_fast.c as device `this` (the guest object). False when C has no room."""
        slot = fast.di_new(this, 0 if self.kind == "keyboard" else 1)
        if slot < 0:
            return False
        run = {k: getattr(self, k) for k in ("acquired", "lost", "overflow", "dx", "dy", "dz")}
        events = list(self.queue)
        self._fast, self._slot = fast, slot
        self._push_cfg()
        for k, v in run.items():
            setattr(self, k, v)
        self.queue = _FastQueue(fast, slot)
        for ev in events:
            self.queue.append(ev)
        return True

    def _push_cfg(self):
        fmt = self.fmt
        objs = [(OBJ_KINDS[k], n, ofs) for (k, n), ofs in fmt["objs"].items()] if fmt else []
        self._fast.di_cfg(self._slot, self.coop, fmt is not None, fmt["size"] if fmt else 0, self.bufsize, objs)


class Input:
    """Shared input state: what the host says the keyboard and mouse are doing right now. keys, buttons and seq live
    in hle_fast.c once the fast path starts (attach_fast)."""
    _fast = None

    @property
    def seq(self):
        return self._fast.di_field(-1, 0) if self._fast else self.__dict__["seq"]

    @seq.setter
    def seq(self, v):
        if self._fast:
            self._fast.di_field(-1, 0, v)
        else:
            self.__dict__["seq"] = v

    @property
    def on_poll(self):
        return self.__dict__["on_poll"]

    @on_poll.setter
    def on_poll(self, fn):
        self.__dict__["on_poll"] = fn
        if self._fast:                     # C cannot call the hook: the polls go to Python while one is set
            self._fast.di_field(-1, 1, fn is not None)

    def attach_fast(self, fast, devices):
        """Move keys, buttons, seq and the run state of devices ({guest object: Device}) into hle_fast.c."""
        keys, buttons, seq = bytes(self.keys), bytes(self.buttons), self.seq
        self._fast = fast
        view = fast.di_keys()
        self.keys, self.buttons = view[:256], view[256:264]
        self.keys[:], self.buttons[:] = keys, buttons
        self.seq = seq
        self.on_poll = self.on_poll
        for this, d in devices.items():
            d.attach_fast(fast, this)

    def __init__(self):
        self.keys = bytearray(256)          # DIK -> 0x80 when down
        self.buttons = bytearray(8)
        self.toggles = set()                # Caps Lock, Num Lock, Scroll Lock (toggled on key-down)
        self.devices = []
        self.seq = 0                        # DirectInput sequence numbers are shared by all devices
        self.on_poll = None
        self.async_seen = set()             # GetAsyncKeyState "pressed since last call" bit
        self.keymsgs = collections.deque()  # (vk, scan, extended, down, alt) for winsys to post as WM_KEY*

    def _post(self, kind, obj, data):
        self.seq += 1
        stamp = now_ms()
        for d in self.devices:
            if d.kind != kind or not d.acquired or not d.fmt or not d.bufsize:
                continue
            ofs = d.fmt["objs"].get(obj)
            if ofs is None:
                continue
            if len(d.queue) >= d.bufsize:
                d.queue.popleft()
                d.overflow = True
            d.queue.append((ofs, data & 0xFFFFFFFF, stamp, self.seq))

    # ---- host API
    def key(self, dik, down):
        dik &= 0xFF
        if bool(self.keys[dik]) == bool(down):
            return
        self.keys[dik] = 0x80 if down else 0
        if down:
            self.async_seen.add(dik)
            if dik in (0x3A, 0xC5, 0x46):
                self.toggles ^= {dik}
        self._post("keyboard", ("key", dik), 0x80 if down else 0)
        if dik in DIK_TO_VK:
            alt = bool(self.keys[0x38] or self.keys[0xB8])
            self.keymsgs.append((DIK_TO_VK[dik], dik & 0x7F, 1 if dik & 0x80 else 0, bool(down), alt))

    def mouse_move(self, dx, dy):
        for d in self.devices:
            if d.kind == "mouse" and d.acquired:
                d.dx += dx
                d.dy += dy
        if dx:
            self._post("mouse", ("axis", 0), dx)
        if dy:
            self._post("mouse", ("axis", 1), dy)

    def mouse_wheel(self, dz):
        for d in self.devices:
            if d.kind == "mouse" and d.acquired:
                d.dz += dz
        self._post("mouse", ("axis", 2), dz)

    def mouse_button(self, n, down):
        if n >= MOUSE_BUTTONS or bool(self.buttons[n]) == bool(down):
            return
        self.buttons[n] = 0x80 if down else 0
        self._post("mouse", ("button", n), 0x80 if down else 0)

    def focus_lost(self):
        """The window lost focus: FOREGROUND devices are unacquired and their next poll says so."""
        for d in self.devices:
            if d.acquired and d.coop & 0x4:
                d.acquired, d.lost = False, True
                d.queue.clear()
        self.keys[:] = bytes(256)
        self.buttons[:] = bytes(8)

    def vk_down(self, vk):
        if vk in VK_MOUSE:
            return bool(self.buttons[VK_MOUSE[vk]])
        return any(self.keys[k] for k in VK_TO_DIK.get(vk, ()))


class Recorder:
    _fast = None                               # native.HleFast once Acquire and the polls are served in C

    def __init__(self):
        self.calls = collections.Counter()
        self.events = []
        self.polls = collections.Counter()
        self.objs = {}

    def report(self):
        if self._fast:
            self._fast.merge()                 # what the C handlers counted
        L = ["# DirectInput usage recorded from Max Payne (emulated run)", ""]
        L.append("Generated by `emu/dinput.py`. Devices and capabilities the game was *given* are chosen by the emulator.\n")
        L.append("## Events")
        L += ["- " + x for x in self.events]
        L.append("\n## Methods called (%d distinct)" % len(self.calls))
        L += ["- `%s` x%d" % (k, v) for k, v in sorted(self.calls.items(), key=lambda kv: (-kv[1], kv[0]))]
        L.append("\n## Polls (device, method, result)")
        L += ["- %s x%d" % (k, v) for k, v in sorted(self.polls.items(), key=lambda kv: (-kv[1], kv[0]))]
        return "\n".join(L) + "\n"


def input_state(e):
    """The emulator's input state (created on first use, also by the host before the game opens DirectInput)."""
    if not hasattr(e, "di"):
        e.di = Recorder()
        e.dinput = Input()
    return e.dinput


def attach_fast(e, fast):
    """Move the device run state and the shared input state into lift/runtime/hle_fast.c (native.HleFast, H61), which
    then serves Acquire, GetDeviceState and GetDeviceData from lifted code."""
    state = input_state(e)
    e.di._fast = fast
    state.attach_fast(fast, {a: o["dev"] for a, o in e.di.objs.items() if "dev" in o})


def install(m):
    if getattr(m, "_dinput_installed", False):
        return
    m._dinput_installed = True
    hle, reg, GuestCall = m.hle, m.reg, m.GuestCall
    DLL = "DINPUT.DLL"
    USER = "USER32.DLL"

    def rec(e):
        input_state(e)
        return e.di

    def inp(e):
        rec(e)
        return e.dinput

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
        rec(e).objs[a] = state
        return a

    def obj(e, this): return rec(e).objs.get(this, {})

    def out32(e, p, v):
        if p:
            e.wr32(p, v & 0xFFFFFFFF)

    def reg_method(iface, name, nparams, fn):
        hle(DLL, "%s::%s" % (iface, name), 1 + nparams)(fn)

    def logged(iface, name, extra=None, ret=DI_OK):
        key = "%s::%s" % (iface, name)

        def fn(e, this, *a):
            rec(e).calls[key] += 1
            if extra:
                r = extra(e, this, *a)
                return ret if r is None else r
            return ret
        return fn

    def s32(v): return v - (1 << 32) if v & 0x80000000 else v

    def guid_name(e, p):
        if p < 0x10000:
            return "#%d" % p
        g = e.rd(p, 16)
        for n, v in list(IID.items()) + [("GUID_SysMouse", GUID_SYSMOUSE), ("GUID_SysKeyboard", GUID_SYSKEYBOARD)]:
            if v == g:
                return n
        return str(uuid.UUID(bytes_le=g))

    # ------------------------------------------------------------ IUnknown
    def make_qi(iface, accepted):
        def qi(e, this, riid, ppv):
            r = rec(e)
            r.calls["%s::QueryInterface" % iface] += 1
            name = guid_name(e, riid)
            ok = name in accepted          # one object implements every version of its interface
            r.events.append("QueryInterface(%s) on %s -> %s" % (name, iface, "ok" if ok else "E_NOINTERFACE"))
            if not ok:
                out32(e, ppv, 0)
                return E_NOINTERFACE
            e.wr32(this + 4, e.rd32(this + 4) + 1)
            out32(e, ppv, this)
            return DI_OK
        return qi

    for iface, accepted in (("IDirectInput7A", DI_IIDS), ("IDirectInputDevice7A", DEV_IIDS)):
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
                d = obj(e, this).get("dev")
                if d in inp(e).devices:
                    inp(e).devices.remove(d)
            return n
        reg_method(iface, "AddRef", 0, addref)
        reg_method(iface, "Release", 0, release)
        reg_method(iface, "QueryInterface", 2, make_qi(iface, accepted))

    # ------------------------------------------------------------ creation
    def create_di(e, hinst, version, ppdi, outer, name="DirectInputCreateA"):
        r = rec(e)
        r.calls[name] += 1
        r.events.append("%s(version=0x%x)" % (name, version))
        if outer:
            out32(e, ppdi, 0)
            return DIERR_NOAGGREGATION
        if version < 0x300:
            out32(e, ppdi, 0)
            return DIERR_OLDDIRECTINPUTVERSION
        if version > 0x700:
            out32(e, ppdi, 0)
            return DIERR_BETADIRECTINPUTVERSION
        out32(e, ppdi, new_obj(e, "IDirectInput7A", version=version))
        return DI_OK

    hle(DLL, "DirectInputCreateA", 4)(create_di)

    @hle(DLL, "DirectInputCreateEx", 5)
    def _(e, hinst, version, riid, ppv, outer):
        if guid_name(e, riid) not in DI_IIDS:
            out32(e, ppv, 0)
            return E_NOINTERFACE
        return create_di(e, hinst, version, ppv, outer, "DirectInputCreateEx")

    # ------------------------------------------------------------ IDirectInput7A
    D = "IDirectInput7A"
    KINDS = {GUID_SYSKEYBOARD: "keyboard", GUID_SYSMOUSE: "mouse"}

    def create_device(e, this, rguid, ppdev, outer):
        kind = KINDS.get(e.rd(rguid, 16)) if rguid >= 0x10000 else None
        rec(e).events.append("CreateDevice(%s) -> %s" % (guid_name(e, rguid), kind or "DIERR_DEVICENOTREG"))
        if outer:
            return DIERR_NOAGGREGATION
        if kind is None:
            out32(e, ppdev, 0)
            return DIERR_DEVICENOTREG
        d = Device(kind)
        inp(e).devices.append(d)
        this = new_obj(e, "IDirectInputDevice7A", dev=d)
        if rec(e)._fast:
            d.attach_fast(rec(e)._fast, this)
        out32(e, ppdev, this)
    reg_method(D, "CreateDevice", 3, logged(D, "CreateDevice", create_device))
    reg_method(D, "CreateDeviceEx", 4, logged(D, "CreateDeviceEx",
               lambda e, this, rguid, riid, ppv, outer: DIERR_INVALIDPARAM if guid_name(e, riid) not in DEV_IIDS
               else create_device(e, this, rguid, ppv, outer)))

    DEVTYPE = {"keyboard": 0x403, "mouse": 0x202}     # DIDEVTYPE_KEYBOARD|PCENH, DIDEVTYPE_MOUSE|TRADITIONAL
    NAMES = {"keyboard": b"Keyboard", "mouse": b"Mouse"}

    def write_instance(e, p, kind):
        """DIDEVICEINSTANCEA (DirectX 5+ layout, 580 bytes; a DirectX 3 caller passes 568)."""
        size = e.rd32(p) or 580
        g = GUID_SYSKEYBOARD if kind == "keyboard" else GUID_SYSMOUSE
        blob = struct.pack("<I16s16sI260s260s16sHH", size, g, PRODUCT[kind], DEVTYPE[kind],
                           NAMES[kind], NAMES[kind], b"\0" * 16, 1, 6 if kind == "keyboard" else 2)
        e.wr(p, blob[:min(size, 580)])

    def enum_devices(e, this, devtype, callback, ref, flags):
        """EnumDevices(type, callback, ref, flags): keyboard and mouse, both attached."""
        rec(e).calls["%s::EnumDevices" % D] += 1
        rec(e).events.append("EnumDevices(type=%d, flags=0x%x)" % (devtype, flags))
        for kind, t in (("mouse", 2), ("keyboard", 3)):
            if devtype not in (0, t):
                continue
            p = e.alloc(580)
            e.wr32(p, 580)
            write_instance(e, p, kind)
            cont = yield GuestCall(callback, (p, ref), "stdcall")
            if not (cont & 0xFFFFFFFF):              # DIENUM_STOP
                break
        return DI_OK
    reg_method(D, "EnumDevices", 4, enum_devices)
    reg_method(D, "GetDeviceStatus", 1, logged(D, "GetDeviceStatus",
               lambda e, this, g: DI_OK if g >= 0x10000 and e.rd(g, 16) in KINDS else DIERR_DEVICENOTREG))
    reg_method(D, "RunControlPanel", 2, logged(D, "RunControlPanel"))
    reg_method(D, "Initialize", 2, logged(D, "Initialize"))
    reg_method(D, "FindDevice", 3, logged(D, "FindDevice", ret=DIERR_DEVICENOTREG))

    # ------------------------------------------------------------ IDirectInputDevice7A
    V = "IDirectInputDevice7A"

    def dev(e, this): return obj(e, this)["dev"]

    def objects(kind):
        """Every object the device has: (kind, instance, guid, DIDFT type)."""
        if kind == "keyboard":
            return [("key", i, GUID_KEY, DIDFT_PSHBUTTON | (i << 8)) for i in range(256)]
        return ([("axis", i, g, DIDFT_RELAXIS | (i << 8)) for i, g in enumerate((GUID_XAXIS, GUID_YAXIS, GUID_ZAXIS))]
                + [("button", i, GUID_BUTTON, DIDFT_PSHBUTTON | (i << 8)) for i in range(MOUSE_BUTTONS)])

    def set_data_format(e, this, pfmt):
        """DIDATAFORMAT: match every DIOBJECTDATAFORMAT to one of the device's objects, like DirectInput does
        (by GUID and type; DIDFT_ANYINSTANCE takes the next unused one; DIDFT_OPTIONAL entries may stay unmatched)."""
        d = dev(e, this)
        if d.acquired:
            return DIERR_ACQUIRED
        size, objsize, flags, datasize, nobjs, prgodf = struct.unpack("<6I", e.rd(pfmt, 24))
        avail = objects(d.kind)
        used, objs = set(), {}
        for i in range(nobjs):
            pg, ofs, typ, _f = struct.unpack("<4I", e.rd(prgodf + objsize * i, 16))
            g = e.rd(pg, 16) if pg else None
            inst = (typ >> 8) & 0xFFFF
            for kind, n, og, ot in avail:
                if (kind, n) in used or (g and g != og) or not (typ & ot & 0xFF):
                    continue
                if (typ & DIDFT_ANYINSTANCE) != DIDFT_ANYINSTANCE and inst != n:
                    continue
                used.add((kind, n))
                objs[(kind, n)] = ofs
                break
            else:
                if not typ & 0x80000000:              # DIDFT_OPTIONAL
                    rec(e).events.append("SetDataFormat(%s): object %d (type 0x%x) has no match" % (d.kind, i, typ))
                    return DIERR_INVALIDPARAM
        d.fmt = dict(size=datasize, flags=flags, objs=objs)
        rec(e).events.append("SetDataFormat(%s): %d bytes, %d objects (%d matched), flags=0x%x" % (
            d.kind, datasize, nobjs, len(objs), flags))
    reg_method(V, "SetDataFormat", 1, logged(V, "SetDataFormat", set_data_format))

    def set_coop(e, this, hwnd, flags):
        d = dev(e, this)
        d.coop = flags
        rec(e).events.append("SetCooperativeLevel(%s, hwnd=0x%x, %s)" % (d.kind, hwnd, flag_text(flags, DISCL)))
    reg_method(V, "SetCooperativeLevel", 2, logged(V, "SetCooperativeLevel", set_coop))

    def acquire(e, this):
        d = dev(e, this)
        if d.fmt is None:
            return DIERR_INVALIDPARAM
        if d.acquired:
            return DI_NOEFFECT
        d.acquired, d.lost = True, False
        d.dx = d.dy = d.dz = 0
        rec(e).polls[(d.kind, "Acquire", "ok")] += 1
    reg_method(V, "Acquire", 0, logged(V, "Acquire", acquire))

    def unacquire(e, this):
        d = dev(e, this)
        if not d.acquired:
            return DI_NOEFFECT
        d.acquired = False
        d.queue.clear()
    reg_method(V, "Unacquire", 0, logged(V, "Unacquire", unacquire))

    def not_ready(e, d):
        if d.acquired:
            return None
        return DIERR_INPUTLOST if d.lost else DIERR_NOTACQUIRED

    def poll_hook(e, d):
        cb = inp(e).on_poll
        if cb:
            cb(e, d.kind)

    def get_state(e, this, cb, p):
        d = dev(e, this)
        poll_hook(e, d)
        err = not_ready(e, d)
        if err is None and cb != d.fmt["size"]:
            err = DIERR_INVALIDPARAM
        rec(e).polls[(d.kind, "GetDeviceState", "ok" if err is None else "0x%x" % err)] += 1
        if err is not None:
            return err
        buf = bytearray(cb)
        state = inp(e)
        for (kind, n), ofs in d.fmt["objs"].items():
            if kind == "key":
                buf[ofs] = state.keys[n]
            elif kind == "button":
                buf[ofs] = state.buttons[n]
            elif ofs + 4 <= cb:
                v = (d.dx, d.dy, d.dz)[n] if n < 3 else 0
                struct.pack_into("<i", buf, ofs, max(-(1 << 31), min(v, (1 << 31) - 1)))
        d.dx = d.dy = d.dz = 0
        e.wr(p, bytes(buf))
    reg_method(V, "GetDeviceState", 2, logged(V, "GetDeviceState", get_state))

    def get_data(e, this, cbobj, rgdod, pinout, flags):
        d = dev(e, this)
        poll_hook(e, d)
        err = not_ready(e, d)
        if err is None and not d.bufsize:
            err = DIERR_NOTBUFFERED
        if err is None and cbobj < 16:
            err = DIERR_INVALIDPARAM
        want = e.rd32(pinout)
        if err is not None:
            rec(e).polls[(d.kind, "GetDeviceData", "0x%x" % err)] += 1
            out32(e, pinout, 0)
            return err
        n = len(d.queue) if want == INFINITE else min(want, len(d.queue))
        if rgdod:
            for i in range(n):
                e.wr(rgdod + cbobj * i, struct.pack("<4I", *d.queue[i]) + b"\0" * (cbobj - 16))
        if not flags & DIGDD_PEEK:
            for _ in range(n):
                d.queue.popleft()
        out32(e, pinout, n)
        rec(e).polls[(d.kind, "GetDeviceData", "%d events" % n if n else "empty")] += 1
        if d.overflow:
            d.overflow = False
            return DI_BUFFEROVERFLOW
    reg_method(V, "GetDeviceData", 4, logged(V, "GetDeviceData", get_data))

    def get_caps(e, this, p):
        """DIDEVCAPS (DirectX 5+ layout, 44 bytes; DirectX 3 callers pass 24)."""
        d = dev(e, this)
        size = e.rd32(p)
        axes, buttons = (0, 256) if d.kind == "keyboard" else (3, MOUSE_BUTTONS)
        blob = struct.pack("<11I", size, 0x1, DEVTYPE[d.kind], axes, buttons, 0, 0, 0, 0x100, 0x100, 0)  # DIDC_ATTACHED
        e.wr(p + 4, blob[4:max(min(size, 44), 4)])
    reg_method(V, "GetCapabilities", 1, logged(V, "GetCapabilities", get_caps))

    def prop_target(e, d, how, objid):
        if how == 0:
            return "device"
        if how == 1 and d.fmt:                       # DIPH_BYOFFSET: offset in the current data format
            return next((k for k, o in d.fmt["objs"].items() if o == objid), None)
        if how == 2:                                 # DIPH_BYID: instance from the DIDFT type
            want = (objid >> 8) & 0xFFFF
            return next(((k, n) for k, n, _, t in objects(d.kind) if n == want and t & objid & 0xFF), None)
        return None

    def get_prop(e, this, rguid, ph):
        d = dev(e, this)
        prop = rguid if rguid < 0x10000 else 0
        size, hsize, objid, how = struct.unpack("<4I", e.rd(ph, 16))
        tgt = prop_target(e, d, how, objid)
        rec(e).events.append("GetProperty(%s, %s, %s %s -> %s)" % (
            d.kind, DIPROP.get(prop, guid_name(e, rguid)), DIPH.get(how, how), objid, tgt))
        if tgt is None:
            return DIERR_NOTFOUND
        if prop == 1:
            val = d.bufsize
        elif prop == 2:
            val = d.axis_mode
        elif prop == 3:                              # granularity: the wheel moves in WHEEL_DELTA steps
            val = WHEEL_DELTA if tgt == ("axis", 2) else 1
        else:
            return DIERR_UNSUPPORTED
        e.wr32(ph + hsize, val)
    reg_method(V, "GetProperty", 2, logged(V, "GetProperty", get_prop))

    def set_prop(e, this, rguid, ph):
        d = dev(e, this)
        prop = rguid if rguid < 0x10000 else 0
        size, hsize, objid, how = struct.unpack("<4I", e.rd(ph, 16))
        val = e.rd32(ph + hsize)
        rec(e).events.append("SetProperty(%s, %s, %s %d, value=%d)" % (
            d.kind, DIPROP.get(prop, guid_name(e, rguid)), DIPH.get(how, how), objid, val))
        if prop == 1:
            if d.acquired:
                return DIERR_ACQUIRED
            d.bufsize = val
            while len(d.queue) > val:
                d.queue.popleft()
        elif prop == 2:
            if d.acquired:
                return DIERR_ACQUIRED
            d.axis_mode = val
        else:
            return DIERR_UNSUPPORTED
    reg_method(V, "SetProperty", 2, logged(V, "SetProperty", set_prop))

    reg_method(V, "GetDeviceInfo", 1, logged(V, "GetDeviceInfo", lambda e, this, p: write_instance(e, p, dev(e, this).kind)))

    def object_instance(e, p, kind, n, g, typ, ofs):
        """DIDEVICEOBJECTINSTANCEA (DirectX 5+ layout, 316 bytes; DirectX 3 callers pass 296)."""
        size = e.rd32(p) or 316
        if kind == "key":
            name = DIK_NAMES.get(n, "Key %d" % n)
        elif kind == "axis":
            name = ("X Axis", "Y Axis", "Wheel")[n]
        else:
            name = ("Left Button", "Right Button", "Middle Button", "Button 4", "Button 5")[n]
        blob = struct.pack("<I16sIII260sIIHHHHIHH", size, g, ofs, typ, 0, name.encode()[:259],
                           0, 0, 0, 0, 1, 0, 0, 0, 0)
        e.wr(p, blob[:min(size, 316)])

    def get_object_info(e, this, p, objid, how):
        d = dev(e, this)
        tgt = prop_target(e, d, how, objid)
        rec(e).calls["%s::GetObjectInfo" % V] += 1
        for k, n, g, t in objects(d.kind):
            if (k, n) == tgt:
                object_instance(e, p, k, n, g, t, d.fmt["objs"].get((k, n), 0) if d.fmt else 0)
                return DI_OK
        return DIERR_NOTFOUND
    reg_method(V, "GetObjectInfo", 3, get_object_info)

    def enum_objects(e, this, callback, ref, flags):
        d = dev(e, this)
        rec(e).calls["%s::EnumObjects" % V] += 1
        p = e.alloc(316)
        for k, n, g, t in objects(d.kind):
            if flags and not (flags & t & 0xFF):
                continue
            e.wr32(p, 316)
            object_instance(e, p, k, n, g, t, d.fmt["objs"].get((k, n), 0) if d.fmt else 0)
            cont = yield GuestCall(callback, (p, ref), "stdcall")
            if not (cont & 0xFFFFFFFF):
                break
        return DI_OK
    reg_method(V, "EnumObjects", 3, enum_objects)

    def set_event(e, this, h):
        dev(e, this).event = h
    reg_method(V, "SetEventNotification", 1, logged(V, "SetEventNotification", set_event))
    reg_method(V, "RunControlPanel", 2, logged(V, "RunControlPanel"))
    reg_method(V, "Initialize", 3, logged(V, "Initialize"))
    reg_method(V, "Poll", 0, logged(V, "Poll", ret=DI_NOEFFECT))      # keyboard and mouse never need polling
    for nm, np_ in IDIRECTINPUTDEVICE7[18:]:                             # force feedback: not available
        if nm != "Poll":
            reg_method(V, nm, np_, logged(V, nm, ret=DIERR_UNSUPPORTED))

    # every DINPUT handler is ordinary but EnumDevices and EnumObjects (coroutines: hle_direct declines them and they
    # run through the stub): lifted code calls them without the emulator (mpemu.HLE_DIRECT, runtime.c hle_direct)
    m.HLE_DIRECT.update(k for k in m.HLE if k[0] == DLL)

    # ------------------------------------------------------------ USER32 keyboard queries on the same state
    @reg("GetAsyncKeyState", 1, dll=USER)
    def _(e, vk):
        s = inp(e)
        down = s.vk_down(vk & 0xFF)
        dik = VK_TO_DIK.get(vk & 0xFF, ())
        pressed = any(k in s.async_seen for k in dik)
        s.async_seen.difference_update(dik)
        return (0x8000 if down else 0) | (1 if pressed else 0)

    @reg("GetKeyState", 1, dll=USER)
    def _(e, vk):
        s = inp(e)
        toggled = any(k in s.toggles for k in VK_TO_DIK.get(vk & 0xFF, ()))
        return (0xFF80 if s.vk_down(vk & 0xFF) else 0) | (1 if toggled else 0)

    @reg("GetKeyboardState", 1, dll=USER)
    def _(e, p):
        s = inp(e)
        st = bytearray(256)
        for vk in list(VK_TO_DIK) + list(VK_MOUSE):
            st[vk] = (0x80 if s.vk_down(vk) else 0) | (1 if any(k in s.toggles for k in VK_TO_DIK.get(vk, ())) else 0)
        e.wr(p, bytes(st))
        return 1

    @reg("ToAscii", 5, dll=USER)
    def _(e, vk, scan, pstate, pchar, flags):
        """US layout: the character for this key given the shift/caps bits of the passed keyboard state."""
        st = e.rd(pstate, 256) if pstate else bytes(256)
        dik = (scan & 0x7F) | (0x80 if scan & 0x100 else 0)
        ch = _US.get(dik) or next((_US[k] for k in VK_TO_DIK.get(vk & 0xFF, ()) if k in _US), None)
        if not ch or st[0x11] & 0x80 or st[0x12] & 0x80:   # Ctrl/Alt chords produce no character here
            return 0
        shift = bool(st[0x10] & 0x80)
        if ch[0].isalpha() and st[0x14] & 1:
            shift = not shift
        e.wr(pchar, ch[1 if shift else 0].encode("latin-1") + b"\0")
        return 1

    @reg("GetKeyNameTextA", 3, dll=USER)
    def _(e, lparam, pbuf, size):
        """lParam bits 16-23 are the scan code, bit 24 the extended flag: the same numbering as DIK codes."""
        dik = ((lparam >> 16) & 0x7F) | (0x80 if lparam & (1 << 24) else 0)
        name = DIK_NAMES.get(dik, "")
        if not name or size <= 0:
            return 0
        b = name.encode()[:size - 1]
        e.wr(pbuf, b + b"\0")
        return len(b)
