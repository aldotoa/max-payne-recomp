"""Minimal Win32 window manager for the emulator.

Enough of USER32 for an MFC application's windows: a window table and class registry, CreateWindowExA that
honours MFC's CBT hook (WH_CBT / HCBT_CREATEWND) and sends WM_NCCREATE / WM_CREATE / WM_SIZE / WM_MOVE, a native
DefWindowProc, SendMessage / PostMessage / a message queue for PeekMessage, Get/SetWindowLong, window geometry.
Every call into a guest window procedure is a coroutine step (see mpemu.Coro), so window procedures can create
windows, send messages and throw C++ exceptions exactly as they would on Windows.

Not here yet (not needed by the startup path): dialog templates and child controls, painting, timers that fire,
keyboard/mouse input. Real input and a real macOS window come with the host layer.

Usage: winsys.install(mpemu_module) once, before running guest code (mpemu.boot does this).
"""
import struct

WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_CAPTION = 0x00C00000
CW_USEDEFAULT = 0x80000000
HCBT_CREATEWND = 3
WH_CBT = 5

WM_CREATE, WM_DESTROY, WM_MOVE, WM_SIZE = 0x1, 0x2, 0x3, 0x5
WM_SETTEXT, WM_GETTEXT, WM_GETTEXTLENGTH = 0xC, 0xD, 0xE
WM_CLOSE, WM_QUIT, WM_ERASEBKGND = 0x10, 0x12, 0x14
WM_SHOWWINDOW, WM_NCCREATE, WM_NCDESTROY, WM_NCCALCSIZE, WM_NCHITTEST = 0x18, 0x81, 0x82, 0x83, 0x84
WM_ACTIVATE, WM_SETFOCUS, WM_KILLFOCUS, WM_ACTIVATEAPP, WM_NCACTIVATE = 0x6, 0x7, 0x8, 0x1C, 0x86
WM_KEYDOWN, WM_KEYUP, WM_CHAR, WM_SYSKEYDOWN, WM_SYSKEYUP, WM_SYSCHAR = 0x100, 0x101, 0x102, 0x104, 0x105, 0x106
WH_KEYBOARD, HC_ACTION, HC_NOREMOVE = 2, 0, 3
GUEST_THREAD_ID = 1

BUILTIN_CLASSES = ("BUTTON", "STATIC", "EDIT", "COMBOBOX", "LISTBOX", "SCROLLBAR", "#32770", "MDICLIENT")


class Cls:
    def __init__(self, name, wndproc, style=0, cbwndextra=0, hinst=0, hicon=0, hcursor=0, hbr=0, menu=0, atom=0):
        self.name, self.wndproc, self.style, self.cbwndextra = name, wndproc, style, cbwndextra
        self.hinst, self.hicon, self.hcursor, self.hbr, self.menu, self.atom = hinst, hicon, hcursor, hbr, menu, atom


class Win:
    def __init__(self, hwnd, cls, wndproc, style, exstyle, parent, x, y, w, h, hinst, ident):
        self.hwnd, self.cls, self.wndproc = hwnd, cls, wndproc
        self.style, self.exstyle, self.parent = style, exstyle, parent
        self.x, self.y, self.w, self.h = x, y, w, h
        self.hinst, self.id, self.userdata = hinst, ident, 0
        self.text, self.visible, self.enabled = "", False, True
        self.extra, self.props = {}, {}


class WinSys:
    def __init__(self, e):
        self.windows, self.classes, self.atoms = {}, {}, {}
        self.queue, self.hooks, self.timers = [], [], {}
        self.next_hwnd, self.next_hook = 0x10010, 0x4000
        self.focus = self.active = self.capture = 0
        self.app_active = False                 # has this app had WM_ACTIVATEAPP(TRUE)?
        self.pending_app_active = None          # host focus change, delivered on the next PeekMessage/GetMessage
        self.defproc = e.stub_for("USER32.DLL", "DefWindowProcA")
        for n in BUILTIN_CLASSES:
            self.classes[n] = Cls(n, self.defproc, atom=self.atom_for(n))

    def atom_for(self, name):
        return self.atoms.setdefault(name.upper(), 0xC000 + len(self.atoms))


def host_post_quit(e, code=0):
    """Host side: end the run the way the game ends, with WM_QUIT in the thread queue (the frame function's message
    pump returns FALSE, CMaxPayneApp::Run calls ExitInstance and the CRT exits). run_init.py --real-entry."""
    if not hasattr(e, "win"):
        e.win = WinSys(e)
    e.win.queue.append((0, WM_QUIT, code, 0))


def host_set_app_active(e, active):
    """Host side: the real window gained/lost focus. Delivered as WM_ACTIVATEAPP etc. on the game's next
    message pump (messages are sent from inside guest execution, never from the host directly)."""
    if not hasattr(e, "win"):
        e.win = WinSys(e)
    e.win.pending_app_active = bool(active)


def install(m):
    if getattr(m, "_winsys_installed", False):
        return
    m._winsys_installed = True
    hle, GuestCall = m.hle, m.GuestCall
    U = "USER32.DLL"
    SCREEN = m.SCREEN
    DESKTOP, LEGACY_ACTIVE = 0x1001, 0x1000

    def S(e):
        if not hasattr(e, "win"):
            e.win = WinSys(e)
        return e.win

    def reg(name, nargs):
        return hle(U, name, nargs)

    def class_name(e, p, wide=False):
        if p < 0x10000:
            for n, a in S(e).atoms.items():
                if a == p:
                    return n
            return "#%d" % p
        return (e.wstr(p) if wide else e.cstr(p)).upper()

    def find_class(e, p):
        return S(e).classes.get(class_name(e, p))

    # ------------------------------------------------------------------ message delivery
    def send(e, hwnd, msg, w, l):
        """Generator: deliver a message synchronously to a window's procedure; returns its result."""
        ws = S(e)
        win = ws.windows.get(hwnd)
        if win is None:
            return 0
        if win.wndproc == ws.defproc:
            return (yield from defproc(e, win, msg, w, l))
        return (yield GuestCall(win.wndproc, (hwnd, msg, w, l), "stdcall"))

    def defproc(e, win, msg, w, l):
        """The native DefWindowProc."""
        if msg == WM_NCCREATE:
            return 1
        if msg == WM_SETTEXT:
            win.text = e.cstr(l) if l else ""
            return 1
        if msg == WM_GETTEXT:
            raw = win.text.encode("latin1")[:max(w - 1, 0)] + b"\0"
            if w:
                e.wr(l, raw)
            return len(raw) - 1
        if msg == WM_GETTEXTLENGTH:
            return len(win.text)
        if msg == WM_ERASEBKGND:
            return 1
        if msg == WM_NCHITTEST:
            return 1                                    # HTCLIENT
        if msg == WM_CLOSE:
            yield from destroy(e, win.hwnd)
            return 0
        return 0
        yield                                           # (makes this a generator in every path)

    def top_level(e, hwnd):
        win = S(e).windows.get(hwnd)
        while win is not None and win.style & WS_CHILD and win.parent in S(e).windows:
            win = S(e).windows[win.parent]
        return win

    def set_app_active(e, active):
        """Generator: WM_ACTIVATEAPP to every top-level window when the app gains or loses activation."""
        ws = S(e)
        if ws.app_active == bool(active):
            return
        ws.app_active = bool(active)
        for h, win in list(ws.windows.items()):
            if not win.style & WS_CHILD:
                yield from send(e, h, WM_ACTIVATEAPP, 1 if active else 0, GUEST_THREAD_ID)

    def set_focus(e, hwnd):
        ws = S(e)
        old = ws.focus
        if old == hwnd:
            return old
        ws.focus = hwnd
        if old in ws.windows:
            yield from send(e, old, WM_KILLFOCUS, hwnd, 0)
        if hwnd in ws.windows:
            yield from send(e, hwnd, WM_SETFOCUS, old, 0)
        return old

    def activate(e, hwnd):
        """Generator: make a top-level window the active one, with the message sequence Windows uses
        (WM_ACTIVATEAPP, WM_NCACTIVATE, WM_ACTIVATE, then focus). The game's main window only renders
        after WM_ACTIVATEAPP(TRUE) (maxpayne.exe+0x40d270 -> app gain-focus at +0x40baf0)."""
        ws = S(e)
        top = top_level(e, hwnd)
        if top is None:
            return ws.active
        old = ws.active
        if old == top.hwnd and ws.app_active:
            return old
        if old in ws.windows and old != top.hwnd:
            yield from send(e, old, WM_NCACTIVATE, 0, 0)
            yield from send(e, old, WM_ACTIVATE, 0, top.hwnd)
        yield from set_app_active(e, True)
        ws.active = top.hwnd
        yield from send(e, top.hwnd, WM_NCACTIVATE, 1, 0)
        yield from send(e, top.hwnd, WM_ACTIVATE, 1, old)          # WA_ACTIVE
        if top_level(e, ws.focus) is not top:
            yield from set_focus(e, top.hwnd)
        return old

    def deactivate_app(e):
        """Generator: the app lost activation (host window lost focus)."""
        ws = S(e)
        if ws.active in ws.windows:
            yield from send(e, ws.active, WM_NCACTIVATE, 0, 0)
            yield from send(e, ws.active, WM_ACTIVATE, 0, 0)
        yield from set_app_active(e, False)
        if ws.focus in ws.windows:
            yield from send(e, ws.focus, WM_KILLFOCUS, 0, 0)
        ws.active = ws.focus = 0
        if hasattr(e, "dinput"):
            e.dinput.focus_lost()

    def destroy(e, hwnd):
        ws = S(e)
        win = ws.windows.get(hwnd)
        if win is None:
            return 0
        win.visible = False
        yield from send(e, hwnd, WM_DESTROY, 0, 0)
        yield from send(e, hwnd, WM_NCDESTROY, 0, 0)
        ws.windows.pop(hwnd, None)
        if ws.focus == hwnd:
            ws.focus = 0
        if ws.active == hwnd:
            ws.active = 0
        return 1

    # ------------------------------------------------------------------ classes
    @reg("RegisterClassA", 1)
    def _(e, wc):
        ws = S(e)
        style, proc, cbcls, cbwnd, hinst, hicon, hcur, hbr, menu, cname = struct.unpack("<10I", e.rd(wc, 40))
        name = class_name(e, cname)
        atom = ws.atom_for(name)
        ws.classes[name] = Cls(name, proc, style, cbwnd, hinst, hicon, hcur, hbr, menu, atom)
        return atom

    @reg("UnregisterClassA", 2)
    def _(e, name, hinst):
        return 1 if S(e).classes.pop(class_name(e, name), None) else 0

    @reg("GetClassInfoA", 3)
    def _(e, hinst, name, wc):
        c = find_class(e, name)
        if c is None:
            e.last_error = 1411                         # ERROR_CLASS_DOES_NOT_EXIST
            return 0
        e.wr(wc, struct.pack("<10I", c.style, c.wndproc, 0, c.cbwndextra, c.hinst, c.hicon, c.hcursor, c.hbr,
                             c.menu, name))
        return c.atom

    @reg("GetClassNameA", 3)
    def _(e, hwnd, buf, n):
        win = S(e).windows.get(hwnd)
        raw = (win.cls if win else "").encode("latin1")[:max(n - 1, 0)] + b"\0"
        if n:
            e.wr(buf, raw)
        return len(raw) - 1

    @reg("GetClassLongA", 2)
    def _(e, hwnd, idx):
        win = S(e).windows.get(hwnd)
        c = S(e).classes.get(win.cls) if win else None
        if c is None:
            return 0
        idx -= (1 << 32) if idx & 0x80000000 else 0
        return {-24: c.wndproc, -10: c.hbr, -12: c.hcursor, -14: c.hicon, -26: c.style, -8: c.menu,
                -18: c.cbwndextra}.get(idx, 0)

    # ------------------------------------------------------------------ hooks
    @reg("SetWindowsHookExA", 4)
    def _(e, hid, proc, hmod, tid):
        ws = S(e)
        ws.next_hook += 4
        ws.hooks.append((ws.next_hook, hid, proc))
        return ws.next_hook

    @reg("UnhookWindowsHookEx", 1)
    def _(e, h):
        ws = S(e)
        before = len(ws.hooks)
        ws.hooks = [x for x in ws.hooks if x[0] != h]
        return 1 if len(ws.hooks) != before else 0

    reg("CallNextHookEx", 4)(lambda e, h, code, w, l: 0)

    # ------------------------------------------------------------------ window creation
    @reg("CreateWindowExA", 12)
    def create_window(e, ex, clsp, title, style, x, y, w, h, parent, menu, hinst, param):
        ws = S(e)
        cls = find_class(e, clsp)
        if cls is None:
            e.last_error = 1407                         # ERROR_CANNOT_FIND_WND_CLASS
            return 0
        if x == CW_USEDEFAULT:
            x = 0
        if y == CW_USEDEFAULT:
            y = 0
        if w == CW_USEDEFAULT:
            w = SCREEN[0] // 2
        if h == CW_USEDEFAULT:
            h = SCREEN[1] // 2
        hwnd = ws.next_hwnd
        ws.next_hwnd += 4
        child = bool(style & WS_CHILD)
        win = Win(hwnd, cls.name, cls.wndproc, style, ex, parent, x, y, w, h, hinst, menu if child else 0)
        win.text = e.cstr(title) if title else ""
        ws.windows[hwnd] = win
        cs = e.alloc(48)
        e.wr(cs, struct.pack("<12I", param, hinst, menu, parent, h, w, y, x, style, title, clsp, ex))
        for hid_handle, hid, proc in list(ws.hooks):    # MFC subclasses the window from its CBT hook
            if hid == WH_CBT:
                cbt = e.alloc(8)
                e.wr(cbt, struct.pack("<II", cs, 0))
                verdict = yield GuestCall(proc, (HCBT_CREATEWND, hwnd, cbt), "stdcall")
                if verdict:                             # the hook vetoed the creation
                    ws.windows.pop(hwnd, None)
                    return 0
        win.wndproc = ws.windows[hwnd].wndproc          # the hook may have replaced it (SetWindowLong)
        if (yield from send(e, hwnd, WM_NCCREATE, 0, cs)) == 0:
            ws.windows.pop(hwnd, None)
            return 0
        if (yield from send(e, hwnd, WM_CREATE, 0, cs)) & 0xFFFFFFFF == 0xFFFFFFFF:
            yield from send(e, hwnd, WM_NCDESTROY, 0, 0)
            ws.windows.pop(hwnd, None)
            return 0
        yield from send(e, hwnd, WM_SIZE, 0, ((h & 0xFFFF) << 16) | (w & 0xFFFF))
        yield from send(e, hwnd, WM_MOVE, 0, ((y & 0xFFFF) << 16) | (x & 0xFFFF))
        if style & WS_VISIBLE:
            win.visible = True
            yield from send(e, hwnd, WM_SHOWWINDOW, 1, 0)
        e.win_log.append("CreateWindowEx class=%s title=%r style=0x%x ex=0x%x %dx%d at (%d,%d) parent=0x%x -> 0x%x" % (
            cls.name, win.text, style, ex, w, h, x, y, parent, hwnd)) if hasattr(e, "win_log") else None
        return hwnd

    @reg("DestroyWindow", 1)
    def _(e, hwnd):
        return (yield from destroy(e, hwnd))

    @reg("DefWindowProcA", 4)
    def _(e, hwnd, msg, w, l):
        win = S(e).windows.get(hwnd)
        if win is None:
            return 0
        return (yield from defproc(e, win, msg, w, l))

    @reg("CallWindowProcA", 5)
    def _(e, prev, hwnd, msg, w, l):
        ws = S(e)
        win = ws.windows.get(hwnd)
        if prev == ws.defproc and win is not None:
            return (yield from defproc(e, win, msg, w, l))
        return (yield GuestCall(prev, (hwnd, msg, w, l), "stdcall"))

    # ------------------------------------------------------------------ messages
    @reg("SendMessageA", 4)
    def _(e, hwnd, msg, w, l):
        return (yield from send(e, hwnd, msg, w, l))

    @reg("PostMessageA", 4)
    def _(e, hwnd, msg, w, l):
        S(e).queue.append((hwnd, msg, w, l))
        return 1

    @reg("PostThreadMessageA", 4)
    def _(e, tid, msg, w, l):
        S(e).queue.append((0, msg, w, l))
        return 1

    @reg("PostQuitMessage", 1)
    def _(e, code):
        S(e).queue.append((0, WM_QUIT, code, 0))

    def host_events(e):
        """Generator: deliver what the host did since the last pump: focus changes (sent messages) and key
        presses from the DirectInput state (posted WM_KEYDOWN/WM_KEYUP to the focus window, as Windows does)."""
        ws = S(e)
        if ws.pending_app_active is not None:
            want, ws.pending_app_active = ws.pending_app_active, None
            if want and ws.windows:
                main = next((h for h, w in ws.windows.items() if not w.style & WS_CHILD and w.visible), None)
                if main:
                    yield from activate(e, main)
            elif not want:
                yield from deactivate_app(e)
        di = getattr(e, "dinput", None)
        while di is not None and di.keymsgs:
            vk, scan, ext, down, alt = di.keymsgs.popleft()
            target = ws.focus or ws.active
            if not target:
                continue                               # no window has the keyboard focus: dropped, like Windows
            sys_key = alt or vk == 0x79                # Alt held, or F10
            msg = (WM_SYSKEYDOWN if down else WM_SYSKEYUP) if sys_key else (WM_KEYDOWN if down else WM_KEYUP)
            l = 1 | (scan << 16) | (ext << 24) | ((1 if alt else 0) << 29) | ((0 if down else 3) << 30)
            ws.queue.append((target, msg, vk, l))

    KEY_MSGS = (WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP)

    def pop_message(e, pmsg, hwnd_filter, lo, hi, remove):
        """Generator: find a matching message; keyboard messages pass the WH_KEYBOARD hooks first (a hook that
        returns nonzero swallows the message)."""
        ws = S(e)
        yield from host_events(e)
        i = 0
        while i < len(ws.queue):
            h, msg, w, l = ws.queue[i][:4]
            if (hwnd_filter and h != hwnd_filter) or ((lo or hi) and not (lo <= msg <= hi)):
                i += 1
                continue
            if msg in KEY_MSGS and not ws.queue[i][4:]:
                swallowed = False
                for _h, hid, proc in list(ws.hooks):
                    if hid == WH_KEYBOARD:
                        r = yield GuestCall(proc, (HC_ACTION if remove else HC_NOREMOVE, w, l), "stdcall")
                        swallowed = swallowed or bool(r & 0xFFFFFFFF)
                if swallowed:
                    ws.queue.pop(i)
                    continue
                if not remove:                         # hooks already saw it: do not call them again
                    ws.queue[i] = (h, msg, w, l, "hooked")
            if remove:
                ws.queue.pop(i)
            e.wr(pmsg, struct.pack("<7I", h, msg, w, l, m.HLE[("KERNEL32.DLL", "GetTickCount")][0](e), 0, 0))
            return True, msg
        return False, 0

    @reg("PeekMessageA", 5)
    def _(e, pmsg, hwnd, lo, hi, flags):
        found, _ = yield from pop_message(e, pmsg, hwnd, lo, hi, flags & 1)
        return 1 if found else 0

    @reg("GetMessageA", 4)
    def _(e, pmsg, hwnd, lo, hi):
        found, msg = yield from pop_message(e, pmsg, hwnd, lo, hi, True)
        if not found:
            return 0                                   # a real GetMessage would block; end the loop instead
        return 0 if msg == WM_QUIT else 1

    @reg("TranslateMessage", 1)
    def _(e, pmsg):
        """WM_KEYDOWN -> WM_CHAR (WM_SYSKEYDOWN -> WM_SYSCHAR), posted at the front of the queue."""
        hwnd, msg, w, l = struct.unpack("<4I", e.rd(pmsg, 16))
        if msg not in (WM_KEYDOWN, WM_SYSKEYDOWN) or not hasattr(e, "dinput"):
            return 0
        import dinput
        dik = ((l >> 16) & 0x7F) | (0x80 if l & (1 << 24) else 0)
        ch = dinput.char_for(e.dinput, dik)
        if ch is None:
            return 0
        S(e).queue.insert(0, (hwnd, WM_CHAR if msg == WM_KEYDOWN else WM_SYSCHAR, ord(ch), l))
        return 1

    @reg("DispatchMessageA", 1)
    def _(e, pmsg):
        hwnd, msg, w, l = struct.unpack("<4I", e.rd(pmsg, 16))
        if not hwnd:
            return 0
        return (yield from send(e, hwnd, msg, w, l))

    # ------------------------------------------------------------------ window state
    def getwin(e, hwnd):
        return S(e).windows.get(hwnd)

    @reg("IsWindow", 1)
    def _(e, hwnd): return 1 if (hwnd in S(e).windows or hwnd in (DESKTOP, LEGACY_ACTIVE)) else 0

    @reg("IsWindowVisible", 1)
    def _(e, hwnd): return 1 if (getwin(e, hwnd) and getwin(e, hwnd).visible) else 0

    @reg("IsWindowEnabled", 1)
    def _(e, hwnd):
        w_ = getwin(e, hwnd)
        return 1 if (w_ is None or w_.enabled) else 0

    @reg("EnableWindow", 2)
    def _(e, hwnd, enable):
        w_ = getwin(e, hwnd)
        if w_ is None:
            return 0
        was = not w_.enabled
        w_.enabled = bool(enable)
        return 1 if was else 0

    @reg("ShowWindow", 2)
    def _(e, hwnd, cmd):
        w_ = getwin(e, hwnd)
        if w_ is None:
            return 0
        was = w_.visible
        w_.visible = cmd != 0
        yield from send(e, hwnd, WM_SHOWWINDOW, 1 if cmd else 0, 0)
        if cmd not in (0, 4, 6, 7, 8) and not w_.style & WS_CHILD:    # every SW_SHOW* that activates
            yield from activate(e, hwnd)
        return 1 if was else 0

    @reg("GetParent", 1)
    def _(e, hwnd):
        w_ = getwin(e, hwnd)
        return w_.parent if w_ else 0

    @reg("SetParent", 2)
    def _(e, hwnd, parent):
        w_ = getwin(e, hwnd)
        if w_ is None:
            return 0
        old, w_.parent = w_.parent, parent
        return old

    reg("GetWindow", 2)(lambda e, hwnd, cmd: 0)
    reg("IsChild", 2)(lambda e, parent, child: 1 if (getwin(e, child) and getwin(e, child).parent == parent) else 0)

    @reg("GetDlgCtrlID", 1)
    def _(e, hwnd):
        w_ = getwin(e, hwnd)
        return w_.id if w_ else 0

    def signed(v): return v - (1 << 32) if v & 0x80000000 else v

    @reg("GetWindowLongA", 2)
    def _(e, hwnd, idx):
        w_ = getwin(e, hwnd)
        if w_ is None:
            return 0
        idx = signed(idx)
        return {-4: w_.wndproc, -6: w_.hinst, -8: w_.parent, -16: w_.style, -20: w_.exstyle, -21: w_.userdata,
                -12: w_.id}.get(idx, w_.extra.get(idx, 0)) & 0xFFFFFFFF

    @reg("SetWindowLongA", 3)
    def _(e, hwnd, idx, val):
        w_ = getwin(e, hwnd)
        if w_ is None:
            return 0
        idx = signed(idx)
        attr = {-4: "wndproc", -6: "hinst", -8: "parent", -16: "style", -20: "exstyle", -21: "userdata", -12: "id"}.get(idx)
        if attr:
            old = getattr(w_, attr)
            setattr(w_, attr, val)
            return old
        old = w_.extra.get(idx, 0)
        w_.extra[idx] = val
        return old

    @reg("SetPropA", 3)
    def _(e, hwnd, name, data):
        w_ = getwin(e, hwnd)
        if w_ is None:
            return 0
        w_.props[class_name(e, name)] = data
        return 1

    @reg("GetPropA", 2)
    def _(e, hwnd, name):
        w_ = getwin(e, hwnd)
        return w_.props.get(class_name(e, name), 0) if w_ else 0

    @reg("RemovePropA", 2)
    def _(e, hwnd, name):
        w_ = getwin(e, hwnd)
        return w_.props.pop(class_name(e, name), 0) if w_ else 0

    # text
    @reg("SetWindowTextA", 2)
    def _(e, hwnd, text):
        w_ = getwin(e, hwnd)
        if w_ is None:
            return 0
        return 1 if (yield from send(e, hwnd, WM_SETTEXT, 0, text)) else 0

    @reg("GetWindowTextA", 3)
    def _(e, hwnd, buf, n):
        return (yield from send(e, hwnd, WM_GETTEXT, n, buf))

    @reg("GetWindowTextLengthA", 1)
    def _(e, hwnd):
        return (yield from send(e, hwnd, WM_GETTEXTLENGTH, 0, 0))

    # geometry
    def rect_of(e, hwnd):
        if hwnd in (DESKTOP, 0):
            return 0, 0, SCREEN[0], SCREEN[1]
        w_ = getwin(e, hwnd)
        if w_ is None:
            return 0, 0, SCREEN[0], SCREEN[1]
        return w_.x, w_.y, w_.x + w_.w, w_.y + w_.h

    @reg("GetWindowRect", 2)
    def _(e, hwnd, p):
        e.wr(p, struct.pack("<4i", *rect_of(e, hwnd)))
        return 1

    @reg("GetClientRect", 2)
    def _(e, hwnd, p):
        l, t, r, b = rect_of(e, hwnd)
        e.wr(p, struct.pack("<4i", 0, 0, r - l, b - t))
        return 1

    @reg("ClientToScreen", 2)
    def _(e, hwnd, pt):
        l, t, _, _ = rect_of(e, hwnd)
        x_, y_ = struct.unpack("<ii", e.rd(pt, 8))
        e.wr(pt, struct.pack("<ii", x_ + l, y_ + t))
        return 1

    @reg("ScreenToClient", 2)
    def _(e, hwnd, pt):
        l, t, _, _ = rect_of(e, hwnd)
        x_, y_ = struct.unpack("<ii", e.rd(pt, 8))
        e.wr(pt, struct.pack("<ii", x_ - l, y_ - t))
        return 1

    def relocate(e, win, x, y, w, h):
        moved, sized = (x, y) != (win.x, win.y), (w, h) != (win.w, win.h)
        win.x, win.y, win.w, win.h = x, y, w, h
        if sized:
            yield from send(e, win.hwnd, WM_SIZE, 0, ((h & 0xFFFF) << 16) | (w & 0xFFFF))
        if moved:
            yield from send(e, win.hwnd, WM_MOVE, 0, ((y & 0xFFFF) << 16) | (x & 0xFFFF))

    @reg("MoveWindow", 6)
    def _(e, hwnd, x, y, w, h, repaint):
        w_ = getwin(e, hwnd)
        if w_ is None:
            return 0
        yield from relocate(e, w_, signed(x), signed(y), w, h)
        return 1

    @reg("SetWindowPos", 7)
    def _(e, hwnd, after, x, y, cx, cy, flags):
        w_ = getwin(e, hwnd)
        if w_ is None:
            return 0
        nx, ny = (w_.x, w_.y) if flags & 2 else (signed(x), signed(y))      # SWP_NOMOVE
        nw, nh = (w_.w, w_.h) if flags & 1 else (cx, cy)                    # SWP_NOSIZE
        yield from relocate(e, w_, nx, ny, nw, nh)
        if flags & 0x40:                                                    # SWP_SHOWWINDOW
            w_.visible = True
        if flags & 0x80:                                                    # SWP_HIDEWINDOW
            w_.visible = False
        return 1

    @reg("AdjustWindowRectEx", 4)
    def _(e, prect, style, menu, exstyle):
        l, t, r, b = struct.unpack("<4i", e.rd(prect, 16))
        if style & WS_CAPTION == WS_CAPTION:
            l, t, r, b = l - 3, t - 22 - (19 if menu else 0), r + 3, b + 3
        elif style & 0x00800000:                                            # WS_BORDER
            l, t, r, b = l - 1, t - 1, r + 1, b + 1
        e.wr(prect, struct.pack("<4i", l, t, r, b))
        return 1

    # focus / activation
    @reg("GetFocus", 0)
    def _(e): return S(e).focus

    @reg("SetFocus", 1)
    def _(e, hwnd):
        ws = S(e)
        top = top_level(e, hwnd)
        if top is not None and top.hwnd != ws.active:
            yield from activate(e, hwnd)
        return (yield from set_focus(e, hwnd))

    @reg("GetActiveWindow", 0)
    def _(e):
        ws = S(e)
        return ws.active or LEGACY_ACTIVE

    @reg("SetActiveWindow", 1)
    def _(e, hwnd):
        return (yield from activate(e, hwnd))

    reg("GetForegroundWindow", 0)(lambda e: S(e).active or LEGACY_ACTIVE)

    @reg("SetForegroundWindow", 1)
    def _(e, hwnd):
        yield from activate(e, hwnd)
        return 1
    reg("BringWindowToTop", 1)(lambda e, hwnd: 1)
    reg("GetCapture", 0)(lambda e: S(e).capture)
    reg("SetCapture", 1)(lambda e, hwnd: (setattr(S(e), "capture", hwnd), 0)[1])
    reg("ReleaseCapture", 0)(lambda e: (setattr(S(e), "capture", 0), 1)[1])
    reg("UpdateWindow", 1)(lambda e, hwnd: 1)
    reg("InvalidateRect", 3)(lambda e, hwnd, rc, erase: 1)
    reg("SetTimer", 4)(lambda e, hwnd, ident, ms, proc: ident or 1)
    reg("KillTimer", 2)(lambda e, hwnd, ident: 1)
    reg("MapWindowPoints", 4)(lambda e, a, b, pts, n: 0)
