"""Live view: the emulated game drawn with Metal in a native window, with keyboard and mouse input.

The D3D8 layer streams its MPD3 records (emu/d3dcap.py) straight into libmprender (render/, `make -C render`);
on every PRESENT the frame is shown in an SDL3 window's CAMetalLayer. SDL events feed the DirectInput layer
(keys as DIK codes, relative mouse motion, buttons, wheel) and window focus changes (WM_ACTIVATEAPP).

The window can open before the game creates its Direct3D device: the intro movie (emu/dshow.py) plays during
InitInstance and shows its frames with show_bgra; attach_renderer() starts the Direct3D view once the device
exists.

Mouse: while the window has focus and the game holds the mouse exclusively (DirectInput DISCL_EXCLUSIVE, as on
Windows), the pointer is captured in relative mode and hidden; the game draws its own. Cmd+Esc releases it until
the next click; losing focus releases it too. Cmd+Return or Cmd+Ctrl+F toggles macOS fullscreen (remembered in
launcher.json, emu/launcher.py); the frame is scaled to fit with its aspect ratio kept.

Used by emu/run_init.py --window. Needs SDL3 (Homebrew: /opt/homebrew/lib/libSDL3.dylib).
"""
import ctypes
import ctypes.util
import os
import struct
import time

import d3d8
import dinput
import mpemu
import winsys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SDL_INIT_VIDEO = 0x20
SDL_WINDOW_RESIZABLE, SDL_WINDOW_HIGH_PIXEL_DENSITY, SDL_WINDOW_METAL = 0x20, 0x2000, 0x20000000
EV_QUIT, EV_FOCUS_GAINED, EV_FOCUS_LOST, EV_CLOSE = 0x100, 0x20E, 0x20F, 0x210
EV_KEY_DOWN, EV_KEY_UP = 0x300, 0x301
EV_MOTION, EV_BUTTON_DOWN, EV_BUTTON_UP, EV_WHEEL = 0x400, 0x401, 0x402, 0x403
SDL_WINDOW_INPUT_FOCUS = 0x200
KMOD_CTRL, KMOD_GUI = 0x00C0, 0x0C00

# SDL scancodes (USB HID usage IDs) -> DirectInput DIK codes
_LETTERS = {name: code for code, name in dinput.DIK_NAMES.items() if len(name) == 1 and name.isalpha()}
SDL_TO_DIK = {4 + i: _LETTERS[chr(ord("A") + i)] for i in range(26)}
SDL_TO_DIK.update({30 + i: 0x02 + i for i in range(9)})                       # 1..9
SDL_TO_DIK.update({39: 0x0B, 40: 0x1C, 41: 0x01, 42: 0x0E, 43: 0x0F, 44: 0x39, 45: 0x0C, 46: 0x0D, 47: 0x1A,
                   48: 0x1B, 49: 0x2B, 51: 0x27, 52: 0x28, 53: 0x29, 54: 0x33, 55: 0x34, 56: 0x35, 57: 0x3A})
SDL_TO_DIK.update({58 + i: 0x3B + i for i in range(10)})                      # F1..F10
SDL_TO_DIK.update({68: 0x57, 69: 0x58, 70: 0xB7, 71: 0x46, 72: 0xC5, 73: 0xD2, 74: 0xC7, 75: 0xC9, 76: 0xD3,
                   77: 0xCF, 78: 0xD1, 79: 0xCD, 80: 0xCB, 81: 0xD0, 82: 0xC8, 83: 0x45, 84: 0xB5, 85: 0x37,
                   86: 0x4A, 87: 0x4E, 88: 0x9C, 98: 0x52, 99: 0x53,
                   224: 0x1D, 225: 0x2A, 226: 0x38, 227: 0xDB, 228: 0x9D, 229: 0x36, 230: 0xB8, 231: 0xDC})
SDL_TO_DIK.update({89 + i: k for i, k in enumerate((0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49))})
SDL_BUTTON_TO_DI = {1: 0, 3: 1, 2: 2, 4: 3, 5: 4}                             # left, right, middle, X1, X2


class LiveView:
    def __init__(self, e, title="Max Payne (emulated)", scale=0.66):
        self.e = e
        self.sdl = ctypes.CDLL(ctypes.util.find_library("SDL3") or "/opt/homebrew/lib/libSDL3.dylib")
        self.mpr = ctypes.CDLL(os.path.join(ROOT, "build", "libmprender.dylib"))
        sdl, mpr = self.sdl, self.mpr
        sdl.SDL_Init.argtypes = [ctypes.c_uint32]; sdl.SDL_Init.restype = ctypes.c_bool
        sdl.SDL_CreateWindow.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_uint64]
        sdl.SDL_CreateWindow.restype = ctypes.c_void_p
        sdl.SDL_Metal_CreateView.argtypes = [ctypes.c_void_p]; sdl.SDL_Metal_CreateView.restype = ctypes.c_void_p
        sdl.SDL_Metal_GetLayer.argtypes = [ctypes.c_void_p]; sdl.SDL_Metal_GetLayer.restype = ctypes.c_void_p
        sdl.SDL_PollEvent.argtypes = [ctypes.c_void_p]; sdl.SDL_PollEvent.restype = ctypes.c_bool
        sdl.SDL_SetWindowRelativeMouseMode.argtypes = [ctypes.c_void_p, ctypes.c_bool]
        sdl.SDL_SetWindowFullscreen.argtypes = [ctypes.c_void_p, ctypes.c_bool]
        sdl.SDL_SetWindowFullscreen.restype = ctypes.c_bool
        sdl.SDL_GetWindowFlags.argtypes = [ctypes.c_void_p]
        sdl.SDL_GetWindowFlags.restype = ctypes.c_uint64
        sdl.SDL_GetError.restype = ctypes.c_char_p
        mpr.mpr_create.argtypes = [ctypes.c_uint32, ctypes.c_uint32]; mpr.mpr_create.restype = ctypes.c_void_p
        mpr.mpr_submit.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32]
        mpr.mpr_present_to_layer.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        mpr.mpr_last_error.restype = ctypes.c_char_p
        mpr.mpr_notes.argtypes = [ctypes.c_void_p]; mpr.mpr_notes.restype = ctypes.c_char_p
        if hasattr(mpr, "mpr_timing"):                 # absent from renderers built before frames in flight
            mpr.mpr_timing.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_double)]
        if hasattr(mpr, "mpr_gpu_timing"):             # GPU time per frame (renderers from H51 on)
            mpr.mpr_gpu_timing.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_double), ctypes.c_int]
        if not sdl.SDL_Init(SDL_INIT_VIDEO):
            raise RuntimeError("SDL_Init: %s" % sdl.SDL_GetError().decode())
        w, h = d3d8.backbuffer_size(e) if hasattr(e, "d3d") else (0, 0)
        if not w:                                      # before the game creates its device (the intro movie)
            import launcher
            w, h = launcher.resolution(mpemu, e)
        self.window = sdl.SDL_CreateWindow(title.encode(), int(w * scale), int(h * scale),
                                           SDL_WINDOW_METAL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIGH_PIXEL_DENSITY)
        if not self.window:
            raise RuntimeError("SDL_CreateWindow: %s" % sdl.SDL_GetError().decode())
        self.layer = sdl.SDL_Metal_GetLayer(sdl.SDL_Metal_CreateView(self.window))
        self.r = None
        self.event = ctypes.create_string_buffer(128)
        self.quit = False
        self.frames = 0
        self.present_s = self.pump_s = 0.0             # time in mpr_present_to_layer and in the window pump at PRESENT
        self.mouse_captured = False
        self.user_released = False                     # Cmd+Esc: leave the mouse alone until the next click
        self.dx = self.dy = 0.0
        self.held = []                                 # input that arrived during a frame (raw SDL events)
        self.fullscreen = False
        e.live = self
        if getattr(e, "host_settings", {}).get("fullscreen"):
            self.set_fullscreen(True)
        if hasattr(e, "d3d") and d3d8.backbuffer_size(e)[0]:
            self.attach_renderer()

    def attach_renderer(self):
        """Start drawing the game's Direct3D frames (needs its device: call once the device exists)."""
        if self.r:
            return
        w, h = d3d8.backbuffer_size(self.e)
        self.r = self.mpr.mpr_create(w, h)
        if not self.r:
            raise RuntimeError("mpr_create: %s" % self.mpr.mpr_last_error().decode())
        addr = lambda f: ctypes.cast(f, ctypes.c_void_p).value
        # the C handlers (lift/runtime/hle_fast.c) submit straight to the renderer; PRESENT still comes through submit
        d3d8.start_capture(self.e, None, sink=self.submit,
                           c_sink=(addr(self.mpr.mpr_submit), self.r, addr(self.mpr.mpr_last_error)))

    def show_bgra(self, pixels, w, h):
        """Show a BGRA image (a movie frame) in the window."""
        import dshow
        if dshow.Movie.load().mpm_present_bgra(self.layer, pixels, w, h):
            print("[live] movie frame: %s" % dshow.Movie.lib.mpm_last_error().decode())

    def submit(self, typ, payload):
        if self.mpr.mpr_submit(self.r, typ, payload, len(payload)):
            print("[live] renderer: %s" % self.mpr.mpr_last_error().decode())
        if typ == 8:                                   # PRESENT: show it, keep the window responsive
            t0 = time.perf_counter()
            self.mpr.mpr_present_to_layer(self.r, self.layer)
            t1 = time.perf_counter()
            self.frames += 1
            self.pump(deliver_input=False)
            self.present_s += t1 - t0
            self.pump_s += time.perf_counter() - t1

    def capture_mouse(self, on):
        if on != self.mouse_captured:
            self.sdl.SDL_SetWindowRelativeMouseMode(self.window, on)
            self.mouse_captured = on

    def set_fullscreen(self, on, remember=False):
        """macOS fullscreen (a desktop-sized window; the frame is scaled to fit) or a normal window."""
        if self.sdl.SDL_SetWindowFullscreen(self.window, on):
            self.fullscreen = on
            if remember and hasattr(self.e, "host_settings"):
                import launcher
                self.e.host_settings["fullscreen"] = on
                launcher.save_host_settings(mpemu, self.e, self.e.host_settings)

    def game_wants_mouse(self):
        """The game holds the mouse exclusively (DirectInput DISCL_EXCLUSIVE, acquired): on Windows the cursor
        is then hidden and captured, and the game draws its own."""
        di = dinput.input_state(self.e)
        return any(d.kind == "mouse" and d.acquired and d.coop & 0x1 for d in di.devices)

    def update_capture(self):
        focused = bool(self.sdl.SDL_GetWindowFlags(self.window) & SDL_WINDOW_INPUT_FOCUS)
        self.capture_mouse(focused and not self.user_released and self.game_wants_mouse())

    def host_shortcut(self, ev):
        """Mac shortcuts handled by the host: Cmd+Esc releases the mouse, Cmd+Return or Cmd+Ctrl+F toggles
        fullscreen. True if the key was one of them (the game does not see it)."""
        scancode, = struct.unpack_from("<I", ev, 24)
        mod = struct.unpack_from("<H", ev, 32)[0]
        if not mod & KMOD_GUI or ev.raw[37]:           # Cmd held, not an auto-repeat
            return False
        if scancode == 41:                             # Esc
            self.user_released = True
            self.capture_mouse(False)
            return True
        if scancode == 40 or (scancode == 9 and mod & KMOD_CTRL):   # Return, or Ctrl+F
            self.set_fullscreen(not self.fullscreen, remember=True)
            return True
        return False

    def pump(self, deliver_input=True):
        """Handle window events; with deliver_input, feed input to the game. The pump at every PRESENT, inside a
        frame, holds input back until the next frame starts (as DirectInput's buffer would on Windows): mouse
        motion keeps adding up, the rest is replayed in order."""
        di = dinput.input_state(self.e)
        ev = self.event
        if deliver_input and di is not None:
            held, self.held = self.held, []
            for raw in held:
                self.input_event(di, raw)
        while self.sdl.SDL_PollEvent(ev):
            typ = struct.unpack_from("<I", ev, 0)[0]
            if typ in (EV_QUIT, EV_CLOSE):
                self.quit = True
            elif typ == EV_FOCUS_GAINED:
                winsys.host_set_app_active(self.e, True)
            elif typ == EV_FOCUS_LOST:
                winsys.host_set_app_active(self.e, False)
                self.capture_mouse(False)
            elif typ == EV_KEY_DOWN and self.host_shortcut(ev):
                continue
            elif typ == EV_MOTION:
                if self.mouse_captured:
                    xrel, yrel = struct.unpack_from("<ff", ev, 36)
                    self.dx += xrel
                    self.dy += yrel
            elif typ in (EV_KEY_DOWN, EV_KEY_UP, EV_BUTTON_DOWN, EV_BUTTON_UP, EV_WHEEL):
                if deliver_input and di is not None:
                    self.input_event(di, ev.raw)
                else:
                    self.held.append(ev.raw)
        self.update_capture()
        if deliver_input and di is not None:
            ix, iy = int(self.dx), int(self.dy)
            if ix or iy:
                di.mouse_move(ix, iy)
                self.dx -= ix
                self.dy -= iy

    def input_event(self, di, ev):
        """Pass one SDL key, button or wheel event (its raw bytes) to the game."""
        typ = struct.unpack_from("<I", ev, 0)[0]
        if typ in (EV_KEY_DOWN, EV_KEY_UP):
            scancode, = struct.unpack_from("<I", ev, 24)
            repeat = ev[37]
            if typ == EV_KEY_DOWN and struct.unpack_from("<H", ev, 32)[0] & KMOD_GUI:
                return                                 # Cmd+key is the Mac's, not the game's (key-ups still pass)
            if not repeat and scancode in SDL_TO_DIK:
                di.key(SDL_TO_DIK[scancode], typ == EV_KEY_DOWN)
        elif typ in (EV_BUTTON_DOWN, EV_BUTTON_UP):
            button, down = ev[24], ev[25]
            if self.user_released and typ == EV_BUTTON_DOWN:
                self.user_released = False             # a click hands the mouse back to the game
                self.update_capture()
                return
            if button in SDL_BUTTON_TO_DI:
                di.mouse_button(SDL_BUTTON_TO_DI[button], bool(down))
        elif typ == EV_WHEEL:
            y, = struct.unpack_from("<f", ev, 28)
            if y:
                di.mouse_wheel(int(round(y * dinput.WHEEL_DELTA)))

    def timing(self):
        """Where PRESENT's time goes: one line (the renderer's timers when it has them)."""
        line = "present_to_layer %.2fs, window pump %.2fs" % (self.present_s, self.pump_s)
        if self.r and hasattr(self.mpr, "mpr_timing"):
            t = (ctypes.c_double * 5)()
            self.mpr.mpr_timing(self.r, t)
            line += "; renderer: frame wait %.2fs%s, nextDrawable %.2fs, present_to_layer in C %.2fs, drawable resized %d times" % (
                t[0], " (MPR_SYNC: waits for the GPU)" if t[3] else " (frames in flight)", t[1], t[2], t[4])
        if self.r and hasattr(self.mpr, "mpr_gpu_timing"):
            g = (ctypes.c_double * 8)()
            self.mpr.mpr_gpu_timing(self.r, g, 0)
            if g[0]:
                line += "; GPU: %d frames, %.2f ms per frame (median %.2f, p95 %.2f, max %.1f), present blit %.2f ms, busy %.0f%% of %.1fs" % (
                    g[0], g[1] * 1e3 / g[0], g[6], g[7], g[2], g[4] * 1e3 / max(g[3], 1), 100 * (g[1] + g[4]) / g[5] if g[5] else 0, g[5])
        return line

    def notes(self):
        if not self.r:
            return ""
        n = self.mpr.mpr_notes(self.r)
        return n.decode() if n else ""
