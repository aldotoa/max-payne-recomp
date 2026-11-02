/* The live view of the native host (E6): a port of emu/live.py. The game drawn with Metal (libmprender, render/) in an
 * SDL3 window, with keyboard and mouse input. The D3D8 capture (hle_d3d8.c, with hle_fast.c's records) streams its MPD3
 * records into the renderer; at every PRESENT the frame is shown in the window's CAMetalLayer and the window's events
 * are pumped. The window opens before the game creates its device, so the intro movie (hle_dshow.c) shows its frames
 * in it (host_live_layer); the renderer starts with the main loop (host_live_start), as run_init.py --window does.
 * Events feed DirectInput (keys as DIK codes, relative mouse motion, buttons, wheel) and the window manager (focus:
 * WM_ACTIVATEAPP). Input that arrives during a frame waits for the next frame's start, as DirectInput's buffer would
 * on Windows (mouse motion adds up). Mouse: while the window has focus and the game holds the mouse exclusively
 * (DISCL_EXCLUSIVE, acquired), the pointer is captured in relative mode and hidden; Cmd+Esc releases it until the next
 * click. Cmd+Return or Cmd+Ctrl+F toggles macOS fullscreen (remembered in launcher.json); the frame is scaled to fit
 * with its aspect kept. A game controller plays as keyboard and mouse (host/gamepad.c). */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <objc/message.h>
#include <objc/runtime.h>

#include <SDL3/SDL.h>
#include <SDL3/SDL_metal.h>

#include "host.h"
#include "../render/mprender.h"

static const uint8_t SDL_TO_DIK[256] = {
    [4] = 0x1e, [5] = 0x30, [6] = 0x2e, [7] = 0x20, [8] = 0x12, [9] = 0x21, [10] = 0x22, [11] = 0x23, [12] = 0x17, [13]
    = 0x24, [14] = 0x25, [15] = 0x26, [16] = 0x32, [17] = 0x31, [18] = 0x18, [19] = 0x19, [20] = 0x10, [21] = 0x13, [22]
    = 0x1f, [23] = 0x14, [24] = 0x16, [25] = 0x2f, [26] = 0x11, [27] = 0x2d, [28] = 0x15, [29] = 0x2c, [30] = 0x02, [31]
    = 0x03, [32] = 0x04, [33] = 0x05, [34] = 0x06, [35] = 0x07, [36] = 0x08, [37] = 0x09, [38] = 0x0a, [39] = 0x0b, [40]
    = 0x1c, [41] = 0x01, [42] = 0x0e, [43] = 0x0f, [44] = 0x39, [45] = 0x0c, [46] = 0x0d, [47] = 0x1a, [48] = 0x1b, [49]
    = 0x2b, [51] = 0x27, [52] = 0x28, [53] = 0x29, [54] = 0x33, [55] = 0x34, [56] = 0x35, [57] = 0x3a, [58] = 0x3b, [59]
    = 0x3c, [60] = 0x3d, [61] = 0x3e, [62] = 0x3f, [63] = 0x40, [64] = 0x41, [65] = 0x42, [66] = 0x43, [67] = 0x44, [68]
    = 0x57, [69] = 0x58, [70] = 0xb7, [71] = 0x46, [72] = 0xc5, [73] = 0xd2, [74] = 0xc7, [75] = 0xc9, [76] = 0xd3, [77]
    = 0xcf, [78] = 0xd1, [79] = 0xcd, [80] = 0xcb, [81] = 0xd0, [82] = 0xc8, [83] = 0x45, [84] = 0xb5, [85] = 0x37, [86]
    = 0x4a, [87] = 0x4e, [88] = 0x9c, [89] = 0x4f, [90] = 0x50, [91] = 0x51, [92] = 0x4b, [93] = 0x4c, [94] = 0x4d, [95]
    = 0x47, [96] = 0x48, [97] = 0x49, [98] = 0x52, [99] = 0x53, [224] = 0x1d, [225] = 0x2a, [226] = 0x38, [227] = 0xdb,
    [228] = 0x9d, [229] = 0x36, [230] = 0xb8, [231] = 0xdc};

/* SDL mouse buttons -> DirectInput's (left, right, middle, X1, X2); 0: none */
static const uint8_t SDL_BUTTON_TO_DI[8] = {[1] = 1, [3] = 2, [2] = 3, [4] = 4, [5] = 5};

static struct {
    int on, quit, mouse_captured, user_released, fullscreen;
    SDL_Window *window;
    void *layer;
    mpr_renderer *r;
    uint32_t rw, rh;                            /* the renderer's back buffer */
    uint8_t *frame;                             /* host_live_read_frame's copy */
    unsigned frames;
    double present_s, pump_s, dx, dy;
    SDL_Event held[1024];                       /* input that arrived during a frame */
    unsigned nheld;
} V;

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

int host_live_on(void) { return V.on; }
void *host_live_layer(void) { return V.layer; }

/* the last presented frame as RGBA8 (valid until the next call); NULL without the renderer */
const uint8_t *host_live_read_frame(uint32_t *w, uint32_t *h)
{
    if (!V.r)
        return NULL;
    if (!V.frame && !(V.frame = malloc((size_t)V.rw * V.rh * 4)))
        return NULL;
    if (mpr_read_rgba(V.r, V.frame))
        return NULL;
    *w = V.rw, *h = V.rh;
    return V.frame;
}

/* ---------------------------------------------------------------- launcher.json (emu/launcher.py host settings) */
static int g_set_fullscreen;
static char g_set_game_mode[16] = "fullscreen";

static void settings_path(char *out, size_t cap) { snprintf(out, cap, "%s/launcher.json", host_data_dir()); }

/* load_host_settings: the two keys launcher.py knows, defaults for the rest */
void host_settings_load(void)
{
    char p[1200], buf[4096];
    settings_path(p, sizeof p);
    FILE *f = fopen(p, "r");
    if (!f)
        return;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *k = strstr(buf, "\"fullscreen\"");
    if (k && (k = strchr(k + 12, ':'))) {
        while (*++k == ' ')
            ;
        g_set_fullscreen = !strncmp(k, "true", 4);
    }
    k = strstr(buf, "\"game_mode\"");
    if (k && (k = strchr(k + 11, ':')) && (k = strchr(k, '"'))) {
        char *e = strchr(k + 1, '"');
        if (e && e - k - 1 < (long)sizeof g_set_game_mode && (!strncmp(k + 1, "fullscreen", 10) ||
                                                             !strncmp(k + 1, "windowed", 8)))
            snprintf(g_set_game_mode, sizeof g_set_game_mode, "%.*s", (int)(e - k - 1), k + 1);
    }
}

/* save_host_settings: json.dump(indent=1), atomically */
void host_settings_save(void)
{
    char p[1200], tmp[1300];
    settings_path(p, sizeof p);
    snprintf(tmp, sizeof tmp, "%s.tmp", p);
    host_mkdirs(host_data_dir());
    FILE *f = fopen(tmp, "w");
    if (!f)
        return;
    fprintf(f, "{\n \"fullscreen\": %s,\n \"game_mode\": \"%s\"\n}", g_set_fullscreen ? "true" : "false",
            g_set_game_mode);
    fclose(f);
    rename(tmp, p);
}

const char *host_settings_game_mode(void) { return g_set_game_mode; }
void host_settings_set_game_mode(const char *m) { snprintf(g_set_game_mode, sizeof g_set_game_mode, "%s", m); }

/* ---------------------------------------------------------------- the window */
static void set_fullscreen(int on, int remember)
{
    if (SDL_SetWindowFullscreen(V.window, on)) {
        V.fullscreen = on;
        if (remember) {
            g_set_fullscreen = on;
            host_settings_save();
        }
    }
}

/* LiveView.__init__: the window at two thirds of the game's resolution (the device's, or the saved video settings
 * before the device exists) */
void host_live_open(void)
{
    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMEPAD))
        host_fatal("SDL_Init: %s", SDL_GetError());
    uint32_t w = host_reg_dword(APP_VIDEO_SETTINGS, "Display Width", HOST_SCREEN_W);
    uint32_t h = host_reg_dword(APP_VIDEO_SETTINGS, "Display Height", HOST_SCREEN_H);
    V.window = SDL_CreateWindow("Max Payne", (int)(w * 0.66), (int)(h * 0.66),
                                SDL_WINDOW_METAL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIGH_PIXEL_DENSITY);
    if (!V.window)
        host_fatal("SDL_CreateWindow: %s", SDL_GetError());
    V.layer = SDL_Metal_GetLayer(SDL_Metal_CreateView(V.window));
    V.on = 1;
    void *ns = SDL_GetPointerProperty(SDL_GetWindowProperties(V.window), SDL_PROP_WINDOW_COCOA_WINDOW_POINTER, NULL);
    long number = ns ? ((long (*)(void *, SEL))objc_msgSend)(ns, sel_registerName("windowNumber")) : 0;
    printf("live view: window %ld (%ux%u)\n", number, (unsigned)(w * 0.66), (unsigned)(h * 0.66));
    if (g_set_fullscreen)
        set_fullscreen(1, 0);
}

static void pump(int deliver_input);

/* the capture's sink: every record to the renderer; PRESENT shows the frame and keeps the window responsive */
static int renderer_sink(void *ctx, uint32_t type, const void *p, uint32_t len)
{
    (void)ctx;
    if (mpr_submit(V.r, type, p, len))
        fprintf(stderr, "[live] renderer: %s\n", mpr_last_error());
    if (type == MPD3_PRESENT) {
        double t0 = now();
        mpr_present_to_layer(V.r, V.layer);
        double t1 = now();
        V.frames++;
        pump(0);
        V.present_s += t1 - t0;
        V.pump_s += now() - t1;
    }
    return 0;
}

/* attach_renderer: draw the game's Direct3D frames from the start of the main loop */
void host_live_start(void)
{
    if (!V.on || V.r)
        return;
    uint32_t w, h;
    host_d3d_backbuffer(&w, &h);
    if (!w)
        host_fatal("the main loop started with no Direct3D device");
    if (!(V.r = mpr_create(w, h)))
        host_fatal("mpr_create: %s", mpr_last_error());
    V.rw = w, V.rh = h;
    host_d3d_start_capture(renderer_sink, NULL);
    printf("live view open: the game captures the mouse; Cmd+Esc releases it (click to return), Cmd+Return toggles "
           "fullscreen, close the window to stop\n");
}

static void capture_mouse(int on)
{
    if (on != V.mouse_captured) {
        SDL_SetWindowRelativeMouseMode(V.window, on);
        V.mouse_captured = on;
    }
}

static void update_capture(void)
{
    int focused = (SDL_GetWindowFlags(V.window) & SDL_WINDOW_INPUT_FOCUS) != 0;
    capture_mouse(focused && !V.user_released && host_di_mouse_exclusive());
}

/* Mac shortcuts: Cmd+Esc releases the mouse, Cmd+Return or Cmd+Ctrl+F toggles fullscreen (the game does not see them) */
static int host_shortcut(const SDL_KeyboardEvent *k)
{
    if (!(k->mod & SDL_KMOD_GUI) || k->repeat)
        return 0;
    if (k->scancode == SDL_SCANCODE_ESCAPE) {
        V.user_released = 1;
        capture_mouse(0);
        return 1;
    }
    if (k->scancode == SDL_SCANCODE_RETURN || (k->scancode == SDL_SCANCODE_F && (k->mod & SDL_KMOD_CTRL))) {
        set_fullscreen(!V.fullscreen, 1);
        return 1;
    }
    return 0;
}

/* one key, button or wheel event to the game */
static void input_event(const SDL_Event *ev)
{
    if (ev->type == SDL_EVENT_KEY_DOWN || ev->type == SDL_EVENT_KEY_UP) {
        if (ev->type == SDL_EVENT_KEY_DOWN && (ev->key.mod & SDL_KMOD_GUI))
            return;                             /* Cmd+key is the Mac's (key-ups still pass) */
        if (!ev->key.repeat && ev->key.scancode < 256 && SDL_TO_DIK[ev->key.scancode])
            host_key(SDL_TO_DIK[ev->key.scancode], ev->type == SDL_EVENT_KEY_DOWN);
    } else if (ev->type == SDL_EVENT_MOUSE_BUTTON_DOWN || ev->type == SDL_EVENT_MOUSE_BUTTON_UP) {
        if (V.user_released && ev->type == SDL_EVENT_MOUSE_BUTTON_DOWN) {
            V.user_released = 0;                /* a click hands the mouse back to the game */
            update_capture();
            return;
        }
        if (ev->button.button < 8 && SDL_BUTTON_TO_DI[ev->button.button])
            host_mouse_button(SDL_BUTTON_TO_DI[ev->button.button] - 1, ev->button.down);
    } else if (ev->type == SDL_EVENT_MOUSE_WHEEL) {
        if (ev->wheel.y != 0)
            host_mouse_wheel((int32_t)lround(ev->wheel.y * 120.0));
    }
}

/* the window's events; with deliver_input, input goes to the game (else it waits for the next frame's start) */
static void pump(int deliver_input)
{
    if (deliver_input) {
        for (unsigned i = 0; i < V.nheld; i++)
            input_event(&V.held[i]);
        V.nheld = 0;
    }
    SDL_Event ev;
    while (SDL_PollEvent(&ev)) {
        switch (ev.type) {
        case SDL_EVENT_QUIT:
        case SDL_EVENT_WINDOW_CLOSE_REQUESTED:
            V.quit = 1;
            break;
        case SDL_EVENT_WINDOW_FOCUS_GAINED:
            host_set_app_active(1);
            break;
        case SDL_EVENT_WINDOW_FOCUS_LOST:
            host_set_app_active(0);
            capture_mouse(0);
            gamepad_focus_lost();
            break;
        case SDL_EVENT_GAMEPAD_ADDED:
        case SDL_EVENT_GAMEPAD_REMOVED:
            gamepad_event(&ev);
            break;
        case SDL_EVENT_MOUSE_MOTION:
            if (V.mouse_captured)
                V.dx += ev.motion.xrel, V.dy += ev.motion.yrel;
            break;
        case SDL_EVENT_KEY_DOWN:
            if (host_shortcut(&ev.key))
                break;
            /* fall through */
        case SDL_EVENT_KEY_UP:
        case SDL_EVENT_MOUSE_BUTTON_DOWN:
        case SDL_EVENT_MOUSE_BUTTON_UP:
        case SDL_EVENT_MOUSE_WHEEL:
            if (deliver_input)
                input_event(&ev);
            else if (V.nheld < sizeof V.held / sizeof *V.held)
                V.held[V.nheld++] = ev;
            break;
        }
    }
    update_capture();
    if (deliver_input) {
        if (SDL_GetWindowFlags(V.window) & SDL_WINDOW_INPUT_FOCUS) {
            double gx = 0, gy = 0;
            gamepad_frame(now(), &gx, &gy);
            if (V.mouse_captured)
                V.dx += gx, V.dy += gy;
        }
        int ix = (int)V.dx, iy = (int)V.dy;     /* (Python's int(): toward zero) */
        if (ix || iy) {
            host_mouse_move(ix, iy);
            V.dx -= ix, V.dy -= iy;
        }
    }
}

void host_live_pump(void)
{
    if (V.on)
        pump(1);
}

/* quit_requested: the frame's pump; 1 when the window was closed */
int host_live_pump_frame(void)
{
    if (!V.on)
        return 0;
    pump(1);
    if (V.quit)
        printf("window closed after %u frames\n", V.frames);
    return V.quit;
}

void host_live_close(void)
{
    if (!V.on)
        return;
    printf("live view: %u frames presented\n", V.frames);
    if (V.r) {
        double t[5];
        mpr_timing(V.r, t);
        printf("live view, present: present_to_layer %.2fs, window pump %.2fs; renderer: frame wait %.2fs%s, "
               "nextDrawable %.2fs, present_to_layer in C %.2fs, drawable resized %d times\n", V.present_s, V.pump_s,
               t[0], t[3] ? " (MPR_SYNC: waits for the GPU)" : " (frames in flight)", t[1], t[2], (int)t[4]);
        const char *n = mpr_notes(V.r);
        if (n && *n)
            printf("renderer notes:\n  %s\n", n);
    }
    V.on = 0;
}
