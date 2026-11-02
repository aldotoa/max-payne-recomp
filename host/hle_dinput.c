/* DirectInput for the native host (E6): a port of emu/dinput.py. The shared input state (Input: the keys, mouse
 * buttons, lock toggles, GetAsyncKeyState's "pressed since" bits, the key messages winsys posts as WM_KEYDOWN/WM_KEYUP),
 * DirectInputCreateA/Ex, IDirectInput7A (devices, enumeration) and IDirectInputDevice7A (the system keyboard and
 * mouse: data formats, cooperative level, properties, acquisition, the immediate state and the buffered events, object
 * and device info), and the USER32 keyboard queries that answer from the same state (GetAsyncKeyState, GetKeyState,
 * GetKeyboardState, ToAscii, GetKeyNameTextA). As in a native emulator run (H61), hle_fast.c serves Acquire,
 * GetDeviceState and GetDeviceData and owns the devices' run state (acquired, lost, overflow, the motion, the event
 * queue) and the keys, buttons and sequence number: a device is registered there when it is created (host_di_new) and
 * its configuration copied there when it changes (host_di_cfg); the rest reads and writes that state (host_di_field,
 * host_di_queue, host_di_keys). Input comes from the live view's window (host/live.c) or from the host itself
 * (hle_dshow.c: Space to skip the intro in a headless run). Not here: a scripted poll hook; joysticks and force
 * feedback are not provided. */
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"

#define DI "DINPUT.DLL"
#define U "USER32.DLL"
#define H(name) static uint32_t name(CPU *c, const uint32_t *a)
#define UNUSED (void)c, (void)a

enum { DI_OK = 0, DI_NOEFFECT = 1, E_NOINTERFACE = 0x80004002u, DIERR_INVALIDPARAM = 0x80070057u,
       DIERR_NOAGGREGATION = 0x80040110u, DIERR_DEVICENOTREG = 0x80040154u, DIERR_UNSUPPORTED = 0x80004001u,
       DIERR_NOTACQUIRED = 0x8007000Cu, DIERR_INPUTLOST = 0x8007001Eu, DIERR_ACQUIRED = 0x800700AAu,
       DIERR_NOTBUFFERED = 0x80040207u, DIERR_OLDDIRECTINPUTVERSION = 0x8007047Eu,
       DIERR_BETADIRECTINPUTVERSION = 0x80070481u, DIERR_NOTFOUND = 0x80070002u };
#define DI_BUFFEROVERFLOW 1u
#define INFINITE 0xFFFFFFFFu
#define DIGDD_PEEK 1u
#define DIDFT_RELAXIS 0x1u
#define DIDFT_PSHBUTTON 0x4u
#define DIDFT_ANYINSTANCE 0xFFFF00u
#define WHEEL_DELTA 120u
#define MOUSE_BUTTONS 5

typedef struct { const char *name; uint8_t nparams; } Meth;
static const Meth IDIRECTINPUT7[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"CreateDevice", 3}, {"EnumDevices", 4}, {"GetDeviceStatus",
    1}, {"RunControlPanel", 2}, {"Initialize", 2}, {"FindDevice", 3}, {"CreateDeviceEx", 4}, {NULL, 0}};
static const Meth IDIRECTINPUTDEVICE7[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"GetCapabilities", 1}, {"EnumObjects", 3}, {"GetProperty",
    2}, {"SetProperty", 2}, {"Acquire", 0}, {"Unacquire", 0}, {"GetDeviceState", 2}, {"GetDeviceData", 4},
    {"SetDataFormat", 1}, {"SetEventNotification", 1}, {"SetCooperativeLevel", 2}, {"GetObjectInfo", 3},
    {"GetDeviceInfo", 1}, {"RunControlPanel", 2}, {"Initialize", 3}, {"CreateEffect", 4}, {"EnumEffects", 3},
    {"GetEffectInfo", 2}, {"GetForceFeedbackState", 1}, {"SendForceFeedbackCommand", 1}, {"EnumCreatedEffectObjects",
    3}, {"Escape", 1}, {"Poll", 0}, {"SendDeviceData", 4}, {"EnumEffectsInFile", 4}, {"WriteEffectToFile", 4}, {NULL,
    0}};
/* VK -> its DIK codes (dinput.VK_TO_DIK; up to two) */
static const uint8_t VK_TO_DIK[256][2] = {
    [0x08] = {0x0e}, [0x09] = {0x0f}, [0x0d] = {0x1c, 0x9c}, [0x10] = {0x2a, 0x36}, [0x11] = {0x1d, 0x9d}, [0x12] =
    {0x38, 0xb8}, [0x13] = {0x45}, [0x14] = {0x3a}, [0x1b] = {0x01}, [0x20] = {0x39}, [0x21] = {0xc9}, [0x22] = {0xd1},
    [0x23] = {0xcf}, [0x24] = {0xc7}, [0x25] = {0xcb}, [0x26] = {0xc8}, [0x27] = {0xcd}, [0x28] = {0xd0}, [0x2d] =
    {0xd2}, [0x2e] = {0xd3}, [0x30] = {0x0b}, [0x31] = {0x02}, [0x32] = {0x03}, [0x33] = {0x04}, [0x34] = {0x05}, [0x35]
    = {0x06}, [0x36] = {0x07}, [0x37] = {0x08}, [0x38] = {0x09}, [0x39] = {0x0a}, [0x41] = {0x1e}, [0x42] = {0x30},
    [0x43] = {0x2e}, [0x44] = {0x20}, [0x45] = {0x12}, [0x46] = {0x21}, [0x47] = {0x22}, [0x48] = {0x23}, [0x49] =
    {0x17}, [0x4a] = {0x24}, [0x4b] = {0x25}, [0x4c] = {0x26}, [0x4d] = {0x32}, [0x4e] = {0x31}, [0x4f] = {0x18}, [0x50]
    = {0x19}, [0x51] = {0x10}, [0x52] = {0x13}, [0x53] = {0x1f}, [0x54] = {0x14}, [0x55] = {0x16}, [0x56] = {0x2f},
    [0x57] = {0x11}, [0x58] = {0x2d}, [0x59] = {0x15}, [0x5a] = {0x2c}, [0x5b] = {0xdb}, [0x5c] = {0xdc}, [0x5d] =
    {0xdd}, [0x60] = {0x52}, [0x61] = {0x4f}, [0x62] = {0x50}, [0x63] = {0x51}, [0x64] = {0x4b}, [0x65] = {0x4c}, [0x66]
    = {0x4d}, [0x67] = {0x47}, [0x68] = {0x48}, [0x69] = {0x49}, [0x6a] = {0x37}, [0x6b] = {0x4e}, [0x6d] = {0x4a},
    [0x6e] = {0x53}, [0x6f] = {0xb5}, [0x70] = {0x3b}, [0x71] = {0x3c}, [0x72] = {0x3d}, [0x73] = {0x3e}, [0x74] =
    {0x3f}, [0x75] = {0x40}, [0x76] = {0x41}, [0x77] = {0x42}, [0x78] = {0x43}, [0x79] = {0x44}, [0x7a] = {0x57}, [0x7b]
    = {0x58}, [0x90] = {0xc5}, [0x91] = {0x46}, [0xa0] = {0x2a}, [0xa1] = {0x36}, [0xa2] = {0x1d}, [0xa3] = {0x9d},
    [0xa4] = {0x38}, [0xa5] = {0xb8}, [0xba] = {0x27}, [0xbb] = {0x0d}, [0xbc] = {0x33}, [0xbd] = {0x0c}, [0xbe] =
    {0x34}, [0xbf] = {0x35}, [0xc0] = {0x29}, [0xdb] = {0x1a}, [0xdc] = {0x2b}, [0xdd] = {0x1b}, [0xde] = {0x28}};
/* VK_LBUTTON.. -> mouse button + 1 (dinput.VK_MOUSE) */
static const uint8_t VK_MOUSE[256] = {[0x01] = 1, [0x02] = 2, [0x04] = 3, [0x05] = 4, [0x06] = 5};
/* DIK -> the name GetKeyNameTextA gives on a US layout (dinput.DIK_NAMES) */
static const char *const DIK_NAMES[256] = {
    [0x01] = "Esc", [0x02] = "1", [0x03] = "2", [0x04] = "3", [0x05] = "4", [0x06] = "5", [0x07] = "6", [0x08] = "7",
    [0x09] = "8", [0x0a] = "9", [0x0b] = "0", [0x0c] = "-", [0x0d] = "=", [0x0e] = "Backspace", [0x0f] = "Tab", [0x10] =
    "Q", [0x11] = "W", [0x12] = "E", [0x13] = "R", [0x14] = "T", [0x15] = "Y", [0x16] = "U", [0x17] = "I", [0x18] = "O",
    [0x19] = "P", [0x1a] = "[", [0x1b] = "]", [0x1c] = "Enter", [0x1d] = "Ctrl", [0x1e] = "A", [0x1f] = "S", [0x20] =
    "D", [0x21] = "F", [0x22] = "G", [0x23] = "H", [0x24] = "J", [0x25] = "K", [0x26] = "L", [0x27] = ";", [0x28] = "'",
    [0x29] = "`", [0x2a] = "Shift", [0x2b] = "\\", [0x2c] = "Z", [0x2d] = "X", [0x2e] = "C", [0x2f] = "V", [0x30] = "B",
    [0x31] = "N", [0x32] = "M", [0x33] = ",", [0x34] = ".", [0x35] = "/", [0x36] = "Right Shift", [0x37] = "Num *",
    [0x38] = "Alt", [0x39] = "Space", [0x3a] = "Caps Lock", [0x3b] = "F1", [0x3c] = "F2", [0x3d] = "F3", [0x3e] = "F4",
    [0x3f] = "F5", [0x40] = "F6", [0x41] = "F7", [0x42] = "F8", [0x43] = "F9", [0x44] = "F10", [0x45] = "Pause", [0x46]
    = "Scroll Lock", [0x47] = "Num 7", [0x48] = "Num 8", [0x49] = "Num 9", [0x4a] = "Num -", [0x4b] = "Num 4", [0x4c] =
    "Num 5", [0x4d] = "Num 6", [0x4e] = "Num +", [0x4f] = "Num 1", [0x50] = "Num 2", [0x51] = "Num 3", [0x52] = "Num 0",
    [0x53] = "Num Del", [0x57] = "F11", [0x58] = "F12", [0x9c] = "Num Enter", [0x9d] = "Right Ctrl", [0xb5] = "Num /",
    [0xb7] = "Prnt Scrn", [0xb8] = "Right Alt", [0xc5] = "Num Lock", [0xc7] = "Home", [0xc8] = "Up", [0xc9] = "Page Up",
    [0xcb] = "Left", [0xcd] = "Right", [0xcf] = "End", [0xd0] = "Down", [0xd1] = "Page Down", [0xd2] = "Insert", [0xd3]
    = "Delete", [0xdb] = "Left Windows", [0xdc] = "Right Windows", [0xdd] = "Application"};


/* DIK -> the virtual key Windows puts in WM_KEYDOWN (dinput.DIK_TO_VK: generic VK_SHIFT/VK_CONTROL/VK_MENU) */
static const uint8_t DIK_TO_VK[256] = {
    0x0, 0x1b, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0xbd, 0xbb, 0x8, 0x9, 0x51, 0x57, 0x45,
    0x52, 0x54, 0x59, 0x55, 0x49, 0x4f, 0x50, 0xdb, 0xdd, 0xd, 0x11, 0x41, 0x53, 0x44, 0x46, 0x47, 0x48, 0x4a, 0x4b,
    0x4c, 0xba, 0xde, 0xc0, 0x10, 0xdc, 0x5a, 0x58, 0x43, 0x56, 0x42, 0x4e, 0x4d, 0xbc, 0xbe, 0xbf, 0x10, 0x6a, 0x12,
    0x20, 0x14, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x13, 0x91, 0x67, 0x68, 0x69, 0x6d, 0x64,
    0x65, 0x66, 0x6b, 0x61, 0x62, 0x63, 0x60, 0x6e, 0x0, 0x0, 0x0, 0x7a, 0x7b,
    [0x9c] = 0xd, [0x9d] = 0x11, [0xb5] = 0x6f, [0xb8] = 0x12, [0xc5] = 0x90, [0xc7] = 0x24, [0xc8] = 0x26,
    [0xc9] = 0x21, [0xcb] = 0x25, [0xcd] = 0x27, [0xcf] = 0x23, [0xd0] = 0x28, [0xd1] = 0x22, [0xd2] = 0x2d,
    [0xd3] = 0x2e, [0xdb] = 0x5b, [0xdc] = 0x5c, [0xdd] = 0x5d,
};

/* US-layout characters (dinput._US): DIK -> plain, shifted */
static const char US[256][3] = {
    [0x01] = "\x1b\x1b", [0x02] = "1!", [0x03] = "2@", [0x04] = "3#", [0x05] = "4$", [0x06] = "5%", [0x07] = "6^",
    [0x08] = "7&", [0x09] = "8*", [0x0A] = "9(", [0x0B] = "0)", [0x0C] = "-_", [0x0D] = "=+", [0x0E] = "\b\b",
    [0x0F] = "\t\t", [0x10] = "qQ", [0x11] = "wW", [0x12] = "eE", [0x13] = "rR", [0x14] = "tT", [0x15] = "yY",
    [0x16] = "uU", [0x17] = "iI", [0x18] = "oO", [0x19] = "pP", [0x1A] = "[{", [0x1B] = "]}", [0x1C] = "\r\r",
    [0x1E] = "aA", [0x1F] = "sS", [0x20] = "dD", [0x21] = "fF", [0x22] = "gG", [0x23] = "hH", [0x24] = "jJ",
    [0x25] = "kK", [0x26] = "lL", [0x27] = ";:", [0x28] = "'\"", [0x29] = "`~", [0x2B] = "\\|", [0x2C] = "zZ",
    [0x2D] = "xX", [0x2E] = "cC", [0x2F] = "vV", [0x30] = "bB", [0x31] = "nN", [0x32] = "mM", [0x33] = ",<",
    [0x34] = ".>", [0x35] = "/?", [0x37] = "**", [0x39] = "  ", [0x4A] = "--", [0x4E] = "++", [0x9C] = "\r\r",
    [0xB5] = "//",
};


static const uint8_t IID_IUNKNOWN[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46};
#define GUIDB(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)                                                                 \
    {(a) & 0xFF, ((a) >> 8) & 0xFF, ((a) >> 16) & 0xFF, ((a) >> 24) & 0xFF, (b) & 0xFF, ((b) >> 8) & 0xFF, (c) & 0xFF, \
     ((c) >> 8) & 0xFF, d0, d1, d2, d3, d4, d5, d6, d7}
static const uint8_t DI_IIDS[3][16] = {
    GUIDB(0x89521360u, 0xAA8A, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00),   /* IDirectInputA */
    GUIDB(0x5944E662u, 0xAA8A, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00),   /* IDirectInput2A */
    GUIDB(0x9A4CB684u, 0x236D, 0x11D3, 0x8E, 0x9D, 0x00, 0xC0, 0x4F, 0x68, 0x44, 0xAE),   /* IDirectInput7A */
};
static const uint8_t DEV_IIDS[3][16] = {
    GUIDB(0x5944E680u, 0xC92E, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00),   /* IDirectInputDeviceA */
    GUIDB(0x5944E682u, 0xC92E, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00),   /* IDirectInputDevice2A */
    GUIDB(0x57D7C6BCu, 0x2356, 0x11D3, 0x8E, 0x9D, 0x00, 0xC0, 0x4F, 0x68, 0x44, 0xAE),   /* IDirectInputDevice7A */
};
static const uint8_t GUID_SYSMOUSE[16] = GUIDB(0x6F1D2B60u, 0xD5A0, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0, 0);
static const uint8_t GUID_SYSKEYBOARD[16] = GUIDB(0x6F1D2B61u, 0xD5A0, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0, 0);
static const uint8_t GUID_AXES[3][16] = {
    GUIDB(0xA36D02E0u, 0xC9F3, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00),
    GUIDB(0xA36D02E1u, 0xC9F3, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00),
    GUIDB(0xA36D02E2u, 0xC9F3, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00),
};
static const uint8_t GUID_BUTTON[16] = GUIDB(0xA36D02F0u, 0xC9F3, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0, 0);
static const uint8_t GUID_KEY[16] = GUIDB(0x55728220u, 0xD33C, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0, 0);
/* product GUIDs: arbitrary but stable, so saved bindings keep matching */
static const uint8_t PRODUCT[2][16] = {
    GUIDB(0x6F1D2B61u, 0xD5A0, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x01),   /* keyboard */
    GUIDB(0x6F1D2B60u, 0xD5A0, 0x11CF, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x01),   /* mouse */
};

static inline uint32_t r32(uint32_t p) { uint32_t v; memcpy(&v, gptr(p), 4); return v; }
static inline void w32(uint32_t p, uint32_t v) { memcpy(gptr(p), &v, 4); }
static inline void out32(uint32_t p, uint32_t v) { if (p) w32(p, v); }

/* now_ms: time.perf_counter_ns() // 1e6 (the emulator's GetTickCount clock), mach time on macOS */
static uint32_t now_ms(void)
{
    if (host_clock_sim_fps())
        return (uint32_t)(host_clock_ns() / 1000000u);
    static mach_timebase_info_data_t tb;
    if (!tb.denom)
        mach_timebase_info(&tb);
    return (uint32_t)((uint64_t)((__uint128_t)mach_absolute_time() * tb.numer / tb.denom) / 1000000u);
}

/* ---------------------------------------------------------------- devices */
enum { KEYBOARD, MOUSE };
enum { DIO_KEY, DIO_BUTTON, DIO_AXIS };         /* hle_fast.c's object kinds */
enum { F_ACQUIRED, F_LOST, F_OVERFLOW, F_DX, F_DY, F_DZ };
enum { Q_LEN, Q_APPEND, Q_POP, Q_CLEAR, Q_GET };

typedef struct { uint32_t kind, inst, ofs; } FmtObj;
typedef struct {
    int kind, slot, live;                       /* live: in Input.devices (until its last Release) */
    uint32_t coop, bufsize, axis_mode, event;
    int has_fmt;
    uint32_t fmt_size, fmt_flags, nobj;
    FmtObj obj[300];                            /* in the order they matched (Python's dict order) */
} Dev;

typedef struct { uint32_t addr; int iface; Dev *dev; } Obj;   /* iface 0 IDirectInput7A, 1 IDirectInputDevice7A */
static Obj *g_objs;
static uint32_t g_nobjs, g_capobjs;
static Dev *g_devs[64];                         /* Input.devices, creation order */
static uint32_t g_ndevs;

static struct {
    uint8_t toggles[256];                       /* Caps Lock, Num Lock, Scroll Lock: toggled on key-down */
    uint8_t async_seen[256];                    /* GetAsyncKeyState's "pressed since the last call" */
    HostKeyMsg q[256];                          /* keymsgs, a ring */
    uint32_t head, n;
    int made;                                   /* input_state(e) was called */
} I = {.made = 1};   /* a native emulator run makes it at start-up (HleFast.__init__ -> dinput.attach_fast) */

static uint8_t *keys(void) { return host_di_keys(); }          /* 256 keys, then 8 buttons, in hle_fast.c */
static uint8_t *buttons(void) { return host_di_keys() + 256; }

int host_input_made(void) { return I.made; }

static void push_cfg(Dev *d)
{
    uint32_t t[900];
    for (uint32_t i = 0; i < d->nobj; i++)
        t[3 * i] = d->obj[i].kind, t[3 * i + 1] = d->obj[i].inst, t[3 * i + 2] = d->obj[i].ofs;
    host_di_cfg(d->slot, d->coop, d->has_fmt, d->has_fmt ? d->fmt_size : 0, d->bufsize, d->nobj, t);
}

static int64_t field(Dev *d, int f) { return host_di_field(d->slot, f, 0, 0); }
static void set_field(Dev *d, int f, int64_t v) { host_di_field(d->slot, f, 1, v); }
static uint32_t qlen(Dev *d) { return host_di_queue(d->slot, Q_LEN, 0, NULL); }

/* Input._post: one event to every acquired, formatted, buffered device of that kind that has the object */
static void post(int kind, uint32_t okind, uint32_t inst, uint32_t data)
{
    uint32_t seq = (uint32_t)host_di_field(-1, 0, 0, 0) + 1;
    host_di_field(-1, 0, 1, seq);
    uint32_t stamp = now_ms();
    for (uint32_t i = 0; i < g_ndevs; i++) {
        Dev *d = g_devs[i];
        if (!d->live || d->kind != kind || !field(d, F_ACQUIRED) || !d->has_fmt || !d->bufsize)
            continue;
        int found = -1;
        for (uint32_t k = 0; k < d->nobj && found < 0; k++)
            if (d->obj[k].kind == okind && d->obj[k].inst == inst)
                found = (int)k;
        if (found < 0)
            continue;
        if (qlen(d) >= d->bufsize) {
            host_di_queue(d->slot, Q_POP, 0, NULL);
            set_field(d, F_OVERFLOW, 1);
        }
        uint32_t ev[4] = {d->obj[found].ofs, data, stamp, seq};
        host_di_queue(d->slot, Q_APPEND, 0, ev);
    }
}

/* Input.key: a host key press or release */
void host_key(uint32_t dik, int down)
{
    I.made = 1;
    dik &= 0xFF;
    uint8_t *k = keys();
    if (!!k[dik] == !!down)
        return;
    k[dik] = down ? 0x80 : 0;
    if (down) {
        I.async_seen[dik] = 1;
        if (dik == 0x3A || dik == 0xC5 || dik == 0x46)
            I.toggles[dik] ^= 1;
    }
    post(KEYBOARD, DIO_KEY, dik, down ? 0x80 : 0);
    if (DIK_TO_VK[dik]) {
        if (I.n == 256)                 /* (Python's deque is unbounded; 256 unread key messages do not happen) */
            host_fatal("too many unread key messages");
        I.q[(I.head + I.n++) % 256] = (HostKeyMsg){DIK_TO_VK[dik], dik & 0x7F, (dik & 0x80) != 0, !!down,
                                                   k[0x38] || k[0xB8]};
    }
}

int host_key_msg(HostKeyMsg *m)
{
    if (!I.n)
        return 0;
    *m = I.q[I.head];
    I.head = (I.head + 1) % 256;
    I.n--;
    return 1;
}

/* Input.mouse_move, mouse_wheel, mouse_button: host mouse input (relative motion, wheel steps, buttons 0..4) */
void host_mouse_move(int32_t dx, int32_t dy)
{
    for (uint32_t i = 0; i < g_ndevs; i++) {
        Dev *d = g_devs[i];
        if (d->live && d->kind == MOUSE && field(d, F_ACQUIRED)) {
            set_field(d, F_DX, field(d, F_DX) + dx);
            set_field(d, F_DY, field(d, F_DY) + dy);
        }
    }
    if (dx)
        post(MOUSE, DIO_AXIS, 0, (uint32_t)dx);
    if (dy)
        post(MOUSE, DIO_AXIS, 1, (uint32_t)dy);
}

void host_mouse_wheel(int32_t dz)
{
    for (uint32_t i = 0; i < g_ndevs; i++) {
        Dev *d = g_devs[i];
        if (d->live && d->kind == MOUSE && field(d, F_ACQUIRED))
            set_field(d, F_DZ, field(d, F_DZ) + dz);
    }
    post(MOUSE, DIO_AXIS, 2, (uint32_t)dz);
}

void host_mouse_button(uint32_t n, int down)
{
    if (n >= MOUSE_BUTTONS || !!buttons()[n] == !!down)
        return;
    buttons()[n] = down ? 0x80 : 0;
    post(MOUSE, DIO_BUTTON, n, down ? 0x80 : 0);
}

/* the game holds the mouse exclusively (DISCL_EXCLUSIVE, acquired): the live view captures the pointer */
int host_di_mouse_exclusive(void)
{
    for (uint32_t i = 0; i < g_ndevs; i++)
        if (g_devs[i]->live && g_devs[i]->kind == MOUSE && field(g_devs[i], F_ACQUIRED) && (g_devs[i]->coop & 0x1))
            return 1;
    return 0;
}

/* Input.focus_lost: FOREGROUND devices are unacquired and their next poll says so */
void host_focus_lost(void)
{
    for (uint32_t i = 0; i < g_ndevs; i++) {
        Dev *d = g_devs[i];
        if (d->live && field(d, F_ACQUIRED) && (d->coop & 0x4)) {
            set_field(d, F_ACQUIRED, 0);
            set_field(d, F_LOST, 1);
            host_di_queue(d->slot, Q_CLEAR, 0, NULL);
        }
    }
    memset(keys(), 0, 264);
}

/* char_for: the character a key gives on a US layout with the current Shift/Ctrl/Alt/Caps Lock, or -1 */
int host_char_for(uint32_t dik)
{
    const char *ch = US[dik & 0xFF];
    uint8_t *k = keys();
    if (!ch[0] || k[0x1D] || k[0x9D] || k[0x38] || k[0xB8])
        return -1;
    int shift = k[0x2A] || k[0x36];
    if (ch[0] >= 'a' && ch[0] <= 'z' && I.toggles[0x3A])
        shift = !shift;
    return (unsigned char)ch[shift];
}

static int vk_down(uint32_t vk)
{
    if (VK_MOUSE[vk])
        return buttons()[VK_MOUSE[vk] - 1] != 0;
    for (int i = 0; i < 2 && VK_TO_DIK[vk][i]; i++)
        if (keys()[VK_TO_DIK[vk][i]])
            return 1;
    return 0;
}

static int vk_toggled(uint32_t vk)
{
    for (int i = 0; i < 2 && VK_TO_DIK[vk][i]; i++)
        if (I.toggles[VK_TO_DIK[vk][i]])
            return 1;
    return 0;
}

/* ---------------------------------------------------------------- objects */
static uint32_t g_vtables[2];

static uint32_t vtable(int iface)
{
    if (!g_vtables[iface]) {
        const Meth *m = iface ? IDIRECTINPUTDEVICE7 : IDIRECTINPUT7;
        const char *name = iface ? "IDirectInputDevice7A" : "IDirectInput7A";
        uint32_t n = 0;
        while (m[n].name)
            n++;
        uint32_t p = host_alloc(4 * n);
        for (uint32_t k = 0; k < n; k++) {
            char s[128];
            snprintf(s, sizeof s, "%s::%s", name, m[k].name);
            w32(p + 4 * k, host_stub_for(DI, s));
        }
        g_vtables[iface] = p;
    }
    return g_vtables[iface];
}

static Obj *new_obj(int iface, Dev *dev)
{
    uint32_t a = host_alloc(16);
    w32(a, vtable(iface));
    w32(a + 4, 1);
    if (g_nobjs == g_capobjs) {
        g_capobjs = g_capobjs ? 2 * g_capobjs : 16;
        g_objs = realloc(g_objs, g_capobjs * sizeof *g_objs);
    }
    g_objs[g_nobjs] = (Obj){a, iface, dev};
    return &g_objs[g_nobjs++];
}

static Obj *find(uint32_t a)
{
    for (uint32_t i = 0; i < g_nobjs; i++)
        if (g_objs[i].addr == a)
            return &g_objs[i];
    return NULL;
}

static Dev *dev(uint32_t this)
{
    Obj *o = find(this);
    if (!o || !o->dev)
        host_fatal("DINPUT: 0x%x is no device", this);
    return o->dev;
}

/* ---------------------------------------------------------------- IUnknown */
static int iid_in(uint32_t p, const uint8_t (*ids)[16])
{
    if (p < 0x10000)
        return 0;
    if (!memcmp(gptr(p), IID_IUNKNOWN, 16))
        return 1;
    for (int i = 0; i < 3; i++)
        if (!memcmp(gptr(p), ids[i], 16))
            return 1;
    return 0;
}

static uint32_t qi(const uint32_t *a, const uint8_t (*ids)[16])
{
    if (!iid_in(a[1], ids)) {
        out32(a[2], 0);
        return E_NOINTERFACE;
    }
    w32(a[0] + 4, r32(a[0] + 4) + 1);
    out32(a[2], a[0]);
    return DI_OK;
}

H(QiDi) { UNUSED; return qi(a, DI_IIDS); }
H(QiDev) { UNUSED; return qi(a, DEV_IIDS); }

H(AddRef)
{
    UNUSED;
    uint32_t n = r32(a[0] + 4) + 1;
    w32(a[0] + 4, n);
    return n;
}

H(Release)
{
    UNUSED;
    uint32_t n = r32(a[0] + 4);
    n = n ? n - 1 : 0;
    w32(a[0] + 4, n);
    if (n == 0) {
        Obj *o = find(a[0]);
        if (o && o->dev)
            o->dev->live = 0;           /* out of Input.devices */
    }
    return n;
}

H(Ok) { UNUSED; return DI_OK; }
H(NoEffect) { UNUSED; return DI_NOEFFECT; }
H(Unsupported) { UNUSED; return DIERR_UNSUPPORTED; }
H(DeviceNotReg) { UNUSED; return DIERR_DEVICENOTREG; }

/* ---------------------------------------------------------------- creation */
static uint32_t create_di(uint32_t version, uint32_t ppdi, uint32_t outer)
{
    I.made = 1;
    if (outer) {
        out32(ppdi, 0);
        return DIERR_NOAGGREGATION;
    }
    if (version < 0x300 || version > 0x700) {
        out32(ppdi, 0);
        return version < 0x300 ? DIERR_OLDDIRECTINPUTVERSION : DIERR_BETADIRECTINPUTVERSION;
    }
    out32(ppdi, new_obj(0, NULL)->addr);
    return DI_OK;
}

H(DirectInputCreateA) { UNUSED; return create_di(a[1], a[2], a[3]); }

H(DirectInputCreateEx)
{
    UNUSED;
    if (!iid_in(a[2], DI_IIDS)) {
        out32(a[3], 0);
        return E_NOINTERFACE;
    }
    return create_di(a[1], a[3], a[4]);
}

/* ---------------------------------------------------------------- IDirectInput7A */
static int kind_of(uint32_t rguid)
{
    if (rguid < 0x10000)
        return -1;
    return !memcmp(gptr(rguid), GUID_SYSKEYBOARD, 16) ? KEYBOARD : !memcmp(gptr(rguid), GUID_SYSMOUSE, 16) ? MOUSE : -1;
}

static uint32_t create_device(uint32_t rguid, uint32_t ppdev, uint32_t outer)
{
    int kind = kind_of(rguid);
    if (outer)
        return DIERR_NOAGGREGATION;
    if (kind < 0) {
        out32(ppdev, 0);
        return DIERR_DEVICENOTREG;
    }
    if (g_ndevs == 64)
        host_fatal("DINPUT: too many devices");
    Dev *d = calloc(1, sizeof *d);
    d->kind = kind;
    d->live = 1;
    d->axis_mode = 1;                           /* DIPROPAXISMODE_REL */
    g_devs[g_ndevs++] = d;
    Obj *o = new_obj(1, d);
    d->slot = host_di_new(o->addr, (uint32_t)kind);
    if (d->slot < 0)
        host_fatal("DINPUT: hle_fast.c has no room for another device");
    push_cfg(d);
    out32(ppdev, o->addr);
    return DI_OK;
}

H(CreateDevice) { UNUSED; return create_device(a[1], a[2], a[3]); }
H(CreateDeviceEx) { UNUSED; return iid_in(a[2], DEV_IIDS) ? create_device(a[1], a[3], a[4]) : DIERR_INVALIDPARAM; }

static const uint32_t DEVTYPE[2] = {0x403, 0x202};   /* DIDEVTYPE_KEYBOARD|PCENH, DIDEVTYPE_MOUSE|TRADITIONAL */
static const char *const NAMES[2] = {"Keyboard", "Mouse"};

/* DIDEVICEINSTANCEA (DirectX 5+ layout, 580 bytes; a DirectX 3 caller passes 568) */
static void write_instance(uint32_t p, int kind)
{
    uint32_t size = r32(p) ? r32(p) : 580;
    uint8_t b[580] = {0};
    memcpy(b, &size, 4);
    memcpy(b + 4, kind == KEYBOARD ? GUID_SYSKEYBOARD : GUID_SYSMOUSE, 16);
    memcpy(b + 20, PRODUCT[kind], 16);
    memcpy(b + 36, &DEVTYPE[kind], 4);
    memcpy(b + 40, NAMES[kind], strlen(NAMES[kind]));
    memcpy(b + 300, NAMES[kind], strlen(NAMES[kind]));
    uint16_t usage[2] = {1, kind == KEYBOARD ? 6 : 2};
    memcpy(b + 576, usage, 4);
    memcpy(gptr(p), b, size < 580 ? size : 580);
}

/* EnumDevices(type, callback, ref, flags): the mouse, then the keyboard */
H(EnumDevices)
{
    static const struct { int kind; uint32_t type; } K[2] = {{MOUSE, 2}, {KEYBOARD, 3}};
    for (int i = 0; i < 2; i++) {
        if (a[1] != 0 && a[1] != K[i].type)
            continue;
        uint32_t p = host_alloc(580);
        w32(p, 580);
        write_instance(p, K[i].kind);
        uint32_t args[2] = {p, a[3]};
        if (!host_guest_call(c, a[2], 2, args))     /* DIENUM_STOP */
            break;
    }
    return DI_OK;
}

H(GetDeviceStatus) { UNUSED; return kind_of(a[1]) >= 0 ? DI_OK : DIERR_DEVICENOTREG; }

/* ---------------------------------------------------------------- IDirectInputDevice7A */
/* the device's objects (objects(kind)): kind, instance, DIDFT type; their GUIDs by obj_guid */
static uint32_t nobjects(int kind) { return kind == KEYBOARD ? 256 : 3 + MOUSE_BUTTONS; }

static void object_at(int dkind, uint32_t i, uint32_t *okind, uint32_t *inst, const uint8_t **guid, uint32_t *type)
{
    if (dkind == KEYBOARD) {
        *okind = DIO_KEY, *inst = i, *guid = GUID_KEY, *type = DIDFT_PSHBUTTON | (i << 8);
    } else if (i < 3) {
        *okind = DIO_AXIS, *inst = i, *guid = GUID_AXES[i], *type = DIDFT_RELAXIS | (i << 8);
    } else {
        *okind = DIO_BUTTON, *inst = i - 3, *guid = GUID_BUTTON, *type = DIDFT_PSHBUTTON | ((i - 3) << 8);
    }
}

/* DIDATAFORMAT: each DIOBJECTDATAFORMAT matched to one of the device's objects, as DirectInput does (by GUID and
 * type; DIDFT_ANYINSTANCE takes the next unused one; DIDFT_OPTIONAL entries may stay unmatched) */
H(SetDataFormat)
{
    UNUSED;
    Dev *d = dev(a[0]);
    if (field(d, F_ACQUIRED))
        return DIERR_ACQUIRED;
    uint32_t h[6];
    memcpy(h, gptr(a[1]), 24);
    uint32_t objsize = h[1], flags = h[2], datasize = h[3], n = h[4], prgodf = h[5];
    uint8_t used[300] = {0};
    FmtObj objs[300];
    uint32_t nobj = 0, total = nobjects(d->kind);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t od[4];
        memcpy(od, gptr(prgodf + objsize * i), 16);
        uint32_t pg = od[0], ofs = od[1], typ = od[2], inst = (typ >> 8) & 0xFFFF;
        int matched = 0;
        for (uint32_t k = 0; k < total; k++) {
            uint32_t okind, oinst, ot;
            const uint8_t *og;
            object_at(d->kind, k, &okind, &oinst, &og, &ot);
            if (used[k] || (pg && memcmp(gptr(pg), og, 16)) || !(typ & ot & 0xFF))
                continue;
            if ((typ & DIDFT_ANYINSTANCE) != DIDFT_ANYINSTANCE && inst != oinst)
                continue;
            used[k] = 1;
            objs[nobj++] = (FmtObj){okind, oinst, ofs};
            matched = 1;
            break;
        }
        if (!matched && !(typ & 0x80000000u))   /* not DIDFT_OPTIONAL */
            return DIERR_INVALIDPARAM;
    }
    d->has_fmt = 1;
    d->fmt_size = datasize, d->fmt_flags = flags, d->nobj = nobj;
    memcpy(d->obj, objs, nobj * sizeof *objs);
    push_cfg(d);
    return DI_OK;
}

H(DevSetCooperativeLevel)
{
    UNUSED;
    Dev *d = dev(a[0]);
    d->coop = a[2];
    push_cfg(d);
    return DI_OK;
}

/* what hle_fast.c declined (a device it does not know) */
H(Acquire)
{
    UNUSED;
    Dev *d = dev(a[0]);
    if (!d->has_fmt)
        return DIERR_INVALIDPARAM;
    if (field(d, F_ACQUIRED))
        return DI_NOEFFECT;
    set_field(d, F_ACQUIRED, 1);
    set_field(d, F_LOST, 0);
    set_field(d, F_DX, 0), set_field(d, F_DY, 0), set_field(d, F_DZ, 0);
    return DI_OK;
}

H(Unacquire)
{
    UNUSED;
    Dev *d = dev(a[0]);
    if (!field(d, F_ACQUIRED))
        return DI_NOEFFECT;
    set_field(d, F_ACQUIRED, 0);
    host_di_queue(d->slot, Q_CLEAR, 0, NULL);
    return DI_OK;
}

static uint32_t not_ready(Dev *d)
{
    if (field(d, F_ACQUIRED))
        return 0;
    return field(d, F_LOST) ? DIERR_INPUTLOST : DIERR_NOTACQUIRED;
}

H(GetDeviceState)
{
    UNUSED;
    Dev *d = dev(a[0]);
    uint32_t err = not_ready(d), cb = a[1];
    if (!err && cb != d->fmt_size)
        err = DIERR_INVALIDPARAM;
    if (err)
        return err;
    uint8_t *buf = calloc(cb ? cb : 1, 1);
    int64_t m[3] = {field(d, F_DX), field(d, F_DY), field(d, F_DZ)};
    for (uint32_t i = 0; i < d->nobj; i++) {
        FmtObj *o = &d->obj[i];
        if (o->kind == DIO_KEY)
            buf[o->ofs] = keys()[o->inst];
        else if (o->kind == DIO_BUTTON)
            buf[o->ofs] = buttons()[o->inst];
        else if (o->ofs + 4 <= cb) {
            int64_t v = o->inst < 3 ? m[o->inst] : 0;
            int32_t x = v < INT32_MIN ? INT32_MIN : v > INT32_MAX ? INT32_MAX : (int32_t)v;
            memcpy(buf + o->ofs, &x, 4);
        }
    }
    set_field(d, F_DX, 0), set_field(d, F_DY, 0), set_field(d, F_DZ, 0);
    memcpy(gptr(a[2]), buf, cb);
    free(buf);
    return DI_OK;
}

H(GetDeviceData)
{
    UNUSED;
    Dev *d = dev(a[0]);
    uint32_t cbobj = a[1], rgdod = a[2], pinout = a[3], flags = a[4];
    uint32_t err = not_ready(d);
    if (!err && !d->bufsize)
        err = DIERR_NOTBUFFERED;
    if (!err && cbobj < 16)
        err = DIERR_INVALIDPARAM;
    uint32_t want = r32(pinout);
    if (err) {
        out32(pinout, 0);
        return err;
    }
    uint32_t len = qlen(d), n = want == INFINITE ? len : (want < len ? want : len);
    if (rgdod)
        for (uint32_t i = 0; i < n; i++) {
            uint32_t ev[4];
            host_di_queue(d->slot, Q_GET, i, ev);
            memcpy(gptr(rgdod + cbobj * i), ev, 16);
            memset(gptr(rgdod + cbobj * i + 16), 0, cbobj - 16);
        }
    if (!(flags & DIGDD_PEEK))
        for (uint32_t i = 0; i < n; i++)
            host_di_queue(d->slot, Q_POP, 0, NULL);
    out32(pinout, n);
    if (field(d, F_OVERFLOW)) {
        set_field(d, F_OVERFLOW, 0);
        return DI_BUFFEROVERFLOW;
    }
    return DI_OK;
}

/* DIDEVCAPS (DirectX 5+ layout, 44 bytes; DirectX 3 callers pass 24): all but dwSize */
H(GetCapabilities)
{
    UNUSED;
    Dev *d = dev(a[0]);
    uint32_t size = r32(a[1]);
    uint32_t v[11] = {size, 0x1, DEVTYPE[d->kind], d->kind == KEYBOARD ? 0 : 3,
                      d->kind == KEYBOARD ? 256 : MOUSE_BUTTONS, 0, 0, 0, 0x100, 0x100, 0};   /* DIDC_ATTACHED */
    uint32_t end = size < 44 ? (size > 4 ? size : 4) : 44;
    memcpy(gptr(a[1] + 4), (uint8_t *)v + 4, end - 4);
    return DI_OK;
}

/* prop_target: the device (1), an object (2, *k its index in objects()), or none (0) */
static int prop_target(Dev *d, uint32_t how, uint32_t objid, uint32_t *k)
{
    if (how == 0)
        return 1;
    uint32_t total = nobjects(d->kind);
    if (how == 1 && d->has_fmt) {               /* DIPH_BYOFFSET: the offset in the current data format */
        for (uint32_t i = 0; i < d->nobj; i++)
            if (d->obj[i].ofs == objid)
                for (uint32_t j = 0; j < total; j++) {
                    uint32_t okind, inst, t;
                    const uint8_t *g;
                    object_at(d->kind, j, &okind, &inst, &g, &t);
                    if (okind == d->obj[i].kind && inst == d->obj[i].inst) {
                        *k = j;
                        return 2;
                    }
                }
        return 0;
    }
    if (how == 2) {                             /* DIPH_BYID: the instance from the DIDFT type */
        uint32_t want = (objid >> 8) & 0xFFFF;
        for (uint32_t j = 0; j < total; j++) {
            uint32_t okind, inst, t;
            const uint8_t *g;
            object_at(d->kind, j, &okind, &inst, &g, &t);
            if (inst == want && (t & objid & 0xFF)) {
                *k = j;
                return 2;
            }
        }
    }
    return 0;
}

H(GetProperty)
{
    UNUSED;
    Dev *d = dev(a[0]);
    uint32_t prop = a[1] < 0x10000 ? a[1] : 0, ph = a[2], hd[4], k = 0;
    memcpy(hd, gptr(ph), 16);
    int t = prop_target(d, hd[3], hd[2], &k);
    if (!t)
        return DIERR_NOTFOUND;
    uint32_t val;
    if (prop == 1)
        val = d->bufsize;
    else if (prop == 2)
        val = d->axis_mode;
    else if (prop == 3)                         /* granularity: the wheel moves in WHEEL_DELTA steps */
        val = t == 2 && d->kind == MOUSE && k == 2 ? WHEEL_DELTA : 1;
    else
        return DIERR_UNSUPPORTED;
    w32(ph + hd[1], val);
    return DI_OK;
}

H(SetProperty)
{
    UNUSED;
    Dev *d = dev(a[0]);
    uint32_t prop = a[1] < 0x10000 ? a[1] : 0, ph = a[2], hsize = r32(ph + 4), val = r32(ph + hsize);
    if (prop == 1) {
        if (field(d, F_ACQUIRED))
            return DIERR_ACQUIRED;
        d->bufsize = val;
        push_cfg(d);                            /* (a smaller buffer keeps the newest events) */
    } else if (prop == 2) {
        if (field(d, F_ACQUIRED))
            return DIERR_ACQUIRED;
        d->axis_mode = val;
    } else
        return DIERR_UNSUPPORTED;
    return DI_OK;
}

H(GetDeviceInfo)
{
    UNUSED;
    write_instance(a[1], dev(a[0])->kind);
    return DI_OK;
}

/* DIDEVICEOBJECTINSTANCEA (DirectX 5+ layout, 316 bytes; DirectX 3 callers pass 296) */
static void object_instance(uint32_t p, Dev *d, uint32_t k)
{
    static const char *const AXES[3] = {"X Axis", "Y Axis", "Wheel"};
    static const char *const BUTTONS[MOUSE_BUTTONS] = {"Left Button", "Right Button", "Middle Button", "Button 4",
                                                       "Button 5"};
    uint32_t okind, inst, type, ofs = 0, size = r32(p) ? r32(p) : 316;
    const uint8_t *g;
    object_at(d->kind, k, &okind, &inst, &g, &type);
    for (uint32_t i = 0; i < d->nobj; i++)
        if (d->obj[i].kind == okind && d->obj[i].inst == inst)
            ofs = d->obj[i].ofs;
    char name[32];
    if (okind == DIO_KEY) {
        if (DIK_NAMES[inst])
            snprintf(name, sizeof name, "%s", DIK_NAMES[inst]);
        else
            snprintf(name, sizeof name, "Key %u", inst);
    } else
        snprintf(name, sizeof name, "%s", okind == DIO_AXIS ? AXES[inst] : BUTTONS[inst]);
    uint8_t b[316] = {0};
    memcpy(b, &size, 4);
    memcpy(b + 4, g, 16);
    memcpy(b + 20, &ofs, 4);
    memcpy(b + 24, &type, 4);
    memcpy(b + 32, name, strlen(name));
    uint16_t usage_page = 1;                    /* (the fifth field after the name, as Python packs it) */
    memcpy(b + 304, &usage_page, 2);
    memcpy(gptr(p), b, size < 316 ? size : 316);
}

H(GetObjectInfo)
{
    UNUSED;
    Dev *d = dev(a[0]);
    uint32_t k = 0;
    if (prop_target(d, a[3], a[2], &k) != 2)
        return DIERR_NOTFOUND;
    object_instance(a[1], d, k);
    return DI_OK;
}

H(EnumObjects)
{
    Dev *d = dev(a[0]);
    uint32_t p = host_alloc(316), total = nobjects(d->kind);
    for (uint32_t k = 0; k < total; k++) {
        uint32_t okind, inst, t;
        const uint8_t *g;
        object_at(d->kind, k, &okind, &inst, &g, &t);
        if (a[3] && !(a[3] & t & 0xFF))
            continue;
        w32(p, 316);
        object_instance(p, d, k);
        uint32_t args[2] = {p, a[2]};
        if (!host_guest_call(c, a[1], 2, args))
            break;
    }
    return DI_OK;
}

H(SetEventNotification)
{
    UNUSED;
    dev(a[0])->event = a[1];
    return DI_OK;
}

/* ---------------------------------------------------------------- USER32 keyboard queries on the same state */
H(GetAsyncKeyState)
{
    UNUSED;
    I.made = 1;
    uint32_t vk = a[0] & 0xFF;
    int down = vk_down(vk), pressed = 0;
    for (int i = 0; i < 2 && VK_TO_DIK[vk][i]; i++) {
        pressed |= I.async_seen[VK_TO_DIK[vk][i]];
        I.async_seen[VK_TO_DIK[vk][i]] = 0;
    }
    return (down ? 0x8000u : 0) | (pressed ? 1u : 0);
}

H(GetKeyState)
{
    UNUSED;
    I.made = 1;
    uint32_t vk = a[0] & 0xFF;
    return (vk_down(vk) ? 0xFF80u : 0) | (vk_toggled(vk) ? 1u : 0);
}

H(GetKeyboardState)
{
    UNUSED;
    I.made = 1;
    uint8_t st[256] = {0};
    for (uint32_t vk = 0; vk < 256; vk++)
        if (VK_TO_DIK[vk][0] || VK_MOUSE[vk])
            st[vk] = (uint8_t)((vk_down(vk) ? 0x80 : 0) | (vk_toggled(vk) ? 1 : 0));
    memcpy(gptr(a[0]), st, 256);
    return 1;
}

/* US layout: the character for this key given the shift/caps bits of the passed keyboard state */
H(ToAscii)
{
    UNUSED;
    I.made = 1;
    uint8_t st[256] = {0};
    if (a[2])
        memcpy(st, gptr(a[2]), 256);
    uint32_t dik = (a[1] & 0x7F) | ((a[1] & 0x100) ? 0x80 : 0), vk = a[0] & 0xFF;
    const char *ch = US[dik][0] ? US[dik] : NULL;
    for (int i = 0; !ch && i < 2 && VK_TO_DIK[vk][i]; i++)
        if (US[VK_TO_DIK[vk][i]][0])
            ch = US[VK_TO_DIK[vk][i]];
    if (!ch || (st[0x11] & 0x80) || (st[0x12] & 0x80))   /* Ctrl/Alt chords produce no character here */
        return 0;
    int shift = (st[0x10] & 0x80) != 0;
    if (ch[0] >= 'a' && ch[0] <= 'z' && (st[0x14] & 1))
        shift = !shift;
    gptr(a[3])[0] = (uint8_t)ch[shift];
    gptr(a[3])[1] = 0;
    return 1;
}

/* lParam bits 16-23 are the scan code, bit 24 the extended flag: the same numbering as DIK codes */
H(GetKeyNameTextA)
{
    UNUSED;
    I.made = 1;
    uint32_t dik = ((a[0] >> 16) & 0x7F) | ((a[0] & (1u << 24)) ? 0x80 : 0);
    const char *name = DIK_NAMES[dik];
    if (!name || (int32_t)a[2] <= 0)
        return 0;
    uint32_t n = (uint32_t)strlen(name);
    if (n > a[2] - 1)
        n = a[2] - 1;
    memcpy(gptr(a[1]), name, n);
    gptr(a[1])[n] = 0;
    return n;
}

/* ---------------------------------------------------------------- the table */
static const struct { int iface; const char *name; HleFn fn; uint8_t flags; } SPECIAL[] = {
    {0, "QueryInterface", QiDi, 0}, {0, "CreateDevice", CreateDevice, 0}, {0, "EnumDevices", EnumDevices, HLE_CORO},
    {0, "GetDeviceStatus", GetDeviceStatus, 0}, {0, "FindDevice", DeviceNotReg, 0},
    {0, "CreateDeviceEx", CreateDeviceEx, 0},
    {1, "QueryInterface", QiDev, 0}, {1, "GetCapabilities", GetCapabilities, 0},
    {1, "EnumObjects", EnumObjects, HLE_CORO}, {1, "GetProperty", GetProperty, 0},
    {1, "SetProperty", SetProperty, 0}, {1, "Acquire", Acquire, 0}, {1, "Unacquire", Unacquire, 0},
    {1, "GetDeviceState", GetDeviceState, 0}, {1, "GetDeviceData", GetDeviceData, 0},
    {1, "SetDataFormat", SetDataFormat, 0}, {1, "SetEventNotification", SetEventNotification, 0},
    {1, "SetCooperativeLevel", DevSetCooperativeLevel, 0}, {1, "GetObjectInfo", GetObjectInfo, 0},
    {1, "GetDeviceInfo", GetDeviceInfo, 0}, {1, "Poll", NoEffect, 0},
};

static char g_names[64][64];
HleDef hle_dinput[80];

__attribute__((constructor)) static void build_table(void)
{
    int n = 0;
    hle_dinput[n++] = (HleDef){DI, "DirectInputCreateA", 4, STDCALL, DirectInputCreateA};
    hle_dinput[n++] = (HleDef){DI, "DirectInputCreateEx", 5, STDCALL, DirectInputCreateEx};
    for (int i = 0; i < 2; i++) {
        const Meth *m0 = i ? IDIRECTINPUTDEVICE7 : IDIRECTINPUT7;
        for (const Meth *m = m0; m->name; m++) {
            HleFn fn = Ok;              /* RunControlPanel, Initialize */
            uint8_t flags = STDCALL;
            if (!strcmp(m->name, "AddRef"))
                fn = AddRef;
            else if (!strcmp(m->name, "Release"))
                fn = Release;
            else if (i == 1 && m - m0 >= 18)    /* force feedback: not available */
                fn = Unsupported;
            for (size_t s = 0; s < sizeof SPECIAL / sizeof *SPECIAL; s++)
                if (SPECIAL[s].iface == i && !strcmp(SPECIAL[s].name, m->name))
                    fn = SPECIAL[s].fn, flags = SPECIAL[s].flags;
            snprintf(g_names[n], sizeof g_names[n], "%s::%s", i ? "IDirectInputDevice7A" : "IDirectInput7A", m->name);
            hle_dinput[n] = (HleDef){DI, g_names[n], (uint8_t)(1 + m->nparams), flags, fn};
            n++;
        }
    }
    hle_dinput[n++] = (HleDef){U, "GetAsyncKeyState", 1, STDCALL, GetAsyncKeyState};
    hle_dinput[n++] = (HleDef){U, "GetKeyState", 1, STDCALL, GetKeyState};
    hle_dinput[n++] = (HleDef){U, "GetKeyboardState", 1, STDCALL, GetKeyboardState};
    hle_dinput[n++] = (HleDef){U, "ToAscii", 5, STDCALL, ToAscii};
    hle_dinput[n++] = (HleDef){U, "GetKeyNameTextA", 3, STDCALL, GetKeyNameTextA};
    hle_dinput[n] = (HleDef){NULL, NULL, 0, 0, NULL};
}
