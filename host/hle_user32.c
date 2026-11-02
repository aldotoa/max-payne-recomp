/* USER32 and GDI32 for the native host (E5/E6): the calls MFC42's start-up makes before any window exists, ported from
 * emu/mpemu.py (the desktop as SCREEN, fixed handles, message and clipboard-format atoms, LoadStringA from the RT_STRING
 * table, the fixed answers of mpemu's _simple tables, wsprintfA, CreateDIBSection; the keyboard queries are hle_dinput.c's). The window manager (emu/winsys.py)
 * is host/hle_winsys.c. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"

#define U "USER32.DLL"
#define G "GDI32.DLL"
#define H(name) static uint32_t name(CPU *c, const uint32_t *a)
#define UNUSED (void)c, (void)a

static const uint32_t SCREEN[2] = {HOST_SCREEN_W, HOST_SCREEN_H};

static inline uint16_t r16(uint32_t p) { uint16_t v; memcpy(&v, gptr(p), 2); return v; }

H(Return0) { UNUSED; return 0; }
H(Return1) { UNUSED; return 1; }
H(GetDC) { UNUSED; return 0x2000; }
H(GetSysColor) { UNUSED; return 0x00C0C0C0; }
H(GetSysColorBrush) { UNUSED; return 0x2200; }
H(LoadCursorA) { UNUSED; return 0x3001; }
H(LoadIconA) { UNUSED; return 0x3002; }
H(LoadAcceleratorsA) { UNUSED; return 0x3003; }

H(GetSystemMetrics)
{
    UNUSED;
    switch (a[0]) {
    case 0: return SCREEN[0];
    case 1: return SCREEN[1];
    case 4: return 19;
    case 5: case 6: return 1;
    case 7: case 8: return 3;
    case 15: return 20;
    }
    return 0;
}

H(GetDeviceCaps)
{
    UNUSED;
    switch (a[1]) {
    case 8: return SCREEN[0];
    case 10: return SCREEN[1];
    case 12: return 32;
    case 14: return 1;
    case 88: case 90: return 96;
    }
    return 0;
}

H(CharNextA) { UNUSED; return a[0] + (gptr(a[0])[0] != 0); }

/* RegisterWindowMessageA and RegisterClipboardFormatA share one table (the Python _msg_atoms dict): name ->
 * 0xC100 + order of first registration; clipboard formats are kept as "clip:" + name. */
static char *g_msg_atoms[1024];
static uint32_t g_nmsg_atoms;

static uint32_t msg_atom(const char *prefix, uint32_t name)
{
    char s[4200];
    size_t k = (size_t)snprintf(s, sizeof s, "%s", prefix);
    host_cstr(name, s + k, sizeof s - k);
    for (uint32_t i = 0; i < g_nmsg_atoms; i++)
        if (strcmp(g_msg_atoms[i], s) == 0)
            return 0xC100 + i;
    if (g_nmsg_atoms == 1024)
        host_fatal("too many window-message atoms");
    g_msg_atoms[g_nmsg_atoms] = strdup(s);
    return 0xC100 + g_nmsg_atoms++;
}

H(RegisterWindowMessageA) { UNUSED; return msg_atom("", a[0]); }
H(RegisterClipboardFormatA) { UNUSED; return msg_atom("clip:", a[0]); }

H(MessageBoxA)
{
    UNUSED;
    char cap[4100], text[4100];
    host_cstr(a[2], cap, sizeof cap);
    host_cstr(a[1], text, sizeof text);
    printf("[MessageBox] %s: %s\n", cap, text);
    return 1;
}

/* Python's str.encode("cp1252", "replace") of one character */
static uint8_t cp1252(uint32_t u)
{
    static const uint16_t HIGH[32] = {
        0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0, 0x017D, 0,
        0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E,
        0x0178};
    if (u < 0x80 || (u >= 0xA0 && u < 0x100))
        return (uint8_t)u;
    for (int i = 0; i < 32; i++)
        if (HIGH[i] && HIGH[i] == u)
            return (uint8_t)(0x80 + i);
    return '?';
}

/* String uid of the module's RT_STRING table (blocks of 16: block uid / 16 + 1, each string a length-prefixed UTF-16
 * run), in the ANSI code page, cut to size - 1 bytes. Returns the length; 0 when there is none. */
H(LoadStringA)
{
    UNUSED;
    uint32_t h = host_find_resource(a[0], (a[1] >> 4) + 1, 6);
    if (!h || a[3] == 0)
        return 0;
    Module *m;
    uint32_t rva, size;
    host_resource(h, 1, &m, &rva, &size);
    uint32_t p = m->base + rva;
    for (uint32_t i = 0; i < (a[1] & 15); i++)
        p += 2 + 2 * (uint32_t)r16(p);
    uint32_t ln = r16(p), k = 0;
    uint8_t *out = gptr(a[2]);
    for (uint32_t i = 0; i < ln && k < a[3] - 1; i++) {
        uint32_t u = r16(p + 2 + 2 * i);
        if (u >= 0xD800 && u < 0xDC00 && i + 1 < ln) {
            uint32_t lo = r16(p + 4 + 2 * i);
            if (lo >= 0xDC00 && lo < 0xE000) {
                u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                i++;
            }
        }
        out[k++] = cp1252(u);
    }
    out[k] = 0;
    return k;
}

H(Return2100) { UNUSED; return 0x2100; }
H(Return2101) { UNUSED; return 0x2101; }
H(Return2102) { UNUSED; return 0x2102; }
H(Return2103) { UNUSED; return 0x2103; }
H(GetDesktopWindow) { UNUSED; return 0x1001; }
H(GetLastActivePopup) { UNUSED; return 0x1000; }

/* the varargs follow (buf, fmt) on the stack; flags and widths are skipped, as the Python handler does */
H(wsprintfA)
{
    char f[4100], out[8192];
    host_cstr(a[1], f, sizeof f);
    uint32_t sp = c->r[ESP] + 12, i = 0;
    size_t k = 0, n = strlen(f);
    for (size_t j = 0; j < n && k < sizeof out - 64;) {
        if (f[j] != '%') {
            out[k++] = f[j++];
            continue;
        }
        j++;
        while (j < n && strchr("-+ #0123456789.l", f[j]))
            j++;
        char t = j < n ? f[j] : 0;
        j++;
        uint32_t v;
        memcpy(&v, gptr(sp + 4 * i), 4);
        i++;
        if (t == 's') {
            char s[4100];
            host_cstr(v, s, sizeof s);
            k += (size_t)snprintf(out + k, sizeof out - k, "%s", s);
        } else if (t == 'd' || t == 'i')
            k += (size_t)snprintf(out + k, sizeof out - k, "%d", (int32_t)v);
        else if (t == 'u')
            k += (size_t)snprintf(out + k, sizeof out - k, "%u", v);
        else if (t == 'x')
            k += (size_t)snprintf(out + k, sizeof out - k, "%x", v);
        else if (t == 'X')
            k += (size_t)snprintf(out + k, sizeof out - k, "%X", v);
        else if (t == 'c')
            out[k++] = (char)(v & 0xFF);
        else if (t == '%') {
            out[k++] = '%';
            i--;
        }
        if (k > sizeof out - 1)
            k = sizeof out - 1;
    }
    memcpy(gptr(a[0]), out, k);
    gptr(a[0])[k] = 0;
    return (uint32_t)k;
}

H(CreateDIBSection)
{
    UNUSED;
    int32_t w, h;
    uint16_t bpp;
    memcpy(&w, gptr(a[1] + 4), 4);
    memcpy(&h, gptr(a[1] + 8), 4);
    memcpy(&bpp, gptr(a[1] + 14), 2);
    uint32_t px = bpp / 8 ? bpp / 8u : 1u;
    uint32_t mem = host_alloc((uint32_t)abs(w) * (uint32_t)abs(h) * px + 64);
    if (a[3])
        memcpy(gptr(a[3]), &mem, 4);
    return host_new_handle(HK_DIB, NULL);
}

H(GetDIBits) { UNUSED; return a[3]; }

const HleDef hle_user32[] = {
    {U, "GetSystemMetrics", 1, STDCALL, GetSystemMetrics},
    {U, "GetDC", 1, STDCALL, GetDC},
    {U, "ReleaseDC", 2, STDCALL, Return1},
    {U, "GetSysColor", 1, STDCALL, GetSysColor},
    {U, "GetSysColorBrush", 1, STDCALL, GetSysColorBrush},
    {U, "LoadCursorA", 2, STDCALL, LoadCursorA},
    {U, "LoadIconA", 2, STDCALL, LoadIconA},
    {U, "LoadAcceleratorsA", 2, STDCALL, LoadAcceleratorsA},
    {U, "GetCursorPos", 1, STDCALL, Return0},
    {U, "RegisterWindowMessageA", 1, STDCALL, RegisterWindowMessageA},
    {U, "RegisterClipboardFormatA", 1, STDCALL, RegisterClipboardFormatA},
    {U, "CharNextA", 1, STDCALL, CharNextA},
    {U, "MessageBoxA", 4, STDCALL, MessageBoxA},
    {U, "LoadStringA", 4, STDCALL, LoadStringA},
    {U, "SystemParametersInfoA", 4, STDCALL, Return1},
    {G, "GetDeviceCaps", 2, STDCALL, GetDeviceCaps},
    {U, "FindWindowA", 2, STDCALL, Return0},
    {U, "GetDesktopWindow", 0, STDCALL, GetDesktopWindow},
    {U, "GetLastActivePopup", 1, STDCALL, GetLastActivePopup},
    {U, "IsIconic", 1, STDCALL, Return0},
    {U, "RedrawWindow", 4, STDCALL, Return1},
    {U, "SetCursor", 1, STDCALL, Return0},
    {U, "TranslateAcceleratorA", 3, STDCALL, Return0},
    {U, "FillRect", 3, STDCALL, Return1},
    {U, "DrawTextA", 5, STDCALL, Return0},
    {U, "DrawTextW", 5, STDCALL, Return0},
    {U, "wsprintfA", 2, CDECL, wsprintfA},
    {G, "CreateCompatibleDC", 1, STDCALL, Return2100},
    {G, "CreateCompatibleBitmap", 3, STDCALL, Return2101},
    {G, "DeleteDC", 1, STDCALL, Return1},
    {G, "DeleteObject", 1, STDCALL, Return1},
    {G, "SelectObject", 2, STDCALL, Return2102},
    {G, "SetBkColor", 2, STDCALL, Return0},
    {G, "SetBkMode", 2, STDCALL, Return1},
    {G, "SetTextColor", 2, STDCALL, Return0},
    {G, "SetMapMode", 2, STDCALL, Return1},
    {G, "GetMapMode", 1, STDCALL, Return1},
    {G, "BitBlt", 9, STDCALL, Return1},
    {G, "CreateFontIndirectA", 1, STDCALL, Return2103},
    {G, "GetObjectA", 3, STDCALL, Return0},
    {G, "CreateDIBSection", 6, STDCALL, CreateDIBSection},
    {G, "GetDIBits", 7, STDCALL, GetDIBits},
    {NULL, NULL, 0, 0, NULL},
};
