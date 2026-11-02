/* KERNEL32 (and WINMM timeGetTime) in C for the native host (E5/E6): ports of the Python handlers in emu/mpemu.py, with
 * the same results, guest writes and heap allocations (so a host trace and an emulator trace compare call for call).
 * Not here yet: files, the registry, and everything else not listed in hle_kernel32[] (the host stops at the first
 * call to one). The TLS slots, the last error, the critical sections, QueryPerformanceCounter and HeapAlloc/HeapFree
 * are served by the runtime (hle_fast.c, heap.c); the versions here only run when those decline. */
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "host.h"

#define K "KERNEL32.DLL"
#define H(name) static uint32_t name(CPU *c, const uint32_t *a)
#define UNUSED (void)c, (void)a

static inline void w32(uint32_t p, uint32_t v) { memcpy(gptr(p), &v, 4); }
static inline uint32_t r32(uint32_t p) { uint32_t v; memcpy(&v, gptr(p), 4); return v; }
static inline uint16_t r16(uint32_t p) { uint16_t v; memcpy(&v, gptr(p), 2); return v; }
static inline void w16(uint32_t p, uint16_t v) { memcpy(gptr(p), &v, 2); }
static void wzero(uint32_t p, uint32_t n) { memset(gptr(p), 0, n); }

/* ---- version, command line, environment */
H(GetVersion) { UNUSED; return 0x0A280105; }

H(GetVersionExA)
{
    UNUSED;
    w32(a[0] + 4, 5);
    w32(a[0] + 8, 1);
    w32(a[0] + 12, 2600);
    w32(a[0] + 16, 2);
    wzero(a[0] + 20, 128);
    return 1;
}

static uint32_t g_cmdline_a, g_cmdline_w;

H(GetCommandLineA)
{
    UNUSED;
    if (!g_cmdline_a)
        g_cmdline_a = host_put_cstr(g_cmdline, 0);
    return g_cmdline_a;
}

H(GetCommandLineW)
{
    UNUSED;
    if (!g_cmdline_w) {
        size_t n = strlen(g_cmdline);
        g_cmdline_w = host_alloc((uint32_t)(2 * n + 2));
        for (size_t i = 0; i <= n; i++)
            w16(g_cmdline_w + 2 * (uint32_t)i, (uint8_t)g_cmdline[i]);
    }
    return g_cmdline_w;
}

H(GetEnvironmentStrings) { UNUSED; return host_alloc(8); }
H(Return1) { UNUSED; return 1; }
H(Return0) { UNUSED; return 0; }

H(GetEnvironmentVariableA)
{
    UNUSED;
    host_set_last_error(203);
    return 0;
}

H(GetStartupInfoA)
{
    UNUSED;
    w32(a[0], 68);
    wzero(a[0] + 4, 64);
    return 0;
}

/* ---- modules */
H(GetModuleHandleA)
{
    UNUSED;
    if (!a[0]) {
        Module *m = host_find_module("maxpayne.exe");
        return m ? m->base : 0x400000;
    }
    char n[512];
    host_cstr(a[0], n, sizeof n);
    Module *m = host_find_module(n);
    return m ? m->base : 0;
}

static const char *module_name(uint32_t h)
{
    Module *m = host_module_by_base(h);
    return m ? m->name : "MaxPayne.exe";
}

H(GetModuleFileNameA)
{
    UNUSED;
    char s[1100];
    snprintf(s, sizeof s, "C:\\MaxPayne\\%s", module_name(a[0]));
    size_t n = strlen(s);
    if (a[2] == 0)                             /* Python: s[:size - 1] with size 0 keeps all but the last byte */
        n = n ? n - 1 : 0;
    else if (n > a[2] - 1)
        n = a[2] - 1;
    memcpy(gptr(a[1]), s, n);
    gptr(a[1])[n] = 0;
    return (uint32_t)n;
}

H(GetModuleFileNameW)
{
    UNUSED;
    char s[1100];
    snprintf(s, sizeof s, "C:\\MaxPayne\\%s", module_name(a[0]));
    size_t n = strlen(s);
    if (a[2] == 0)
        n = n ? n - 1 : 0;
    else if (n > a[2] - 1)
        n = a[2] - 1;
    for (size_t i = 0; i < n; i++)
        w16(a[1] + 2 * (uint32_t)i, (uint8_t)s[i]);
    w16(a[1] + 2 * (uint32_t)n, 0);
    return (uint32_t)n;
}

H(LoadLibraryA)
{
    char n[1024];
    host_cstr(a[0], n, sizeof n);
    return host_load_library(c, n);
}

H(GetProcAddress) { UNUSED; return host_get_proc_address(a[0], a[1]); }

/* ---- process and thread */
H(GetCurrentProcess) { UNUSED; return 0xFFFFFFFF; }
H(GetCurrentThread) { UNUSED; return 0xFFFFFFFE; }
H(GetCurrentProcessId) { UNUSED; return 0x100; }
H(GetCurrentThreadId) { UNUSED; return 0x104; }
H(GetPriorityClass) { UNUSED; return 0x20; }
/* the call's log line first, as the emulator writes it (the handler never returns to the dispatcher) */
H(ExitProcess)
{
    UNUSED;
    host_note("KERNEL32.DLL!ExitProcess(0x%x) -> 0x0", a[0]);
    host_exit(a[0]);
}
H(TerminateProcess) { UNUSED; host_exit(a[1]); }

H(OutputDebugStringA)
{
    UNUSED;
    char s[4100];
    size_t n = host_cstr(a[0], s, sizeof s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = 0;
    printf("[OutputDebugString] %s\n", s);
    return 0;
}

H(GetComputerNameA)
{
    UNUSED;
    memcpy(gptr(a[0]), "MACBOOK", 8);
    w32(a[1], 7);
    return 1;
}

/* ---- heap and virtual memory */
H(GetProcessHeap) { UNUSED; return 0x30000000; }
H(HeapCreate) { UNUSED; return 0x30000000 + 0x10000 * (host_heap_live() % 255 + 1); }
H(HeapAlloc) { UNUSED; return host_alloc(a[2]); }

H(HeapFree)
{
    UNUSED;
    host_free(a[2]);
    return 1;
}

static uint32_t realloc_block(uint32_t p, uint32_t size)
{
    uint32_t old = 0, cap = 0;
    if (p && !host_heap_get(p, &old, &cap))
        old = cap = 0;
    if (p && old && cap >= size) {             /* fits in place: grow or shrink without moving */
        host_heap_resize(p, size ? size : 1);
        return p;
    }
    uint32_t n = host_alloc(size);
    if (p && old) {
        memmove(gptr(n), gptr(p), old < size ? old : size);
        host_free(p);
    }
    return n;
}

H(HeapReAlloc)
{
    UNUSED;
    uint32_t size = 0, cap = 0;
    if ((a[1] & 0x10) && (host_heap_get(a[2], &size, &cap) ? cap : 0) < a[3])
        return 0;                              /* HEAP_REALLOC_IN_PLACE_ONLY and it does not fit */
    return realloc_block(a[2], a[3]);
}

H(HeapSize)
{
    UNUSED;
    uint32_t size, cap;
    return host_heap_get(a[2], &size, &cap) ? size : 0xFFFFFFFF;
}

H(HeapCompact) { UNUSED; return 0x10000; }
H(VirtualAlloc) { UNUSED; return host_heap_reserve(a[1], 1); }

H(GlobalMemoryStatus)
{
    UNUSED;
    static const uint32_t v[8] = {32, 50, 0x40000000, 0x20000000, 0x80000000, 0x40000000, 0x7FFE0000, 0x70000000};
    memcpy(gptr(a[0]), v, sizeof v);
    return 0;
}

/* ---- TLS, last error, critical sections, interlocked, synchronisation */
static uint32_t g_tls_next;

H(TlsAlloc)
{
    UNUSED;
    uint32_t i = g_tls_next++;
    host_tls_set(i, 0, 1);
    return i;
}

H(TlsFree)
{
    UNUSED;
    host_tls_set(a[0], 0, 0);
    return 1;
}

H(GetLastError) { UNUSED; return host_last_error(); }

H(SetLastError)
{
    UNUSED;
    host_set_last_error(a[0]);
    return 0;
}

H(InterlockedIncrement)
{
    UNUSED;
    uint32_t v = r32(a[0]) + 1;
    w32(a[0], v);
    return v;
}

H(InterlockedDecrement)
{
    UNUSED;
    uint32_t v = r32(a[0]) - 1;
    w32(a[0], v);
    return v;
}

H(InterlockedExchange)
{
    UNUSED;
    uint32_t old = r32(a[0]);
    w32(a[0], a[1]);
    return old;
}

H(NewHandleMutex) { UNUSED; return host_new_handle(HK_MUTEX, NULL); }
H(NewHandleEvent) { UNUSED; return host_new_handle(HK_EVENT, NULL); }
H(NewHandleSemaphore) { UNUSED; return host_new_handle(HK_SEMAPHORE, NULL); }

/* single-threaded: a thread is a handle that never runs */
H(CreateThread)
{
    UNUSED;
    printf("[CreateThread] fn=%s param=0x%x flags=0x%x (not run: single-threaded bring-up)\n", host_module_at(a[2]),
           a[3], a[4]);
    if (a[5])
        w32(a[5], 0x200);
    return host_new_handle(HK_THREAD, NULL);
}

H(VirtualProtect)
{
    UNUSED;
    if (a[3])
        w32(a[3], 0x40);
    return 1;
}

/* ---- Local and Global memory: fixed, the handle is the pointer */
H(LocalAlloc) { UNUSED; return host_alloc(a[1]); }
H(LocalReAlloc) { UNUSED; return realloc_block(a[0], a[1]); }

H(LocalFree)
{
    UNUSED;
    host_free(a[0]);
    return 0;
}

H(LocalLock) { UNUSED; return a[0]; }

H(LocalSize)
{
    UNUSED;
    uint32_t size, cap;
    return host_heap_get(a[0], &size, &cap) ? size : 0;
}

/* ---- strings */
H(lstrlenA) { UNUSED; return a[0] ? (uint32_t)strnlen((const char *)gptr(a[0]), 4096) : 0; }

H(lstrlenW)
{
    UNUSED;
    uint32_t n = 0;
    if (a[0])
        while (n < 4096 && r16(a[0] + 2 * n))
            n++;
    return n;
}

H(lstrcpyA)
{
    UNUSED;
    size_t n = a[1] ? strnlen((const char *)gptr(a[1]), 4096) : 0;
    memmove(gptr(a[0]), gptr(a[1]), n);
    gptr(a[0])[n] = 0;
    return a[0];
}

H(lstrcpynA)
{
    UNUSED;
    if (a[2]) {
        size_t n = a[1] ? strnlen((const char *)gptr(a[1]), 4096) : 0;
        if (n > a[2] - 1)
            n = a[2] - 1;
        memmove(gptr(a[0]), gptr(a[1]), n);
        gptr(a[0])[n] = 0;
    }
    return a[0];
}

H(lstrcatA)
{
    UNUSED;
    size_t d = a[0] ? strnlen((const char *)gptr(a[0]), 4096) : 0;
    size_t n = a[1] ? strnlen((const char *)gptr(a[1]), 4096) : 0;
    memmove(gptr(a[0] + (uint32_t)d), gptr(a[1]), n);
    gptr(a[0] + (uint32_t)d)[n] = 0;
    return a[0];
}

/* Python's comparison of the Latin-1 strings: by code point; lower() first for lstrcmpiA (Latin-1 lower case:
 * A-Z, 0xC0-0xDE but 0xD7) */
static int latin1_lower(int ch) { return (ch >= 'A' && ch <= 'Z') || (ch >= 0xC0 && ch <= 0xDE && ch != 0xD7) ? ch + 32 : ch; }
static int latin1_upper(int ch) { return (ch >= 'a' && ch <= 'z') || (ch >= 0xE0 && ch <= 0xFE && ch != 0xF7) ? ch - 32 : ch; }

static uint32_t cmp_cstr(uint32_t x, uint32_t y, int fold)
{
    char s[4100], t[4100];
    size_t n = host_cstr(x, s, sizeof s), m = host_cstr(y, t, sizeof t);
    for (size_t i = 0;; i++) {
        if (i == n || i == m)
            return n == m ? 0 : (n < m ? 0xFFFFFFFF : 1);
        int p = (uint8_t)s[i], q = (uint8_t)t[i];
        if (fold)
            p = latin1_lower(p), q = latin1_lower(q);
        if (p != q)
            return p < q ? 0xFFFFFFFF : 1;
    }
}

H(lstrcmpA) { UNUSED; return cmp_cstr(a[0], a[1], 0); }
H(lstrcmpiA) { UNUSED; return cmp_cstr(a[0], a[1], 1); }

H(GetThreadLocale) { UNUSED; return 0x409; }
H(GetProcessVersion) { UNUSED; return 0x00050001; }

H(MulDiv)
{
    UNUSED;
    int64_t x = (int32_t)a[0], y = (int32_t)a[1], z = (int32_t)a[2];
    if (z == 0)
        return 0xFFFFFFFF;
    double q = (double)(x * y) / (double)z;       /* round(a * b / c): Python's round, half to even */
    double r = __builtin_rint(q);
    return (uint32_t)(int64_t)r;
}

H(GetSystemDirectoryA)
{
    UNUSED;
    static const char s[] = "C:\\WINDOWS\\SYSTEM32";
    if (a[1] > sizeof s - 1)
        memcpy(gptr(a[0]), s, sizeof s);
    return sizeof s - 1;
}

H(GetTempPathA)
{
    UNUSED;
    static const char s[] = "C:\\TEMP\\";
    if (a[0] > sizeof s - 1)
        memcpy(gptr(a[1]), s, sizeof s);
    return sizeof s - 1;
}

H(SearchPathA)
{
    UNUSED;
    host_set_last_error(2);
    return 0;
}

/* ---- atoms: name (lower case) -> 0xC000 + order of addition */
static char *g_atoms[4096];
static uint32_t g_natoms;

H(GlobalAddAtomA)
{
    UNUSED;
    char n[4100];
    host_cstr(a[0], n, sizeof n);
    for (char *p = n; *p; p++)
        *p = (char)latin1_lower((uint8_t)*p);
    for (uint32_t i = 0; i < g_natoms; i++)
        if (g_atoms[i] && strcmp(g_atoms[i], n) == 0)
            return 0xC000 + i;
    if (g_natoms == 4096)
        host_fatal("too many atoms");
    g_atoms[g_natoms] = strdup(n);
    return 0xC000 + g_natoms++;
}

/* ---- resources: (type, name) in a loaded module's resource directory, read from its image */
typedef struct {
    Module *m;
    uint32_t rva, size;
} Resource;

/* the entry of dir whose id (key < 0x10000) or upper-cased name (key_s) matches; its OffsetToData, or 0 */
static uint32_t res_entry(uint32_t root, uint32_t dir, uint32_t key, const char *key_s)
{
    uint32_t n = (uint32_t)r16(dir + 12) + r16(dir + 14);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t e = dir + 16 + 8 * i, name = r32(e), off = r32(e + 4);
        int hit;
        if (name & 0x80000000u) {
            if (!key_s)
                continue;
            uint32_t s = root + (name & 0x7fffffffu);
            uint32_t len = r16(s), k = 0;
            char buf[512];
            for (; k < len && k < sizeof buf - 1; k++) {
                uint16_t u = r16(s + 2 + 2 * k);
                buf[k] = (char)(u < 256 ? latin1_upper(u) : '?');
            }
            buf[k] = 0;
            hit = strcmp(buf, key_s) == 0;
        } else {
            hit = !key_s && name == key;
        }
        if (hit)
            return off;
    }
    return 0;
}

static void res_key(uint32_t v, char *buf, size_t cap, const char **key_s)
{
    *key_s = NULL;
    if (v < 0x10000)
        return;
    host_cstr(v, buf, cap);
    for (char *p = buf; *p; p++)
        *p = (char)latin1_upper((uint8_t)*p);
    *key_s = buf;
}

uint32_t host_find_resource(uint32_t hmod, uint32_t name, uint32_t typ)
{
    Module *m = host_module_by_base(hmod);
    if (!m && hmod == 0)
        m = host_find_module("maxpayne.exe");
    uint32_t nt = m ? m->base + r32(m->base + 0x3c) : 0;
    uint32_t rdir = m && r32(nt + 24 + 92) > 2 ? r32(nt + 24 + 96 + 16) : 0;
    if (!rdir) {
        host_set_last_error(1813);
        return 0;
    }
    uint32_t root = m->base + rdir;
    char kt_buf[512], kn_buf[512];
    const char *kt, *kn;
    res_key(typ, kt_buf, sizeof kt_buf, &kt);
    res_key(name, kn_buf, sizeof kn_buf, &kn);
    uint32_t t = res_entry(root, root, typ, kt);
    if (t & 0x80000000u) {
        uint32_t nd = res_entry(root, root + (t & 0x7fffffffu), name, kn);
        if (nd & 0x80000000u) {
            uint32_t ld = root + (nd & 0x7fffffffu);
            if ((uint32_t)r16(ld + 12) + r16(ld + 14)) {
                uint32_t leaf = r32(ld + 16 + 4);
                if (!(leaf & 0x80000000u)) {
                    Resource *r = malloc(sizeof *r);
                    r->m = m;
                    r->rva = r32(root + leaf);
                    r->size = r32(root + leaf + 4);
                    return host_new_handle(HK_RESOURCE, r);
                }
            }
        }
    }
    host_set_last_error(1814);
    return 0;
}

int host_resource(uint32_t h, int pop, Module **m, uint32_t *rva, uint32_t *size)
{
    int kind = HK_NONE;
    Resource *r = pop ? host_handle_pop(h, &kind) : host_handle(h, HK_RESOURCE);
    if (!r || (pop && kind != HK_RESOURCE))
        return 0;
    *m = r->m;
    *rva = r->rva;
    *size = r->size;
    return 1;
}

H(FindResourceA) { UNUSED; return host_find_resource(a[0], a[1], a[2]); }

H(LoadResource)
{
    UNUSED;
    Module *m;
    uint32_t rva, size;
    return host_resource(a[1], 0, &m, &rva, &size) ? m->base + rva : 0;
}

H(LockResource) { UNUSED; return a[0]; }

H(SizeofResource)
{
    UNUSED;
    Module *m;
    uint32_t rva, size;
    return host_resource(a[1], 0, &m, &rva, &size) ? size : 0;
}

/* ---- std handles and the console (the CRT probes these at start-up) */
H(GetStdHandle)
{
    UNUSED;
    switch (a[0]) {
    case 0xFFFFFFF6: return 0x10;
    case 0xFFFFFFF5: return 0x11;
    case 0xFFFFFFF4: return 0x12;
    }
    return 0xFFFFFFFF;
}

H(GetFileType) { UNUSED; return (a[0] == 0x10 || a[0] == 0x11 || a[0] == 0x12) ? 2 : 1; }
H(SetHandleCount) { UNUSED; return a[0]; }

H(GetConsoleMode)
{
    UNUSED;
    w32(a[1], 3);
    return 1;
}

/* ---- code pages and strings (Latin-1 throughout, as the Python handlers) */
H(GetACP) { UNUSED; return 1252; }
H(GetOEMCP) { UNUSED; return 437; }
H(GetUserDefaultLCID) { UNUSED; return 0x409; }

H(GetCPInfo)
{
    UNUSED;
    w32(a[1], 1);
    gptr(a[1])[4] = '?';
    gptr(a[1])[5] = 0;
    wzero(a[1] + 6, 12);
    return 1;
}

H(MultiByteToWideChar)
{
    UNUSED;
    uint32_t src = a[2], srclen = a[3], dst = a[4], dstlen = a[5];
    uint32_t n = srclen != 0xFFFFFFFF ? srclen : (uint32_t)strnlen((const char *)gptr(src), 4096) + 1;
    if (dstlen == 0)
        return n;
    if (n > dstlen) {
        host_set_last_error(122);
        return 0;
    }
    for (uint32_t i = 0; i < n; i++)
        w16(dst + 2 * i, gptr(src)[i]);
    if (srclen == 0xFFFFFFFF)
        w16(dst + 2 * (n - 1), 0);             /* the cstr stops at 4096 bytes: its terminator is ours */
    return n;
}

/* UTF-16 units -> Latin-1, '?' for what Latin-1 lacks (a surrogate pair is one character, one '?'). */
static uint32_t wide_to_latin1(uint32_t src, uint32_t units, uint8_t *out)
{
    uint32_t k = 0;
    for (uint32_t i = 0; i < units; i++) {
        uint16_t u = r16(src + 2 * i);
        if (u >= 0xD800 && u < 0xDC00 && i + 1 < units && r16(src + 2 * i + 2) >= 0xDC00 && r16(src + 2 * i + 2) < 0xE000)
            i++;
        out[k++] = u < 256 ? (uint8_t)u : '?';
    }
    return k;
}

H(WideCharToMultiByte)
{
    UNUSED;
    uint32_t src = a[2], srclen = a[3], dst = a[4], dstlen = a[5];
    uint32_t units = srclen;
    if (srclen == 0xFFFFFFFF) {
        units = 0;
        while (units < 4096 && r16(src + 2 * units))
            units++;
    }
    uint8_t *out = malloc(units + 1);
    uint32_t n = wide_to_latin1(src, units, out);
    if (srclen == 0xFFFFFFFF)
        out[n++] = 0;
    uint32_t res = n;
    if (dstlen != 0) {
        if (n > dstlen) {
            host_set_last_error(122);
            res = 0;
        } else {
            memcpy(gptr(dst), out, n);
        }
    }
    free(out);
    return res;
}

/* Python's str.isupper/islower/isdigit/isspace/isalpha and the punctuation, control and hex tests on chr(c), as
 * GetStringTypeA (CTYPE_A) and GetStringTypeW (CTYPE_W) combine them; Latin-1 characters only. */
static const uint16_t CTYPE_A[256] = {
    0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x028, 0x028, 0x028, 0x028, 0x028, 0x020, 0x020,
    0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x028, 0x028, 0x028, 0x028,
    0x008, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010,
    0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010,
    0x010, 0x181, 0x181, 0x181, 0x181, 0x181, 0x181, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101,
    0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x010, 0x010, 0x010, 0x010, 0x010,
    0x010, 0x182, 0x182, 0x182, 0x182, 0x182, 0x182, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102,
    0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x010, 0x010, 0x010, 0x010, 0x020,
    0x000, 0x000, 0x000, 0x000, 0x000, 0x008, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x008, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x102, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x000, 0x000, 0x004, 0x004, 0x000, 0x102, 0x000, 0x000, 0x000, 0x004, 0x102, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101,
    0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x000, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x102,
    0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102,
    0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x000, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102};
static const uint16_t CTYPE_W[256] = {
    0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x008, 0x008, 0x008, 0x008, 0x008, 0x000, 0x000,
    0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x008, 0x008, 0x008, 0x008,
    0x008, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x000, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101,
    0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x000, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102,
    0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x000, 0x000, 0x000, 0x000, 0x000, 0x008, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x008, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x102, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x000, 0x000, 0x004, 0x004, 0x000, 0x102, 0x000, 0x000, 0x000, 0x004, 0x102, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101,
    0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x000, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x102,
    0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102,
    0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x000, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102};

H(GetStringTypeA)
{
    UNUSED;
    uint32_t src = a[2], n = a[3], out = a[4];
    uint32_t cnt = n != 0xFFFFFFFF ? n : (uint32_t)strnlen((const char *)gptr(src), 4096) + 1;
    for (uint32_t i = 0; i < cnt; i++)
        w16(out + 2 * i, CTYPE_A[gptr(src)[i]]);
    return 1;
}

H(GetStringTypeW)
{
    UNUSED;
    uint32_t src = a[1], n = a[2], out = a[3];
    uint32_t cnt = n;
    if (n == 0xFFFFFFFF) {
        cnt = 0;
        while (cnt < 4096 && r16(src + 2 * cnt))
            cnt++;
        cnt++;
    }
    for (uint32_t i = 0; i < cnt; i++) {
        uint16_t ch = r16(src + 2 * i);
        if (ch > 255)
            host_fatal("GetStringTypeW of U+%04X: only Latin-1 is ported (emu/mpemu.py uses Python's Unicode tables)", ch);
        w16(out + 2 * i, CTYPE_W[ch]);
    }
    return 1;
}

H(LCMapStringA)
{
    UNUSED;
    uint32_t flags = a[1], src = a[2], srclen = a[3], dst = a[4], dstlen = a[5];
    uint32_t n = srclen != 0xFFFFFFFF ? srclen : (uint32_t)strnlen((const char *)gptr(src), 4096) + 1;
    uint8_t *s = malloc(n + 1);
    memcpy(s, gptr(src), n);
    if (srclen == 0xFFFFFFFF)
        s[n - 1] = 0;
    for (uint32_t i = 0; i < n; i++) {         /* bytes.upper()/lower(): ASCII only */
        if ((flags & 0x200) && s[i] >= 'a' && s[i] <= 'z')
            s[i] = (uint8_t)(s[i] - 32);
        else if (!(flags & 0x200) && (flags & 0x100) && s[i] >= 'A' && s[i] <= 'Z')
            s[i] = (uint8_t)(s[i] + 32);
    }
    if (dstlen)
        memcpy(gptr(dst), s, n < dstlen ? n : dstlen);
    free(s);
    return n;
}

H(LCMapStringW)
{
    UNUSED;
    uint32_t src = a[2], srclen = a[3], dst = a[4], dstlen = a[5];
    uint32_t n = srclen;
    if (srclen == 0xFFFFFFFF) {
        n = 0;
        while (n < 4096 && r16(src + 2 * n))
            n++;
        n++;
    }
    if (dstlen == 0)
        return n;
    memmove(gptr(dst), gptr(src), 2 * (n < dstlen ? n : dstlen));
    return n;
}

/* Python bytes comparison: lexicographic, then the shorter first. 1 (less), 2 (equal), 3 (greater). */
static uint32_t cmp_bytes(const uint8_t *x, size_t nx, const uint8_t *y, size_t ny)
{
    size_t n = nx < ny ? nx : ny;
    int r = memcmp(x, y, n);
    if (r == 0)
        r = nx < ny ? -1 : nx > ny ? 1 : 0;
    return r < 0 ? 1 : r > 0 ? 3 : 2;
}

H(CompareStringA)
{
    UNUSED;
    uint32_t flags = a[1];
    size_t na = a[3] != 0xFFFFFFFF ? a[3] : strnlen((const char *)gptr(a[2]), 4096);
    size_t nb = a[5] != 0xFFFFFFFF ? a[5] : strnlen((const char *)gptr(a[4]), 4096);
    uint8_t *x = malloc(na + 1), *y = malloc(nb + 1);
    memcpy(x, gptr(a[2]), na);
    memcpy(y, gptr(a[4]), nb);
    if (flags & 1) {
        for (size_t i = 0; i < na; i++)
            if (x[i] >= 'A' && x[i] <= 'Z')
                x[i] = (uint8_t)(x[i] + 32);
        for (size_t i = 0; i < nb; i++)
            if (y[i] >= 'A' && y[i] <= 'Z')
                y[i] = (uint8_t)(y[i] + 32);
    }
    uint32_t r = cmp_bytes(x, na, y, nb);
    free(x);
    free(y);
    return r;
}

H(CompareStringW)
{
    UNUSED;
    size_t na = a[3], nb = a[5];
    if (a[3] == 0xFFFFFFFF)
        for (na = 0; na < 4096 && r16(a[2] + 2 * (uint32_t)na); na++)
            ;
    if (a[5] == 0xFFFFFFFF)
        for (nb = 0; nb < 4096 && r16(a[4] + 2 * (uint32_t)nb); nb++)
            ;
    return cmp_bytes(gptr(a[2]), 2 * na, gptr(a[4]), 2 * nb);
}

H(GetLocaleInfoA)
{
    UNUSED;
    if (a[3])
        memcpy(gptr(a[2]), "1", 2);
    return 2;
}

H(GetLocaleInfoW)
{
    UNUSED;
    if (a[3])
        memcpy(gptr(a[2]), "1\0\0", 4);
    return 2;
}

/* ---- time */
/* --sim-fps N (M7): a virtual clock for runs that must not depend on the wall clock. Each main-loop frame advances it
 * by exactly 1/N s (host_clock_frame); until the first frame every read advances it by 1 ms, so start-up code that
 * waits for time to pass still finishes. Every guest clock reads it: QueryPerformanceCounter, timeGetTime/GetTickCount,
 * the system time, the DSOUND play cursors and the DINPUT timestamps. */
static unsigned g_sim_fps;
static uint64_t g_sim_ns, g_sim_frames;
static int g_sim_running;
#define SIM_EPOCH_S 1000000000ull                   /* 2001-09-09, the system time's origin under --sim-fps */

void host_clock_sim(unsigned fps) { g_sim_fps = fps; }
unsigned host_clock_sim_fps(void) { return g_sim_fps; }

void host_clock_frame(void)
{
    if (!g_sim_fps)
        return;
    if (g_sim_running)
        g_sim_frames++;
    g_sim_running = 1;
}

static uint64_t now_ns(void)
{
    if (g_sim_fps) {
        if (!g_sim_running)
            g_sim_ns += 1000000;
        return g_sim_ns + g_sim_frames * 1000000000ull / g_sim_fps;
    }
    static mach_timebase_info_data_t tb;
    if (!tb.denom)
        mach_timebase_info(&tb);
    return mach_absolute_time() * tb.numer / tb.denom;
}

uint64_t host_clock_ns(void) { return now_ns(); }

static void now_timeval(struct timeval *tv)
{
    if (!g_sim_fps) {
        gettimeofday(tv, NULL);
        return;
    }
    uint64_t ns = now_ns();
    tv->tv_sec = (time_t)(SIM_EPOCH_S + ns / 1000000000ull);
    tv->tv_usec = (suseconds_t)(ns % 1000000000ull / 1000);
}

H(GetSystemTimeAsFileTime)
{
    UNUSED;
    struct timeval tv;
    now_timeval(&tv);
    uint64_t ft = ((uint64_t)tv.tv_sec + 11644473600ull) * 10000000ull + (uint64_t)tv.tv_usec * 10u;
    memcpy(gptr(a[0]), &ft, 8);
    return 0;
}

H(QueryPerformanceCounter)
{
    UNUSED;
    uint64_t us = now_ns() / 1000;
    memcpy(gptr(a[0]), &us, 8);
    return 1;
}

H(QueryPerformanceFrequency)
{
    UNUSED;
    uint64_t f = 1000000;
    memcpy(gptr(a[0]), &f, 8);
    return 1;
}

H(timeGetTime) { UNUSED; return (uint32_t)(now_ns() / 1000000); }
/* Sleep returns at once (the game runs slower than real time anyway), but waits for real while a movie runs */
H(Sleep)
{
    UNUSED;
    host_movie_sleep(a[0]);
    return 0;
}

uint32_t host_tick(void) { return (uint32_t)(now_ns() / 1000000); }

/* SYSTEMTIME from time.gmtime (both GetSystemTime and GetLocalTime, as the Python handlers) */
H(GetSystemTime)
{
    UNUSED;
    struct timeval tv;
    now_timeval(&tv);
    time_t t = tv.tv_sec;
    struct tm tm;
    gmtime_r(&t, &tm);
    uint16_t v[8] = {(uint16_t)(tm.tm_year + 1900), (uint16_t)(tm.tm_mon + 1), (uint16_t)tm.tm_wday,
                     (uint16_t)tm.tm_mday, (uint16_t)tm.tm_hour, (uint16_t)tm.tm_min, (uint16_t)tm.tm_sec, 0};
    memcpy(gptr(a[0]), v, sizeof v);
    return 0;
}

H(GetTimeZoneInformation)
{
    UNUSED;
    wzero(a[0], 172);
    return 0;
}

/* ---- current directory */
H(GetCurrentDirectoryA)
{
    UNUSED;
    uint32_t n = (uint32_t)strlen(g_cwd);
    if (a[0] < n + 1)
        return n + 1;
    memcpy(gptr(a[1]), g_cwd, n + 1);
    return n;
}

H(GetCurrentDirectoryW)
{
    UNUSED;
    uint32_t n = (uint32_t)strlen(g_cwd);
    if (a[0] < n + 1)
        return n + 1;
    for (uint32_t i = 0; i <= n; i++)
        w16(a[1] + 2 * i, (uint8_t)g_cwd[i]);
    return n;
}

static void set_cwd(const char *g)
{
    char abs[1024];
    host_guest_abs(g, abs, sizeof abs);
    size_t k = strlen(abs);
    while (k && abs[k - 1] == '\\')
        abs[--k] = 0;
    snprintf(g_cwd, sizeof g_cwd, "%s", abs);
}

H(SetCurrentDirectoryA)
{
    UNUSED;
    char s[1024];
    host_cstr(a[0], s, sizeof s);
    set_cwd(s);
    return 1;
}

const HleDef hle_kernel32[] = {
    {K, "GetVersion", 0, STDCALL, GetVersion},
    {K, "GetVersionExA", 1, STDCALL, GetVersionExA},
    {K, "GetCommandLineA", 0, STDCALL, GetCommandLineA},
    {K, "GetCommandLineW", 0, STDCALL, GetCommandLineW},
    {K, "GetEnvironmentStrings", 0, STDCALL, GetEnvironmentStrings},
    {K, "GetEnvironmentStringsW", 0, STDCALL, GetEnvironmentStrings},
    {K, "FreeEnvironmentStringsA", 1, STDCALL, Return1},
    {K, "FreeEnvironmentStringsW", 1, STDCALL, Return1},
    {K, "GetEnvironmentVariableA", 3, STDCALL, GetEnvironmentVariableA},
    {K, "SetEnvironmentVariableA", 2, STDCALL, Return1},
    {K, "SetEnvironmentVariableW", 2, STDCALL, Return1},
    {K, "GetStartupInfoA", 1, STDCALL, GetStartupInfoA},
    {K, "GetModuleHandleA", 1, STDCALL, GetModuleHandleA},
    {K, "GetModuleFileNameA", 3, STDCALL, GetModuleFileNameA},
    {K, "GetModuleFileNameW", 3, STDCALL, GetModuleFileNameW},
    {K, "LoadLibraryA", 1, STDCALL | HLE_CORO, LoadLibraryA},
    {K, "FreeLibrary", 1, STDCALL, Return1},
    {K, "GetProcAddress", 2, STDCALL, GetProcAddress},
    {K, "DisableThreadLibraryCalls", 1, STDCALL, Return1},
    {K, "GetCurrentProcess", 0, STDCALL, GetCurrentProcess},
    {K, "GetCurrentThread", 0, STDCALL, GetCurrentThread},
    {K, "GetCurrentProcessId", 0, STDCALL, GetCurrentProcessId},
    {K, "GetCurrentThreadId", 0, STDCALL, GetCurrentThreadId},
    {K, "GetPriorityClass", 1, STDCALL, GetPriorityClass},
    {K, "SetPriorityClass", 2, STDCALL, Return1},
    {K, "GetThreadPriority", 1, STDCALL, Return0},
    {K, "SetThreadPriority", 2, STDCALL, Return1},
    {K, "ExitProcess", 1, STDCALL, ExitProcess},
    {K, "TerminateProcess", 2, STDCALL, TerminateProcess},
    {K, "SetErrorMode", 1, STDCALL, Return0},
    {K, "SetUnhandledExceptionFilter", 1, STDCALL, Return0},
    {K, "UnhandledExceptionFilter", 1, STDCALL, Return0},
    {K, "OutputDebugStringA", 1, STDCALL, OutputDebugStringA},
    {K, "GetComputerNameA", 2, STDCALL, GetComputerNameA},
    {K, "Sleep", 1, STDCALL, Sleep},
    {K, "GetProcessHeap", 0, STDCALL, GetProcessHeap},
    {K, "HeapCreate", 3, STDCALL, HeapCreate},
    {K, "HeapDestroy", 1, STDCALL, Return1},
    {K, "HeapAlloc", 3, STDCALL, HeapAlloc},
    {K, "HeapFree", 3, STDCALL, HeapFree},
    {K, "HeapReAlloc", 4, STDCALL, HeapReAlloc},
    {K, "HeapSize", 3, STDCALL, HeapSize},
    {K, "HeapValidate", 3, STDCALL, Return1},
    {K, "HeapCompact", 2, STDCALL, HeapCompact},
    {K, "VirtualAlloc", 4, STDCALL, VirtualAlloc},
    {K, "VirtualFree", 3, STDCALL, Return1},
    {K, "GlobalMemoryStatus", 1, STDCALL, GlobalMemoryStatus},
    {K, "IsBadReadPtr", 2, STDCALL, Return0},
    {K, "IsBadWritePtr", 2, STDCALL, Return0},
    {K, "IsBadCodePtr", 1, STDCALL, Return0},
    {K, "TlsAlloc", 0, STDCALL, TlsAlloc},
    {K, "TlsFree", 1, STDCALL, TlsFree},
    {K, "GetLastError", 0, STDCALL, GetLastError},
    {K, "SetLastError", 1, STDCALL, SetLastError},
    {K, "InitializeCriticalSection", 1, STDCALL, Return0},
    {K, "EnterCriticalSection", 1, STDCALL, Return0},
    {K, "LeaveCriticalSection", 1, STDCALL, Return0},
    {K, "DeleteCriticalSection", 1, STDCALL, Return0},
    {K, "InterlockedIncrement", 1, STDCALL, InterlockedIncrement},
    {K, "InterlockedDecrement", 1, STDCALL, InterlockedDecrement},
    {K, "InterlockedExchange", 2, STDCALL, InterlockedExchange},
    {K, "CreateMutexA", 3, STDCALL, NewHandleMutex},
    {K, "ReleaseMutex", 1, STDCALL, Return1},
    {K, "CreateEventA", 4, STDCALL, NewHandleEvent},
    {K, "SetEvent", 1, STDCALL, Return1},
    {K, "WaitForSingleObject", 2, STDCALL, Return0},
    {K, "GetStdHandle", 1, STDCALL, GetStdHandle},
    {K, "SetStdHandle", 2, STDCALL, Return1},
    {K, "GetFileType", 1, STDCALL, GetFileType},
    {K, "SetHandleCount", 1, STDCALL, SetHandleCount},
    {K, "GetConsoleMode", 2, STDCALL, GetConsoleMode},
    {K, "SetConsoleMode", 2, STDCALL, Return1},
    {K, "SetConsoleCtrlHandler", 2, STDCALL, Return1},
    {K, "GetACP", 0, STDCALL, GetACP},
    {K, "GetOEMCP", 0, STDCALL, GetOEMCP},
    {K, "IsValidCodePage", 1, STDCALL, Return1},
    {K, "IsValidLocale", 2, STDCALL, Return1},
    {K, "GetUserDefaultLCID", 0, STDCALL, GetUserDefaultLCID},
    {K, "GetCPInfo", 2, STDCALL, GetCPInfo},
    {K, "MultiByteToWideChar", 6, STDCALL, MultiByteToWideChar},
    {K, "WideCharToMultiByte", 8, STDCALL, WideCharToMultiByte},
    {K, "GetStringTypeA", 5, STDCALL, GetStringTypeA},
    {K, "GetStringTypeW", 4, STDCALL, GetStringTypeW},
    {K, "LCMapStringA", 6, STDCALL, LCMapStringA},
    {K, "LCMapStringW", 6, STDCALL, LCMapStringW},
    {K, "CompareStringA", 6, STDCALL, CompareStringA},
    {K, "CompareStringW", 6, STDCALL, CompareStringW},
    {K, "GetLocaleInfoA", 4, STDCALL, GetLocaleInfoA},
    {K, "GetLocaleInfoW", 4, STDCALL, GetLocaleInfoW},
    {K, "EnumSystemLocalesA", 2, STDCALL, Return1},
    {K, "GetSystemTimeAsFileTime", 1, STDCALL, GetSystemTimeAsFileTime},
    {K, "QueryPerformanceCounter", 1, STDCALL, QueryPerformanceCounter},
    {K, "QueryPerformanceFrequency", 1, STDCALL, QueryPerformanceFrequency},
    {"WINMM.DLL", "timeGetTime", 0, STDCALL, timeGetTime},
    {K, "GetSystemTime", 1, STDCALL, GetSystemTime},
    {K, "GetLocalTime", 1, STDCALL, GetSystemTime},
    {K, "GetTimeZoneInformation", 1, STDCALL, GetTimeZoneInformation},
    {K, "GetCurrentDirectoryA", 2, STDCALL, GetCurrentDirectoryA},
    {K, "GetCurrentDirectoryW", 2, STDCALL, GetCurrentDirectoryW},
    {K, "SetCurrentDirectoryA", 1, STDCALL, SetCurrentDirectoryA},
    {K, "CreateSemaphoreA", 4, STDCALL, NewHandleSemaphore},
    {K, "ReleaseSemaphore", 3, STDCALL, Return1},
    {K, "WaitForMultipleObjects", 4, STDCALL, Return0},
    {K, "SuspendThread", 1, STDCALL, Return0},
    {K, "ResumeThread", 1, STDCALL, Return1},
    {K, "VirtualProtect", 4, STDCALL, VirtualProtect},
    {K, "CreateThread", 6, STDCALL, CreateThread},
    {K, "LocalAlloc", 2, STDCALL, LocalAlloc},
    {K, "LocalReAlloc", 3, STDCALL, LocalReAlloc},
    {K, "LocalFree", 1, STDCALL, LocalFree},
    {K, "LocalLock", 1, STDCALL, LocalLock},
    {K, "LocalUnlock", 1, STDCALL, Return0},
    {K, "LocalSize", 1, STDCALL, LocalSize},
    {K, "GlobalAlloc", 2, STDCALL, LocalAlloc},
    {K, "GlobalReAlloc", 3, STDCALL, LocalReAlloc},
    {K, "GlobalFree", 1, STDCALL, LocalFree},
    {K, "GlobalLock", 1, STDCALL, LocalLock},
    {K, "GlobalUnlock", 1, STDCALL, Return0},
    {K, "GlobalSize", 1, STDCALL, LocalSize},
    {K, "GlobalHandle", 1, STDCALL, LocalLock},
    {K, "GlobalFlags", 1, STDCALL, Return0},
    {K, "lstrlenA", 1, STDCALL, lstrlenA},
    {K, "lstrlenW", 1, STDCALL, lstrlenW},
    {K, "lstrcpyA", 2, STDCALL, lstrcpyA},
    {K, "lstrcpynA", 3, STDCALL, lstrcpynA},
    {K, "lstrcatA", 2, STDCALL, lstrcatA},
    {K, "lstrcmpA", 2, STDCALL, lstrcmpA},
    {K, "lstrcmpiA", 2, STDCALL, lstrcmpiA},
    {K, "IsBadStringPtrA", 2, STDCALL, Return0},
    {K, "IsBadStringPtrW", 2, STDCALL, Return0},
    {K, "IsDBCSLeadByte", 1, STDCALL, Return0},
    {K, "GetThreadLocale", 0, STDCALL, GetThreadLocale},
    {K, "GetProcessVersion", 1, STDCALL, GetProcessVersion},
    {K, "GetTickCount", 0, STDCALL, timeGetTime},
    {K, "MulDiv", 3, STDCALL, MulDiv},
    {K, "GetStringTypeExA", 5, STDCALL, GetStringTypeA},
    {K, "GetSystemDirectoryA", 2, STDCALL, GetSystemDirectoryA},
    {K, "GetTempPathA", 2, STDCALL, GetTempPathA},
    {K, "GetVolumeInformationA", 8, STDCALL, Return0},
    {K, "SearchPathA", 6, STDCALL, SearchPathA},
    {K, "FormatMessageA", 7, STDCALL, Return0},
    {K, "GlobalAddAtomA", 1, STDCALL, GlobalAddAtomA},
    {K, "FindResourceA", 3, STDCALL, FindResourceA},
    {K, "LoadResource", 2, STDCALL, LoadResource},
    {K, "LockResource", 1, STDCALL, LockResource},
    {K, "SizeofResource", 2, STDCALL, SizeofResource},
    {NULL, NULL, 0, 0, NULL},
};
