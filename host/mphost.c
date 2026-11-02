/* mphost: the native host (E5, docs/m6-emu-removal.md). See host.h.
 *
 *   mphost GAME_DIR --lib build-lift/liblifted_full_h64.dylib [--trace FILE] [--data-dir DIR] [--frames N] [--window]
 *          [--intro skip|play] [--game-mode fullscreen|windowed] [--capture DIR --capture-frames N,...]
 *          [--audio device|null|off] [--audio-wav FILE]
 *
 * What emu/mpemu.py boot + run_dll_mains and emu/run_init.py --real-entry do, in the same order and at the same
 * addresses: reserve the 4 GB guest space (one host mapping, guest address A at mem + A), map the stack, TEB, PEB, stub
 * region and heap; load the runtime DLLs, the game DLLs and the exe at the MODULE_BASES (relocated) and resolve their
 * imports across the loaded modules, every other import becoming an HLE stub (stub indexes are handed out in the
 * emulator's order); run each DLL's entry point, then the exe's entry point, in the lifted library. The run ends when
 * the game calls ExitProcess.
 *
 * Calls from lifted code to a stub go through runtime.c hle_direct: heap.c, seh.c and hle_fast.c serve theirs, and
 * everything else comes here (host_hle), which runs the stub's C handler (host/hle_*.c). A stub without one, or guest
 * code that is not lifted (the CPU's call_guest), stops the process with the name or address and the last API calls.
 * --trace FILE writes every call served here as the emulator's API log writes it (emu/mpemu.py ApiLog.line), for the
 * call-by-call comparison with a Python run (tools/m6/api_trace.py). */
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "host.h"
#include "runtime.h"

/* ---------------------------------------------------------------- the lifted library */
static struct {
    const LiftEntry *table;
    const unsigned *table_len;
    void (*host_init)(void *, void *, uint32_t, uint32_t);
    void (*host_call)(CPU *, uint32_t, uint32_t);
    void (*set_bridge_stop)(uint32_t);
    void (*set_entry_hook)(void *);
    void (*set_exit_hook)(void *);      /* H74 or later; NULL in older libraries */
    void (*set_insn_hook)(void *);      /* H76 or later; NULL in older libraries */
    int (*crt_regions)(const uint32_t *, uint32_t);
    int (*crt_bind)(const char *, uint32_t, uint32_t);
    uint32_t (*crt_counts)(uint64_t *, uint32_t);
    const char *(*crt_name)(uint32_t);
    void (*heap_reset)(uint64_t, uint64_t);
    uint32_t (*heap_alloc)(uint32_t, int *);
    int (*heap_free)(uint32_t);
    int (*heap_get)(uint32_t, uint32_t *, uint32_t *);
    void (*heap_set_live)(uint32_t, uint32_t, uint32_t);
    uint32_t (*heap_reserve)(uint32_t, int);
    void (*heap_stats)(uint64_t *);
    void (*heap_direct_bind)(uint32_t, uint32_t);
    void (*seh_bind)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    void (*seh_stats)(uint64_t *);
    void (*fast_reset)(void);
    void (*fast_bind)(uint32_t, uint32_t);
    int (*fast_set)(int, uint32_t, uint32_t, uint32_t, uint32_t, int);
    int (*fast_get)(int, uint32_t, uint32_t, uint32_t *, uint32_t *);
    uint64_t (*fast_total)(void);
    void (*fast_obj)(uint32_t, uint32_t, uint32_t, uint32_t);
    void (*fast_tex)(uint32_t, uint32_t, uint32_t, int);
    void (*fast_capture)(int, void *, void *, void *, int);
    int (*fast_blob)(int, uint32_t, int, void *);
    int (*ds_new)(uint32_t);
    void (*ds_cfg)(int, uint32_t, uint32_t, int, uint32_t, uint32_t);
    double (*ds_field)(int, int, int, double);
    void (*ds_gains)(int, double, double, int);
    void (*ds_mixer)(void *, void *, void *, void *);
    int (*di_new)(uint32_t, uint32_t);
    void (*di_cfg)(int, uint32_t, int, uint32_t, uint32_t, uint32_t, const uint32_t *);
    int64_t (*di_field)(int, int, int, int64_t);
    uint32_t (*di_queue)(int, int, uint32_t, uint32_t *);
    uint8_t *(*di_keys)(void);
    uint64_t (*hle_direct_calls)(void);
    void (*call_cache_stats)(uint64_t *);
} L;

static void *lib_sym(void *h, const char *name)
{
    void *p = dlsym(h, name);
    if (!p) {
        fprintf(stderr, "mphost: the library has no %s (build it from H64 or later: lift/runtime with lift_host_init)\n",
                name);
        exit(2);
    }
    return p;
}

static void lib_open(const char *path)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        fprintf(stderr, "mphost: %s\n", dlerror());
        exit(2);
    }
#define S(field, name) *(void **)&L.field = lib_sym(h, name)
    S(table, "lift_table");
    S(table_len, "lift_table_len");
    S(host_init, "lift_host_init");
    S(host_call, "lift_host_call");
    S(set_bridge_stop, "lift_set_bridge_stop");
    S(set_entry_hook, "lift_set_entry_hook");
    S(crt_regions, "lift_crt_regions");
    S(crt_bind, "lift_crt_bind");
    S(crt_counts, "lift_crt_counts");
    S(crt_name, "lift_crt_name");
    S(heap_reset, "lift_heap_reset");
    S(heap_alloc, "lift_heap_alloc");
    S(heap_free, "lift_heap_free");
    S(heap_get, "lift_heap_get");
    S(heap_set_live, "lift_heap_set_live");
    S(heap_reserve, "lift_heap_reserve");
    S(heap_stats, "lift_heap_stats");
    S(heap_direct_bind, "lift_heap_direct_bind");
    S(seh_bind, "lift_seh_bind");
    S(seh_stats, "lift_seh_stats");
    S(fast_reset, "lift_hle_fast_reset");
    S(fast_bind, "lift_hle_fast_bind");
    S(fast_set, "lift_hle_fast_set");
    S(fast_get, "lift_hle_fast_get");
    S(fast_total, "lift_hle_fast_total");
    S(fast_obj, "lift_hle_fast_obj");
    S(fast_tex, "lift_hle_fast_tex");
    S(fast_capture, "lift_hle_fast_capture");
    S(fast_blob, "lift_hle_fast_blob");
    S(ds_new, "lift_hle_fast_ds_new");
    S(ds_cfg, "lift_hle_fast_ds_cfg");
    S(ds_field, "lift_hle_fast_ds_field");
    S(ds_gains, "lift_hle_fast_ds_gains");
    S(ds_mixer, "lift_hle_fast_ds_mixer");
    S(di_new, "lift_hle_fast_di_new");
    S(di_cfg, "lift_hle_fast_di_cfg");
    S(di_field, "lift_hle_fast_di_field");
    S(di_queue, "lift_hle_fast_di_queue");
    S(di_keys, "lift_hle_fast_di_keys");
    S(hle_direct_calls, "lift_hle_direct_calls");
    S(call_cache_stats, "lift_call_cache_stats");
#undef S
    *(void **)&L.set_exit_hook = dlsym(h, "lift_set_exit_hook");
    *(void **)&L.set_insn_hook = dlsym(h, "lift_set_insn_hook");
}

static int lifted(uint32_t va)
{
    unsigned lo = 0, hi = *L.table_len;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        uint32_t t = L.table[mid].va;
        if (t == va)
            return 1;
        if (t < va)
            lo = mid + 1;
        else
            hi = mid;
    }
    return 0;
}

/* ---------------------------------------------------------------- guest memory */
CPU g_cpu;
const char *g_game_dir;
#define MAX_REGIONS 256
static uint32_t g_regions[2 * MAX_REGIONS];
static int g_nregions;

/* Emu.map: the region joins the list the CRT helpers and the thunk shortcut may read (lift_crt_regions). The memory
 * itself is all there already (the whole 4 GB is one mapping). */
static void map_region(uint32_t addr, uint32_t size)
{
    uint32_t start = addr & ~(PAGE - 1);
    uint64_t end = ((uint64_t)addr + size + PAGE - 1) & ~(uint64_t)(PAGE - 1);
    if (g_nregions == MAX_REGIONS)
        host_fatal("too many mapped regions");
    g_regions[2 * g_nregions] = start;
    g_regions[2 * g_nregions + 1] = (uint32_t)(end - start);
    g_nregions++;
    if (L.crt_regions(g_regions, (uint32_t)g_nregions) < 0)
        host_fatal("lift_crt_regions refused %d regions", g_nregions);
}

static inline void w32(uint32_t a, uint32_t v) { memcpy(gptr(a), &v, 4); }
static inline uint32_t r32(uint32_t a) { uint32_t v; memcpy(&v, gptr(a), 4); return v; }
static inline uint16_t r16(uint32_t a) { uint16_t v; memcpy(&v, gptr(a), 2); return v; }

uint32_t host_alloc(uint32_t size)
{
    if (size == 0)
        size = 1;
    int reused = 0;
    uint32_t p = L.heap_alloc(size, &reused);
    if (!p)
        host_fatal("guest heap exhausted (alloc of %u bytes)", size);
    if (reused)
        memset(gptr(p), 0, (size + 15u) & ~15u);
    return p;
}

int host_free(uint32_t p) { return L.heap_free(p); }

int host_heap_get(uint32_t p, uint32_t *size, uint32_t *cap) { return L.heap_get(p, size, cap); }
void host_heap_resize(uint32_t p, uint32_t size)
{
    uint32_t s, cap;
    if (L.heap_get(p, &s, &cap))
        L.heap_set_live(p, size, cap);
}
uint32_t host_heap_reserve(uint32_t size, int record) { return L.heap_reserve(size, record); }
uint32_t host_heap_live(void)
{
    uint64_t st[8];
    L.heap_stats(st);
    return (uint32_t)st[1];
}

uint32_t host_put_cstr(const char *s, uint32_t extra)
{
    size_t n = strlen(s);
    uint32_t p = host_alloc((uint32_t)(n + 1 + extra));
    memcpy(gptr(p), s, n + 1);
    return p;
}

size_t host_cstr(uint32_t a, char *out, size_t cap)
{
    size_t n = 0;
    if (a)
        while (n < 4096 && n + 1 < cap && gptr(a)[n])
            out[n] = (char)gptr(a)[n], n++;
    out[n] = 0;
    return n;
}

size_t host_wstr(uint32_t a, uint16_t *out, size_t cap)
{
    size_t n = 0;
    if (a)
        while (n < 4096 && n + 1 < cap && r16(a + 2 * (uint32_t)n))
            out[n] = r16(a + 2 * (uint32_t)n), n++;
    out[n] = 0;
    return n;
}

uint32_t host_last_error(void)
{
    uint32_t v = 0, v2;
    L.fast_get(6, 0, 0, &v, &v2);
    return v;
}

void host_set_last_error(uint32_t v) { L.fast_set(6, 0, 0, v, 0, 1); }

void host_tls_set(uint32_t i, uint32_t v, int set)
{
    if (!L.fast_set(7, i, 0, v, 0, set))
        host_fatal("TLS slot %u is past the C table", i);
}

/* Emu.new_handle and Emu.handles: a counter from 0x200 in steps of 4 (after a CloseHandle the number is not handed out
 * again), each handle a (kind, object) the subsystems own. */
typedef struct {
    int kind;
    void *obj;
} Handle;
static Handle *g_handles;
static uint32_t g_nhandles, g_handles_cap;

uint32_t host_new_handle(int kind, void *obj)
{
    if (g_nhandles == g_handles_cap) {
        g_handles_cap = g_handles_cap ? 2 * g_handles_cap : 1024;
        g_handles = realloc(g_handles, g_handles_cap * sizeof *g_handles);
    }
    g_handles[g_nhandles].kind = kind;
    g_handles[g_nhandles].obj = obj;
    return 0x200 + 4 * g_nhandles++;
}

static Handle *handle_at(uint32_t h)
{
    uint32_t i = (h - 0x200) / 4;
    return (h >= 0x200 && (h & 3) == 0 && i < g_nhandles && g_handles[i].kind) ? &g_handles[i] : NULL;
}

void *host_handle(uint32_t h, int kind)
{
    Handle *p = handle_at(h);
    return p && p->kind == kind ? p->obj : NULL;
}

int host_handle_kind(uint32_t h)
{
    Handle *p = handle_at(h);
    return p ? p->kind : HK_NONE;
}

void *host_handle_pop(uint32_t h, int *kind)
{
    Handle *p = handle_at(h);
    *kind = p ? p->kind : HK_NONE;
    if (!p)
        return NULL;
    p->kind = HK_NONE;
    return p->obj;
}

/* ---------------------------------------------------------------- modules */
Module *g_mods[64];
int g_nmods;

static const struct { const char *name; uint32_t base; } MODULE_BASES[] = {
    {"rlmfc.dll", 0x10000000}, {"e2mfc.dll", 0x10100000}, {"grphmfc.dll", 0x10200000}, {"sndmfc.dll", 0x10300000},
    {"e2_d3d8_driver_mfc.dll", 0x10400000},
};
/* system DLLs replaced by the HLE: LoadLibraryA hands out these bases, GetProcAddress on them makes stubs */
static const struct { const char *name, *upper; uint32_t base; } FAKE_DLLS[] = {
    {"d3d8.dll", "D3D8.DLL", 0x7E010000}, {"dinput.dll", "DINPUT.DLL", 0x7E020000},
    {"dsound.dll", "DSOUND.DLL", 0x7E030000}, {"advapi32.dll", "ADVAPI32.DLL", 0x7E040000},
    {"shell32.dll", "SHELL32.DLL", 0x7E050000},
};
static const char *GAME_DLLS[] = {"MSVCRT.DLL", "MSVCIRT.DLL", "MSVCP60.DLL", "MFC42.DLL",
                                  "rlmfc.dll", "grphmfc.dll", "e2mfc.dll", "sndmfc.dll"};

static void lower(char *s)
{
    for (; *s; s++)
        if (*s >= 'A' && *s <= 'Z')
            *s = (char)(*s - 'A' + 'a');
}

Module *host_find_module(const char *name)
{
    for (int i = 0; i < g_nmods; i++)
        if (strcasecmp(g_mods[i]->name, name) == 0)
            return g_mods[i];
    return NULL;
}

Module *host_module_by_base(uint32_t base)
{
    for (int i = 0; i < g_nmods; i++)
        if (g_mods[i]->base == base)
            return g_mods[i];
    return NULL;
}

const char *host_module_at(uint32_t va)
{
    static char buf[96];
    for (int i = 0; i < g_nmods; i++)
        if (va >= g_mods[i]->base && va - g_mods[i]->base < g_mods[i]->size) {
            snprintf(buf, sizeof buf, "%s+0x%x", g_mods[i]->name, va - g_mods[i]->base);
            return buf;
        }
    snprintf(buf, sizeof buf, "0x%x", va);
    return buf;
}

static int export_cmp(const void *a, const void *b)
{
    return strcmp(((const Export *)a)->name, ((const Export *)b)->name);
}

uint32_t host_export(Module *m, const char *name)
{
    Export key = {(char *)name, 0};
    Export *e = bsearch(&key, m->exports, m->nexports, sizeof *m->exports, export_cmp);
    return e ? e->va : 0;
}

uint32_t host_export_ord(Module *m, uint32_t ord)
{
    return ord >= m->ord_base && ord - m->ord_base < m->nords ? m->ords[ord - m->ord_base] : 0;
}

/* PE accessors on the file image */
static uint32_t f32(Module *m, uint32_t off)
{
    uint32_t v = 0;
    if (off + 4 <= m->file_size)
        memcpy(&v, m->file + off, 4);
    return v;
}
static uint16_t f16(Module *m, uint32_t off)
{
    uint16_t v = 0;
    if (off + 2 <= m->file_size)
        memcpy(&v, m->file + off, 2);
    return v;
}

/* Emu.load_module: map the headers and sections at the base, relocate, read the exports. */
static Module *load_module(const char *path, const char *name, uint32_t base)
{
    Module *m = calloc(1, sizeof *m);
    snprintf(m->path, sizeof m->path, "%s", path);
    snprintf(m->name, sizeof m->name, "%s", name);
    lower(m->name);
    int fd = open(path, O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0)
        host_fatal("cannot open %s: %s", path, strerror(errno));
    m->file_size = (uint32_t)st.st_size;
    m->file = malloc(m->file_size);
    if (read(fd, m->file, m->file_size) != (ssize_t)m->file_size)
        host_fatal("cannot read %s", path);
    close(fd);
    uint32_t nt = f32(m, 0x3c), opt = nt + 24;
    if (f32(m, nt) != 0x4550 || f16(m, opt) != 0x10b)
        host_fatal("%s is not a PE32 image", path);
    uint32_t nsec = f16(m, nt + 6), optsize = f16(m, nt + 20);
    m->pref = f32(m, opt + 28);
    m->size = (f32(m, opt + 56) + PAGE - 1) & ~(PAGE - 1);
    if (!base) {
        base = m->pref;
        for (size_t i = 0; i < sizeof MODULE_BASES / sizeof *MODULE_BASES; i++)
            if (strcmp(MODULE_BASES[i].name, m->name) == 0)
                base = MODULE_BASES[i].base;
    }
    m->base = base;
    uint32_t ep = f32(m, opt + 16);
    m->entry = ep ? base + ep : 0;
    map_region(base, m->size);
    uint32_t hdrs = f32(m, opt + 60);
    memcpy(gptr(base), m->file, hdrs < m->file_size ? hdrs : m->file_size);
    for (uint32_t s = 0; s < nsec; s++) {
        uint32_t sh = opt + optsize + 40 * s;
        uint32_t va = f32(m, sh + 12), rawsz = f32(m, sh + 16), rawp = f32(m, sh + 20);
        if (rawp >= m->file_size)
            continue;
        if (rawsz > m->file_size - rawp)
            rawsz = m->file_size - rawp;
        memcpy(gptr(base + va), m->file + rawp, rawsz);
    }
    uint32_t ndir = f32(m, opt + 92);
#define DIR(i) (ndir > (i) ? f32(m, opt + 96 + 8 * (i)) : 0)
#define DIRSZ(i) (ndir > (i) ? f32(m, opt + 100 + 8 * (i)) : 0)
    uint32_t delta = base - m->pref;
    if (delta && DIR(5)) {                     /* IMAGE_DIRECTORY_ENTRY_BASERELOC: HIGHLOW only */
        uint32_t p = base + DIR(5), end = p + DIRSZ(5);
        while (p + 8 <= end) {
            uint32_t page = r32(p), bsz = r32(p + 4);
            if (bsz < 8)
                break;
            for (uint32_t k = 8; k + 2 <= bsz; k += 2) {
                uint16_t e = r16(p + k);
                if ((e >> 12) == 3) {
                    uint32_t a = base + page + (e & 0xfff);
                    w32(a, r32(a) + delta);
                }
            }
            p += bsz;
        }
    }
    if (DIR(0)) {                              /* exports (pefile: entries with address 0 are skipped) */
        uint32_t ed = base + DIR(0);
        m->ord_base = r32(ed + 16);
        m->nords = r32(ed + 20);
        uint32_t nnames = r32(ed + 24), funcs = base + r32(ed + 28), names = base + r32(ed + 32);
        uint32_t nords = base + r32(ed + 36);
        m->ords = calloc(m->nords ? m->nords : 1, sizeof *m->ords);
        for (uint32_t i = 0; i < m->nords; i++) {
            uint32_t rva = r32(funcs + 4 * i);
            m->ords[i] = rva ? base + rva : 0;
        }
        m->exports = calloc(nnames ? nnames : 1, sizeof *m->exports);
        for (uint32_t i = 0; i < nnames; i++) {
            uint16_t oi = r16(nords + 2 * i);
            if (oi >= m->nords || !m->ords[oi])
                continue;
            m->exports[m->nexports].name = strdup((const char *)gptr(base + r32(names + 4 * i)));
            m->exports[m->nexports].va = m->ords[oi];
            m->nexports++;
        }
        qsort(m->exports, m->nexports, sizeof *m->exports, export_cmp);
    }
#undef DIR
#undef DIRSZ
    g_mods[g_nmods++] = m;
    return m;
}

/* ---------------------------------------------------------------- stubs */
typedef struct {
    char *dll, *name;
    const HleDef *def;
    uint64_t calls;
} Stub;
static Stub g_stubs[STUB_SIZE / STUB_STRIDE];
static uint32_t g_nstubs;

/* the runtime's own handlers: hle_fast.c kinds (emu/native.py HLE_FAST_KINDS, all of them; the D3D8, DINPUT and
 * DSOUND ones need the objects registered, which hle_d3d8.c, hle_dinput.c and hle_dsound.c do) and heap.c */
static const struct { const char *dll, *name; uint32_t kind; } FAST[] = {
    {"KERNEL32.DLL", "QueryPerformanceCounter", 1}, {"KERNEL32.DLL", "TlsGetValue", 11},
    {"KERNEL32.DLL", "TlsSetValue", 12}, {"KERNEL32.DLL", "GetLastError", 13}, {"KERNEL32.DLL", "SetLastError", 14},
    {"KERNEL32.DLL", "InitializeCriticalSection", 15}, {"KERNEL32.DLL", "EnterCriticalSection", 15},
    {"KERNEL32.DLL", "LeaveCriticalSection", 15}, {"KERNEL32.DLL", "DeleteCriticalSection", 15},
    {"D3D8.DLL", "IDirect3DDevice8::SetRenderState", 2}, {"D3D8.DLL", "IDirect3DDevice8::SetTextureStageState", 3},
    {"D3D8.DLL", "IDirect3DDevice8::SetTexture", 4}, {"D3D8.DLL", "IDirect3DDevice8::SetStreamSource", 5},
    {"D3D8.DLL", "IDirect3DDevice8::SetIndices", 6}, {"D3D8.DLL", "IDirect3DVertexBuffer8::Lock", 7},
    {"D3D8.DLL", "IDirect3DIndexBuffer8::Lock", 8}, {"D3D8.DLL", "IDirect3DVertexBuffer8::Unlock", 9},
    {"D3D8.DLL", "IDirect3DIndexBuffer8::Unlock", 9}, {"D3D8.DLL", "IDirect3DDevice8::DrawIndexedPrimitive", 10},
    {"D3D8.DLL", "IDirect3DDevice8::SetVertexShader", 16}, {"D3D8.DLL", "IDirect3DDevice8::SetTransform", 17},
    {"D3D8.DLL", "IDirect3DDevice8::SetViewport", 18}, {"D3D8.DLL", "IDirect3DDevice8::Clear", 19},
    {"DINPUT.DLL", "IDirectInputDevice7A::Acquire", 20}, {"DINPUT.DLL", "IDirectInputDevice7A::GetDeviceState", 21},
    {"DINPUT.DLL", "IDirectInputDevice7A::GetDeviceData", 22},
    {"DSOUND.DLL", "IDirectSoundBuffer::Lock", 23}, {"DSOUND.DLL", "IDirectSoundBuffer::Unlock", 24},
    {"DSOUND.DLL", "IDirectSoundBuffer::GetCurrentPosition", 25}, {"DSOUND.DLL", "IDirectSoundBuffer::SetVolume", 26},
};

/* the kinds that read the wall clock in hle_fast.c (QueryPerformanceCounter, the DSOUND cursors): under --sim-fps the
 * host's handlers serve them from the virtual clock */
static int sim_clock_kind(uint32_t kind) { return host_clock_sim_fps() && (kind == 1 || (kind >= 23 && kind <= 25)); }

void host_fast_obj(uint32_t addr, uint32_t kind, uint32_t ptr, uint32_t fmt) { L.fast_obj(addr, kind, ptr, fmt); }
void host_fast_tex_sent(uint32_t addr, uint32_t ver, uint32_t sent, int has_sent) { L.fast_tex(addr, ver, sent, has_sent); }
int host_fast_get(int which, uint32_t a, uint32_t b, uint32_t *v, uint32_t *v2) { return L.fast_get(which, a, b, v, v2); }
int host_fast_set(int which, uint32_t a, uint32_t b, uint32_t v) { return L.fast_set(which, a, b, v, 0, 1); }
void host_fast_capture(int mode, void *sink, void *r, void *err, int reset_sent)
{
    L.fast_capture(mode, sink, r, err, reset_sent);
}
int host_fast_blob(int which, uint32_t a, int op, void *p) { return L.fast_blob(which, a, op, p); }
int host_ds_new(uint32_t this) { return L.ds_new(this); }
void host_ds_cfg(int slot, uint32_t ptr, uint32_t size, int has_wfx, uint32_t avg, uint32_t align)
{
    L.ds_cfg(slot, ptr, size, has_wfx, avg, align);
}
double host_ds_field(int slot, int field, int set, double v) { return L.ds_field(slot, field, set, v); }
void host_ds_gains(int slot, double gl, double gr, int downmix) { L.ds_gains(slot, gl, gr, downmix); }
void host_ds_mixer(void *m, void *write, void *pos, void *gain) { L.ds_mixer(m, write, pos, gain); }
int host_di_new(uint32_t this, uint32_t kind) { return L.di_new(this, kind); }
void host_di_cfg(int slot, uint32_t coop, int has_fmt, uint32_t fmt_size, uint32_t bufsize, uint32_t nobj,
                 const uint32_t *obj)
{
    L.di_cfg(slot, coop, has_fmt, fmt_size, bufsize, nobj, obj);
}
int64_t host_di_field(int slot, int field, int set, int64_t v) { return L.di_field(slot, field, set, v); }
uint32_t host_di_queue(int slot, int op, uint32_t i, uint32_t *ev) { return L.di_queue(slot, op, i, ev); }
uint8_t *host_di_keys(void) { return L.di_keys(); }
static uint32_t g_heap_idx[2] = {UINT32_MAX, UINT32_MAX};

static const HleDef *find_def(const char *dll, const char *name)
{
    static const HleDef *const tables[] = {hle_kernel32, hle_files, hle_user32, hle_winsys, hle_advapi32, hle_d3d8, hle_dshow, hle_dsound, hle_dinput};
    for (size_t t = 0; t < sizeof tables / sizeof *tables; t++)
        for (const HleDef *d = tables[t]; d->name; d++)
            if (strcmp(d->name, name) == 0 && strcmp(d->dll, dll) == 0)
                return d;
    return NULL;
}

/* Emu.stub_for: the stub of (DLL, name), made on first use (hlt bytes, as the emulator's). */
uint32_t host_stub_for(const char *dll, const char *name)
{
    char up[64];
    snprintf(up, sizeof up, "%s", dll);
    for (char *s = up; *s; s++)
        if (*s >= 'a' && *s <= 'z')
            *s = (char)(*s - 'a' + 'A');
    for (uint32_t i = 0; i < g_nstubs; i++)
        if (strcmp(g_stubs[i].dll, up) == 0 && strcmp(g_stubs[i].name, name) == 0)
            return STUB_BASE + i * STUB_STRIDE;
    uint32_t idx = g_nstubs;
    if ((idx + 1) * STUB_STRIDE > STUB_SIZE)
        host_fatal("stub region full");
    g_stubs[idx].dll = strdup(up);
    g_stubs[idx].name = strdup(name);
    g_stubs[idx].def = find_def(up, name);
    g_nstubs++;
    uint32_t va = STUB_BASE + idx * STUB_STRIDE;
    memset(gptr(va), 0xf4, STUB_STRIDE);
    for (size_t k = 0; k < sizeof FAST / sizeof *FAST; k++)
        if (strcmp(FAST[k].name, name) == 0 && strcmp(FAST[k].dll, up) == 0 && !sim_clock_kind(FAST[k].kind))
            L.fast_bind(idx, FAST[k].kind);
    if (strcmp(up, "KERNEL32.DLL") == 0) {
        if (strcmp(name, "HeapAlloc") == 0 || strcmp(name, "HeapFree") == 0) {
            g_heap_idx[name[4] == 'F'] = idx;
            L.heap_direct_bind(g_heap_idx[0], g_heap_idx[1]);
        }
    }
    return va;
}

/* Emu.resolve_imports: each import slot gets the export of a loaded module, else a stub; MFC42's delay imports are
 * bound now as well (the stubs of __delayLoadHelper then never run). */
static void resolve_imports(Module *m)
{
    uint32_t nt = f32(m, 0x3c), opt = nt + 24, ndir = f32(m, opt + 92);
    uint32_t base = m->base;
    for (int pass = 0; pass < 2; pass++) {
        uint32_t di = pass ? 13 : 1;
        uint32_t dir = ndir > di ? f32(m, opt + 96 + 8 * di) : 0;
        if (!dir)
            continue;
        for (uint32_t d = base + dir;; d += pass ? 32 : 20) {
            uint32_t name_rva, ilt, iat, va_mode = 0;
            if (!pass) {
                ilt = r32(d);
                name_rva = r32(d + 12);
                iat = r32(d + 16);
                if (!name_rva && !iat)
                    break;
                if (!ilt)
                    ilt = iat;
            } else {
                uint32_t attrs = r32(d);
                name_rva = r32(d + 4);
                iat = r32(d + 12);
                ilt = r32(d + 16);
                if (!name_rva)
                    break;
                va_mode = !(attrs & 1);        /* the old (VC6) format holds VAs at the preferred base */
                if (va_mode) {
                    name_rva -= m->pref;
                    iat -= m->pref;
                    ilt -= m->pref;
                }
            }
            const char *dll = (const char *)gptr(base + name_rva);
            Module *target = host_find_module(dll);
            for (uint32_t i = 0;; i++) {
                uint32_t t = r32(base + ilt + 4 * i);
                if (!t)
                    break;
                char label[512];
                uint32_t va = 0;
                if (t & 0x80000000u) {
                    snprintf(label, sizeof label, "#%u", t & 0xffff);
                    if (target)
                        va = host_export_ord(target, t & 0xffff);
                } else {
                    if (va_mode)
                        t -= m->pref;
                    snprintf(label, sizeof label, "%s", (const char *)gptr(base + t + 2));
                    if (target)
                        va = host_export(target, label);
                }
                if (!va)
                    va = host_stub_for(dll, label);
                w32(base + iat + 4 * i, va);
            }
        }
    }
}

/* ---------------------------------------------------------------- the API log */
static FILE *g_trace;
#define RING 16
static char g_ring[RING][256];
static unsigned g_ring_n;

static void log_line(const char *s)
{
    snprintf(g_ring[g_ring_n++ % RING], sizeof g_ring[0], "%s", s);
    if (g_trace)
        fprintf(g_trace, "%s\n", s);
}

void host_note(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    log_line(buf);
}

static void format_call(char *buf, size_t cap, const Stub *s, const uint32_t *a, int n)
{
    size_t k = (size_t)snprintf(buf, cap, "%s!%s(", s->dll, s->name);
    for (int i = 0; i < n && k < cap; i++)
        k += (size_t)snprintf(buf + k, cap - k, "%s0x%x", i ? ", " : "", a[i]);
    if (k < cap)
        snprintf(buf + k, cap - k, ")");
}

static void report_tail(void)
{
    unsigned n = g_ring_n < RING ? g_ring_n : RING;
    fprintf(stderr, "last API calls:\n");
    for (unsigned i = g_ring_n - n; i < g_ring_n; i++)
        fprintf(stderr, "   %s\n", g_ring[i % RING]);
}

void host_fatal(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    fflush(stdout);
    fprintf(stderr, "mphost: fatal: %s\n", buf);
    if (g_cpu.mem) {
        fprintf(stderr, "at: eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x\n",
                g_cpu.r[EAX], g_cpu.r[EBX], g_cpu.r[ECX], g_cpu.r[EDX], g_cpu.r[ESI], g_cpu.r[EDI], g_cpu.r[EBP],
                g_cpu.r[ESP]);
        /* words on the guest stack that point into a module: return addresses, most likely */
        fprintf(stderr, "stack words into modules:");
        int shown = 0;
        for (uint32_t sp = g_cpu.r[ESP]; sp < STACK_TOP && sp - g_cpu.r[ESP] < 0x400 && shown < 12; sp += 4) {
            uint32_t v = r32(sp);
            for (int i = 0; i < g_nmods; i++)
                if (v - g_mods[i]->base < g_mods[i]->size) {
                    fprintf(stderr, " [%x]%s", sp - g_cpu.r[ESP], host_module_at(v));
                    shown++;
                    break;
                }
        }
        fprintf(stderr, "\n");
        report_tail();
    }
    if (g_trace) {
        fprintf(g_trace, "# fatal: %s\n", buf);
        fclose(g_trace);
    }
    exit(3);
}

/* ---------------------------------------------------------------- HLE dispatch */
enum { HLE_DECLINE, HLE_DONE, HLE_NEVER, HLE_HALT };

static int host_hle(CPU *c, uint32_t idx)
{
    if (idx >= g_nstubs)
        host_fatal("call to stub %u, which was never handed out", idx);
    Stub *s = &g_stubs[idx];
    uint32_t sp = c->r[ESP], ret = r32(sp);
    if (idx < 2)
        host_fatal("lifted code called the host's own stub %u (%s) from %s", idx, s->name, host_module_at(ret));
    const HleDef *d = s->def;
    if (!d) {
        uint32_t a[6];
        for (int i = 0; i < 6; i++)
            a[i] = r32(sp + 4 + 4 * (uint32_t)i);
        host_fatal("unimplemented import %s!%s (called from %s; first words 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x)", s->dll,
                   s->name, host_module_at(ret), a[0], a[1], a[2], a[3], a[4], a[5]);
    }
    uint32_t a[16];
    for (int i = 0; i < d->nargs; i++)
        a[i] = r32(sp + 4 + 4 * (uint32_t)i);
    char line[1024];
    format_call(line, sizeof line, s, a, d->nargs);
    if (d->flags & HLE_CORO) {
        size_t k = strlen(line);
        snprintf(line + k, sizeof line - k, " [coroutine]");
        log_line(line);
    }
    s->calls++;
    uint32_t res = d->fn(c, a);
    if (!(d->flags & HLE_CORO)) {
        size_t k = strlen(line);
        snprintf(line + k, sizeof line - k, " -> 0x%x", res);
        log_line(line);
    }
    c->r[EAX] = res;
    c->r[ESP] = sp + 4 + ((d->flags & CDECL) ? 0 : 4u * d->nargs);
    return HLE_DONE;
}

/* The host CPU's call_guest: lifted code reached code that is not lifted. A stub (a call through lift_call, or a
 * declined direct call) is served as a call: the bridge's return address is pushed for the handler to pop. */
static void host_call_guest(CPU *c, uint32_t addr)
{
    if (addr - STUB_BASE < STUB_SIZE && (addr - STUB_BASE) % STUB_STRIDE == 0) {
        c->r[ESP] -= 4;
        w32(c->r[ESP], STUB_BASE);
        host_hle(c, (addr - STUB_BASE) / STUB_STRIDE);
        return;
    }
    host_fatal("guest code at %s is not lifted (reached from lifted code; [esp] %s)", host_module_at(addr),
               host_module_at(r32(c->r[ESP])));
}

/* emu/mpemu.py Emu.call: the dead SEH records below the stack the call starts from are unlinked, the arguments and
 * the host's return address pushed, and ESP is put back afterwards; the other registers are as the callee left them. */
static uint32_t call_top(uint32_t va, int nargs, const uint32_t *args)
{
    CPU *c = &g_cpu;
    uint32_t base_sp = c->r[ESP];
    uint32_t head = r32(TEB);
    while (head != 0xFFFFFFFFu && head < base_sp) {
        uint32_t nxt = (head >= STACK_TOP - STACK_SIZE && head < STACK_TOP) ? r32(head) : 0xFFFFFFFFu;
        head = (nxt == 0xFFFFFFFFu || (nxt >= STACK_TOP - STACK_SIZE && nxt < STACK_TOP && nxt > head)) ? nxt
                                                                                                         : 0xFFFFFFFFu;
    }
    w32(TEB, head);
    for (int i = nargs - 1; i >= 0; i--) {
        c->r[ESP] -= 4;
        w32(c->r[ESP], args[i]);
    }
    L.host_call(c, va, STUB_BASE);
    c->r[ESP] = base_sp;
    return c->r[EAX];
}

uint32_t host_guest_call(CPU *c, uint32_t va, int nargs, const uint32_t *args)
{
    uint32_t saved[8];
    memcpy(saved, c->r, sizeof saved);
    c->r[ESP] -= 0x100;                 /* below the HLE frame, as Emu._advance runs a coroutine's guest call */
    for (int i = nargs - 1; i >= 0; i--) {
        c->r[ESP] -= 4;
        w32(c->r[ESP], args[i]);
    }
    L.host_call(c, va, STUB_BASE);
    uint32_t eax = c->r[EAX];
    memcpy(c->r, saved, sizeof saved);
    return eax;
}

/* ---------------------------------------------------------------- paths (emu/mpemu.py data_dir, host_read_path) */
static char g_data_dir[1024];
char g_cwd[1024] = "C:\\MaxPayne";

const char *host_data_dir(void)
{
    if (!g_data_dir[0]) {
        const char *env = getenv("MAXPAYNE_DATA"), *home = getenv("HOME");
        if (env && *env)
            snprintf(g_data_dir, sizeof g_data_dir, "%s", env);
        else
            snprintf(g_data_dir, sizeof g_data_dir, "%s/Library/Application Support/Max Payne Recomp", home ? home : ".");
    }
    return g_data_dir;
}

void host_mkdirs(const char *path)
{
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    mkdir(tmp, 0755);
}

/* Join parts under root, matching existing names case-insensitively. */
static void ci_join(char *out, size_t cap, const char *root, char **parts, int n)
{
    snprintf(out, cap, "%s", root);
    for (int i = 0; i < n; i++) {
        const char *hit = parts[i];
        char found[256];
        DIR *dir = opendir(out);
        if (dir) {
            struct dirent *de;
            while ((de = readdir(dir)))
                if (strcasecmp(de->d_name, parts[i]) == 0) {
                    snprintf(found, sizeof found, "%s", de->d_name);
                    hit = found;
                    break;
                }
            closedir(dir);
        }
        size_t k = strlen(out);
        snprintf(out + k, cap - k, "/%s", hit);
    }
}

/* _locate: 1 and the parts below C:\MaxPayne for the game folder, 0 and [drive] + parts elsewhere. parts point into
 * buf. */
void host_guest_abs(const char *guest, char *buf, size_t cap)
{
    char g[1024];
    snprintf(g, sizeof g, "%s", guest);
    for (char *p = g; *p; p++)
        if (*p == '/')
            *p = '\\';
    if (strlen(g) > 1 && g[1] == ':')
        snprintf(buf, cap, "%s", g);
    else if (g[0] == '\\')                     /* rooted: on the current drive (C:) */
        snprintf(buf, cap, "C:%s", g);
    else {
        char base[1024];
        snprintf(base, sizeof base, "%s", g_cwd);
        size_t k = strlen(base);
        while (k && base[k - 1] == '\\')
            base[--k] = 0;
        snprintf(buf, cap, "%s\\%s", base, g);
    }
}

static int locate(const char *guest, char *buf, size_t cap, char **parts, int *n)
{
    host_guest_abs(guest, buf, cap);
    char drive = (strlen(buf) > 1 && buf[1] == ':') ? buf[0] : 'C';
    if (drive >= 'a' && drive <= 'z')
        drive = (char)(drive - 'a' + 'A');
    static char drv[2];
    drv[0] = drive;
    *n = 0;
    parts[(*n)++] = drv;
    char *save = NULL;
    for (char *tok = strtok_r(buf + 2, "\\", &save); tok; tok = strtok_r(NULL, "\\", &save)) {
        if (!strcmp(tok, "."))
            continue;
        if (!strcmp(tok, "..")) {
            if (*n > 1)
                (*n)--;
            continue;
        }
        if (*n < 64)
            parts[(*n)++] = tok;
    }
    if (drive == 'C' && *n > 1 && strcasecmp(parts[1], "maxpayne") == 0) {
        memmove(parts, parts + 2, (size_t)(*n - 2) * sizeof *parts);
        *n -= 2;
        return 1;
    }
    return 0;
}

void host_read_path(const char *guest, char *out, size_t cap)
{
    char buf[1024], *parts[66];
    int n;
    if (!locate(guest, buf, sizeof buf, parts, &n)) {
        host_mkdirs(host_data_dir());
        ci_join(out, cap, host_data_dir(), parts, n);
        return;
    }
    if (n) {
        char ov[1024];
        snprintf(ov, sizeof ov, "%s/game", host_data_dir());
        host_mkdirs(ov);
        ci_join(out, cap, ov, parts, n);
        struct stat st;
        if (stat(out, &st) == 0)
            return;
    }
    ci_join(out, cap, g_game_dir, parts, n);
}

/* _find_entries' folders for a guest directory: in the game folder the game's and the overlay's, elsewhere the
 * per-user data's (both the same). */
void host_dir_paths(const char *guest_dir, char *game, char *ov, size_t cap)
{
    char buf[1024], *parts[66], root[1024];
    int n;
    if (!locate(guest_dir, buf, sizeof buf, parts, &n)) {
        host_mkdirs(host_data_dir());
        ci_join(game, cap, host_data_dir(), parts, n);
        snprintf(ov, cap, "%s", game);
        return;
    }
    ci_join(game, cap, g_game_dir, parts, n);
    snprintf(root, sizeof root, "%s/game", host_data_dir());
    host_mkdirs(root);
    ci_join(ov, cap, root, parts, n);
}

void host_write_path(const char *guest, char *out, size_t cap)
{
    char buf[1024], *parts[66], root[1024];
    int n;
    if (locate(guest, buf, sizeof buf, parts, &n))
        snprintf(root, sizeof root, "%s/game", host_data_dir());
    else
        snprintf(root, sizeof root, "%s", host_data_dir());
    host_mkdirs(root);
    ci_join(out, cap, root, parts, n);
    char dir[1024];
    snprintf(dir, sizeof dir, "%s", out);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = 0;
        host_mkdirs(dir);
    }
}

/* ---------------------------------------------------------------- LoadLibraryA, GetProcAddress */
uint32_t host_load_library(CPU *c, const char *raw)
{
    const char *bs = raw;
    for (const char *p = raw; *p; p++)
        if (*p == '\\' || *p == '/')
            bs = p + 1;
    char n[256];
    snprintf(n, sizeof n, "%s", bs);
    lower(n);
    Module *m = host_find_module(n);
    if (m)
        return m->base;
    for (size_t i = 0; i < sizeof FAKE_DLLS / sizeof *FAKE_DLLS; i++)
        if (strcmp(FAKE_DLLS[i].name, n) == 0)
            return FAKE_DLLS[i].base;
    char hp[1024];
    host_read_path(raw, hp, sizeof hp);
    struct stat st;
    size_t len = strlen(n);
    if (len > 4 && strcmp(n + len - 4, ".dll") == 0 && stat(hp, &st) == 0 && S_ISREG(st.st_mode)) {
        m = load_module(hp, n, 0);
        resolve_imports(m);
        printf("[LoadLibraryA] loaded %s at 0x%x (called from %s)\n", m->name, m->base, host_module_at(r32(c->r[ESP])));
        if (m->entry) {
            uint32_t args[3] = {m->base, 1, 0};
            if (!host_guest_call(c, m->entry, 3, args)) {
                printf("[LoadLibraryA] DllMain of %s returned FALSE\n", m->name);
                host_set_last_error(1114);
                return 0;
            }
        }
        return m->base;
    }
    printf("[LoadLibraryA] '%s' is not available -> NULL\n", n);
    host_set_last_error(126);
    return 0;
}

uint32_t host_get_proc_address(uint32_t h, uint32_t name)
{
    Module *m = host_module_by_base(h);
    if (name < 0x10000)
        return m ? host_export_ord(m, name) : 0;
    char n[512];
    host_cstr(name, n, sizeof n);
    if (m)
        return host_export(m, n);
    for (size_t i = 0; i < sizeof FAKE_DLLS / sizeof *FAKE_DLLS; i++)
        if (FAKE_DLLS[i].base == h)
            return host_stub_for(FAKE_DLLS[i].upper, n);
    /* resolve_name(KERNEL32, n): the KERNEL32 stub if there is a handler for it */
    for (int i = 0; i < g_nmods; i++) {
        uint32_t va = host_export(g_mods[i], n);
        if (va)
            return va;
    }
    if (find_def("KERNEL32.DLL", n))
        return host_stub_for("KERNEL32.DLL", n);
    return 0;
}

/* ---------------------------------------------------------------- the CRT helpers (emu/native.py _bind_crt) */
static const struct { const char *name; uint32_t rva; const char *hex; } CRT_CHECK[] = {
#include "crt_check.inc"
};

static void bind_crt(void)
{
    Module *m = host_find_module("msvcrt.dll");
    if (!m)
        return;
    size_t n = sizeof CRT_CHECK / sizeof *CRT_CHECK;
    for (size_t i = 0; i < n; i++) {
        if (i && strcmp(CRT_CHECK[i - 1].name, CRT_CHECK[i].name) == 0)
            continue;                          /* the first range of each helper starts its group */
        const char *name = CRT_CHECK[i].name;
        uint32_t va = host_export(m, name);
        int ok = va != 0;
        for (size_t j = i; ok && j < n && strcmp(CRT_CHECK[j].name, name) == 0; j++) {
            const char *h = CRT_CHECK[j].hex;
            for (uint32_t k = 0; ok && h[2 * k]; k++) {
                unsigned b;
                sscanf(h + 2 * k, "%2x", &b);
                ok = gptr(m->base + CRT_CHECK[j].rva)[k] == b;
            }
        }
        if (ok && L.crt_bind(name, va, m->base) < 0)
            printf("native CRT: %s is not in this library\n", name);
    }
}

/* ---------------------------------------------------------------- set-up and run */
static void setup_memory(void)
{
    void *mem = mmap(NULL, 1ull << 32, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if (mem == MAP_FAILED)
        host_fatal("cannot reserve the 4 GB guest space: %s", strerror(errno));
    g_cpu.mem = mem;
    map_region(STACK_TOP - STACK_SIZE, STACK_SIZE);
    map_region(TEB, PAGE * 2);
    map_region(SCRATCH, PAGE);
    map_region(STUB_BASE, STUB_SIZE);
    map_region(HEAP_BASE, HEAP_SIZE);
    map_region(GDT, PAGE);
    host_stub_for("<host>", "exit");           /* stub 0: the return to the host */
    host_stub_for("<host>", "resume");         /* stub 1: unused here (the emulator's coroutine resume) */
    w32(TEB + 0x00, 0xFFFFFFFFu);              /* SEH chain end */
    w32(TEB + 0x04, STACK_TOP);
    w32(TEB + 0x08, STACK_TOP - STACK_SIZE);
    w32(TEB + 0x18, TEB);
    w32(TEB + 0x20, 0x100);                    /* pid */
    w32(TEB + 0x24, 0x104);                    /* tid */
    w32(TEB + 0x30, PEB);
    w32(PEB + 0xA4, 5);                        /* OSMajorVersion */
    w32(PEB + 0xA8, 1);                        /* OSMinorVersion */
    memcpy(gptr(PEB + 0xAC), &(uint16_t){2600}, 2);   /* OSBuildNumber */
    w32(PEB + 0xB0, 2);                        /* OSPlatformId (NT) */
    g_cpu.fs_base = TEB;
    g_cpu.call_guest = host_call_guest;
    g_cpu.cw = 0x027F;                         /* 53-bit precision, round to nearest */
    g_cpu.tag = 0xff;
    g_cpu.r[ESP] = STACK_TOP - 0x1000;
}


/* ---------------------------------------------------------------- the frame loop (run_init.py --real-entry) */
static unsigned g_frame_limit;
static int g_frame_no = -1;                    /* the main-loop frame running now */
static const char *g_cap_dir;                   /* --capture DIR --capture-frames 5,40 */
static unsigned g_cap_frames[64], g_ncap_frames;
static FILE *g_cap_file;
static char g_cap_path[1200];

static const char *const MPD3_NAMES[10] = {"?", "TEXTURE", "RENDERSTATE", "TSS", "SETTEXTURE", "VIEWPORT", "CLEAR",
                                           "DRAW", "PRESENT", "TRANSFORM"};

/* d3dcap.Writer to a file: u32 type, u32 length, payload */
static int file_sink(void *ctx, uint32_t type, const void *p, uint32_t len)
{
    uint32_t hd[2] = {type, len};
    fwrite(hd, 4, 2, (FILE *)ctx);
    if (len)
        fwrite(p, 1, len, (FILE *)ctx);
    return 0;
}

static void capture_stop(void)
{
    if (!g_cap_file)
        return;
    const uint32_t *n = host_d3d_stop_capture();
    fclose(g_cap_file);
    g_cap_file = NULL;
    printf("  captured -> %s (", g_cap_path);
    for (int t = 1, first = 1; t < 10; t++)
        if (n[t]) {
            printf("%s%s %u", first ? "" : ", ", MPD3_NAMES[t], n[t]);
            first = 0;
        }
    printf(")\n");
}

/* --input "F:ACTION,..." (run_init.py): host input before frame F, where ACTION is key=DIK (hex) / keyup=DIK /
 * move=dx;dy / wheel=dz / button=n / buttonup=n / focus=0|1; "@F" counts from the anchor: the frame in which the
 * game first opens a file whose name contains --anchor TEXT (case-insensitive); --anchor-frames N stops the run N
 * frames after it */
typedef struct { int frame, anchored; char act[32]; } InputAct;
static InputAct *g_input;
static int g_ninput;
static const char *g_anchor;
static int g_anchor_frame = -1, g_anchor_stop = -1, g_opened_anchor;

static void parse_input(char *spec)
{
    for (char *t = strtok(spec, ","); t; t = strtok(NULL, ",")) {
        char *c = strchr(t, ':');
        if (!c || c - t < 1 || strlen(c + 1) >= sizeof g_input->act) {
            fprintf(stderr, "mphost: bad --input item %s\n", t);
            exit(2);
        }
        g_input = realloc(g_input, (size_t)(g_ninput + 1) * sizeof *g_input);
        InputAct *a = &g_input[g_ninput++];
        a->anchored = *t == '@';
        a->frame = atoi(t + a->anchored);
        snprintf(a->act, sizeof a->act, "%s", c + 1);
    }
}

static void apply_input(const char *act)
{
    char k[16];
    const char *eq = strchr(act, '=');
    size_t n = eq ? (size_t)(eq - act) : strlen(act);
    if (!eq || n >= sizeof k)
        host_fatal("bad --input action %s", act);
    memcpy(k, act, n);
    k[n] = 0;
    const char *v = eq + 1;
    if (!strcmp(k, "key"))
        host_key((uint32_t)strtoul(v, NULL, 16), 1);
    else if (!strcmp(k, "keyup"))
        host_key((uint32_t)strtoul(v, NULL, 16), 0);
    else if (!strcmp(k, "move")) {
        const char *sc = strchr(v, ';');
        if (!sc)
            host_fatal("bad --input action %s", act);
        host_mouse_move(atoi(v), atoi(sc + 1));
    } else if (!strcmp(k, "wheel"))
        host_mouse_wheel(atoi(v));
    else if (!strcmp(k, "button"))
        host_mouse_button((uint32_t)atoi(v), 1);
    else if (!strcmp(k, "buttonup"))
        host_mouse_button((uint32_t)atoi(v), 0);
    else if (!strcmp(k, "focus"))
        host_set_app_active(!strcmp(v, "1"));
    else
        host_fatal("bad --input action %s", act);
}

void host_note_open(const char *guest)
{
    if (!g_anchor || g_anchor_frame >= 0 || g_opened_anchor)
        return;
    for (const char *p = guest; *p; p++)
        if (!strncasecmp(p, g_anchor, strlen(g_anchor))) {
            g_opened_anchor = 1;
            return;
        }
}

/* after_frame(i): the frame's capture ends; the anchor, once its file was opened in this frame. 1: stop the run */
static int after_frame(int i)
{
    capture_stop();
    if (g_opened_anchor && g_anchor_frame < 0) {
        g_anchor_frame = i;
        printf("  anchor '%s' opened in frame %d\n", g_anchor, i);
    }
    if (g_anchor_frame >= 0 && g_anchor_stop >= 0 && i - g_anchor_frame >= g_anchor_stop) {
        printf("  stopping %d frames after the anchor\n", i - g_anchor_frame);
        return 1;
    }
    return 0;
}

/* before_frame(i): the frame's capture starts (MPD3 header: version 1, the back buffer's size) */
static void before_frame(int i)
{
    for (int pass = 0; pass < 2; pass++)       /* run_init.py: the frame's own actions, then the anchored ones */
        for (int k = 0; k < g_ninput; k++) {
            InputAct *a = &g_input[k];
            if (a->anchored != pass || (pass ? g_anchor_frame < 0 || i - g_anchor_frame != a->frame : a->frame != i))
                continue;
            apply_input(a->act);
            printf("  input before frame %d: %s\n", i, a->act);
        }
    for (unsigned k = 0; k < g_ncap_frames && !host_live_on(); k++)
        if (g_cap_frames[k] == (unsigned)i) {
            snprintf(g_cap_path, sizeof g_cap_path, "%s/frame_%03d.mpd3", g_cap_dir, i);
            if (!(g_cap_file = fopen(g_cap_path, "wb")))
                host_fatal("cannot write %s", g_cap_path);
            uint32_t w, h;
            host_d3d_backbuffer(&w, &h);
            uint32_t hd[3] = {1, w, h};
            fwrite("MPD3", 1, 4, g_cap_file);
            fwrite(hd, 4, 3, g_cap_file);
            host_d3d_start_capture(file_sink, g_cap_file);
        }
}

/* ---------------------------------------------------------------- Hor+ (M7) */
/* P_Camera::validate (e2mfc 0x10014d60, at 0x10114d60 here) caches tan(fov/2) at camera +0x200 and the vertical tangent
 * at +0x204 = +0x200 * h / w of the camera's viewport, which is in the 640x480 virtual space: a 4:3 view on any back
 * buffer. The projection, the frustum culling and the engine's own vertex transform all read the two tangents. For
 * Hor+ the host widens +0x200 by k = (W / H) / (4 / 3) of the back buffer after validate (lifted with
 * build.py --exit-hook 0x10114d60), keeping the vertical FOV. --view stretch leaves the 4:3 view stretched. */
#define CAMERA_VALIDATE 0x10114d60u
static int g_view_stretch;
/* The exe's portal code computes its own 4:3 tangent from the camera's FOV and viewport (fld [cam + 0x242] ... fptan):
 * 0x679e80 for the window that portals are clipped against (0x8b4608), 0x67a9f0 for the sub-viewport of a room seen
 * through a portal (P_Camera::setSubViewport). With the camera widened and these not, rooms behind doors were clipped
 * 1.2x off at 16:10. Both derive the vertical tangent from tan(fov/2) and the viewport, as validate does, so the host
 * widens only the horizontal one by the same k, once the vertical one is computed: at 0x67a148 it is the float at
 * [ebp - 0x10], at 0x67aec8 st(1) (st(0) is the vertical one). Lifted with build.py --insn-hook 0x67a148,0x67aec8. */
#define PORTAL_CLIP_TAN 0x0067a148u
#define PORTAL_SUBVIEW_TAN 0x0067aec8u

/* The HUD's corners (M7). The HUD is made of e2mfc P_Sprite and P_Text objects, each owned by an exe wrapper
 * (MaxPayne_HUDSprite, made by 0x4c99f0, owns an X_AdvSprite; MaxPayne_HUDSpriteWindow, by 0x4ca2a0; MaxPayne_HUDText,
 * by 0x4ca920; the object at wrapper +0x1e). Their
 * executeAlways (P_Sprite 0x10108040, P_Text 0x10104280) map the object's position in 640x480 virtual pixels (sprite
 * +0x188, text +0x16c: x) into camera space with the 4:3 tangent, so under Hor+ the HUD keeps its 4:3 layout in the
 * middle of the screen. For an object of a HUD wrapper, the host moves x by 320 (k - 1) virtual pixels towards the
 * nearer screen edge on entry to executeAlways and puts it back on exit: a corner element sits at the real edge at
 * its own size. Objects in the middle third stay. A sprite that reaches a 4:3 edge (its extent from the reference
 * point +0x160 and width +0x144: the sniper scope's black paddings) is widened to the screen edge instead, as moving
 * it would open a gap beside the scope. The weapon inventory (the row of slots at the top) is one centred group and
 * stays where it is. Hooks: build.py --entry-hook 0x4c99f0,0x4ca2a0,0x4ca920,
 * 0x10104280,0x10108040
 * --exit-hook 0x10104280,0x10108040. MPHOST_HUD_LOG=1 prints each HUD object the first time it is moved.
 * The HUD's fade layer (MaxPayne_HUDFadeLayer, made by 0x4ab8f0: the fades from and to a colour, the flashes) is a
 * P_Sprite at layer +0xad covering the 640x480 virtual space (x +0x188 = 0, width +0x144 = 640), so under Hor+ it
 * stopped at the 4:3 edges. On entry to executeAlways the host widens it to the real screen edges (x - 320 (k - 1),
 * width 640 k) and puts both back on exit. Hook: build.py --entry-hook 0x4ab8f0. */
#define HUD_SPRITE_NEW 0x004c99f0u
#define HUD_WINDOW_NEW 0x004ca2a0u
#define HUD_TEXT_NEW 0x004ca920u
#define HUD_FADE_NEW 0x004ab8f0u
#define SPRITE_EXEC 0x10108040u
#define TEXT_EXEC 0x10104280u
static uint32_t g_hud_wrap[256];                /* HUD wrappers seen (sprite wrappers tagged with bit 0) */
static uint8_t g_hud_keep[256];                 /* 1: the weapon inventory's, kept in its 4:3 layout */
static unsigned g_hud_nwrap;
static uint32_t g_hud_fade[16];                 /* fade layers seen */
static unsigned g_hud_nfade;
static float g_hud_shift;                       /* 320 (k - 1), refreshed every frame; 0: off */
static struct { uint32_t addr, bits; } g_hud_pend[16];   /* moved x fields, restored on exit (or at the frame) */
static unsigned g_hud_npend;

static void hud_restore_all(void)
{
    while (g_hud_npend) {
        g_hud_npend--;
        memcpy(gptr(g_hud_pend[g_hud_npend].addr), &g_hud_pend[g_hud_npend].bits, 4);
    }
}

static void hud_frame(void)
{
    hud_restore_all();                          /* an executeAlways left without its ret (an unwind) */
    uint32_t w, h;
    host_d3d_backbuffer(&w, &h);
    g_hud_shift = g_view_stretch || !w || !h ? 0.0f : (float)(320.0 * ((double)w * 3.0 / ((double)h * 4.0) - 1.0));
}

static void hud_register(uint32_t wrapper, int sprite, int keep)
{
    uint32_t tagged = wrapper | (uint32_t)sprite;
    unsigned i = 0;
    while (i < g_hud_nwrap && g_hud_wrap[i] != tagged)
        i++;
    if (i == g_hud_nwrap) {
        if (g_hud_nwrap == sizeof g_hud_wrap / sizeof g_hud_wrap[0])
            return;
        g_hud_wrap[g_hud_nwrap++] = tagged;
    }
    g_hud_keep[i] = (uint8_t)keep;
}

/* a sprite window made by the weapon inventory's loader: its caller returns to the frame (0x4b2e5f), the slot number
 * (0x4b3024) or the slot weapon (0x4bdbac) call. On entry to 0x4ca2a0 the constructor 0x4ca1c0's return address is
 * at esp + 48 (0x4ca2a0's own, its 6 arguments, 0x4ca1c0's 5 pushes) */
static int hud_inventory_window(void)
{
    uint32_t ret = r32(g_cpu.r[ESP] + 48u);
    return ret == 0x004b2e64u || ret == 0x004b3029u || ret == 0x004bdbb1u;
}

static void hud_register_fade(uint32_t layer)
{
    for (unsigned i = 0; i < g_hud_nfade; i++)
        if (g_hud_fade[i] == layer)
            return;
    if (g_hud_nfade < sizeof g_hud_fade / sizeof g_hud_fade[0])
        g_hud_fade[g_hud_nfade++] = layer;
}

static void hud_pend(uint32_t addr, float v)
{
    memcpy(&g_hud_pend[g_hud_npend].bits, gptr(addr), 4);
    g_hud_pend[g_hud_npend++].addr = addr;
    memcpy(gptr(addr), &v, 4);
}

static void hud_enter(uint32_t obj, int sprite)
{
    if (g_hud_shift == 0.0f || g_hud_npend + 2u > sizeof g_hud_pend / sizeof g_hud_pend[0])
        return;
    if (sprite)
        for (unsigned j = 0; j < g_hud_nfade; j++)
            if (r32(g_hud_fade[j] + 0xadu) == obj) {
                float x, w;
                memcpy(&x, gptr(obj + 0x188u), 4);
                memcpy(&w, gptr(obj + 0x144u), 4);
                hud_pend(obj + 0x188u, x - g_hud_shift);
                hud_pend(obj + 0x144u, w + 2.0f * g_hud_shift);
                return;
            }
    unsigned i = 0;
    for (; i < g_hud_nwrap; i++)
        if ((g_hud_wrap[i] & 1u) == (uint32_t)sprite && r32((g_hud_wrap[i] & ~1u) + 0x1eu) == obj)
            break;
    if (i == g_hud_nwrap || g_hud_keep[i])
        return;
    uint32_t addr = obj + (sprite ? 0x188u : 0x16cu);
    float x, rot = 0.0f;
    memcpy(&x, gptr(addr), 4);
    float nx = x < 640.0f / 3.0f ? x - g_hud_shift : x > 1280.0f / 3.0f ? x + g_hud_shift : x;
    if (sprite)
        memcpy(&rot, gptr(obj + 0x14cu), 4);
    if (sprite && rot == 0.0f) {                /* a sprite reaching a 4:3 edge is widened to the screen edge */
        uint32_t ref = r32(obj + 0x160u);
        float w, frac = ref <= 2u ? 0.0f : ref == 3u || ref >= 7u ? 0.5f : 1.0f;
        memcpy(&w, gptr(obj + 0x144u), 4);
        float l = x - frac * w;
        int el = l <= 0.5f, er = l + w >= 639.5f;
        if (el || er) {
            float nw = w + (float)(el + er) * g_hud_shift;
            nx = (el ? l - g_hud_shift : l) + frac * nw;
            hud_pend(obj + 0x144u, nw);
        }
    }
    static uint32_t logged[256];
    static unsigned nlogged;
    static int log = -1;
    if (log < 0)
        log = getenv("MPHOST_HUD_LOG") != NULL;
    if (log) {
        unsigned j = 0;
        while (j < nlogged && logged[j] != obj)
            j++;
        if (j == nlogged && nlogged < 256) {
            logged[nlogged++] = obj;
            float y;
            memcpy(&y, gptr(addr + 4u), 4);
            printf("HUD %s 0x%08x at (%.1f, %.1f) -> x %.1f\n", sprite ? "sprite" : "text", obj, x, y, nx);
        }
    }
    if (nx != x)
        hud_pend(addr, nx);
}

static void on_exit_hook(CPU *c, uint32_t va)
{
    if (va == SPRITE_EXEC || va == TEXT_EXEC) {
        hud_restore_all();
        return;
    }
    if (va != CAMERA_VALIDATE || !(*gptr(c->r[ECX] + 0xe0u) & 0x40u))
        return;                                 /* validate recomputes only with dirty bit 0x40 set (rarely) */
    uint32_t w, h;
    host_d3d_backbuffer(&w, &h);                /* the device's back buffer now, so a mode change is followed */
    if (!w || !h || w * 3u == h * 4u)
        return;
    float t;
    memcpy(&t, gptr(c->r[ECX] + 0x200u), 4);
    t *= (float)((double)w * 3.0 / ((double)h * 4.0));
    memcpy(gptr(c->r[ECX] + 0x200u), &t, 4);
}

/* the portal code's horizontal tangent, widened as validate's: [ebp - 0x10] at PORTAL_CLIP_TAN, st(1) at
 * PORTAL_SUBVIEW_TAN */
static void on_insn_hook(CPU *c, uint32_t va)
{
    if (va != PORTAL_CLIP_TAN && va != PORTAL_SUBVIEW_TAN)
        return;
    uint32_t w, h;
    host_d3d_backbuffer(&w, &h);
    if (!w || !h || w * 3u == h * 4u)
        return;
    float k = (float)((double)w * 3.0 / ((double)h * 4.0));
    if (va == PORTAL_CLIP_TAN) {
        float t;
        memcpy(&t, gptr(c->r[EBP] - 0x10u), 4);
        t *= k;
        memcpy(gptr(c->r[EBP] - 0x10u), &t, 4);
    } else {
        c->st[(c->top + 1u) & 7u] *= (double)k;
    }
}

/* MPH_RAND_LOG=path (M7): MSVCRT's rand state (the thread's tiddata +0x14, from _getptd) at each frame's start, "frame
 * state" per line; tools/m7/rand_steps.py turns it into rand() calls per frame */
#define MSVCRT_GETPTD 0x78003857u
static void rand_log(int frame)
{
    static FILE *f;
    static uint32_t ptd;
    static int off;
    if (off)
        return;
    if (!f) {
        const char *p = getenv("MPH_RAND_LOG");
        if (!p || !(f = fopen(p, "w"))) {
            off = 1;
            return;
        }
    }
    if (!ptd)
        ptd = host_guest_call(&g_cpu, MSVCRT_GETPTD, 0, NULL);
    uint32_t v;
    memcpy(&v, gptr(ptd + 0x14), 4);
    fprintf(f, "%d %u\n", frame, v);
    fflush(f);
}

/* the frame function's entry: as run_init.py --real-entry, the first entry starts the loop (the live view's
 * renderer), each later one ends the frame before it; WM_QUIT is posted when the window was closed or frame N-1 of
 * --frames N is entered (that frame still runs, its pump sees WM_QUIT, then ExitInstance and ExitProcess) */
static void on_frame(void)
{
    static int i = -1, quit, stop;
    host_clock_frame();
    rand_log(i);
    if (i < 0) {
        host_live_start();
        printf("running %u frames of the main loop\n", g_frame_limit ? g_frame_limit : 1000000000u);
    } else
        stop = after_frame(i);
    hud_frame();
    g_frame_no = ++i;
    if (!quit && (stop || host_live_pump_frame() || (g_frame_limit && (unsigned)i >= g_frame_limit - 1))) {
        quit = 1;
        printf("frame %d is the last: WM_QUIT posted\n", i);
        host_post_quit(0);
    }
    before_frame(i);
}

/* MPH_AI_LOG=path (M7, a probe): with a library lifted with --entry-hook 0x4ffef0, every evaluation of an AI condition
 * (MaxPayne_ArtificialPlayerInput slot 2: this, the condition type, its float operand; type 0x1a is "rand() / 32767
 * <= operand") as "frame this type operand" */
#define AI_CONDITION 0x004ffef0u
static void ai_condition_log(void)
{
    static FILE *f;
    static int off;
    if (off)
        return;
    if (!f) {
        const char *p = getenv("MPH_AI_LOG");
        if (!p || !(f = fopen(p, "w"))) {
            off = 1;
            return;
        }
    }
    uint32_t sp = g_cpu.r[ESP], type;
    float x;
    memcpy(&type, gptr(sp + 0xc), 4);
    memcpy(&x, gptr(sp + 0x10), 4);
    fprintf(f, "%d %08x %x %g\n", g_frame_no, g_cpu.r[ECX], type, x);
}

/* MPH_RAND_CALLERS=path (M7, a probe): with a library lifted with --entry-hook 0x7801f40b, each rand() call's return
 * address as "frame address" */
#define MSVCRT_RAND 0x7801f40bu
static void rand_caller_log(void)
{
    static FILE *f;
    static int off;
    if (off)
        return;
    if (!f) {
        const char *p = getenv("MPH_RAND_CALLERS");
        if (!p || !(f = fopen(p, "w"))) {
            off = 1;
            return;
        }
    }
    uint32_t ret;
    memcpy(&ret, gptr(g_cpu.r[ESP]), 4);
    fprintf(f, "%d %08x\n", g_frame_no, ret);
}

/* entry hooks: the frame function (0x40c020), the HUD wrappers' and the fade layer's constructors and the HUD objects'
 * executeAlways */
static void on_entry_hook(uint32_t va)
{
    switch (va) {
    case HUD_SPRITE_NEW: hud_register(g_cpu.r[ECX], 1, 0); break;
    case HUD_WINDOW_NEW: hud_register(g_cpu.r[ECX], 1, hud_inventory_window()); break;
    case HUD_TEXT_NEW: hud_register(g_cpu.r[ECX], 0, 0); break;
    case HUD_FADE_NEW: hud_register_fade(g_cpu.r[ECX]); break;
    case SPRITE_EXEC: hud_enter(g_cpu.r[ECX], 1); break;
    case TEXT_EXEC: hud_enter(g_cpu.r[ECX], 0); break;
    case AI_CONDITION: ai_condition_log(); break;
    case MSVCRT_RAND: rand_caller_log(); break;
    default: on_frame(); break;
    }
}

static int stub_cmp(const void *a, const void *b)
{
    uint64_t x = g_stubs[*(const uint32_t *)a].calls, y = g_stubs[*(const uint32_t *)b].calls;
    return x < y ? 1 : x > y ? -1 : 0;
}

void host_exit(uint32_t code)
{
    capture_stop();                             /* the last frame's (never ended by a frame entry) */
    host_live_close();
    host_audio_close();
    fflush(stdout);
    uint64_t seh[4], cc[2];
    L.seh_stats(seh);
    L.call_cache_stats(cc);
    printf("process exit code %u: no fault\n", code);
    printf("HLE calls: %llu direct (%llu served in C by the runtime: heap, SEH, hle_fast); SEH raises %llu, unwinds "
           "%llu, handled %llu; call cache %llu hits, %llu misses\n",
           (unsigned long long)L.hle_direct_calls(), (unsigned long long)L.fast_total(), (unsigned long long)seh[0],
           (unsigned long long)seh[1], (unsigned long long)seh[2], (unsigned long long)cc[0], (unsigned long long)cc[1]);
    uint32_t order[STUB_SIZE / STUB_STRIDE], k = 0;
    for (uint32_t i = 2; i < g_nstubs; i++)
        if (g_stubs[i].calls)
            order[k++] = i;
    qsort(order, k, sizeof *order, stub_cmp);
    printf("host handlers called: %u; top:\n", k);
    for (uint32_t i = 0; i < k && i < 20; i++)
        printf("   %10llu  %s!%s\n", (unsigned long long)g_stubs[order[i]].calls, g_stubs[order[i]].dll,
               g_stubs[order[i]].name);
    if (g_trace)
        fclose(g_trace);
    fflush(stdout);
    exit((int)code);
}

static void usage(void)
{
    fprintf(stderr, "usage: mphost GAME_DIR --lib LIB [--trace FILE] [--data-dir DIR] [--frames N] [--window]\n"
                    "       [--intro skip|play] [--game-mode fullscreen|windowed] [--capture DIR --capture-frames N,...]\n"
                    "       [--audio device|null|off] [--audio-wav FILE] [--input F:ACTION,...] [--anchor TEXT]\n"
                    "       [--anchor-frames N] [--view hor+|stretch] [--resolution WxH] [--sim-fps N]\n"
                    "       [--pad modern|classic] [--pad-look N] [--pad-invert]\n"
                    "  --window: show the game in a Metal window and play it with keyboard and mouse (until the window\n"
                    "  is closed or --frames N); --capture: write those frames as MPD3 streams (frame_NNN.mpd3); --audio: sound\n"
                    "  on the default device (the default with --window), mixed silently in real time, or none; --input: scripted\n"
                    "  input as run_init.py's (key=DIK hex, keyup=, move=dx;dy, wheel=, button=n, buttonup=, focus=0|1;\n"
                    "  \"@F\" frames count from the frame that first opens a file named like --anchor TEXT); --view: the 3D\n"
                    "  view on a wide back buffer, widened (Hor+, the default) or the game's 4:3 view stretched;\n"
                    "  --resolution: the display mode to run at, one the adapter offers (saved in the data dir's Video\n"
                    "  Settings, as the launcher's); --sim-fps: a virtual clock that advances 1/N s per frame (deterministic\n"
                    "  runs at a chosen frame rate; sound off unless --audio is given, then cursors follow the mixer); --pad: the game\n"
                    "  controller's layout (host/gamepad.c), --pad-look its aim speed (px/s, default 1008), --pad-invert\n"
                    "  vertical look inverted\n");
    exit(2);
}

char g_cmdline[256] = "\"C:\\MaxPayne\\MaxPayne.exe\" -nodialog";

int main(int argc, char **argv)
{
    const char *libpath = NULL, *trace = NULL, *dump_dir = NULL;
    int window = 0, intro = -1, audio = -3;
    const char *game_mode = NULL, *audio_wav = NULL;
    uint32_t res_w = 0, res_h = 0;
    int pad_modern = 1, pad_invert = 0;
    double pad_look = 0;
    if (argc < 2)
        usage();
    g_game_dir = argv[1];
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--lib") && i + 1 < argc)
            libpath = argv[++i];
        else if (!strcmp(argv[i], "--trace") && i + 1 < argc)
            trace = argv[++i];
        else if (!strcmp(argv[i], "--data-dir") && i + 1 < argc)
            snprintf(g_data_dir, sizeof g_data_dir, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--window"))
            window = 1;
        else if (!strcmp(argv[i], "--game-mode") && i + 1 < argc) {
            game_mode = argv[++i];
            if (strcmp(game_mode, "windowed") && strcmp(game_mode, "fullscreen"))
                usage();
        } else if (!strcmp(argv[i], "--intro") && i + 1 < argc) {
            const char *v = argv[++i];
            if (strcmp(v, "skip") && strcmp(v, "play"))
                usage();
            intro = !strcmp(v, "skip");
        } else if (!strcmp(argv[i], "--audio") && i + 1 < argc) {
            const char *v = argv[++i];
            audio = !strcmp(v, "device") ? 1 : !strcmp(v, "null") ? 0 : !strcmp(v, "off") ? -2 : -4;
            if (audio == -4)
                usage();
        } else if (!strcmp(argv[i], "--audio-wav") && i + 1 < argc)
            audio_wav = argv[++i];
        else if (!strcmp(argv[i], "--capture") && i + 1 < argc)
            g_cap_dir = argv[++i];
        else if (!strcmp(argv[i], "--capture-frames") && i + 1 < argc) {
            for (char *t = strtok(argv[++i], ","); t && g_ncap_frames < 64; t = strtok(NULL, ","))
                g_cap_frames[g_ncap_frames++] = (unsigned)atoi(t);
        } else if (!strcmp(argv[i], "--frames") && i + 1 < argc)
            g_frame_limit = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--input") && i + 1 < argc)
            parse_input(argv[++i]);
        else if (!strcmp(argv[i], "--anchor") && i + 1 < argc)
            g_anchor = argv[++i];
        else if (!strcmp(argv[i], "--anchor-frames") && i + 1 < argc)
            g_anchor_stop = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--view") && i + 1 < argc) {
            const char *v = argv[++i];
            if (strcmp(v, "hor+") && strcmp(v, "stretch"))
                usage();
            g_view_stretch = !strcmp(v, "stretch");
        } else if (!strcmp(argv[i], "--resolution") && i + 1 < argc) {
            const char *v = argv[++i];
            char x, end;
            if (sscanf(v, "%u%c%u%c", &res_w, &x, &res_h, &end) != 3 || (x != 'x' && x != 'X')) {
                fprintf(stderr, "mphost: --resolution takes WxH, e.g. 1280x720\n");
                return 2;
            }
            uint32_t w, h;
            unsigned m = 0;
            while (host_d3d_mode(m, &w, &h) && (w != res_w || h != res_h))
                m++;
            if (!host_d3d_mode(m, &w, &h)) {
                fprintf(stderr, "mphost: --resolution %ux%u is not offered; modes:", res_w, res_h);
                for (m = 0; host_d3d_mode(m, &w, &h); m++)
                    fprintf(stderr, "%s %ux%u", m ? "," : "", w, h);
                fprintf(stderr, "\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--sim-fps") && i + 1 < argc) {
            int n = atoi(argv[++i]);
            if (n < 1 || n > 1000)
                usage();
            host_clock_sim((unsigned)n);
        } else if (!strcmp(argv[i], "--pad") && i + 1 < argc) {
            const char *v = argv[++i];
            if (strcmp(v, "modern") && strcmp(v, "classic"))
                usage();
            pad_modern = !strcmp(v, "modern");
        } else if (!strcmp(argv[i], "--pad-look") && i + 1 < argc) {
            if ((pad_look = atof(argv[++i])) <= 0)
                usage();
        } else if (!strcmp(argv[i], "--pad-invert"))
            pad_invert = 1;
        else if (!strcmp(argv[i], "--dump-images") && i + 1 < argc)
            dump_dir = argv[++i];
        else
            usage();
    }
    if (!libpath)
        usage();
    gamepad_config(pad_modern, pad_look, pad_invert);
    g_intro_skip = intro >= 0 ? intro : !window;    /* run_init.py: the intro plays with a window, else is skipped */
    if (audio == -3)                            /* run_init.py: sound with a window, none otherwise; a WAV needs a mixer */
        audio = window && !host_clock_sim_fps() ? 1 : -2;
    if (audio_wav && audio == -2)
        audio = 0;
    host_audio_set(audio, audio_wav);
    if (g_ncap_frames) {
        if (!g_cap_dir)
            g_cap_dir = "captures";
        host_mkdirs(g_cap_dir);
    }
    char real[1024];
    if (!realpath(g_game_dir, real)) {
        fprintf(stderr, "mphost: no game folder %s\n", g_game_dir);
        return 2;
    }
    g_game_dir = strdup(real);
    if (trace && !(g_trace = fopen(trace, "w"))) {
        fprintf(stderr, "mphost: cannot write %s\n", trace);
        return 2;
    }
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    host_registry_init();
    if (res_w)
        host_registry_set_resolution(res_w, res_h);
    host_settings_load();                       /* launcher.configure: the host settings, the game mode remembered */
    if (game_mode)
        host_settings_set_game_mode(game_mode);
    host_settings_save();
    if (!strcmp(host_settings_game_mode(), "windowed"))
        strcat(g_cmdline, " -window");
    lib_open(libpath);
    if (window)
        host_live_open();
    printf("lifted library: %s (%u functions)\n", libpath, *L.table_len);
    L.heap_reset(HEAP_BASE, (uint64_t)HEAP_BASE + HEAP_SIZE);
    L.fast_reset();
    L.fast_capture(0, NULL, NULL, NULL, 0);    /* CAP_NONE: no capture (d3d8.Recorder._fast_capture) */
    L.set_bridge_stop(STUB_BASE);
    L.host_init((void *)host_call_guest, (void *)host_hle, STUB_BASE, STUB_STRIDE);
    setup_memory();

    /* mpemu.boot(with_exe=True): the DLLs, then the exe, then the imports of all of them */
    for (size_t i = 0; i < sizeof GAME_DLLS / sizeof *GAME_DLLS; i++) {
        char path[1024];
        ci_join(path, sizeof path, g_game_dir, (char *[]){(char *)GAME_DLLS[i]}, 1);
        load_module(path, GAME_DLLS[i], 0);
    }
    {
        char path[1024];
        ci_join(path, sizeof path, g_game_dir, (char *[]){"MaxPayne.exe"}, 1);
        load_module(path, "MaxPayne.exe", 0);
    }
    for (int i = 0; i < g_nmods; i++)
        resolve_imports(g_mods[i]);
    bind_crt();
    printf("loaded:");
    for (int i = 0; i < g_nmods; i++)
        printf(" %s@0x%x", g_mods[i]->name, g_mods[i]->base);
    printf("\nimports bound to stubs: %u\n", g_nstubs - 2);
    if (dump_dir) {                            /* --dump-images DIR: each linked image, for a comparison with mpemu.boot */
        for (int i = 0; i < g_nmods; i++) {
            char p[1200];
            snprintf(p, sizeof p, "%s/%s.bin", dump_dir, g_mods[i]->name);
            FILE *f = fopen(p, "wb");
            if (!f)
                host_fatal("cannot write %s", p);
            fwrite(gptr(g_mods[i]->base), 1, g_mods[i]->size, f);
            fclose(f);
        }
        printf("images written to %s\n", dump_dir);
        return 0;
    }
    for (int i = 0; i < g_nmods; i++)
        if (g_mods[i]->entry && !lifted(g_mods[i]->entry))
            host_fatal("the entry point of %s (%s) is not in the library", g_mods[i]->name,
                       host_module_at(g_mods[i]->entry));

    /* run_dll_mains */
    for (size_t i = 0; i < sizeof GAME_DLLS / sizeof *GAME_DLLS; i++) {
        Module *m = host_find_module(GAME_DLLS[i]);
        if (!m->entry)
            continue;
        uint32_t args[3] = {m->base, 1, 0};
        uint32_t r = call_top(m->entry, 3, args);
        printf("DllMain %-12s -> eax=%u\n", m->name, r);
    }

    /* native.Native.enable_fast: RaiseException and RtlUnwind in C when MSVCRT's frame handlers are lifted */
    Module *crt = host_find_module("msvcrt.dll");
    if (lifted(host_export(crt, "__CxxFrameHandler")) && lifted(host_export(crt, "_except_handler3")) &&
        lifted(host_export(crt, "_CxxThrowException"))) {
        uint32_t ir = (host_stub_for("KERNEL32.DLL", "RaiseException") - STUB_BASE) / STUB_STRIDE;
        uint32_t iu = (host_stub_for("KERNEL32.DLL", "RtlUnwind") - STUB_BASE) / STUB_STRIDE;
        L.seh_bind(ir, iu, host_stub_for("NTDLL.DLL", "ExceptionNestedHandler"), TEB, STACK_TOP - STACK_SIZE,
                   STACK_TOP);
    } else {
        printf("SEH: MSVCRT's frame handlers are not lifted; RaiseException will stop the host\n");
    }
    L.set_entry_hook((void *)on_entry_hook);
    if (!g_view_stretch && (!L.set_exit_hook || !lifted(CAMERA_VALIDATE)))
        printf("view: the library has no exit hook for P_Camera::validate; the 4:3 view is stretched (Hor+ needs "
               "build.py --exit-hook 0x%08x)\n", CAMERA_VALIDATE);
    else if (!g_view_stretch)
        L.set_exit_hook((void *)on_exit_hook);
    if (!g_view_stretch && (!L.set_insn_hook || !lifted(0x679e80u) || !lifted(0x67a9f0u)))
        printf("view: the library has no instruction hooks for the portal code; rooms seen through doors are clipped "
               "to the 4:3 view (build.py --insn-hook 0x%08x,0x%08x)\n", PORTAL_CLIP_TAN, PORTAL_SUBVIEW_TAN);
    else if (!g_view_stretch)
        L.set_insn_hook((void *)on_insn_hook);

    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("start-up %.2fs; calling the exe entry point %s\n",
           (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9,
           host_module_at(host_find_module("maxpayne.exe")->entry));
    fflush(stdout);
    call_top(host_find_module("maxpayne.exe")->entry, 0, NULL);
    host_fatal("the exe entry point returned (eax=0x%x) without calling ExitProcess", g_cpu.r[EAX]);
}
