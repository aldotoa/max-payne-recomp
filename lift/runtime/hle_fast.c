/* HLE handlers in C (H50, H60): calls from lifted code to KERNEL32 QueryPerformanceCounter, the TLS and last-error calls
 * and the critical sections, and to the D3D8 methods the game calls a thousand times a frame, served in runtime.c hle_direct without the Python callback. Each does what its Python
 * handler in emu/mpemu.py or emu/d3d8.py does: the same result, the same guest writes, the same stack pop (stdcall), and
 * the same device state and capture records. Anything else is declined (return 0) and the call goes to Python.
 *
 * The D3D8 state the handlers read and write lives here once the fast path starts (emu/native.py HleFast): render
 * states, texture-stage states, bound textures, stream sources, indices and the vertex shader. emu/d3d8.py's Recorder
 * reads and writes it through views, so the Python handlers see the same state. Objects (textures, vertex and index
 * buffers) are registered by Python when it creates them (guest pointer, format, the lock version of a texture and the
 * version last sent to the renderer). Statistics for the Recorder's report are counted here and merged by Python.
 * The transforms and the viewport (H60) live here too, as the guest wrote them (raw bits).
 *
 * KERNEL32 (H60): the last error and the TLS slots live here once the fast path starts; emu/mpemu.py Emu.last_error and
 * Emu.tls read and write them, so the Python handlers (which set the last error in many places) see the same values.
 *
 * DINPUT (H61): IDirectInputDevice7A Acquire, GetDeviceState and GetDeviceData. Each device's run state (acquired, lost,
 * the relative motion, the event queue and its overflow flag) and the shared key, button and sequence state live here
 * once the fast path starts; emu/dinput.py's Device and Input read and write them through views, so the host side
 * (key presses, mouse motion, focus loss) and the other Python handlers see the same state. The configuration
 * (cooperative level, data format, buffer size) stays in Python, which copies it here when it changes. With a
 * Python poll hook (dinput on_poll) the polls are declined.
 *
 * DSOUND (H62): IDirectSoundBuffer Lock, Unlock, GetCurrentPosition and SetVolume. Each secondary and primary buffer's
 * run state (volume, playing, looping, the clock cursor and its start time, the unlock counters, the mixer voice) lives
 * here once the fast path starts; emu/dsound.py's buffer dicts are views of it (_FastBuf). The layout (guest pointer,
 * size, format) and the voice's pan/3D gains stay computed in Python, which copies them here when they change. The
 * mixer is audio/mpaudio.c: Python registers the mixer and three of its functions (lift_hle_fast_ds_mixer), and the
 * handlers call them as dsound.py does. A buffer with a voice and no mixer registered is declined.
 *
 * Capture: with no capture, the handlers only track state. With a live capture whose sink is registered here
 * (lift_hle_fast_sink: mpr_submit of render/libmprender.dylib, or a test callback), they build the MPD3 records
 * (emu/d3dcap.py) and submit them. With any other capture (a file), the calls that emit records are declined. */
#include <mach/mach_time.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpu.h"
#include "runtime.h"

enum {                       /* handler kinds (emu/native.py HLE_FAST_KINDS) */
    K_NONE, K_QPC, K_RS, K_TSS, K_SETTEX, K_STREAM, K_INDICES, K_VBLOCK, K_IBLOCK, K_UNLOCK, K_DIP,
    K_TLSGET, K_TLSSET, K_GETLE, K_SETLE, K_CRITSEC, K_SETVS, K_SETXF, K_SETVP, K_CLEAR,
    K_DIACQ, K_DISTATE, K_DIDATA, K_DSLOCK, K_DSUNLOCK, K_DSPOS, K_DSVOL, K_COUNT
};
enum { O_OTHER, O_TEX, O_VB, O_IB };                      /* object kinds */
enum { CAP_NONE, CAP_SINK, CAP_PYTHON };                  /* capture modes */
enum { REC_RENDERSTATE = 2, REC_TSS = 3, REC_SETTEXTURE = 4, REC_VIEWPORT = 5, REC_CLEAR = 6, REC_DRAW = 7,
       REC_TRANSFORM = 9 };
enum { H_RS = 1, H_TSS, H_SETTEX, H_DRAW, H_FVF, H_XF, H_CLEAR, H_DI };   /* histogram kinds (lift_hle_fast_hist) */
/* H_DI's a: what dinput.py's Recorder.polls counts (emu/native.py HleFast.merge) */
enum { DIP_ACQ, DIP_STATE, DIP_DATA, DIP_DATA_ERR, DIP_STATE_ERR };

#define FAST_STUBS 65536u
static uint8_t g_kind[FAST_STUBS];
static uint64_t g_count[FAST_STUBS];        /* per stub index, cleared by lift_hle_fast_counts */
static uint64_t g_total;                     /* every call served since lift_hle_fast_reset */
static int g_on;

/* ---- device state */
static uint32_t g_rs[256], g_tss[8][32], g_bound[8], g_stream_vb[16], g_stream_stride[16];
static uint8_t g_rs_set[256], g_tss_set[8][32], g_bound_set[8], g_stream_set[16];
static uint32_t g_ib, g_ib_base, g_vs;
#define XF_STATES 512u                          /* D3DTS_WORLDMATRIX(255) is 511 */
static uint32_t g_xf[XF_STATES][16];            /* D3DMATRIX bits, row-major */
static uint8_t g_xf_set[XF_STATES];
static uint32_t g_vp[6];                        /* D3DVIEWPORT8: x, y, w, h, f32 minz, f32 maxz */
static uint8_t g_vp_set;

/* ---- KERNEL32 state */
#define TLS_SLOTS 1088u                         /* TLS_MINIMUM_AVAILABLE + the 1024 expansion slots */
static uint32_t g_last_error, g_tls[TLS_SLOTS];
static uint8_t g_tls_set[TLS_SLOTS];

/* ---- DINPUT state */
#define DI_DEVS 16u
#define DI_NOEFFECT 1u                          /* also DI_BUFFEROVERFLOW */
#define DIERR_INVALIDPARAM 0x80070057u
#define DIERR_NOTACQUIRED 0x8007000Cu
#define DIERR_INPUTLOST 0x8007001Eu
#define DIERR_NOTBUFFERED 0x80040207u
enum { DIO_KEY, DIO_BUTTON, DIO_AXIS };         /* object kinds of a data format */
typedef struct {
    uint32_t this, kind;                        /* the guest object; 0 keyboard, 1 mouse */
    uint8_t acquired, lost, overflow, has_fmt;
    uint32_t coop, fmt_size, bufsize;
    uint32_t nobj, *obj;                        /* (kind, instance, offset) triples, in Python's dict order */
    int64_t d[3];                               /* dx, dy, dz: Python ints (clamped to int32 when read) */
    uint32_t (*q)[4], qcap, qhead, qlen;        /* the event queue: (offset, data, stamp, sequence), a ring */
} DiDev;
static DiDev g_di[DI_DEVS];
static uint32_t g_di_n;
static struct { uint8_t keys[256], buttons[8]; } g_di_in;   /* dinput.py Input.keys, Input.buttons */
static uint32_t g_di_seq;
static uint8_t g_di_pypoll;                     /* a Python poll hook is set: polls go to Python */

static void di_clear(void)
{
    for (uint32_t i = 0; i < g_di_n; i++) {
        free(g_di[i].obj);
        free(g_di[i].q);
    }
    memset(g_di, 0, sizeof g_di);
    g_di_n = 0;
    memset(&g_di_in, 0, sizeof g_di_in);
    g_di_seq = 0;
    g_di_pypoll = 0;
}

static DiDev *di_find(uint32_t this)
{
    for (uint32_t i = 0; i < g_di_n; i++)
        if (g_di[i].this == this)
            return &g_di[i];
    return NULL;
}

static uint32_t *di_at(DiDev *d, uint32_t i) { return d->q[(d->qhead + i) & (d->qcap - 1)]; }

static void di_popleft(DiDev *d)
{
    d->qhead = (d->qhead + 1) & (d->qcap - 1);
    d->qlen--;
}

static uint32_t obj_hash(uint32_t a);

/* ---- DSOUND state */
#define DSERR_INVALIDPARAM 0x80070057u
#define DSBLOCK_FROMWRITECURSOR 0x1u
#define DSBLOCK_ENTIREBUFFER 0x2u
#define WRITE_LEAD_FRAMES 768u                  /* dsound.py WRITE_LEAD_FRAMES */
typedef struct {
    uint32_t this, ptr, size, avg, align;       /* avg, align: of the format (has_wfx) */
    uint8_t has_wfx, playing, looping;
    int32_t voice, volume;                      /* voice -1: none */
    uint32_t pos;                               /* the clock cursor (no voice), or where Stop left it */
    double started;                             /* time.perf_counter() at Play / SetCurrentPosition */
    uint64_t unlocks, written;
    double gl, gr;                              /* the voice's pan or 3D gains (dsound.py update_voice) */
    int downmix;
} DsBuf;
static DsBuf *g_ds;
static uint32_t g_ds_n, g_ds_cap;
static uint32_t *g_ds_idx, g_ds_idx_mask;       /* this -> slot + 1 (open addressing) */
typedef void (*mpa_write_fn)(void *m, int id, uint32_t offset, const void *data, uint32_t len);
typedef uint32_t (*mpa_pos_fn)(void *m, int id, int *playing);
typedef void (*mpa_gain_fn)(void *m, int id, float l, float r, int downmix);
static void *g_mpa;
static mpa_write_fn g_mpa_write;
static mpa_pos_fn g_mpa_pos;
static mpa_gain_fn g_mpa_gain;

static void ds_clear(void)
{
    free(g_ds);
    free(g_ds_idx);
    g_ds = NULL;
    g_ds_idx = NULL;
    g_ds_n = g_ds_cap = g_ds_idx_mask = 0;
    g_mpa = NULL;
}

static DsBuf *ds_find(uint32_t this)
{
    if (!g_ds_idx || !this)
        return NULL;
    for (uint32_t i = obj_hash(this) & g_ds_idx_mask; g_ds_idx[i]; i = (i + 1) & g_ds_idx_mask)
        if (g_ds[g_ds_idx[i] - 1].this == this)
            return &g_ds[g_ds_idx[i] - 1];
    return NULL;
}

/* ---- objects: guest address -> slot in g_obj (open addressing, never deleted) */
typedef struct {
    uint32_t addr, kind, ptr, fmt;
    uint32_t ver, sent;
    int has_sent;
} Obj;
static Obj *g_obj;
static uint32_t g_obj_mask, g_obj_n;

static uint32_t obj_hash(uint32_t a) { return (a >> 4) * 0x9E3779B1u; }

static Obj *obj_find(uint32_t a)
{
    if (!g_obj || !a)
        return NULL;
    for (uint32_t i = obj_hash(a) & g_obj_mask;; i = (i + 1) & g_obj_mask) {
        if (g_obj[i].addr == a)
            return &g_obj[i];
        if (!g_obj[i].addr)
            return NULL;
    }
}

static Obj *obj_add(uint32_t a)
{
    Obj *o = obj_find(a);
    if (o)
        return o;
    if (!g_obj || (g_obj_n + 1) * 2 > g_obj_mask + 1) {
        uint32_t cap = g_obj ? (g_obj_mask + 1) * 2 : 1024;
        Obj *old = g_obj;
        uint32_t oldcap = g_obj ? g_obj_mask + 1 : 0;
        g_obj = calloc(cap, sizeof *g_obj);
        g_obj_mask = cap - 1;
        for (uint32_t i = 0; i < oldcap; i++)
            if (old[i].addr) {
                uint32_t j = obj_hash(old[i].addr) & g_obj_mask;
                while (g_obj[j].addr)
                    j = (j + 1) & g_obj_mask;
                g_obj[j] = old[i];
            }
        free(old);
    }
    uint32_t i = obj_hash(a) & g_obj_mask;
    while (g_obj[i].addr)
        i = (i + 1) & g_obj_mask;
    g_obj[i].addr = a;
    g_obj_n++;
    return &g_obj[i];
}

/* ---- statistics: (kind, a, b, value) -> count, merged into the Recorder by Python */
typedef struct {
    uint64_t key;
    uint64_t n;
} Hist;
static Hist *g_hist;
static uint32_t g_hist_mask, g_hist_n;

static void hist_add(uint64_t key)
{
    if (!g_hist || (g_hist_n + 1) * 2 > g_hist_mask + 1) {
        uint32_t cap = g_hist ? (g_hist_mask + 1) * 2 : 4096;
        Hist *old = g_hist;
        uint32_t oldcap = g_hist ? g_hist_mask + 1 : 0;
        g_hist = calloc(cap, sizeof *g_hist);
        g_hist_mask = cap - 1;
        g_hist_n = 0;
        for (uint32_t i = 0; i < oldcap; i++)
            if (old[i].n) {
                uint32_t j = (uint32_t)((old[i].key * 0x9E3779B97F4A7C15ull) >> 40) & g_hist_mask;
                while (g_hist[j].n)
                    j = (j + 1) & g_hist_mask;
                g_hist[j] = old[i];
                g_hist_n++;
            }
        free(old);
    }
    uint32_t i = (uint32_t)((key * 0x9E3779B97F4A7C15ull) >> 40) & g_hist_mask;
    while (g_hist[i].n && g_hist[i].key != key)
        i = (i + 1) & g_hist_mask;
    if (!g_hist[i].n)
        g_hist_n++;
    g_hist[i].key = key;
    g_hist[i].n++;
}

static uint64_t hkey(uint32_t kind, uint32_t a, uint32_t b, uint32_t v)
{
    return (uint64_t)kind << 60 | (uint64_t)(a & 0xfffu) << 48 | (uint64_t)(b & 0xffffu) << 32 | v;
}

/* ---- capture */
typedef int (*sink_fn)(void *r, uint32_t type, const void *payload, uint32_t len);
typedef const char *(*err_fn)(void);
static int g_cap;
static sink_fn g_sink;
static void *g_sink_r;
static err_fn g_sink_err;
static uint8_t *g_buf;
static size_t g_buf_cap;
static uint64_t g_sink_errors;

static uint8_t *buf(size_t n)
{
    if (n > g_buf_cap) {
        g_buf_cap = n * 2;
        g_buf = realloc(g_buf, g_buf_cap);
    }
    return g_buf;
}

static void submit(uint32_t type, const void *p, uint32_t len)
{
    if (g_sink(g_sink_r, type, p, len)) {
        g_sink_errors++;
        if (g_sink_err && g_sink_errors <= 10)
            fprintf(stderr, "[live] renderer: %s\n", g_sink_err());
    }
}

static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

/* ---- Python API */
void lift_hle_fast_reset(void)
{
    memset(g_kind, 0, sizeof g_kind);
    memset(g_count, 0, sizeof g_count);
    g_total = 0;
    memset(g_rs_set, 0, sizeof g_rs_set);
    memset(g_tss_set, 0, sizeof g_tss_set);
    memset(g_bound_set, 0, sizeof g_bound_set);
    memset(g_stream_set, 0, sizeof g_stream_set);
    g_ib = g_ib_base = g_vs = 0;
    memset(g_xf_set, 0, sizeof g_xf_set);
    g_vp_set = 0;
    g_last_error = 0;
    memset(g_tls_set, 0, sizeof g_tls_set);
    free(g_obj);
    g_obj = NULL;
    g_obj_mask = g_obj_n = 0;
    free(g_hist);
    g_hist = NULL;
    g_hist_mask = g_hist_n = 0;
    g_cap = CAP_NONE;
    g_sink = NULL;
    di_clear();
    ds_clear();
    g_on = 1;
}

void lift_hle_fast_bind(uint32_t idx, uint32_t kind)
{
    if (idx < FAST_STUBS && kind < K_COUNT)
        g_kind[idx] = (uint8_t)kind;
}

/* which: 0 render state (a), 1 texture-stage state (a = stage, b = type), 2 bound texture (a = stage), 3 stream (a = n:
 * v = vb, v2 = stride), 4 indices (v = ib, v2 = base), 5 vertex shader (v), 6 the last error (v), 7 a TLS slot (a). set: 0
 * clears (the dict entry is gone). Returns 0 when the key is out of range (Python keeps it). */
int lift_hle_fast_set(int which, uint32_t a, uint32_t b, uint32_t v, uint32_t v2, int set)
{
    switch (which) {
    case 0: if (a >= 256) return 0; g_rs[a] = v; g_rs_set[a] = (uint8_t)set; return 1;
    case 1: if (a >= 8 || b >= 32) return 0; g_tss[a][b] = v; g_tss_set[a][b] = (uint8_t)set; return 1;
    case 2: if (a >= 8) return 0; g_bound[a] = v; g_bound_set[a] = (uint8_t)set; return 1;
    case 3: if (a >= 16) return 0; g_stream_vb[a] = v; g_stream_stride[a] = v2; g_stream_set[a] = (uint8_t)set; return 1;
    case 4: g_ib = v; g_ib_base = v2; return 1;
    case 5: g_vs = v; return 1;
    case 6: g_last_error = v; return 1;
    case 7: if (a >= TLS_SLOTS) return 0; g_tls[a] = v; g_tls_set[a] = (uint8_t)set; return 1;
    }
    return 0;
}

/* The same keys: 1 and *v (*v2) when set, 0 when not (or out of range). */
int lift_hle_fast_get(int which, uint32_t a, uint32_t b, uint32_t *v, uint32_t *v2)
{
    switch (which) {
    case 0: if (a >= 256 || !g_rs_set[a]) return 0; *v = g_rs[a]; return 1;
    case 1: if (a >= 8 || b >= 32 || !g_tss_set[a][b]) return 0; *v = g_tss[a][b]; return 1;
    case 2: if (a >= 8 || !g_bound_set[a]) return 0; *v = g_bound[a]; return 1;
    case 3: if (a >= 16 || !g_stream_set[a]) return 0; *v = g_stream_vb[a]; *v2 = g_stream_stride[a]; return 1;
    case 4: *v = g_ib; *v2 = g_ib_base; return 1;
    case 5: *v = g_vs; return 1;
    case 6: *v = g_last_error; return 1;
    case 7: if (a >= TLS_SLOTS || !g_tls_set[a]) return 0; *v = g_tls[a]; return 1;
    }
    return 0;
}

/* The transforms (which 0: a = D3DTRANSFORMSTATETYPE, 64 bytes) and the viewport (which 1, 24 bytes) as raw bytes. op 0
 * gets (returns 1 when set), 1 sets, 2 clears. Returns 0 when the key is out of range or not set. */
int lift_hle_fast_blob(int which, uint32_t a, int op, void *p)
{
    uint8_t *set;
    void *d;
    size_t n;
    if (which == 0 && a < XF_STATES)
        set = &g_xf_set[a], d = g_xf[a], n = sizeof g_xf[a];
    else if (which == 1)
        set = &g_vp_set, d = g_vp, n = sizeof g_vp;
    else
        return 0;
    if (op == 1) {
        memcpy(d, p, n);
        *set = 1;
    } else if (op == 2) {
        *set = 0;
    } else {
        if (!*set)
            return 0;
        memcpy(p, d, n);
    }
    return 1;
}

/* ---- DINPUT (H61), for emu/dinput.py */
/* A new device for guest object this (kind 0 keyboard, 1 mouse): its slot, or -1 when C has no room (Python keeps it). */
int lift_hle_fast_di_new(uint32_t this, uint32_t kind)
{
    if (g_di_n >= DI_DEVS)
        return -1;
    DiDev *d = &g_di[g_di_n];
    memset(d, 0, sizeof *d);
    d->this = this;
    d->kind = kind;
    return (int)g_di_n++;
}

/* The device's configuration as Python holds it: cooperative level, the data format (has_fmt, its size and nobj
 * (kind, instance, offset) triples) and the buffer size. A smaller buffer keeps the newest events, as set_prop does. */
void lift_hle_fast_di_cfg(int slot, uint32_t coop, int has_fmt, uint32_t fmt_size, uint32_t bufsize, uint32_t nobj,
                          const uint32_t *obj)
{
    if (slot < 0 || (uint32_t)slot >= g_di_n)
        return;
    DiDev *d = &g_di[slot];
    d->coop = coop;
    d->has_fmt = (uint8_t)has_fmt;
    d->fmt_size = fmt_size;
    d->bufsize = bufsize;
    free(d->obj);
    d->obj = nobj ? malloc(12 * (size_t)nobj) : NULL;
    if (nobj)
        memcpy(d->obj, obj, 12 * (size_t)nobj);
    d->nobj = nobj;
    while (d->qlen > bufsize)
        di_popleft(d);
}

/* A run-state field: slot >= 0: 0 acquired, 1 lost, 2 overflow, 3..5 dx, dy, dz; slot -1: 0 the sequence number, 1 the
 * Python poll flag. set: write v first. Returns the value. */
int64_t lift_hle_fast_di_field(int slot, int field, int set, int64_t v)
{
    if (slot < 0) {
        if (field == 0) {
            if (set)
                g_di_seq = (uint32_t)v;
            return g_di_seq;
        }
        if (set)
            g_di_pypoll = v != 0;
        return g_di_pypoll;
    }
    if ((uint32_t)slot >= g_di_n)
        return 0;
    DiDev *d = &g_di[slot];
    if (field >= 3 && field <= 5) {
        if (set)
            d->d[field - 3] = v;
        return d->d[field - 3];
    }
    uint8_t *f = field == 0 ? &d->acquired : field == 1 ? &d->lost : &d->overflow;
    if (set)
        *f = v != 0;
    return *f;
}

/* The event queue: op 0 its length, 1 append ev, 2 pop the oldest, 3 clear, 4 copy event i to ev. */
uint32_t lift_hle_fast_di_queue(int slot, int op, uint32_t i, uint32_t *ev)
{
    if (slot < 0 || (uint32_t)slot >= g_di_n)
        return 0;
    DiDev *d = &g_di[slot];
    switch (op) {
    case 1:
        if (d->qlen == d->qcap) {                      /* grow: the ring unrolled into twice the room */
            uint32_t cap = d->qcap ? d->qcap * 2 : 16;
            uint32_t (*q)[4] = malloc(16 * (size_t)cap);
            for (uint32_t k = 0; k < d->qlen; k++)
                memcpy(q[k], di_at(d, k), 16);
            free(d->q);
            d->q = q;
            d->qcap = cap;
            d->qhead = 0;
        }
        d->qlen++;
        memcpy(di_at(d, d->qlen - 1), ev, 16);
        break;
    case 2:
        if (d->qlen)
            di_popleft(d);
        break;
    case 3:
        d->qhead = d->qlen = 0;
        break;
    case 4:
        if (i >= d->qlen)
            return 0;
        memcpy(ev, di_at(d, i), 16);
        return 1;
    }
    return d->qlen;
}

/* Input.keys (256 bytes) followed by Input.buttons (8): Python views them in place. */
uint8_t *lift_hle_fast_di_keys(void) { return g_di_in.keys; }

/* ---- DSOUND (H62), for emu/dsound.py */
/* A new buffer for guest object this: its slot (Python then sends the layout, run state and gains). */
int lift_hle_fast_ds_new(uint32_t this)
{
    if (g_ds_n == g_ds_cap) {
        g_ds_cap = g_ds_cap ? g_ds_cap * 2 : 256;
        g_ds = realloc(g_ds, g_ds_cap * sizeof *g_ds);
    }
    if (!g_ds_idx || (g_ds_n + 1) * 2 > g_ds_idx_mask + 1) {
        uint32_t cap = g_ds_idx ? (g_ds_idx_mask + 1) * 2 : 1024;
        free(g_ds_idx);
        g_ds_idx = calloc(cap, sizeof *g_ds_idx);
        g_ds_idx_mask = cap - 1;
        for (uint32_t k = 0; k < g_ds_n; k++) {
            uint32_t j = obj_hash(g_ds[k].this) & g_ds_idx_mask;
            while (g_ds_idx[j])
                j = (j + 1) & g_ds_idx_mask;
            g_ds_idx[j] = k + 1;
        }
    }
    DsBuf *b = &g_ds[g_ds_n];
    memset(b, 0, sizeof *b);
    b->this = this;
    b->voice = -1;
    b->gl = b->gr = 1.0;
    uint32_t j = obj_hash(this) & g_ds_idx_mask;
    while (g_ds_idx[j])
        j = (j + 1) & g_ds_idx_mask;
    g_ds_idx[j] = ++g_ds_n;
    return (int)g_ds_n - 1;
}

/* The buffer's layout as Python holds it: guest pointer, size, and the format's avg and align (has_wfx). */
void lift_hle_fast_ds_cfg(int slot, uint32_t ptr, uint32_t size, int has_wfx, uint32_t avg, uint32_t align)
{
    if (slot < 0 || (uint32_t)slot >= g_ds_n)
        return;
    DsBuf *b = &g_ds[slot];
    b->ptr = ptr;
    b->size = size;
    b->has_wfx = (uint8_t)has_wfx;
    b->avg = avg;
    b->align = align;
}

/* A run-state field: 0 volume, 1 playing, 2 looping, 3 pos, 4 started, 5 unlocks, 6 written, 7 voice (-1 none). set:
 * write v first. Returns the value. */
double lift_hle_fast_ds_field(int slot, int field, int set, double v)
{
    if (slot < 0 || (uint32_t)slot >= g_ds_n)
        return 0;
    DsBuf *b = &g_ds[slot];
    switch (field) {
    case 0: if (set) b->volume = (int32_t)v; return b->volume;
    case 1: if (set) b->playing = v != 0; return b->playing;
    case 2: if (set) b->looping = v != 0; return b->looping;
    case 3: if (set) b->pos = (uint32_t)v; return b->pos;
    case 4: if (set) b->started = v; return b->started;
    case 5: if (set) b->unlocks = (uint64_t)v; return (double)b->unlocks;
    case 6: if (set) b->written = (uint64_t)v; return (double)b->written;
    case 7: if (set) b->voice = (int32_t)v; return b->voice;
    }
    return 0;
}

/* The voice's gains before the volume (pan or 3D) and whether it is downmixed, from dsound.py update_voice. */
void lift_hle_fast_ds_gains(int slot, double gl, double gr, int downmix)
{
    if (slot < 0 || (uint32_t)slot >= g_ds_n)
        return;
    g_ds[slot].gl = gl;
    g_ds[slot].gr = gr;
    g_ds[slot].downmix = downmix;
}

/* The mixer (an mpa *) and mpa_voice_write, mpa_voice_get_pos and mpa_voice_set_gain; m NULL: none (closed). */
void lift_hle_fast_ds_mixer(void *m, void *write, void *pos, void *gain)
{
    g_mpa = m;
    g_mpa_write = (mpa_write_fn)write;
    g_mpa_pos = (mpa_pos_fn)pos;
    g_mpa_gain = (mpa_gain_fn)gain;
}

void lift_hle_fast_obj(uint32_t addr, uint32_t kind, uint32_t ptr, uint32_t fmt)
{
    Obj *o = obj_add(addr);
    o->kind = kind;
    o->ptr = ptr;
    o->fmt = fmt;
}

/* A texture's lock version (d3d8.py touch), and the version last sent to the renderer (send_textures; has_sent 0: none,
 * as after a new capture). */
void lift_hle_fast_tex(uint32_t addr, uint32_t ver, uint32_t sent, int has_sent)
{
    Obj *o = obj_add(addr);
    o->ver = ver;
    o->sent = sent;
    o->has_sent = has_sent;
}

int lift_hle_fast_tex_get(uint32_t addr, uint32_t *ver, uint32_t *sent)
{
    Obj *o = obj_find(addr);
    if (!o)
        return 0;
    *ver = o->ver;
    *sent = o->sent;
    return o->has_sent ? 2 : 1;
}

/* mode: CAP_NONE, CAP_SINK (with sink, r, err) or CAP_PYTHON. A new capture forgets every sent version. */
void lift_hle_fast_capture(int mode, void *sink, void *r, void *err, int reset_sent)
{
    g_cap = mode;
    g_sink = (sink_fn)sink;
    g_sink_r = r;
    g_sink_err = (err_fn)err;
    if (mode == CAP_SINK && !g_sink)
        g_cap = CAP_PYTHON;
    if (reset_sent && g_obj)
        for (uint32_t i = 0; i <= g_obj_mask; i++)
            g_obj[i].has_sent = 0;
}

/* Handled calls per stub index: up to cap (idx, count) pairs, then cleared (Python adds them to its counters). */
uint32_t lift_hle_fast_counts(uint32_t *idx, uint64_t *n, uint32_t cap)
{
    uint32_t k = 0;
    for (uint32_t i = 0; i < FAST_STUBS && k < cap; i++)
        if (g_count[i]) {
            idx[k] = i;
            n[k++] = g_count[i];
            g_count[i] = 0;
        }
    return k;
}

/* Histogram entries as (key, count), then cleared. */
uint32_t lift_hle_fast_hist(uint64_t *key, uint64_t *n, uint32_t cap)
{
    uint32_t k = 0;
    if (!g_hist)
        return 0;
    for (uint32_t i = 0; i <= g_hist_mask && k < cap; i++)
        if (g_hist[i].n) {
            key[k] = g_hist[i].key;
            n[k++] = g_hist[i].n;
        }
    memset(g_hist, 0, (g_hist_mask + 1) * sizeof *g_hist);
    g_hist_n = 0;
    return k;
}

uint64_t lift_hle_fast_total(void) { return g_total; }

/* ---- the handlers. sp: [sp] return address, [sp + 4] the first argument (this for a method). */
static uint64_t now_us(void)
{
    static mach_timebase_info_data_t tb;
    if (!tb.denom)
        mach_timebase_info(&tb);
    /* time.perf_counter_ns() // 1000 (mpemu.py): mach_absolute_time in ns, as CPython computes it */
    return (uint64_t)((__uint128_t)mach_absolute_time() * tb.numer / tb.denom) / 1000;
}

static uint32_t index_count(uint32_t prim, uint32_t count)          /* d3dcap.index_count */
{
    switch (prim) {
    case 1: return count;
    case 2: return 2 * count;
    case 3: return count + 1;
    case 4: return 3 * count;
    case 5: case 6: return count + 2;
    }
    return 0;
}

/* d3d8.py draw_indexed + capture_draw for a live capture: the vertices the indices use, the indices rebased to the
 * first of them. Declines when Python would raise (unknown buffers, memory outside the mapped regions) or would send a
 * texture first. */
static int dip(CPU *c, uint32_t sp)
{
    uint32_t prim = rd32(c, sp + 8), si = rd32(c, sp + 0x14), count = rd32(c, sp + 0x18);
    if (g_cap == CAP_PYTHON)
        return 0;
    if (g_cap == CAP_SINK) {
        for (int s = 0; s < 8; s++) {
            if (!g_bound_set[s])
                continue;
            Obj *t = obj_find(g_bound[s]);
            if (t && t->kind == O_TEX && (!t->has_sent || t->sent != t->ver))
                return 0;                                    /* send_textures would read it back: Python */
        }
        Obj *vb = g_stream_set[0] ? obj_find(g_stream_vb[0]) : NULL, *ib = obj_find(g_ib);
        if (!vb || vb->kind != O_VB || !ib || ib->kind != O_IB)
            return 0;
        uint32_t stride = g_stream_set[0] ? g_stream_stride[0] : 0;
        uint32_t isize = ib->fmt == 102 ? 4 : 2, n = index_count(prim, count);
        uint64_t ia = (uint64_t)ib->ptr + (uint64_t)si * isize;
        if (ia + (uint64_t)n * isize > 0xffffffffull || !lift_mapped((uint32_t)ia, n * isize))
            return 0;
        uint32_t lo = UINT32_MAX, hi = 0;
        for (uint32_t i = 0; i < n; i++) {
            uint32_t x = isize == 4 ? rd32(c, (uint32_t)ia + 4 * i) : rd16(c, (uint32_t)ia + 2 * i);
            if (x < lo)
                lo = x;
            if (x > hi)
                hi = x;
        }
        if (!n)
            lo = 0;                                          /* no indices: no vertices (lo, hi = 0, -1) */
        uint64_t nv = n ? (uint64_t)hi - lo + 1 : 0;
        uint64_t first = (uint64_t)g_ib_base + lo, va = (uint64_t)vb->ptr + first * stride, vlen = nv * stride;
        if (vlen && (va + vlen > 0xffffffffull || !lift_mapped((uint32_t)va, (uint32_t)vlen)))
            return 0;
        uint32_t fvf = (g_vs & 0x80000000u) ? 0 : g_vs;
        uint32_t nverts = stride ? (uint32_t)(vlen / stride) : 0;
        size_t len = 24 + (size_t)vlen + (size_t)n * isize;
        uint8_t *p = buf(len);
        put32(p, prim); put32(p + 4, fvf); put32(p + 8, stride); put32(p + 12, nverts);
        put32(p + 16, n); put32(p + 20, isize);
        if (vlen)
            memcpy(p + 24, MEM(c, (uint32_t)va), (size_t)vlen);
        uint8_t *q = p + 24 + vlen;
        for (uint32_t i = 0; i < n; i++) {
            if (isize == 4) {
                uint32_t x = rd32(c, (uint32_t)ia + 4 * i) - lo;
                memcpy(q + 4 * i, &x, 4);
            } else {
                uint16_t x = (uint16_t)(rd16(c, (uint32_t)ia + 2 * i) - lo);
                memcpy(q + 2 * i, &x, 2);
            }
        }
        submit(REC_DRAW, p, (uint32_t)len);
    }
    hist_add(hkey(H_DRAW, prim & 0xfffu, 0, prim));
    return 1;
}

/* dinput.py not_ready: 0 when acquired, else the error a poll returns. */
static uint32_t di_not_ready(const DiDev *d)
{
    return d->acquired ? 0 : d->lost ? DIERR_INPUTLOST : DIERR_NOTACQUIRED;
}

/* dinput.py get_state: the immediate state in the device's data format. Declines when Python would raise (a key or
 * button offset past cb) or the buffer is not mapped. */
static int di_state(CPU *c, DiDev *d, uint32_t sp, uint32_t *ret)
{
    uint32_t cb = rd32(c, sp + 8), p = rd32(c, sp + 12);
    uint32_t err = di_not_ready(d);
    if (!err && cb != d->fmt_size)
        err = DIERR_INVALIDPARAM;
    if (err) {
        hist_add(hkey(H_DI, DIP_STATE_ERR, d->kind, err));
        *ret = err;
        return 1;
    }
    for (uint32_t i = 0; i < d->nobj; i++)
        if (d->obj[3 * i] != DIO_AXIS && d->obj[3 * i + 2] >= cb)
            return 0;
    if (cb && !lift_mapped(p, cb))
        return 0;
    uint8_t *b = buf(cb ? cb : 1);
    memset(b, 0, cb);
    for (uint32_t i = 0; i < d->nobj; i++) {
        uint32_t k = d->obj[3 * i], n = d->obj[3 * i + 1], ofs = d->obj[3 * i + 2];
        if (k == DIO_KEY)
            b[ofs] = n < 256 ? g_di_in.keys[n] : 0;
        else if (k == DIO_BUTTON)
            b[ofs] = n < 8 ? g_di_in.buttons[n] : 0;
        else if ((uint64_t)ofs + 4 <= cb) {
            int64_t v = n < 3 ? d->d[n] : 0;
            int32_t x = v < INT32_MIN ? INT32_MIN : v > INT32_MAX ? INT32_MAX : (int32_t)v;
            memcpy(b + ofs, &x, 4);
        }
    }
    d->d[0] = d->d[1] = d->d[2] = 0;
    if (cb)
        memcpy(MEM(c, p), b, cb);
    hist_add(hkey(H_DI, DIP_STATE, d->kind, 0));
    *ret = 0;
    return 1;
}

/* dinput.py get_data: the buffered events. Declines when Python would raise (the count or the records not mapped). */
static int di_data(CPU *c, DiDev *d, uint32_t sp, uint32_t *ret)
{
    uint32_t cbobj = rd32(c, sp + 8), rgdod = rd32(c, sp + 12), pinout = rd32(c, sp + 16), flags = rd32(c, sp + 20);
    uint32_t err = di_not_ready(d);
    if (!err && !d->bufsize)
        err = DIERR_NOTBUFFERED;
    if (!err && cbobj < 16)
        err = DIERR_INVALIDPARAM;
    if (!lift_mapped(pinout, 4))
        return 0;
    uint32_t want = rd32(c, pinout);
    if (err) {
        hist_add(hkey(H_DI, DIP_DATA_ERR, d->kind, err));
        if (pinout)
            wr32(c, pinout, 0);
        *ret = err;
        return 1;
    }
    uint32_t n = want == 0xffffffffu || want > d->qlen ? d->qlen : want;
    if (rgdod && n) {
        uint64_t len = (uint64_t)cbobj * n;
        if (rgdod + len > 0x100000000ull || !lift_mapped(rgdod, (uint32_t)len))
            return 0;
        for (uint32_t i = 0; i < n; i++) {
            uint8_t *r = MEM(c, rgdod + cbobj * i);
            memcpy(r, di_at(d, i), 16);
            memset(r + 16, 0, cbobj - 16);
        }
    }
    if (!(flags & 1))                                  /* DIGDD_PEEK */
        for (uint32_t i = 0; i < n; i++)
            di_popleft(d);
    if (pinout)
        wr32(c, pinout, n);
    hist_add(hkey(H_DI, DIP_DATA, d->kind, n));
    *ret = 0;
    if (d->overflow) {
        d->overflow = 0;
        *ret = DI_NOEFFECT;                            /* DI_BUFFEROVERFLOW */
    }
    return 1;
}

/* time.perf_counter(): mach_absolute_time in seconds, as CPython computes it */
static double perf_counter(void)
{
    static mach_timebase_info_data_t tb;
    if (!tb.denom)
        mach_timebase_info(&tb);
    return (double)(uint64_t)((__uint128_t)mach_absolute_time() * tb.numer / tb.denom) / 1e9;
}

static double ds_db_gain(int32_t h)                 /* dsound.py db_gain */
{
    return h <= -10000 ? 0.0 : pow(10.0, (h < 0 ? h : 0) / 2000.0);
}

/* dsound.py play_cursor: the play cursor, and whether the buffer still plays. With a voice, the mixer's. */
static uint32_t ds_play_cursor(DsBuf *b, int *playing)
{
    if (b->voice >= 0) {
        int p = 0;
        uint32_t pos = g_mpa_pos(g_mpa, b->voice, &p);
        b->playing = p != 0;
        *playing = b->playing;
        return pos;
    }
    if (!b->playing) {
        *playing = 0;
        return b->pos;
    }
    double rate = b->has_wfx && b->avg ? b->avg : 44100.0 * 4;
    uint64_t pos = b->pos + (uint64_t)((perf_counter() - b->started) * rate);
    *playing = 1;
    if (b->looping)
        return (uint32_t)(pos % b->size);
    if (pos >= b->size) {
        b->playing = 0;
        b->pos = 0;
        *playing = 0;
        return 0;
    }
    return (uint32_t)pos;
}

static uint32_t ds_write_cursor(DsBuf *b, uint32_t *play)        /* dsound.py write_cursor */
{
    int playing;
    uint32_t p = ds_play_cursor(b, &playing);
    *play = p;
    if (!playing || !b->has_wfx)
        return p;
    return (uint32_t)(((uint64_t)p + (uint64_t)WRITE_LEAD_FRAMES * b->align) % b->size);
}

static int ds_ready(const DsBuf *b) { return b && b->size && (b->voice < 0 || g_mpa); }

int lift_hle_fast(CPU *c, uint32_t idx)
{
    if (!g_on || idx >= FAST_STUBS || !g_kind[idx])
        return 0;
    uint32_t sp = c->r[ESP];
    uint32_t pop = 0, ret = 0;                      /* D3D_OK */
    switch (g_kind[idx]) {
    case K_QPC: {
        uint32_t p = rd32(c, sp + 4);
        if (!lift_mapped(p, 8))
            return 0;
        wr64(c, p, now_us());
        ret = 1;
        pop = 1;
        break;
    }
    case K_RS: {
        uint32_t state = rd32(c, sp + 8), value = rd32(c, sp + 12);
        if (state >= 256 || g_cap == CAP_PYTHON)
            return 0;
        g_rs[state] = value;
        g_rs_set[state] = 1;
        hist_add(hkey(H_RS, state, 0, value));
        if (g_cap == CAP_SINK) {
            uint8_t p[12];
            put32(p, 1); put32(p + 4, state); put32(p + 8, value);
            submit(REC_RENDERSTATE, p, 12);
        }
        pop = 3;
        break;
    }
    case K_TSS: {
        uint32_t stage = rd32(c, sp + 8), ty = rd32(c, sp + 12), value = rd32(c, sp + 16);
        if (stage >= 8 || ty >= 32 || g_cap == CAP_PYTHON)
            return 0;
        g_tss[stage][ty] = value;
        g_tss_set[stage][ty] = 1;
        hist_add(hkey(H_TSS, stage, ty, value));
        if (g_cap == CAP_SINK) {
            uint8_t p[16];
            put32(p, 1); put32(p + 4, stage); put32(p + 8, ty); put32(p + 12, value);
            submit(REC_TSS, p, 16);
        }
        pop = 4;
        break;
    }
    case K_SETTEX: {
        uint32_t stage = rd32(c, sp + 8), tex = rd32(c, sp + 12);
        if (stage >= 8 || g_cap == CAP_PYTHON)
            return 0;
        g_bound[stage] = tex;
        g_bound_set[stage] = 1;
        Obj *o = obj_find(tex);
        if (o)
            hist_add(hkey(H_SETTEX, stage, 0, tex));
        if (g_cap == CAP_SINK) {
            uint8_t p[8];
            put32(p, stage); put32(p + 4, o && o->kind == O_TEX ? tex : 0);
            submit(REC_SETTEXTURE, p, 8);
        }
        pop = 3;
        break;
    }
    case K_STREAM: {
        uint32_t n = rd32(c, sp + 8), vb = rd32(c, sp + 12), stride = rd32(c, sp + 16);
        if (n >= 16)
            return 0;
        g_stream_vb[n] = vb;
        g_stream_stride[n] = stride;
        g_stream_set[n] = 1;
        pop = 4;
        break;
    }
    case K_INDICES:
        g_ib = rd32(c, sp + 8);
        g_ib_base = rd32(c, sp + 12);
        pop = 3;
        break;
    case K_VBLOCK: case K_IBLOCK: {
        Obj *o = obj_find(rd32(c, sp + 4));
        uint32_t off = rd32(c, sp + 8), pp = rd32(c, sp + 16);
        if (!o || o->kind != (g_kind[idx] == K_VBLOCK ? O_VB : O_IB) || !lift_mapped(pp, 4))
            return 0;
        wr32(c, pp, o->ptr + off);
        pop = 5;
        break;
    }
    case K_UNLOCK:
        pop = 1;
        break;
    case K_DIP:
        if (!dip(c, sp))
            return 0;
        pop = 6;
        break;
    case K_TLSGET: {                                /* sets the last error to 0, as Windows does */
        uint32_t i = rd32(c, sp + 4);
        if (i >= TLS_SLOTS)
            return 0;
        g_last_error = 0;
        ret = g_tls_set[i] ? g_tls[i] : 0;
        pop = 1;
        break;
    }
    case K_TLSSET: {
        uint32_t i = rd32(c, sp + 4);
        if (i >= TLS_SLOTS)
            return 0;
        g_tls[i] = rd32(c, sp + 8);
        g_tls_set[i] = 1;
        ret = 1;
        pop = 2;
        break;
    }
    case K_GETLE:
        ret = g_last_error;
        break;
    case K_SETLE:
        g_last_error = rd32(c, sp + 4);
        pop = 1;
        break;
    case K_CRITSEC:                                 /* Initialize/Enter/Leave/DeleteCriticalSection: one thread */
        pop = 1;
        break;
    case K_SETVS: {
        uint32_t h = rd32(c, sp + 8);
        g_vs = h;
        if (!(h & 0x80000000u))
            hist_add(hkey(H_FVF, 0, 0, h));
        pop = 2;
        break;
    }
    case K_SETXF: {
        uint32_t state = rd32(c, sp + 8), pm = rd32(c, sp + 12);
        if (state >= XF_STATES || g_cap == CAP_PYTHON || !lift_mapped(pm, 64))
            return 0;
        memcpy(g_xf[state], MEM(c, pm), 64);
        g_xf_set[state] = 1;
        hist_add(hkey(H_XF, 0, 0, state));
        if (g_cap == CAP_SINK) {
            uint8_t p[68];
            put32(p, state);
            memcpy(p + 4, g_xf[state], 64);
            submit(REC_TRANSFORM, p, 68);
        }
        pop = 3;
        break;
    }
    case K_SETVP: {
        uint32_t pv = rd32(c, sp + 8);
        if (g_cap == CAP_PYTHON || !lift_mapped(pv, 24))
            return 0;
        memcpy(g_vp, MEM(c, pv), 24);
        g_vp_set = 1;
        if (g_cap == CAP_SINK)
            submit(REC_VIEWPORT, g_vp, 24);
        pop = 2;
        break;
    }
    case K_CLEAR: {                                 /* Clear(count, rects, flags, color, z, stencil) */
        uint32_t count = rd32(c, sp + 8), rects = rd32(c, sp + 12), flags = rd32(c, sp + 16);
        if (g_cap == CAP_PYTHON)
            return 0;
        if (g_cap == CAP_SINK) {
            uint32_t n = rects ? count : 0;       /* the rects are read only for a capture, as in d3d8.py */
            if (n > 0x10000u || (n && !lift_mapped(rects, 16 * n)))
                return 0;
            uint8_t *p = buf(20 + 16 * (size_t)n);
            put32(p, flags); put32(p + 4, rd32(c, sp + 20)); put32(p + 8, rd32(c, sp + 24));
            put32(p + 12, rd32(c, sp + 28)); put32(p + 16, n);
            if (n)
                memcpy(p + 20, MEM(c, rects), 16 * (size_t)n);
            submit(REC_CLEAR, p, 20 + 16 * n);
        }
        hist_add(hkey(H_CLEAR, 0, 0, flags));
        pop = 7;
        break;
    }
    case K_DIACQ: {
        DiDev *d = di_find(rd32(c, sp + 4));
        if (!d)
            return 0;
        if (!d->has_fmt)
            ret = DIERR_INVALIDPARAM;
        else if (d->acquired)
            ret = DI_NOEFFECT;
        else {
            d->acquired = 1;
            d->lost = 0;
            d->d[0] = d->d[1] = d->d[2] = 0;
            hist_add(hkey(H_DI, DIP_ACQ, d->kind, 0));
        }
        pop = 1;
        break;
    }
    case K_DISTATE: case K_DIDATA: {
        DiDev *d = di_find(rd32(c, sp + 4));
        if (!d || g_di_pypoll || !(g_kind[idx] == K_DISTATE ? di_state(c, d, sp, &ret) : di_data(c, d, sp, &ret)))
            return 0;
        pop = g_kind[idx] == K_DISTATE ? 3 : 5;
        break;
    }
    case K_DSLOCK: {                                /* Lock(off, nbytes, pp1, pcb1, pp2, pcb2, flags) */
        DsBuf *b = ds_find(rd32(c, sp + 4));
        uint32_t off = rd32(c, sp + 8), n = rd32(c, sp + 12), flags = rd32(c, sp + 32), out[4], play;
        if (!ds_ready(b))
            return 0;
        for (int k = 0; k < 4; k++) {
            out[k] = rd32(c, sp + 16 + 4 * k);
            if (out[k] && !lift_mapped(out[k], 4))
                return 0;
        }
        if (flags & DSBLOCK_ENTIREBUFFER)
            off = 0, n = b->size;
        else if (flags & DSBLOCK_FROMWRITECURSOR)
            off = ds_write_cursor(b, &play);
        pop = 8;
        if (off >= b->size || n > b->size) {
            ret = DSERR_INVALIDPARAM;
            break;
        }
        uint32_t first = n < b->size - off ? n : b->size - off;
        uint32_t v[4] = {b->ptr + off, first, n > first ? b->ptr : 0, n > first ? n - first : 0};
        for (int k = 0; k < 4; k++)
            if (out[k])
                wr32(c, out[k], v[k]);
        break;
    }
    case K_DSUNLOCK: {                              /* Unlock(p1, n1, p2, n2): hand the regions to the mixer */
        DsBuf *b = ds_find(rd32(c, sp + 4));
        uint32_t p[2] = {rd32(c, sp + 8), rd32(c, sp + 16)}, n[2] = {rd32(c, sp + 12), rd32(c, sp + 20)};
        if (!ds_ready(b))
            return 0;
        uint32_t m[2] = {0, 0};
        for (int k = 0; k < 2; k++) {
            int64_t off = (int64_t)p[k] - b->ptr;
            if (b->voice >= 0 && p[k] && n[k] && off >= 0 && off < b->size) {
                m[k] = n[k] < b->size - off ? n[k] : (uint32_t)(b->size - off);
                if (!lift_mapped(p[k], m[k]))
                    return 0;
            }
        }
        b->unlocks++;
        b->written += (uint64_t)n[0] + n[1];
        for (int k = 0; k < 2; k++)
            if (m[k])
                g_mpa_write(g_mpa, b->voice, p[k] - b->ptr, MEM(c, p[k]), m[k]);
        pop = 5;
        break;
    }
    case K_DSPOS: {                                 /* GetCurrentPosition(pplay, pwrite) */
        DsBuf *b = ds_find(rd32(c, sp + 4));
        uint32_t pp = rd32(c, sp + 8), pw = rd32(c, sp + 12), play;
        if (!ds_ready(b) || (pp && !lift_mapped(pp, 4)) || (pw && !lift_mapped(pw, 4)))
            return 0;
        uint32_t w = ds_write_cursor(b, &play);
        if (pp)
            wr32(c, pp, play);
        if (pw)
            wr32(c, pw, w);
        pop = 3;
        break;
    }
    case K_DSVOL: {                                 /* SetVolume(v): the voice's gains, as update_voice */
        DsBuf *b = ds_find(rd32(c, sp + 4));
        if (!ds_ready(b))
            return 0;
        b->volume = (int32_t)rd32(c, sp + 8);
        if (b->voice >= 0) {
            double vol = ds_db_gain(b->volume);
            g_mpa_gain(g_mpa, b->voice, (float)(vol * b->gl), (float)(vol * b->gr), b->downmix);
        }
        pop = 2;
        break;
    }
    default:
        return 0;
    }
    g_count[idx]++;
    g_total++;
    c->r[EAX] = ret;
    c->r[ESP] = sp + 4 + 4 * pop;
    return 1;
}
