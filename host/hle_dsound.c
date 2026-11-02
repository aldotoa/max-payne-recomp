/* DirectSound for the native host (E6): a port of emu/dsound.py without the mixer, as an --audio off run of the
 * emulator: DirectSoundEnumerateA (ordinal 2), DirectSoundCreate and the DirectSound COM classes, the DirectSound
 * object, primary and secondary buffers (static and streaming, duplicates), the 3D listener, 3D buffers and the notify
 * interface, as COM objects in guest memory with the emulator's vtable layouts and allocation order. As in a native
 * emulator run (H62), hle_fast.c serves IDirectSoundBuffer Lock, Unlock, GetCurrentPosition and SetVolume and owns
 * each buffer's run state (volume, playing, looping, the clock cursor and its start, the unlock counters): a buffer is
 * registered there when it is created (host_ds_new, host_ds_cfg) and the other methods here read and write that state
 * (host_ds_field). With no mixer a buffer's play cursor runs on the host clock (time.perf_counter's, mach time) and
 * the 3D parameters are stored (the getters read them back; DS3D_DEFERRED changes wait for the commit). With a mixer
 * (--audio device|null, libmpaudio, audio/) each secondary buffer is a voice: hle_fast.c copies the unlocked regions
 * to it and its position is the play cursor; volume, pan, frequency and the DS3D model (gains_3d: distance rolloff,
 * cones, listener-relative pan, doppler) become the voice's gains and rate (update_voice), as in Python, double for
 * double (no fused multiply-adds: Python has none). */
#include <math.h>
#include <mach/mach_time.h>
#pragma clang fp contract(off)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"

#define DS "DSOUND.DLL"
#define H(name) static uint32_t name(CPU *c, const uint32_t *a)
#define UNUSED (void)c, (void)a

enum { DS_OK = 0, E_NOINTERFACE = 0x80004002u, DSERR_INVALIDPARAM = 0x80070057u, DSERR_UNSUPPORTED = 0x80004001u,
       DSERR_NOAGGREGATION = 0x80040110u, DSERR_ALREADYINITIALIZED = 0x88780082u };
#define DSBSTATUS_PLAYING 0x1u
#define DSBSTATUS_LOOPING 0x4u
#define DSBPLAY_LOOPING 0x1u
#define DSBLOCK_FROMWRITECURSOR 0x1u
#define DSBLOCK_ENTIREBUFFER 0x2u
#define DS3D_DEFERRED 0x1u
#define WRITE_LEAD_FRAMES 768u

/* ---------------------------------------------------------------- vtable layouts (dsound.py INTERFACES) */
typedef struct { const char *name; uint8_t nparams; } Meth;
static const Meth IDIRECTSOUND[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"CreateSoundBuffer", 3}, {"GetCaps", 1},
    {"DuplicateSoundBuffer", 2}, {"SetCooperativeLevel", 2}, {"Compact", 0}, {"GetSpeakerConfig", 1},
    {"SetSpeakerConfig", 1}, {"Initialize", 1}, {NULL, 0}};
static const Meth IDIRECTSOUNDBUFFER[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"GetCaps", 1}, {"GetCurrentPosition", 2}, {"GetFormat", 3},
    {"GetVolume", 1}, {"GetPan", 1}, {"GetFrequency", 1}, {"GetStatus", 1}, {"Initialize", 2}, {"Lock", 7}, {"Play", 3},
    {"SetCurrentPosition", 1}, {"SetFormat", 1}, {"SetVolume", 1}, {"SetPan", 1}, {"SetFrequency", 1}, {"Stop", 0},
    {"Unlock", 4}, {"Restore", 0}, {NULL, 0}};
static const Meth IDIRECTSOUND3DLISTENER[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"GetAllParameters", 1}, {"GetDistanceFactor", 1},
    {"GetDopplerFactor", 1}, {"GetOrientation", 2}, {"GetPosition", 1}, {"GetRolloffFactor", 1}, {"GetVelocity", 1},
    {"SetAllParameters", 2}, {"SetDistanceFactor", 2}, {"SetDopplerFactor", 2}, {"SetOrientation", 7}, {"SetPosition",
    4}, {"SetRolloffFactor", 2}, {"SetVelocity", 4}, {"CommitDeferredSettings", 0}, {NULL, 0}};
static const Meth IDIRECTSOUND3DBUFFER[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"GetAllParameters", 1}, {"GetConeAngles", 2},
    {"GetConeOrientation", 1}, {"GetConeOutsideVolume", 1}, {"GetMaxDistance", 1}, {"GetMinDistance", 1}, {"GetMode",
    1}, {"GetPosition", 1}, {"GetVelocity", 1}, {"SetAllParameters", 2}, {"SetConeAngles", 3}, {"SetConeOrientation",
    4}, {"SetConeOutsideVolume", 2}, {"SetMaxDistance", 2}, {"SetMinDistance", 2}, {"SetMode", 2}, {"SetPosition", 4},
    {"SetVelocity", 4}, {NULL, 0}};
static const Meth IDIRECTSOUNDNOTIFY[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"SetNotificationPositions", 2}, {NULL, 0}};

enum { I_DS, I_BUF, I_LISTENER, I_3DBUF, I_NOTIFY, NIFACES };
static struct {
    const char *name;
    const Meth *m;
    uint8_t iid[16];
    uint32_t vtable;
} g_ifaces[NIFACES] = {
    {"IDirectSound", IDIRECTSOUND, {0x83, 0xFA, 0x9A, 0x27, 0x81, 0x49, 0xCE, 0x11, 0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60}, 0},
    {"IDirectSoundBuffer", IDIRECTSOUNDBUFFER, {0x85, 0xFA, 0x9A, 0x27, 0x81, 0x49, 0xCE, 0x11, 0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60}, 0},
    {"IDirectSound3DListener", IDIRECTSOUND3DLISTENER, {0x84, 0xFA, 0x9A, 0x27, 0x81, 0x49, 0xCE, 0x11, 0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60}, 0},
    {"IDirectSound3DBuffer", IDIRECTSOUND3DBUFFER, {0x86, 0xFA, 0x9A, 0x27, 0x81, 0x49, 0xCE, 0x11, 0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60}, 0},
    {"IDirectSoundNotify", IDIRECTSOUNDNOTIFY, {0x83, 0x07, 0x21, 0xB0, 0xCD, 0x89, 0xD0, 0x11, 0xAF, 0x08, 0x00, 0xA0, 0xC9, 0x25, 0xCD, 0x16}, 0},
};
static const uint8_t IID_IUNKNOWN[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46};
static const uint8_t CLSID_DIRECTSOUND[16] = {0x46, 0xD9, 0xD4, 0x47, 0xE8, 0x62, 0xCF, 0x11, 0x93, 0xBC, 0x44, 0x45,
                                              0x53, 0x54, 0x00, 0x00};
static const uint8_t CLSID_DIRECTSOUND8[16] = {0x3F, 0xCC, 0x01, 0x39, 0xB5, 0x84, 0xA4, 0x4F, 0xBA, 0x35, 0xAA, 0x81,
                                               0x72, 0xB8, 0xA0, 0x9B};
static const uint8_t DEVICE_GUID[16] = {0xC3, 0xF6, 0xE2, 0xA5, 0x1D, 0x1B, 0x8E, 0x4C, 0x9F, 0x3A, 0x6D, 0x1F, 0x4E,
                                        0x7B, 0x2C, 0x90};   /* A5E2F6C3-1B1D-4C8E-9F3A-6D1F4E7B2C90 */

static inline uint32_t r32(uint32_t p) { uint32_t v; memcpy(&v, gptr(p), 4); return v; }
static inline void w32(uint32_t p, uint32_t v) { memcpy(gptr(p), &v, 4); }
static inline void out32(uint32_t p, uint32_t v) { if (p) w32(p, v); }
static inline float f32(uint32_t v) { float f; memcpy(&f, &v, 4); return f; }

/* ---------------------------------------------------------------- the mixer (libmpaudio, audio/mpaudio.c) */
typedef struct mpa mpa;
mpa *mpa_create(int rate, int device);
void mpa_destroy(mpa *m);
int mpa_record(mpa *m, const char *path);
int mpa_voice_new(mpa *m, int channels, int bits, int rate, uint32_t size);
void mpa_voice_free(mpa *m, int id);
void mpa_voice_write(mpa *m, int id, uint32_t offset, const void *data, uint32_t len);
void mpa_voice_play(mpa *m, int id, int looping);
void mpa_voice_stop(mpa *m, int id);
void mpa_voice_set_pos(mpa *m, int id, uint32_t byte);
uint32_t mpa_voice_get_pos(mpa *m, int id, int *playing);
void mpa_voice_set_freq(mpa *m, int id, double hz);
void mpa_voice_set_gain(mpa *m, int id, float left, float right, int downmix);
uint64_t mpa_frames_out(mpa *m);
const char *mpa_last_error(void);

#define MIX_RATE 44100
static int g_audio = -2;                        /* mpa_create's device: 1 device, 0 null, -2 none (--audio off) */
static const char *g_audio_wav;
static mpa *g_mx;
static int g_mx_made;

void host_audio_set(int device, const char *wav)
{
    g_audio = device;
    g_audio_wav = wav;
}

/* dsound.mixer: made on first use when there is to be sound; hle_fast.c calls it too (its voice writes, positions,
 * gains) */
void *host_mixer(void)
{
    if (g_mx_made)
        return g_mx;
    g_mx_made = 1;
    if (g_audio < -1)
        return NULL;
    g_mx = mpa_create(MIX_RATE, g_audio);
    if (!g_mx && g_audio == 1) {
        printf("[dsound] no audio device (%s); mixing silently\n", mpa_last_error());
        g_mx = mpa_create(MIX_RATE, 0);
    }
    if (g_mx && g_audio_wav && mpa_record(g_mx, g_audio_wav))
        host_fatal("%s", mpa_last_error());
    if (g_mx)
        host_ds_mixer(g_mx, (void *)mpa_voice_write, (void *)mpa_voice_get_pos, (void *)mpa_voice_set_gain);
    return g_mx;
}

void host_audio_close(void)
{
    if (!g_mx)
        return;
    printf("audio: %.1fs mixed%s%s\n", (double)mpa_frames_out(g_mx) / MIX_RATE, g_audio_wav ? " -> " : "",
           g_audio_wav ? g_audio_wav : "");
    host_ds_mixer(NULL, NULL, NULL, NULL);
    mpa_destroy(g_mx);
    g_mx = NULL;
}

/* time.perf_counter() on macOS, as hle_fast.c's perf_counter (the buffers' clock cursor compares the two) */
static double perf_counter(void)
{
    if (host_clock_sim_fps())
        return (double)host_clock_ns() / 1e9;
    static mach_timebase_info_data_t tb;
    if (!tb.denom)
        mach_timebase_info(&tb);
    return (double)(uint64_t)((__uint128_t)mach_absolute_time() * tb.numer / tb.denom) / 1e9;
}

/* ---------------------------------------------------------------- objects */
typedef struct { uint16_t tag, channels; uint32_t rate, avg; uint16_t align, bits; } Wfx;
typedef struct {
    float position[3], velocity[3], cone_orientation[3], min_distance, max_distance;
    uint32_t inside_angle, outside_angle, mode;
    int32_t outside_volume;
} P3;
typedef struct {
    float position[3], velocity[3], front[3], top[3], distance_factor, rolloff_factor, doppler_factor;
} Listener;

typedef struct {
    uint32_t addr;
    int iface;
    /* IDirectSound */
    uint32_t coop, primary;
    int uninitialized;
    /* IDirectSoundBuffer: the layout and the Python-side state; the run state is hle_fast.c's (slot) */
    uint32_t flags, size, ptr, ds;
    int has_wfx, slot, has_p3;
    Wfx wfx;
    int32_t pan;
    uint32_t freq;
    uint32_t sub[3];            /* the 3D buffer, listener and notify interfaces handed out (0: not yet) */
    P3 p3;
    /* the 3D buffer, listener and notify interfaces: their buffer */
    uint32_t buffer;
} Obj;

static Obj **g_objs;
static uint32_t g_nobjs, g_capobjs;

static Obj *find(uint32_t a)
{
    for (uint32_t i = g_nobjs; i-- > 0;)
        if (g_objs[i]->addr == a)
            return g_objs[i];
    return NULL;
}

static Obj *self(uint32_t a, int iface)
{
    Obj *o = find(a);
    if (!o || o->iface != iface)
        host_fatal("DSOUND: 0x%x is no %s", a, g_ifaces[iface].name);
    return o;
}

static uint32_t vtable(int i)
{
    if (!g_ifaces[i].vtable) {
        uint32_t n = 0;
        while (g_ifaces[i].m[n].name)
            n++;
        uint32_t p = host_alloc(4 * n);
        for (uint32_t k = 0; k < n; k++) {
            char name[128];
            snprintf(name, sizeof name, "%s::%s", g_ifaces[i].name, g_ifaces[i].m[k].name);
            w32(p + 4 * k, host_stub_for(DS, name));
        }
        g_ifaces[i].vtable = p;
    }
    return g_ifaces[i].vtable;
}

static Obj *new_obj(int iface)
{
    uint32_t a = host_alloc(16);
    w32(a, vtable(iface));
    w32(a + 4, 1);
    Obj *o = calloc(1, sizeof *o);
    o->addr = a;
    o->iface = iface;
    o->slot = -1;
    if (g_nobjs == g_capobjs) {
        g_capobjs = g_capobjs ? 2 * g_capobjs : 64;
        g_objs = realloc(g_objs, g_capobjs * sizeof *g_objs);
    }
    g_objs[g_nobjs++] = o;
    return o;
}

/* the buffer's layout to hle_fast.c (_FastBuf._push_cfg) */
static void push_cfg(Obj *b) { host_ds_cfg(b->slot, b->ptr, b->size, b->has_wfx, b->wfx.avg, b->wfx.align); }

enum { F_VOLUME, F_PLAYING, F_LOOPING, F_POS, F_STARTED, F_UNLOCKS, F_WRITTEN, F_VOICE };
static double field(Obj *b, int f) { return host_ds_field(b->slot, f, 0, 0); }
static void set_field(Obj *b, int f, double v) { host_ds_field(b->slot, f, 1, v); }
static int voice(Obj *b) { return (int)field(b, F_VOICE); }

/* ---------------------------------------------------------------- gains (dsound.py db_gain, pan_gains, gains_3d) */
#define SPEED_OF_SOUND 343.3
#define FAR_EAR_DB (-12.0)
#define DS3DMODE_HEADRELATIVE 1u
#define DS3DMODE_DISABLE 2u

/* pow through a pointer: clang turns pow(10.0, x) into exp10(x), which rounds differently from Python's pow */
static double (*volatile p_pow)(double, double) = pow;
static double db_gain(int32_t h) { return h <= -10000 ? 0.0 : p_pow(10.0, (h < 0 ? h : 0) / 2000.0); }
static double dot(const double *a, const double *b) { return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]; }

static void unit(const double *a, double *out)
{
    double n = sqrt(dot(a, a));
    for (int i = 0; i < 3; i++)
        out[i] = n > 1e-9 ? a[i] / n : 0.0;
}

static void vec_d(const float *f, double *d) { d[0] = f[0], d[1] = f[1], d[2] = f[2]; }

static Listener g_listener = {{0, 0, 0}, {0, 0, 0}, {0, 0, 1}, {0, 1, 0}, 1, 1, 1};

/* left gain, right gain and doppler frequency ratio of a 3D buffer heard by the listener: full volume up to the
 * minimum distance, then min / (min + rolloff * (d - min)) up to the maximum; the cone between its angles, in dB; the
 * far ear attenuated by up to FAR_EAR_DB as the source moves to the side; left-handed coordinates */
static void gains_3d(const P3 *q, double *gl, double *gr, double *ratio)
{
    const Listener *l = &g_listener;
    double rel[3], right[3], front[3], top[3], lvel[3], qpos[3], qvel[3], cone[3];
    vec_d(q->position, qpos), vec_d(q->velocity, qvel), vec_d(q->cone_orientation, cone);
    if (q->mode == DS3DMODE_HEADRELATIVE) {
        memcpy(rel, qpos, sizeof rel);
        right[0] = 1, right[1] = 0, right[2] = 0;
        lvel[0] = lvel[1] = lvel[2] = 0;
    } else {
        double lp[3], lf[3], lt[3], cr[3];
        vec_d(l->position, lp), vec_d(l->front, lf), vec_d(l->top, lt), vec_d(l->velocity, lvel);
        for (int i = 0; i < 3; i++)
            rel[i] = qpos[i] - lp[i];
        unit(lf, front), unit(lt, top);
        cr[0] = top[1] * front[2] - top[2] * front[1];
        cr[1] = top[2] * front[0] - top[0] * front[2];
        cr[2] = top[0] * front[1] - top[1] * front[0];
        unit(cr, right);
    }
    double d = sqrt(dot(rel, rel));
    double mind = q->min_distance, maxd = q->max_distance;
    double mn = mind > 1e-6 ? mind : 1e-6, mx = maxd > mind ? maxd : mind;
    double dd = d < mx ? d : mx;
    double gain = dd <= mn ? 1.0 : mn / (mn + (double)l->rolloff_factor * (dd - mn));
    double inside = q->inside_angle, outside = q->outside_angle;
    if (d > 1e-6 && inside < 360 && dot(cone, cone) > 0) {
        double to_l[3] = {-rel[0] / d, -rel[1] / d, -rel[2] / d}, uc[3];
        unit(cone, uc);
        double cc = dot(uc, to_l);
        cc = cc > 1.0 ? 1.0 : cc < -1.0 ? -1.0 : cc;
        double angle = acos(cc) * (180.0 / M_PI) * 2;   /* math.degrees: x * (180 / pi) */
        if (angle > inside) {
            double t = angle >= outside || outside <= inside ? 1.0 : (angle - inside) / (outside - inside);
            gain *= db_gain((int32_t)(q->outside_volume * t));
        }
    }
    *gl = *gr = gain;
    if (d > 1e-6) {
        double x = dot(rel, right) / d;         /* -1 left .. 1 right */
        double far = p_pow(10.0, FAR_EAR_DB * fabs(x) / 20.0);
        if (x > 0)
            *gl *= far;
        else
            *gr *= far;
    }
    *ratio = 1.0;
    if (d > 1e-6 && l->doppler_factor > 0) {
        double df = l->distance_factor;
        double c_units = SPEED_OF_SOUND / (df > 1e-6 ? df : 1e-6);
        double u[3] = {-rel[0] / d, -rel[1] / d, -rel[2] / d}, k = l->doppler_factor;
        double num = c_units - k * dot(lvel, u), den = c_units - k * dot(qvel, u);
        if (den > 1e-6 && num > 0) {
            double r = num / den;
            *ratio = r < 0.5 ? 0.5 : r > 2.0 ? 2.0 : r;
        }
    }
}

/* update_voice: the buffer's volume, pan, frequency and 3D state to its voice (and the gains to hle_fast.c, whose
 * SetVolume applies them) */
static void update_voice(Obj *b)
{
    int v = voice(b);
    if (v < 0)
        return;
    double vol = db_gain((int32_t)field(b, F_VOLUME)), gl, gr, freq = b->freq ? b->freq : b->wfx.rate;
    int downmix;
    if (b->has_p3 && b->p3.mode != DS3DMODE_DISABLE) {
        double doppler;
        gains_3d(&b->p3, &gl, &gr, &doppler);
        downmix = 1;
        freq *= doppler;
    } else {
        gl = b->pan > 0 ? db_gain(-b->pan) : 1.0;
        gr = b->pan < 0 ? db_gain(b->pan) : 1.0;
        downmix = 0;
    }
    host_ds_gains(b->slot, gl, gr, downmix);
    mpa_voice_set_gain(g_mx, v, (float)(vol * gl), (float)(vol * gr), downmix);
    mpa_voice_set_freq(g_mx, v, freq);
}

static void free_voice(Obj *b)
{
    int v = voice(b);
    if (v < 0)
        return;
    mpa_voice_free(g_mx, v);
    set_field(b, F_VOICE, -1);
}

/* new_buffer: the data first, then the object, registered with hle_fast.c; a voice for a secondary buffer when there
 * is a mixer; the 3D parameters; the voice's gains */
static Obj *new_buffer(uint32_t flags, uint32_t nbytes, const Wfx *wfx, uint32_t ds)
{
    uint32_t size = nbytes > 16 ? nbytes : 16;
    uint32_t ptr = host_alloc(size);
    Obj *b = new_obj(I_BUF);
    b->flags = flags, b->size = size, b->ptr = ptr, b->ds = ds;
    if (wfx)
        b->wfx = *wfx, b->has_wfx = 1;
    b->slot = host_ds_new(b->addr);
    push_cfg(b);
    set_field(b, F_VOICE, -1);
    if (wfx && !(flags & 0x1) && host_mixer()) {
        int v = mpa_voice_new(g_mx, wfx->channels, wfx->bits, (int)wfx->rate, size);
        if (v >= 0)
            set_field(b, F_VOICE, v);
    }
    if ((flags & 0x10) && !(flags & 0x1)) {
        b->has_p3 = 1;
        b->p3 = (P3){{0, 0, 0}, {0, 0, 0}, {0, 0, 1}, 1.0f, 1e9f, 360, 360, 0, 0};
    }
    update_voice(b);
    return b;
}

/* ---------------------------------------------------------------- the 3D listener and deferred settings */
/* a change: which setter and its values, applied to the listener (buf NULL) or a 3D buffer's parameters */
typedef struct { int kind; Obj *buf; float f[15]; uint32_t u[4]; } Change;
enum { C_POS, C_VEL, C_ORIENT, C_DIST, C_DOPPLER, C_ROLLOFF, C_LALL,
       C_CONE_ORIENT, C_CONE_ANGLES, C_CONE_VOL, C_MIN, C_MAX, C_MODE, C_BALL };
static Change *g_deferred;
static uint32_t g_ndeferred, g_capdeferred;

static void apply(const Change *ch)
{
    Listener *l = &g_listener;
    P3 *q = ch->buf ? &ch->buf->p3 : NULL;
    switch (ch->kind) {
    case C_POS: memcpy(q ? q->position : l->position, ch->f, 12); break;
    case C_VEL: memcpy(q ? q->velocity : l->velocity, ch->f, 12); break;
    case C_ORIENT: memcpy(l->front, ch->f, 12), memcpy(l->top, ch->f + 3, 12); break;
    case C_DIST: l->distance_factor = ch->f[0]; break;
    case C_DOPPLER: l->doppler_factor = ch->f[0]; break;
    case C_ROLLOFF: l->rolloff_factor = ch->f[0]; break;
    case C_LALL:
        memcpy(l->position, ch->f, 12), memcpy(l->velocity, ch->f + 3, 12), memcpy(l->front, ch->f + 6, 12);
        memcpy(l->top, ch->f + 9, 12);
        l->distance_factor = ch->f[12], l->rolloff_factor = ch->f[13], l->doppler_factor = ch->f[14];
        break;
    case C_CONE_ORIENT: memcpy(q->cone_orientation, ch->f, 12); break;
    case C_CONE_ANGLES: q->inside_angle = ch->u[0], q->outside_angle = ch->u[1]; break;
    case C_CONE_VOL: q->outside_volume = (int32_t)ch->u[0]; break;
    case C_MIN: q->min_distance = ch->f[0]; break;
    case C_MAX: q->max_distance = ch->f[0]; break;
    case C_MODE: q->mode = ch->u[0]; break;
    case C_BALL:
        memcpy(q->position, ch->f, 12), memcpy(q->velocity, ch->f + 3, 12), memcpy(q->cone_orientation, ch->f + 6, 12);
        q->min_distance = ch->f[9], q->max_distance = ch->f[10];
        q->inside_angle = ch->u[0], q->outside_angle = ch->u[1], q->mode = ch->u[2];
        q->outside_volume = (int32_t)ch->u[3];
        break;
    }
}

/* refresh_3d: the listener moved (every 3D buffer's voice, in creation order) or one 3D buffer changed */
static void refresh_3d(Obj *buf)
{
    if (buf) {
        update_voice(buf);
        return;
    }
    for (uint32_t i = 0; i < g_nobjs; i++)
        if (g_objs[i]->iface == I_BUF && g_objs[i]->has_p3)
            update_voice(g_objs[i]);
}

static void apply_param(const Change *ch, uint32_t flag)
{
    if (flag & DS3D_DEFERRED) {
        if (g_ndeferred == g_capdeferred) {
            g_capdeferred = g_capdeferred ? 2 * g_capdeferred : 64;
            g_deferred = realloc(g_deferred, g_capdeferred * sizeof *g_deferred);
        }
        g_deferred[g_ndeferred++] = *ch;
        return;
    }
    apply(ch);
    refresh_3d(ch->buf);
}

static void put_vec(uint32_t p, const float *v) { if (p) memcpy(gptr(p), v, 12); }

/* ---------------------------------------------------------------- IUnknown, per interface */
H(AddRef)
{
    UNUSED;
    uint32_t n = r32(a[0] + 4) + 1;
    w32(a[0] + 4, n);
    return n;
}

/* released: a buffer stops sounding when its last reference goes (and its 3D interface's); releasing a DirectSound
 * object frees the voices of all its buffers */
H(Release)
{
    UNUSED;
    uint32_t n = r32(a[0] + 4);
    n = n ? n - 1 : 0;
    w32(a[0] + 4, n);
    Obj *o = find(a[0]);
    if (n || !o)
        return n;
    if (o->iface == I_3DBUF)
        o = find(o->buffer);
    if (o && o->iface == I_BUF) {
        if (r32(o->addr + 4) == 0 && !(o->sub[0] && r32(o->sub[0] + 4)))
            free_voice(o);
    } else if (o && o->iface == I_DS) {
        for (uint32_t i = 0; i < g_nobjs; i++)
            if (g_objs[i]->iface == I_BUF && g_objs[i]->ds == o->addr)
                free_voice(g_objs[i]);
    }
    return n;
}

/* sub_obj: the interface a buffer hands out (one per buffer, created unreferenced) */
static uint32_t sub_obj(Obj *b, int k, int iface)
{
    if (!b->sub[k]) {
        Obj *s = new_obj(iface);
        s->buffer = b->addr;
        w32(s->addr + 4, 0);
        b->sub[k] = s->addr;
    }
    return b->sub[k];
}

static uint32_t query(int iface, const uint32_t *a)
{
    const uint8_t *want = gptr(a[1]);
    Obj *o = find(a[0]);
    uint32_t flags = o && o->iface == I_BUF ? o->flags : 0, result = 0;
    if (!memcmp(want, IID_IUNKNOWN, 16) || !memcmp(want, g_ifaces[iface].iid, 16))
        result = a[0];
    else if (iface == I_BUF && !memcmp(want, g_ifaces[I_3DBUF].iid, 16) && (flags & 0x10))
        result = sub_obj(o, 0, I_3DBUF);
    else if (iface == I_BUF && !memcmp(want, g_ifaces[I_LISTENER].iid, 16) && (flags & 0x1) && (flags & 0x10))
        result = sub_obj(o, 1, I_LISTENER);
    else if (iface == I_BUF && !memcmp(want, g_ifaces[I_NOTIFY].iid, 16) && (flags & 0x100))
        result = sub_obj(o, 2, I_NOTIFY);
    if (!result) {
        out32(a[2], 0);
        return E_NOINTERFACE;
    }
    w32(result + 4, r32(result + 4) + 1);
    out32(a[2], result);
    return DS_OK;
}

H(QiDs) { UNUSED; return query(I_DS, a); }
H(QiBuf) { UNUSED; return query(I_BUF, a); }
H(QiListener) { UNUSED; return query(I_LISTENER, a); }
H(Qi3dBuf) { UNUSED; return query(I_3DBUF, a); }
H(QiNotify) { UNUSED; return query(I_NOTIFY, a); }
H(Ok) { UNUSED; return DS_OK; }

/* ---------------------------------------------------------------- enumeration and creation */
/* DirectSoundEnumerateA(callback, context): the default device (NULL guid), then the named one, until the callback
 * returns FALSE */
H(DirectSoundEnumerateA)
{
    uint32_t dev = host_alloc(16);
    memcpy(gptr(dev), DEVICE_GUID, 16);
    static const char *const DEV[2][2] = {{"Primary Sound Driver", ""}, {"Apple CoreAudio (emulated)", "coreaudio.drv"}};
    for (int i = 0; i < 2; i++) {
        uint32_t pd = host_alloc((uint32_t)strlen(DEV[i][0]) + 1), pm = host_alloc((uint32_t)strlen(DEV[i][1]) + 1);
        memcpy(gptr(pd), DEV[i][0], strlen(DEV[i][0]) + 1);
        memcpy(gptr(pm), DEV[i][1], strlen(DEV[i][1]) + 1);
        uint32_t args[4] = {i ? dev : 0, pd, pm, a[1]};
        if (!host_guest_call(c, a[0], 4, args))
            break;
    }
    return DS_OK;
}

H(DirectSoundCreate)
{
    UNUSED;
    if (a[2])
        return DSERR_NOAGGREGATION;
    out32(a[1], new_obj(I_DS)->addr);
    return DS_OK;
}

/* the DirectSound COM classes (CoCreateInstance, hle_dshow.c); -1: not one of them */
int64_t host_dsound_com(const uint8_t *clsid, uint32_t outer, uint32_t ppv)
{
    if (memcmp(clsid, CLSID_DIRECTSOUND, 16) && memcmp(clsid, CLSID_DIRECTSOUND8, 16))
        return -1;
    if (outer) {
        out32(ppv, 0);
        return DSERR_NOAGGREGATION;
    }
    Obj *o = new_obj(I_DS);
    o->uninitialized = 1;
    out32(ppv, o->addr);
    return DS_OK;
}

/* ---------------------------------------------------------------- IDirectSound */
H(DsGetCaps)
{
    UNUSED;
    (void)self(a[0], I_DS);
    uint32_t size = r32(a[1]), k[24] = {0};
    k[0] = size ? size : 96;
    k[1] = 0x2 | 0x8 | 0x10 | 0x200 | 0x800;   /* primary stereo/16-bit, continuous rate, secondary stereo/16-bit */
    k[2] = 4000, k[3] = 96000;                  /* secondary sample rate range */
    k[4] = 1;                                   /* primary buffers */
    k[20] = 100000;                             /* unlock transfer rate (KB/s) */
    uint32_t n = size ? (size < 96 ? (size > 4 ? size : 4) : 96) : 96;
    memcpy(gptr(a[1]), k, n);
    return DS_OK;
}

H(SetCooperativeLevel)
{
    UNUSED;
    self(a[0], I_DS)->coop = a[2];
    return DS_OK;
}

H(DsInitialize)
{
    UNUSED;
    Obj *o = self(a[0], I_DS);
    if (!o->uninitialized)
        return DSERR_ALREADYINITIALIZED;
    o->uninitialized = 0;
    return DS_OK;
}

H(GetSpeakerConfig) { UNUSED; out32(a[1], 0x4); return DS_OK; }   /* STEREO */

static Wfx read_wfx(uint32_t p)
{
    Wfx w;
    uint8_t *s = gptr(p);
    memcpy(&w.tag, s, 2), memcpy(&w.channels, s + 2, 2), memcpy(&w.rate, s + 4, 4), memcpy(&w.avg, s + 8, 4);
    memcpy(&w.align, s + 12, 2), memcpy(&w.bits, s + 14, 2);
    return w;
}

H(CreateSoundBuffer)
{
    UNUSED;
    Obj *ds = self(a[0], I_DS);
    if (a[3])
        return DSERR_NOAGGREGATION;
    uint32_t flags = r32(a[1] + 4), nbytes = r32(a[1] + 8), pwfx = r32(a[1] + 16);
    Obj *b;
    if (flags & 0x1) {                          /* the primary buffer: no format, no size */
        b = new_buffer(flags, 4096, NULL, 0);
        ds->primary = b->addr;
    } else {
        if (!pwfx)
            return DSERR_INVALIDPARAM;
        Wfx w = read_wfx(pwfx);
        b = new_buffer(flags, nbytes, &w, a[0]);
    }
    out32(a[2], b->addr);
    return DS_OK;
}

H(DuplicateSoundBuffer)
{
    UNUSED;
    Obj *s = find(a[1]);
    if (!s || s->iface != I_BUF)
        return DSERR_INVALIDPARAM;
    Obj *d = new_buffer(s->flags, s->size, s->has_wfx ? &s->wfx : NULL, a[0]);
    memmove(gptr(d->ptr), gptr(s->ptr), s->size);
    if (voice(d) >= 0)
        mpa_voice_write(g_mx, voice(d), 0, gptr(d->ptr), s->size);
    set_field(d, F_VOLUME, field(s, F_VOLUME));
    d->pan = s->pan, d->freq = s->freq;
    update_voice(d);
    out32(a[2], d->addr);
    return DS_OK;
}

/* ---------------------------------------------------------------- IDirectSoundBuffer */
/* play_cursor: the voice's position, or without one the clock cursor (hle_fast.c ds_play_cursor) */
static uint32_t play_cursor(Obj *b, int *playing)
{
    if (voice(b) >= 0) {
        uint32_t pos = mpa_voice_get_pos(g_mx, voice(b), playing);
        set_field(b, F_PLAYING, *playing != 0);
        return pos;
    }
    if (!field(b, F_PLAYING)) {
        *playing = 0;
        return (uint32_t)field(b, F_POS);
    }
    double rate = b->has_wfx && b->wfx.avg ? b->wfx.avg : 44100.0 * 4;
    uint64_t pos = (uint64_t)field(b, F_POS) + (uint64_t)((perf_counter() - field(b, F_STARTED)) * rate);
    *playing = 1;
    if (field(b, F_LOOPING))
        return (uint32_t)(pos % b->size);
    if (pos >= b->size) {
        set_field(b, F_PLAYING, 0);
        set_field(b, F_POS, 0);
        *playing = 0;
        return 0;
    }
    return (uint32_t)pos;
}

static uint32_t write_cursor(Obj *b, uint32_t *play)
{
    int playing;
    uint32_t p = play_cursor(b, &playing);
    *play = p;
    if (!playing || !b->has_wfx)
        return p;
    return (uint32_t)(((uint64_t)p + (uint64_t)WRITE_LEAD_FRAMES * b->wfx.align) % b->size);
}

H(GetCurrentPosition)
{
    UNUSED;
    uint32_t play, w = write_cursor(self(a[0], I_BUF), &play);
    out32(a[1], play);
    out32(a[2], w);
    return DS_OK;
}

H(GetStatus)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    int playing;
    play_cursor(b, &playing);
    out32(a[1], (playing ? DSBSTATUS_PLAYING : 0) | (playing && field(b, F_LOOPING) ? DSBSTATUS_LOOPING : 0));
    return DS_OK;
}

H(Play)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    set_field(b, F_PLAYING, 1);
    set_field(b, F_LOOPING, (a[3] & DSBPLAY_LOOPING) != 0);
    set_field(b, F_STARTED, perf_counter());
    if (voice(b) >= 0)
        mpa_voice_play(g_mx, voice(b), (a[3] & DSBPLAY_LOOPING) != 0);
    return DS_OK;
}

H(Stop)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    int playing;
    set_field(b, F_POS, play_cursor(b, &playing));
    set_field(b, F_PLAYING, 0);
    if (voice(b) >= 0)
        mpa_voice_stop(g_mx, voice(b));
    return DS_OK;
}

H(SetCurrentPosition)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    set_field(b, F_POS, a[1] % b->size);
    set_field(b, F_STARTED, perf_counter());
    if (voice(b) >= 0)
        mpa_voice_set_pos(g_mx, voice(b), (uint32_t)field(b, F_POS));
    return DS_OK;
}

/* Lock(off, nbytes, pp1, pcb1, pp2, pcb2, flags): what hle_fast.c declined */
H(Lock)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    uint32_t off = a[1], n = a[2], play;
    if (a[7] & DSBLOCK_ENTIREBUFFER)
        off = 0, n = b->size;
    else if (a[7] & DSBLOCK_FROMWRITECURSOR)
        off = write_cursor(b, &play);
    if (off >= b->size || n > b->size)
        return DSERR_INVALIDPARAM;
    uint32_t first = n < b->size - off ? n : b->size - off;
    out32(a[3], b->ptr + off);
    out32(a[4], first);
    out32(a[5], n > first ? b->ptr : 0);
    out32(a[6], n > first ? n - first : 0);
    return DS_OK;
}

H(Unlock)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    set_field(b, F_UNLOCKS, field(b, F_UNLOCKS) + 1);
    set_field(b, F_WRITTEN, field(b, F_WRITTEN) + (double)a[2] + (double)a[4]);
    for (int k = 0; k < 2 && voice(b) >= 0; k++) {     /* the written regions to the mixer */
        uint32_t p = a[1 + 2 * k], n = a[2 + 2 * k];
        int64_t off = (int64_t)p - b->ptr;
        if (p && n && off >= 0 && off < b->size) {
            if (n > b->size - off)
                n = (uint32_t)(b->size - off);
            mpa_voice_write(g_mx, voice(b), (uint32_t)off, gptr(p), n);
        }
    }
    return DS_OK;
}

H(BufInitialize) { UNUSED; return DSERR_ALREADYINITIALIZED; }

H(SetFormat)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    if (b->has_wfx)
        return DSERR_UNSUPPORTED;
    b->wfx = read_wfx(a[1]);                    /* the primary buffer: remember the requested format */
    b->has_wfx = 1;
    push_cfg(b);
    return DS_OK;
}

H(GetFormat)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    Wfx w = b->has_wfx ? b->wfx : (Wfx){1, 2, 22050, 88200, 4, 16};
    if (a[1]) {
        uint8_t *p = gptr(a[1]);
        memcpy(p, &w.tag, 2), memcpy(p + 2, &w.channels, 2), memcpy(p + 4, &w.rate, 4), memcpy(p + 8, &w.avg, 4);
        memcpy(p + 12, &w.align, 2), memcpy(p + 14, &w.bits, 2), memset(p + 16, 0, 2);
    }
    out32(a[3], 18);
    return DS_OK;
}

H(BufGetCaps)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    uint32_t v[5] = {20, b->flags, b->size, 0, 0};
    memcpy(gptr(a[1]), v, 20);
    return DS_OK;
}

H(GetVolume) { UNUSED; out32(a[1], (uint32_t)(int32_t)field(self(a[0], I_BUF), F_VOLUME)); return DS_OK; }
H(GetPan) { UNUSED; out32(a[1], (uint32_t)self(a[0], I_BUF)->pan); return DS_OK; }
H(GetFrequency) { UNUSED; out32(a[1], self(a[0], I_BUF)->freq); return DS_OK; }
/* (and update_voice: no voice) */
H(SetVolume)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    set_field(b, F_VOLUME, (int32_t)a[1]);
    update_voice(b);
    return DS_OK;
}

H(SetPan)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    b->pan = (int32_t)a[1];
    update_voice(b);
    return DS_OK;
}

H(SetFrequency)
{
    UNUSED;
    Obj *b = self(a[0], I_BUF);
    b->freq = a[1];
    update_voice(b);
    return DS_OK;
}

/* ---------------------------------------------------------------- IDirectSound3DListener */
#define LSET(name, kind, nvals)                                                                                       \
    H(name)                                                                                                           \
    {                                                                                                                 \
        UNUSED;                                                                                                       \
        Change ch = {kind, NULL, {0}, {0}};                                                                           \
        for (int i = 0; i < (nvals); i++)                                                                             \
            ch.f[i] = f32(a[1 + i]);                                                                                  \
        apply_param(&ch, a[1 + (nvals)]);                                                                             \
        return DS_OK;                                                                                                 \
    }
LSET(LSetPosition, C_POS, 3)
LSET(LSetVelocity, C_VEL, 3)
LSET(LSetOrientation, C_ORIENT, 6)
LSET(LSetDistanceFactor, C_DIST, 1)
LSET(LSetDopplerFactor, C_DOPPLER, 1)
LSET(LSetRolloffFactor, C_ROLLOFF, 1)

H(LSetAllParameters)
{
    UNUSED;
    Change ch = {C_LALL, NULL, {0}, {0}};
    memcpy(ch.f, gptr(a[1] + 4), 60);
    apply_param(&ch, a[2]);
    return DS_OK;
}

H(LGetAllParameters)
{
    UNUSED;
    Listener *l = &g_listener;
    float v[15];
    memcpy(v, l->position, 12), memcpy(v + 3, l->velocity, 12), memcpy(v + 6, l->front, 12), memcpy(v + 9, l->top, 12);
    v[12] = l->distance_factor, v[13] = l->rolloff_factor, v[14] = l->doppler_factor;
    memcpy(gptr(a[1] + 4), v, 60);
    return DS_OK;
}

H(LGetPosition) { UNUSED; put_vec(a[1], g_listener.position); return DS_OK; }
H(LGetVelocity) { UNUSED; put_vec(a[1], g_listener.velocity); return DS_OK; }

H(LGetOrientation)
{
    UNUSED;
    put_vec(a[1], g_listener.front);
    put_vec(a[2], g_listener.top);
    return DS_OK;
}

H(LGetDistanceFactor) { UNUSED; memcpy(gptr(a[1]), &g_listener.distance_factor, 4); return DS_OK; }
H(LGetDopplerFactor) { UNUSED; memcpy(gptr(a[1]), &g_listener.doppler_factor, 4); return DS_OK; }
H(LGetRolloffFactor) { UNUSED; memcpy(gptr(a[1]), &g_listener.rolloff_factor, 4); return DS_OK; }

/* the deferred changes in order, then the voices: every 3D buffer's if the listener was among them, else each
 * changed buffer's once, in the order first changed */
H(CommitDeferredSettings)
{
    UNUSED;
    uint32_t n = g_ndeferred;
    g_ndeferred = 0;
    int listener = 0;
    for (uint32_t i = 0; i < n; i++) {
        apply(&g_deferred[i]);
        listener |= !g_deferred[i].buf;
    }
    if (listener) {
        refresh_3d(NULL);
        return DS_OK;
    }
    for (uint32_t i = 0; i < n; i++) {
        int seen = 0;
        for (uint32_t j = 0; j < i && !seen; j++)
            seen = g_deferred[j].buf == g_deferred[i].buf;
        if (!seen)
            refresh_3d(g_deferred[i].buf);
    }
    return DS_OK;
}

/* ---------------------------------------------------------------- IDirectSound3DBuffer */
static Obj *p3buf(uint32_t this)
{
    Obj *b = find(self(this, I_3DBUF)->buffer);
    if (!b || !b->has_p3)
        host_fatal("DSOUND: the buffer of 3D buffer 0x%x has no 3D parameters", this);
    return b;
}

static P3 *p3(uint32_t this) { return &p3buf(this)->p3; }

#define BSET(name, kind, nf, nu)                                                                                      \
    H(name)                                                                                                           \
    {                                                                                                                 \
        UNUSED;                                                                                                       \
        Change ch = {kind, p3buf(a[0]), {0}, {0}};                                                                    \
        for (int i = 0; i < (nf); i++)                                                                                \
            ch.f[i] = f32(a[1 + i]);                                                                                  \
        for (int i = 0; i < (nu); i++)                                                                                \
            ch.u[i] = a[1 + i];                                                                                       \
        apply_param(&ch, a[1 + (nf) + (nu)]);                                                                         \
        return DS_OK;                                                                                                 \
    }
BSET(BSetPosition, C_POS, 3, 0)
BSET(BSetVelocity, C_VEL, 3, 0)
BSET(BSetConeOrientation, C_CONE_ORIENT, 3, 0)
BSET(BSetConeAngles, C_CONE_ANGLES, 0, 2)
BSET(BSetConeOutsideVolume, C_CONE_VOL, 0, 1)
BSET(BSetMinDistance, C_MIN, 1, 0)
BSET(BSetMaxDistance, C_MAX, 1, 0)
BSET(BSetMode, C_MODE, 0, 1)

/* DS3DBUFFER after dwSize: position, velocity, inside/outside angle, cone orientation, outside volume, min, max, mode */
H(BSetAllParameters)
{
    UNUSED;
    Change ch = {C_BALL, p3buf(a[0]), {0}, {0}};
    uint32_t v[15];
    memcpy(v, gptr(a[1] + 4), 60);
    for (int i = 0; i < 6; i++)
        ch.f[i] = f32(v[i]);
    ch.u[0] = v[6], ch.u[1] = v[7];
    for (int i = 0; i < 3; i++)
        ch.f[6 + i] = f32(v[8 + i]);
    ch.u[3] = v[11];
    ch.f[9] = f32(v[12]), ch.f[10] = f32(v[13]);
    ch.u[2] = v[14];
    apply_param(&ch, a[2]);
    return DS_OK;
}

H(BGetAllParameters)
{
    UNUSED;
    P3 *q = p3(a[0]);
    uint8_t *p = gptr(a[1] + 4);
    memcpy(p, q->position, 12), memcpy(p + 12, q->velocity, 12);
    memcpy(p + 24, &q->inside_angle, 4), memcpy(p + 28, &q->outside_angle, 4);
    memcpy(p + 32, q->cone_orientation, 12), memcpy(p + 44, &q->outside_volume, 4);
    memcpy(p + 48, &q->min_distance, 4), memcpy(p + 52, &q->max_distance, 4), memcpy(p + 56, &q->mode, 4);
    return DS_OK;
}

H(BGetPosition) { UNUSED; put_vec(a[1], p3(a[0])->position); return DS_OK; }
H(BGetVelocity) { UNUSED; put_vec(a[1], p3(a[0])->velocity); return DS_OK; }
H(BGetConeOrientation) { UNUSED; put_vec(a[1], p3(a[0])->cone_orientation); return DS_OK; }
H(BGetMinDistance) { UNUSED; memcpy(gptr(a[1]), &p3(a[0])->min_distance, 4); return DS_OK; }
H(BGetMaxDistance) { UNUSED; memcpy(gptr(a[1]), &p3(a[0])->max_distance, 4); return DS_OK; }
H(BGetConeOutsideVolume) { UNUSED; memcpy(gptr(a[1]), &p3(a[0])->outside_volume, 4); return DS_OK; }
H(BGetMode) { UNUSED; memcpy(gptr(a[1]), &p3(a[0])->mode, 4); return DS_OK; }

H(BGetConeAngles)
{
    UNUSED;
    P3 *q = p3(a[0]);
    out32(a[1], q->inside_angle);
    out32(a[2], q->outside_angle);
    return DS_OK;
}

/* ---------------------------------------------------------------- the table */
static const struct { int iface; const char *name; HleFn fn; } SPECIAL[] = {
    {I_DS, "QueryInterface", QiDs}, {I_BUF, "QueryInterface", QiBuf}, {I_LISTENER, "QueryInterface", QiListener},
    {I_3DBUF, "QueryInterface", Qi3dBuf}, {I_NOTIFY, "QueryInterface", QiNotify},
    {I_DS, "CreateSoundBuffer", CreateSoundBuffer}, {I_DS, "GetCaps", DsGetCaps},
    {I_DS, "DuplicateSoundBuffer", DuplicateSoundBuffer}, {I_DS, "SetCooperativeLevel", SetCooperativeLevel},
    {I_DS, "GetSpeakerConfig", GetSpeakerConfig}, {I_DS, "Initialize", DsInitialize},
    {I_BUF, "GetCaps", BufGetCaps}, {I_BUF, "GetCurrentPosition", GetCurrentPosition}, {I_BUF, "GetFormat", GetFormat},
    {I_BUF, "GetVolume", GetVolume}, {I_BUF, "GetPan", GetPan}, {I_BUF, "GetFrequency", GetFrequency},
    {I_BUF, "GetStatus", GetStatus}, {I_BUF, "Initialize", BufInitialize}, {I_BUF, "Lock", Lock},
    {I_BUF, "Play", Play}, {I_BUF, "SetCurrentPosition", SetCurrentPosition}, {I_BUF, "SetFormat", SetFormat},
    {I_BUF, "SetVolume", SetVolume}, {I_BUF, "SetPan", SetPan}, {I_BUF, "SetFrequency", SetFrequency},
    {I_BUF, "Stop", Stop}, {I_BUF, "Unlock", Unlock},
    {I_LISTENER, "GetAllParameters", LGetAllParameters}, {I_LISTENER, "GetDistanceFactor", LGetDistanceFactor},
    {I_LISTENER, "GetDopplerFactor", LGetDopplerFactor}, {I_LISTENER, "GetOrientation", LGetOrientation},
    {I_LISTENER, "GetPosition", LGetPosition}, {I_LISTENER, "GetRolloffFactor", LGetRolloffFactor},
    {I_LISTENER, "GetVelocity", LGetVelocity}, {I_LISTENER, "SetAllParameters", LSetAllParameters},
    {I_LISTENER, "SetDistanceFactor", LSetDistanceFactor}, {I_LISTENER, "SetDopplerFactor", LSetDopplerFactor},
    {I_LISTENER, "SetOrientation", LSetOrientation}, {I_LISTENER, "SetPosition", LSetPosition},
    {I_LISTENER, "SetRolloffFactor", LSetRolloffFactor}, {I_LISTENER, "SetVelocity", LSetVelocity},
    {I_LISTENER, "CommitDeferredSettings", CommitDeferredSettings},
    {I_3DBUF, "GetAllParameters", BGetAllParameters}, {I_3DBUF, "GetConeAngles", BGetConeAngles},
    {I_3DBUF, "GetConeOrientation", BGetConeOrientation}, {I_3DBUF, "GetConeOutsideVolume", BGetConeOutsideVolume},
    {I_3DBUF, "GetMaxDistance", BGetMaxDistance}, {I_3DBUF, "GetMinDistance", BGetMinDistance},
    {I_3DBUF, "GetMode", BGetMode}, {I_3DBUF, "GetPosition", BGetPosition}, {I_3DBUF, "GetVelocity", BGetVelocity},
    {I_3DBUF, "SetAllParameters", BSetAllParameters}, {I_3DBUF, "SetConeAngles", BSetConeAngles},
    {I_3DBUF, "SetConeOrientation", BSetConeOrientation}, {I_3DBUF, "SetConeOutsideVolume", BSetConeOutsideVolume},
    {I_3DBUF, "SetMaxDistance", BSetMaxDistance}, {I_3DBUF, "SetMinDistance", BSetMinDistance},
    {I_3DBUF, "SetMode", BSetMode}, {I_3DBUF, "SetPosition", BSetPosition}, {I_3DBUF, "SetVelocity", BSetVelocity},
};

static char g_names[128][64];
HleDef hle_dsound[128];

__attribute__((constructor)) static void build_table(void)
{
    int n = 0;
    hle_dsound[n++] = (HleDef){DS, "#2", 2, HLE_CORO, DirectSoundEnumerateA};
    hle_dsound[n++] = (HleDef){DS, "DirectSoundEnumerateA", 2, HLE_CORO, DirectSoundEnumerateA};
    hle_dsound[n++] = (HleDef){DS, "#1", 3, STDCALL, DirectSoundCreate};
    hle_dsound[n++] = (HleDef){DS, "DirectSoundCreate", 3, STDCALL, DirectSoundCreate};
    for (int i = 0; i < NIFACES; i++)
        for (const Meth *m = g_ifaces[i].m; m->name; m++) {
            HleFn fn = Ok;              /* Compact, SetSpeakerConfig, Restore, SetNotificationPositions */
            if (!strcmp(m->name, "AddRef"))
                fn = AddRef;
            else if (!strcmp(m->name, "Release"))
                fn = Release;
            for (size_t s = 0; s < sizeof SPECIAL / sizeof *SPECIAL; s++)
                if (SPECIAL[s].iface == i && !strcmp(SPECIAL[s].name, m->name))
                    fn = SPECIAL[s].fn;
            snprintf(g_names[n], sizeof g_names[n], "%s::%s", g_ifaces[i].name, m->name);
            hle_dsound[n] = (HleDef){DS, g_names[n], (uint8_t)(1 + m->nparams), STDCALL, fn};
            n++;
        }
    hle_dsound[n] = (HleDef){NULL, NULL, 0, 0, NULL};
}
