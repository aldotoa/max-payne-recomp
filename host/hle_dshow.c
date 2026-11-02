/* DirectShow (quartz.dll's filter graph) and OLE32 for the native host (E6): a port of emu/dshow.py, which plays the
 * game's movies (CoCreateInstance also makes hle_dsound.c's DirectSound classes). The intro (movies/intro.mpg, from InitInstance) is CoCreateInstance(CLSID_FilterGraph), the
 * QueryInterfaces, RenderFile, the video window calls, Run, then get_CurrentPosition until the end or a key, Stop,
 * Release. The graph is one object with all seven interfaces (each an 8-byte object: its vtable), every method of
 * which has a handler, as in Python. RenderFile opens the file with libmpmovie for its size and duration; the clock is
 * the host clock from Run. A headless "skip" run (--intro skip, the default) presses Space when a movie starts, as a
 * player would, through the DINPUT state (hle_dinput.c), so the game sees WM_KEYDOWN.
 * With the live view's window (host/live.c) the frames are decoded on time and shown in it, and the movie plays (the
 * default with --window: a key press skips it). With a mixer (hle_dsound.c) the soundtrack is one voice, started by
 * Run on the same clock. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <strings.h>

#include "host.h"

#define Q "QUARTZ.DLL"
#define O "OLE32.DLL"
#define H(name) static uint32_t name(CPU *c, const uint32_t *a)
#define UNUSED (void)c, (void)a

enum { S_OK = 0, E_NOTIMPL = 0x80004001u, E_NOINTERFACE = 0x80004002u, VFW_E_NOT_FOUND = 0x80040216u,
       CLASS_E_NOAGGREGATION = 0x80040110u };
#define OATRUE 0xFFFFFFFFu
#define OAFALSE 0u
#define UNITS 10000000.0                /* REFERENCE_TIME: 100 ns */
#define SKIP_KEY 0x39                   /* DIK_SPACE */
enum { STATE_STOPPED, STATE_PAUSED, STATE_RUNNING };

int g_intro_skip = 1;

/* libmpmovie (movie/mpmovie.m) */
typedef struct mpm mpm;
mpm *mpm_open(const char *path);
void mpm_info(mpm *m, int *w, int *h, double *duration, double *fps, int *audio_rate, int *audio_channels);
void mpm_close(mpm *m);
const char *mpm_last_error(void);
int mpm_next_frame(mpm *m, uint8_t *bgra, double *pts);
int mpm_seek(mpm *m, double t);
int mpm_present_bgra(void *layer, const uint8_t *bgra, int w, int h);
int mpm_read_audio(mpm *m, int16_t **out, uint32_t *frames);
void mpm_free(void *p);
/* libmpaudio (the mixer, host_mixer) */
int mpa_voice_new(void *m, int channels, int bits, int rate, uint32_t size);
void mpa_voice_free(void *m, int id);
void mpa_voice_write(void *m, int id, uint32_t offset, const void *data, uint32_t len);
void mpa_voice_play(void *m, int id, int looping);
void mpa_voice_stop(void *m, int id);
void mpa_voice_set_pos(void *m, int id, uint32_t byte);

/* ---------------------------------------------------------------- interfaces (vtable order) */
typedef struct { const char *name; uint8_t nparams; } Meth;
#define IUNK {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}
#define IDISP IUNK, {"GetTypeInfoCount", 1}, {"GetTypeInfo", 3}, {"GetIDsOfNames", 5}, {"Invoke", 8}
static const Meth GB[] = {IUNK, {"AddFilter", 2}, {"RemoveFilter", 1}, {"EnumFilters", 1}, {"FindFilterByName", 2},
    {"ConnectDirect", 3}, {"Reconnect", 1}, {"Disconnect", 1}, {"SetDefaultSyncSource", 0}, {"Connect", 2},
    {"Render", 1}, {"RenderFile", 2}, {"AddSourceFilter", 3}, {"SetLogFile", 1}, {"Abort", 0},
    {"ShouldOperationContinue", 0}, {NULL, 0}};
static const Meth MC[] = {IDISP, {"Run", 0}, {"Pause", 0}, {"Stop", 0}, {"GetState", 2}, {"RenderFile", 1},
    {"AddSourceFilter", 2}, {"get_FilterCollection", 1}, {"get_RegFilterCollection", 1}, {"StopWhenReady", 0},
    {NULL, 0}};
static const Meth MP[] = {IDISP, {"get_Duration", 1}, {"put_CurrentPosition", 2}, {"get_CurrentPosition", 1},
    {"get_StopTime", 1}, {"put_StopTime", 2}, {"get_PrerollTime", 1}, {"put_PrerollTime", 2}, {"put_Rate", 2},
    {"get_Rate", 1}, {"CanSeekForward", 1}, {"CanSeekBackward", 1}, {NULL, 0}};
static const Meth MS[] = {IUNK, {"GetCapabilities", 1}, {"CheckCapabilities", 1}, {"IsFormatSupported", 1},
    {"QueryPreferredFormat", 1}, {"GetTimeFormat", 1}, {"IsUsingTimeFormat", 1}, {"SetTimeFormat", 1},
    {"GetDuration", 1}, {"GetStopPosition", 1}, {"GetCurrentPosition", 1}, {"ConvertTimeFormat", 5},
    {"SetPositions", 4}, {"GetPositions", 2}, {"GetAvailable", 2}, {"SetRate", 2}, {"GetRate", 1},
    {"GetPreroll", 1}, {NULL, 0}};
static const Meth VW[] = {IDISP, {"put_Caption", 1}, {"get_Caption", 1}, {"put_WindowStyle", 1},
    {"get_WindowStyle", 1}, {"put_WindowStyleEx", 1}, {"get_WindowStyleEx", 1}, {"put_AutoShow", 1},
    {"get_AutoShow", 1}, {"put_WindowState", 1}, {"get_WindowState", 1}, {"put_BackgroundPalette", 1},
    {"get_BackgroundPalette", 1}, {"put_Visible", 1}, {"get_Visible", 1}, {"put_Left", 1}, {"get_Left", 1},
    {"put_Width", 1}, {"get_Width", 1}, {"put_Top", 1}, {"get_Top", 1}, {"put_Height", 1}, {"get_Height", 1},
    {"put_Owner", 1}, {"get_Owner", 1}, {"put_MessageDrain", 1}, {"get_MessageDrain", 1}, {"get_BorderColor", 1},
    {"put_BorderColor", 1}, {"get_FullScreenMode", 1}, {"put_FullScreenMode", 1}, {"SetWindowForeground", 1},
    {"NotifyOwnerMessage", 4}, {"SetWindowPosition", 4}, {"GetWindowPosition", 4}, {"GetMinIdealImageSize", 2},
    {"GetMaxIdealImageSize", 2}, {"GetRestorePosition", 4}, {"HideCursor", 1}, {"IsCursorHidden", 1}, {NULL, 0}};
static const Meth BV[] = {IDISP, {"get_AvgTimePerFrame", 1}, {"get_BitRate", 1}, {"get_BitErrorRate", 1},
    {"get_VideoWidth", 1}, {"get_VideoHeight", 1}, {"put_SourceLeft", 1}, {"get_SourceLeft", 1},
    {"put_SourceWidth", 1}, {"get_SourceWidth", 1}, {"put_SourceTop", 1}, {"get_SourceTop", 1},
    {"put_SourceHeight", 1}, {"get_SourceHeight", 1}, {"put_DestinationLeft", 1}, {"get_DestinationLeft", 1},
    {"put_DestinationWidth", 1}, {"get_DestinationWidth", 1}, {"put_DestinationTop", 1}, {"get_DestinationTop", 1},
    {"put_DestinationHeight", 1}, {"get_DestinationHeight", 1}, {"SetSourcePosition", 4}, {"GetSourcePosition", 4},
    {"SetDefaultSourcePosition", 0}, {"SetDestinationPosition", 4}, {"GetDestinationPosition", 4},
    {"SetDefaultDestinationPosition", 0}, {"GetVideoSize", 2}, {"GetVideoPaletteEntries", 4},
    {"GetCurrentImage", 2}, {"IsUsingDefaultSource", 0}, {"IsUsingDefaultDestination", 0}, {NULL, 0}};
static const Meth BA[] = {IDISP, {"put_Volume", 1}, {"get_Volume", 1}, {"put_Balance", 1}, {"get_Balance", 1},
    {NULL, 0}};

enum { F_GB, F_MC, F_MP, F_MS, F_VW, F_BV, F_BA, NFACES };
static struct {
    const char *name;
    const Meth *m;
    uint8_t iid[16];
    uint32_t vtable;
} F[NFACES] = {
    {"IGraphBuilder", GB, {0xA9, 0x68, 0xA8, 0x56, 0xD4, 0x0A, 0xCE, 0x11, 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70}, 0},
    {"IMediaControl", MC, {0xB1, 0x68, 0xA8, 0x56, 0xD4, 0x0A, 0xCE, 0x11, 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70}, 0},
    {"IMediaPosition", MP, {0xB2, 0x68, 0xA8, 0x56, 0xD4, 0x0A, 0xCE, 0x11, 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70}, 0},
    {"IMediaSeeking", MS, {0x80, 0x38, 0xB7, 0x36, 0xC8, 0xC2, 0xCF, 0x11, 0x8B, 0x46, 0x00, 0x80, 0x5F, 0x6C, 0xEF, 0x60}, 0},
    {"IVideoWindow", VW, {0xB4, 0x68, 0xA8, 0x56, 0xD4, 0x0A, 0xCE, 0x11, 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70}, 0},
    {"IBasicVideo", BV, {0xB5, 0x68, 0xA8, 0x56, 0xD4, 0x0A, 0xCE, 0x11, 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70}, 0},
    {"IBasicAudio", BA, {0xB3, 0x68, 0xA8, 0x56, 0xD4, 0x0A, 0xCE, 0x11, 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70}, 0},
};
/* the aliases: IUnknown and IFilterGraph give the IGraphBuilder face, IDispatch the IMediaControl one */
static const uint8_t IID_IUNKNOWN[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46};
static const uint8_t IID_IDISPATCH[16] = {0x00, 0x04, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46};
static const uint8_t IID_IFILTERGRAPH[16] = {0x9F, 0x68, 0xA8, 0x56, 0xD4, 0x0A, 0xCE, 0x11, 0xB0, 0x3A, 0x00, 0x20,
                                             0xAF, 0x0B, 0xA7, 0x70};
static const uint8_t CLSID_FILTERGRAPH[16] = {0xB3, 0xEB, 0x36, 0xE4, 0x4F, 0x52, 0xCE, 0x11, 0x9F, 0x53, 0x00, 0x20,
                                              0xAF, 0x0B, 0xA7, 0x70};
/* TIME_FORMAT_MEDIA_TIME */
static const uint8_t TIME_FORMAT_MEDIA_TIME[16] = {0x74, 0x55, 0x78, 0x7B, 0x82, 0x8C, 0xCF, 0x11, 0xBC, 0x0C, 0x00,
                                                   0xAA, 0x00, 0xAC, 0x74, 0xF6};

/* -1: not one of the graph's interfaces */
static int face_of_iid(const uint8_t *iid)
{
    if (!memcmp(iid, IID_IUNKNOWN, 16) || !memcmp(iid, IID_IFILTERGRAPH, 16))
        return F_GB;
    if (!memcmp(iid, IID_IDISPATCH, 16))
        return F_MC;
    for (int i = 0; i < NFACES; i++)
        if (!memcmp(iid, F[i].iid, 16))
            return i;
    return -1;
}

/* ---------------------------------------------------------------- the graph */
typedef struct {
    uint32_t faces[NFACES];
    int refs, state, visible, autoshow, fullscreen, skip_pressed, active;
    uint32_t owner, drain, style, rect[4];
    double pos, started;
    mpm *movie;
    int width, height;
    double duration, fps;
    int audio_rate, audio_channels, voice;      /* the soundtrack as one mixer voice (-1: none) */
    /* the decoder (Movie.advance; only with a window to show the frames in): the frame shown, the next one decoded */
    uint8_t *frame, *ahead;
    double frame_pts, ahead_pts;
    int has_frame, has_ahead, ended;
    unsigned shown;
} Graph;

static Graph *g_graphs[64];
static int g_ngraphs;

static inline void out32(uint32_t p, uint32_t v) { if (p) memcpy(gptr(p), &v, 4); }
static inline void outf64(uint32_t p, double v) { if (p) memcpy(gptr(p), &v, 8); }
static inline void out64(uint32_t p, double v) { int64_t q = (int64_t)v; if (p) memcpy(gptr(p), &q, 8); }

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static uint32_t vtable(int i)
{
    if (!F[i].vtable) {
        uint32_t n = 0;
        while (F[i].m[n].name)
            n++;
        uint32_t p = host_alloc(4 * n);
        for (uint32_t k = 0; k < n; k++) {
            char name[128];
            snprintf(name, sizeof name, "%s::%s", F[i].name, F[i].m[k].name);
            uint32_t s = host_stub_for(Q, name);
            memcpy(gptr(p + 4 * k), &s, 4);
        }
        F[i].vtable = p;
    }
    return F[i].vtable;
}

/* new_graph: each face (8 bytes: the vtable), its vtable made with the first */
static Graph *new_graph(void)
{
    if (g_ngraphs == 64)
        host_fatal("too many DirectShow filter graphs");
    Graph *g = calloc(1, sizeof *g);
    g->autoshow = 1;
    g->voice = -1;
    for (int i = 0; i < NFACES; i++) {
        uint32_t o = host_alloc(8);
        uint32_t vt = vtable(i);
        memcpy(gptr(o), &vt, 4);
        g->faces[i] = o;
    }
    return g_graphs[g_ngraphs++] = g;
}

static Graph *graph(uint32_t this)
{
    for (int i = 0; i < g_ngraphs; i++)
        for (int f = 0; f < NFACES; f++)
            if (g_graphs[i]->faces[f] == this)
                return g_graphs[i];
    host_fatal("DirectShow call on 0x%x, which is no filter graph", this);
}

static double position(Graph *g) { return g->state == STATE_RUNNING ? g->pos + now() - g->started : g->pos; }
static double duration(Graph *g) { return g->movie ? g->duration : 0.0; }

/* Movie.advance: decode up to time t; 1 if the frame to show changed */
static int advance(Graph *g, double t)
{
    int changed = 0;
    while (!g->ended) {
        if (!g->has_ahead) {
            if (mpm_next_frame(g->movie, g->ahead, &g->ahead_pts) <= 0) {
                g->ended = 1;
                break;
            }
            g->has_ahead = 1;
        }
        if (g->ahead_pts > t)
            break;
        uint8_t *x = g->frame;
        g->frame = g->ahead, g->ahead = x;
        g->frame_pts = g->ahead_pts, g->has_frame = 1, g->has_ahead = 0;
        changed = 1;
    }
    return changed;
}

/* tick: decode up to the clock and show the newest frame in the live view's window, whose events are pumped (so a key
 * press reaches the game as WM_KEYDOWN) */
static void tick(Graph *g)
{
    if (!g->movie || !g->frame)
        return;
    if (advance(g, position(g)) && g->visible) {
        g->shown++;
        if (mpm_present_bgra(host_live_layer(), g->frame, g->width, g->height))
            printf("[live] movie frame: %s\n", mpm_last_error());
    }
    host_live_pump();
}

static void stop(Graph *g, int new_state)
{
    if (g->state == STATE_RUNNING) {
        double p = position(g);
        g->pos = p < duration(g) ? p : duration(g);
        printf("[dshow] %s at %.2f s (%u frames shown)\n", new_state == STATE_PAUSED ? "Pause" : "Stop", g->pos,
               g->shown);
    }
    g->state = new_state;
    g->active = 0;
    if (g->voice >= 0)
        mpa_voice_stop(host_mixer(), g->voice);
    if (g->skip_pressed) {
        host_key(SKIP_KEY, 0);
        g->skip_pressed = 0;
    }
}

static void seek(Graph *g, double t)
{
    if (t > duration(g))
        t = duration(g);
    if (t < 0)
        t = 0;
    if (g->frame && !(g->has_frame && g->frame_pts <= t && t < g->frame_pts + 1.0)) {
        mpm_seek(g->movie, t);                  /* backwards or far ahead: restart decoding there */
        g->has_frame = g->has_ahead = g->ended = 0;
    }
    g->pos = t;
    g->started = now();
    if (g->voice >= 0 && g->movie)
        mpa_voice_set_pos(host_mixer(), g->voice, (uint32_t)(t * g->audio_rate) * 2u * (uint32_t)g->audio_channels);
}

/* a guest Sleep while a movie runs: wait for real, decoding and showing the frames on time (on_sleep) */
void host_movie_sleep(uint32_t ms)
{
    double end = now() + ms / 1000.0;
    for (;;) {
        int active = 0;
        double next = 0.01;
        for (int i = 0; i < g_ngraphs; i++)
            if (g_graphs[i]->active) {
                Graph *g = g_graphs[i];
                if (!active || g->has_ahead)
                    next = g->has_ahead ? g->ahead_pts - position(g) : next;
                active = 1;
                tick(g);
            }
        if (!active)
            return;
        double t = now();
        if (t >= end)
            return;
        double d = end - t;
        if (next < d)
            d = next;
        if (d > 0.02)
            d = 0.02;
        if (d < 0.001)
            d = 0.001;
        struct timespec ts = {(time_t)d, (long)((d - (double)(time_t)d) * 1e9)};
        nanosleep(&ts, NULL);
    }
}

/* ---------------------------------------------------------------- handlers (a[0] is the face) */
#define G graph(a[0])
H(NotImpl) { UNUSED; return E_NOTIMPL; }

H(QueryInterface)
{
    UNUSED;
    Graph *g = G;
    int f = face_of_iid(gptr(a[1]));
    if (f < 0) {
        out32(a[2], 0);
        return E_NOINTERFACE;
    }
    g->refs++;
    out32(a[2], g->faces[f]);
    return S_OK;
}

H(AddRef) { UNUSED; return (uint32_t)++G->refs; }

H(Release)
{
    UNUSED;
    Graph *g = G;
    g->refs = g->refs > 0 ? g->refs - 1 : 0;
    if (g->refs == 0) {
        stop(g, STATE_STOPPED);
        if (g->voice >= 0) {
            mpa_voice_free(host_mixer(), g->voice);
            g->voice = -1;
        }
        if (g->movie) {
            mpm_close(g->movie);
            g->movie = NULL;
            free(g->frame), free(g->ahead);
            g->frame = g->ahead = NULL;
        }
    }
    return (uint32_t)g->refs;
}

/* e.host_path: a guest path onto the game folder, case-insensitively (C:\MaxPayne\ and a leading slash dropped) */
static void game_path(const char *guest, char *out, size_t cap)
{
    char p[1024];
    snprintf(p, sizeof p, "%s", guest);
    for (char *s = p; *s; s++)
        if (*s == '\\')
            *s = '/';
    char *q = p;
    if (q[0] && q[1] == ':')
        q += 2;
    if (!strncasecmp(q, "/maxpayne/", 10))
        q += 10;
    while (*q == '/')
        q++;
    snprintf(out, cap, "%s", g_game_dir);
    for (char *part = strtok(q, "/"); part; part = strtok(NULL, "/")) {
        if (!strcmp(part, "."))
            continue;
        if (!strcmp(part, "..")) {
            char *sl = strrchr(out, '/');
            if (sl && sl != out)
                *sl = 0;
            continue;
        }
        const char *hit = part;
        char found[256];
        DIR *d = opendir(out);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)))
                if (!strcasecmp(de->d_name, part)) {
                    snprintf(found, sizeof found, "%s", de->d_name);
                    hit = found;
                    break;
                }
            closedir(d);
        }
        size_t k = strlen(out);
        snprintf(out + k, cap - k, "/%s", hit);
    }
}

H(RenderFile)
{
    UNUSED;
    Graph *g = G;
    uint16_t w[1024];
    size_t n = host_wstr(a[1], w, 1024);
    char name[1024], path[2048];
    for (size_t i = 0; i <= n && i < sizeof name - 1; i++)
        name[i] = (char)(w[i] < 0x100 ? w[i] : '?');
    name[n < sizeof name - 1 ? n : sizeof name - 1] = 0;
    game_path(name, path, sizeof path);
    mpm *mv = mpm_open(path);
    if (!mv) {
        printf("[dshow] RenderFile(%s) -> VFW_E_NOT_FOUND (%s)\n", name, mpm_last_error());
        return VFW_E_NOT_FOUND;
    }
    int ar, ac;
    mpm_info(mv, &g->width, &g->height, &g->duration, &g->fps, &ar, &ac);
    g->movie = mv;
    g->audio_rate = ar, g->audio_channels = ac;
    void *mx = host_mixer();
    if (ar && mx) {                             /* the whole soundtrack, one voice started by Run */
        int16_t *pcm = NULL;
        uint32_t frames = 0;
        if (mpm_read_audio(mv, &pcm, &frames))
            host_fatal("RenderFile(%s): %s", name, mpm_last_error());
        uint32_t len = frames * 2u * (uint32_t)ac;
        if (pcm && len) {
            int v = mpa_voice_new(mx, ac, 16, ar, len);
            if (v >= 0) {
                mpa_voice_write(mx, v, 0, pcm, len);
                g->voice = v;
            }
        }
        mpm_free(pcm);
    }
    if (host_live_on()) {
        size_t n = (size_t)(g->width * g->height * 4 > 4 ? g->width * g->height * 4 : 4);
        g->frame = malloc(n), g->ahead = malloc(n);
    }
    printf("[dshow] RenderFile(%s): %dx%d %.2f s %.2f fps, audio %d Hz %d ch%s\n", name, g->width, g->height,
           g->duration, g->fps, ar, ac, g->voice >= 0 || !ar ? "" : " (not played: no mixer)");
    return S_OK;
}

H(Run)
{
    UNUSED;
    Graph *g = G;
    if (!g->movie)
        return VFW_E_NOT_FOUND;
    if (g->state != STATE_RUNNING) {
        g->started = now();
        g->state = STATE_RUNNING;
        if (g->autoshow)
            g->visible = 1;
        if (g->voice >= 0) {
            mpa_voice_set_pos(host_mixer(), g->voice,
                              (uint32_t)(g->pos * g->audio_rate) * 2u * (uint32_t)g->audio_channels);
            mpa_voice_play(host_mixer(), g->voice, 0);
        }
        g->active = 1;
        if (!host_live_on() && g_intro_skip && !g->skip_pressed) {
            host_key(SKIP_KEY, 1);     /* a player pressing a key: WM_KEYDOWN */
            g->skip_pressed = 1;
            printf("[dshow] headless run: pressed Space to skip the movie\n");
        }
        tick(g);
    }
    return S_OK;
}

H(Pause) { UNUSED; stop(G, STATE_PAUSED); return S_OK; }
H(Stop) { UNUSED; stop(G, STATE_STOPPED); return S_OK; }
H(GetState) { UNUSED; out32(a[2], (uint32_t)G->state); return S_OK; }

H(get_Duration) { UNUSED; outf64(a[1], duration(G)); return S_OK; }

H(get_CurrentPosition)
{
    UNUSED;
    Graph *g = G;
    tick(g);
    double p = position(g);
    outf64(a[1], p < duration(g) ? p : duration(g));
    return S_OK;
}

H(put_CurrentPosition)
{
    UNUSED;
    uint32_t lohi[2] = {a[1], a[2]};
    double t;
    memcpy(&t, lohi, 8);
    seek(G, t);
    return S_OK;
}

H(get_PrerollTime) { UNUSED; (void)G; outf64(a[1], 0.0); return S_OK; }
H(get_Rate) { UNUSED; (void)G; outf64(a[1], 1.0); return S_OK; }
H(CanSeek) { UNUSED; (void)G; out32(a[1], OATRUE); return S_OK; }

H(SetPositions)
{
    UNUSED;
    Graph *g = G;
    if (a[1] && (a[2] & 3)) {
        int64_t v;
        memcpy(&v, gptr(a[1]), 8);
        seek(g, ((a[2] & 3) == 1 ? 0.0 : position(g)) + (double)v / UNITS);   /* absolute, else relative */
    }
    return S_OK;
}

H(GetDuration) { UNUSED; out64(a[1], duration(G) * UNITS); return S_OK; }

H(GetCurrentPositionMS)
{
    UNUSED;
    Graph *g = G;
    tick(g);
    double p = position(g);
    out64(a[1], (p < duration(g) ? p : duration(g)) * UNITS);
    return S_OK;
}

H(GetPositions)
{
    UNUSED;
    Graph *g = G;
    double p = position(g);
    out64(a[1], (p < duration(g) ? p : duration(g)) * UNITS);
    out64(a[2], duration(g) * UNITS);
    return S_OK;
}

H(GetCapabilities) { UNUSED; (void)G; out32(a[1], 0x1 | 0x2 | 0x4 | 0x8 | 0x100); return S_OK; }

H(GetTimeFormat)
{
    UNUSED;
    (void)G;
    if (a[1])
        memcpy(gptr(a[1]), TIME_FORMAT_MEDIA_TIME, 16);
    return S_OK;
}

/* the IVideoWindow / IBasicVideo calls need a rendered video stream */
static Graph *video(uint32_t this)
{
    Graph *g = graph(this);
    return g->movie && g->width ? g : NULL;
}

#define V(name, body)                                                                                                 \
    H(name)                                                                                                           \
    {                                                                                                                 \
        UNUSED;                                                                                                       \
        Graph *g = video(a[0]);                                                                                       \
        if (!g)                                                                                                       \
            return E_NOINTERFACE;                                                                                     \
        body;                                                                                                         \
        return S_OK;                                                                                                  \
    }
V(VideoOk, (void)g)
V(put_Visible, g->visible = a[1] != OAFALSE)
V(get_Visible, out32(a[1], g->visible ? OATRUE : OAFALSE))
V(put_AutoShow, g->autoshow = a[1] != OAFALSE)
V(get_AutoShow, out32(a[1], g->autoshow ? OATRUE : OAFALSE))
V(put_Owner, g->owner = a[1])
V(get_Owner, out32(a[1], g->owner))
V(put_MessageDrain, g->drain = a[1])
V(get_MessageDrain, out32(a[1], g->drain))
V(put_WindowStyle, g->style = a[1])
V(get_WindowStyle, out32(a[1], g->style))
V(put_FullScreenMode, g->fullscreen = a[1] != OAFALSE)
V(get_FullScreenMode, out32(a[1], g->fullscreen ? OATRUE : OAFALSE))
V(SetWindowPosition, memcpy(g->rect, a + 1, 16))
V(GetWindowPosition, for (int i = 0; i < 4; i++) out32(a[1 + i], g->rect[i]))
V(GetVideoSize, out32(a[1], (uint32_t)g->width); out32(a[2], (uint32_t)g->height))
V(get_VideoWidth, out32(a[1], (uint32_t)g->width))
V(get_VideoHeight, out32(a[1], (uint32_t)g->height))
V(get_AvgTimePerFrame, outf64(a[1], 1.0 / (g->fps ? g->fps : 25)))

static const struct { int face; const char *name; HleFn fn; } SPECIAL[] = {
    {F_GB, "RenderFile", RenderFile},
    {F_MC, "Run", Run}, {F_MC, "Pause", Pause}, {F_MC, "Stop", Stop}, {F_MC, "StopWhenReady", Stop},
    {F_MC, "GetState", GetState},
    {F_MP, "get_Duration", get_Duration}, {F_MP, "get_CurrentPosition", get_CurrentPosition},
    {F_MP, "put_CurrentPosition", put_CurrentPosition}, {F_MP, "get_StopTime", get_Duration},
    {F_MP, "get_PrerollTime", get_PrerollTime}, {F_MP, "get_Rate", get_Rate}, {F_MP, "CanSeekForward", CanSeek},
    {F_MP, "CanSeekBackward", CanSeek},
    {F_MS, "SetPositions", SetPositions}, {F_MS, "GetDuration", GetDuration}, {F_MS, "GetStopPosition", GetDuration},
    {F_MS, "GetCurrentPosition", GetCurrentPositionMS}, {F_MS, "GetPositions", GetPositions},
    {F_MS, "GetCapabilities", GetCapabilities}, {F_MS, "GetTimeFormat", GetTimeFormat}, {F_MS, "GetRate", get_Rate},
    {F_VW, "put_Visible", put_Visible}, {F_VW, "get_Visible", get_Visible}, {F_VW, "put_AutoShow", put_AutoShow},
    {F_VW, "get_AutoShow", get_AutoShow}, {F_VW, "put_Owner", put_Owner}, {F_VW, "get_Owner", get_Owner},
    {F_VW, "put_MessageDrain", put_MessageDrain}, {F_VW, "get_MessageDrain", get_MessageDrain},
    {F_VW, "put_WindowStyle", put_WindowStyle}, {F_VW, "get_WindowStyle", get_WindowStyle},
    {F_VW, "put_FullScreenMode", put_FullScreenMode}, {F_VW, "get_FullScreenMode", get_FullScreenMode},
    {F_VW, "SetWindowPosition", SetWindowPosition}, {F_VW, "GetWindowPosition", GetWindowPosition},
    {F_VW, "HideCursor", VideoOk}, {F_VW, "SetWindowForeground", VideoOk}, {F_VW, "NotifyOwnerMessage", VideoOk},
    {F_BV, "GetVideoSize", GetVideoSize}, {F_BV, "get_VideoWidth", get_VideoWidth},
    {F_BV, "get_VideoHeight", get_VideoHeight}, {F_BV, "get_AvgTimePerFrame", get_AvgTimePerFrame},
};

/* ---------------------------------------------------------------- OLE32 */
H(CoCreateInstance)
{
    UNUSED;
    int64_t ds = host_dsound_com(gptr(a[0]), a[1], a[4]);   /* DirectSound, DirectSound8 */
    if (ds >= 0)
        return (uint32_t)ds;
    if (memcmp(gptr(a[0]), CLSID_FILTERGRAPH, 16) != 0) {
        const uint8_t *k = gptr(a[0]);
        host_fatal("unimplemented import OLE32.DLL!CoCreateInstance of class "
                   "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x (no C class yet)",
                   k[3], k[2], k[1], k[0], k[5], k[4], k[7], k[6], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15]);
    }
    if (a[1]) {
        out32(a[4], 0);
        return CLASS_E_NOAGGREGATION;
    }
    int f = face_of_iid(gptr(a[3]));
    Graph *g = new_graph();
    if (f < 0) {
        out32(a[4], 0);
        return E_NOINTERFACE;
    }
    g->refs = 1;
    out32(a[4], g->faces[f]);
    return S_OK;
}

H(Return0) { UNUSED; return 0; }

/* the table: every method of every face, with Python's defaults (an IVideoWindow / IBasicVideo setter is accepted
 * when there is video, a getter is E_NOTIMPL; everything else E_NOTIMPL), then OLE32 */
static char g_names[512][96];
HleDef hle_dshow[512];

__attribute__((constructor)) static void build_table(void)
{
    int n = 0;
    for (int f = 0; f < NFACES; f++)
        for (const Meth *m = F[f].m; m->name; m++) {
            HleFn fn = NotImpl;
            if (!strcmp(m->name, "QueryInterface"))
                fn = QueryInterface;
            else if (!strcmp(m->name, "AddRef"))
                fn = AddRef;
            else if (!strcmp(m->name, "Release"))
                fn = Release;
            else if ((f == F_VW && m - F[f].m >= 7) || (f == F_BV && m - F[f].m >= 7)) {
                if (strncmp(m->name, "get_", 4) && strncmp(m->name, "Get", 3) && strncmp(m->name, "Is", 2))
                    fn = VideoOk;
            }
            for (size_t s = 0; s < sizeof SPECIAL / sizeof *SPECIAL; s++)
                if (SPECIAL[s].face == f && !strcmp(SPECIAL[s].name, m->name))
                    fn = SPECIAL[s].fn;
            snprintf(g_names[n], sizeof g_names[n], "%s::%s", F[f].name, m->name);
            hle_dshow[n] = (HleDef){Q, g_names[n], (uint8_t)(1 + m->nparams), STDCALL, fn};
            n++;
        }
    hle_dshow[n++] = (HleDef){O, "CoInitialize", 1, STDCALL, Return0};
    hle_dshow[n++] = (HleDef){O, "CoUninitialize", 0, STDCALL, Return0};
    hle_dshow[n++] = (HleDef){O, "CoCreateInstance", 5, STDCALL, CoCreateInstance};
    hle_dshow[n] = (HleDef){NULL, NULL, 0, 0, NULL};
}
