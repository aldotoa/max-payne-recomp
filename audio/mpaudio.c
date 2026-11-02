// libmpaudio: the software mixer behind the emulator's DirectSound layer (emu/dsound.py).
//
// Each DirectSound secondary buffer is a voice: a copy of the buffer's PCM (8-bit unsigned or 16-bit signed,
// mono or stereo, any rate), a play position in frames, a playback rate and a final left/right gain. The Python
// side copies the guest's data in on every Unlock and computes the gains from volume, pan and the 3D parameters;
// this library only resamples (linear) and mixes. The voices' play positions are the DirectSound play cursors, so
// a streaming buffer's cursor advances exactly as fast as its sound is consumed.
//
// Output: an SDL3 audio stream on the default playback device (float stereo), or with device=0 a "null device":
// a thread that consumes audio at the real-time rate without playing it. Either way mpa_record() can write the
// mixed output to a WAV file, and mpa_render() mixes on demand for tests (use it only with device=-1: no
// consumer of its own).
//
// MPA_LOG=FILE (environment, read by mpa_create) logs every call that changes a voice, one line each: "new ch bits rate
// size -> id", "free id", "write id offset len fnv" (FNV-1a of the bytes), "play id looping", "stop id", "pos id byte",
// "freq id hz" and "gain id left right downmix" (floats as %a), so two callers (the emulator's dsound.py and the native
// host) can be compared call by call.
#include <SDL3/SDL.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHUNK 1024
#define BLOCK 64

typedef struct {
    int used;
    int channels, bits, rate;
    uint32_t size, frame_bytes, nframes;
    uint8_t *data;
    int playing, looping;
    double pos;           // in source frames
    // Starvation check: each block of BLOCK frames is stamped with the lap it was written for; a looping voice
    // that plays a block whose stamp is older than the current lap is replaying stale data.
    int32_t *stamp;
    int32_t lap;
    uint32_t stale_block;      // last block counted stale (so a block counts once per lap)
    uint64_t stale;            // frames played from stale blocks
    double freq;          // playback rate in Hz
    float gl, gr;
    int downmix;          // mix the source to mono before applying the gains (3D voices)
} Voice;

typedef struct mpa {
    pthread_mutex_t lock;
    int rate;
    Voice *v;
    int nv;
    SDL_AudioStream *stream;
    pthread_t thread;
    volatile int thread_run;
    FILE *wav;
    uint32_t wav_frames;
    uint64_t frames_out;
} mpa;

static char last_error[256];
const char *mpa_last_error(void) { return last_error; }

static FILE *g_log;               // MPA_LOG

#define LOG(...)                                                                                                       \
    do {                                                                                                               \
        if (g_log) {                                                                                                   \
            fprintf(g_log, __VA_ARGS__);                                                                               \
            fputc('\n', g_log);                                                                                        \
            fflush(g_log);                                                                                             \
        }                                                                                                              \
    } while (0)

static uint32_t fnv(const void *p, uint32_t n) {
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < n; i++)
        h = (h ^ ((const uint8_t *)p)[i]) * 16777619u;
    return h;
}

static inline float sample_at(const Voice *v, uint32_t frame, int ch) {
    const uint8_t *p = v->data + (size_t)frame * v->frame_bytes;
    if (v->bits == 8)
        return ((int)p[ch] - 128) * (1.0f / 128.0f);
    int16_t s;
    memcpy(&s, p + 2 * ch, 2);
    return s * (1.0f / 32768.0f);
}

static void mix_voice(mpa *m, Voice *v, float *out, int n) {
    double step = v->freq / m->rate;
    for (int i = 0; i < n; i++) {
        uint32_t i0 = (uint32_t)v->pos;
        uint32_t i1 = i0 + 1;
        if (i1 >= v->nframes)
            i1 = v->looping ? 0 : i0;
        float t = (float)(v->pos - i0);
        float l0 = sample_at(v, i0, 0), l1 = sample_at(v, i1, 0);
        float l = l0 + (l1 - l0) * t, r = l;
        if (v->channels == 2) {
            float r0 = sample_at(v, i0, 1), r1 = sample_at(v, i1, 1);
            r = r0 + (r1 - r0) * t;
        }
        if (v->downmix)
            l = r = 0.5f * (l + r);
        out[2 * i] += l * v->gl;
        out[2 * i + 1] += r * v->gr;
        uint32_t b = i0 / BLOCK;
        if (v->stamp[b] < v->lap && b != v->stale_block) {
            v->stale_block = b;
            uint32_t end = (b + 1) * BLOCK < v->nframes ? (b + 1) * BLOCK : v->nframes;
            v->stale += end - b * BLOCK;
        }
        v->pos += step;
        if (v->pos >= v->nframes) {
            if (!v->looping) {
                v->playing = 0;
                v->pos = 0;
                return;
            }
            v->pos = fmod(v->pos, v->nframes);
            v->lap++;
            v->stale_block = UINT32_MAX;
        }
    }
}

static void wav_header(FILE *f, int rate, uint32_t frames) {
    uint32_t data = frames * 4;
    uint8_t h[44];
    memcpy(h, "RIFF", 4);
    uint32_t riff = 36 + data;
    memcpy(h + 4, &riff, 4);
    memcpy(h + 8, "WAVEfmt ", 8);
    uint32_t fmt_len = 16, avg = rate * 4;
    uint16_t tag = 1, ch = 2, align = 4, bits = 16;
    memcpy(h + 16, &fmt_len, 4);
    memcpy(h + 20, &tag, 2);
    memcpy(h + 22, &ch, 2);
    memcpy(h + 24, &rate, 4);
    memcpy(h + 28, &avg, 4);
    memcpy(h + 32, &align, 2);
    memcpy(h + 34, &bits, 2);
    memcpy(h + 36, "data", 4);
    memcpy(h + 40, &data, 4);
    fseek(f, 0, SEEK_SET);
    fwrite(h, 1, 44, f);
    fseek(f, 0, SEEK_END);
}

// Mix n frames of float stereo into out. Called with the lock held.
static void render_locked(mpa *m, float *out, int n) {
    memset(out, 0, sizeof(float) * 2 * n);
    for (int i = 0; i < m->nv; i++) {
        Voice *v = &m->v[i];
        if (v->used && v->playing && v->nframes && v->freq > 0)
            mix_voice(m, v, out, n);
    }
    m->frames_out += n;
    if (m->wav) {
        int16_t pcm[2 * CHUNK];
        for (int done = 0; done < n; done += CHUNK) {
            int k = n - done < CHUNK ? n - done : CHUNK;
            for (int j = 0; j < 2 * k; j++) {
                float s = out[2 * done + j];
                s = s > 1.0f ? 1.0f : s < -1.0f ? -1.0f : s;
                pcm[j] = (int16_t)lrintf(s * 32767.0f);
            }
            fwrite(pcm, 4, k, m->wav);
        }
        m->wav_frames += n;
    }
}

void mpa_render(mpa *m, float *out, int n) {
    pthread_mutex_lock(&m->lock);
    for (int done = 0; done < n; done += CHUNK)
        render_locked(m, out + 2 * done, n - done < CHUNK ? n - done : CHUNK);
    pthread_mutex_unlock(&m->lock);
}

static void SDLCALL sdl_callback(void *ud, SDL_AudioStream *s, int additional, int total) {
    mpa *m = ud;
    float buf[2 * CHUNK];
    for (int frames = additional / 8; frames > 0;) {
        int n = frames < CHUNK ? frames : CHUNK;
        pthread_mutex_lock(&m->lock);
        render_locked(m, buf, n);
        pthread_mutex_unlock(&m->lock);
        SDL_PutAudioStreamData(s, buf, n * 8);
        frames -= n;
    }
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void *null_device(void *ud) {
    mpa *m = ud;
    float buf[2 * CHUNK];
    double t0 = now();
    uint64_t done = 0;
    while (m->thread_run) {
        struct timespec ts = {0, 5 * 1000 * 1000};
        nanosleep(&ts, NULL);
        uint64_t want = (uint64_t)((now() - t0) * m->rate);
        while (done < want) {
            int n = want - done < CHUNK ? (int)(want - done) : CHUNK;
            pthread_mutex_lock(&m->lock);
            render_locked(m, buf, n);
            pthread_mutex_unlock(&m->lock);
            done += n;
        }
    }
    return NULL;
}

// device: 1 = SDL default playback device, 0 = null device (real-time, silent), -1 = none (mpa_render only).
mpa *mpa_create(int rate, int device) {
    const char *log = getenv("MPA_LOG");
    if (log && *log && !g_log)
        g_log = fopen(log, "w");
    mpa *m = calloc(1, sizeof *m);
    pthread_mutex_init(&m->lock, NULL);
    m->rate = rate;
    if (device == 1) {
        if (!SDL_InitSubSystem(SDL_INIT_AUDIO)) {
            snprintf(last_error, sizeof last_error, "SDL_InitSubSystem(AUDIO): %s", SDL_GetError());
            free(m);
            return NULL;
        }
        SDL_SetHint(SDL_HINT_AUDIO_DEVICE_SAMPLE_FRAMES, "512");
        SDL_AudioSpec spec = {SDL_AUDIO_F32, 2, rate};
        m->stream = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &spec, sdl_callback, m);
        if (!m->stream) {
            snprintf(last_error, sizeof last_error, "SDL_OpenAudioDeviceStream: %s", SDL_GetError());
            free(m);
            return NULL;
        }
        SDL_ResumeAudioStreamDevice(m->stream);
    } else if (device == 0) {
        m->thread_run = 1;
        pthread_create(&m->thread, NULL, null_device, m);
    }
    return m;
}

int mpa_record(mpa *m, const char *path) {
    pthread_mutex_lock(&m->lock);
    if (m->wav) {
        wav_header(m->wav, m->rate, m->wav_frames);
        fclose(m->wav);
        m->wav = NULL;
    }
    int rc = 0;
    if (path) {
        m->wav = fopen(path, "wb");
        if (m->wav) {
            m->wav_frames = 0;
            wav_header(m->wav, m->rate, 0);
        } else {
            snprintf(last_error, sizeof last_error, "cannot open %s", path);
            rc = -1;
        }
    }
    pthread_mutex_unlock(&m->lock);
    return rc;
}

void mpa_destroy(mpa *m) {
    if (m->stream)
        SDL_DestroyAudioStream(m->stream);    // stops the callback
    if (m->thread_run) {
        m->thread_run = 0;
        pthread_join(m->thread, NULL);
    }
    mpa_record(m, NULL);
    for (int i = 0; i < m->nv; i++) {
        free(m->v[i].data);
        free(m->v[i].stamp);
    }
    free(m->v);
    free(m);
}

int mpa_voice_new(mpa *m, int channels, int bits, int rate, uint32_t size) {
    if ((channels != 1 && channels != 2) || (bits != 8 && bits != 16) || rate <= 0) {
        snprintf(last_error, sizeof last_error, "unsupported format %dch %d-bit %dHz", channels, bits, rate);
        return -1;
    }
    pthread_mutex_lock(&m->lock);
    int id = 0;
    while (id < m->nv && m->v[id].used)
        id++;
    if (id == m->nv) {
        m->v = realloc(m->v, sizeof(Voice) * (m->nv + 1));
        m->nv++;
    }
    Voice *v = &m->v[id];
    memset(v, 0, sizeof *v);
    v->used = 1;
    v->channels = channels;
    v->bits = bits;
    v->rate = rate;
    v->freq = rate;
    v->size = size;
    v->frame_bytes = channels * bits / 8;
    v->nframes = size / v->frame_bytes;
    v->data = calloc(1, size ? size : 1);
    if (bits == 8)
        memset(v->data, 0x80, size);          // 8-bit silence
    uint32_t nblocks = v->nframes / BLOCK + 1;
    v->stamp = malloc(sizeof(int32_t) * nblocks);
    for (uint32_t b = 0; b < nblocks; b++)
        v->stamp[b] = -1;                     // never written: stale even on the first lap
    v->stale_block = UINT32_MAX;
    v->gl = v->gr = 1.0f;
    LOG("new %d %d %d %u -> %d", channels, bits, rate, size, id);
    pthread_mutex_unlock(&m->lock);
    return id;
}

static Voice *voice(mpa *m, int id) { return id >= 0 && id < m->nv && m->v[id].used ? &m->v[id] : NULL; }

void mpa_voice_free(mpa *m, int id) {
    pthread_mutex_lock(&m->lock);
    Voice *v = voice(m, id);
    LOG("free %d", id);
    if (v) {
        free(v->data);
        free(v->stamp);
        memset(v, 0, sizeof *v);
    }
    pthread_mutex_unlock(&m->lock);
}

void mpa_voice_write(mpa *m, int id, uint32_t offset, const void *data, uint32_t len) {
    pthread_mutex_lock(&m->lock);
    Voice *v = voice(m, id);
    LOG("write %d %u %u %08x", id, offset, len, fnv(data, len));
    if (v && offset < v->size) {
        if (len > v->size - offset)
            len = v->size - offset;
        memcpy(v->data + offset, data, len);
        // data ahead of the play cursor is for this lap, data behind it for the next one
        uint32_t cur = (uint32_t)v->pos;
        for (uint32_t b = offset / v->frame_bytes / BLOCK; b <= (offset + len - 1) / v->frame_bytes / BLOCK; b++)
            v->stamp[b] = b * BLOCK + BLOCK > cur ? v->lap : v->lap + 1;
    }
    pthread_mutex_unlock(&m->lock);
}

void mpa_voice_play(mpa *m, int id, int looping) {
    pthread_mutex_lock(&m->lock);
    Voice *v = voice(m, id);
    LOG("play %d %d", id, looping);
    if (v) {
        v->playing = 1;
        v->looping = looping;
    }
    pthread_mutex_unlock(&m->lock);
}

void mpa_voice_stop(mpa *m, int id) {
    pthread_mutex_lock(&m->lock);
    Voice *v = voice(m, id);
    LOG("stop %d", id);
    if (v)
        v->playing = 0;
    pthread_mutex_unlock(&m->lock);
}

void mpa_voice_set_pos(mpa *m, int id, uint32_t byte) {
    pthread_mutex_lock(&m->lock);
    Voice *v = voice(m, id);
    LOG("pos %d %u", id, byte);
    if (v && v->nframes)
        v->pos = (byte / v->frame_bytes) % v->nframes;
    pthread_mutex_unlock(&m->lock);
}

// Play cursor in bytes; *playing is set to whether the voice is still playing.
uint32_t mpa_voice_get_pos(mpa *m, int id, int *playing) {
    pthread_mutex_lock(&m->lock);
    Voice *v = voice(m, id);
    uint32_t pos = v ? (uint32_t)v->pos * v->frame_bytes : 0;
    if (playing)
        *playing = v ? v->playing : 0;
    pthread_mutex_unlock(&m->lock);
    return pos;
}

// Frames this voice has played from data the game had not refreshed for the current lap.
uint64_t mpa_voice_stale(mpa *m, int id) {
    pthread_mutex_lock(&m->lock);
    Voice *v = voice(m, id);
    uint64_t n = v ? v->stale : 0;
    pthread_mutex_unlock(&m->lock);
    return n;
}

void mpa_voice_set_freq(mpa *m, int id, double hz) {
    pthread_mutex_lock(&m->lock);
    Voice *v = voice(m, id);
    LOG("freq %d %a", id, hz);
    if (v)
        v->freq = hz > 0 ? hz : v->rate;
    pthread_mutex_unlock(&m->lock);
}

void mpa_voice_set_gain(mpa *m, int id, float left, float right, int downmix) {
    pthread_mutex_lock(&m->lock);
    Voice *v = voice(m, id);
    LOG("gain %d %a %a %d", id, (double)left, (double)right, downmix);
    if (v) {
        v->gl = left;
        v->gr = right;
        v->downmix = downmix;
    }
    pthread_mutex_unlock(&m->lock);
}

uint64_t mpa_frames_out(mpa *m) {
    pthread_mutex_lock(&m->lock);
    uint64_t n = m->frames_out;
    pthread_mutex_unlock(&m->lock);
    return n;
}
