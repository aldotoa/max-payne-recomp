/* The registry for the native host (E6): a port of emu/mpemu.py's ADVAPI32 handlers and of what emu/launcher.py
 * configure does for a --real-entry run. The store is kept in <data>/registry.json, read at start-up and written
 * through on every change in json.dump's format (indent 1, ASCII), so the emulator and the host share one file. Key
 * paths and value names are stored lower-case: the registry is case-insensitive. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"

#define A "ADVAPI32.DLL"
#define H(name) static uint32_t name(CPU *c, const uint32_t *a)
#define UNUSED (void)c, (void)a

enum { ERROR_FILE_NOT_FOUND = 2, ERROR_ACCESS_DENIED = 5, ERROR_INVALID_HANDLE = 6, ERROR_MORE_DATA = 234,
       ERROR_NO_MORE_ITEMS = 259 };
enum { REG_SZ = 1, REG_EXPAND_SZ = 2, REG_BINARY = 3, REG_DWORD = 4 };

/* emu/launcher.py: ROOT_KEY, APP_KEY (the settings key from the real entry point) and the video settings the
 * startup dialog must have stored (seeded when missing) */
#define ROOT_KEY "HKCU\\Software\\Remedy Entertainment"
#define APP_KEY ROOT_KEY "\\Max Payne"
#define ADAPTER_DESCRIPTION "Apple GPU (Metal), Direct3D 8 emulation"   /* emu/d3d8.py */

typedef struct { char *name; uint32_t type, len; uint8_t *data; } Val;
typedef struct { char *path; Val *vals; uint32_t nvals; } Key;

static Key *g_keys;
static uint32_t g_nkeys, g_capkeys;
static struct { uint32_t h; char *path; } *g_handles;   /* open handles -> key path (as given, not lower-cased) */
static uint32_t g_nhandles, g_caphandles, g_reg_next = 0x5000;

static char *lower_dup(const char *s)
{
    char *d = strdup(s);
    for (char *p = d; *p; p++)
        if (*p >= 'A' && *p <= 'Z')
            *p = (char)(*p - 'A' + 'a');
    return d;
}

static Key *key_find(const char *path)
{
    char *lo = lower_dup(path);
    Key *k = NULL;
    for (uint32_t i = 0; i < g_nkeys && !k; i++)
        if (strcmp(g_keys[i].path, lo) == 0)
            k = &g_keys[i];
    free(lo);
    return k;
}

static Key *key_add(const char *path)
{
    Key *k = key_find(path);
    if (k)
        return k;
    if (g_nkeys == g_capkeys) {
        g_capkeys = g_capkeys ? 2 * g_capkeys : 64;
        g_keys = realloc(g_keys, g_capkeys * sizeof *g_keys);
    }
    k = &g_keys[g_nkeys++];
    k->path = lower_dup(path);
    k->vals = NULL;
    k->nvals = 0;
    return k;
}

/* _reg_key: the key, creating it and every missing key on the way (from the second part on), as Windows does */
static Key *reg_key(const char *path)
{
    char *p = strdup(path);
    int parts = 1;
    for (char *s = p; *s; s++)
        if (*s == '\\' && ++parts >= 3) {
            *s = 0;
            key_add(p);
            *s = '\\';
        }
    free(p);
    return key_add(path);
}

static Val *val_find(Key *k, const char *name)
{
    char *lo = lower_dup(name);
    Val *v = NULL;
    for (uint32_t i = 0; i < k->nvals && !v; i++)
        if (strcmp(k->vals[i].name, lo) == 0)
            v = &k->vals[i];
    free(lo);
    return v;
}

/* set (replace) or, with only_new, add when missing */
static void val_set(Key *k, const char *name, uint32_t type, const void *data, uint32_t len, int only_new)
{
    Val *v = val_find(k, name);
    if (v && only_new)
        return;
    if (!v) {
        k->vals = realloc(k->vals, (k->nvals + 1) * sizeof *k->vals);
        v = &k->vals[k->nvals++];
        v->name = lower_dup(name);
    } else
        free(v->data);
    v->type = type;
    v->len = len;
    v->data = malloc(len ? len : 1);
    if (len)
        memcpy(v->data, data, len);
}

static void val_del(Key *k, Val *v)
{
    uint32_t i = (uint32_t)(v - k->vals);
    free(v->name);
    free(v->data);
    memmove(&k->vals[i], &k->vals[i + 1], (k->nvals - i - 1) * sizeof *k->vals);
    k->nvals--;
}

static void val_sz(Key *k, const char *name, const char *s, int only_new)
{
    val_set(k, name, REG_SZ, s, (uint32_t)strlen(s) + 1, only_new);
}

static void val_dword(Key *k, const char *name, uint32_t d, int only_new)
{
    val_set(k, name, REG_DWORD, &d, 4, only_new);
}

/* ---------------------------------------------------------------- registry.json */
static void reg_file(char *out, size_t cap) { snprintf(out, cap, "%s/registry.json", host_data_dir()); }

/* json.dump's string, ensure_ascii: \" \\ \n \r \t \b \f, anything else outside ' '..'~' as \u00xx */
static void json_str(FILE *f, const uint8_t *s, size_t n)
{
    fputc('"', f);
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = s[i];
        switch (ch) {
        case '"': fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        case '\b': fputs("\\b", f); break;
        case '\f': fputs("\\f", f); break;
        default:
            if (ch < 0x20 || ch > 0x7E)
                fprintf(f, "\\u%04x", ch);
            else
                fputc(ch, f);
        }
    }
    fputc('"', f);
}

static int key_cmp(const void *x, const void *y)
{
    return strcmp((*(Key *const *)x)->path, (*(Key *const *)y)->path);
}

static int val_cmp(const void *x, const void *y)
{
    return strcmp((*(Val *const *)x)->name, (*(Val *const *)y)->name);
}

/* _reg_save: the store, sorted by key and value name, atomically */
static void reg_save(void)
{
    char path[1200], tmp[1300];
    reg_file(path, sizeof path);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f)
        host_fatal("cannot write %s", tmp);
    Key **ks = malloc((g_nkeys + 1) * sizeof *ks);
    for (uint32_t i = 0; i < g_nkeys; i++)
        ks[i] = &g_keys[i];
    qsort(ks, g_nkeys, sizeof *ks, key_cmp);
    fputs("{\n \"version\": 1,\n \"keys\": {", f);
    for (uint32_t i = 0; i < g_nkeys; i++) {
        Key *k = ks[i];
        fputs(i ? ",\n  " : "\n  ", f);
        json_str(f, (const uint8_t *)k->path, strlen(k->path));
        if (!k->nvals) {
            fputs(": {}", f);
            continue;
        }
        fputs(": {", f);
        Val **vs = malloc(k->nvals * sizeof *vs);
        for (uint32_t j = 0; j < k->nvals; j++)
            vs[j] = &k->vals[j];
        qsort(vs, k->nvals, sizeof *vs, val_cmp);
        for (uint32_t j = 0; j < k->nvals; j++) {
            Val *v = vs[j];
            fputs(j ? ",\n   " : "\n   ", f);
            json_str(f, (const uint8_t *)v->name, strlen(v->name));
            fputs(": {\n    ", f);
            if (v->type == REG_DWORD && v->len == 4) {
                uint32_t d;
                memcpy(&d, v->data, 4);
                fprintf(f, "\"dword\": %u", d);
            } else if ((v->type == REG_SZ || v->type == REG_EXPAND_SZ) && v->len && v->data[v->len - 1] == 0 &&
                       memchr(v->data, 0, v->len - 1) == NULL) {
                fprintf(f, "\"type\": %u,\n    \"string\": ", v->type);
                json_str(f, v->data, v->len - 1);
            } else {
                fprintf(f, "\"type\": %u,\n    \"hex\": \"", v->type);
                for (uint32_t b = 0; b < v->len; b++)
                    fprintf(f, "%02x", v->data[b]);
                fputc('"', f);
            }
            fputs("\n   }", f);
        }
        free(vs);
        fputs("\n  }", f);
    }
    fputs(g_nkeys ? "\n }\n}" : "}\n}", f);
    free(ks);
    fclose(f);
    if (rename(tmp, path) != 0)
        host_fatal("cannot replace %s", path);
}

/* A reader for registry.json's shape: objects, strings, integers. A malformed file reads as empty, as in Python. */
typedef struct { const char *p, *end; int bad; } J;

static void jws(J *j)
{
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\n' || *j->p == '\r' || *j->p == '\t'))
        j->p++;
}

static int jeat(J *j, char ch)
{
    jws(j);
    if (j->p < j->end && *j->p == ch) {
        j->p++;
        return 1;
    }
    return 0;
}

/* a string as latin-1 bytes (a code point above 0xFF reads as '?'); returns a malloc'd buffer and its length */
static char *jstr(J *j, size_t *len)
{
    if (!jeat(j, '"')) {
        j->bad = 1;
        return strdup("");
    }
    size_t cap = 64, n = 0;
    char *s = malloc(cap);
    while (j->p < j->end && *j->p != '"') {
        unsigned ch = (unsigned char)*j->p++;
        if (ch == '\\' && j->p < j->end) {
            char e = *j->p++;
            switch (e) {
            case 'n': ch = '\n'; break;
            case 'r': ch = '\r'; break;
            case 't': ch = '\t'; break;
            case 'b': ch = '\b'; break;
            case 'f': ch = '\f'; break;
            case 'u': {
                char hex[5] = {0};
                for (int i = 0; i < 4 && j->p < j->end; i++)
                    hex[i] = *j->p++;
                ch = (unsigned)strtoul(hex, NULL, 16);
                if (ch > 0xFF)
                    ch = '?';
                break;
            }
            default: ch = (unsigned char)e;
            }
        }
        if (n + 1 >= cap)
            s = realloc(s, cap *= 2);
        s[n++] = (char)ch;
    }
    if (!jeat(j, '"'))
        j->bad = 1;
    s[n] = 0;
    *len = n;
    return s;
}

static long long jint(J *j)
{
    jws(j);
    char *e;
    long long v = strtoll(j->p, &e, 10);
    if (e == j->p)
        j->bad = 1;
    j->p = e;
    return v;
}

static void jskip(J *j);

static void jskip_obj(J *j)
{
    if (jeat(j, '}'))
        return;
    do {
        size_t n;
        free(jstr(j, &n));
        if (!jeat(j, ':'))
            j->bad = 1;
        jskip(j);
    } while (!j->bad && jeat(j, ','));
    if (!jeat(j, '}'))
        j->bad = 1;
}

static void jskip(J *j)
{
    jws(j);
    if (j->p >= j->end) {
        j->bad = 1;
        return;
    }
    if (*j->p == '"') {
        size_t n;
        free(jstr(j, &n));
    } else if (jeat(j, '{'))
        jskip_obj(j);
    else
        jint(j);
}

static int hexval(char ch)
{
    return ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : 0;
}

/* one value object: {"dword": N} | {"type": T, "string": S} | {"type": T, "hex": H} */
static void jvalue(J *j, Key *k, const char *name)
{
    if (!jeat(j, '{')) {
        j->bad = 1;
        return;
    }
    long long dword = 0, type = -1;
    int has_dword = 0, has_string = 0;
    char *str = NULL, *hex = NULL;
    size_t slen = 0, hlen = 0;
    if (!jeat(j, '}')) {
        do {
            size_t n;
            char *field = jstr(j, &n);
            if (!jeat(j, ':'))
                j->bad = 1;
            if (!strcmp(field, "dword"))
                dword = jint(j), has_dword = 1;
            else if (!strcmp(field, "type"))
                type = jint(j);
            else if (!strcmp(field, "string"))
                free(str), str = jstr(j, &slen), has_string = 1;
            else if (!strcmp(field, "hex"))
                free(hex), hex = jstr(j, &hlen);
            else
                jskip(j);
            free(field);
        } while (!j->bad && jeat(j, ','));
        if (!jeat(j, '}'))
            j->bad = 1;
    }
    if (!j->bad) {
        if (has_dword)
            val_dword(k, name, (uint32_t)dword, 0);
        else if (has_string) {
            str = realloc(str, slen + 1);
            str[slen] = 0;
            val_set(k, name, type < 0 ? REG_SZ : (uint32_t)type, str, (uint32_t)slen + 1, 0);
        } else {
            uint32_t n = (uint32_t)(hex ? hlen / 2 : 0);
            uint8_t *b = malloc(n + 1);
            for (uint32_t i = 0; i < n; i++)
                b[i] = (uint8_t)(hexval(hex[2 * i]) << 4 | hexval(hex[2 * i + 1]));
            val_set(k, name, type < 0 ? REG_BINARY : (uint32_t)type, b, n, 0);
            free(b);
        }
    }
    free(str);
    free(hex);
}

/* _reg_load into the store; nothing when the file is missing or malformed */
static void reg_load(void)
{
    char path[1200];
    reg_file(path, sizeof path);
    FILE *f = fopen(path, "rb");
    if (!f)
        return;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)size + 1);
    size_t got = fread(buf, 1, (size_t)size, f);
    fclose(f);
    /* parse into a scratch store first: a malformed file must leave nothing behind */
    Key *keep = g_keys;
    uint32_t keep_n = g_nkeys, keep_cap = g_capkeys;
    g_keys = NULL, g_nkeys = g_capkeys = 0;
    J j = {buf, buf + got, 0};
    if (jeat(&j, '{') && !jeat(&j, '}')) {
        do {
            size_t n;
            char *field = jstr(&j, &n);
            if (!jeat(&j, ':'))
                j.bad = 1;
            if (strcmp(field, "keys") != 0 || !jeat(&j, '{')) {
                if (strcmp(field, "keys") == 0)
                    j.bad = 1;
                jskip(&j);
            } else if (!jeat(&j, '}')) {
                do {
                    char *kp = jstr(&j, &n);
                    Key *k = key_add(kp);
                    free(kp);
                    if (!jeat(&j, ':') || !jeat(&j, '{'))
                        j.bad = 1;
                    else if (!jeat(&j, '}')) {
                        do {
                            char *vn = jstr(&j, &n);
                            if (!jeat(&j, ':'))
                                j.bad = 1;
                            if (!j.bad)
                                jvalue(&j, k, vn);
                            free(vn);
                        } while (!j.bad && jeat(&j, ','));
                        if (!jeat(&j, '}'))
                            j.bad = 1;
                    }
                } while (!j.bad && jeat(&j, ','));
                if (!jeat(&j, '}'))
                    j.bad = 1;
            }
            free(field);
        } while (!j.bad && jeat(&j, ','));
    }
    free(buf);
    Key *loaded = g_keys;
    uint32_t loaded_n = g_nkeys, nloaded = j.bad ? 0 : g_nkeys;
    g_keys = keep, g_nkeys = keep_n, g_capkeys = keep_cap;
    for (uint32_t i = 0; i < nloaded; i++) {      /* e.registry.setdefault(key, {}).update(values) */
        Key *k = key_add(loaded[i].path);
        for (uint32_t v = 0; v < loaded[i].nvals; v++)
            val_set(k, loaded[i].vals[v].name, loaded[i].vals[v].type, loaded[i].vals[v].data, loaded[i].vals[v].len,
                    0);
    }
    for (uint32_t i = 0; i < loaded_n; i++) {
        for (uint32_t v = 0; v < loaded[i].nvals; v++)
            free(loaded[i].vals[v].name), free(loaded[i].vals[v].data);
        free(loaded[i].vals);
        free(loaded[i].path);
    }
    free(loaded);
}

/* The store as emu/run_init.py --real-entry leaves it before guest code runs: _regstore (the keys every Windows has,
 * then the file), launcher._copy_classic_settings (the settings under ROOT_KEY copied to APP_KEY on the first such
 * run), the launcher's seed (the Video Settings the dialog would have stored, when missing), saved. */
void host_registry_init(void)
{
    host_mkdirs(host_data_dir());
    key_add("hkcu\\software");
    key_add("hklm\\software");
    key_add("hkcr");
    reg_load();
    char *old = lower_dup(ROOT_KEY), *new = lower_dup(APP_KEY);
    size_t no = strlen(old), nn = strlen(new);
    int have = 0;
    for (uint32_t i = 0; i < g_nkeys; i++)
        if (strncmp(g_keys[i].path, new, nn) == 0 && (g_keys[i].path[nn] == 0 || g_keys[i].path[nn] == '\\'))
            have = 1;
    if (!have) {
        uint32_t n = g_nkeys;
        for (uint32_t i = 0; i < n; i++) {
            if (strncmp(g_keys[i].path, old, no) != 0 || g_keys[i].path[no] != '\\')
                continue;
            char dst[2048];
            snprintf(dst, sizeof dst, "%s%s", new, g_keys[i].path + no);
            Key *d = reg_key(dst), *s = &g_keys[i];
            for (uint32_t v = 0; v < s->nvals; v++)
                val_set(d, s->vals[v].name, s->vals[v].type, s->vals[v].data, s->vals[v].len, 0);
        }
    }
    free(old);
    free(new);
    Key *vs = reg_key(APP_KEY "\\Video Settings");
    val_sz(vs, "Driver", ADAPTER_DESCRIPTION, 1);
    val_dword(vs, "Display Width", HOST_SCREEN_W, 1);
    val_dword(vs, "Display Height", HOST_SCREEN_H, 1);
    val_dword(vs, "Display Bits Per Pixel", 32, 1);
    val_dword(vs, "CPU Driver", 0, 1);
    val_dword(vs, "HW Acceleration Level", 2, 1);
    reg_save();
}

void host_registry_set_resolution(uint32_t w, uint32_t h)
{
    Key *vs = reg_key(APP_KEY "\\Video Settings");
    val_dword(vs, "Display Width", w, 0);
    val_dword(vs, "Display Height", h, 0);
    reg_save();
}

/* a REG_DWORD value of the store, or dflt (launcher.resolution reads the video settings so) */
uint32_t host_reg_dword(const char *path, const char *name, uint32_t dflt)
{
    Key *k = key_find(path);
    Val *v = k ? val_find(k, name) : NULL;
    uint32_t d = dflt;
    if (v && v->len >= 4)
        memcpy(&d, v->data, 4);
    return d;
}

/* ---------------------------------------------------------------- handles */
static const char *root_name(uint32_t hk)
{
    switch (hk) {
    case 0x80000000u: return "HKCR";
    case 0x80000001u: return "HKCU";
    case 0x80000002u: return "HKLM";
    case 0x80000003u: return "HKU";
    }
    return NULL;
}

static const char *handle_path(uint32_t h)
{
    for (uint32_t i = 0; i < g_nhandles; i++)
        if (g_handles[i].h == h)
            return g_handles[i].path;
    return NULL;
}

/* HKEY_ROOTS.get(hk) or e.reg_handles.get(hk) */
static const char *base_of(uint32_t hk)
{
    const char *r = root_name(hk);
    return r ? r : handle_path(hk);
}

/* _reg_open: a new handle to base\sub; 0 when the base is unknown, or the key is missing and not created */
static uint32_t reg_open(uint32_t hk, uint32_t subp, int create)
{
    const char *base = base_of(hk);
    if (!base)
        return 0;
    char sub[4100] = "", path[8300];
    if (subp)
        host_cstr(subp, sub, sizeof sub);
    snprintf(path, sizeof path, sub[0] ? "%s\\%s" : "%s", base, sub);
    if (!key_find(path)) {
        if (!create)
            return 0;
        reg_key(path);
        reg_save();
    }
    uint32_t h = g_reg_next;               /* a counter: handles of closed keys are never reused */
    g_reg_next += 4;
    if (g_nhandles == g_caphandles) {
        g_caphandles = g_caphandles ? 2 * g_caphandles : 64;
        g_handles = realloc(g_handles, g_caphandles * sizeof *g_handles);
    }
    g_handles[g_nhandles].h = h;
    g_handles[g_nhandles].path = strdup(path);
    g_nhandles++;
    return h;
}

H(RegCreateKeyExA)
{
    UNUSED;
    uint32_t h = reg_open(a[0], a[1], 1);
    if (!h)
        return ERROR_INVALID_HANDLE;
    memcpy(gptr(a[7]), &h, 4);
    if (a[8]) {
        uint32_t disp = 2;                 /* REG_OPENED_EXISTING_KEY */
        memcpy(gptr(a[8]), &disp, 4);
    }
    return 0;
}

H(RegCreateKeyA)
{
    UNUSED;
    uint32_t h = reg_open(a[0], a[1], 1);
    if (!h)
        return ERROR_INVALID_HANDLE;
    memcpy(gptr(a[2]), &h, 4);
    return 0;
}

H(RegOpenKeyExA)
{
    UNUSED;
    uint32_t h = reg_open(a[0], a[1], 0);
    if (!h)
        return ERROR_FILE_NOT_FOUND;
    memcpy(gptr(a[4]), &h, 4);
    return 0;
}

H(RegOpenKeyA)
{
    UNUSED;
    uint32_t h = reg_open(a[0], a[1], 0);
    if (!h)
        return ERROR_FILE_NOT_FOUND;
    memcpy(gptr(a[2]), &h, 4);
    return 0;
}

H(RegQueryValueExA)
{
    UNUSED;
    const char *path = handle_path(a[0]);
    char name[4100] = "";
    if (a[1])
        host_cstr(a[1], name, sizeof name);
    Key *k = key_find(path ? path : "");
    Val *v = k ? val_find(k, name) : NULL;
    if (!v)
        return ERROR_FILE_NOT_FOUND;
    if (a[3])
        memcpy(gptr(a[3]), &v->type, 4);
    if (a[5]) {
        uint32_t cap;
        memcpy(&cap, gptr(a[5]), 4);
        memcpy(gptr(a[5]), &v->len, 4);
        if (a[4]) {
            if (cap < v->len)
                return ERROR_MORE_DATA;
            memcpy(gptr(a[4]), v->data, v->len);
        }
    }
    return 0;
}

H(RegSetValueExA)
{
    UNUSED;
    const char *path = handle_path(a[0]);
    if (!path)
        return ERROR_INVALID_HANDLE;
    char name[4100] = "";
    if (a[1])
        host_cstr(a[1], name, sizeof name);
    val_set(key_add(path), name, a[3], gptr(a[4]), a[5], 0);
    reg_save();
    return 0;
}

H(RegSetValueA)
{
    UNUSED;
    const char *base = base_of(a[0]);
    char sub[4100] = "", path[8300], data[4100];
    if (a[1])
        host_cstr(a[1], sub, sizeof sub);
    snprintf(path, sizeof path, a[1] ? "%s\\%s" : "%s", base ? base : "?", sub);
    data[0] = 0;
    if (a[3])
        host_cstr(a[3], data, sizeof data);
    val_sz(key_add(path), "", data, 0);
    reg_save();
    return 0;
}

H(RegDeleteValueA)
{
    UNUSED;
    const char *path = handle_path(a[0]);
    if (!path)
        path = root_name(a[0]);
    char name[4100] = "";
    if (a[1])
        host_cstr(a[1], name, sizeof name);
    Key *k = key_find(path ? path : "");
    Val *v = k ? val_find(k, name) : NULL;
    if (!v)
        return ERROR_FILE_NOT_FOUND;
    val_del(k, v);
    reg_save();
    return 0;
}

/* a key that has no subkeys (Windows NT semantics) */
H(RegDeleteKeyA)
{
    UNUSED;
    const char *base = handle_path(a[0]);
    if (!base)
        base = root_name(a[0]);
    if (!base || !a[1])
        return ERROR_INVALID_HANDLE;
    char sub[4100], path[8300];
    host_cstr(a[1], sub, sizeof sub);
    snprintf(path, sizeof path, "%s\\%s", base, sub);
    Key *k = key_find(path);
    if (!k)
        return ERROR_FILE_NOT_FOUND;
    size_t n = strlen(k->path);
    for (uint32_t i = 0; i < g_nkeys; i++)
        if (strncmp(g_keys[i].path, k->path, n) == 0 && g_keys[i].path[n] == '\\')
            return ERROR_ACCESS_DENIED;
    uint32_t i = (uint32_t)(k - g_keys);
    for (uint32_t v = 0; v < k->nvals; v++)
        free(k->vals[v].name), free(k->vals[v].data);
    free(k->vals);
    free(k->path);
    memmove(&g_keys[i], &g_keys[i + 1], (g_nkeys - i - 1) * sizeof *g_keys);
    g_nkeys--;
    reg_save();
    return 0;
}

H(RegCloseKey)
{
    UNUSED;
    for (uint32_t i = 0; i < g_nhandles; i++)
        if (g_handles[i].h == a[0]) {
            free(g_handles[i].path);
            g_handles[i] = g_handles[--g_nhandles];
            break;
        }
    return 0;
}

H(Return0) { UNUSED; return 0; }
H(NotFound) { UNUSED; return ERROR_FILE_NOT_FOUND; }
H(NoMoreItems) { UNUSED; return ERROR_NO_MORE_ITEMS; }

const HleDef hle_advapi32[] = {
    {A, "RegCreateKeyExA", 9, STDCALL, RegCreateKeyExA},
    {A, "RegCreateKeyA", 3, STDCALL, RegCreateKeyA},
    {A, "RegOpenKeyExA", 5, STDCALL, RegOpenKeyExA},
    {A, "RegOpenKeyA", 3, STDCALL, RegOpenKeyA},
    {A, "RegQueryValueExA", 6, STDCALL, RegQueryValueExA},
    {A, "RegSetValueExA", 6, STDCALL, RegSetValueExA},
    {A, "RegSetValueA", 5, STDCALL, RegSetValueA},
    {A, "RegDeleteValueA", 2, STDCALL, RegDeleteValueA},
    {A, "RegDeleteKeyA", 2, STDCALL, RegDeleteKeyA},
    {A, "RegQueryValueA", 4, STDCALL, NotFound},
    {A, "RegCloseKey", 1, STDCALL, RegCloseKey},
    {A, "RegFlushKey", 1, STDCALL, Return0},
    {A, "RegEnumKeyA", 4, STDCALL, NoMoreItems},
    {A, "RegEnumKeyExA", 8, STDCALL, NoMoreItems},
    {NULL, NULL, 0, 0, NULL},
};
