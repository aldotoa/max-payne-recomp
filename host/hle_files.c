/* KERNEL32 files for the native host (E5/E6): ports of emu/mpemu.py's file handlers. Guest paths map onto the game
 * folder (read-only; a write copies the file into the overlay first) and the per-user data (host_read_path,
 * host_write_path in mphost.c). A file handle holds a stdio stream, as the Python handle holds a file object. */
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "host.h"

#define K "KERNEL32.DLL"
#define H(name) static uint32_t name(CPU *c, const uint32_t *a)
#define UNUSED (void)c, (void)a
#define INVALID_HANDLE 0xFFFFFFFFu
#define GENERIC_WRITE 0x40000000u

static inline void w32(uint32_t p, uint32_t v) { memcpy(gptr(p), &v, 4); }
static inline uint16_t r16(uint32_t p) { uint16_t v; memcpy(&v, gptr(p), 2); return v; }
static inline void w16(uint32_t p, uint16_t v) { memcpy(gptr(p), &v, 2); }

/* e.wstr as a Latin-1 string (the paths are ASCII; a wider character becomes '?') */
static void wpath(uint32_t a, char *out, size_t cap)
{
    uint16_t w[4100];
    size_t n = host_wstr(a, w, 4100);
    size_t k = 0;
    for (; k < n && k + 1 < cap; k++)
        out[k] = (char)(w[k] < 256 ? w[k] : '?');
    out[k] = 0;
}

static int is_dir(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

static int is_file(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static int exists(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0;
}

static void copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb"), *out = in ? fopen(dst, "wb") : NULL;
    if (!in || !out)
        host_fatal("cannot copy %s to %s: %s", src, dst, strerror(errno));
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0)
        fwrite(buf, 1, n, out);
    fclose(in);
    fclose(out);
}

/* time.time() and os.path.getmtime as FILETIMEs, computed in doubles as Python does */
static uint64_t now_filetime(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double t = (double)tv.tv_sec + (double)tv.tv_usec * 1e-6;
    return (uint64_t)((t + 11644473600.0) * 10000000.0);
}

static uint64_t filetime_of(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    double m = (double)st.st_mtimespec.tv_sec + (double)st.st_mtimespec.tv_nsec * 1e-9;
    return (uint64_t)((m + 11644473600.0) * 10000000.0);
}

/* ---- paths */
H(GetFullPathNameA)
{
    UNUSED;
    char g[1024], full[1100];
    host_cstr(a[0], g, sizeof g);
    host_guest_abs(g, full, sizeof full);
    uint32_t n = (uint32_t)strlen(full);
    if (a[1] < n + 1)
        return n + 1;
    memcpy(gptr(a[2]), full, n + 1);
    if (a[3]) {
        char *bs = strrchr(full, '\\');
        w32(a[3], a[2] + (bs ? (uint32_t)(bs - full) + 1 : 0));
    }
    return n;
}

H(GetFullPathNameW)
{
    UNUSED;
    char g[1024], full[1100];
    wpath(a[0], g, sizeof g);
    host_guest_abs(g, full, sizeof full);
    uint32_t n = (uint32_t)strlen(full);
    if (a[1] < n + 1)
        return n + 1;
    for (uint32_t i = 0; i <= n; i++)
        w16(a[2] + 2 * i, (uint8_t)full[i]);
    if (a[3]) {
        char *bs = strrchr(full, '\\');
        w32(a[3], a[2] + 2 * (bs ? (uint32_t)(bs - full) + 1 : 0));
    }
    return n;
}

H(GetShortPathNameA)
{
    UNUSED;
    char s[4100];
    uint32_t n = (uint32_t)host_cstr(a[0], s, sizeof s);
    if (a[2] < n + 1)
        return n + 1;
    memcpy(gptr(a[1]), s, n + 1);
    return n;
}

static uint32_t attrs(const char *guest)
{
    char hp[1024];
    host_read_path(guest, hp, sizeof hp);
    if (is_dir(hp))
        return 0x10;
    if (exists(hp))
        return 0x20;
    host_set_last_error(2);
    return INVALID_HANDLE;
}

H(GetFileAttributesA)
{
    UNUSED;
    char g[1024];
    host_cstr(a[0], g, sizeof g);
    return attrs(g);
}

H(GetFileAttributesW)
{
    UNUSED;
    char g[1024];
    wpath(a[0], g, sizeof g);
    return attrs(g);
}

H(Return1) { UNUSED; return 1; }

/* ---- open, read, write, seek */
static uint32_t open_file(const char *guest, uint32_t access, uint32_t disp)
{
    int writing = (access & GENERIC_WRITE) || disp == 1 || disp == 2 || disp == 4 || disp == 5;
    char rp[1024];
    FILE *f;
    host_read_path(guest, rp, sizeof rp);
    if (writing) {
        char wp[1024];
        host_write_path(guest, wp, sizeof wp);
        int ex = exists(rp);
        if (disp == 1 && ex) {
            host_set_last_error(80);
            return INVALID_HANDLE;
        }
        if (disp == 3 && !ex) {
            host_set_last_error(2);
            return INVALID_HANDLE;
        }
        if (ex && strcmp(rp, wp) != 0 && disp != 2 && disp != 5)
            copy_file(rp, wp);                 /* copy-on-write into the overlay */
        f = fopen(wp, (disp == 2 || disp == 5 || !exists(wp)) ? "w+b" : "r+b");
        if (!f)
            host_fatal("cannot open %s for writing: %s", wp, strerror(errno));
    } else {
        if (!is_file(rp)) {
            host_set_last_error(2);
            return INVALID_HANDLE;
        }
        f = fopen(rp, "rb");
        if (!f)
            host_fatal("cannot open %s: %s", rp, strerror(errno));
    }
    host_set_last_error(0);
    return host_new_handle(HK_FILE, f);
}

H(CreateFileA)
{
    UNUSED;
    char g[1024];
    host_cstr(a[0], g, sizeof g);
    host_note_open(g);
    return open_file(g, a[1], a[4]);
}

H(CreateFileW)
{
    UNUSED;
    char g[1024];
    wpath(a[0], g, sizeof g);
    return open_file(g, a[1], a[4]);
}

H(ReadFile)
{
    UNUSED;
    FILE *f = host_handle(a[0], HK_FILE);
    if (!f) {
        host_set_last_error(6);
        return 0;
    }
    size_t n = fread(gptr(a[1]), 1, a[2], f);
    if (a[3])
        w32(a[3], (uint32_t)n);
    return 1;
}

H(WriteFile)
{
    UNUSED;
    if (a[0] == 0x11 || a[0] == 0x12) {
        fwrite(gptr(a[1]), 1, a[2], stdout);
    } else {
        FILE *f = host_handle(a[0], HK_FILE);
        if (!f) {
            host_set_last_error(6);
            return 0;
        }
        fwrite(gptr(a[1]), 1, a[2], f);
    }
    if (a[3])
        w32(a[3], a[2]);
    return 1;
}

H(SetFilePointer)
{
    UNUSED;
    FILE *f = host_handle(a[0], HK_FILE);
    if (!f)
        return INVALID_HANDLE;
    if (fseeko(f, (off_t)(int32_t)a[1], (int)a[3]) != 0)
        host_fatal("SetFilePointer(0x%x, %d, method %u): %s", a[0], (int32_t)a[1], a[3], strerror(errno));
    return (uint32_t)ftello(f);
}

static off_t file_size(FILE *f)
{
    off_t cur = ftello(f);
    fseeko(f, 0, SEEK_END);
    off_t size = ftello(f);
    fseeko(f, cur, SEEK_SET);
    return size;
}

H(GetFileSize)
{
    UNUSED;
    FILE *f = host_handle(a[0], HK_FILE);
    if (!f)
        return INVALID_HANDLE;
    off_t size = file_size(f);
    if (a[1])
        w32(a[1], (uint32_t)((uint64_t)size >> 32));
    return (uint32_t)size;
}

H(GetFileTime)
{
    UNUSED;
    uint64_t t = now_filetime();
    for (int i = 1; i < 4; i++)
        if (a[i])
            memcpy(gptr(a[i]), &t, 8);
    return 1;
}

H(SetEndOfFile)
{
    UNUSED;
    FILE *f = host_handle(a[0], HK_FILE);
    if (f) {
        fflush(f);
        if (ftruncate(fileno(f), ftello(f)) != 0)
            host_fatal("SetEndOfFile: %s", strerror(errno));
    }
    return 1;
}

H(GetFileInformationByHandle)
{
    UNUSED;
    FILE *f = host_handle(a[0], HK_FILE);
    if (!f)
        return 0;
    uint32_t size = (uint32_t)file_size(f), p = a[1];
    memset(gptr(p), 0, 52);
    w32(p, 0x20);
    w32(p + 32, size);                         /* nFileSizeLow (struct.pack("<IIIII", 0, size, 1, 0, 0) at +28) */
    w32(p + 36, 1);
    return 1;
}

H(CloseHandle)
{
    UNUSED;
    int kind;
    void *obj = host_handle_pop(a[0], &kind);
    if (kind == HK_FILE && obj)
        fclose(obj);
    return 1;
}

H(CreateFileMappingA)
{
    UNUSED;
    FILE *f = host_handle(a[0], HK_FILE);
    return f ? host_new_handle(HK_MAPPING, f) : 0;
}

H(MapViewOfFile)
{
    UNUSED;
    FILE *f = host_handle(a[0], HK_MAPPING);
    if (!f)
        return 0;
    off_t cur = ftello(f), size = file_size(f);
    off_t n = a[4] ? (off_t)a[4] : size - (off_t)a[3];
    fseeko(f, (off_t)a[3], SEEK_SET);
    char *buf = malloc(n > 0 ? (size_t)n : 1);
    size_t got = n > 0 ? fread(buf, 1, (size_t)n, f) : 0;
    fseeko(f, cur, SEEK_SET);
    uint32_t p = host_heap_reserve((uint32_t)got, 0);
    memcpy(gptr(p), buf, got);
    free(buf);
    return p;
}

/* ---- directory enumeration */
typedef struct {
    char name[256], *full;
} FindEnt;

typedef struct {
    FindEnt *ents;
    uint32_t n, i;
    int wide;
} Find;

static int ent_cmp(const void *x, const void *y)
{
    return strcmp(((const FindEnt *)x)->name, ((const FindEnt *)y)->name);
}

static void join(char *out, size_t cap, const char *dir, const char *name)
{
    snprintf(out, cap, "%s/%s", dir, name);
}

/* _find_entries: ".", ".." and the folder's entries (the overlay's shadow the game's of the same name, any case),
 * sorted, that match the pattern (fnmatch on lower case, "*.*" as "*"). */
static Find *find_entries(const char *pattern_guest, int wide)
{
    char abs[1100];
    host_guest_abs(pattern_guest, abs, sizeof abs);
    char *bs = strrchr(abs, '\\');
    char guest_dir[1100], pat[512];
    if (bs) {
        *bs = 0;
        snprintf(guest_dir, sizeof guest_dir, "%s", abs[0] ? abs : "C:\\MaxPayne");
        snprintf(pat, sizeof pat, "%s", bs + 1);
    } else {
        snprintf(guest_dir, sizeof guest_dir, "C:\\MaxPayne");
        snprintf(pat, sizeof pat, "%s", abs);
    }
    char game_dir[1024], ov_dir[1024];
    host_dir_paths(guest_dir, game_dir, ov_dir, sizeof game_dir);
    FindEnt *list = NULL;
    uint32_t n = 0, cap = 0;
    const char *bases[2] = {game_dir, ov_dir};
    for (int b = 0; b < 2; b++) {
        if (b == 1 && strcmp(game_dir, ov_dir) == 0)
            break;
        DIR *d = opendir(bases[b]);
        if (!d)
            continue;
        struct dirent *de;
        while ((de = readdir(d))) {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                continue;
            uint32_t k = 0;
            while (k < n && strcasecmp(list[k].name, de->d_name) != 0)
                k++;
            if (k == n) {
                if (n == cap) {
                    cap = cap ? 2 * cap : 64;
                    list = realloc(list, cap * sizeof *list);
                }
                n++;
                list[k].full = NULL;
            }
            snprintf(list[k].name, sizeof list[k].name, "%s", de->d_name);
            char full[1300];
            join(full, sizeof full, bases[b], de->d_name);
            free(list[k].full);
            list[k].full = strdup(full);
        }
        closedir(d);
    }
    if (!n && !is_dir(game_dir) && !is_dir(ov_dir)) {
        free(list);
        return NULL;
    }
    qsort(list, n, sizeof *list, ent_cmp);
    char lpat[512];
    snprintf(lpat, sizeof lpat, "%s", pat);
    for (char *p = lpat; *p; p++)
        if (*p >= 'A' && *p <= 'Z')
            *p = (char)(*p + 32);
    char *star = strstr(lpat, "*.*");
    while (star) {                             /* pat.lower().replace("*.*", "*") */
        memmove(star + 1, star + 3, strlen(star + 3) + 1);
        star = strstr(star + 1, "*.*");
    }
    Find *fd = calloc(1, sizeof *fd);
    fd->ents = calloc(n + 2, sizeof *fd->ents);
    fd->wide = wide;
    for (uint32_t k = 0; k < n + 2; k++) {
        const char *name = k == 0 ? "." : k == 1 ? ".." : list[k - 2].name;
        char lname[256];
        snprintf(lname, sizeof lname, "%s", name);
        for (char *p = lname; *p; p++)
            if (*p >= 'A' && *p <= 'Z')
                *p = (char)(*p + 32);
        if (fnmatch(lpat, lname, FNM_NOESCAPE) != 0)
            continue;
        FindEnt *e = &fd->ents[fd->n++];
        snprintf(e->name, sizeof e->name, "%s", name);
        e->full = strdup(k < 2 ? game_dir : list[k - 2].full);
    }
    for (uint32_t k = 0; k < n; k++)
        free(list[k].full);
    free(list);
    return fd;
}

static void fill_find(uint32_t p, const FindEnt *e, int wide)
{
    struct stat st;
    int isdir = stat(e->full, &st) == 0 && S_ISDIR(st.st_mode);
    uint64_t size = isdir ? 0 : (uint64_t)st.st_size, ft = filetime_of(e->full);
    w32(p, isdir ? 0x10 : 0x20);
    for (int i = 0; i < 3; i++)
        memcpy(gptr(p + 4 + 8 * (uint32_t)i), &ft, 8);
    w32(p + 28, (uint32_t)(size >> 32));
    w32(p + 32, (uint32_t)size);
    w32(p + 36, 0);
    w32(p + 40, 0);
    size_t n = strlen(e->name);
    if (wide) {
        memset(gptr(p + 44), 0, 520 + 28);
        if (n > 259)
            n = 259;
        for (size_t i = 0; i < n; i++)
            w16(p + 44 + 2 * (uint32_t)i, (uint8_t)e->name[i]);
    } else {
        memset(gptr(p + 44), 0, 260 + 14);
        memcpy(gptr(p + 44), e->name, n > 259 ? 259 : n);
    }
}

static uint32_t find_first(const char *pattern, uint32_t p, int wide)
{
    Find *fd = find_entries(pattern, wide);
    if (!fd || !fd->n) {
        if (fd) {
            free(fd->ents);
            free(fd);
        }
        host_set_last_error(2);
        return INVALID_HANDLE;
    }
    fd->i = 1;
    uint32_t h = host_new_handle(HK_FIND, fd);
    fill_find(p, &fd->ents[0], wide);
    return h;
}

H(FindFirstFileA)
{
    UNUSED;
    char g[1024];
    host_cstr(a[0], g, sizeof g);
    return find_first(g, a[1], 0);
}

H(FindFirstFileW)
{
    UNUSED;
    char g[1024];
    wpath(a[0], g, sizeof g);
    return find_first(g, a[1], 1);
}

H(FindNextFile)
{
    UNUSED;
    Find *fd = host_handle(a[0], HK_FIND);
    if (!fd)
        return 0;
    if (fd->i >= fd->n) {
        host_set_last_error(18);
        return 0;
    }
    fill_find(a[1], &fd->ents[fd->i++], fd->wide);
    return 1;
}

H(FindClose)
{
    UNUSED;
    int kind;
    host_handle_pop(a[0], &kind);              /* the entries stay allocated: a handle number is never reused */
    return 1;
}

/* ---- directories, deletion, copies */
static void make_dirs(const char *path)
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

H(CreateDirectoryA)
{
    UNUSED;
    char g[1024], wp[1024];
    host_cstr(a[0], g, sizeof g);
    host_write_path(g, wp, sizeof wp);
    make_dirs(wp);
    return 1;
}

H(DeleteFileA)
{
    UNUSED;
    char g[1024], wp[1024];
    host_cstr(a[0], g, sizeof g);
    host_write_path(g, wp, sizeof wp);
    remove(wp);
    return 1;
}

H(CopyFileA)
{
    UNUSED;
    char g[1024], src[1024], dst[1024];
    host_cstr(a[0], g, sizeof g);
    host_read_path(g, src, sizeof src);
    if (!is_file(src)) {
        host_set_last_error(2);
        return 0;
    }
    host_cstr(a[1], g, sizeof g);
    host_write_path(g, dst, sizeof dst);
    copy_file(src, dst);
    return 1;
}

/* SHELL32 SHGetSpecialFolderPathA: the folders under the guest C:\ (mpemu SHELL_FOLDERS), made when asked to */
H(SHGetSpecialFolderPathA)
{
    UNUSED;
    const char *path = NULL;
    switch (a[2] & 0xFF) {
    case 0x05: case 0x2E: path = "C:\\My Documents"; break;
    case 0x1A: path = "C:\\Application Data"; break;
    case 0x1C: path = "C:\\Local Settings\\Application Data"; break;
    case 0x10: path = "C:\\Desktop"; break;
    case 0x23: path = "C:\\All Users\\Application Data"; break;
    }
    if (!path)
        return 0;
    if (a[3]) {
        char host[2048];
        host_write_path(path, host, sizeof host);
        host_mkdirs(host);
    }
    memcpy(gptr(a[1]), path, strlen(path) + 1);
    return 1;
}

H(GetDiskFreeSpaceA)
{
    UNUSED;
    static const uint32_t v[4] = {8, 512, 1u << 20, 2u << 20};
    for (int i = 0; i < 4; i++)
        if (a[i + 1])
            w32(a[i + 1], v[i]);
    return 1;
}

H(GetDriveType) { UNUSED; return 3; }
H(GetLogicalDrives) { UNUSED; return 0x4; }

/* SYSTEMTIME from time.gmtime of a FILETIME's seconds (floored, as time.gmtime takes a float) */
H(FileTimeToSystemTime)
{
    UNUSED;
    uint64_t ft;
    memcpy(&ft, gptr(a[0]), 8);
    time_t t = (time_t)floor((double)ft / 10000000.0 - 11644473600.0);
    struct tm tm;
    gmtime_r(&t, &tm);
    uint16_t v[8] = {(uint16_t)(tm.tm_year + 1900), (uint16_t)(tm.tm_mon + 1), (uint16_t)tm.tm_wday,
                     (uint16_t)tm.tm_mday, (uint16_t)tm.tm_hour, (uint16_t)tm.tm_min, (uint16_t)tm.tm_sec, 0};
    memcpy(gptr(a[1]), v, sizeof v);
    return 1;
}

H(CopyFileTime)
{
    UNUSED;
    memmove(gptr(a[1]), gptr(a[0]), 8);
    return 1;
}

H(SystemTimeToFileTime)
{
    UNUSED;
    struct tm tm = {0};
    tm.tm_year = r16(a[0]) - 1900;
    tm.tm_mon = r16(a[0] + 2) - 1;
    tm.tm_mday = r16(a[0] + 6);
    tm.tm_hour = r16(a[0] + 8);
    tm.tm_min = r16(a[0] + 10);
    tm.tm_sec = r16(a[0] + 12);
    uint64_t ft = ((uint64_t)timegm(&tm) + 11644473600ull) * 10000000ull;
    memcpy(gptr(a[1]), &ft, 8);
    return 1;
}

const HleDef hle_files[] = {
    {K, "GetFullPathNameA", 4, STDCALL, GetFullPathNameA},
    {K, "GetFullPathNameW", 4, STDCALL, GetFullPathNameW},
    {K, "GetShortPathNameA", 3, STDCALL, GetShortPathNameA},
    {K, "GetFileAttributesA", 1, STDCALL, GetFileAttributesA},
    {K, "GetFileAttributesW", 1, STDCALL, GetFileAttributesW},
    {K, "SetFileAttributesA", 2, STDCALL, Return1},
    {K, "SetFileAttributesW", 2, STDCALL, Return1},
    {K, "CreateFileA", 7, STDCALL, CreateFileA},
    {K, "CreateFileW", 7, STDCALL, CreateFileW},
    {K, "ReadFile", 5, STDCALL, ReadFile},
    {K, "WriteFile", 5, STDCALL, WriteFile},
    {K, "SetFilePointer", 4, STDCALL, SetFilePointer},
    {K, "GetFileSize", 2, STDCALL, GetFileSize},
    {K, "GetFileTime", 4, STDCALL, GetFileTime},
    {K, "SetFileTime", 4, STDCALL, Return1},
    {K, "SetEndOfFile", 1, STDCALL, SetEndOfFile},
    {K, "FlushFileBuffers", 1, STDCALL, Return1},
    {K, "GetFileInformationByHandle", 2, STDCALL, GetFileInformationByHandle},
    {K, "LockFile", 5, STDCALL, Return1},
    {K, "UnlockFile", 5, STDCALL, Return1},
    {K, "CloseHandle", 1, STDCALL, CloseHandle},
    {K, "CreateFileMappingA", 6, STDCALL, CreateFileMappingA},
    {K, "MapViewOfFile", 5, STDCALL, MapViewOfFile},
    {K, "UnmapViewOfFile", 1, STDCALL, Return1},
    {K, "FindFirstFileA", 2, STDCALL, FindFirstFileA},
    {K, "FindFirstFileW", 2, STDCALL, FindFirstFileW},
    {K, "FindNextFileA", 2, STDCALL, FindNextFile},
    {K, "FindNextFileW", 2, STDCALL, FindNextFile},
    {K, "FindClose", 1, STDCALL, FindClose},
    {K, "CreateDirectoryA", 2, STDCALL, CreateDirectoryA},
    {K, "RemoveDirectoryA", 1, STDCALL, Return1},
    {K, "RemoveDirectoryW", 1, STDCALL, Return1},
    {K, "DeleteFileA", 1, STDCALL, DeleteFileA},
    {K, "CopyFileA", 3, STDCALL, CopyFileA},
    {K, "GetDiskFreeSpaceA", 5, STDCALL, GetDiskFreeSpaceA},
    {"SHELL32.DLL", "SHGetSpecialFolderPathA", 4, STDCALL, SHGetSpecialFolderPathA},
    {K, "GetDriveTypeA", 1, STDCALL, GetDriveType},
    {K, "GetDriveTypeW", 1, STDCALL, GetDriveType},
    {K, "GetLogicalDrives", 0, STDCALL, GetLogicalDrives},
    {K, "FileTimeToSystemTime", 2, STDCALL, FileTimeToSystemTime},
    {K, "FileTimeToLocalFileTime", 2, STDCALL, CopyFileTime},
    {K, "LocalFileTimeToFileTime", 2, STDCALL, CopyFileTime},
    {K, "SystemTimeToFileTime", 2, STDCALL, SystemTimeToFileTime},
    {NULL, NULL, 0, 0, NULL},
};
