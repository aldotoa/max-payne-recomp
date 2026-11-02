/* The native host (E5, docs/m6-emu-removal.md): what emu/mpemu.py boot and emu/run_init.py --real-entry do, in C and
 * without the emulator. host/mphost.c reserves the guest space, loads and links the PE images, sets up the TEB, PEB,
 * stack and heap, and runs the DLL entry points and the exe's entry point in the lifted library (dlopen); every import
 * that no loaded module exports is an HLE stub, served by a C handler (host/hle_*.c, the ports of emu/mpemu.py's Python
 * handlers) or by the runtime's own (heap.c, seh.c, hle_fast.c). Reaching guest code that is not lifted, or a stub with
 * no C handler, stops the process with the address or the name. */
#ifndef MPHOST_H
#define MPHOST_H

#include <stdint.h>
#include "cpu.h"

/* The guest layout, as emu/mpemu.py has it (the same addresses, so traces compare call for call). */
#define PAGE 0x1000u
#define STACK_TOP 0x00300000u
#define STACK_SIZE 0x00200000u
#define TEB 0x7FFDE000u
#define SCRATCH 0x7FFDB000u
#define PEB 0x7FFDF000u
#define GDT 0x7FFDC000u
#define STUB_BASE 0x7F000000u
#define STUB_SIZE 0x00100000u
#define STUB_STRIDE 16u
#define HEAP_BASE 0x20000000u
#define HEAP_SIZE 0x20000000u

typedef struct {
    char *name;
    uint32_t va;
} Export;

typedef struct Module {
    char name[64];              /* lower case file name: "rlmfc.dll" */
    char path[1024];
    uint32_t base, size, pref, entry;
    uint8_t *file;              /* the PE file */
    uint32_t file_size;
    Export *exports;            /* sorted by name */
    uint32_t nexports;
    uint32_t ord_base, nords, *ords;   /* ordinal -> va (0: none) */
} Module;

/* A handler gets the CPU (return address at [esp]) and the arguments; it returns EAX. The dispatcher pops the return
 * address and, for stdcall, the arguments. */
typedef uint32_t (*HleFn)(CPU *c, const uint32_t *a);

typedef struct {
    const char *dll, *name;
    uint8_t nargs, flags;
    HleFn fn;
} HleDef;

/* HleDef.flags */
#define STDCALL 0
#define CDECL 1                 /* the caller pops the arguments */
#define HLE_CORO 2              /* the handler calls guest code (a coroutine in Python): logged before it runs */

/* ---- host services (mphost.c) */
extern CPU g_cpu;
extern Module *g_mods[];
extern int g_nmods;
extern const char *g_game_dir;

Module *host_find_module(const char *name);          /* by file name, any case; NULL */
Module *host_module_by_base(uint32_t base);
uint32_t host_export(Module *m, const char *name);   /* 0 when absent */
uint32_t host_export_ord(Module *m, uint32_t ord);
uint32_t host_stub_for(const char *dll, const char *name);
const char *host_module_at(uint32_t va);             /* "module+0xoff" or "0xva" (a static buffer, one at a time) */
/* LoadLibraryA of a DLL in the game folder: map, link, run its entry point. Returns its base, 0 if absent. */
uint32_t host_load_library(CPU *c, const char *name);
/* Call the lifted function at va with args (pushed right to left) and return EAX; the registers but EAX are kept. */
uint32_t host_guest_call(CPU *c, uint32_t va, int nargs, const uint32_t *args);
void host_fatal(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
void host_exit(uint32_t code) __attribute__((noreturn));
void host_note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));   /* a line in the API log */

/* guest memory */
static inline uint8_t *gptr(uint32_t a) { return g_cpu.mem + a; }
uint32_t host_alloc(uint32_t size);                  /* Emu.alloc: 16-byte aligned, zeroed */
int host_free(uint32_t p);
uint32_t host_put_cstr(const char *s, uint32_t extra);
size_t host_cstr(uint32_t a, char *out, size_t cap);   /* Emu.cstr (limit 4096); returns the length */
size_t host_wstr(uint32_t a, uint16_t *out, size_t cap);
uint32_t host_last_error(void);
void host_set_last_error(uint32_t v);
void host_tls_set(uint32_t i, uint32_t v, int set);  /* hle_fast.c's TLS slot (set 0: freed) */
/* handles (Emu.new_handle, Emu.handles): kind and object; host_handle gives the object of a handle of that kind (else
 * NULL), host_handle_pop forgets the handle and gives its object and kind (HK_NONE: no such handle) */
enum { HK_NONE, HK_MUTEX, HK_EVENT, HK_FILE, HK_FIND, HK_MAPPING, HK_RESOURCE, HK_THREAD, HK_SEMAPHORE, HK_DIB };
uint32_t host_new_handle(int kind, void *obj);
void *host_handle(uint32_t h, int kind);
int host_handle_kind(uint32_t h);
void *host_handle_pop(uint32_t h, int *kind);
/* the heap.c blocks: (size, cap) of a live block (cap 0: VirtualAlloc), resize in place, page-aligned reservations,
 * the number of live blocks */
int host_heap_get(uint32_t p, uint32_t *size, uint32_t *cap);
void host_heap_resize(uint32_t p, uint32_t size);
uint32_t host_heap_reserve(uint32_t size, int record);
uint32_t host_heap_live(void);
uint32_t host_get_proc_address(uint32_t h, uint32_t name);

/* paths (emu/mpemu.py data_dir, host_read_path, host_write_path): guest path -> host path */
extern char g_cwd[1024];                             /* the guest's current directory, "C:\MaxPayne" */
extern char g_cmdline[256];
const char *host_data_dir(void);
void host_mkdirs(const char *path);              /* mkdir -p */
void host_guest_abs(const char *guest, char *out, size_t cap);   /* _guest_abs: drive-absolute, backslashes */
void host_read_path(const char *guest, char *out, size_t cap);
void host_write_path(const char *guest, char *out, size_t cap);
void host_dir_paths(const char *guest_dir, char *game, char *ov, size_t cap);
/* resources (hle_kernel32.c): FindResourceA's handle, and its module, RVA and size (pop: forget the handle) */
uint32_t host_find_resource(uint32_t hmod, uint32_t name, uint32_t typ);
int host_resource(uint32_t h, int pop, Module **m, uint32_t *rva, uint32_t *size);

/* --anchor (mphost.c): CreateFileA's guest path, for the frame in which the game first opens the anchor file */
void host_note_open(const char *guest);

/* the desktop the game sees (emu/mpemu.py SCREEN): the M7 target, 2560x1600 */
#define HOST_SCREEN_W 2560
#define HOST_SCREEN_H 1600

/* GetTickCount's clock (hle_kernel32.c), for the MSG time */
uint32_t host_tick(void);
/* the guest clock (hle_kernel32.c): the host's, or with --sim-fps N a virtual one that advances 1/N s per main-loop
 * frame (host_clock_frame, at the frame function's entry) */
void host_clock_sim(unsigned fps);
unsigned host_clock_sim_fps(void);
void host_clock_frame(void);
uint64_t host_clock_ns(void);
/* the window manager (hle_winsys.c), host side: WM_QUIT in the thread queue (the game's pump ends the run), and the
 * real window's focus, delivered as WM_ACTIVATEAPP etc. on the game's next PeekMessage/GetMessage */
void host_post_quit(uint32_t code);
void host_set_app_active(int active);

/* DINPUT (hle_dinput.c): host key presses, the key messages winsys posts, the US-layout character */
typedef struct { uint32_t vk, scan, ext, down, alt; } HostKeyMsg;
void host_key(uint32_t dik, int down);
int host_key_msg(HostKeyMsg *m);                     /* the oldest unread key message; 0 when none */
int host_input_made(void);
int host_char_for(uint32_t dik);                     /* -1: no character */
void host_focus_lost(void);                          /* FOREGROUND devices unacquired, keys released */
void host_mouse_move(int32_t dx, int32_t dy);
void host_mouse_wheel(int32_t dz);
void host_mouse_button(uint32_t n, int down);        /* 0 left, 1 right, 2 middle, 3 X1, 4 X2 */
int host_di_mouse_exclusive(void);
/* hle_fast.c's DINPUT side: a device's slot (kind 0 keyboard, 1 mouse; -1: no room), its configuration (cooperative
 * level, data format as (kind, instance, offset) triples, buffer size), a run-state field (slot >= 0: 0 acquired,
 * 1 lost, 2 overflow, 3-5 dx, dy, dz; slot -1: 0 the sequence number), the event queue (op 0 length, 1 append ev,
 * 2 pop, 3 clear, 4 event i to ev), and the 256 keys followed by the 8 buttons */
int host_di_new(uint32_t this, uint32_t kind);
void host_di_cfg(int slot, uint32_t coop, int has_fmt, uint32_t fmt_size, uint32_t bufsize, uint32_t nobj,
                 const uint32_t *obj);
int64_t host_di_field(int slot, int field, int set, int64_t v);
uint32_t host_di_queue(int slot, int op, uint32_t i, uint32_t *ev);
uint8_t *host_di_keys(void);
/* DirectShow (hle_dshow.c): the intro mode (1: a headless run presses Space when a movie starts), and Sleep while
 * a movie runs */
extern int g_intro_skip;
void host_movie_sleep(uint32_t ms);

/* handler tables (NULL-terminated) */
extern const HleDef hle_kernel32[], hle_files[], hle_user32[], hle_winsys[], hle_advapi32[];
extern HleDef hle_d3d8[], hle_dshow[], hle_dsound[], hle_dinput[];   /* built at start-up from the vtable layouts */
/* hle_fast.c's DSOUND side: a buffer's slot, its layout (pointer, size, the format's avg and align), a run-state field
 * (0 volume, 1 playing, 2 looping, 3 pos, 4 started, 5 unlocks, 6 written, 7 voice; set: write v first) */
int host_ds_new(uint32_t this);
void host_ds_cfg(int slot, uint32_t ptr, uint32_t size, int has_wfx, uint32_t avg, uint32_t align);
double host_ds_field(int slot, int field, int set, double v);
void host_ds_gains(int slot, double gl, double gr, int downmix);   /* the voice's gains before the volume */
void host_ds_mixer(void *m, void *write, void *pos, void *gain);   /* the mixer hle_fast.c calls (NULL: none) */
/* the mixer (hle_dsound.c): the device (1 the default playback device, 0 null: real time, silent, -2 off) and a WAV
 * file for the mixed output; the mixer, made on first use (NULL with --audio off); closed at exit */
void host_audio_set(int device, const char *wav);
void *host_mixer(void);
void host_audio_close(void);
/* the DirectSound COM classes (hle_dsound.c) for CoCreateInstance: the HRESULT, or -1 for another class */
int64_t host_dsound_com(const uint8_t *clsid, uint32_t outer, uint32_t ppv);
/* hle_fast.c's D3D8 side (the runtime): an object's kind (native.HleFast.OBJ_KINDS), buffer and format; a texture's
 * lock version; a transform (which 0, a = state) or the viewport (which 1): op 0 read (0: not set), 1 write */
void host_fast_obj(uint32_t addr, uint32_t kind, uint32_t ptr, uint32_t fmt);
void host_fast_tex_sent(uint32_t addr, uint32_t ver, uint32_t sent, int has_sent);
int host_fast_blob(int which, uint32_t a, int op, void *p);
/* hle_fast.c's device state (which: 0 render state, 1 texture-stage state, 2 bound texture, 3 stream, 4 indices,
 * 5 vertex shader): get (0: not set) and set (0: out of C's range), and its capture mode */
int host_fast_get(int which, uint32_t a, uint32_t b, uint32_t *v, uint32_t *v2);
int host_fast_set(int which, uint32_t a, uint32_t b, uint32_t v);
void host_fast_capture(int mode, void *sink, void *r, void *err, int reset_sent);
/* the D3D8 capture (hle_d3d8.c): MPD3 records (emu/d3dcap.py) to sink(ctx, type, payload, length) from now on,
 * starting with the current state; the back buffer's size (0 before CreateDevice) */
typedef int (*HostSink)(void *ctx, uint32_t type, const void *payload, uint32_t length);
void host_d3d_start_capture(HostSink sink, void *ctx);
const uint32_t *host_d3d_stop_capture(void);     /* the record counts by type */
void host_d3d_backbuffer(uint32_t *w, uint32_t *h);
int host_d3d_mode(unsigned i, uint32_t *w, uint32_t *h);   /* the adapter's mode i (d3d8.display_modes); 0 past the end */
/* the registry (hle_advapi32.c): <data>/registry.json loaded, the launcher's settings applied, saved; a DWORD value;
 * launcher.py --resolution (a display mode written to Video Settings and saved, as a dialog OK would) */
void host_registry_init(void);
void host_registry_set_resolution(uint32_t w, uint32_t h);
uint32_t host_reg_dword(const char *path, const char *name, uint32_t dflt);
#define APP_VIDEO_SETTINGS "HKCU\\Software\\Remedy Entertainment\\Max Payne\\Video Settings"
/* the live view (live.c): an SDL3 window with the Metal renderer; launcher.json's host settings */
void host_live_open(void);
int host_live_on(void);
void *host_live_layer(void);                         /* the window's CAMetalLayer */
const uint8_t *host_live_read_frame(uint32_t *w, uint32_t *h);  /* the last presented frame, RGBA8; NULL: none */
void host_live_start(void);                          /* the main loop starts: the renderer, the capture into it */
int host_live_pump_frame(void);                      /* a frame starts: input to the game; 1: the window was closed */
void host_live_pump(void);                           /* the window's events (input to the game) */
void host_live_close(void);
void host_settings_load(void);
void host_settings_save(void);
const char *host_settings_game_mode(void);
void host_settings_set_game_mode(const char *mode);

#endif
