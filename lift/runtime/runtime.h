/* Runtime shared by generated lifted code and the Python bridge (emu/native.py), M5.
 *
 * lift_table is generated (table.c, written by lift/build.py): every lifted function, sorted by va.
 * lift_table_len counts the real entries; the array has one extra sentinel entry so it is never empty.
 */
#ifndef LIFT_RUNTIME_H
#define LIFT_RUNTIME_H

#include <stdint.h>
#include "cpu.h"

/* LiftEntry.flags bit 0: the function, or a function it reaches directly, uses x87 or MMX, or makes a call
 * the bridge cannot see through (call_guest, lift_call). The bridge syncs x87 and MMX state only for these. */
#define LIFT_FLAG_FPU 1u

typedef struct {
    uint32_t va;
    void (*fn)(CPU *);
    uint32_t flags;
} LiftEntry;

extern const LiftEntry lift_table[];
extern const unsigned lift_table_len;

/* An x86 #DE inside lifted code. Not supported in the spike: prints and aborts. */
void lift_div_fault(CPU *c, uint32_t va);

/* Writes sizeof(CPU), the offset of every CPU field in cpu_fields order (see emu/native.py), then
 * sizeof(LiftEntry) and the offsets of its fn and flags members. Returns the number of words written. */
uint32_t lift_cpu_layout(uint32_t *out);

/* Register sync with a Unicorn engine (runtime/runtime.c). lift_bridge_init stores the engine handle and the
 * libunicorn batch functions (pointers taken from the libunicorn the Python binding loaded). lift_bridge_regs
 * writes the Unicorn register ids the sync uses, in this order: EAX..EDI, EFLAGS, FPSW, FPCW, FPTAG, FP0..FP7,
 * so the Python side can check them against unicorn.x86_const. */
void lift_bridge_init(void *uc, void *reg_read_batch, void *reg_write_batch);
void lift_bridge_regs(int32_t *out);

/* Copy the Unicorn state into c: GPRs, the six arithmetic flags and DF, and, when fpu is set, the x87 state
 * (top, sw C bits, cw, tag, st[]) and mm[]. Returns how many non-empty x87 registers were not exactly doubles. */
int lift_sync_from_uc(CPU *c, int fpu);

/* Copy c back into Unicorn: GPRs; EFLAGS (the arithmetic flags and DF only, other bits kept); and, when fpu or
 * c->mmx_dirty is set, the x87 state and the dirty MMX registers. An x87 register is written only if its value
 * changed since sync-from, so values that are not doubles and MMX values are not rounded. Clears mmx_dirty. */
void lift_sync_to_uc(CPU *c, int fpu);

/* The double <-> 80-bit conversions the sync uses, exposed so the Python versions can be tested against them. */
void lift_conv_d2x(double d, uint64_t *mantissa, uint16_t *exponent);
double lift_conv_x2d(uint64_t mantissa, uint16_t exponent, int *exact);

/* Bridge entry points (runtime.c): run a lifted function with the guest's rounding control, and the
 * call_guest trampoline that restores round-to-nearest around the Python callback. */
void lift_invoke(CPU *c, void *fn, int fpu);
/* As lift_invoke, but returns 1 when the function faulted with #DE (differential mode), and 2 when lift_diff_abort
 * was called during the run (a divergence): the state is then garbage and the caller rolls it back. Returns 0 when
 * the function returned. */
int lift_invoke_checked(CPU *c, void *fn, int fpu);
/* Differential mode: the Python side can no longer run guest code. The lifted code stops at the next return from a
 * guest callback (runtime.c guest_trampoline), and lift_invoke_checked returns 2. */
void lift_diff_abort(void);
void lift_set_guest_callback(void *cb);
void lift_set_entry_hook(void *cb);            /* host callback for x86c.ENTRY_HOOKS functions: void cb(uint32_t va) */
void lift_entry_hook(CPU *c, uint32_t va);     /* called at entry of a hooked function */
void lift_set_exit_hook(void *cb);             /* host callback for x86c.EXIT_HOOKS functions: void cb(CPU *, uint32_t va) */
void lift_exit_hook(CPU *c, uint32_t va);      /* called at every ret of a hooked function */
void lift_set_insn_hook(void *cb);             /* host callback for x86c.INSN_HOOKS: void cb(CPU *, uint32_t va) */
void lift_insn_hook(CPU *c, uint32_t va);      /* called before a hooked instruction, the x87 stack in st[] */
void lift_set_bridge_stop(uint32_t va);   /* the slow bridge's return address (emu/native.py: STUB_BASE) */
void *lift_guest_trampoline(void);

/* Fast native dispatch (runtime.c): native calls run from a code hook inside emu_start, and calls back into guest code
 * are nested uc_emu_start runs. lift_fast_init registers the hook over (fast_base, fast_base + fast_size); the
 * libunicorn entry points are the binding's (uc_hook_add, uc_emu_start, uc_emu_stop, the batch register calls); mem is
 * the host address of guest 0, fs_base the TEB; fallback is called when a nested run stops anywhere but at fast_base:
 * int fallback(CPU *c, uint32_t addr, uint32_t eip, int err), returns 1 when the guest call finished. lift_fast_set
 * binds slot (1..65535) to the lifted function of va; it returns -1 when va is not lifted. lift_fast_halt_set stops
 * native calls (an error was recorded). lift_fast_stats writes the FS_* counters (runtime.c). */
void lift_fast_init(void *uc, void *hook_add, void *emu_start, void *reg_read_batch, void *reg_write_batch,
                    void *reg_write, void *emu_stop, uint32_t fast_base, uint32_t fast_size, void *fallback,
                    uint8_t *mem, uint32_t fs_base);
int lift_fast_set(uint32_t slot, uint32_t va);
uint32_t lift_fast_ret_current(void);   /* return address of the innermost nested guest call */
void lift_fast_halt_set(int on);
void lift_fast_undo_set(int on);
void lift_fast_stats(uint64_t *out);
void lift_fast_slot_counts(uint64_t *out);     /* out[FAST_SLOTS] (65536 entries): calls per slot number */
/* Guest calls from native code per target: up to cap (addr, count) pairs; returns the number of targets. */
uint32_t lift_fast_guest_counts(uint32_t *addrs, uint64_t *counts, uint32_t cap);

/* Direct HLE calls (runtime.c): cb(CPU *, stub index) for calls from lifted code to the stubs at base + i * stride. */
void lift_hle_direct_init(void *cb, uint32_t base, uint32_t stride);
uint64_t lift_hle_direct_calls(void);
/* The native host (E5, host/mphost.c; runtime.c): the host CPU's call_guest and its HLE dispatcher (see there), and a
 * call into lifted code from the host with return address ret, in the guest's rounding. */
void lift_host_init(void *call_guest, void *hle_cb, uint32_t base, uint32_t stride);
void lift_host_call(CPU *c, uint32_t target, uint32_t ret);

/* Native MSVCRT helpers (crt.c). lift_crt_bind binds the helper called name to the guest address va of its import in
 * a module loaded at base; returns its index, or -1 for a name crt.c does not have. lift_crt_call runs the bound
 * helper of target as a call with return address ret (esp not yet moved) and returns 1, or returns 0 (no helper, or
 * a case it leaves to the guest; nothing changed). lift_crt_counts writes the calls each helper handled, by index,
 * and returns the number of helpers; lift_crt_name gives the name of an index (NULL past the end). */
int lift_crt_bind(const char *name, uint32_t va, uint32_t base);
int lift_crt_regions(const uint32_t *pairs, uint32_t npairs);
/* Whether [a, a + n) lies inside the regions lift_crt_regions gave (crt.c). An empty list maps nothing. */
int lift_mapped(uint32_t a, uint32_t n);
/* Import thunk shortcut (runtime.c call_fill): on (default) or off. Off is for comparing against the guest calls. */
void lift_thunk_shortcut(int on);
int lift_crt_call(CPU *c, uint32_t target, uint32_t ret);
int lift_crt_index(uint32_t target);                 /* the helper bound to target, or -1 */
int lift_crt_call_index(CPU *c, int i, uint32_t ret); /* lift_crt_call for that helper */
/* Call-target cache for lift_call / lift_call_ret / lift_jump (runtime.c, H47): on (default) or off, emptied by
 * lift_call_cache_clear; lift_call_cache_stats writes hits and misses. */
void lift_call_cache(int on);
void lift_call_cache_clear(void);
void lift_call_cache_stats(uint64_t *out);
uint32_t lift_crt_counts(uint64_t *out, uint32_t cap);
const char *lift_crt_name(uint32_t i);

/* The guest heap (heap.c, H44): emu/mpemu.py's allocator in C. Python copies its heap in (lift_heap_reset,
 * lift_heap_set_live, lift_heap_add_free) when the fast path starts and then allocates through lift_heap_alloc /
 * lift_heap_free; lift_heap_direct serves KERNEL32 HeapAlloc/HeapFree (stub indexes from lift_heap_direct_bind) for
 * runtime.c hle_direct. See heap.c for each call. */
void lift_heap_reset(uint64_t next, uint64_t limit);
void lift_heap_set_live(uint32_t p, uint32_t size, uint32_t cap);
void lift_heap_add_free(uint32_t p, uint32_t size);
uint32_t lift_heap_alloc(uint32_t size, int *reused);
int lift_heap_free(uint32_t p);
int lift_heap_get(uint32_t p, uint32_t *size, uint32_t *cap);
uint32_t lift_heap_reserve(uint32_t size, int record);
uint64_t lift_heap_next(void);
void lift_heap_stats(uint64_t *out);
uint32_t lift_heap_export_live(uint32_t *out, uint32_t cap_n);
uint32_t lift_heap_export_free(uint32_t *out, uint32_t cap_n);
void lift_heap_direct_bind(uint32_t idx_alloc, uint32_t idx_free);
int lift_heap_direct(CPU *c, uint32_t idx);

/* HLE handlers in C (hle_fast.c, H50): QueryPerformanceCounter and the hot D3D8 methods, with the D3D8 device state
 * they keep. See hle_fast.c for each call; emu/native.py HleFast is the Python side. */
void lift_hle_fast_reset(void);
void lift_hle_fast_bind(uint32_t idx, uint32_t kind);
int lift_hle_fast_set(int which, uint32_t a, uint32_t b, uint32_t v, uint32_t v2, int set);
int lift_hle_fast_get(int which, uint32_t a, uint32_t b, uint32_t *v, uint32_t *v2);
int lift_hle_fast_blob(int which, uint32_t a, int op, void *p);
int lift_hle_fast_di_new(uint32_t this, uint32_t kind);
void lift_hle_fast_di_cfg(int slot, uint32_t coop, int has_fmt, uint32_t fmt_size, uint32_t bufsize, uint32_t nobj,
                          const uint32_t *obj);
int64_t lift_hle_fast_di_field(int slot, int field, int set, int64_t v);
uint32_t lift_hle_fast_di_queue(int slot, int op, uint32_t i, uint32_t *ev);
uint8_t *lift_hle_fast_di_keys(void);
int lift_hle_fast_ds_new(uint32_t this);
void lift_hle_fast_ds_cfg(int slot, uint32_t ptr, uint32_t size, int has_wfx, uint32_t avg, uint32_t align);
double lift_hle_fast_ds_field(int slot, int field, int set, double v);
void lift_hle_fast_ds_gains(int slot, double gl, double gr, int downmix);
void lift_hle_fast_ds_mixer(void *m, void *write, void *pos, void *gain);
void lift_hle_fast_obj(uint32_t addr, uint32_t kind, uint32_t ptr, uint32_t fmt);
void lift_hle_fast_tex(uint32_t addr, uint32_t ver, uint32_t sent, int has_sent);
int lift_hle_fast_tex_get(uint32_t addr, uint32_t *ver, uint32_t *sent);
void lift_hle_fast_capture(int mode, void *sink, void *r, void *err, int reset_sent);
uint32_t lift_hle_fast_counts(uint32_t *idx, uint64_t *n, uint32_t cap);
uint32_t lift_hle_fast_hist(uint64_t *key, uint64_t *n, uint32_t cap);
uint64_t lift_hle_fast_total(void);
int lift_hle_fast(CPU *c, uint32_t idx);

/* Guest write log for differential mode (-DLIFT_WRITE_LOG builds only; runtime.c). lift_note_write (cpu.h) records the
 * old bytes of every write while the log is on. lift_wlog_export writes the records (uint32 addr, uint32 n, n bytes),
 * returns the size needed, and lift_wlog_clear forgets them. lift_wlog_rollback restores the logged bytes at mem and
 * clears the log. lift_wlog_begin/end switch logging on (and clear) and off (and clear). */
void lift_wlog_begin(void);
void lift_wlog_end(void);
void lift_wlog_clear(void);
uint32_t lift_wlog_pages(void);
size_t lift_wlog_export(uint8_t *buf, size_t cap);
void lift_wlog_rollback(uint8_t *mem);

/* seh.c: RaiseException and RtlUnwind for lifted code (E3). lift_seh_bind gives the HLE stub indexes of
 * KERNEL32 RaiseException and RtlUnwind (UINT32_MAX: none), the ExceptionNestedHandler stub's address, the TEB and the
 * guest stack range; lift_seh_direct serves a direct call to one of them (1: done; 0: not handled, Python runs it).
 * lift_seh_stats: raises, unwinds, raises handled in C, deepest nesting. lift_stack_check stops the process with a
 * message when nested transfers have nearly exhausted the host stack. */
void lift_seh_bind(uint32_t idx_raise, uint32_t idx_unwind, uint32_t nested_va, uint32_t teb, uint32_t stack_lo,
                   uint32_t stack_hi);
int lift_seh_direct(CPU *c, uint32_t idx);
void lift_seh_stats(uint64_t *out);
void lift_stack_guard_init(void);
void lift_stack_check(uint32_t eip);

#endif
