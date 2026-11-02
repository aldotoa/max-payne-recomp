/* Runtime for lifted code (M5): dispatch for run-time calls, abort paths, layout export. */
#include <fenv.h>
#include <math.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"

static void (*lift_find(uint32_t target))(CPU *)
{
    unsigned lo = 0, hi = lift_table_len;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        uint32_t va = lift_table[mid].va;
        if (va == target)
            return lift_table[mid].fn;
        if (va < target)
            lo = mid + 1;
        else
            hi = mid;
    }
    return 0;
}

/* Import thunks (lift/build.py split_thunks): a 6-byte `jmp dword ptr [slot]` (ff 25 imm32) is never lifted, so a call
 * through a register or a vtable that reaches one misses lift_find and would be a guest call. The thunk only changes
 * EIP, so calling it with return address R is calling the slot's target with R: lift_call and friends resolve the chain
 * here, after a miss, and dispatch to the final target (lifted, CRT helper or guest). The slot is read at call time (the
 * IAT can change). Guest bytes are read only inside the regions the emulator maps (lift_mapped); anything else is left
 * as it was, so the call goes to the guest as before. At most THUNK_HOPS slots are followed. */
#define THUNK_HOPS 4
static int g_thunk_on = 1;

void lift_thunk_shortcut(int on)
{
    g_thunk_on = on != 0;
    lift_call_cache_clear();
}

static int hle_direct(CPU *c, uint32_t target, int push, uint32_t ret);

/* Call-target cache (H47). Resolving a run-time call target (lift_find's binary search over the table, then
 * the thunk chain and a second search on a miss, then the CRT helpers) cost 9% of a gameplay frame: imports such as
 * _ftol are called through their IAT slots thousands of times per frame. An entry keeps what one target resolved to:
 * the final target, its lifted function or CRT helper (crt < 0: none), and the thunk slots followed with the values
 * read from them. A hit re-reads those slots and resolves again when one changed (the IAT is read at call time, as
 * the thunk shortcut always has); thunk bytes are code and do not change. lift_call_cache_clear (called by lift_crt_bind,
 * lift_crt_regions and lift_thunk_shortcut) empties it; lift_call_cache(0) resolves every call afresh (comparisons). */
#define CALL_CACHE 4096u
typedef struct {
    uint32_t key, final;
    void (*fn)(CPU *);
    int16_t crt;
    uint8_t hops, valid;
    uint32_t slot[THUNK_HOPS], val[THUNK_HOPS];
} CallEnt;
static CallEnt g_call_cache[CALL_CACHE];
static CallEnt g_call_scratch;
static int g_call_cache_on = 1;
static uint64_t g_call_hits, g_call_misses;

void lift_call_cache_clear(void)
{
    memset(g_call_cache, 0, sizeof g_call_cache);
}

void lift_call_cache(int on)
{
    g_call_cache_on = on != 0;
    lift_call_cache_clear();
}

void lift_call_cache_stats(uint64_t *out)
{
    out[0] = g_call_hits;
    out[1] = g_call_misses;
}

/* Resolve target into e: lift_find, then on a miss the thunk chain (each slot followed and the value read from it), then
 * the CRT helper of the final target. A helper bound to a lifted function (type_info::name since H63) comes first in
 * lift_call_ret, and the lifted function runs when it declines. */
static void call_fill(CPU *c, CallEnt *e, uint32_t target)
{
    e->key = target;
    e->hops = 0;
    e->fn = lift_find(target);
    uint32_t t = target;
    if (!e->fn) {
        for (unsigned hop = 0; hop < THUNK_HOPS && g_thunk_on; hop++) {
            if (!lift_mapped(t, 6) || rd8(c, t) != 0xff || rd8(c, t + 1) != 0x25)
                break;
            uint32_t slot = rd32(c, t + 2);
            if (!lift_mapped(slot, 4))
                break;
            t = rd32(c, slot);
            e->slot[e->hops] = slot;
            e->val[e->hops] = t;
            e->hops++;
        }
        if (t != target)
            e->fn = lift_find(t);
    }
    e->final = t;
    e->crt = (int16_t)lift_crt_index(t);
    e->valid = 1;
}

static const CallEnt *call_resolve(CPU *c, uint32_t target)
{
    if (!g_call_cache_on) {
        call_fill(c, &g_call_scratch, target);
        return &g_call_scratch;
    }
    CallEnt *e = &g_call_cache[(target * 0x9E3779B1u) >> 20];
    if (e->valid && e->key == target) {
        unsigned h = 0;
        while (h < e->hops && rd32(c, e->slot[h]) == e->val[h])
            h++;
        if (h == e->hops) {
            g_call_hits++;
            return e;
        }
    }
    g_call_misses++;
    call_fill(c, e, target);
    return e;
}

void lift_call(CPU *c, uint32_t target)
{
    const CallEnt *e = call_resolve(c, target);
    if (e->fn) {
        push32(c, 0);                          /* dummy return address: the callee's ret pops it */
        e->fn(c);
        return;
    }
    c->call_guest(c, e->final);
}

void lift_call_ret(CPU *c, uint32_t target, uint32_t ret)
{
    const CallEnt *e = call_resolve(c, target);
    if (e->crt >= 0 && lift_crt_call_index(c, e->crt, ret))
        return;
    if (e->fn) {
        push32(c, ret);
        e->fn(c);
        return;
    }
    target = e->final;
    if (hle_direct(c, target, 1, ret))
        return;
    lift_guest(c, target, ret);
}

void lift_jump(CPU *c, uint32_t target)
{
    lift_stack_check(target);                   /* transfers nest on the host stack (seh.c) */
    const CallEnt *e = call_resolve(c, target);
    if (e->fn) {
        e->fn(c);
        return;
    }
    target = e->final;
    int crt = e->crt;
    if (hle_direct(c, target, 0, 0))            /* the caller's return address is at [esp], as for a call */
        return;
    /* the bridge's return address replaces our caller's in its slot; a real jmp leaves the caller's there */
    uint32_t sp = c->r[ESP], caller = rd32(c, sp);
    c->r[ESP] += 4;
    if (crt >= 0 && lift_crt_call_index(c, crt, caller))
        return;
    c->call_guest(c, target);
    if (lift_is_bridge_ret(rd32(c, sp)))         /* the callee did not write the slot (see lift_guest) */
        wr32(c, sp, caller);
}

void lift_unsupported(CPU *c, uint32_t va, const char *what)
{
    (void)c;
    fprintf(stderr, "lifted code reached unsupported instruction at %08x: %s\n", va, what);
    abort();
}

/* Armed by lift_invoke_checked (differential mode): a #DE with no Python callback active is reported to the
 * caller as a fault instead of aborting. g_cg_depth counts the Python callbacks (guest_trampoline) in progress;
 * a longjmp across them would skip their frames, so with any active the process still aborts. */
static jmp_buf *g_fault_jb;
static int g_cg_depth;
/* Set by lift_diff_abort (the Python side has no way to run the guest any more): the next guest_trampoline return
 * with no Python callback active longjmps to g_fault_jb with 2, so the native code stops instead of running on. */
static int g_diff_abort;

void lift_div_fault(CPU *c, uint32_t va)
{
    (void)c;
    if (g_fault_jb && g_cg_depth == 0)
        longjmp(*g_fault_jb, 1);
    fprintf(stderr, "lifted code raised #DE at %08x (not supported)\n", va);
    abort();
}

uint32_t lift_cpu_layout(uint32_t *out)
{
    uint32_t n = 0;
    out[n++] = (uint32_t)sizeof(CPU);
    out[n++] = (uint32_t)offsetof(CPU, r);
    out[n++] = (uint32_t)offsetof(CPU, eip);
    out[n++] = (uint32_t)offsetof(CPU, cf);
    out[n++] = (uint32_t)offsetof(CPU, pf);
    out[n++] = (uint32_t)offsetof(CPU, af);
    out[n++] = (uint32_t)offsetof(CPU, zf);
    out[n++] = (uint32_t)offsetof(CPU, sf);
    out[n++] = (uint32_t)offsetof(CPU, of);
    out[n++] = (uint32_t)offsetof(CPU, df);
    out[n++] = (uint32_t)offsetof(CPU, _pad);
    out[n++] = (uint32_t)offsetof(CPU, st);
    out[n++] = (uint32_t)offsetof(CPU, top);
    out[n++] = (uint32_t)offsetof(CPU, tag);
    out[n++] = (uint32_t)offsetof(CPU, cw);
    out[n++] = (uint32_t)offsetof(CPU, sw);
    out[n++] = (uint32_t)offsetof(CPU, fs_base);
    out[n++] = (uint32_t)offsetof(CPU, mem);
    out[n++] = (uint32_t)offsetof(CPU, call_guest);
    out[n++] = (uint32_t)offsetof(CPU, user);
    out[n++] = (uint32_t)offsetof(CPU, mm);
    out[n++] = (uint32_t)offsetof(CPU, mmx_dirty);
    out[n++] = (uint32_t)sizeof(LiftEntry);
    out[n++] = (uint32_t)offsetof(LiftEntry, fn);
    out[n++] = (uint32_t)offsetof(LiftEntry, flags);
    return n;
}

/* ---------------------------------------------------------------- Unicorn register sync (M5)
 *
 * The ids below are Unicorn's UC_X86_REG_* values (unicorn/x86.h of the libunicorn the binding loads).
 * lift_bridge_regs exports them so emu/native.py can check them against unicorn.x86_const at load time.
 */
enum {
    ID_EAX = 19, ID_ECX = 22, ID_EDX = 24, ID_EBX = 21, ID_ESP = 30, ID_EBP = 20, ID_ESI = 29, ID_EDI = 23,
    ID_EFLAGS = 25, ID_EIP = 26, ID_FPSW = 31, ID_FPCW = 246, ID_FPTAG = 247, ID_FP0 = 82,
};

static const int32_t gpr_ids[8] = {ID_EAX, ID_ECX, ID_EDX, ID_EBX, ID_ESP, ID_EBP, ID_ESI, ID_EDI};
#define SW_C_MASK   0x4700u
#define SW_TOP_MASK 0x3800u
#define SW_EXC_MASK 0x003fu        /* sticky exception flags IE..PE (carried with the state) */
#define FLAG_MASK   ((1u << 0) | (1u << 2) | (1u << 4) | (1u << 6) | (1u << 7) | (1u << 10) | (1u << 11))

/* Unicorn's uc_x86_float80: the 80-bit x87 register as (mantissa, sign|exponent), 16 bytes. */
typedef struct {
    uint64_t mantissa;
    uint16_t exponent;
} uc_fp80;

typedef int (*uc_reg_read_batch_fn)(void *uc, const int32_t *regs, void **vals, int32_t count);
typedef int (*uc_reg_write_batch_fn)(void *uc, const int32_t *regs, void *const *vals, int32_t count);

static void *g_uc;
static uc_reg_read_batch_fn g_read_batch;
static uc_reg_write_batch_fn g_write_batch;

void lift_bridge_init(void *uc, void *reg_read_batch, void *reg_write_batch)
{
    g_uc = uc;
    g_read_batch = (uc_reg_read_batch_fn)reg_read_batch;
    g_write_batch = (uc_reg_write_batch_fn)reg_write_batch;
}

void lift_bridge_regs(int32_t *out)
{
    int k = 0;
    for (int i = 0; i < 8; i++)
        out[k++] = gpr_ids[i];
    out[k++] = ID_EFLAGS;
    out[k++] = ID_FPSW;
    out[k++] = ID_FPCW;
    out[k++] = ID_FPTAG;
    for (int p = 0; p < 8; p++)
        out[k++] = ID_FP0 + p;
}

static void uc_read_many(const int32_t *ids, void **vals, int32_t n)
{
    if (!g_read_batch || g_read_batch(g_uc, ids, vals, n) != 0) {
        fprintf(stderr, "lift: uc_reg_read_batch failed (bridge not initialised?)\n");
        abort();
    }
}

static void uc_write_many(const int32_t *ids, void *const *vals, int32_t n)
{
    if (!g_write_batch || g_write_batch(g_uc, ids, vals, n) != 0) {
        fprintf(stderr, "lift: uc_reg_write_batch failed (bridge not initialised?)\n");
        abort();
    }
}

/* ---- double <-> 80-bit, bit-identical to emu/native.py d2x / x2d (tested against them) */

void lift_conv_d2x(double d, uint64_t *mantissa, uint16_t *exponent)
{
    uint64_t bits;
    memcpy(&bits, &d, 8);
    uint16_t sign = (uint16_t)((bits >> 63) << 15);
    uint32_t e11 = (uint32_t)((bits >> 52) & 0x7ffu);
    uint64_t frac = bits & ((1ull << 52) - 1);
    if (e11 == 0x7ffu) {                                        /* inf, NaN (payload kept) */
        *mantissa = frac ? ((1ull << 63) | (frac << 11)) : (1ull << 63);
        *exponent = (uint16_t)(sign | 0x7fff);
        return;
    }
    if (e11 == 0) {
        if (!frac) {                                            /* +-0 */
            *mantissa = 0;
            *exponent = sign;
            return;
        }
        int ex = 0;                                             /* denormal: normalise */
        double m = frexp(fabs(d), &ex);
        *mantissa = ((uint64_t)(m * 9007199254740992.0)) << 11;
        *exponent = (uint16_t)(sign | (uint32_t)(ex - 1 + 16383));
        return;
    }
    *mantissa = ((1ull << 52) | frac) << 11;
    *exponent = (uint16_t)(sign | (e11 + 15360));
}

/* |m * 2^E| rounded to the nearest double, ties to even, subnormals included (what Python's float(Fraction) does). */
static double mant_to_double(uint64_t m, int E)
{
    int p = 64 - __builtin_clzll(m);                  /* bit length of m, 1..64 */
    int t = p - 1 + E;                                /* the value lies in [2^t, 2^(t+1)) */
    int keep = t >= -1022 ? 53 : t + 1075;            /* significant bits a double has at this magnitude */
    if (keep < 0)
        return 0.0;                                   /* below half the smallest subnormal */
    int shift = p - keep;
    if (shift <= 0)                                   /* exact: m has at most 53 bits */
        return ldexp((double)m, E);
    uint64_t q = shift == 64 ? 0 : m >> shift;
    uint64_t rem = shift == 64 ? m : (m & ((1ull << shift) - 1));
    uint64_t half = 1ull << (shift - 1);
    if (rem > half || (rem == half && (q & 1)))
        q++;
    return ldexp((double)q, E + shift);               /* q <= 2^53: exact in every case */
}

double lift_conv_x2d(uint64_t mant, uint16_t exp, int *exact)
{
    double sign = (exp & 0x8000) ? -1.0 : 1.0;
    unsigned e = exp & 0x7fff;
    if (e == 0x7fff) {
        *exact = 1;
        if (mant & ((1ull << 63) - 1)) {
            uint64_t frac = (mant >> 11) & ((1ull << 52) - 1);
            if (!frac)
                frac = 1ull << 51;
            uint64_t bits = ((uint64_t)(exp >> 15) << 63) | (0x7ffull << 52) | frac;
            double d;
            memcpy(&d, &bits, 8);
            return d;
        }
        return sign * INFINITY;
    }
    if (mant == 0) {
        *exact = 1;
        return sign * 0.0;
    }
    unsigned e_eff = e ? e : 1;
    if ((mant & 0x7ffu) == 0) {                       /* fits in 53 bits: exact through ldexp */
        double d = ldexp((double)(mant >> 11), (int)e_eff - 16383 - 52);
        int fe = 0;
        if (!isinf(d) && d != 0.0)
            frexp(d, &fe);
        if (!isinf(d) && d != 0.0 && fe >= -1021) {
            *exact = 1;
            return sign * d;
        }
    }
    double d = sign * mant_to_double(mant, (int)e_eff - 16383 - 63);
    uint64_t dm;
    uint16_t de;
    lift_conv_d2x(d, &dm, &de);
    *exact = (dm == mant && de == exp);
    return d;
}

/* ---- the sync */

int lift_sync_from_uc(CPU *c, int fpu)
{
    int32_t ids[20];
    void *vals[20];
    uint64_t sc[12];
    uc_fp80 fp[8];
    memset(sc, 0, sizeof sc);
    int n = 0;
    for (int i = 0; i < 8; i++) {
        ids[n] = gpr_ids[i];
        vals[n++] = &sc[i];
    }
    ids[n] = ID_EFLAGS;
    vals[n++] = &sc[8];
    if (fpu) {
        ids[n] = ID_FPSW;
        vals[n++] = &sc[9];
        ids[n] = ID_FPCW;
        vals[n++] = &sc[10];
        ids[n] = ID_FPTAG;
        vals[n++] = &sc[11];
        for (int p = 0; p < 8; p++) {
            ids[n] = ID_FP0 + p;
            vals[n++] = &fp[p];
        }
    }
    uc_read_many(ids, vals, n);

    for (int i = 0; i < 8; i++)
        c->r[i] = (uint32_t)sc[i];
    uint32_t ef = (uint32_t)sc[8];
    c->cf = (ef >> 0) & 1;
    c->pf = (ef >> 2) & 1;
    c->af = (ef >> 4) & 1;
    c->zf = (ef >> 6) & 1;
    c->sf = (ef >> 7) & 1;
    c->df = (ef >> 10) & 1;
    c->of = (ef >> 11) & 1;
    if (!fpu)
        return 0;

    uint32_t sw = (uint32_t)sc[9] & 0xffffu;
    c->top = (sw >> 11) & 7;
    c->sw = (uint16_t)(sw & (SW_C_MASK | SW_EXC_MASK));
    c->cw = (uint16_t)sc[10];
    uint32_t tagw = (uint32_t)sc[11] & 0xffffu, tag = 0;
    for (int p = 0; p < 8; p++)
        if (((tagw >> (2 * p)) & 3) == 3)
            tag |= 1u << p;
    c->tag = tag;
    int inexact = 0;
    for (int p = 0; p < 8; p++) {
        c->mm[p] = fp[p].mantissa;
        if (tag & (1u << p)) {
            c->st[p] = 0.0;
            continue;
        }
        int exact = 1;
        c->st[p] = lift_conv_x2d(fp[p].mantissa, fp[p].exponent, &exact);
        if (!exact)
            inexact++;
    }
    return inexact;
}

void lift_sync_to_uc(CPU *c, int fpu)
{
    fpu = fpu || c->mmx_dirty != 0;

    /* read what the write-back depends on: EFLAGS (other bits kept), and for x87 the FPSW/FPTAG to merge into and
     * the raw FP values, to see which st[] entries changed since sync-from */
    int32_t rids[11];
    void *rvals[11];
    uint64_t rs[3];
    uc_fp80 raw[8];
    memset(rs, 0, sizeof rs);
    memset(raw, 0, sizeof raw);
    int n = 0;
    rids[n] = ID_EFLAGS;
    rvals[n++] = &rs[0];
    if (fpu) {
        rids[n] = ID_FPSW;
        rvals[n++] = &rs[1];
        rids[n] = ID_FPTAG;
        rvals[n++] = &rs[2];
        for (int p = 0; p < 8; p++) {
            rids[n] = ID_FP0 + p;
            rvals[n++] = &raw[p];
        }
    }
    uc_read_many(rids, rvals, n);

    uint32_t bits = (c->cf ? 1u << 0 : 0) | (c->pf ? 1u << 2 : 0) | (c->af ? 1u << 4 : 0) |
                    (c->zf ? 1u << 6 : 0) | (c->sf ? 1u << 7 : 0) | (c->df ? 1u << 10 : 0) |
                    (c->of ? 1u << 11 : 0);
    uint32_t ef = (((uint32_t)rs[0]) & ~FLAG_MASK) | bits;

    int32_t wids[8 + 1 + 8 + 3];
    void *wvals[8 + 1 + 8 + 3];
    uint64_t ws[8 + 1 + 3];
    uc_fp80 wfp[8];
    int m = 0;
    for (int i = 0; i < 8; i++) {
        ws[i] = c->r[i];
        wids[m] = gpr_ids[i];
        wvals[m++] = &ws[i];
    }
    ws[8] = ef;
    wids[m] = ID_EFLAGS;
    wvals[m++] = &ws[8];

    if (fpu) {
        for (int p = 0; p < 8; p++) {
            uint32_t bit = 1u << p;
            if (c->mmx_dirty & bit) {                     /* MMX wins: the register holds mm[p] */
                wfp[p].mantissa = c->mm[p];
                wfp[p].exponent = 0xffff;
            } else if (c->tag & bit) {
                continue;                                 /* empty: the raw value is not observable, keep it */
            } else {
                int exact = 1;
                double cur = lift_conv_x2d(raw[p].mantissa, raw[p].exponent, &exact);
                if (memcmp(&cur, &c->st[p], 8) == 0)
                    continue;                             /* unchanged: writing it back could round it */
                lift_conv_d2x(c->st[p], &wfp[p].mantissa, &wfp[p].exponent);
            }
            wids[m] = ID_FP0 + p;
            wvals[m++] = &wfp[p];
        }
        uint32_t sw = ((uint32_t)rs[1] & 0xffffu & ~(SW_TOP_MASK | SW_C_MASK | SW_EXC_MASK)) |
                      ((uint32_t)(c->top & 7) << 11) | (c->sw & (SW_C_MASK | SW_EXC_MASK));
        uint32_t tagw = (uint32_t)rs[2] & 0xffffu;
        for (int p = 0; p < 8; p++) {
            int sh = 2 * p;
            if (c->tag & (1u << p))
                tagw |= 3u << sh;
            else if (((tagw >> sh) & 3) == 3)
                tagw &= ~(3u << sh);
        }
        ws[9] = c->cw;
        wids[m] = ID_FPCW;
        wvals[m++] = &ws[9];
        ws[10] = sw;
        wids[m] = ID_FPSW;
        wvals[m++] = &ws[10];
        ws[11] = tagw & 0xffffu;
        wids[m] = ID_FPTAG;
        wvals[m++] = &ws[11];
    }
    uc_write_many(wids, wvals, m);
    c->mmx_dirty = 0;
}

/* ---- host rounding while native code runs
 * Lifted x87 arithmetic rounds with the host FPU, so the host gets the guest's rounding control
 * (cw bits 10-11) for exactly as long as lifted code runs: set on entry, round-to-nearest again
 * whenever control goes back to Python or the emulator (return, or a call_guest). */

static void (*guest_cb)(CPU *c, uint32_t addr);

static void set_guest_rounding(const CPU *c)
{
    static const int mode[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    fesetround(mode[(c->cw >> 10) & 3]);
}

static void guest_trampoline(CPU *c, uint32_t addr)
{
    fesetround(FE_TONEAREST);
    g_cg_depth++;
    guest_cb(c, addr);
    g_cg_depth--;
    if (g_diff_abort && g_fault_jb && g_cg_depth == 0)
        longjmp(*g_fault_jb, 2);
    set_guest_rounding(c);
}

void lift_diff_abort(void) { g_diff_abort = 1; }

void lift_set_guest_callback(void *cb) { guest_cb = (void (*)(CPU *, uint32_t))cb; }

/* Entry hooks (x86c.ENTRY_HOOKS): a hooked lifted function calls this at entry. The host callback (emu/native.py
 * set_entry_hook) runs in round-to-nearest, as guest calls do; without one this is a no-op. */
static void (*entry_cb)(uint32_t);

void lift_set_entry_hook(void *cb) { entry_cb = (void (*)(uint32_t))cb; }

void lift_entry_hook(CPU *c, uint32_t va)
{
    if (!entry_cb)
        return;
    fesetround(FE_TONEAREST);
    entry_cb(va);
    set_guest_rounding(c);
}

/* Exit hooks (x86c.EXIT_HOOKS): a hooked lifted function calls this at every ret, before ESP moves past the return
 * address. The host callback (mphost's Hor+) gets the CPU and runs in round-to-nearest; without one this is a no-op. */
static void (*exit_cb)(CPU *, uint32_t);

void lift_set_exit_hook(void *cb) { exit_cb = (void (*)(CPU *, uint32_t))cb; }

void lift_exit_hook(CPU *c, uint32_t va)
{
    if (!exit_cb)
        return;
    fesetround(FE_TONEAREST);
    exit_cb(c, va);
    set_guest_rounding(c);
}

/* Instruction hooks (x86c.INSN_HOOKS): the lifted code calls this before a hooked instruction, with the x87 stack in
 * st[]/top/tag. The host callback (mphost's Hor+ for the portal code) gets the CPU and runs in round-to-nearest;
 * without one this is a no-op. */
static void (*insn_cb)(CPU *, uint32_t);

void lift_set_insn_hook(void *cb) { insn_cb = (void (*)(CPU *, uint32_t))cb; }

void lift_insn_hook(CPU *c, uint32_t va)
{
    if (!insn_cb)
        return;
    fesetround(FE_TONEAREST);
    insn_cb(c, va);
    set_guest_rounding(c);
}

void *lift_guest_trampoline(void) { return (void *)guest_trampoline; }

void lift_invoke(CPU *c, void *fn, int fpu)
{
    if (fpu)
        set_guest_rounding(c);
    ((void (*)(CPU *))fn)(c);
    fesetround(FE_TONEAREST);
}

/* Runs fn(c) as a fault-checked call (differential mode). Returns 0 when fn returned, 1 for a #DE (no callback active),
 * and 2 when the run was aborted by lift_diff_abort (a divergence in the guest replay, see _call_guest in
 * emu/native.py). In both fault cases the CPU state is whatever the function left; the caller discards it. */
int lift_invoke_checked(CPU *c, void *fn, int fpu)
{
    jmp_buf jb;
    jmp_buf *prev = g_fault_jb;
    int r;
    g_diff_abort = 0;
    if (fpu)
        set_guest_rounding(c);
    if ((r = setjmp(jb)) != 0) {
        g_fault_jb = prev;
        g_diff_abort = 0;
        fesetround(FE_TONEAREST);
        return r;
    }
    g_fault_jb = &jb;
    ((void (*)(CPU *))fn)(c);
    g_fault_jb = prev;
    g_diff_abort = 0;
    fesetround(FE_TONEAREST);
    return 0;
}

/* ---------------------------------------------------------------- fast native dispatch (M5)
 *
 * The bridge above stops emu_start for every native call. The fast path keeps it running. Fast slots are 16-byte
 * entries of a region of their own (emu/native.py FAST_BASE), each holding hlt. A Unicorn code hook over the region
 * runs the lifted function of the slot from inside emu_start, then sets EIP to the guest return address (the same
 * mechanism the HLE stubs use: a register write of EIP in a hook restarts the translation at the new address).
 *
 * Dispatch is an interrupt, not a code hook: each slot starts with `int 0x99`, and fast_intr is a UC_HOOK_INTR hook.
 * Unicorn calls interrupt hooks from cpu_exec's exception handling, after the guest code's translated block has been
 * left, so no translated code is live on the host stack while native code runs. With a code hook it was: the hook
 * returned into its translated block, and any flush of the translation cache during a nested run (Unicorn flushes
 * when its code buffer is full) left that return address pointing at reused memory (intermittent SIGILL/SIGSEGV).
 *
 * Calls from native code back into guest code (c->call_guest) are nested uc_emu_start runs. The run at nesting level
 * D (1..FAST_MAX_DEPTH) returns to fast_ret(D), an hlt inside slot D that the hook never handles (it is not at a
 * slot start): the run stops there because it is the until address.
 *
 * Unwinding: a guest longjmp or C++ throw can discard native frames (a native function calls the guest, and the guest
 * unwinds to a frame above it). The guest then returns to an outer level's fast_ret(j) instead of its own, and the
 * hlt there ends the run with an error. fast_call_guest sees which level that address belongs to, and the native
 * frames in between are dropped the way the guest dropped them: it longjmps to the fast_intr that entered them (only
 * lifted C frames lie in between, never Unicorn's), that hook stops its run, and its level repeats this until level j
 * is reached, which returns to its native caller as if its guest call had returned normally. Guest code past the
 * unwind runs emulated: lifted calls push real return addresses, so the guest returns through the rest of the
 * dropped frames' code until it reaches a fast_ret.
 *
 * Dead frames: the guest can also continue past a native entry without landing on any fast_ret. A catch in a lifted
 * frame, or in an emulated caller below the entry, sends the guest on up the real return addresses, past the outermost
 * native frame it discarded, and the run stops at an address that is no level's fast_ret (in the exe case, the
 * emulator's own return stop). Those native frames must never resume (their registers are stale). fast_intr records
 * the guest ESP at its entry (g_entry_esp[level]: the return-address slot). A level's native frames are dead when the
 * guest ESP is above its entry (live frames lie below it, and a normal return leaves ESP at or below it). After a
 * run that did not land on a fast_ret, fast_call_guest checks this, after the unwind logic above (an unwind to a
 * level's fast_ret also leaves ESP above the entries of the frames it drops, so that is the unwind, not this). The
 * outermost dead level j is the target: the hooks above it are dropped level by level as in an unwind (g_dead_to: each
 * hook stops its run), and hook j does not stop. It writes EIP = the guest's eip, the way a normal return does, so the
 * run that contains hook j goes on with the guest state: the driver's run for j = 0, the nested run of the level below
 * otherwise. The guest state is the continuation, and nothing of the dropped frames runs again. Before the drop, the
 * Python fallback is asked (err -5) whether a stop was recorded; a fatal stop is then not continued. Counted in FS_DEAD.
 *
 * Any other stop (an HLE handler called uc_emu_stop: fatal error, process exit, a timer; a Unicorn error) goes to the
 * Python fallback, which finishes the guest call with the driver or records the error. Once an error is recorded
 * (g_fast_halt), native code must not run on: the native frames still on the host stack would continue with stale
 * guest registers (a loop around a guest call would never end). So a halted fast_call_guest, at entry, after its
 * nested run, or after the fallback, longjmps to the fast_intr of its own level (g_hook_jb), the way an unwind does,
 * and each level below repeats this until the outermost run stops and returns to Python, which raises the error. A
 * halt-unwind is not an FS_UNWIND and leaves g_unwind_to at -1. Python clears the halt when it raises.
 * Unicorn allows UC_MAX_NESTED_LEVEL (64) nested runs; FAST_MAX_DEPTH stays below that.
 */
#define FAST_STRIDE 16u
#define FAST_SLOTS 65536u               /* slot 0 is the stop address; 65535 functions at most (emu/native.py) */
#define FAST_MAX_DEPTH 60
#define FAST_UC_HOOK_INTR 1             /* UC_HOOK_INTR */
#define FAST_INTNO 0x99u                /* each slot starts with int 0x99 (cd 99) */

typedef int (*uc_hook_add_fn)(void *uc, uint64_t *hh, int type, void *cb, void *user, uint64_t begin, uint64_t end);
typedef int (*uc_emu_start_fn)(void *uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count);
typedef int (*uc_emu_stop_fn)(void *uc);
typedef int (*uc_reg_write_fn)(void *uc, int regid, const void *value);
/* Python fallback: a nested run stopped at eip (err: the Unicorn error, or -2 when nesting is too deep). Returns 1
 * when the guest call finished (the CPU is synced from the emulator), 0 when an error was recorded (nothing synced). */
typedef int (*fast_fallback_fn)(CPU *c, uint32_t addr, uint32_t eip, int err);

enum { FS_CALLS, FS_GUEST, FS_FALLBACK, FS_DEPTH, FS_DEEP, FS_INEXACT, FS_NATIVE_NS, FS_GUEST_NS, FS_UNWIND, FS_DEAD, FS_N };

/* Time (ns) for the profile, both exclusive, so they add up to the time spent inside outermost native calls:
 * FS_NATIVE_NS is the time of lifted code (each hook's time minus the time of the guest calls it made itself);
 * FS_GUEST_NS is the time of nested uc_emu_start runs and their fallbacks, minus the native calls inside them.
 * g_level_guest_ns[d] is the guest time charged to the hook running at nesting level d. */
#ifdef __APPLE__
#include <mach/mach_time.h>
static uint64_t fast_now_ns(void)
{
    static mach_timebase_info_data_t tb;
    if (!tb.denom)
        mach_timebase_info(&tb);
    return mach_absolute_time() * tb.numer / tb.denom;
}
#else
static uint64_t fast_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}
#endif
static uint64_t g_fast_count[FAST_SLOTS];      /* calls per slot */
static uint64_t g_level_guest_ns[FAST_MAX_DEPTH + 2];

/* Guest calls from native code per target address: open addressing, a power-of-two table; a target that does not
 * fit (the table is full) is counted under address 0. */
#define GC_BUCKETS 16384u
static uint32_t g_gc_addr[GC_BUCKETS];
static uint64_t g_gc_count[GC_BUCKETS];
static uint64_t g_gc_overflow;

static void gc_note(uint32_t addr)
{
    uint32_t h = (addr * 2654435761u) & (GC_BUCKETS - 1);
    for (uint32_t i = 0; i < 64; i++, h = (h + 1) & (GC_BUCKETS - 1)) {
        if (g_gc_count[h] && g_gc_addr[h] == addr) {
            g_gc_count[h]++;
            return;
        }
        if (!g_gc_count[h]) {
            g_gc_addr[h] = addr;
            g_gc_count[h] = 1;
            return;
        }
    }
    g_gc_overflow++;
}

/* Fast-path entries per return address (the caller's, read from [esp] at the slot): same table as the guest calls
 * above. Entries that did not fit are counted under address 0. */
static uint32_t g_ec_addr[GC_BUCKETS];
static uint64_t g_ec_count[GC_BUCKETS];
static uint64_t g_ec_overflow;

static void ec_note(uint32_t addr)
{
    uint32_t h = (addr * 2654435761u) & (GC_BUCKETS - 1);
    for (uint32_t i = 0; i < 64; i++, h = (h + 1) & (GC_BUCKETS - 1)) {
        if (g_ec_count[h] && g_ec_addr[h] == addr) {
            g_ec_count[h]++;
            return;
        }
        if (!g_ec_count[h]) {
            g_ec_addr[h] = addr;
            g_ec_count[h] = 1;
            return;
        }
    }
    g_ec_overflow++;
}

static uc_emu_start_fn g_emu_start;
static uc_emu_stop_fn g_emu_stop;
static uc_reg_write_fn g_reg_write;      /* single uc_reg_write for EIP: uc_reg_write_batch does not set skip_sync_pc */
static fast_fallback_fn g_fallback;
static uint32_t g_fast_base, g_fast_fs;
static uint8_t *g_fast_mem;
static void (*g_fast_fn[FAST_SLOTS])(CPU *);
static uint8_t g_fast_fpu[FAST_SLOTS];
static int g_fast_depth, g_fast_halt, g_fast_undo;
static jmp_buf *g_hook_jb[FAST_MAX_DEPTH + 1];  /* the fast_intr running at each nesting level (see Unwinding) */
static int g_unwind_to = -1;                     /* level an unwind in progress stops at, or -1 */
static uint32_t g_entry_esp[FAST_MAX_DEPTH + 1]; /* guest ESP at the entry of the fast_intr at each level (Dead frames) */
static int g_dead_to = -1;                       /* level a dead-frame unwind continues at, or -1 */
static uint32_t g_dead_eip;                      /* the guest eip the dead-frame unwind continues at */

static uint32_t fast_ret(int depth)
{
    return g_fast_base + (uint32_t)depth * FAST_STRIDE + 8u;
}

/* The level whose return address eip is (or just past, after the hlt), or -1. */
static int fast_ret_level(uint32_t eip)
{
    uint32_t off = eip - g_fast_base;
    uint32_t d = off / FAST_STRIDE, k = off % FAST_STRIDE;
    if ((k == 8u || k == 9u) && d >= 1 && d <= FAST_MAX_DEPTH)
        return (int)d;
    return -1;
}
/* The return addresses the bridges put in a return-address slot (lift_guest, lift_jump): fast_ret(d) for a fast
 * nesting level d (fast_ret is FAST_BASE + d * FAST_STRIDE + 8), and the slow bridge's stop address, set once by
 * Python (lift_set_bridge_stop). A slot that still holds one of them was not written by the callee. */
static uint32_t g_bridge_stop;
void lift_set_bridge_stop(uint32_t va)
{
    g_bridge_stop = va;
}

int lift_is_bridge_ret(uint32_t v)
{
    uint32_t off = v - g_fast_base;
    if (v && v == g_bridge_stop)
        return 1;
    return g_fast_base && off % FAST_STRIDE == 8u && off / FAST_STRIDE >= 1 && off / FAST_STRIDE <= FAST_MAX_DEPTH;
}

static uint64_t g_fast_stat[FS_N];

static uint32_t fast_read_eip(void)
{
    uint32_t eip = 0;
    int32_t id = ID_EIP;
    void *v = &eip;
    uc_read_many(&id, &v, 1);
    return eip;
}

static uint32_t fast_read_esp(void)
{
    uint32_t esp = 0;
    int32_t id = ID_ESP;
    void *v = &esp;
    uc_read_many(&id, &v, 1);
    return esp;
}

/* The outermost level j <= level whose native frames are dead for the guest ESP (see Dead frames), or -1. The entries
 * fall as the levels deepen, so the first level whose entry the guest ESP is above is the outermost one. */
static int dead_level(uint32_t esp, int level)
{
    for (int j = 0; j <= level; j++)
        if (esp > g_entry_esp[j])
            return j;
    return -1;
}

/* Drops the native frames from the hook at level down to hook target (never returns: a longjmp). */
static void fast_dead_unwind(int level, int target, uint32_t eip) __attribute__((noreturn));
static void fast_dead_unwind(int level, int target, uint32_t eip)
{
    g_fast_stat[FS_DEAD]++;
    g_dead_to = target;
    g_dead_eip = eip;
    longjmp(*g_hook_jb[level], 1);
}

static void fast_call_guest(CPU *c, uint32_t addr);

static void fast_intr(void *uc, uint32_t intno, void *user)
{
    (void)user;
    uint32_t addr = fast_read_eip() - 2;  /* EIP is past the int instruction */
    uint32_t off = addr - g_fast_base;
    uint32_t idx = off / FAST_STRIDE;
    if (intno != FAST_INTNO || off % FAST_STRIDE || idx == 0 || idx >= FAST_SLOTS || !g_fast_fn[idx]) {
        /* any other interrupt (or an unbound slot) stops the run, as an unhooked one would: an error (-4) */
        g_fallback(NULL, intno, addr + 2, -4);
        g_emu_stop(uc);
        return;
    }
    if (g_fast_undo) {                   /* native writes would bypass the undo log: refused (-3 to the fallback) */
        g_fallback(NULL, (uint32_t)addr, 0, -3);
        g_emu_stop(uc);
        return;
    }
    if (g_fast_halt) {
        g_emu_stop(uc);
        return;
    }
    CPU c;
    memset(&c, 0, sizeof c);
    c.mem = g_fast_mem;
    c.call_guest = fast_call_guest;
    c.fs_base = g_fast_fs;
    int fpu = g_fast_fpu[idx];
    int level = g_fast_depth;
    jmp_buf jb;
    jmp_buf *outer = g_hook_jb[level];
    if (_setjmp(jb)) {                   /* an unwind dropped the native frames this hook entered */
        g_hook_jb[level] = outer;
        g_fast_depth = level;
        fesetround(FE_TONEAREST);
        if (g_dead_to == level) {        /* the dead-frame unwind's target: the guest goes on from its eip here */
            g_dead_to = -1;
            g_reg_write(uc, ID_EIP, &g_dead_eip);
            return;
        }
        g_emu_stop(uc);                  /* this level's fast_call_guest continues the unwind */
        return;
    }
    g_hook_jb[level] = &jb;
    lift_sync_from_uc(&c, fpu);
    g_entry_esp[level] = c.r[ESP];       /* Dead frames: the native frames of this level are above this ESP only if dead */
    uint32_t ret = rd32(&c, c.r[ESP]);   /* the entry was reached by jmp: the return address is at [esp] */
    ec_note(ret);
    g_fast_stat[FS_CALLS]++;
    g_fast_count[idx]++;
    uint64_t t0 = fast_now_ns(), guest0 = g_level_guest_ns[level];
    if (fpu)
        set_guest_rounding(&c);
    g_fast_fn[idx](&c);
    g_hook_jb[level] = outer;
    fesetround(FE_TONEAREST);
    uint64_t total = fast_now_ns() - t0;
    g_fast_stat[FS_NATIVE_NS] += total - (g_level_guest_ns[level] - guest0);
    if (level > 0)                       /* inside a guest run of the level below: not that run's guest time */
        g_fast_stat[FS_GUEST_NS] -= total;
    if (g_fast_halt) {
        g_emu_stop(uc);
        return;
    }
    lift_sync_to_uc(&c, fpu);
    /* Quits this translation and continues at ret. Must be uc_reg_write, not the batch call: only the single write
     * sets uc->skip_sync_pc_on_exit, and without it Unicorn puts the slot's address back as EIP when the TB exits. */
    g_reg_write(uc, ID_EIP, &ret);
}

/* Halted (see the comment above FAST_STRIDE): drop the native frames of the hook at level, which is making the guest
 * call. The caller returns right after this. With no hook there is nothing to drop (not reached from native code). */
static void fast_halt_unwind(int level)
{
    g_unwind_to = -1;
    g_dead_to = -1;                      /* a halt stops at every hook, a dead-frame unwind's target included */
    if (g_hook_jb[level])
        longjmp(*g_hook_jb[level], 1);
}

static void fast_call_guest(CPU *c, uint32_t addr)
{
    int level = g_fast_depth;            /* the hook making this call */
    if (g_fast_halt) {
        fast_halt_unwind(level);
        return;
    }
    g_fast_stat[FS_GUEST]++;
    gc_note(addr);
    fesetround(FE_TONEAREST);
    int err = -2;
    uint32_t eip = 0;
    if (g_fast_depth < FAST_MAX_DEPTH) {
        int depth = g_fast_depth + 1;
        c->r[ESP] -= 4;                  /* the guest returns to this level's fast_ret */
        wr32(c, c->r[ESP], fast_ret(depth));
        lift_sync_to_uc(c, 1);
        g_fast_depth = depth;
        if ((uint64_t)g_fast_depth > g_fast_stat[FS_DEPTH])
            g_fast_stat[FS_DEPTH] = (uint64_t)g_fast_depth;
        uint64_t tg = fast_now_ns();
        err = g_emu_start(g_uc, addr, fast_ret(depth), 0, 0);
        tg = fast_now_ns() - tg;
        g_fast_stat[FS_GUEST_NS] += tg;
        g_level_guest_ns[level] += tg;
        g_fast_depth = depth - 1;
        eip = fast_read_eip();
        if (g_fast_halt) {               /* the nested run recorded an error (or a nested fallback did) */
            fast_halt_unwind(level);
            return;
        }
        if (g_dead_to >= 0)              /* a dead-frame unwind passes this level: drop its frame too */
            longjmp(*g_hook_jb[level], 1);
        int lv = g_unwind_to >= 0 ? g_unwind_to : fast_ret_level(eip);
        if (lv >= 1 && lv < depth && g_hook_jb[depth - 1]) {
            /* the guest unwound past this level's native frames to level lv: drop them (see Unwinding) */
            if (g_unwind_to < 0)
                g_fast_stat[FS_UNWIND]++;
            g_unwind_to = lv;
            longjmp(*g_hook_jb[depth - 1], 1);
        }
        if (lv == depth) {               /* the unwind's target: as if the guest call returned here */
            g_unwind_to = -1;
            err = 0;
            eip = fast_ret(depth);
        }
        if (err == 0 && eip == fast_ret(depth)) {
            g_fast_stat[FS_INEXACT] += (uint64_t)lift_sync_from_uc(c, 1);
            set_guest_rounding(c);
            return;
        }
        if (err == 0 && lv < 0) {        /* stopped away from every fast_ret: did the guest return past a native entry? */
            int dj = dead_level(fast_read_esp(), level);
            if (dj >= 0) {
                g_fallback(c, addr, eip, -5);   /* asks the driver only whether a stop was recorded */
                if (g_fast_halt) {
                    fast_halt_unwind(level);
                    return;
                }
                fast_dead_unwind(level, dj, eip);
            }
        }
    } else {
        g_fast_stat[FS_DEEP]++;
    }
    g_fast_stat[FS_FALLBACK]++;
    g_fast_depth++;
    uint64_t tf = fast_now_ns();
    int done = g_fallback(c, addr, eip, err);
    tf = fast_now_ns() - tf;
    g_fast_stat[FS_GUEST_NS] += tf;
    g_level_guest_ns[level] += tf;
    g_fast_depth--;
    if (g_fast_halt) {                   /* the fallback recorded an error, or a nested run inside it did */
        fast_halt_unwind(level);
        return;
    }
    if (!done)
        return;
    int dj = dead_level(fast_read_esp(), level);   /* the fallback's own run may have returned past a native entry */
    if (dj >= 0)
        fast_dead_unwind(level, dj, fast_read_eip());
    lift_sync_from_uc(c, 1);
    set_guest_rounding(c);
}

/* Direct HLE calls. A call from lifted code (fast path only) to an HLE stub (STUB_BASE + idx * STUB_STRIDE,
 * emu/mpemu.py) runs the Python handler through g_hle_cb instead of a nested emu_start that the stub's code hook would
 * serve: no register sync, no emulator entry. With push, ret is pushed first (lift_call_ret; popped again when the
 * call is declined); without it the return address is already at [esp] (lift_jump). The handler sees the arguments
 * above it, as the stub would. The callback returns HLE_DONE (it set EAX and popped ESP as the stub's return would), HLE_DECLINE
 * (take the emulator path this time), HLE_NEVER (the same, and never ask again for this stub) or HLE_HALT (it
 * recorded an error and set the halt flag: the native frames are dropped as for a failed guest call).
 * lift_hle_direct_init(NULL, ...) turns it off. */
enum { HLE_DECLINE, HLE_DONE, HLE_NEVER, HLE_HALT };
#define HLE_STUBS 65536u
typedef int (*hle_direct_fn)(CPU *c, uint32_t idx);
static hle_direct_fn g_hle_cb;
static uint32_t g_hle_base, g_hle_stride = 1;
static uint8_t g_hle_never[HLE_STUBS];
static uint64_t g_hle_calls;

void lift_hle_direct_init(void *cb, uint32_t base, uint32_t stride)
{
    g_hle_cb = (hle_direct_fn)cb;
    g_hle_base = base;
    g_hle_stride = stride ? stride : 1;
    memset(g_hle_never, 0, sizeof g_hle_never);
    g_hle_calls = 0;
}

uint64_t lift_hle_direct_calls(void) { return g_hle_calls; }

/* The native host (E5, host/mphost.c): lifted code runs with no emulator and no Python. The host's CPU has its own
 * call_guest (guest code reached there is a fatal error), and its HLE dispatcher serves every stub call the C handlers
 * here decline; it never declines or halts (it returns HLE_DONE or stops the process). lift_host_call runs a lifted
 * function from the host (an entry point, a callback) with ret as its return address, in the guest's rounding. */
static void (*g_host_call_guest)(CPU *, uint32_t);

void lift_host_init(void *call_guest, void *hle_cb, uint32_t base, uint32_t stride)
{
    g_host_call_guest = (void (*)(CPU *, uint32_t))call_guest;
    lift_hle_direct_init(hle_cb, base, stride);
}

void lift_host_call(CPU *c, uint32_t target, uint32_t ret)
{
    set_guest_rounding(c);
    lift_call_ret(c, target, ret);
    fesetround(FE_TONEAREST);
}

static int hle_direct(CPU *c, uint32_t target, int push, uint32_t ret)
{
    uint32_t off = target - g_hle_base, idx = off / g_hle_stride;
    if (!g_hle_cb || (c->call_guest != fast_call_guest && (!g_host_call_guest || c->call_guest != g_host_call_guest)) ||
        off % g_hle_stride || idx >= HLE_STUBS || g_hle_never[idx])
        return 0;
    int level = g_fast_depth;
    if (g_fast_halt) {
        fast_halt_unwind(level);
        return 1;
    }
    if (push)
        push32(c, ret);
    if (lift_heap_direct(c, idx) || lift_seh_direct(c, idx) || lift_hle_fast(c, idx)) {
        /* served in C (heap.c, seh.c, hle_fast.c), no Python */
        g_hle_calls++;
        return 1;
    }
    fesetround(FE_TONEAREST);
    uint64_t t = fast_now_ns();
    int r = g_hle_cb(c, idx);
    t = fast_now_ns() - t;
    g_fast_stat[FS_GUEST_NS] += t;      /* the handler's time counts as guest time, as it does through the stub */
    g_level_guest_ns[level] += t;
    set_guest_rounding(c);
    if (r == HLE_DONE) {
        g_hle_calls++;
        return 1;
    }
    if (r == HLE_HALT) {
        fast_halt_unwind(level);
        return 1;
    }
    if (r == HLE_NEVER)
        g_hle_never[idx] = 1;
    if (push)
        c->r[ESP] += 4;
    return 0;
}

/* Called by Python (emu/native.py) once per engine. The libunicorn entry points come from the binding that loaded
 * it (the same library the batch sync uses). mem: host address of guest 0; fs_base: the TEB. Registers the code hook
 * over (fast_base, fast_base + fast_size): slot 0 (fast_base) is not hooked. */
void lift_fast_init(void *uc, void *hook_add, void *emu_start, void *reg_read_batch, void *reg_write_batch,
                    void *reg_write, void *emu_stop, uint32_t fast_base, uint32_t fast_size, void *fallback,
                    uint8_t *mem, uint32_t fs_base)
{
    lift_bridge_init(uc, reg_read_batch, reg_write_batch);
    g_emu_start = (uc_emu_start_fn)emu_start;
    g_emu_stop = (uc_emu_stop_fn)emu_stop;
    g_reg_write = (uc_reg_write_fn)reg_write;
    g_fallback = (fast_fallback_fn)fallback;
    g_fast_base = fast_base;
    g_fast_mem = mem;
    g_fast_fs = fs_base;
    memset(g_fast_fn, 0, sizeof g_fast_fn);
    memset(g_fast_fpu, 0, sizeof g_fast_fpu);
    memset(g_fast_stat, 0, sizeof g_fast_stat);
    memset(g_fast_count, 0, sizeof g_fast_count);
    memset(g_level_guest_ns, 0, sizeof g_level_guest_ns);
    memset(g_gc_count, 0, sizeof g_gc_count);
    g_gc_overflow = 0;
    memset(g_ec_count, 0, sizeof g_ec_count);
    g_ec_overflow = 0;
    g_fast_depth = 0;
    g_fast_halt = 0;
    g_fast_undo = 0;
    g_dead_to = -1;
    uint64_t hh = 0;
    ((uc_hook_add_fn)hook_add)(uc, &hh, FAST_UC_HOOK_INTR, (void *)fast_intr, NULL, 1, 0);
}

/* Slot number -> lifted function of va (0 when va is not in lift_table). */
int lift_fast_set(uint32_t slot, uint32_t va)
{
    if (slot == 0 || slot >= FAST_SLOTS)
        return -1;
    unsigned lo = 0, hi = lift_table_len;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        uint32_t t = lift_table[mid].va;
        if (t == va) {
            g_fast_fn[slot] = lift_table[mid].fn;
            g_fast_fpu[slot] = (lift_table[mid].flags & LIFT_FLAG_FPU) != 0;
            return 0;
        }
        if (t < va)
            lo = mid + 1;
        else
            hi = mid;
    }
    return -1;
}

/* The return address of the innermost nested guest call (the one the Python fallback is finishing). */
uint32_t lift_fast_ret_current(void)
{
    return fast_ret(g_fast_depth);
}

/* Python sets this when it records an error (the emulator is stopped at the next hook); clears it after raising. */
void lift_fast_halt_set(int on)
{
    g_fast_halt = on;
    if (!on) {
        g_unwind_to = -1;                /* cleared at the top level, after every halt-unwind has landed */
        g_dead_to = -1;
    }
}

/* Python sets this while an undo log is active: a native slot reached then is refused (fallback with err -3). */
void lift_fast_undo_set(int on)
{
    g_fast_undo = on;
}

void lift_fast_stats(uint64_t *out)
{
    memcpy(out, g_fast_stat, sizeof g_fast_stat);
}

/* Calls per slot number (0..FAST_SLOTS-1) since lift_fast_init. */
void lift_fast_slot_counts(uint64_t *out)
{
    memcpy(out, g_fast_count, sizeof g_fast_count);
}

/* Guest calls made from native code, per target address, since lift_fast_init: writes up to cap (addr, count) pairs
 * and returns how many targets there are. Targets that did not fit the table are reported as address 0. */
uint32_t lift_fast_guest_counts(uint32_t *addrs, uint64_t *counts, uint32_t cap)
{
    uint32_t n = 0;
    for (uint32_t h = 0; h < GC_BUCKETS; h++)
        if (g_gc_count[h]) {
            if (n < cap) {
                addrs[n] = g_gc_addr[h];
                counts[n] = g_gc_count[h];
            }
            n++;
        }
    if (g_gc_overflow) {
        if (n < cap) {
            addrs[n] = 0;
            counts[n] = g_gc_overflow;
        }
        n++;
    }
    return n;
}

/* Fast-path entries per return address (the caller of the slot), since lift_fast_init: same layout as
 * lift_fast_guest_counts. */
uint32_t lift_fast_entry_callers(uint32_t *addrs, uint64_t *counts, uint32_t cap)
{
    uint32_t n = 0;
    for (uint32_t h = 0; h < GC_BUCKETS; h++)
        if (g_ec_count[h]) {
            if (n < cap) {
                addrs[n] = g_ec_addr[h];
                counts[n] = g_ec_count[h];
            }
            n++;
        }
    if (g_ec_overflow) {
        if (n < cap) {
            addrs[n] = 0;
            counts[n] = g_ec_overflow;
        }
        n++;
    }
    return n;
}

/* ---------------------------------------------------------------- guest write log (differential mode)
 *
 * Built with -DLIFT_WRITE_LOG only. lift_note_write records, for each guest byte the first time it is written
 * while the log is on, its value before the write. Pages are 4 KB: a table of page pointers over the 4 GB guest
 * space, each page with the old bytes and a seen mask. lift_wlog_export hands the log to Python as records
 * (uint32 addr, uint32 n, n old bytes, little endian), and Python merges them into its own undo log.
 */
#ifdef LIFT_WRITE_LOG

#define WL_PAGE_SHIFT 12
#define WL_PAGES (1u << 20)              /* 4 GB / 4 KB */
#define WL_MAX_LISTED (1u << 16)         /* 256 MB of logged pages: beyond that the run is hopeless, stop */

typedef struct {
    uint8_t old[4096];
    uint8_t seen[4096];
    uint8_t listed;
} wl_page;

static wl_page **wl_tab;                  /* by page index, allocated on first use */
static uint32_t *wl_list;                 /* page indices with at least one seen byte */
static uint32_t wl_n;
static int wl_on;

static void wl_clear(void)
{
    for (uint32_t i = 0; i < wl_n; i++) {
        wl_page *pg = wl_tab[wl_list[i]];
        memset(pg->seen, 0, sizeof pg->seen);
        pg->listed = 0;
    }
    wl_n = 0;
}

void lift_wlog_begin(void) { wl_clear(); wl_on = 1; }
void lift_wlog_end(void) { wl_clear(); wl_on = 0; }
void lift_wlog_clear(void) { wl_clear(); }

uint32_t lift_wlog_pages(void) { return wl_n; }

void lift_note_write(CPU *c, uint32_t a, uint32_t n)
{
    if (!wl_on || n == 0)
        return;
    uint64_t p = a, end = (uint64_t)a + n;
    if (end > (1ull << 32))
        end = 1ull << 32;
    if (!wl_tab)
        wl_tab = calloc(WL_PAGES, sizeof *wl_tab);
    if (!wl_list)
        wl_list = malloc(WL_MAX_LISTED * sizeof *wl_list);
    while (p < end) {
        uint32_t pi = (uint32_t)(p >> WL_PAGE_SHIFT);
        uint64_t stop = ((uint64_t)pi + 1) << WL_PAGE_SHIFT;
        if (stop > end)
            stop = end;
        wl_page *pg = wl_tab[pi];
        if (!pg)
            pg = wl_tab[pi] = calloc(1, sizeof *pg);
        if (!pg->listed) {
            if (wl_n == WL_MAX_LISTED) {
                fprintf(stderr, "lift: write log full (%u pages) at %08x: the run is not undoable\n", wl_n, a);
                abort();
            }
            pg->listed = 1;
            wl_list[wl_n++] = pi;
        }
        uint32_t off = (uint32_t)(p & 4095u), lim = off + (uint32_t)(stop - p);
        uint32_t base = pi << WL_PAGE_SHIFT;
        for (uint32_t j = off; j < lim; j++)
            if (!pg->seen[j]) {
                pg->old[j] = c->mem[base + j];
                pg->seen[j] = 1;
            }
        p = stop;
    }
}

/* Records for every seen run, in list order. Returns the size needed; writes it when buf holds cap bytes. */
size_t lift_wlog_export(uint8_t *buf, size_t cap)
{
    size_t total = 0;
    for (uint32_t i = 0; i < wl_n; i++) {
        uint32_t pi = wl_list[i];
        wl_page *pg = wl_tab[pi];
        uint32_t j = 0;
        while (j < 4096) {
            if (!pg->seen[j]) {
                j++;
                continue;
            }
            uint32_t s = j;
            while (j < 4096 && pg->seen[j])
                j++;
            uint32_t len = j - s, addr = (pi << WL_PAGE_SHIFT) + s;
            if (buf && total + 8 + len <= cap) {
                memcpy(buf + total, &addr, 4);
                memcpy(buf + total + 4, &len, 4);
                memcpy(buf + total + 8, pg->old + s, len);
            }
            total += 8 + len;
        }
    }
    return total;
}

/* Restore every logged byte of the guest memory at mem (the host address of guest 0), then clear the log. */
void lift_wlog_rollback(uint8_t *mem)
{
    for (uint32_t i = 0; i < wl_n; i++) {
        uint32_t pi = wl_list[i];
        wl_page *pg = wl_tab[pi];
        for (uint32_t j = 0; j < 4096; j++)
            if (pg->seen[j])
                mem[(pi << WL_PAGE_SHIFT) + j] = pg->old[j];
    }
    wl_clear();
}

#endif /* LIFT_WRITE_LOG */
