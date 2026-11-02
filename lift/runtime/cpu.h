/* Guest CPU state shared by lifted code, the runtime and the emulator bridge (M5).
 *
 * Guest memory is one host mapping: guest address A lives at mem_base + A. The guest stack, TEB
 * (fs:[0] SEH chain) and heap are all in it, so lifted code needs no memory syncing.
 *
 * A lifted function is `void f_<hex va>(CPU *c)`. It is entered as if by `call`: the return
 * address is at [esp]. It runs on the guest stack and leaves esp/eax/... as the original would,
 * so stdcall, cdecl and thiscall all fall out of the guest code itself.
 *
 * Flags are kept as one byte each (0 or 1). x87 is modelled on doubles: the game requires 53-bit
 * precision and round-to-nearest (docs/census.md §7), so + - * / sqrt are bit-exact. */
#ifndef LIFT_CPU_H
#define LIFT_CPU_H

#include <stdint.h>
#include <string.h>

enum { EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI };   /* x86 register-number order */

typedef struct CPU {
    uint32_t r[8];              /* indexed by EAX..EDI */
    uint32_t eip;               /* set by the bridge on exit; lifted code does not maintain it */
    uint8_t cf, pf, af, zf, sf, of, df, _pad;
    /* x87: st(i) is st[(top + i) & 7]. tag bit i set = physical register i empty. */
    double st[8];
    uint32_t top, tag;
    uint16_t cw, sw;            /* sw: condition bits C0..C3 only; top is kept in `top` */
    uint32_t fs_base;           /* guest address of the TEB */
    uint8_t *mem;               /* host address of guest address 0 */
    /* Bridge: run guest (emulated) code at addr as if called. Lifted code does NOT push a return
     * address first: the bridge pushes its own return slot, syncs this struct into the emulator,
     * runs addr until it returns to that slot (popping it and any stdcall args), and syncs back. */
    void (*call_guest)(struct CPU *c, uint32_t addr);
    void *user;                 /* owned by the bridge */
    /* MMX (M5). Model: lifted MMX code works on mm[], never on st[]. mm[i] is the low 64 bits (mantissa) of
     * PHYSICAL x87 register i, and the bridge syncs the two separately: from the emulator it loads mm[i] from
     * FPi's mantissa; back to it, FPi takes (mm[i], exponent 0xffff) for each register whose bit is set in
     * mmx_dirty, and the x87 values (st/top/tag) are written as usual. Every MMX instruction sets top = 0 and
     * marks all tags valid (the hardware does the same); emms sets tag = 0xff (all empty) and keeps mm[].
     * A function that touches MMX has the FPU flag in its LiftEntry, so the bridge always syncs its FP state.
     * Lifted code that reads st[] after MMX code wrote mm[] without emms is not modelled: real code does not
     * do that. */
    uint64_t mm[8];
    uint32_t mmx_dirty;         /* bit i set: mm[i] was written by lifted code and FPi must be updated */
} CPU;

#define R(c, n)     ((c)->r[n])
#define MEM(c, a)   ((c)->mem + (uint32_t)(a))

/* Write logging for the differential mode: a library built with -DLIFT_WRITE_LOG reports every
 * guest-memory write (address and length, before the bytes change) to lift_note_write, so the run
 * can be compared and rolled back. Every direct write to guest memory must go through NOTE_WRITE. */
#ifdef LIFT_WRITE_LOG
void lift_note_write(struct CPU *c, uint32_t a, uint32_t n);
#define NOTE_WRITE(c, a, n) lift_note_write((c), (uint32_t)(a), (uint32_t)(n))
#else
#define NOTE_WRITE(c, a, n) ((void)0)
#endif

/* Unaligned little-endian guest accesses (arm64 is little-endian; memcpy compiles to ldr/str). */
static inline uint8_t  rd8 (CPU *c, uint32_t a) { return *MEM(c, a); }
static inline uint16_t rd16(CPU *c, uint32_t a) { uint16_t v; memcpy(&v, MEM(c, a), 2); return v; }
static inline uint32_t rd32(CPU *c, uint32_t a) { uint32_t v; memcpy(&v, MEM(c, a), 4); return v; }
static inline uint64_t rd64(CPU *c, uint32_t a) { uint64_t v; memcpy(&v, MEM(c, a), 8); return v; }
static inline void wr8 (CPU *c, uint32_t a, uint8_t v)  { NOTE_WRITE(c, a, 1); *MEM(c, a) = v; }
static inline void wr16(CPU *c, uint32_t a, uint16_t v) { NOTE_WRITE(c, a, 2); memcpy(MEM(c, a), &v, 2); }
static inline void wr32(CPU *c, uint32_t a, uint32_t v) { NOTE_WRITE(c, a, 4); memcpy(MEM(c, a), &v, 4); }
static inline void wr64(CPU *c, uint32_t a, uint64_t v) { NOTE_WRITE(c, a, 8); memcpy(MEM(c, a), &v, 8); }

static inline void push32(CPU *c, uint32_t v) { c->r[ESP] -= 4; wr32(c, c->r[ESP], v); }
static inline uint32_t pop32(CPU *c) { uint32_t v = rd32(c, c->r[ESP]); c->r[ESP] += 4; return v; }

/* Call a target only known at run time (or not lifted): a lifted function if one exists at
 * target, else c->call_guest. Same convention as call_guest: no return address pushed. */
void lift_call(CPU *c, uint32_t target);

/* A call to guest code that is not lifted: c->call_guest, then the return-address slot left as a real call leaves
 * it. call_guest's bridge puts its own return address in that slot (just below the caller's esp), and the guest's
 * ret leaves it there; emulated code can later read the slot as an uninitialised local, so it must hold ret.
 * A callee may write its own slot instead (MSVCRT's _EH_prolog overwrites it with the caller's ebp and points ebp at
 * it), so ret is put back only while the slot still holds the bridge's address (lift_is_bridge_ret, runtime.c). */
int lift_is_bridge_ret(uint32_t v);
static inline void lift_guest(CPU *c, uint32_t target, uint32_t ret)
{
    uint32_t sp = c->r[ESP];
    c->call_guest(c, target);
    if (lift_is_bridge_ret(rd32(c, sp - 4)))
        wr32(c, sp - 4, ret);
}

/* A call through a register, memory or an IAT slot, so the target is only known at run time. A lifted target
 * is entered with ret (the real return address) pushed, as the original call would; any other target goes to
 * c->call_guest (no push). This is how calls between lifted modules (imports) stay native. */
void lift_call_ret(CPU *c, uint32_t target, uint32_t ret);

/* A tail jump through an IAT slot: the caller's return address is at [esp]. A lifted target is entered as is
 * (its ret pops that address); any other target gets `esp += 4; call_guest`, as for an import tail jump. */
void lift_jump(CPU *c, uint32_t target);

/* An instruction the translator does not handle. The function is marked emulator-only at
 * translation time, so reaching this at run time is a bug. */
void lift_unsupported(CPU *c, uint32_t va, const char *what);
#define UNSUPPORTED(c, va, what) lift_unsupported((c), (va), (what))

#endif
