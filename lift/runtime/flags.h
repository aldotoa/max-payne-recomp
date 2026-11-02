/* Arithmetic flag helpers for lifted code (M5). Each computes the six arithmetic flags exactly as
 * the Intel manual specifies, from the operands (not the result alone). Flags the manual leaves
 * undefined get the value Unicorn (qemu's cc_helper_template.h) gives them, so lifted code and the
 * emulator agree bit for bit: AF = 0 after logic ops, shifts, mul/imul and bsf/bsr; shr's OF for
 * counts above 1 is the top bit of (value >> (count - 1)) ^ result; mul/imul set SF ZF PF from the
 * low half of the product; bsf/bsr set the logic-op flags of the source. Operands may be passed
 * unmasked; they are truncated to the operation width here.
 *
 *   flags_sub8/16/32(c, a, b)  cmp and sub: flags of a - b (the result is not written back)
 *   flags_add8/16/32(c, a, b)  add: flags of a + b
 *   flags_logic8/16/32(c, r)   and/or/xor/test: r is the already-computed result;
 *                              CF = OF = AF = 0 (AF is undefined by the manual; qemu clears it)
 *
 * Parity is taken over the low byte of the result, for every width. */
#ifndef LIFT_FLAGS_H
#define LIFT_FLAGS_H

#include "cpu.h"

/* The flags of a helper whose flags are dead (lift/x86c.py, dead-flag elimination): a throwaway block for the
 * helper to write into. Nothing reads it, so the compiler drops the stores. cf is copied in because adc, sbb,
 * rcl, rcr, inc and dec read CF; the other flags are never read before they are written. */
#define FL_DEAD(c) (&(CPU){ .cf = (c)->cf })

static inline uint8_t fl_parity(uint32_t v)
{
    v &= 0xffu;
    v ^= v >> 4;
    v &= 0xfu;
    return (0x9669u >> v) & 1u;        /* 1 when the number of set bits is even */
}

#define FL_SUB(N, MASK, SIGN)                                                           \
static inline void flags_sub##N(CPU *c, uint32_t a, uint32_t b)                         \
{                                                                                       \
    uint32_t aa = a & (MASK), bb = b & (MASK), r = (aa - bb) & (MASK);                  \
    c->cf = aa < bb;                                                                    \
    c->zf = r == 0;                                                                     \
    c->sf = (r & (SIGN)) != 0;                                                          \
    c->of = ((aa ^ bb) & (aa ^ r) & (SIGN)) != 0;                                       \
    c->af = ((aa ^ bb ^ r) & 0x10u) != 0;                                               \
    c->pf = fl_parity(r);                                                               \
}

#define FL_ADD(N, MASK, SIGN)                                                           \
static inline void flags_add##N(CPU *c, uint32_t a, uint32_t b)                         \
{                                                                                       \
    uint32_t aa = a & (MASK), bb = b & (MASK), r = (aa + bb) & (MASK);                  \
    c->cf = r < aa;                                                                     \
    c->zf = r == 0;                                                                     \
    c->sf = (r & (SIGN)) != 0;                                                          \
    c->of = ((aa ^ r) & (bb ^ r) & (SIGN)) != 0;                                        \
    c->af = ((aa ^ bb ^ r) & 0x10u) != 0;                                               \
    c->pf = fl_parity(r);                                                               \
}

#define FL_LOGIC(N, MASK, SIGN)                                                         \
static inline void flags_logic##N(CPU *c, uint32_t r)                                   \
{                                                                                       \
    r &= (MASK);                                                                        \
    c->cf = 0;                                                                          \
    c->of = 0;                                                                          \
    c->af = 0;                                                                          \
    c->zf = r == 0;                                                                     \
    c->sf = (r & (SIGN)) != 0;                                                          \
    c->pf = fl_parity(r);                                                               \
}

FL_SUB(8,  0xffu,        0x80u)
FL_SUB(16, 0xffffu,      0x8000u)
FL_SUB(32, 0xffffffffu,  0x80000000u)
FL_ADD(8,  0xffu,        0x80u)
FL_ADD(16, 0xffffu,      0x8000u)
FL_ADD(32, 0xffffffffu,  0x80000000u)
FL_LOGIC(8,  0xffu,       0x80u)
FL_LOGIC(16, 0xffffu,     0x8000u)
FL_LOGIC(32, 0xffffffffu, 0x80000000u)

#undef FL_SUB
#undef FL_ADD
#undef FL_LOGIC

/* ---- Integer ALU helpers (M5, lift/ops_alu.py). w is the operand width in bits: 8, 16 or 32.
 * Every helper that returns a value returns it truncated to w bits. Flags the manual leaves
 * undefined are still set to a definite value (the one the hardware gives for the common case). */

static inline uint32_t fl_mask(unsigned w) { return w == 32 ? 0xffffffffu : (1u << w) - 1u; }  /* w-bit mask */
static inline uint32_t fl_msb(uint32_t v, unsigned w) { return (v >> (w - 1)) & 1u; }          /* sign bit */

/* SF, ZF and PF from a w-bit result. */
static inline void fl_szp(CPU *c, uint32_t r, unsigned w)
{
    r &= fl_mask(w);
    c->sf = fl_msb(r, w);
    c->zf = r == 0;
    c->pf = fl_parity(r);
}

/* Flags of a + b, a - b and a logic result r, for width w. */
static inline void fl_add(CPU *c, uint32_t a, uint32_t b, unsigned w)
{
    if (w == 8) flags_add8(c, a, b); else if (w == 16) flags_add16(c, a, b); else flags_add32(c, a, b);
}
static inline void fl_sub(CPU *c, uint32_t a, uint32_t b, unsigned w)
{
    if (w == 8) flags_sub8(c, a, b); else if (w == 16) flags_sub16(c, a, b); else flags_sub32(c, a, b);
}
static inline void fl_logic(CPU *c, uint32_t r, unsigned w)
{
    if (w == 8) flags_logic8(c, r); else if (w == 16) flags_logic16(c, r); else flags_logic32(c, r);
}

/* adc: a + b + CF, all six flags. */
static inline uint32_t flags_adc(CPU *c, uint32_t a, uint32_t b, unsigned w)
{
    uint64_t m = fl_mask(w), aa = a & m, bb = b & m, full = aa + bb + c->cf;
    uint32_t r = (uint32_t)(full & m);
    c->cf = full > m;
    c->of = ((aa ^ r) & (bb ^ r) & (1ull << (w - 1))) != 0;
    c->af = ((aa ^ bb ^ r) & 0x10u) != 0;
    fl_szp(c, r, w);
    return r;
}

/* sbb: a - b - CF, all six flags. */
static inline uint32_t flags_sbb(CPU *c, uint32_t a, uint32_t b, unsigned w)
{
    uint64_t m = fl_mask(w), aa = a & m, bb = b & m, cin = c->cf;
    uint32_t r = (uint32_t)((aa - bb - cin) & m);
    c->cf = aa < bb + cin;
    c->of = ((aa ^ bb) & (aa ^ r) & (1ull << (w - 1))) != 0;
    c->af = ((aa ^ bb ^ r) & 0x10u) != 0;
    fl_szp(c, r, w);
    return r;
}

/* inc and dec: all flags but CF, which is kept. */
static inline uint32_t flags_inc(CPU *c, uint32_t a, unsigned w)
{
    uint8_t cf = c->cf;
    fl_add(c, a, 1, w);
    c->cf = cf;
    return (a + 1) & fl_mask(w);
}
static inline uint32_t flags_dec(CPU *c, uint32_t a, unsigned w)
{
    uint8_t cf = c->cf;
    fl_sub(c, a, 1, w);
    c->cf = cf;
    return (a - 1) & fl_mask(w);
}

/* Shifts and rotates. n is the raw count: masked to 5 bits here. n == 0 changes no flags.
 * OF is exact for n == 1 only (undefined for other counts by the manual). */

/* shl / sal: CF = last bit out, SF ZF PF from the result. */
static inline uint32_t flags_shl(CPU *c, uint32_t v, uint32_t n, unsigned w)
{
    uint32_t m = fl_mask(w);
    n &= 31;
    v &= m;
    if (n == 0)
        return v;
    uint64_t t = (uint64_t)v << n;
    uint32_t r = (uint32_t)t & m;
    c->cf = (t >> w) & 1u;
    c->of = fl_msb(r, w) ^ c->cf;
    c->af = 0;
    fl_szp(c, r, w);
    return r;
}

/* shr: logical right shift. */
static inline uint32_t flags_shr(CPU *c, uint32_t v, uint32_t n, unsigned w)
{
    n &= 31;
    v &= fl_mask(w);
    if (n == 0)
        return v;
    uint32_t r = v >> n;
    c->cf = (v >> (n - 1)) & 1u;
    c->of = fl_msb((v >> (n - 1)) ^ r, w);          /* the manual's OF for n == 1; qemu's for n > 1 */
    c->af = 0;
    fl_szp(c, r, w);
    return r;
}

/* sar: arithmetic right shift; counts past the width give the sign. */
static inline uint32_t flags_sar(CPU *c, uint32_t v, uint32_t n, unsigned w)
{
    uint32_t m = fl_mask(w);
    n &= 31;
    if (n == 0)
        return v & m;
    int64_t sv = w == 8 ? (int8_t)v : w == 16 ? (int16_t)v : (int32_t)v;
    uint32_t r = (uint32_t)(sv >> n) & m;
    c->cf = (sv >> (n - 1)) & 1;
    c->of = 0;
    c->af = 0;
    fl_szp(c, r, w);
    return r;
}

/* rol: rotate left by n mod w; only CF and OF change. */
static inline uint32_t flags_rol(CPU *c, uint32_t v, uint32_t n, unsigned w)
{
    uint32_t m = fl_mask(w);
    n &= 31;
    v &= m;
    if (n == 0)
        return v;
    n %= w;
    uint32_t r = n ? ((v << n) | (v >> (w - n))) & m : v;
    c->cf = r & 1u;
    c->of = fl_msb(r, w) ^ c->cf;
    return r;
}

/* ror: rotate right by n mod w; only CF and OF change. */
static inline uint32_t flags_ror(CPU *c, uint32_t v, uint32_t n, unsigned w)
{
    uint32_t m = fl_mask(w);
    n &= 31;
    v &= m;
    if (n == 0)
        return v;
    n %= w;
    uint32_t r = n ? ((v >> n) | (v << (w - n))) & m : v;
    c->cf = fl_msb(r, w);
    c->of = fl_msb(r, w) ^ ((r >> (w - 2)) & 1u);
    return r;
}

/* rcl: rotate through CF, a ring of w+1 bits (CF on top), by n mod (w+1); only CF and OF change. */
static inline uint32_t flags_rcl(CPU *c, uint32_t v, uint32_t n, unsigned w)
{
    uint32_t m = fl_mask(w);
    uint64_t all = (2ull << w) - 1;
    n &= 31;
    v &= m;
    if (n == 0)
        return v;
    n %= w + 1;
    if (n == 0)                     /* a whole turn of the ring: qemu changes no flags */
        return v;
    uint64_t ring = ((uint64_t)c->cf << w) | v;
    ring = ((ring << n) | (ring >> (w + 1 - n))) & all;
    uint32_t r = (uint32_t)ring & m;
    c->cf = (ring >> w) & 1u;
    c->of = fl_msb(v ^ r, w);       /* the manual's OF for n == 1; qemu's for n > 1 */
    return r;
}

/* rcr: rotate right through CF, same ring as rcl. */
static inline uint32_t flags_rcr(CPU *c, uint32_t v, uint32_t n, unsigned w)
{
    uint32_t m = fl_mask(w);
    uint64_t all = (2ull << w) - 1;
    n &= 31;
    v &= m;
    if (n == 0)
        return v;
    n %= w + 1;
    if (n == 0)                     /* a whole turn of the ring: qemu changes no flags */
        return v;
    uint64_t ring = ((uint64_t)c->cf << w) | v;
    ring = ((ring >> n) | (ring << (w + 1 - n))) & all;
    uint32_t r = (uint32_t)ring & m;
    c->cf = (ring >> w) & 1u;
    c->of = fl_msb(v ^ r, w);       /* the manual's OF for n == 1; qemu's for n > 1 */
    return r;
}

/* shld / shrd (w = 16 or 32). For w = 16 a count above 16 is undefined by the manual; qemu (and
 * Intel hardware) shift the 48-bit value d:s:d (high to low), and so do these. OF is the manual's for n == 1 and qemu's top bit of (value shifted by n - 1) ^ result
 * otherwise. */

/* shld: d << n | s >> (w - n). CF = last bit out of the top of d. */
static inline uint32_t flags_shld(CPU *c, uint32_t d, uint32_t s, uint32_t n, unsigned w)
{
    uint32_t m = fl_mask(w);
    n &= 31;
    d &= m;
    s &= m;
    if (n == 0)
        return d;
    /* the value, left-aligned in 64 bits: d then s (then d again for w = 16) */
    uint64_t x = w == 16 ? ((uint64_t)d << 48 | (uint64_t)s << 32 | (uint64_t)d << 16)
                         : ((uint64_t)d << 32 | s);
    unsigned top = w == 16 ? 48 : 32;                    /* where d's low bit sits */
    uint32_t r = (uint32_t)((x << n) >> top) & m;
    uint32_t prev = (uint32_t)((x << (n - 1)) >> top) & m;
    c->cf = fl_msb(prev, w);
    c->of = fl_msb(prev ^ r, w);
    c->af = 0;
    fl_szp(c, r, w);
    return r;
}

/* shrd: d >> n | s << (w - n). CF = last bit out of the bottom of d. */
static inline uint32_t flags_shrd(CPU *c, uint32_t d, uint32_t s, uint32_t n, unsigned w)
{
    uint32_t m = fl_mask(w);
    n &= 31;
    d &= m;
    s &= m;
    if (n == 0)
        return d;
    /* the value, right-aligned: d at the bottom, then s (then d again for w = 16) */
    uint64_t x = w == 16 ? ((uint64_t)d << 32 | (uint64_t)s << 16 | d) : ((uint64_t)s << 32 | d);
    uint32_t r = (uint32_t)(x >> n) & m;
    uint32_t prev = (uint32_t)(x >> (n - 1)) & m;
    c->cf = prev & 1u;
    c->of = fl_msb(prev ^ r, w);
    c->af = 0;
    fl_szp(c, r, w);
    return r;
}

/* Divide error (#DE), raised by div and idiv for a zero divisor or a quotient that does not fit.
 * The bridge implements it. Lifted code calls it with the faulting instruction's address, then
 * returns. */
void lift_div_fault(CPU *c, uint32_t va);

#endif
