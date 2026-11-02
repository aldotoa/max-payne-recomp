/* x87 FPU state and helpers for lifted code (M5), modelled on C doubles.
 *
 * The game runs with precision control 53 bits and round-to-nearest (checked every frame), so an
 * x87 register is a double and + - * / sqrt are bit-exact. Within a frame, e2mfc's vertex code runs
 * with precision control 00 (24-bit; H54 profile), so x87_finw rounds that case inline. Other settings:
 *   - Rounding control (cw bits 10-11) is applied to the host FP environment with fesetround() on
 *     fldcw, so host arithmetic follows it. fist/fistp round in software (x87_rint), so they do
 *     not depend on the host mode.
 *   - Precision control 00 (24-bit) rounds each arithmetic result to 24 significant bits
 *     (x87_round). 10 (53-bit) and 11 (64-bit) use the double as is: 64-bit precision is treated
 *     as 53-bit, so that setting is not bit-exact with a real 80-bit register. 01 is reserved and
 *     is treated as 53-bit.
 *   - Values held in registers are doubles. An 80-bit value outside double range cannot be held.
 *     Loads from m80 round to nearest-even (x87_f80_to_double); stores to m80 are exact.
 *
 * Stack faults are not modelled: the reference emulator does not model them either, and the game
 * never reaches one. ST(i) reads the stored value whatever its tag, a push overwrites its target,
 * and only push, pop, ffree and fninit change tags (writes to ST(i) do not). This is the
 * reference's behaviour, which differs from the SDM for empty registers.
 *
 * Status word: cpu.sw holds exception bits 0-6 and C0..C3 (0x4700); TOP is kept in `top` and added
 * in fnstsw. C1 is not written by compares or fxch, and fxam writes all four.
 *
 * Tags: cpu.h has `top` and `tag` (bit p set = physical register p empty). ST(i) is
 * st[(top + i) & 7]. */
#ifndef LIFT_X87_H
#define LIFT_X87_H

#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "cpu.h"

#define X87_SW_IE 0x0001u
#define X87_SW_ZE 0x0004u
#define X87_SW_SF 0x0040u
#define X87_SW_C0 0x0100u
#define X87_SW_C1 0x0200u
#define X87_SW_C2 0x0400u
#define X87_SW_C3 0x4000u
#define X87_SW_CC 0x4700u        /* C0..C3 */
#define X87_SW_CMP 0x4500u       /* C0, C2, C3: what fcom and ftst write (C1 is kept) */

/* The default NaN ("indefinite"): negative quiet NaN, as the x87 produces on an invalid operation. */
static inline double x87_indef(void)
{
    uint64_t b = 0xfff8000000000000ull;
    double d;
    memcpy(&d, &b, 8);
    return d;
}

/* Host rounding mode from a control word (RC = bits 10-11). */
static inline void x87_set_rounding(uint16_t cw)
{
    static const int mode[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    fesetround(mode[(cw >> 10) & 3]);
}

static inline void x87_init(CPU *c)                      /* fninit */
{
    c->top = 0;
    c->tag = 0xffu;
    c->cw = 0x037fu;
    c->sw = 0;
    x87_set_rounding(c->cw);
}

static inline void x87_ldcw(CPU *c, uint16_t cw)         /* fldcw */
{
    c->cw = cw;
    x87_set_rounding(cw);
}

static inline uint16_t x87_status(CPU *c)                /* fnstsw: TOP in bits 11-13, B and ES clear */
{
    return (uint16_t)((c->sw & 0x477fu) | ((c->top & 7u) << 11));
}

/* x87_status with TOP given: lifted code that keeps the stack in locals (lift/x86c.py X87Cache) has not written TOP
 * back yet. */
static inline uint16_t x87_status_top(CPU *c, uint32_t top)
{
    return (uint16_t)((c->sw & 0x477fu) | ((top & 7u) << 11));
}

/* The tag word after a block's pushes and pops (X87Cache.flush): valid and empty are masks of slots relative to xt
 * (the TOP the block started from), rotated to physical registers. valid clears tag bits, empty sets them. */
static inline uint32_t x87_tag_update(uint32_t tag, uint32_t xt, uint32_t valid, uint32_t empty)
{
    xt &= 7u;
    uint32_t v = ((valid << xt) | (valid >> (8u - xt))) & 0xffu;
    uint32_t e = ((empty << xt) | (empty >> (8u - xt))) & 0xffu;
    return (tag & ~v) | e;
}

static inline void x87_clex(CPU *c)                      /* fnclex: exception flags and B/ES clear */
{
    c->sw &= (uint16_t)~0x00ffu;
}

/* Stack faults are not modelled (see the header comment): ST(i) reads the stored value whatever
 * its tag, and a push overwrites its target. The reference emulator does the same. */

/* ST(i) for reading. */
static inline double x87_rd(CPU *c, unsigned i)
{
    return c->st[(c->top + i) & 7u];
}

/* ST(i) = v. The tag is not changed (only push, pop, ffree and fninit change tags, as in the
 * reference emulator). */
static inline void x87_wr(CPU *c, unsigned i, double v)
{
    c->st[(c->top + i) & 7u] = v;
}

/* push: TOP = TOP - 1, then store. */
static inline void x87_push(CPU *c, double v)
{
    unsigned p = (c->top - 1u) & 7u;
    c->top = p;
    c->st[p] = v;
    c->tag &= ~(1u << p);
}

/* pop: mark ST(0) empty, TOP = TOP + 1. */
static inline void x87_pop(CPU *c)
{
    c->tag |= 1u << (c->top & 7u);
    c->top = (c->top + 1u) & 7u;
}

/* ffree ST(i): mark empty, nothing else changes. */
static inline void x87_free(CPU *c, unsigned i)
{
    c->tag |= 1u << ((c->top + i) & 7u);
}

/* fxch ST(i): swap the values. Tags stay with their physical registers. */
static inline void x87_xch(CPU *c, unsigned i)
{
    unsigned p0 = c->top & 7u, pi = (c->top + i) & 7u;
    double t = c->st[p0];
    c->st[p0] = c->st[pi];
    c->st[pi] = t;
}

/* fsqrt: for a negative input (sign bit set, NaNs included) C0, C1, C3 are cleared and C2 set; the
 * SDM leaves these bits undefined, and this is what the reference emulator does (the rig compares
 * them). Otherwise they are unchanged. */
static inline void x87_sqrt(CPU *c, double x)
{
    if (signbit(x))
        c->sw = (uint16_t)((c->sw & ~X87_SW_CC) | X87_SW_C2);
}

/* Round to an integer with an explicit RC mode (0 nearest-even, 1 down, 2 up, 3 truncate),
 * independent of the host mode. |v| >= 2^52 is already an integer. */
static inline double x87_rint(double v, unsigned rc)
{
    double f = floor(v);
    switch (rc & 3u) {
    case 0: {
        double d = v - f;                      /* exact for |v| < 2^52 */
        if (d > 0.5 || (d == 0.5 && fmod(f, 2.0) != 0.0))
            f += 1.0;
        return f;
    }
    case 1:
        return f;
    case 2:
        return ceil(v);
    default:
        return trunc(v);
    }
}

/* The slow path of x87_round: a subnormal double under precision control 00 (the only input that
 * reaches it, see x87_round). Kept out of line and cold, so that x87_round and its callers stay
 * small enough to inline: the frexp/ldexp and rint calls are not in any hot caller. static, not
 * extern: each translation unit that uses it gets its own copy, emitted only where x87_round
 * calls it (the copy is small and cold). Behaviour is that of the original inline code. */
static __attribute__((noinline, cold)) double x87_round_slow(CPU *c, double v)
{
    if (((c->cw >> 8) & 3u) != 0 || v != v || v == 0.0 || isinf(v))
        return v;
    int e;
    frexp(v, &e);
    double s = ldexp(v, 24 - e);               /* 24 integer bits */
    return ldexp(x87_rint(s, (c->cw >> 10) & 3u), e - 24);
}

/* Precision control: 00 rounds to 24 significant bits, with the same RC rounding. Other
 * settings return v unchanged (see the header comment).
 *
 * Fast path for a normal double (not zero, subnormal, inf or NaN): its significand is 1.m with
 * 52 explicit bits, and 24 significant bits keep the top 23 of them. The low 29 bits of the
 * mantissa are the part rounded off, and bit 29 is the last kept bit. Rounding is then integer
 * arithmetic on the bit pattern: adding 2^28 - 1 plus the last kept bit, then clearing the low
 * 29 bits, is round-half-even; a carry out of the mantissa moves into the exponent, which is the
 * next binade, and past DBL_MAX it is the infinity bit pattern (the overflow ldexp gives under the
 * host mode that matches RC, which fldcw sets). Sign and magnitude are separate here, so for the
 * directed modes the sign decides whether the magnitude is rounded up. Only integer ops are used,
 * so the host rounding mode does not matter. */
static inline double x87_round(CPU *c, double v)
{
    uint64_t u;
    memcpy(&u, &v, 8);
    if (__builtin_expect(((c->cw >> 8) & 3u) != 0, 0))
        return v;                              /* precision control 01, 10, 11: no change */
    uint64_t ex = (u >> 52) & 0x7ffu;
    if (ex - 1u < 0x7feu) {                    /* normal: not zero, subnormal, inf or NaN */
        unsigned rc = (c->cw >> 10) & 3u;
        uint64_t neg = u >> 63;
        if (rc == 0) {
            u += 0x0FFFFFFFull + ((u >> 29) & 1);     /* nearest-even */
        } else {
            /* Magnitude goes up (away from zero) for RC up on a positive value and RC down on a
             * negative one; RC toward zero never does. A dropped bit is needed for any change. */
            int away = (rc == 2) ? !neg : (rc == 1) ? (int)neg : 0;
            if (away && (u & 0x1FFFFFFFull))
                u += 1ull << 29;
        }
        u &= ~0x1FFFFFFFull;
        memcpy(&v, &u, 8);
        return v;
    }
    if (__builtin_expect(ex == 0 && (u & 0xFFFFFFFFFFFFFull) != 0, 0))
        return x87_round_slow(c, v);           /* subnormal, PC 00 */
    return v;                                  /* zero, inf, NaN */
}

/* Result of an arithmetic op on x and y: a NaN result is x or y when one of them is NaN (x
 * first, as x87 does), else the default NaN. Then precision control. */
static __attribute__((noinline, cold)) double x87_fin_slow(CPU *c, double r, double x, double y)
{
    if (r != r)
        r = (x != x) ? x : (y != y) ? y : x87_indef();
    return x87_round(c, r);
}

/* x87_fin with the control word passed in: lifted code keeps it in a local (xcw, x86c.X87_CW_LOCAL), because reading
 * c->cw would be repeated after every guest store (guest memory is a uint8_t pointer, which may alias the CPU struct).
 * Same result as the NaN choice followed by x87_round. Inline cases: PC 00 with RC nearest and a normal result (the
 * 24-bit rounding of x87_round; e2mfc's vertex code runs like this), and PC 01..11 without a NaN (the result as is;
 * the game's default, cw 0x023f). Everything else (NaN, zero, inf or subnormal under PC 00, directed rounding under
 * PC 00) goes to x87_fin_slow, which reads c->cw (equal to cw). H54. */
static inline double x87_finw(CPU *c, uint16_t cw, double r, double x, double y)
{
    if ((cw & 0xf00u) == 0) {                                            /* PC 00, RC nearest */
        uint64_t u;
        memcpy(&u, &r, 8);
        if (__builtin_expect(((u >> 52) & 0x7ffu) - 1u < 0x7feu, 1)) {  /* normal: as x87_round */
            u += 0x0FFFFFFFull + ((u >> 29) & 1);
            u &= ~0x1FFFFFFFull;
            memcpy(&r, &u, 8);
            return r;
        }
    } else if ((cw & 0x300u) != 0 && r == r) {                          /* PC 01, 10, 11, not NaN: unchanged */
        return r;
    }
    return x87_fin_slow(c, r, x, y);
}

static inline double x87_fin(CPU *c, double r, double x, double y) { return x87_finw(c, c->cw, r, x, y); }

/* The arithmetic ops. The ...w forms take the control word (lifted code passes xcw); the others read c->cw. */
static inline double x87_addw(CPU *c, uint16_t cw, double x, double y) { return x87_finw(c, cw, x + y, x, y); }
static inline double x87_subw(CPU *c, uint16_t cw, double x, double y) { return x87_finw(c, cw, x - y, x, y); }
static inline double x87_subrw(CPU *c, uint16_t cw, double x, double y) { return x87_finw(c, cw, y - x, x, y); }
static inline double x87_mulw(CPU *c, uint16_t cw, double x, double y) { return x87_finw(c, cw, x * y, x, y); }
static inline double x87_add(CPU *c, double x, double y) { return x87_addw(c, c->cw, x, y); }
static inline double x87_sub(CPU *c, double x, double y) { return x87_subw(c, c->cw, x, y); }
static inline double x87_subr(CPU *c, double x, double y) { return x87_subrw(c, c->cw, x, y); }
static inline double x87_mul(CPU *c, double x, double y) { return x87_mulw(c, c->cw, x, y); }
/* The sticky flags of a divide of dividend n by divisor d. This matches the reference emulator (Unicorn), which sets
 * ZE whenever the divisor is zero, whatever the dividend (0/0 and NaN/0 included), and sets nothing for inf/inf. Real
 * x87 hardware sets IE for 0/0 and inf/inf and no ZE for NaN/0; the emulator is the oracle the diff runs check against,
 * so this follows it (see lift/test_ops_x87.py test_divide_flags_zero_divisor_and_invalid). */
static inline void x87_div_flags(CPU *c, double n, double d)
{
    (void)n;
    if (d == 0.0)
        c->sw |= X87_SW_ZE;
}
static inline double x87_divw(CPU *c, uint16_t cw, double x, double y)
{
    x87_div_flags(c, x, y);
    return x87_finw(c, cw, x / y, x, y);
}
static inline double x87_divrw(CPU *c, uint16_t cw, double x, double y)
{
    x87_div_flags(c, y, x);
    return x87_finw(c, cw, y / x, x, y);
}
static inline double x87_sqrtvw(CPU *c, uint16_t cw, double x)
{
    x87_sqrt(c, x);
    return x87_finw(c, cw, sqrt(x), x, x);
}
static inline double x87_div(CPU *c, double x, double y) { return x87_divw(c, c->cw, x, y); }
static inline double x87_divr(CPU *c, double x, double y) { return x87_divrw(c, c->cw, x, y); }
static inline double x87_sqrtv(CPU *c, double x) { return x87_sqrtvw(c, c->cw, x); }

/* A constant that is not a double: the nearest double, moved one step if the RC mode asks for
 * the other side. above = the nearest double is above the true value (positive constants). */
static inline double x87_konst(CPU *c, double nearest, int above)
{
    unsigned rc = (c->cw >> 10) & 3u;
    if (above && (rc == 1 || rc == 3))
        return nextafter(nearest, -INFINITY);
    if (!above && rc == 2)
        return nextafter(nearest, INFINITY);
    return nearest;
}

/* fcom family: C3 C2 C0 from the order of a and b. C1 is not written. Any NaN is unordered. */
static inline void x87_compare(CPU *c, double a, double b)
{
    uint16_t cc;
    if (a != a || b != b)
        cc = X87_SW_C3 | X87_SW_C2 | X87_SW_C0;
    else if (a < b)
        cc = X87_SW_C0;
    else if (a == b)
        cc = X87_SW_C3;
    else
        cc = 0;
    c->sw = (uint16_t)((c->sw & ~X87_SW_CMP) | cc);
}

/* fcomi family: ZF PF CF from the order; OF SF AF are cleared as the SDM says (the reference
 * emulator leaves them alone). Unordered sets all three. */
static inline void x87_comi(CPU *c, double a, double b)
{
    c->of = 0;
    c->sf = 0;
    c->af = 0;
    if (a != a || b != b) {
        c->zf = c->pf = c->cf = 1;
    } else if (a < b) {
        c->zf = 0; c->pf = 0; c->cf = 1;
    } else if (a == b) {
        c->zf = 1; c->pf = 0; c->cf = 0;
    } else {
        c->zf = 0; c->pf = 0; c->cf = 0;
    }
}

/* fxam: C3 C2 C0 classify ST(0) (empty 101, NaN 001, normal 010, infinity 011, zero 100); C1 is
 * the sign. A double subnormal is a normal number in the 80-bit register, so it is "normal"
 * here, and there is no denormal class. */
static inline void x87_fxam(CPU *c)
{
    unsigned p = c->top & 7u;
    double v = c->st[p];
    uint64_t b;
    memcpy(&b, &v, 8);
    uint16_t cc, sign = (b >> 63) ? X87_SW_C1 : 0;
    if (c->tag & (1u << p))
        cc = X87_SW_C3 | X87_SW_C0;
    else if (v != v)
        cc = X87_SW_C0;
    else if (isinf(v))
        cc = X87_SW_C2 | X87_SW_C0;
    else if (v == 0.0)
        cc = X87_SW_C3;
    else
        cc = X87_SW_C2;
    c->sw = (uint16_t)((c->sw & ~X87_SW_CC) | cc | sign);
}

/* Transcendentals (fsin, fcos, fptan, fsincos), as the reference emulator (Unicorn 2.1.4, qemu 5)
 * computes them: ST(0) as a host double, the host libm (the same one the emulator links), the result
 * stored as a double. An operand with |x| > 2^63 sets C2 and is left alone: no result, and for fptan
 * and fsincos no push. Probed on the emulator: 2^63 itself is in range, the next double up is not.
 * C0, C1 and C3 are not written here. fptan pushes 1.0; fsincos stores sin in ST(0) and pushes cos,
 * so ST(0) = cos and ST(1) = sin afterwards. Checked bit for bit by lift/test_ops_x87.py.
 *
 * The host rounding mode is round-to-nearest during the libm call, whatever RC says. The emulator
 * never changes the host mode (its RC only applies to its softfloat conversions), so a libm that
 * reads the mode would otherwise give a different last bit under RC down/up/truncate. */
#define X87_TRIG_LIMIT 9223372036854775808.0          /* 2^63 */

typedef double (*x87_fn1)(double);

static inline double x87_libm_near(x87_fn1 f, double x)
{
    int saved = fegetround();
    if (saved != FE_TONEAREST)
        fesetround(FE_TONEAREST);
    /* The compiler may otherwise hoist the libm call above the mode change (tan is readnone), so the
     * operand and the result go through memory around an empty asm: the call is after the change and
     * before the restore. */
    double a = x;
    __asm__ volatile("" : "+m"(a) : : "memory");
    double r = f(a);
    __asm__ volatile("" : "+m"(r) : : "memory");
    if (saved != FE_TONEAREST)
        fesetround(saved);
    return r;
}

static inline int x87_trig_out_of_range(CPU *c, double x)
{
    if (fabs(x) > X87_TRIG_LIMIT) {
        c->sw |= X87_SW_C2;
        return 1;
    }
    c->sw &= (uint16_t)~X87_SW_C2;
    return 0;
}

static inline void x87_fsin(CPU *c)
{
    double x = x87_rd(c, 0);
    if (!x87_trig_out_of_range(c, x))
        x87_wr(c, 0, x87_libm_near(sin, x));
}

static inline void x87_fcos(CPU *c)
{
    double x = x87_rd(c, 0);
    if (!x87_trig_out_of_range(c, x))
        x87_wr(c, 0, x87_libm_near(cos, x));
}

static inline void x87_fptan(CPU *c)
{
    double x = x87_rd(c, 0);
    if (!x87_trig_out_of_range(c, x)) {
        x87_wr(c, 0, x87_libm_near(tan, x));
        x87_push(c, 1.0);
    }
}

static inline void x87_fsincos(CPU *c)
{
    double x = x87_rd(c, 0);
    if (!x87_trig_out_of_range(c, x)) {
        double s = x87_libm_near(sin, x);
        double co = x87_libm_near(cos, x);
        x87_wr(c, 0, s);
        x87_push(c, co);
    }
}

/* fpatan, as qemu 5's helper_fpatan: ST(1) = atan2(ST(1), ST(0)) as host doubles through the host
 * libm (under round-to-nearest, as above), then pop. No range check and no condition codes written.
 * Checked bit for bit by lift/test_ops_x87.py. */
static inline void x87_fpatan(CPU *c)
{
    double y = x87_rd(c, 1), x = x87_rd(c, 0);
    int saved = fegetround();
    if (saved != FE_TONEAREST)
        fesetround(FE_TONEAREST);
    __asm__ volatile("" : "+m"(y), "+m"(x) : : "memory");
    double r = atan2(y, x);
    __asm__ volatile("" : "+m"(r) : : "memory");
    if (saved != FE_TONEAREST)
        fesetround(saved);
    x87_wr(c, 1, r);
    x87_pop(c);
}

/* fyl2x, as qemu 5's helper_fyl2x: for ST(0) > 0, ST(1) = ST(1) * (log(ST(0)) / log(2.0)) as host doubles (libm
 * under round-to-nearest, as above), then pop; otherwise (zero, negative, NaN) C0 C1 C3 are cleared, C2 set and
 * nothing is popped. Checked bit for bit by lift/test_ops_x87.py. */
static inline void x87_fyl2x(CPU *c)
{
    double x = x87_rd(c, 0);
    if (!(x > 0.0)) {
        c->sw = (uint16_t)((c->sw & ~0x4700) | X87_SW_C2);
        return;
    }
    double y = x87_rd(c, 1);
    int saved = fegetround();
    if (saved != FE_TONEAREST)
        fesetround(FE_TONEAREST);
    __asm__ volatile("" : "+m"(x), "+m"(y) : : "memory");
    double r = log(x) / log(2.0);
    r *= y;
    __asm__ volatile("" : "+m"(r) : : "memory");
    if (saved != FE_TONEAREST)
        fesetround(saved);
    x87_wr(c, 1, r);
    x87_pop(c);
}

/* frndint, as qemu 5's helper_frndint (softfloat round-to-int under RC; precision control does not apply). A zero
 * result keeps the operand's sign; infinities, NaNs and |x| >= 2^52 are already integers. */
static inline void x87_frndint(CPU *c)
{
    double x = x87_rd(c, 0);
    if (fabs(x) < 4503599627370496.0)
        x87_wr(c, 0, copysign(x87_rint(x, (c->cw >> 10) & 3u), x));
}

/* fscale, as the reference emulator does it: a NaN in ST(1) is copied to ST(0) (probed); otherwise n = ST(1)
 * converted to int32 toward zero (softfloat: out of range gives INT32_MIN for a negative operand, INT32_MAX
 * otherwise), ST(0) = ST(0) * 2^n, rounded to the precision control. Past double range the register holds what an
 * fst would store (infinity or DBL_MAX by RC), not the extended value. */
static inline void x87_fscale(CPU *c)
{
    double x = x87_rd(c, 0), s = x87_rd(c, 1);
    int n;
    if (s != s) {
        x87_wr(c, 0, s);
        return;
    }
    if (s >= 2147483648.0)
        n = 2147483647;
    else if (s <= -2147483649.0)
        n = -2147483647 - 1;
    else
        n = (int)s;
    double r;
    if (isfinite(x) && x != 0.0 && (long long)ilogb(x) + n > 1023) {
        /* Past double range (ldexp would follow the host mode): the extended result rounds to infinity only when RC
         * rounds away from zero for its sign; otherwise it is the largest finite value, which stores as DBL_MAX
         * whatever the precision control. */
        unsigned rc = (c->cw >> 10) & 3u;
        int up = rc == 0 || (rc == 2 && x > 0) || (rc == 1 && x < 0);
        r = copysign(up ? INFINITY : 1.7976931348623157e308, x);
    } else {
        r = x87_round(c, ldexp(x, n));
    }
    x87_wr(c, 0, r);
}

/* f2xm1, as qemu 5's helper_f2xm1: ST(0) = pow(2.0, ST(0)) - 1.0 in host doubles (libm under round-to-nearest, as
 * above). No range check and no condition codes. */
static inline void x87_f2xm1(CPU *c)
{
    double x = x87_rd(c, 0);
    int saved = fegetround();
    if (saved != FE_TONEAREST)
        fesetround(FE_TONEAREST);
    __asm__ volatile("" : "+m"(x) : : "memory");
    double r = pow(2.0, x) - 1.0;
    __asm__ volatile("" : "+m"(r) : : "memory");
    if (saved != FE_TONEAREST)
        fesetround(saved);
    x87_wr(c, 0, r);
}

/* The 80-bit biased exponent of a register value (qemu's EXPD): 0 for zero, 0x7fff for infinities and NaNs. A
 * subnormal double is a normal extended value. */
static inline int x87_expd(double v)
{
    if (v == 0.0)
        return 0;
    if (!isfinite(v))
        return 0x7fff;
    int e;
    frexp(v, &e);
    return e - 1 + 16383;
}

/* fprem (round toward zero, partial: N = 32 + expdif % 32) and fprem1 (round to nearest, N = 50), as qemu 5's
 * helper_fprem/helper_fprem1, which compute in host doubles: the host libm and the host's own arithmetic under
 * round-to-nearest (the emulator never changes the host mode). Invalid operands (ST(0) infinite or NaN, ST(1) NaN
 * or zero) give the default NaN of the host (0.0 / 0.0: positive on arm64) and clear C0..C3. With expdif < 0, ST(0)
 * is kept and C0..C3 cleared. Complete reduction: C2 clear, (C0, C3, C1) = the low three quotient bits. Partial:
 * C2 set, the other bits kept. The statements follow qemu's, so the compiler contracts the same expressions. */
static inline void x87_fprem_any(CPU *c, int ieee)
{
    double st0 = x87_rd(c, 0), st1 = x87_rd(c, 1);
    if (isinf(st0) || isnan(st0) || isnan(st1) || (st1 == 0.0)) {
        x87_wr(c, 0, 0.0 / 0.0);
        c->sw &= (uint16_t)~0x4700u;
        return;
    }
    int expdif = x87_expd(st0) - x87_expd(st1);
    if (expdif < 0) {
        c->sw &= (uint16_t)~0x4700u;
        return;
    }
    int saved = fegetround();
    if (saved != FE_TONEAREST)
        fesetround(FE_TONEAREST);
    double fpsrcop = st0, fptemp = st1, dblq;
    __asm__ volatile("" : "+m"(fpsrcop), "+m"(fptemp) : : "memory");
    if (expdif < 53) {
        dblq = fpsrcop / fptemp;
        if (ieee)
            dblq = rint(dblq);
        else
            dblq = (dblq < 0.0) ? ceil(dblq) : floor(dblq);
        st0 = fpsrcop - fptemp * dblq;
        long long q = dblq < 0.0 ? (long long)(-dblq) : (long long)dblq;
        c->sw &= (uint16_t)~0x4700u;
        c->sw |= (uint16_t)((q & 0x4) << (8 - 2));
        c->sw |= (uint16_t)((q & 0x2) << (14 - 1));
        c->sw |= (uint16_t)((q & 0x1) << (9 - 0));
    } else {
        c->sw |= 0x400u;
        int N = ieee ? 50 : 32 + (expdif % 32);
        fptemp = pow(2.0, (double)(expdif - N));
        fpsrcop = (st0 / st1) / fptemp;
        fpsrcop = (fpsrcop < 0.0) ? -(floor(fabs(fpsrcop))) : floor(fpsrcop);
        st0 -= (st1 * fpsrcop * fptemp);
    }
    __asm__ volatile("" : "+m"(st0) : : "memory");
    if (saved != FE_TONEAREST)
        fesetround(saved);
    x87_wr(c, 0, st0);
}

static inline void x87_fprem(CPU *c) { x87_fprem_any(c, 0); }
static inline void x87_fprem1(CPU *c) { x87_fprem_any(c, 1); }

/* m32 and m64 (float and double) */
static inline double x87_ld_f32(CPU *c, uint32_t a)
{
    uint32_t b = rd32(c, a);
    float f;
    memcpy(&f, &b, 4);
    return (double)f;
}

static inline double x87_ld_f64(CPU *c, uint32_t a)
{
    uint64_t b = rd64(c, a);
    double d;
    memcpy(&d, &b, 8);
    return d;
}

static inline void x87_st_f32(CPU *c, uint32_t a, double v)
{
    float f = (float)v;
    uint32_t b;
    memcpy(&b, &f, 4);
    wr32(c, a, b);
}

static inline void x87_st_f64(CPU *c, uint32_t a, double v)
{
    uint64_t b;
    memcpy(&b, &v, 8);
    wr64(c, a, b);
}

/* m80 (extended precision). Double -> m80 is exact. m80 -> double rounds to nearest-even, with
 * gradual underflow and overflow to infinity. */
static inline void x87_double_to_f80(double v, uint64_t *sig, uint16_t *se)
{
    uint64_t b;
    memcpy(&b, &v, 8);
    uint16_t sign = (uint16_t)((b >> 63) << 15);
    unsigned e = (unsigned)((b >> 52) & 0x7ffu);
    uint64_t m = b & 0xfffffffffffffull;
    if (e == 0x7ffu) {                          /* infinity or NaN; the NaN payload is kept */
        *se = sign | 0x7fffu;
        *sig = m ? ((1ull << 63) | (m << 11)) : (1ull << 63);
    } else if (e == 0) {
        if (m == 0) {
            *se = sign;
            *sig = 0;
        } else {                                /* subnormal double: normal in extended */
            int k = 63 - __builtin_clzll(m);
            *sig = m << (63 - k);
            *se = (uint16_t)(sign | (uint16_t)(k - 1074 + 16383));
        }
    } else {
        *sig = (1ull << 63) | (m << 11);
        *se = (uint16_t)(sign | (uint16_t)(e - 1023 + 16383));
    }
}

static inline double x87_f80_to_double(uint16_t se, uint64_t sig)
{
    uint64_t sign = (uint64_t)(se >> 15) << 63;
    int e = se & 0x7fff;
    uint64_t bits;
    if (e == 0x7fff) {
        if ((sig << 1) == 0)
            bits = sign | 0x7ff0000000000000ull;
        else                                    /* quiet bit (bit 62 of sig) becomes bit 51 */
            bits = sign | 0x7ff0000000000000ull | (1ull << 51) | ((sig >> 11) & ((1ull << 51) - 1));
    } else {
        if (sig == 0) {
            bits = sign;
        } else {
            int E = (e == 0 ? 1 : e) - 16383;  /* value = sig * 2^(E - 63) */
            int lz = __builtin_clzll(sig);
            sig <<= lz;                         /* normalise: bit 63 set (unnormals too) */
            E -= lz;
            if (E > 1023) {
                bits = sign | 0x7ff0000000000000ull;
            } else if (E >= -1022) {
                uint64_t mant = sig >> 11;
                uint64_t rem = sig & 0x7ffu;
                if (rem > 0x400u || (rem == 0x400u && (mant & 1)))
                    mant++;
                if (mant >> 53) {               /* rounding carried into a new bit */
                    mant >>= 1;
                    E++;
                }
                if (E > 1023)
                    bits = sign | 0x7ff0000000000000ull;
                else
                    bits = sign | ((uint64_t)(E + 1023) << 52) | (mant & 0xfffffffffffffull);
            } else {
                /* subnormal result: the unit is 2^-1074, so shift right by s = -(E + 1011) */
                int s = -(E + 1011);
                uint64_t q;
                if (s >= 65) {
                    q = 0;
                } else if (s == 64) {
                    q = sig > (1ull << 63) ? 1 : 0;
                } else {
                    uint64_t half = 1ull << (s - 1);
                    uint64_t rem = sig & ((1ull << s) - 1);
                    q = sig >> s;
                    if (rem > half || (rem == half && (q & 1)))
                        q++;
                }
                bits = sign | q;                /* q may be 2^52: the smallest normal, same encoding */
            }
        }
    }
    double d;
    memcpy(&d, &bits, 8);
    return d;
}

static inline double x87_ld_f80(CPU *c, uint32_t a)
{
    return x87_f80_to_double(rd16(c, a + 8), rd64(c, a));
}

static inline void x87_st_f80(CPU *c, uint32_t a, double v)
{
    uint64_t sig;
    uint16_t se;
    x87_double_to_f80(v, &sig, &se);
    wr64(c, a, sig);
    wr16(c, a + 8, se);
}

/* fnstenv / fldenv and fnsave / frstor with a 32-bit operand size, as qemu 5's helper_fstenv/fldenv/fsave/frstor
 * (fnstenv does not mask exceptions there): the 28-byte environment (each
 * field a dword: cw, sw with TOP, the tag word, then the instruction and operand pointers), then ST(0)..
 * ST(7) as 80-bit values; fnsave ends with fninit. Tag word: 11 empty, 01 zero, 10 infinity or NaN (a double is never
 * an extended denormal or unnormal), 00 valid. fldenv/frstor mark a register empty only for tag 11; frstor loads all eight
 * values whatever their tags. The pointers (bytes 12-27) are written as zero: lifted code does not track the last x87
 * instruction and operand, which the reference stores there. frstor ignores them, and the only user (MSVCRT pow's
 * fnsave/frstor pair around its helper call) reads nothing else from the area. */
static inline void x87_fnstenv(CPU *c, uint32_t a)
{
    uint32_t tw = 0;
    for (int p = 7; p >= 0; p--) {
        tw <<= 2;
        if (c->tag & (1u << p)) {
            tw |= 3;
        } else {
            double v = c->st[p];
            if (v == 0.0)
                tw |= 1;
            else if (!isfinite(v))
                tw |= 2;
        }
    }
    wr32(c, a, c->cw);
    wr32(c, a + 4, x87_status(c));
    wr32(c, a + 8, tw);
    wr32(c, a + 12, 0);
    wr32(c, a + 16, 0);
    wr32(c, a + 20, 0);
    wr32(c, a + 24, 0);
}

static inline void x87_fldenv(CPU *c, uint32_t a)
{
    uint16_t sw = rd16(c, a + 4), tw = rd16(c, a + 8);
    x87_ldcw(c, rd16(c, a));
    c->top = (sw >> 11) & 7u;
    c->sw = (uint16_t)(sw & ~0x3800u);
    c->tag = 0;
    for (unsigned p = 0; p < 8; p++, tw >>= 2)
        if ((tw & 3) == 3)
            c->tag |= 1u << p;
}

static inline void x87_fnsave(CPU *c, uint32_t a)
{
    x87_fnstenv(c, a);
    for (unsigned i = 0; i < 8; i++)
        x87_st_f80(c, a + 28 + 10 * i, x87_rd(c, i));
    x87_init(c);
}

static inline void x87_frstor(CPU *c, uint32_t a)
{
    x87_fldenv(c, a);
    for (unsigned i = 0; i < 8; i++)
        x87_wr(c, i, x87_ld_f80(c, a + 28 + 10 * i));
}

/* Integers. size is the memory width in bytes: 2, 4 or 8. */
static inline double x87_ild(CPU *c, uint32_t a, unsigned size)
{
    if (size == 2)
        return (double)(int16_t)rd16(c, a);
    if (size == 4)
        return (double)(int32_t)rd32(c, a);
    return (double)(int64_t)rd64(c, a);
}

/* fist/fistp: the stored bit pattern (low `size` bytes). RC rounding; out of range or NaN gives
 * the integer indefinite (0x8000, 0x80000000, 0x8000000000000000). The status word is not changed: the reference
 * emulator (Unicorn 2.1.4, qemu 5) raises no exception bit for these stores (probed for fist/fistp m16/m32/m64 at
 * 2^63, 1e30, 3e9, NaN and +-inf; see lift/test_ops_x87.py test_integer_store_flags_match_emulator). */
static inline uint64_t x87_ival(CPU *c, double v, unsigned size)
{
    uint64_t ind = size == 2 ? 0x8000u : size == 4 ? 0x80000000u : 0x8000000000000000ull;
    if (v != v)
        return ind;
    double r = x87_rint(v, (c->cw >> 10) & 3u);
    int ok;
    if (size == 2)
        ok = r >= -32768.0 && r <= 32767.0;
    else if (size == 4)
        ok = r >= -2147483648.0 && r <= 2147483647.0;
    else
        ok = r >= -9223372036854775808.0 && r < 9223372036854775808.0;
    if (!ok)
        return ind;
    return (uint64_t)(int64_t)r;
}

static inline void x87_ist(CPU *c, uint32_t a, double v, unsigned size)
{
    uint64_t b = x87_ival(c, v, size);
    if (size == 2)
        wr16(c, a, (uint16_t)b);
    else if (size == 4)
        wr32(c, a, (uint32_t)b);
    else
        wr64(c, a, b);
}

#endif
