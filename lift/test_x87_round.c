/* Bit-exact check of x87_round (lift/runtime/x87.h, precision control 00) against the implementation it
 * replaced, and a timing of both. Built and run by lift/test_x87_round.py.
 *
 *   test_x87_round         compare on random and edge-case doubles, for each RC mode; exit 1 on any mismatch
 *   test_x87_round bench   time old and new x87_round over 100M values per RC mode
 *
 * The reference (ref_round) is the previous x87_round, copied verbatim: frexp/ldexp/x87_rint. */
#include <fenv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "x87.h"

/* The previous x87_round. */
static double ref_round(CPU *c, double v)
{
    if (((c->cw >> 8) & 3u) != 0 || v != v || v == 0.0 || isinf(v))
        return v;
    int e;
    frexp(v, &e);
    double s = ldexp(v, 24 - e);               /* 24 integer bits */
    return ldexp(x87_rint(s, (c->cw >> 10) & 3u), e - 24);
}

static uint64_t rng_state = 0x243F6A8885A308D3ull;

/* splitmix64 */
static uint64_t rnd(void)
{
    uint64_t z = (rng_state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static double bits2d(uint64_t b)
{
    double d;
    memcpy(&d, &b, 8);
    return d;
}

static uint64_t d2bits(double d)
{
    uint64_t b;
    memcpy(&b, &d, 8);
    return b;
}

#define SIGN_EXP_MASK 0x800FFFFFFFFFFFFFull   /* sign and mantissa; the exponent field is set on top */
#define LOW29 0x1FFFFFFFull

/* Random normal double over the whole range: random sign and mantissa, exponent uniform in 1..2046. */
static uint64_t gen_any(void)
{
    uint64_t ex = 1 + rnd() % 2046;
    return (rnd() & SIGN_EXP_MASK) | (ex << 52);
}

/* Near 1.0: 1.0 plus a small signed offset in units of 2^-52, so both neighbours (exponent 1022 and
 * 1023) and the low bits all vary. Random sign. */
static uint64_t gen_near1(void)
{
    int64_t delta = (int64_t)(rnd() % (1u << 21)) - (1 << 20);
    uint64_t b = (uint64_t)(0x3FF0000000000000ll + delta);
    return b | ((rnd() & 1) << 63);
}

/* Ties and near-ties: the low 29 bits (the part rounded off) are chosen from the edge patterns (exact
 * half with either parity of bit 29, one below and one above half, 0x0FFFFFFF, 0x1FFFFFFF, 0), or a
 * random value near half. The kept 23 bits are random, all ones (carry into the exponent), zero, or
 * random; the exponent is random, with extra weight on the ends of the range. */
static uint64_t gen_tie(void)
{
    static const uint64_t low_pat[] = {
        0x10000000ull, 0x0FFFFFFFull, 0x1FFFFFFFull, 0x00000000ull,
        0x10000001ull, 0x0FFFFFFEull, 0x1FFFFFFEull, 0x00000001ull,
    };
    static const uint64_t top_pat[] = { 0x7FFFFFull, 0x000000ull, 0x7FFFFEull, 0x000001ull };
    uint64_t low = (rnd() & 1) ? low_pat[rnd() % (sizeof low_pat / sizeof low_pat[0])]
                               : ((0x10000000ull + (rnd() % 7) - 3) & LOW29);
    uint64_t top = (rnd() % 4 == 0) ? top_pat[rnd() % 4] : (rnd() & 0x7FFFFFull);
    uint64_t ex;
    switch (rnd() % 8) {
    case 0: ex = 1; break;
    case 1: ex = 2; break;
    case 2: ex = 2045; break;
    case 3: ex = 2046; break;
    default: ex = 1 + rnd() % 2046; break;
    }
    return (rnd() & 0x8000000000000000ull) | (ex << 52) | (top << 29) | low;
}

typedef struct {
    uint64_t n, bad;
} tally;

static void test_value(CPU *c, uint64_t bits, tally *t)
{
    double v = bits2d(bits);
    uint64_t a = d2bits(ref_round(c, v));
    uint64_t b = d2bits(x87_round(c, v));
    t->n++;
    if (a != b) {
        if (t->bad < 10)
            fprintf(stderr, "mismatch: rc=%u in=%016llx ref=%016llx new=%016llx\n",
                    (c->cw >> 10) & 3u, (unsigned long long)bits, (unsigned long long)a, (unsigned long long)b);
        t->bad++;
    }
}

/* Edge values, each with both signs and every RC mode; deterministic. */
static void test_specials(CPU *c, tally *t)
{
    static const uint64_t exps[] = { 0, 1, 2, 1022, 1023, 1024, 2045, 2046, 2047 };
    static const uint64_t tops[] = { 0x000000ull, 0x000001ull, 0x7FFFFEull, 0x7FFFFFull };
    static const uint64_t lows[] = {
        0x00000000ull, 0x10000000ull, 0x0FFFFFFFull, 0x1FFFFFFFull, 0x10000001ull, 0x0FFFFFFEull,
        0x00000001ull, 0x1FFFFFFEull, 0x18000000ull, 0x08000000ull,
    };
    static const uint64_t fixed[] = {
        0x7FEFFFFFFFFFFFFFull,      /* largest finite double */
        0x0010000000000000ull,      /* smallest normal */
        0x0010000000000001ull,
        0x7FEFFFFFF0000000ull,      /* rounds up to 2^1024 */
        0x7FEFFFFFE0000000ull,
        0x7FEFFFFFEFFFFFFFull,
        0x7FEFFFFFF8000000ull,
        0x3FF0000000000000ull,      /* 1.0 */
        0x3FEFFFFFFFFFFFFFull,      /* 1.0 - 2^-53 */
        0x4000000000000000ull,      /* 2.0 */
        0x0000000000000001ull,      /* smallest subnormal: old path, must be unchanged */
        0x000FFFFFFFFFFFFFull,      /* largest subnormal */
        0x0000000000000000ull,      /* +0 */
        0x7FF0000000000000ull,      /* +inf */
        0x7FF8000000000000ull,      /* qNaN */
    };
    for (unsigned s = 0; s < 2; s++) {
        uint64_t sg = (uint64_t)s << 63;
        for (size_t i = 0; i < sizeof fixed / sizeof fixed[0]; i++)
            test_value(c, sg | fixed[i], t);
        for (size_t e = 0; e < sizeof exps / sizeof exps[0]; e++)
            for (size_t m = 0; m < sizeof tops / sizeof tops[0]; m++)
                for (size_t l = 0; l < sizeof lows / sizeof lows[0]; l++)
                    test_value(c, sg | (exps[e] << 52) | (tops[m] << 29) | (lows[l] & LOW29), t);
        for (size_t e = 0; e < sizeof exps / sizeof exps[0]; e++) {
            /* all-ones mantissa (carry into the exponent), and all-ones top bits with a half-ulp tail */
            test_value(c, sg | (exps[e] << 52) | 0x000FFFFFFFFFFFFFull, t);
            test_value(c, sg | (exps[e] << 52) | 0x000FFFFFF0000000ull, t);
            test_value(c, sg | (exps[e] << 52) | 0x000FFFFFE8000000ull, t);
        }
    }
}

/* PC other than 00 must return the value unchanged, for any RC. */
static void test_other_pc(tally *t)
{
    CPU c;
    for (unsigned pc = 1; pc < 4; pc++)
        for (unsigned rc = 0; rc < 4; rc++) {
            memset(&c, 0, sizeof c);
            c.cw = (uint16_t)((pc << 8) | (rc << 10));
            for (int i = 0; i < 100000; i++) {
                uint64_t b = gen_any();
                double v = bits2d(b);
                t->n++;
                if (d2bits(x87_round(&c, v)) != b) {
                    t->bad++;
                }
            }
        }
}

static int run_compare(void)
{
    static const char *set_names[] = { "any", "near1", "tie" };
    const uint64_t n_set[] = { 30000000ull, 20000000ull, 30000000ull };
    uint64_t total_n = 0, total_bad = 0;
    CPU c;
    for (unsigned rc = 0; rc < 4; rc++) {
        memset(&c, 0, sizeof c);
        c.cw = (uint16_t)(rc << 10);           /* PC 00: 24-bit */
        for (int s = 0; s < 3; s++) {
            tally t = { 0, 0 };
            for (uint64_t i = 0; i < n_set[s]; i++) {
                uint64_t b = s == 0 ? gen_any() : s == 1 ? gen_near1() : gen_tie();
                test_value(&c, b, &t);
            }
            printf("rc=%u set=%-6s n=%llu mismatches=%llu\n", rc, set_names[s],
                   (unsigned long long)t.n, (unsigned long long)t.bad);
            total_n += t.n;
            total_bad += t.bad;
        }
        tally sp = { 0, 0 };
        test_specials(&c, &sp);
        printf("rc=%u set=%-6s n=%llu mismatches=%llu\n", rc, "edge",
               (unsigned long long)sp.n, (unsigned long long)sp.bad);
        total_n += sp.n;
        total_bad += sp.bad;
    }
    /* The host mode. fldcw sets the host mode to the RC of the control word (x87_set_rounding), so
     * the reference is run with host mode = RC; that is the state the lifted code is in. */
    static const int host[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    for (unsigned rc = 0; rc < 4; rc++) {
        fesetround(host[rc]);
        memset(&c, 0, sizeof c);
        c.cw = (uint16_t)(rc << 10);
        tally t = { 0, 0 };
        for (uint64_t i = 0; i < 2000000; i++)
            test_value(&c, gen_tie(), &t);
        for (uint64_t i = 0; i < 1000000; i++)
            test_value(&c, gen_any(), &t);
        printf("host=RC rc=%u set=host n=%llu mismatches=%llu\n", rc,
               (unsigned long long)t.n, (unsigned long long)t.bad);
        total_n += t.n;
        total_bad += t.bad;
    }
    /* The new x87_round must not depend on the host mode: its result under each host mode equals the
     * result under nearest. (The reference does depend on it, at overflow only; see the report.) */
    {
        uint64_t hn = 0, hbad = 0;
        for (unsigned rc = 0; rc < 4; rc++) {
            memset(&c, 0, sizeof c);
            c.cw = (uint16_t)(rc << 10);
            for (uint64_t i = 0; i < 1000000; i++) {
                uint64_t b = (i & 1) ? gen_tie() : gen_any();
                double v = bits2d(b);
                fesetround(FE_TONEAREST);
                uint64_t want = d2bits(x87_round(&c, v));
                for (unsigned h = 1; h < 4; h++) {
                    fesetround(host[h]);
                    hn++;
                    if (d2bits(x87_round(&c, v)) != want)
                        hbad++;
                }
            }
        }
        printf("host-independence of new x87_round n=%llu mismatches=%llu\n", (unsigned long long)hn,
               (unsigned long long)hbad);
        total_n += hn;
        total_bad += hbad;
    }
    fesetround(FE_TONEAREST);
    tally op = { 0, 0 };
    test_other_pc(&op);
    printf("pc!=00 (unchanged) n=%llu mismatches=%llu\n", (unsigned long long)op.n, (unsigned long long)op.bad);
    total_n += op.n;
    total_bad += op.bad;
    /* x87_finw (H54: the NaN choice folded into the rounding, the control word passed in) against the NaN choice
     * followed by x87_round, for every PC and RC, with NaN operands mixed in. */
    {
        uint64_t fn = 0, fbad = 0;
        for (unsigned pc = 0; pc < 4; pc++)
            for (unsigned rc = 0; rc < 4; rc++) {
                fesetround(host[rc]);
                memset(&c, 0, sizeof c);
                c.cw = (uint16_t)((pc << 8) | (rc << 10) | 0x7f);
                for (uint64_t i = 0; i < 1000000; i++) {
                    double r = bits2d((i & 1) ? gen_tie() : gen_any());
                    double x = bits2d(gen_any()), y = bits2d(gen_any());
                    if (i % 7 == 0) r = x87_indef();
                    if (i % 11 == 0) x = bits2d(0x7ff4000000000123ull);
                    if (i % 13 == 0) y = bits2d(0xfff8000000000456ull);
                    double want = r;
                    if (want != want)
                        want = (x != x) ? x : (y != y) ? y : x87_indef();
                    want = x87_round(&c, want);
                    fn++;
                    if (d2bits(x87_finw(&c, c.cw, r, x, y)) != d2bits(want))
                        fbad++;
                }
            }
        fesetround(FE_TONEAREST);
        printf("x87_finw vs NaN choice + x87_round n=%llu mismatches=%llu\n", (unsigned long long)fn,
               (unsigned long long)fbad);
        total_n += fn;
        total_bad += fbad;
    }
    printf("TOTAL n=%llu mismatches=%llu\n", (unsigned long long)total_n, (unsigned long long)total_bad);
    return total_bad == 0 ? 0 : 1;
}

/* ns per call over N values drawn once; the buffer is walked 100 times, so 100M calls per timing. */
#define BENCH_BUF (1u << 20)
#define BENCH_PASSES 100u

static volatile uint64_t sink;

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static double time_old(CPU *c, const double *buf)
{
    uint64_t acc = 0;
    double t0 = now_ns();
    for (unsigned p = 0; p < BENCH_PASSES; p++)
        for (unsigned i = 0; i < BENCH_BUF; i++)
            acc ^= d2bits(ref_round(c, buf[i]));
    double t1 = now_ns();
    sink ^= acc;
    return (t1 - t0) / ((double)BENCH_PASSES * BENCH_BUF);
}

static double time_new(CPU *c, const double *buf)
{
    uint64_t acc = 0;
    double t0 = now_ns();
    for (unsigned p = 0; p < BENCH_PASSES; p++)
        for (unsigned i = 0; i < BENCH_BUF; i++)
            acc ^= d2bits(x87_round(c, buf[i]));
    double t1 = now_ns();
    sink ^= acc;
    return (t1 - t0) / ((double)BENCH_PASSES * BENCH_BUF);
}

static void run_bench(void)
{
    double *buf = malloc(sizeof(double) * BENCH_BUF);
    for (unsigned i = 0; i < BENCH_BUF; i++)
        buf[i] = bits2d((i & 1) ? gen_any() : gen_tie());
    CPU c;
    printf("%u values x %u passes = %llu calls per timing\n", BENCH_BUF, BENCH_PASSES,
           (unsigned long long)BENCH_BUF * BENCH_PASSES);
    for (unsigned rc = 0; rc < 4; rc++) {
        memset(&c, 0, sizeof c);
        c.cw = (uint16_t)(rc << 10);
        /* run each twice and keep the second, to take the warm number */
        time_old(&c, buf);
        time_new(&c, buf);
        double o = time_old(&c, buf), n = time_new(&c, buf);
        printf("rc=%u old %.2f ns/op  new %.2f ns/op  speedup %.1fx\n", rc, o, n, o / n);
    }
    free(buf);
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "bench") == 0) {
        run_bench();
        return 0;
    }
    return run_compare();
}
