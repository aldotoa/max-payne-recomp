/* Native replacements for e2mfc.dll's hot vertex functions (M7: 60 fps at 2560x1600).
 *
 * Each f_XXXXXXXX here replaces the lifted function of that name in the library (lift/build.py links these instead
 * of the generated C; the generated C is still compiled, renamed lifted_XXXXXXXX, as the fallback). The code is the
 * guest function transcribed by hand with registers and the x87 stack in C locals:
 *   - x87 arithmetic gives the lifter's results (fin below: x87_finw's rounding, NaN choice and sticky flags; the
 *     operand order of each instruction is kept), compares go through x87_compare.
 *   - Every guest memory write the function makes is made, in the same order per iteration: globals, the arrays it
 *     fills, its stack frame (locals, saved registers, the return slots of the calls it makes), so memory after the
 *     call is the same as after the lifted function.
 *   - On return: esp, ebx/esi/edi/ebp and eax/ecx/edx hold what the guest code leaves; the x87 TOP is unchanged, the
 *     slots the function pushed are tagged empty and the C bits are those of the last compare. Not kept: the stale
 *     values the guest leaves in popped x87 registers (nothing reads an empty register).
 *   - Calls to trivial getters (0x10125380, 0x10125470) are inlined. Other calls are made as the lifted code makes
 *     them (CALL: registers to the CPU struct, the return address pushed, the frame-discarded check, registers and
 *     the control word read back).
 * The first call's static initialisation (a guard byte not yet set) goes to the lifted function.
 * The check is the MPD3 capture of the deterministic H53 workload (mphost --sim-fps 60), byte-identical to H77's. */
#include "lift.h"

void lifted_1013bf40(CPU *c);
void lifted_10136f20(CPU *c);
void lifted_10137a40(CPU *c);
void f_1011c900(CPU *c);
void f_10125bf0(CPU *c);
void f_1012e7c0(CPU *c);
void f_10131b30(CPU *c);

#define RD(a) rd32(c, (uint32_t)(a))
#define WR(a, v) wr32(c, (uint32_t)(a), (uint32_t)(v))
#define LF(a) x87_ld_f32(c, (uint32_t)(a))
#define SF(a, v) x87_st_f32(c, (uint32_t)(a), (v))

/* x87_finw, faster at PC 00 / RC nearest (the vertex code's setting; the host rounding mode then is nearest too). The
 * operands have 24-bit significands, so the double result r is exact or rounded innocuously (53 >= 2 * 24 + 2 for
 * + - * / sqrt), and while |r| is in float's normal range rounding it to float is the 24-bit rounding x87_finw does
 * with integer arithmetic, at a shorter latency. Zero needs no rounding. The rest (NaN, inf, values outside float's
 * range) goes to x87_fin_slow as in x87_finw, and any other control word to x87_finw itself. */
static inline double fin(CPU *c, uint16_t cw, double r, double x, double y)
{
    if (__builtin_expect(cw & 0xf00u, 0))
        return x87_finw(c, cw, r, x, y);
    double a = fabs(r);
    if (__builtin_expect(a >= 0x1p-126 && a <= 0x1.fffffep127, 1))
        return (double)(float)r;
    if (r == 0)
        return r;
    return x87_fin_slow(c, r, x, y);
}
static inline double addw(CPU *c, uint16_t cw, double x, double y) { return fin(c, cw, x + y, x, y); }
static inline double subw(CPU *c, uint16_t cw, double x, double y) { return fin(c, cw, x - y, x, y); }
static inline double subrw(CPU *c, uint16_t cw, double x, double y) { return fin(c, cw, y - x, x, y); }
static inline double mulw(CPU *c, uint16_t cw, double x, double y) { return fin(c, cw, x * y, x, y); }
static inline double divw(CPU *c, uint16_t cw, double x, double y) { x87_div_flags(c, x, y); return fin(c, cw, x / y, x, y); }
static inline double divrw(CPU *c, uint16_t cw, double x, double y) { x87_div_flags(c, y, x); return fin(c, cw, y / x, x, y); }
static inline double sqrtw(CPU *c, uint16_t cw, double x) { x87_sqrt(c, x); return fin(c, cw, sqrt(x), x, x); }
#define ADD(x, y) addw(c, cw, (x), (y))
#define SUB(x, y) subw(c, cw, (x), (y))
#define SUBR(x, y) subrw(c, cw, (x), (y))
#define MUL(x, y) mulw(c, cw, (x), (y))
#define DIV(x, y) divw(c, cw, (x), (y))
#define DIVR(x, y) divrw(c, cw, (x), (y))
#define SQRT(x) sqrtw(c, cw, (x))
/* fcom/fcomp then fnstsw ax: the C bits in c->sw, ax = status word with TOP = top */
#define FCOM(a, b, top) (x87_compare(c, (a), (b)), eax = (eax & 0xffff0000u) | x87_status_top(c, (top)))
#define C0 0x0100u
#define C3 0x4000u

/* float store and reload: the value a later fld of the stored float gives */
static inline double f32(double v) { return (double)(float)v; }
static inline uint32_t f32bits(double v) { float f = (float)v; uint32_t b; memcpy(&b, &f, 4); return b; }

/* tag the n slots below TOP empty (the guest pushed n values and popped them) */
static inline void x87_popped(CPU *c, uint32_t top, unsigned n)
{
    for (unsigned i = 1; i <= n; i++)
        c->tag |= 1u << ((top - i) & 7u);
}

/* 0x1013af30 (stdcall, 6 args): the plane test. For vertices [first, first + count) of the transformed-position
 * array (*0x10166ab8, 16-byte stride): dot(plane, v) + d > 0 sets `bit` in the vertex's word of *0x10166ad0.
 * args: +8 first, +0xc count, +0x10 plane (4 floats), +0x14 d (float), +0x18 bit index. */
void f_1013af30(CPU *c)
{
    const uint16_t cw = c->cw;
    const uint32_t sp = c->r[ESP];
    uint32_t eax = RD(sp + 0xc), ecx = RD(sp + 0x18), edx = RD(sp + 8);
    WR(sp - 4, c->r[EBX]);
    WR(sp - 8, c->r[EBP]);
    const uint32_t ebx = 1u << (ecx & 31u);
    const uint32_t end = edx + eax;
    ecx = edx;
    if ((int32_t)edx < (int32_t)end) {
        WR(sp - 12, c->r[ESI]);
        uint32_t esi = RD(0x10166ab8u);
        WR(sp - 16, c->r[EDI]);
        const uint32_t edi = RD(sp + 0x10);
        const uint32_t top = c->top;
        edx <<= 4;
        double s0, s1;
        do {
            s0 = MUL(LF(edx + esi + 8), LF(edi + 8));
            s1 = MUL(LF(edx + esi + 4), LF(edi + 4));
            s0 = ADD(s0, s1);
            s1 = MUL(LF(edx + esi + 0xc), LF(edi + 0xc));
            s0 = ADD(s0, s1);
            s1 = MUL(LF(edi), LF(edx + esi));
            s0 = ADD(s0, s1);
            s0 = ADD(s0, LF(sp + 0x14));
            FCOM(s0, 0.0, top);
            if (!(c->sw & (C0 | C3))) {
                eax = RD(0x10166ad0u);
                WR(eax + ecx * 4, RD(eax + ecx * 4) | ebx);
                esi = RD(0x10166ab8u);
            }
            ecx++;
            edx += 0x10;
        } while ((int32_t)ecx < (int32_t)end);
        x87_popped(c, top, 2);
        (void)s1;
    }
    c->r[EAX] = eax;
    c->r[ECX] = ecx;
    c->r[EDX] = edx;
    c->r[ESP] = sp + 0x1c;
}

/* 0x1013bf40 (thiscall, 4 args): one point light's diffuse and specular terms added into the vertex colour
 * accumulators, for vertices [first, first + count).
 * this+8: the material (+0x84 shininess, +0x31 specular on); args: +8 the eye (+8: position), +0xc the light (+4
 * diffuse colour, +0x10 specular colour, +0x1c position, +0x34/+0x38/+0x3c attenuation, +0x40 range), +0x10 first,
 * +0x14 count. Arrays: positions *0x10166ab8 (16 bytes), normals *0x10166abc (12), diffuse *0x10166ac8 (12),
 * specular *0x10166acc (12). Static vectors: A 0x101667a0, B 0x101667b0, C 0x101667c0 (guard byte 0x101667cc). */
void f_1013bf40(CPU *c)
{
    const uint16_t cw = c->cw;
    if ((rd8(c, 0x101667ccu) & 7u) != 7u) { lifted_1013bf40(c); return; }
    const uint32_t sp = c->r[ESP];
    const uint32_t ebp = sp - 4;
    const uint32_t top = c->top;
    const uint32_t self = c->r[ECX];
    uint32_t eax, ecx, edx = c->r[EDX];
    WR(ebp, c->r[EBP]);
    WR(ebp - 0x48, c->r[EBX]);
    WR(ebp - 0x4c, c->r[ESI]);
    WR(ebp - 0x24, self);
    ecx = RD(self + 8);
    WR(ebp - 0x50, 0x1013c018u);                        /* call 0x10125470: fld [ecx + 0x84] */
    SF(ebp - 8, LF(ecx + 0x84));
    const uint32_t L = RD(ebp + 0xc);
    double s0 = LF(L + 0x40);
    eax = RD(ebp + 0x10);
    ecx = RD(ebp + 0x14) + eax;
    SF(ebp - 0x20, MUL(s0, s0));
    if ((int32_t)eax >= (int32_t)ecx) {
        x87_popped(c, top, 2);
        goto out;
    }
    WR(ebp - 0x50, c->r[EDI]);                          /* push edi */
    WR(ebp - 0x18, ebp - 0x38);
    uint32_t esi = eax * 12u, edi = eax * 16u;
    WR(ebp - 0x1c, L + 0x1c);
    uint32_t n = ecx - eax;
    WR(ebp - 0x10, n);
    do {
        double x2, y2, z2, t, inv;
        eax = RD(0x10166ab8u);
        const uint32_t vz = f32bits(LF(edi + eax + 8)), vy = f32bits(LF(edi + eax + 4)), vx = f32bits(LF(edi + eax));
        WR(ebp - 0xc, vz);
        WR(ebp - 4, vy);
        WR(ebp - 0x14, vx);
        WR(ebp - 0x38, vx);
        WR(ebp - 0x34, vy);
        WR(ebp - 0x30, vz);
        WR(0x101667b0u, vx);
        WR(0x101667b4u, vy);
        WR(0x101667b8u, vz);
        ecx = vy;
        edx = L + 0x1c;
        {   /* B = vertex - light position */
            double bx = SUB(LF(0x101667b0u), LF(L + 0x1c));
            double by = SUB(LF(0x101667b4u), LF(L + 0x20));
            double bz = SUB(LF(0x101667b8u), LF(L + 0x24));
            SF(0x101667b0u, bx);
            SF(0x101667b4u, by);
            SF(0x101667b8u, bz);
        }
        z2 = MUL(LF(0x101667b8u), LF(0x101667b8u));
        y2 = MUL(LF(0x101667b4u), LF(0x101667b4u));
        x2 = MUL(LF(0x101667b0u), LF(0x101667b0u));
        t = ADD(ADD(x2, y2), z2);
        SF(ebp - 4, t);
        FCOM(t, LF(ebp - 0x20), top - 3);
        if (!(c->sw & C0)) {                            /* out of range */
            x87_popped(c, top, 4);
            goto next;
        }
        t = SQRT(ADD(z2, ADD(x2, y2)));
        FCOM(t, 0.0, top - 1);
        if (c->sw & C3) {
            WR(ebp + 0xc, 0);
        } else {
            SF(ebp + 0xc, DIV(1.0, t));
        }
        inv = LF(ebp + 0xc);
        edx = ebp + 0xc;
        {
            double bx = MUL(inv, LF(0x101667b0u)), by = MUL(inv, LF(0x101667b4u)), bz = MUL(inv, LF(0x101667b8u));
            SF(0x101667b0u, bx);
            SF(0x101667b4u, by);
            SF(0x101667b8u, bz);
        }
        t = SQRT(LF(ebp - 4));
        eax = RD(0x10166abcu);
        {   /* attenuation 1 / ((d * a2 + a1) * d + a0) */
            double a = MUL(t, LF(L + 0x3c));
            a = ADD(a, LF(L + 0x38));
            a = MUL(a, t);
            a = ADD(a, LF(L + 0x34));
            SF(ebp - 0xc, DIVR(a, 1.0));
        }
        t = MUL(LF(0x101667b8u), LF(esi + eax + 8));
        t = ADD(t, MUL(LF(0x101667b4u), LF(esi + eax + 4)));
        t = ADD(t, MUL(LF(0x101667b0u), LF(esi + eax)));
        t = -t;
        FCOM(t, 0.0, top - 1);
        if (!(c->sw & (C0 | C3))) {                     /* diffuse */
            t = MUL(t, LF(ebp - 0xc));
            ecx = RD(L + 4);
            WR(0x101667c0u, ecx);
            edx = RD(L + 8);
            WR(0x101667c4u, edx);
            eax = RD(L + 0xc);
            SF(ebp - 4, t);
            WR(0x101667c8u, eax);
            double k = LF(ebp - 4);
            double cx = MUL(k, LF(0x101667c0u)), cy = MUL(k, LF(0x101667c4u)), cz = MUL(k, LF(0x101667c8u));
            SF(0x101667c0u, cx);
            SF(0x101667c4u, cy);
            SF(0x101667c8u, cz);
            ecx = RD(0x10166ac8u);
            const uint32_t acc = esi + ecx;
            WR(ebp - 0x14, acc);
            double ax = ADD(LF(acc), LF(0x101667c0u)), ay = ADD(LF(acc + 4), LF(0x101667c4u)),
                   az = ADD(LF(acc + 8), LF(0x101667c8u));
            SF(acc, ax);
            SF(acc + 4, ay);
            SF(acc + 8, az);
            edx = 0x101667c0u;
        }
        x87_popped(c, top, 4);
        eax = RD(ebp - 0x24);
        ecx = RD(eax + 8);
        WR(ebp - 0x54, 0x1013c223u);                    /* call 0x10125380: mov al, [ecx + 0x31] */
        eax = (eax & 0xffffff00u) | rd8(c, ecx + 0x31);
        if (!(eax & 0xffu))
            goto next;
        {   /* specular */
            ecx = RD(ebp + 8) + 8;
            edx = RD(ecx);
            WR(0x101667a0u, edx);
            eax = RD(ecx + 4);
            WR(0x101667a4u, eax);
            eax = RD(0x10166ab8u);
            ecx = RD(ecx + 8);
            WR(0x101667a8u, ecx);
            const uint32_t wz = f32bits(LF(edi + eax + 8)), wy = f32bits(LF(edi + eax + 4)), wx = f32bits(LF(edi + eax));
            WR(ebp - 0x14, wz);
            WR(ebp - 0x2c, ebp - 0x44);
            WR(ebp - 4, wy);
            WR(ebp - 0x28, wx);
            WR(ebp - 0x44, wx);
            WR(ebp - 0x40, wy);
            WR(ebp - 0x3c, wz);
            WR(ebp - 0x2c, ebp - 0x44);
            ecx = ebp - 0x44;
            {   /* A = eye - vertex */
                double ax = SUB(LF(0x101667a0u), LF(ebp - 0x44));
                double ay = SUB(LF(0x101667a4u), LF(ebp - 0x40));
                double az = SUB(LF(0x101667a8u), LF(ebp - 0x3c));
                SF(0x101667a0u, ax);
                SF(0x101667a4u, ay);
                SF(0x101667a8u, az);
            }
            for (int pass = 0; pass < 2; pass++) {      /* normalise A; then A -= B and normalise again */
                const uint32_t slot = pass ? ebp + 0x14 : ebp + 0x10;
                if (pass) {
                    double ax = SUB(LF(0x101667a0u), LF(0x101667b0u));
                    double ay = SUB(LF(0x101667a4u), LF(0x101667b4u));
                    double az = SUB(LF(0x101667a8u), LF(0x101667b8u));
                    SF(0x101667a0u, ax);
                    SF(0x101667a4u, ay);
                    SF(0x101667a8u, az);
                }
                t = MUL(LF(0x101667a8u), LF(0x101667a8u));
                t = ADD(t, MUL(LF(0x101667a4u), LF(0x101667a4u)));
                t = ADD(t, MUL(LF(0x101667a0u), LF(0x101667a0u)));
                t = SQRT(t);
                FCOM(t, 0.0, top - 1);
                if (c->sw & C3)
                    WR(slot, 0);
                else
                    SF(slot, DIV(1.0, t));
                inv = LF(slot);
                double ax = MUL(inv, LF(0x101667a0u)), ay = MUL(inv, LF(0x101667a4u)), az = MUL(inv, LF(0x101667a8u));
                SF(0x101667a0u, ax);
                SF(0x101667a4u, ay);
                SF(0x101667a8u, az);
            }
            edx = ebp + 0x14;
            eax = RD(0x10166abcu);
            t = MUL(LF(0x101667a8u), LF(esi + eax + 8));
            t = ADD(t, MUL(LF(0x101667a4u), LF(esi + eax + 4)));
            t = ADD(t, MUL(LF(0x101667a0u), LF(esi + eax)));
            FCOM(t, 0.0, top - 1);
            if (!(c->sw & (C0 | C3))) {
                /* k = h / (s - h s + h) * attenuation, s = shininess */
                double s = LF(ebp - 8);
                double k = MUL(t, s);
                ecx = L + 0x10;
                edx = RD(ecx);
                WR(0x101667c0u, edx);
                eax = RD(ecx + 4);
                k = SUBR(k, s);
                WR(0x101667c4u, eax);
                ecx = RD(ecx + 8);
                WR(0x101667c8u, ecx);
                k = ADD(k, t);
                k = DIVR(k, t);
                k = MUL(k, LF(ebp - 0xc));
                SF(ebp - 0xc, k);
                k = LF(ebp - 0xc);
                double cx = MUL(k, LF(0x101667c0u)), cy = MUL(k, LF(0x101667c4u)), cz = MUL(k, LF(0x101667c8u));
                SF(0x101667c0u, cx);
                SF(0x101667c4u, cy);
                SF(0x101667c8u, cz);
                edx = RD(0x10166acc);
                const uint32_t acc = esi + edx;
                WR(ebp - 0x2c, acc);
                double sx = ADD(LF(acc), LF(0x101667c0u)), sy = ADD(LF(acc + 4), LF(0x101667c4u)),
                       sz = ADD(LF(acc + 8), LF(0x101667c8u));
                SF(acc, sx);
                SF(acc + 4, sy);
                SF(acc + 8, sz);
                edx = 0x101667c0u;
            }
        }
    next:
        eax = RD(ebp - 0x10);
        edi += 0x10;
        esi += 0xc;
        eax--;
        WR(ebp - 0x10, eax);
    } while (eax);
    c->r[EDI] = RD(ebp - 0x50);
out:
    c->r[EAX] = eax;
    c->r[ECX] = ecx;
    c->r[EDX] = edx;
    c->r[ESI] = RD(ebp - 0x4c);
    c->r[EBX] = RD(ebp - 0x48);
    c->r[EBP] = RD(ebp);
    c->r[ESP] = sp + 0x14;
}

/* Registers between the CPU struct and the locals of a function with calls (eax..edi, esp, ebp locals). */
#define FLUSH() (c->r[EAX] = eax, c->r[ECX] = ecx, c->r[EDX] = edx, c->r[EBX] = ebx, c->r[ESI] = esi, \
                 c->r[EDI] = edi, c->r[EBP] = ebp, c->r[ESP] = esp)
#define RELOAD() (eax = c->r[EAX], ecx = c->r[ECX], edx = c->r[EDX], ebx = c->r[EBX], esi = c->r[ESI], \
                  edi = c->r[EDI], ebp = c->r[EBP], esp = c->r[ESP], cw = c->cw)
#define CALL(fn, ret) do { FLUSH(); push32(c, (ret)); fn(c); \
                           if (__builtin_expect(c->r[ESP] > xesp0, 0)) return; RELOAD(); } while (0)
#define CALL_IND(slot, ret) do { FLUSH(); lift_call_ret(c, RD(slot), (ret)); \
                                 if (__builtin_expect(c->r[ESP] > xesp0, 0)) return; RELOAD(); } while (0)
#define PUSH(v) (esp -= 4, WR(esp, (v)))
#define LO8(r, v) ((r) = ((r) & 0xffffff00u) | ((uint32_t)(v) & 0xffu))

/* 0x10136f20 (thiscall, 8 args): a mesh's triangles into the frame's vertex arrays. this+0xc: the vertex source
 * (+0xc format bits, +0x2c positions, +0x30 normals, +0x34/+0x38 colours, +0x3c.. UV sets), this+0x10: the mesh
 * (+8 face count, +0x1c bit 1: face planes stale, +0x2c faces (3 indices), +0x30 face planes). Recomputes stale face
 * planes (normal by a table reciprocal square root, d = -n.p0), drops triangles facing away from the eye (args +8:
 * eye in object space at +8; +0x24 a winding flag, flipped when the object matrix mirrors), and appends the rest:
 * each vertex once (remap table *0x10166ad8, cleared to -1 for args +0x10 vertices), its position, normal, colours
 * and UVs copied to the output arrays, the triangle's new indices to args +0x18; *args+0x20 the vertex count,
 * *args+0x1c the triangle count. */
void f_10136f20(CPU *c)
{
    if ((rd8(c, 0x10166a44u) & 7u) != 7u) { lifted_10136f20(c); return; }
    uint16_t cw = c->cw;
    const uint32_t xesp0 = c->r[ESP];
    const uint32_t top = c->top;
    uint32_t eax = c->r[EAX], ecx = c->r[ECX], edx = c->r[EDX], ebx = c->r[EBX], esi = c->r[ESI], edi = c->r[EDI];
    uint32_t esp = xesp0, ebp = c->r[EBP];
    double t, u;

    PUSH(ebp);
    ebp = esp;
    esp -= 0x34;
    PUSH(ebx);
    ebx = RD(ebp + 8);
    PUSH(esi);
    esi = RD(ebx + 4);
    LO8(eax, rd8(c, esi + 0xe0) >> 5);
    PUSH(edi);
    edi = ecx;
    if (!(eax & 1)) {
        ecx = esi;
        CALL(f_1011c900, 0x10136f45u);
    }
    ecx = esi + 0x5c;
    edx = ecx;
    eax = RD(edx); WR(ebp - 0x24, eax);
    eax = RD(edx + 4); WR(ebp - 0x20, eax);
    edx = RD(edx + 8); WR(ebp - 0x1c, edx);
    eax = ecx + 0xc;
    edx = ebp - 0x24;
    WR(ebp - 0x14, eax);
    WR(ebp - 0x10, edx);
    eax = RD(ebp - 0x10);
    edx = RD(ebp - 0x14);
#define CROSS(a, b) do { /* [a] = [a] x [b], the guest's operation order */ \
        double p1 = MUL(LF((a) + 4), LF((b) + 8)), p2 = MUL(LF((a) + 8), LF((b) + 4)); \
        double p3 = MUL(LF((a) + 8), LF(b)), p4 = MUL(LF(a), LF((b) + 8)); \
        double p5 = MUL(LF(a), LF((b) + 4)), p6 = MUL(LF((a) + 4), LF(b)); \
        double r1 = SUB(p1, p2), r2 = SUB(p3, p4), r3 = SUBR(p6, p5); \
        SF((a), r1); SF((a) + 4, r2); SF((a) + 8, r3); } while (0)
    CROSS(eax, edx);
    x87_popped(c, top, 6);
    t = MUL(LF(ebp - 0x1c), LF(ecx + 0x20));
    t = ADD(t, MUL(LF(ebp - 0x20), LF(ecx + 0x1c)));
    t = ADD(t, MUL(LF(ebp - 0x24), LF(ecx + 0x18)));
    FCOM(t, 0.0, top);
    if (c->sw & C0) {
        LO8(eax, rd8(c, ebp + 0x24));
        wr8(c, ebp + 0x24, (eax & 0xffu) == 0);
    }
    LO8(eax, rd8(c, 0x10166a44u));
    eax = RD(edi + 0x10);
    ecx = RD(eax + 0x1c) >> 1;
    if (ecx & 1) {                                      /* face planes */
        PUSH(0x10163e38u);
        CALL(f_10131b30, 0x10137068u);
        PUSH(eax);
        CALL(f_1012e7c0, 0x1013706eu);
        eax = RD(edi + 0x10);
        edx = RD(eax + 8);
        ecx = 0;
        esp += 8;
        WR(ebp - 0xc, ecx);
        if (edx > ecx) {
            esi = 0;
            WR(ebp - 0x10, esi);
            WR(ebp - 8, ecx);
            do {
#define EDGE(g, k) do { /* g = p[k] - p[0] of the face at ecx */ \
                edx = RD(eax + 0x2c); eax = RD(edx + ecx + (k)); edx = RD(edi + 0xc); edx = RD(edx + 0x2c); \
                eax = edx + eax * 12u; \
                edx = RD(eax); WR((g), edx); edx = RD(eax + 4); WR((g) + 4, edx); eax = RD(eax + 8); WR((g) + 8, eax); \
                edx = RD(edi + 0x10); eax = RD(edx + 0x2c); eax = RD(eax + ecx); edx = eax * 3u; eax = RD(edi + 0xc); \
                eax = RD(eax + 0x2c); edx = eax + edx * 4u; WR(ebp - 0x14, edx); \
                eax = (g); edx = RD(ebp - 0x14); \
                { double x = SUB(LF(eax), LF(edx)), y = SUB(LF(eax + 4), LF(edx + 4)), z = SUB(LF(eax + 8), LF(edx + 8)); \
                  SF(eax, x); SF(eax + 4, y); SF(eax + 8, z); } } while (0)
                EDGE(0x10166a28u, 4);
                eax = RD(edi + 0x10);
                EDGE(0x10166a38u, 8);
                eax = 0x10166a28u;
                edx = 0x10166a38u;
                CROSS(eax, edx);
                t = MUL(LF(0x10166a30u), LF(0x10166a30u));
                t = ADD(t, MUL(LF(0x10166a2cu), LF(0x10166a2cu)));
                t = ADD(t, MUL(LF(0x10166a28u), LF(0x10166a28u)));
                FCOM(t, 0.0, top - 1);
                if (c->sw & C3) {
                    t = 0.0;
                } else {                                /* reciprocal square root from the table at *0x10149114 */
                    eax = RD(0x10149114u);
                    SF(ebp - 4, t);
                    WR(ebp - 0x14, eax);
                    esi = RD(ebp - 0x14);
                    ecx = RD(ebp - 4);
                    ebx = 0xbe7fffffu;
                    ecx >>= 16;
                    eax = RD(ebp - 4);
                    ebx -= eax;
                    ecx &= 0xff;
                    ebx >>= 1;
                    LO8(ecx, rd8(c, esi + ecx));
                    ecx <<= 15;
                    ebx &= 0xff800000u;
                    ebx |= ecx;
                    WR(ebp - 4, ebx);
                    t = LF(ebp - 4);
                    ecx = RD(ebp - 8);
                    esi = RD(ebp - 0x10);
                }
                SF(ebp - 8, t);
                eax = 0x10166a28u;
                edx = ebp - 8;
                {
                    double x = MUL(LF(edx), LF(eax)), y = MUL(LF(edx), LF(eax + 4)), z = MUL(LF(edx), LF(eax + 8));
                    SF(eax, x); SF(eax + 4, y); SF(eax + 8, z);
                }
                edx = RD(edi + 0x10); eax = RD(edx + 0x30); SF(eax + esi, LF(0x10166a28u));
                edx = RD(edi + 0x10); eax = RD(edx + 0x30); SF(eax + esi + 4, LF(0x10166a2cu));
                edx = RD(edi + 0x10); eax = RD(edx + 0x30); SF(eax + esi + 8, LF(0x10166a30u));
                edx = RD(edi + 0x10);
                eax = RD(edx + 0x2c);
                eax = RD(eax + ecx);
                ebx = RD(edi + 0xc);
                ebx = RD(ebx + 0x2c);
                edx = RD(edx + 0x30);
                eax = eax * 3u;
                t = MUL(LF(0x10166a30u), LF(ebx + eax * 4u + 8));
                eax = ebx + eax * 4u;
                u = LF(0x10166a2cu);
                ecx += 0xc;
                u = MUL(u, LF(eax + 4));
                esi += 0x10;
                WR(ebp - 8, ecx);
                WR(ebp - 0x10, esi);
                t = ADD(t, u);
                t = ADD(t, MUL(LF(0x10166a28u), LF(eax)));
                SF(edx + esi - 4, -t);
                edx = RD(ebp - 0xc);
                eax = RD(edi + 0x10);
                ebx = RD(eax + 8);
                edx++;
                WR(ebp - 0xc, edx);
            } while (edx < ebx);
#undef EDGE
            ebx = RD(ebp + 8);
        }
        eax = RD(edi + 0x10);
        ecx = RD(eax + 0x14);
        eax += 0x14;
        ecx &= 0xfffffffdu;
        WR(eax, ecx);
    }
#undef CROSS
    eax = RD(ebp + 0x10);
    ecx = eax * 4u;
    PUSH(ecx);
    ecx = RD(0x10166ad8u);
    edx |= 0xffu;
    CALL_IND(0x101491b0u, 0x101372f8u);                 /* R_Memory::set(remap, 0xff, 4 * vertices) */
    edx = RD(ebp + 0x20);
    esi = 0;
    WR(edx, esi);
    LO8(eax, rd8(c, 0x10166a44u));
    WR(ebp + 8, esi);
    eax = RD(ebx + 8);
    ecx = RD(ebx + 0xc);
    edx = RD(ebx + 0x10);
    WR(ebp - 0x34, eax);
    WR(0x10166a18u, eax);
    WR(ebp - 0x28, 0);
    eax = RD(ebp - 0x28);
    WR(0x10166a24u, eax);
    LO8(eax, rd8(c, ebp + 0x24));
    WR(ebp - 0x30, ecx);
    WR(ebp - 0x2c, edx);
    WR(0x10166a1cu, ecx);
    WR(0x10166a20u, edx);
    WR(0x10166a24u, 0x3f800000u);
    if (!(eax & 0xffu)) {                               /* negate the eye plane (x, y, z, 1) */
        ecx = RD(0x10166a18u);
        WR(ebp + 0x24, ecx);
        WR(ebp + 0x24, RD(ebp + 0x24) ^ 0x80000000u);
        edx = RD(ebp + 0x24);
        eax = RD(0x10166a1cu);
        WR(0x10166a18u, edx);
        WR(ebp + 0x24, eax);
        WR(ebp + 0x24, RD(ebp + 0x24) ^ 0x80000000u);
        t = LF(ebp + 0x24);
        ecx = RD(0x10166a20u);
        SF(0x10166a1cu, t);
        WR(ebp + 0x24, ecx);
        WR(ebp + 0x24, RD(ebp + 0x24) ^ 0x80000000u);
        t = LF(ebp + 0x24);
        edx = RD(0x10166a24u);
        SF(0x10166a20u, t);
        WR(ebp + 0x24, edx);
        WR(ebp + 0x24, RD(ebp + 0x24) ^ 0x80000000u);
        t = LF(ebp + 0x24);
        SF(0x10166a24u, t);
    }
    eax = RD(ebp + 0xc);
    if ((int32_t)eax > 0) {
        ecx = RD(ebp + 0x14);
        WR(ebp - 4, 0);
        WR(ebp - 8, ecx);
        WR(ebp - 0x14, eax);
        do {
            edx = RD(edi + 0x10);
            eax = RD(edx + 0x30);
            ecx = RD(ebp - 4);
            t = MUL(LF(0x10166a20u), LF(eax + ecx + 8));
            eax += ecx;
            t = ADD(t, MUL(LF(0x10166a1cu), LF(eax + 4)));
            t = ADD(t, MUL(LF(0x10166a24u), LF(eax + 0xc)));
            t = ADD(t, MUL(LF(0x10166a18u), LF(eax)));
            FCOM(t, 0.0, top);
            if (!(c->sw & (C0 | C3))) {                 /* facing the eye */
                eax = RD(ebp + 0x18);
                ecx = RD(ebp - 8);
                edx = eax + esi * 4u;
                WR(ebp + 0x14, ecx);
                WR(ebp - 0xc, 3);
                do {
                    eax = RD(ebp + 0x14);
                    esi = RD(eax);
                    eax = RD(0x10166ad8u);
                    ecx = RD(eax + esi * 4u);
                    WR(ebp + 0x10, esi);
                    if (ecx != 0xffffffffu) {           /* already appended */
                        WR(edx, ecx);
                        WR(ebp + 8, RD(ebp + 8) + 1);
                        edx += 4;
                        goto vnext;
                    }
                    ecx = RD(ebp + 0x20);
                    ebx = RD(ecx);
                    WR(eax + esi * 4u, ebx);
                    eax = ecx;
                    ecx = RD(eax);
                    WR(edx, ecx);
                    ecx = RD(ebp + 8);
                    edx += 4;
                    WR(ebp - 0x10, edx);
                    edx = RD(eax);
                    ecx++;
                    edx++;
                    WR(eax, edx);
                    eax = RD(edi + 0xc);
                    edx = RD(eax + 0xc) >> 4;
                    WR(ebp + 0xc, ebx);
                    WR(ebp + 8, ecx);
                    if (edx & 1) {                      /* position, w = 1 */
                        edx = RD(eax + 0x2c);
                        ecx = esi * 3u;
                        eax = edx + ecx * 4u;
                        ecx = RD(eax);
                        edx = RD(eax + 4);
                        eax = RD(eax + 8);
                        WR(ebp - 0x34, ecx);
                        ecx = RD(0x10166ab8u);
                        WR(ebp - 0x2c, eax);
                        WR(ebp - 0x30, edx);
                        eax = ebx << 4;
                        edx = eax + ecx;
                        ecx = RD(ebp - 0x34); WR(edx, ecx);
                        ecx = RD(ebp - 0x30); WR(edx + 4, ecx);
                        ecx = RD(ebp - 0x2c); WR(edx + 8, ecx);
                        WR(ebp - 0x28, 0);
                        ecx = RD(ebp - 0x28); WR(edx + 0xc, ecx);
                        edx = RD(0x10166ab8u);
                        WR(eax + edx + 0xc, 0x3f800000u);
                    }
                    eax = RD(edi + 0xc);
                    ecx = RD(eax + 0xc) >> 5;
                    if (ecx & 1) {
                        ecx = RD(edi + 8);
                        CALL(f_10125bf0, 0x10137509u);
                        edx = RD(eax) >> 5;
                        if (edx & 1) {                  /* normal */
                            eax = RD(edi + 0xc);
                            edx = RD(eax + 0x30);
                            ecx = esi * 3u;
                            eax = edx + ecx * 4u;
                            edx = RD(0x10166abcu);
                            ecx = ebx * 3u;
                            ecx = edx + ecx * 4u;
                            edx = RD(eax); WR(ecx, edx);
                            edx = RD(eax + 4); WR(ecx + 4, edx);
                            eax = RD(eax + 8); WR(ecx + 8, eax);
                        }
                    }
                    ecx = RD(edi + 0xc);
                    edx = RD(ecx + 0xc) >> 6;
                    if (edx & 1) {
                        ecx = RD(edi + 8);
                        CALL(f_10125bf0, 0x10137551u);
                        eax = RD(eax) >> 6;
                        if (eax & 1) {                  /* colour 1 */
                            ecx = RD(edi + 0xc);
                            ecx = RD(ecx + 0x34);
                            edx = esi << 4;
                            ecx += edx;
                            edx = RD(0x10166ac0u);
                            WR(ebp + 0x24, ecx);
                            eax = ebx << 4;
                            eax += edx;
                            edx = RD(ecx);
                            WR(ebp - 0x18, eax);
                            WR(eax, edx);
                            edx = RD(ecx + 4); WR(eax + 4, edx);
                            ecx = RD(ecx + 8);
                            edx = RD(ebp + 0x24);
                            WR(eax + 8, ecx);
                            eax = RD(edx + 0xc);
                            ecx = RD(ebp - 0x18);
                            WR(ecx + 0xc, eax);
                        }
                    }
                    edx = RD(edi + 0xc);
                    eax = RD(edx + 0xc) >> 7;
                    if (eax & 1) {
                        ecx = RD(edi + 8);
                        CALL(f_10125bf0, 0x101375abu);
                        ecx = RD(eax) >> 7;
                        if (ecx & 1) {                  /* colour 2 */
                            edx = RD(edi + 0xc);
                            eax = RD(edx + 0x38);
                            ecx = RD(0x10166ac4u);
                            esi <<= 4;
                            eax += esi;
                            ebx <<= 4;
                            ebx += ecx;
                            ecx = eax;
                            esi = RD(ecx);
                            edx = ebx;
                            WR(edx, esi);
                            esi = RD(ecx + 4); WR(edx + 4, esi);
                            ecx = RD(ecx + 8); WR(edx + 8, ecx);
                            edx = RD(eax + 0xc); WR(ebx + 0xc, edx);
                        }
                    }
                    edx = RD(edi + 0xc);
                    ecx = RD(edx + 0xc) & 0xf;
                    eax = 0;
                    if (ecx & 0xf) {                    /* UV sets: format bits 11+2k, 0/1/2 = 2, 3 or 4 floats */
                        ecx = 0xb;
                        WR(ebp + 0x24, ecx);
                        do {
                            if ((int32_t)ecx >= 0xb) {
                                for (uint32_t kind = 0; kind < 3; kind++) {
                                    esi = RD(edx + 0xc) & 0xf;
                                    if (eax >= esi)
                                        continue;       /* cmp ecx, 0xb holds: ecx is unchanged */
                                    ebx = RD(edx + 0xc);
                                    esi = (3u << (ecx & 31u)) & ebx;
                                    ebx = kind << (ecx & 31u);
                                    if (esi != ebx) {
                                        ecx = RD(ebp + 0x24);
                                        continue;
                                    }
                                    edx = RD(edx + eax * 4u + 0x3c);
                                    ecx = RD(ebp + 0x10);
                                    if (kind == 0) {
                                        ebx = RD(edx + ecx * 8u);
                                        esi = RD(eax * 4u + 0x10166a88u);
                                        ecx = RD(ebp + 0xc);
                                        WR(esi + ecx * 8u, ebx);
                                        ebx = RD(ebp + 0x10);
                                        edx = RD(edx + ebx * 8u + 4);
                                        WR(esi + ecx * 8u + 4, edx);
                                    } else if (kind == 1) {
                                        esi = RD(eax * 4u + 0x10166a68u);
                                        ecx = ecx * 3u;
                                        edx = edx + ecx * 4u;
                                        ecx = RD(ebp + 0xc);
                                        ecx = ecx * 3u;
                                        ecx = esi + ecx * 4u;
                                        esi = RD(edx); WR(ecx, esi);
                                        esi = RD(edx + 4); WR(ecx + 4, esi);
                                        edx = RD(edx + 8); WR(ecx + 8, edx);
                                    } else {
                                        esi = RD(eax * 4u + 0x10166a48u);
                                        ecx <<= 4;
                                        edx += ecx;
                                        ecx = RD(ebp + 0xc);
                                        ecx <<= 4;
                                        esi += ecx;
                                        ecx = RD(edx); WR(esi, ecx);
                                        ecx = RD(edx + 4); WR(esi + 4, ecx);
                                        ecx = RD(edx + 8); WR(esi + 8, ecx);
                                        edx = RD(edx + 0xc); WR(esi + 0xc, edx);
                                    }
                                    ecx = RD(ebp + 0x24);
                                    break;
                                }
                            }
                            edx = RD(edi + 0xc);
                            esi = RD(edx + 0xc) & 0xf;
                            eax++;
                            ecx += 2;
                            WR(ebp + 0x24, ecx);
                        } while ((int32_t)eax < (int32_t)esi);
                    }
                    edx = RD(ebp - 0x10);
                vnext:
                    ecx = RD(ebp + 0x14);
                    eax = RD(ebp - 0xc);
                    ecx += 4;
                    eax--;
                    WR(ebp + 0x14, ecx);
                    WR(ebp - 0xc, eax);
                } while (eax);
                esi = RD(ebp + 8);
            }
            edx = RD(ebp - 4);
            ecx = RD(ebp - 8);
            eax = RD(ebp - 0x14);
            edx += 0x10;
            ecx += 0xc;
            eax--;
            WR(ebp - 4, edx);
            WR(ebp - 8, ecx);
            WR(ebp - 0x14, eax);
        } while (eax);
    }
    ecx = RD(ebp + 0x1c);
    {
        int64_t p = (int64_t)(int32_t)esi * 0x55555556;    /* esi / 3 */
        edx = (uint32_t)((uint64_t)p >> 32);
    }
    eax = edx >> 31;
    edx += eax;
    WR(ecx, edx);
    c->r[EDI] = RD(esp);
    c->r[ESI] = RD(esp + 4);
    c->r[EBX] = RD(esp + 8);
    c->r[EBP] = RD(ebp);
    c->r[EAX] = eax;
    c->r[ECX] = ecx;
    c->r[EDX] = edx;
    c->r[ESP] = ebp + 4 + 4 + 0x20;
}

/* 0x10137a40 (thiscall, 3 args): transform positions [first, first + count) of *0x10166ab8 (x, y, z, w; 16 bytes)
 * in place by the 4x4 matrix at args+8 +0x48 (row vectors: v' = x r0 + y r1 + z r2 + w r3), copied to 0x101669d0
 * with m[3][2] reduced by this+8's +0xa0 (the getter 0x10125910). args: +8 the matrix owner, +0xc first, +0x10 count.
 * Guard byte 0x10166a10. */
void f_10137a40(CPU *c)
{
    if (!(rd8(c, 0x10166a10u) & 1u)) { lifted_10137a40(c); return; }
    const uint16_t cw = c->cw;
    const uint32_t sp = c->r[ESP];
    const uint32_t ebp = sp - 4;
    const uint32_t top = c->top;
    const uint32_t self = c->r[ECX];
    uint32_t eax, ecx, edx = c->r[EDX];
    WR(ebp, c->r[EBP]);
    WR(ebp - 4, c->r[EBX]);
    WR(ebp - 8, c->r[ESI]);
    WR(ebp - 0xc, c->r[EDI]);
    eax = RD(ebp + 8);
    for (uint32_t i = 0; i < 0x40; i += 4)
        SF(0x101669d0u + i, LF(eax + 0x48 + i));
    ecx = RD(self + 8);
    WR(ebp - 0x10, 0x10137bd5u);                        /* call 0x10125910: fld [ecx + 0xa0] */
    double t = SUBR(LF(ecx + 0xa0), LF(0x10166a08u));
    ecx = RD(ebp + 0xc);
    eax = RD(ebp + 0x10) + ecx;
    SF(0x10166a08u, t);
    x87_popped(c, top, 1);
    if ((int32_t)ecx < (int32_t)eax) {
        uint32_t esi = ecx << 4, edi = eax - ecx;
        do {
            ecx = RD(0x10166ab8u);
            WR(ebp + 8, esi + ecx);
            WR(ebp - 0x10, self);                       /* push ebx */
            eax = esi + ecx;
            uint32_t m = 0x101669d0u;
            double v = LF(eax);
            double a0 = MUL(v, LF(m)), a1 = MUL(v, LF(m + 4)), a2 = MUL(v, LF(m + 8)), a3 = MUL(v, LF(m + 0xc));
            for (ecx = 1; ecx <= 3; ecx++) {
                m += 0x10;
                v = LF(eax + ecx * 4);
                double b0 = MUL(v, LF(m)), b1 = MUL(v, LF(m + 4)), b2 = MUL(v, LF(m + 8)), b3 = MUL(v, LF(m + 0xc));
                a0 = ADD(a0, b0);
                a2 = ADD(a2, b2);
                a1 = ADD(a1, b1);
                a3 = ADD(a3, b3);
            }
            SF(eax, a0);
            SF(eax + 8, a2);
            SF(eax + 4, a1);
            SF(eax + 0xc, a3);
            esi += 0x10;
        } while (--edi);
        edx = 0;
        x87_popped(c, top, 8);
    }
    c->r[EAX] = eax;
    c->r[ECX] = ecx;
    c->r[EDX] = edx;
    c->r[ESP] = sp + 0x10;
}
