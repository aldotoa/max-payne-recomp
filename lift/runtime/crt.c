/* Native versions of hot MSVCRT helpers (M6), for calls from lifted code.
 *
 * Lifted code reaches an import through lift_call_ret / lift_jump (runtime.c). When the target is not lifted it would
 * be a guest call: a nested emulator run, ~1 us each. For the helpers below, the runtime runs this C instead. Each one
 * does exactly what the guest function does on the path it handles: the same registers, flags, x87 state and guest
 * memory writes, including the bytes it leaves below esp (its return address, saved registers and locals), since
 * emulated code can later read them as uninitialised locals. A helper that meets a case it does not handle returns 0
 * before changing anything, and the call goes to the guest as before.
 *
 * Python binds each helper to the guest address of its import (emu/native.py CRT_HELPERS, which also checks that the
 * guest bytes are the ones the code below was written from, the game's MSVCRT.DLL). Unbound helpers are never used. */
#include <stdint.h>
#include <string.h>

#include "cpu.h"
#include "flags.h"
#include "runtime.h"
#include "x87.h"

/* The helper of a call from lifted code: entered as `call` would enter the function (ret is the return address the
 * call pushes; esp has not moved yet). Leaves the state as the guest's ret would. Returns 1 when done, 0 when the
 * call must go to the guest (nothing was changed). */
typedef int (*crt_fn)(CPU *c, uint32_t ret, uint32_t base);

/* _ftol (MSVCRT+0x1f14): st(0) to a 64-bit integer in edx:eax with rounding control chop, popped.
 *     push ebp; mov ebp, esp; add esp, -0xc; fnstcw [ebp-2]; mov ax, [ebp-2]; or ah, 0xc; mov [ebp-4], ax;
 *     fldcw [ebp-4]; fistp qword [ebp-0xc]; fldcw [ebp-2]; mov eax, [ebp-0xc]; mov edx, [ebp-8]; leave; ret
 * An out-of-range value or a NaN gives the integer indefinite 0x8000000000000000 (edx 0x80000000, eax 0). The status
 * word's exception bits are left alone, as the reference emulator leaves them (see x87_ival).
 * Flags are those of `or ah, 0xc`. The host rounding mode is not touched: the result is rounded in software
 * (x87_ival), and the control word is the caller's again on return. */
static int crt_ftol(CPU *c, uint32_t ret, uint32_t base)
{
    (void)base;
    uint32_t e = c->r[ESP] - 4;               /* esp after the call pushed ret */
    uint16_t cw = c->cw, chop = (uint16_t)(cw | 0x0c00u);
    wr32(c, e, ret);
    wr32(c, e - 4, c->r[EBP]);
    wr16(c, e - 6, cw);
    wr16(c, e - 8, chop);
    c->cw = chop;
    uint64_t v = x87_ival(c, x87_rd(c, 0), 8);
    c->cw = cw;
    wr64(c, e - 0x10, v);
    x87_pop(c);
    flags_logic8(c, (uint8_t)(chop >> 8));
    c->r[EAX] = (uint32_t)v;
    c->r[EDX] = (uint32_t)(v >> 32);
    return 1;
}

/* tolower (MSVCRT+0x11790), the "C" locale path only (__lc_handle[LC_CTYPE], MSVCRT+0x37164, is 0):
 *     push ebx; xor ebx, ebx; cmp [__lc_handle_ctype], ebx; jne <locale path>; mov eax, [esp+8];
 *     cmp eax, 0x41; jl done; cmp eax, 0x5a; jg done; add eax, 0x20; [done:] pop ebx; ret
 * Any other locale takes the guest's locked path. */
static int crt_tolower(CPU *c, uint32_t ret, uint32_t base)
{
    if (rd32(c, base + 0x37164u) != 0)
        return 0;
    uint32_t e = c->r[ESP] - 4;
    uint32_t a = rd32(c, c->r[ESP]);
    wr32(c, e, ret);
    wr32(c, e - 4, c->r[EBX]);
    if ((int32_t)a < 0x41)
        flags_sub32(c, a, 0x41);
    else if ((int32_t)a > 0x5a)
        flags_sub32(c, a, 0x5a);
    else {
        flags_add32(c, a, 0x20);
        a += 0x20;
    }
    c->r[EAX] = a;
    return 1;
}

/* The ASCII fold of the guest's stricmp byte loop, on al, with cl set as the guest sets it:
 *     sub al, 0x41; cmp al, 0x1a; sbb cl, cl; and cl, 0x20; add al, cl; add al, 0x41
 * (al is then tolower(al) for 'A'..'Z' and unchanged otherwise). */
static uint8_t crt_fold_upper(uint8_t al, uint8_t *cl)
{
    al = (uint8_t)(al - 0x41);
    *cl = (uint8_t)((al < 0x1a ? 0xff : 0x00) & 0x20);
    al = (uint8_t)(al + *cl);
    return (uint8_t)(al + 0x41);
}

/* _stricmp (MSVCRT+0x10d13), the "C" locale path only (__lc_handle[LC_CTYPE] == 0). The guest code, from the
 * prologue to the ret (the path is contiguous: bytes 0x10d13..0x10d68):
 *     push ebp; mov ebp, esp; push edi; push esi; push ebx; mov esi, [ebp+0xc]; mov edi, [ebp+8];
 *     lea eax, [0x7803715c]; cmp dword [eax+8], 0; jne <locale path>;
 *     mov al, 0xff; [loop:] or al, al; je done; mov al, [esi]; inc esi; mov ah, [edi]; inc edi; cmp ah, al; je loop;
 *     <fold al> ; xchg al, ah; <fold al>; cmp al, ah; je loop; sbb al, al; sbb al, 0xff;
 *     [done:] movsx eax, al; pop ebx; pop esi; pop edi; leave; ret
 * where <fold al> is crt_fold_upper. So it returns the sign of tolower(s1[i]) - tolower(s2[i]) at the first
 * difference, 0 at the common NUL. Writes: ret at e, ebp, edi, esi, ebx at e-4, e-8, e-0xc, e-0x10 (e = esp - 4).
 * ecx: its low byte is the last cl the fold set (upper bits kept). edx, ebx, esi, edi, ebp are unchanged.
 * Flags: or al,al (al = 0) for the zero exit; for a difference, the last sbb: CF = 1 and the result's SF and PF.
 * Those are the flags the helper leaves, computed by the same flags_sbb the guest's sbb follows. */
static int crt_stricmp(CPU *c, uint32_t ret, uint32_t base)
{
    if (rd32(c, base + 0x37164u) != 0)
        return 0;
    uint32_t p = c->r[ESP];
    uint32_t e = p - 4;
    wr32(c, e, ret);
    wr32(c, e - 4, c->r[EBP]);
    wr32(c, e - 8, c->r[EDI]);
    wr32(c, e - 0xc, c->r[ESI]);
    wr32(c, e - 0x10, c->r[EBX]);
    uint32_t esi = rd32(c, p + 4), edi = rd32(c, p);       /* esi = s2, edi = s1 (args at [ebp+0xc], [ebp+8]) */
    uint8_t cl = (uint8_t)c->r[ECX];
    uint8_t al = 0xff, ah = 0;
    for (;;) {
        if (al == 0) {                                      /* or al, al; je done */
            flags_logic8(c, 0);
            break;
        }
        al = rd8(c, esi++);                                 /* mov al, [esi]; inc esi */
        ah = rd8(c, edi++);                                 /* mov ah, [edi]; inc edi */
        if (ah == al)                                       /* cmp ah, al; je loop */
            continue;
        al = crt_fold_upper(al, &cl);
        uint8_t t = al;                                     /* xchg al, ah */
        al = ah;
        ah = t;
        al = crt_fold_upper(al, &cl);
        flags_sub8(c, al, ah);                              /* cmp al, ah */
        if (al == ah)                                       /* je loop */
            continue;
        uint32_t r1 = flags_sbb(c, al, al, 8);              /* sbb al, al */
        uint32_t r2 = flags_sbb(c, r1, 0xff, 8);            /* sbb al, 0xff */
        al = (uint8_t)r2;
        break;
    }
    c->r[ECX] = (c->r[ECX] & ~0xffu) | cl;
    c->r[EAX] = (uint32_t)(int32_t)(int8_t)al;              /* movsx eax, al */
    return 1;
}

/* The guest's ASCII case step of _strnicmp: cmp ch, 0x41; jb skip; cmp ch, 0x5a; ja skip; add ch, 0x20. */
static uint8_t crt_ci(uint8_t ch)
{
    return (uint8_t)(ch >= 0x41 && ch <= 0x5a ? ch + 0x20 : ch);
}

/* _strnicmp (MSVCRT+0x139f6), the "C" locale path only. The guest code, prologue to ret (bytes 0x139f6..0x13a5c):
 *     push ebp; mov ebp, esp; push edi; push esi; push ebx; mov ecx, [ebp+0x10]; or ecx, ecx; je done;
 *     mov esi, [ebp+8]; mov edi, [ebp+0xc]; lea eax, [0x7803715c]; cmp dword [eax+8], 0; jne <locale path>;
 *     mov bh, 0x41; mov bl, 0x5a; mov dh, 0x20;
 *     [loop:] mov ah, [esi]; or ah, ah; mov al, [edi]; je end; or al, al; je end; inc esi; inc edi;
 *     <ci ah>; <ci al>; cmp ah, al; jne diff; dec ecx; jne loop;
 *     [end:] xor ecx, ecx; cmp ah, al; je done; [diff:] mov ecx, 0xffffffff; jb done; neg ecx;
 *     [done:] mov eax, ecx; pop ebx; pop esi; pop edi; leave; ret
 * n == 0 returns 0 with flags of or ecx, ecx. Writes: the same stack slots as _stricmp. edx: dh = 0x20 when n != 0;
 * ebx, esi, edi, ebp are restored by the pops. ecx and eax are the result. Flags: the last compare (cmp ah, al),
 * or for a result of 1 the flags of neg ecx (sub 0 - 0xffffffff), as the guest's neg sets them. */
static int crt_strnicmp(CPU *c, uint32_t ret, uint32_t base)
{
    if (rd32(c, base + 0x37164u) != 0)
        return 0;
    uint32_t p = c->r[ESP];
    uint32_t e = p - 4;
    wr32(c, e, ret);
    wr32(c, e - 4, c->r[EBP]);
    wr32(c, e - 8, c->r[EDI]);
    wr32(c, e - 0xc, c->r[ESI]);
    wr32(c, e - 0x10, c->r[EBX]);
    uint32_t ecx = rd32(c, p + 8);                          /* mov ecx, [ebp+0x10] */
    uint32_t edx = c->r[EDX];
    if (ecx == 0) {                                         /* or ecx, ecx; je done */
        flags_logic32(c, 0);
    } else {
        uint32_t esi = rd32(c, p), edi = rd32(c, p + 4);    /* esi = s1, edi = s2 */
        edx = (edx & 0xffff00ffu) | 0x2000u;                /* mov dh, 0x20 */
        uint8_t ah, al;
        for (;;) {
            ah = rd8(c, esi);                               /* mov ah, [esi]; or ah, ah */
            al = rd8(c, edi);                               /* mov al, [edi]; */
            if (ah == 0 || al == 0)                         /* je end (the NUL checks, before any fold) */
                break;
            esi++;
            edi++;
            ah = crt_ci(ah);
            al = crt_ci(al);
            if (ah != al)                                   /* jne diff */
                break;
            if (--ecx == 0)                                 /* dec ecx; jne loop */
                break;
        }
        /* end: xor ecx, ecx; cmp ah, al; je done. diff: mov ecx, -1; jb done; neg ecx; done: */
        flags_sub8(c, ah, al);
        if (ah == al) {
            ecx = 0;
        } else {
            ecx = 0xffffffffu;
            if (!c->cf) {
                ecx = 0u - ecx;
                flags_sub32(c, 0, 0xffffffffu);             /* neg ecx: the flags of 0 - (-1) */
            }
        }
    }
    c->r[ECX] = ecx;
    c->r[EAX] = ecx;
    c->r[EDX] = edx;
    return 1;
}

/* ---- __RTDynamicCast (MSVCRT+0x1844e), dynamic_cast ----
 *
 * __RTDynamicCast(inptr, VfDelta, SrcType, TargetType, isReference). The helper reproduces the guest for:
 *   - inptr == NULL: returns 0 (the guest returns at once, after its SEH frame);
 *   - an object whose COL has cdOffset 0 (no vbtable) and whose class hierarchy has no virtual inheritance
 *     (CHD attributes bit 1 clear), searched with the single-inheritance search (CHD attributes bit 0 clear,
 *     0x1857c) or the multiple-inheritance search (bit 0 set, 0x185d6), where every PMD it reads has pdisp < 0;
 *   - a failing cast with isReference == 0 returns 0.
 * Everything else returns 0 with nothing changed: a failing cast with isReference != 0 (the guest throws bad_cast,
 * 0x78018505..0x78018543), a virtual base or inheritance (the guest reads a vbtable), and any read or write
 * outside the regions the emulator maps (lift_crt_regions).
 *
 * The guest, prologue to the NULL test (B = ebp, E = the return slot = esp-4 at entry, arguments at [B+8]...):
 *     push ebp; mov ebp,esp; push -1; push 0x7802fb40; push 0x7800ef06; mov eax,fs:[0]; push eax;
 *     mov fs:[0],esp; sub esp,0x3c; push ebx; push esi; push edi; mov [ebp-0x18],esp;
 *     mov esi,[ebp+8]; test esi,esi; jne body
 * Body (the calls with their pushes, the callee frames and the return addresses are in rt_complete, rt_si, rt_mi,
 * rt_pmd and rt_strcmp below):
 *     and [ebp-4],0; push esi; call GetCompleteObject (ret 0x78018496); pop ecx; mov edi,eax; mov [ebp-0x2c],edi;
 *     mov eax,[esi]; mov eax,[eax-4]; mov [ebp-0x24],eax; sub esi,[ebp+0xc]; mov [ebp+8],esi; sub esi,edi;
 *     mov [ebp-0x28],esi; mov ecx,[eax+0x10]; mov ecx,[ecx+4]; test cl,1; jne MI (0x780184e9)
 *     push [ebp+0x14]; push esi; push [ebp+0x10]; push eax; push edi; call SI (0x7801857c, ret 0x780184c8) ...
 * Epilogue, the same for every exit that returns: mov ecx,[ebp-0x10]; mov fs:[0],ecx; pop edi; pop esi; pop ebx;
 * leave; ret, so ebx, esi and edi are the entry values and ecx is the previous SEH record. The last flag-setting
 * instruction is `or dword [ebp-4], 0xffffffff` (the body) or `xor eax, eax` (NULL), so the flags are those.
 *
 * The state written. Let W(x) be a guest write, then the helper writes the same dwords the guest writes, with the
 * same final values: the frame slots [B-4 .. B-0x2c], the caller's argument slot [B+8] (the adjusted pointer), the
 * pushes and return addresses of each call (B-0x5c .. B-0x98, the deepest is the strcmp call of the MI search), the
 * saved registers of each callee and its loop counter. The helper keeps the writes in a window
 * [E-0x100, E+0x20) and commits them only when the whole case is handled. Its eax is the result, edx is the one the
 * last edx writer leaves (GetCompleteObject: 0, strcmp: its walking pointer, PMDtoOffset: pdisp). */

#define RT_WIN 0x120u                 /* the stack window: [E - 0x100, E + 0x20) */
#define CRT_MAXREG 4096

/* The guest address ranges the emulator maps (lift_crt_regions), sorted and merged. A read or write outside them
 * declines: the emulator would fault there. An empty list declines everything. */
static uint64_t g_rlo[CRT_MAXREG], g_rhi[CRT_MAXREG];
static uint32_t g_nreg;

int lift_crt_regions(const uint32_t *pairs, uint32_t npairs)
{
    uint32_t k = 0;
    g_nreg = 0;
    if (npairs > CRT_MAXREG)
        return -1;
    for (uint32_t i = 0; i < npairs; i++) {
        uint64_t lo = pairs[2 * i], hi = lo + pairs[2 * i + 1];
        if (pairs[2 * i + 1] == 0)
            continue;
        uint32_t j = k;
        while (j > 0 && g_rlo[j - 1] > lo) {
            g_rlo[j] = g_rlo[j - 1];
            g_rhi[j] = g_rhi[j - 1];
            j--;
        }
        g_rlo[j] = lo;
        g_rhi[j] = hi;
        k++;
    }
    uint32_t m = 0;
    for (uint32_t i = 0; i < k; i++) {
        if (m && g_rlo[i] <= g_rhi[m - 1]) {
            if (g_rhi[i] > g_rhi[m - 1])
                g_rhi[m - 1] = g_rhi[i];
        } else {
            g_rlo[m] = g_rlo[i];
            g_rhi[m] = g_rhi[i];
            m++;
        }
    }
    g_nreg = m;
    lift_call_cache_clear();             /* thunk resolution depends on the mapped regions */
    return 0;
}

static int crt_mapped(uint32_t a, uint32_t n)
{
    uint64_t hi = (uint64_t)a + n;
    uint32_t l = 0, r = g_nreg;
    while (l < r) {                           /* the last region that starts at or below a */
        uint32_t mid = (l + r) / 2;
        if (g_rlo[mid] <= a)
            l = mid + 1;
        else
            r = mid;
    }
    return l > 0 && hi <= g_rhi[l - 1];
}

/* crt_mapped for the rest of the runtime: the thunk shortcut (runtime.c call_fill) reads guest bytes only here. */
int lift_mapped(uint32_t a, uint32_t n)
{
    return crt_mapped(a, n);
}

typedef struct {
    CPU *c;
    uint32_t lo;                  /* guest address of v[0] */
    uint8_t v[RT_WIN], d[RT_WIN]; /* the pending bytes of the window, where d is set */
    uint32_t dlo, dhi;            /* the dirty index range */
    int bad;                      /* a write outside the window: not modelled, decline */
    uint32_t edx;                 /* the guest's edx at the end */
} RtTx;

static int rt_rd8(RtTx *t, uint32_t a, uint8_t *out)
{
    uint32_t i = a - t->lo;
    if (i < RT_WIN && t->d[i]) {
        *out = t->v[i];
        return 1;
    }
    if (!crt_mapped(a, 1))
        return 0;
    *out = rd8(t->c, a);
    return 1;
}

static int rt_rd32(RtTx *t, uint32_t a, uint32_t *out)
{
    int touches = 0;
    for (uint32_t k = 0; k < 4; k++)
        touches |= (a + k - t->lo) < RT_WIN;
    if (!touches) {
        if (!crt_mapped(a, 4))
            return 0;
        *out = rd32(t->c, a);
        return 1;
    }
    uint32_t v = 0;
    for (uint32_t k = 0; k < 4; k++) {
        uint8_t b;
        if (!rt_rd8(t, a + k, &b))
            return 0;
        v |= (uint32_t)b << (8 * k);
    }
    *out = v;
    return 1;
}

static void rt_wr32(RtTx *t, uint32_t a, uint32_t v)
{
    for (uint32_t k = 0; k < 4; k++) {
        uint32_t i = a + k - t->lo;
        if (i >= RT_WIN) {
            t->bad = 1;
            return;
        }
        t->v[i] = (uint8_t)(v >> (8 * k));
        t->d[i] = 1;
        if (i < t->dlo)
            t->dlo = i;
        if (i >= t->dhi)
            t->dhi = i + 1;
    }
}

static void rt_commit(RtTx *t)
{
    for (uint32_t i = t->dlo; i < t->dhi; i++)
        if (t->d[i])
            wr8(t->c, t->lo + i, t->v[i]);
}

/* MSVCRT's string compare (+0x2a53, and its unaligned path at +0x106e4): the registers as the guest moves them.
 * edx walks s1 (a dword at a time once aligned), ecx walks s2. *same is 1 for equal strings. t->edx is the guest's
 * final edx. Returns 0 when a byte it reads is not mapped. */
static int rt_strcmp(RtTx *t, uint32_t s1, uint32_t s2, int *same)
{
    uint32_t edx = s1, ecx = s2, w;
    uint8_t a, b;
    if (edx & 3)
        goto unaligned;
aligned:
    if (!rt_rd32(t, edx, &w) || !rt_rd8(t, ecx, &b))
        return 0;
    a = (uint8_t)w;                                     /* cmp al,[ecx] */
    if (a != b)
        goto ne;
    if (a == 0)
        goto eq;
    if (!rt_rd8(t, ecx + 1, &b))
        return 0;
    if ((uint8_t)(w >> 8) != b)                         /* cmp ah,[ecx+1] */
        goto ne;
    if (((w >> 8) & 0xff) == 0)
        goto eq;
    if (!rt_rd8(t, ecx + 2, &b))
        return 0;
    if ((uint8_t)(w >> 16) != b)                        /* shr eax,16; cmp al,[ecx+2] */
        goto ne;
    if (((w >> 16) & 0xff) == 0)
        goto eq;
    if (!rt_rd8(t, ecx + 3, &b))
        return 0;
    if ((uint8_t)(w >> 24) != b)                        /* cmp ah,[ecx+3] */
        goto ne;
    ecx += 4;
    edx += 4;
    if ((w >> 24) & 0xff)                               /* or ah,ah; jne aligned */
        goto aligned;
    goto eq;
unaligned:
    if (edx & 1) {                                      /* test edx,1; je word */
        if (!rt_rd8(t, edx, &a))
            return 0;
        edx++;
        if (!rt_rd8(t, ecx, &b))
            return 0;
        if (a != b)
            goto ne;
        ecx++;
        if (a == 0)
            goto eq;
        if (!(edx & 2))                                 /* test edx,2; je aligned */
            goto aligned;
    }
    {                                                   /* the word step: mov ax,[edx]; add edx,2 */
        uint8_t lo, hi;
        if (!rt_rd8(t, edx, &lo) || !rt_rd8(t, edx + 1, &hi))
            return 0;
        edx += 2;
        if (!rt_rd8(t, ecx, &b))
            return 0;
        if (lo != b)
            goto ne;
        if (lo == 0)
            goto eq;
        if (!rt_rd8(t, ecx + 1, &b))
            return 0;
        if (hi != b)
            goto ne;
        if (hi == 0)
            goto eq;
        ecx += 2;
        goto aligned;
    }
eq:
    *same = 1;
    t->edx = edx;
    return 1;
ne:
    *same = 0;
    t->edx = edx;
    return 1;
}

/* GetCompleteObject (MSVCRT+0x18562), for cdOffset 0: complete = p - COL.offset, and edx = cdOffset = 0. Sets *col to
 * the COL (eax-4 of the vtable). Returns 0 for a vbtable (cdOffset != 0) or an unmapped read. */
static int rt_complete(RtTx *t, uint32_t p, uint32_t *complete, uint32_t *col)
{
    uint32_t vt, cl, off, cd;
    if (!rt_rd32(t, p, &vt) || !rt_rd32(t, vt - 4, &cl) || !rt_rd32(t, cl + 4, &off) || !rt_rd32(t, cl + 8, &cd))
        return 0;
    if (cd != 0)
        return 0;
    *complete = p - off;
    *col = cl;
    t->edx = 0;
    return 1;
}

/* PMDtoOffset (MSVCRT+0x18807) with pdisp < 0: its result is mdisp, and its edx is pdisp. pdisp >= 0 reads a
 * vbtable: not modelled, returns 0. */
static int rt_pmd(RtTx *t, uint32_t pmd, uint32_t *off)
{
    uint32_t pdisp, mdisp;
    if (!rt_rd32(t, pmd + 4, &pdisp) || (int32_t)pdisp >= 0)
        return 0;
    if (!rt_rd32(t, pmd, &mdisp))
        return 0;
    t->edx = pdisp;
    *off = mdisp;
    return 1;
}

/* The base search of a single inheritance hierarchy (MSVCRT+0x1857c..0x185d1). Called from the cast with the
 * arguments at [B-0x6c..B-0x5c] (complete, COL, SrcType, offset, TargetType) and the return address at B-0x70, so
 * its ebp is F = B-0x74. Walks the BCD array for a base whose type name equals the target's (pointer equality, or
 * strcmp), and returns the first such BCD whose attributes bit 0 is clear, or 0.
 *     push ebp; mov ebp,esp; push ecx; and [ebp-4],0; push ebx; mov ebx,[ebp+0xc]; push esi; push edi;
 *     mov eax,[ebx+0x10]; cmp [eax+8],0; mov esi,[eax+0xc]; jbe done;
 *     loop: mov edi,[esi]; mov ecx,[ebp+0x18]; mov eax,[edi]; cmp eax,ecx; je same;
 *           add ecx,8; add eax,8; push ecx; push eax; call strcmp (ret 0x780185ae); pop ecx; test eax,eax; pop ecx;
 *           jne next; same: test byte [edi+0x14],1; je found; next: inc [ebp-4]; mov eax,[ebx+0x10];
 *           mov ecx,[ebp-4]; add esi,4; cmp ecx,[eax+8]; jb loop; done: xor eax,eax; ... ret
 *     found: mov eax,edi; ... ret */
static int rt_si(RtTx *t, uint32_t B, uint32_t col, uint32_t attr, uint32_t offset, uint32_t complete,
                 uint32_t target, uint32_t ebx0, uint32_t *bcd)
{
    uint32_t F = B - 0x74, chd, n, slot, bc, tdp, i = 0;
    int same;
    *bcd = 0;
    rt_wr32(t, F, B);                                   /* push ebp */
    rt_wr32(t, F - 4, attr);                            /* push ecx */
    rt_wr32(t, F - 4, 0);                               /* and [ebp-4],0 */
    rt_wr32(t, F - 8, ebx0);                            /* push ebx */
    rt_wr32(t, F - 0xc, offset);                        /* push esi */
    rt_wr32(t, F - 0x10, complete);                     /* push edi */
    if (!rt_rd32(t, col + 0x10, &chd) || !rt_rd32(t, chd + 8, &n) || !rt_rd32(t, chd + 0xc, &slot))
        return 0;
    if (n == 0)
        return 1;
    for (;;) {
        if (!rt_rd32(t, slot, &bc) || !rt_rd32(t, bc, &tdp))
            return 0;
        same = tdp == target;
        if (!same) {
            rt_wr32(t, F - 0x14, target + 8);           /* push ecx */
            rt_wr32(t, F - 0x18, tdp + 8);              /* push eax */
            rt_wr32(t, F - 0x1c, 0x780185aeu);          /* the call's return address */
            if (!rt_strcmp(t, tdp + 8, target + 8, &same))
                return 0;
        }
        if (same) {
            uint8_t at;
            if (!rt_rd8(t, bc + 0x14, &at))
                return 0;
            if (!(at & 1)) {
                *bcd = bc;
                return 1;
            }
        }
        i++;
        rt_wr32(t, F - 4, i);
        slot += 4;
        if (!rt_rd32(t, col + 0x10, &chd) || !rt_rd32(t, chd + 8, &n))
            return 0;
        if (i >= n)
            break;
    }
    return 1;
}

/* The base search of a multiple inheritance hierarchy, non-virtual (MSVCRT+0x185d6..0x186cb). Frame F = B-0x74,
 * as rt_si. The first loop finds a BCD i whose type is the target, then a contained BCD k (k > i, within
 * numContained of i) whose type is SrcType and whose PMD gives the offset; the result is BCD i. Otherwise the
 * second loop returns the first BCD whose type is the target and whose attributes bits 0 and 1 are clear.
 * The strcmp calls return to 0x7801860e (outer), 0x7801863f (contained) and 0x780186a7 (second loop); the PMD
 * call to 0x78018651. Its pushes are at B-0x90 and B-0x94, its return addresses at B-0x98 (F-0x24 for the
 * strcmp, which pushes at F-0x1c and F-0x20). */
static int rt_mi(RtTx *t, uint32_t B, uint32_t col, uint32_t offset, uint32_t complete, uint32_t src,
                 uint32_t target, uint32_t ebx0, uint32_t *bcd)
{
    uint32_t F = B - 0x74, chd, n, slot, bc, tdp, nc, i = 0, j, p8, bk, tdk, where, mdisp;
    int same;
    *bcd = 0;
    rt_wr32(t, F, B);                                   /* push ebp */
    rt_wr32(t, F - 4, 0);                               /* and [ebp-4],0 */
    rt_wr32(t, F - 0x10, ebx0);                         /* push ebx */
    rt_wr32(t, F - 0x14, offset);                       /* push esi */
    rt_wr32(t, F - 0x18, complete);                     /* push edi */
    if (!rt_rd32(t, col + 0x10, &chd) || !rt_rd32(t, chd + 8, &n) || !rt_rd32(t, chd + 0xc, &slot))
        return 0;
    if (n != 0) {
        for (;;) {                                      /* 0x780185f6: the outer loop */
            if (!rt_rd32(t, slot, &bc) || !rt_rd32(t, bc, &tdp))
                return 0;
            same = tdp == target;
            if (!same) {
                rt_wr32(t, F - 0x1c, target + 8);
                rt_wr32(t, F - 0x20, tdp + 8);
                rt_wr32(t, F - 0x24, 0x7801860eu);
                if (!rt_strcmp(t, tdp + 8, target + 8, &same))
                    return 0;
            }
            if (same) {                                 /* 0x78018614 */
                rt_wr32(t, F - 0xc, 0);                 /* and [ebp-0xc],0 */
                p8 = slot + 4;
                rt_wr32(t, F - 8, p8);                  /* lea eax,[edi+4]; mov [ebp-8],eax */
                if (!rt_rd32(t, bc + 4, &nc))
                    return 0;
                if (nc != 0) {
                    j = 0;
                    for (;;) {                          /* 0x78018624: the contained bases */
                        if (!rt_rd32(t, p8, &bk) || !rt_rd32(t, bk, &tdk))
                            return 0;
                        same = tdk == src;
                        if (!same) {
                            rt_wr32(t, F - 0x1c, src + 8);
                            rt_wr32(t, F - 0x20, tdk + 8);
                            rt_wr32(t, F - 0x24, 0x7801863fu);
                            if (!rt_strcmp(t, tdk + 8, src + 8, &same))
                                return 0;
                        }
                        if (same) {                     /* 0x78018645 */
                            where = bk + 8;
                            rt_wr32(t, F - 0x1c, where);
                            rt_wr32(t, F - 0x20, complete);
                            rt_wr32(t, F - 0x24, 0x78018651u);
                            if (!rt_pmd(t, where, &mdisp))
                                return 0;
                            if (mdisp == offset) {      /* 0x780186cb: return esi */
                                *bcd = bc;
                                return 1;
                            }
                        }
                        j++;                            /* 0x78018658 */
                        rt_wr32(t, F - 0xc, j);
                        p8 += 4;
                        rt_wr32(t, F - 8, p8);
                        if (!rt_rd32(t, bc + 4, &nc))
                            return 0;
                        if (j >= nc)
                            break;
                    }
                }
            }
            i++;                                        /* 0x7801866a */
            rt_wr32(t, F - 4, i);
            slot += 4;
            if (!rt_rd32(t, col + 0x10, &chd) || !rt_rd32(t, chd + 8, &n))
                return 0;
            if (i >= n)
                break;
        }
    }
    /* 0x7801867f: the second loop */
    rt_wr32(t, F - 4, 0);
    i = 0;
    if (!rt_rd32(t, col + 0x10, &chd) || !rt_rd32(t, chd + 8, &n) || !rt_rd32(t, chd + 0xc, &slot))
        return 0;
    if (n == 0)
        return 1;
    for (;;) {                                          /* 0x7801868f */
        if (!rt_rd32(t, slot, &bc) || !rt_rd32(t, bc, &tdp))
            return 0;
        same = tdp == target;
        if (!same) {
            rt_wr32(t, F - 0x1c, target + 8);
            rt_wr32(t, F - 0x20, tdp + 8);
            rt_wr32(t, F - 0x24, 0x780186a7u);
            if (!rt_strcmp(t, tdp + 8, target + 8, &same))
                return 0;
        }
        if (same) {
            uint8_t at;
            if (!rt_rd8(t, bc + 0x14, &at))
                return 0;
            if ((at & 3) == 0) {
                *bcd = bc;
                return 1;
            }
        }
        i++;
        rt_wr32(t, F - 4, i);
        slot += 4;
        if (!rt_rd32(t, col + 0x10, &chd) || !rt_rd32(t, chd + 8, &n))
            return 0;
        if (i >= n)
            break;
    }
    return 1;
}

/* __RTDynamicCast (MSVCRT+0x1844e). Returns 1 when it handled the call (the state is as the guest leaves it), 0 when
 * the call must go to the guest (nothing was changed). The arguments are at [esp] = p (inptr, VfDelta, SrcType,
 * TargetType, isReference), the return slot at E = p-4, and ebp = B = E-4. */
static int crt_rtdynamiccast(CPU *c, uint32_t ret, uint32_t base)
{
    (void)base;
    uint32_t p = c->r[ESP];
    uint32_t E = p - 4, B = E - 4;
    RtTx T, *t = &T;
    uint32_t inptr, vfd, src, tgt, isref, prev, result = 0, fl = 0, ebx0 = c->r[EBX], esi0 = c->r[ESI],
             edi0 = c->r[EDI];
    t->c = c;
    t->lo = E - 0x100;
    memset(t->d, 0, sizeof t->d);
    t->dlo = RT_WIN;
    t->dhi = 0;
    t->bad = 0;
    t->edx = c->r[EDX];
    if (!crt_mapped(t->lo, RT_WIN))
        return 0;
    if (!rt_rd32(t, p, &inptr) || !rt_rd32(t, p + 4, &vfd) || !rt_rd32(t, p + 8, &src) ||
        !rt_rd32(t, p + 0xc, &tgt) || !rt_rd32(t, p + 0x10, &isref) || !rt_rd32(t, c->fs_base, &prev))
        return 0;

    /* prologue */
    rt_wr32(t, E, ret);
    rt_wr32(t, B, c->r[EBP]);
    rt_wr32(t, B - 4, 0xffffffffu);                     /* push -1 */
    rt_wr32(t, B - 8, 0x7802fb40u);                     /* push the scope table */
    rt_wr32(t, B - 0xc, 0x7800ef06u);                   /* push __except_handler3 */
    rt_wr32(t, B - 0x10, prev);                         /* push fs:[0] */
    rt_wr32(t, B - 0x50, ebx0);
    rt_wr32(t, B - 0x54, esi0);
    rt_wr32(t, B - 0x58, edi0);
    rt_wr32(t, B - 0x18, B - 0x58);                     /* mov [ebp-0x18],esp */

    if (inptr == 0) {                                   /* test esi,esi; jne: NULL returns 0 */
        result = 0;
        fl = 0;
    } else {
        uint32_t complete, col, adj, offset, chd, attr, bcd = 0, where, mdisp;
        rt_wr32(t, B - 4, 0);                           /* and [ebp-4],0 */
        rt_wr32(t, B - 0x5c, inptr);                    /* push esi (GetCompleteObject's argument) */
        rt_wr32(t, B - 0x60, 0x78018496u);              /* call 0x78018562: return address */
        if (!rt_complete(t, inptr, &complete, &col))
            return 0;
        rt_wr32(t, B - 0x2c, complete);                 /* mov edi,eax; mov [ebp-0x2c],edi */
        rt_wr32(t, B - 0x24, col);                      /* mov [ebp-0x24],eax */
        adj = inptr - vfd;                              /* sub esi,[ebp+0xc]; mov [ebp+8],esi */
        rt_wr32(t, B + 8, adj);
        offset = adj - complete;                        /* sub esi,edi; mov [ebp-0x28],esi */
        rt_wr32(t, B - 0x28, offset);
        if (!rt_rd32(t, col + 0x10, &chd) || !rt_rd32(t, chd + 4, &attr))
            return 0;
        if (attr & 2)                                   /* virtual inheritance: not modelled */
            return 0;
        rt_wr32(t, B - 0x5c, tgt);                      /* the five arguments: [ebp+0x14], esi, [ebp+0x10], eax, edi */
        rt_wr32(t, B - 0x60, offset);
        rt_wr32(t, B - 0x64, src);
        rt_wr32(t, B - 0x68, col);
        rt_wr32(t, B - 0x6c, complete);
        if (attr & 1) {                                 /* 0x780184e9: multiple inheritance, call 0x780185d6 */
            rt_wr32(t, B - 0x70, 0x780184fcu);
            if (!rt_mi(t, B, col, offset, complete, src, tgt, ebx0, &bcd))
                return 0;
        } else {                                        /* call 0x7801857c */
            rt_wr32(t, B - 0x70, 0x780184c8u);
            if (!rt_si(t, B, col, attr, offset, complete, tgt, ebx0, &bcd))
                return 0;
        }
        rt_wr32(t, B - 0x1c, bcd);                      /* mov [ebp-0x1c],eax */
        if (bcd == 0) {                                 /* 0x78018505 */
            rt_wr32(t, B - 0x20, 0);
            if (isref)                                  /* bad_cast: not modelled */
                return 0;
            result = 0;
        } else {                                        /* add eax,8; push eax; push edi; call PMDtoOffset */
            where = bcd + 8;
            rt_wr32(t, B - 0x5c, where);
            rt_wr32(t, B - 0x60, complete);
            rt_wr32(t, B - 0x64, 0x780184dcu);
            if (!rt_pmd(t, where, &mdisp))
                return 0;
            result = mdisp + complete;                  /* add eax,edi */
            rt_wr32(t, B - 0x20, result);               /* mov [ebp-0x20],eax */
        }
        rt_wr32(t, B - 4, 0xffffffffu);                 /* or dword [ebp-4],0xffffffff */
        fl = 0xffffffffu;
    }
    if (t->bad)
        return 0;
    rt_commit(t);
    c->r[EAX] = result;
    c->r[ECX] = prev;                                   /* mov ecx,[ebp-0x10] */
    c->r[EDX] = t->edx;
    flags_logic32(c, fl);
    return 1;
}

/* type_info::name (MSVCRT+0xb20f, thiscall), the cached path only ([ecx+4], the undecorated name, is set):
 *     push edi; mov edi, ecx; cmp dword [edi+4], 0; jne cached; ... [cached:] mov eax, [edi+4]; pop edi; ret
 * The first call for a type undecorates the name and allocates it: that is left to the guest. */
static int crt_typeinfo_name(CPU *c, uint32_t ret, uint32_t base)
{
    (void)base;
    uint32_t v = rd32(c, c->r[ECX] + 4);
    if (v == 0)
        return 0;
    uint32_t e = c->r[ESP] - 4;
    wr32(c, e, ret);
    wr32(c, e - 4, c->r[EDI]);
    flags_sub32(c, v, 0);
    c->r[EAX] = v;
    return 1;
}

/* floor (MSVCRT+0x2bbf0), for a finite argument x (its exponent is not 0x7ff), when the result is x or the caller's
 * control word masks the precision exception (bit 5); otherwise the guest's _except1 path. The guest, with B = ebp
 * (E = esp - 4 at entry, the return slot, B = E - 4) and _ctrlfp(new, mask) at 0x7802d278:
 *     push ebp; mov ebp,esp; push ecx; push ecx; push ebx; push esi; mov esi,0xffff;
 *     push esi; push [0x7803ae14]; call _ctrlfp (ret 0x7802bc08)    ; cw = [0x7803ae14] (RC down), eax = sext(old)
 *     fld qword [ebp+8]; pop ecx; mov ebx,eax; mov eax,[ebp+0xe]; pop ecx; push ecx; and ax,0x7ff0; push ecx;
 *     cmp ax,0x7ff0; fstp qword [esp]; jne finite
 *     finite: call 0x7802d2f1 (ret 0x7802bc85)                       ; fld [arg]; frndint; fstp [l]; fld [l]
 *     fstp qword [ebp-8]; fld qword [ebp-8]; fcomp qword [ebp+8]; pop ecx; pop ecx; fnstsw ax; sahf; jne differs
 *     same: push esi; push ebx; call _ctrlfp (ret 0x7802bc9c)        ; the caller's control word again
 *     fld qword [ebp-8]; pop ecx; pop ecx; pop esi; pop ebx; leave; ret
 *     differs: test bl,0x20; jne same; <_except1>
 * _ctrlfp: push ebp; mov ebp,esp; push ecx; fnstcw [ebp-4]; mov eax,[ebp+0xc]; mov ecx,eax; and eax,[ebp+8];
 *     not ecx; and ecx,[ebp-4]; or ecx,eax; mov [ebp+0xc],ecx; fldcw [ebp+0xc]; movsx eax,word [ebp-4]; leave; ret
 * The final values of the slots it writes: ret at E, ebp at B, the result r at B-8 (over the two ecx pushes), ebx
 * at B-0xc, esi at B-0x10, the second _ctrlfp's new value at B-0x14, sext(old cw) at B-0x18, its return address at
 * B-0x1c, B at B-0x20, at B-0x28 the low dword of r (0x7802d2f1's local) and at B-0x24 the second _ctrlfp's push of
 * ecx with the control word stored over its low half. That ecx is x's high dword: the pops after fcomp read the
 * copy of x that fstp [esp] left. Registers: eax = sext(the floor control word), ecx = x's high dword's high half
 * | old cw, ebx, esi, ebp restored; flags of the second _ctrlfp's or. x87: r pushed, C0 C2 C3
 * from fcomp (r, x), the caller's control word. frndint is rounding to an integer under the new RC, exact. */
static int crt_floor(CPU *c, uint32_t ret, uint32_t base)
{
    uint32_t E = c->r[ESP] - 4, B = E - 4;
    if ((rd16(c, B + 0xe) & 0x7ff0u) == 0x7ff0u)     /* infinity or NaN: _except1 */
        return 0;
    uint16_t old = c->cw, cw1 = (uint16_t)rd32(c, base + 0x3ae14);
    double x = x87_ld_f64(c, B + 8);
    double r = x87_rint(x, (cw1 >> 10) & 3u);
    if (r != x && !(old & 0x20))                     /* precision exception unmasked: _except1 */
        return 0;
    uint32_t hi = rd32(c, B + 0xc) & 0xffff0000u, ecx2 = hi | old;   /* ecx popped from x's high dword */
    wr32(c, E, ret);
    wr32(c, B, c->r[EBP]);
    x87_st_f64(c, B - 8, r);
    wr32(c, B - 0xc, c->r[EBX]);
    wr32(c, B - 0x10, c->r[ESI]);
    wr32(c, B - 0x14, ecx2);
    wr32(c, B - 0x18, (uint32_t)(int32_t)(int16_t)old);
    wr32(c, B - 0x1c, base + 0x2bc9cu);
    wr32(c, B - 0x20, B);
    x87_st_f64(c, B - 0x28, r);
    wr32(c, B - 0x24, hi | cw1);
    x87_push(c, r);
    x87_compare(c, r, x);
    x87_ldcw(c, old);
    c->r[EAX] = (uint32_t)(int32_t)(int16_t)cw1;
    c->r[ECX] = ecx2;
    flags_logic32(c, ecx2);
    return 1;
}

/* The biased exponent of a double as the 80-bit register holds it (qemu's EXPD): 0 for zero, the true exponent
 * + 16383 otherwise (a double subnormal is normalised in the 80-bit format). */
static int crt_expd(double v)
{
    return v == 0.0 ? 0 : ilogb(v) + 16383;
}

/* fprem as the reference emulator computes it (qemu 5 helper_fprem, on host doubles; the operands and the result are
 * doubles, so its floatx80 conversions are exact). ST0 = ST0 rem ST1, the condition bits as qemu sets them. The
 * expressions are qemu's, in the same form. The emulator runs with the host rounding to nearest whatever RC is
 * (runtime.c resets it before guest code runs), so the caller computes this under round-to-nearest. */
static void crt_fprem(CPU *c)
{
    double st0 = x87_rd(c, 0), st1 = x87_rd(c, 1), dblq, fpsrcop, fptemp;
    int expdif;
    long long q;
    if (isinf(st0) || isnan(st0) || isnan(st1) || st1 == 0.0) {
        x87_wr(c, 0, NAN);
        c->sw &= (uint16_t)~0x4700u;
        return;
    }
    fpsrcop = st0;
    fptemp = st1;
    expdif = crt_expd(st0) - crt_expd(st1);
    if (expdif < 0) {
        c->sw &= (uint16_t)~0x4700u;
        return;
    }
    if (expdif < 53) {
        dblq = fpsrcop / fptemp;
        dblq = (dblq < 0.0) ? ceil(dblq) : floor(dblq);
        st0 = fpsrcop - fptemp * dblq;
        q = (dblq < 0.0) ? (long long)(-dblq) : (long long)dblq;
        c->sw &= (uint16_t)~0x4700u;
        c->sw |= (uint16_t)((q & 0x4) << (8 - 2));
        c->sw |= (uint16_t)((q & 0x2) << (14 - 1));
        c->sw |= (uint16_t)((q & 0x1) << (9 - 0));
    } else {
        int N = 32 + (expdif % 32);
        c->sw |= 0x400u;
        fptemp = pow(2.0, (double)(expdif - N));
        fpsrcop = (st0 / st1) / fptemp;
        fpsrcop = (fpsrcop < 0.0) ? -(floor(fabs(fpsrcop))) : floor(fpsrcop);
        st0 -= (st1 * fpsrcop * fptemp);
    }
    x87_wr(c, 0, st0);
}

/* _CIfmod (MSVCRT+0x28d47): ST0 = fmod(ST1, ST0), popping one, for a divisor fxam calls normal (not zero,
 * infinity, NaN or empty) and a normal or zero dividend (a zero takes the class table's handler 0x7802c1a5, which
 * pops both and loads +0). Declined: [0x7803b718] != 0, the P5 fprem workaround ([0x78037c0c] == 1), and an
 * unmasked precision exception that is pending (the error paths). The guest (B = ebp = E - 4):
 *     mov edx,0x7803a690; push ebp; mov ebp,esp; add esp,-0x2d0; push ebx; fnstcw [ebp-0xa4];
 *     cmp [0x78039298],0; je (fxch; fst qword [ebp-0x86]; fxch; fst qword [ebp-0x7e]);
 *     call 0x7802c115 (ret 0x78028bdd): bx = 0x133f, or when [edx+0xe] == 5 the caller's cw with PC 10 and
 *         every exception masked; mov [ebp-0xa2],bx; fldcw [ebp-0xa2]; mov ebx,0x7803ae3c; fxam;
 *         mov [ebp-0x94],edx; fnstsw [ebp-0xa0]; mov byte [ebp-0x90],0; fxch; mov cl,[ebp-0x9f]; fxam;
 *         fnstsw [ebp-0xa0]; fxch; mov ch,[ebp-0x9f]; <class of each operand by xlat>; movsx eax,al;
 *         and ecx,0x404; mov ebx,edx; add ebx,eax; add ebx,0x10; jmp [ebx]
 *     both normal (eax 0): fxch; [loop:] cmp [0x78037c0c],1; fprem; fnstsw ax; sahf; jp loop; fstp st(1); ret
 *     or byte [ebp-0x2c8],3; call 0x7802c436 (ret 0x78028be9): cmp [0x7803b718],0; fst qword [ebp-0x2d0];
 *         mov al,[ebp-0x90]; or al,al; je; mov ax,[ebp-0xa4]; and ax,0x20; jne restore;
 *         fnstsw ax; and ax,0x20; je restore; <error>; restore: fldcw [ebp-0xa4]; ret
 *     pop ebx; leave; ret
 * So eax = 0x20 when the caller masks the precision exception, else 0, with the flags of that and; ecx holds the
 * operands' signs (0x400 for ST1, 4 for ST0); edx = 0x7803a690; ebx and ebp are restored. */
static int crt_cifmod(CPU *c, uint32_t ret, uint32_t base)
{
    unsigned p0 = c->top & 7u, p1 = (c->top + 1u) & 7u;
    double y = x87_rd(c, 0), x = x87_rd(c, 1);
    if ((c->tag & ((1u << p0) | (1u << p1))) || !isfinite(x) || !isfinite(y) || y == 0.0)
        return 0;
    if (rd32(c, base + 0x3b718u) != 0 || rd32(c, base + 0x37c0cu) == 1)
        return 0;
    uint16_t cw0 = c->cw;
    if (!(cw0 & 0x20) && (c->sw & 0x20))
        return 0;
    uint32_t E = c->r[ESP] - 4, B = E - 4, tab = base + 0x3a690u;
    uint16_t cw1 = 0x133f;
    if (rd8(c, tab + 0xe) == 5)
        cw1 = (uint16_t)(((((cw0 >> 8) | 2u) & 0xfeu) << 8) | 0x3fu);
    wr32(c, E, ret);
    wr32(c, B, c->r[EBP]);
    wr32(c, B - 0x2d4, c->r[EBX]);
    wr16(c, B - 0xa4, cw0);
    if (rd32(c, base + 0x39298u) == 0) {
        x87_st_f64(c, B - 0x86, x);
        x87_st_f64(c, B - 0x7e, y);
    }
    wr16(c, B - 0xa2, cw1);
    x87_ldcw(c, cw1);
    wr32(c, B - 0x94, tab);
    wr8(c, B - 0x90, 0);
    x87_xch(c, 1);                                   /* fxch; fxam (ST1's value); its status at [ebp-0xa0] */
    x87_fxam(c);
    wr16(c, B - 0xa0, x87_status(c));
    x87_xch(c, 1);
    double r = 0.0;
    if (x == 0.0) {                                  /* 0x7802c1a5: fstp st(0); fstp st(0); fldz; ret */
        x87_pop(c);
        x87_pop(c);
        x87_push(c, r);
    } else {
        x87_xch(c, 1);                               /* the handler's fxch: ST0 = x, ST1 = y */
        fesetround(FE_TONEAREST);
        do
            crt_fprem(c);
        while (c->sw & 0x400u);                      /* fnstsw ax; sahf; jp loop (PF = C2) */
        r = x87_rd(c, 0);
        x87_wr(c, 1, r);                             /* fstp st(1) */
        x87_pop(c);
    }
    wr8(c, B - 0x2c8, (uint8_t)(rd8(c, B - 0x2c8) | 3u));
    wr32(c, B - 0x2d8, base + 0x28be9u);
    x87_st_f64(c, B - 0x2d0, r);
    x87_ldcw(c, cw0);
    uint32_t eax = (cw0 & 0x20) ? 0x20u : 0u;
    c->r[EAX] = eax;
    flags_logic16(c, eax);
    c->r[ECX] = (signbit(x) ? 0x400u : 0u) | (signbit(y) ? 4u : 0u);
    c->r[EDX] = tab;
    return 1;
}

static const struct {
    const char *name;
    crt_fn fn;
} CRT_TAB[] = {
    {"?name@type_info@@QBEPBDXZ", crt_typeinfo_name},
    {"floor", crt_floor},
    {"_CIfmod", crt_cifmod},
    {"_ftol", crt_ftol},
    {"tolower", crt_tolower},
    {"_stricmp", crt_stricmp},
    {"_strnicmp", crt_strnicmp},
    {"__RTDynamicCast", crt_rtdynamiccast},
};
#define CRT_N (sizeof CRT_TAB / sizeof CRT_TAB[0])

static uint32_t g_crt_va[CRT_N], g_crt_base[CRT_N];
static uint64_t g_crt_count[CRT_N];

int lift_crt_bind(const char *name, uint32_t va, uint32_t base)
{
    for (unsigned i = 0; i < CRT_N; i++)
        if (strcmp(CRT_TAB[i].name, name) == 0) {
            g_crt_va[i] = va;
            g_crt_base[i] = base;
            g_crt_count[i] = 0;
            lift_call_cache_clear();
            return (int)i;
        }
    return -1;
}

uint32_t lift_crt_counts(uint64_t *out, uint32_t cap)
{
    for (unsigned i = 0; i < CRT_N && i < cap; i++)
        out[i] = g_crt_count[i];
    return (uint32_t)CRT_N;
}

const char *lift_crt_name(uint32_t i)
{
    return i < CRT_N ? CRT_TAB[i].name : NULL;
}

/* The helper bound to target (the first, as lift_crt_call finds it), or -1. */
int lift_crt_index(uint32_t target)
{
    for (unsigned i = 0; i < CRT_N; i++)
        if (g_crt_va[i] == target && target)
            return (int)i;
    return -1;
}

/* lift_crt_call for a helper index from lift_crt_index. */
int lift_crt_call_index(CPU *c, int i, uint32_t ret)
{
    if (!CRT_TAB[i].fn(c, ret, g_crt_base[i]))
        return 0;
    g_crt_count[i]++;
    return 1;
}

int lift_crt_call(CPU *c, uint32_t target, uint32_t ret)
{
    for (unsigned i = 0; i < CRT_N; i++)
        if (g_crt_va[i] == target && target) {
            if (!CRT_TAB[i].fn(c, ret, g_crt_base[i]))
                return 0;
            g_crt_count[i]++;
            return 1;
        }
    return 0;
}
