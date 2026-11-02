/* RaiseException and RtlUnwind in C (E3, docs/m6-emu-removal.md): the OS half of Win32 SEH for lifted code, without
 * the emulator. A port of emu/mpemu.py raise_exception / rtl_unwind (the Python coroutines, M2): pass 1 walks the
 * fs:[0] registration chain calling each handler, RtlUnwind calls them again with EH_UNWINDING and unlinks the frames.
 * The frame handlers are the guest's own (MSVCRT __CxxFrameHandler, _except_handler3), lifted; they reach the catch or
 * __except continuation through a transfer (x86c.DEAD_FRAMES): after such a handler call the guest ESP is above the
 * dispatcher's entry, its host frame is dead, and it returns at once like a lifted function does.
 *
 * Served from runtime.c hle_direct (lift_seh_direct) once lift_seh_bind gave the stub indexes; the return address is
 * at [esp] and the stdcall arguments above it, as for every direct HLE call. While a handler runs, the dispatcher's own
 * registration record is at the head of fs:[0] (real Windows does this, and MSVC's _UnwindNestedFrames relies on it,
 * m2-progress.md); its handler is the ExceptionNestedHandler stub, answered here without a call.
 *
 * The EXCEPTION_RECORD, CONTEXT and dispatcher context live on the guest stack below the call (Windows puts them on the
 * same stack too), and the handlers run below them: nothing is allocated from the guest heap (the Python version
 * leaks a record and a context per raise).
 *
 * Not handled in C (returns 0, so Python's handler runs as before and reports it): an exception no frame handles
 * (Python walks the chain again and reports it unhandled), a nested or collided disposition, and a guest stack out of
 * range. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"

#define EH_NONCONTINUABLE 0x1u
#define EH_UNWINDING 0x2u
#define EH_EXIT_UNWIND 0x4u
#define STATUS_UNWIND 0xC0000027u
#define CONTEXT_SIZE 716u
#define CHAIN_END 0xFFFFFFFFu
#define CHAIN_MAX 256

static uint32_t g_idx_raise = UINT32_MAX, g_idx_unwind = UINT32_MAX;
static uint32_t g_nested_va;                     /* the ExceptionNestedHandler stub's address */
static uint32_t g_teb, g_stack_lo, g_stack_hi;   /* fs:[0] lives at g_teb; the guest stack range for frames */
static uint64_t g_raises, g_unwinds, g_handled;
static int g_depth, g_depth_max;

/* Host stack guard (lift_stack_check): each exception caught in a frame that stays live runs its continuation on top
 * of the host stack until that frame returns (x86c.DEAD_FRAMES), and a guest longjmp does the same. A loop that
 * throws every iteration would grow the host stack without bound: stop with a message well before the OS does. */
static char *g_host_floor;

void lift_stack_guard_init(void)
{
    pthread_t self = pthread_self();
    char *top = (char *)pthread_get_stackaddr_np(self);
    size_t size = pthread_get_stacksize_np(self);
    g_host_floor = top - size + (size / 8 > (1u << 20) ? (1u << 20) : size / 8);
}

void lift_stack_check(uint32_t eip)
{
    char probe;
    if (g_host_floor && &probe < g_host_floor) {
        fprintf(stderr, "lifted code: the host stack is nearly exhausted at a transfer to %08x (nested "
                "continuations: a guest loop that throws or longjmps without returning)\n", eip);
        abort();
    }
}

void lift_seh_bind(uint32_t idx_raise, uint32_t idx_unwind, uint32_t nested_va, uint32_t teb, uint32_t stack_lo,
                   uint32_t stack_hi)
{
    g_idx_raise = idx_raise;
    g_idx_unwind = idx_unwind;
    g_nested_va = nested_va;
    g_teb = teb;
    g_stack_lo = stack_lo;
    g_stack_hi = stack_hi;
    if (!g_host_floor)
        lift_stack_guard_init();
}

/* raises, unwinds, raises handled in C, the deepest nesting of dispatches in progress */
void lift_seh_stats(uint64_t *out)
{
    out[0] = g_raises;
    out[1] = g_unwinds;
    out[2] = g_handled;
    out[3] = (uint64_t)g_depth_max;
}

static int in_stack(uint32_t a)
{
    return a >= g_stack_lo && a < g_stack_hi;
}

/* The x86 CONTEXT a handler sees (CONTEXT_FULL | floating point), Eip/Esp as the caller will see them. */
static void capture_context(CPU *c, uint32_t ctx, uint32_t eip, uint32_t esp, uint32_t eax)
{
    NOTE_WRITE(c, ctx, CONTEXT_SIZE);
    memset(MEM(c, ctx), 0, CONTEXT_SIZE);
    wr32(c, ctx, 0x1003Fu);
    wr32(c, ctx + 28, c->cw);
    wr32(c, ctx + 156, c->r[EDI]);
    wr32(c, ctx + 160, c->r[ESI]);
    wr32(c, ctx + 164, c->r[EBX]);
    wr32(c, ctx + 168, c->r[EDX]);
    wr32(c, ctx + 172, c->r[ECX]);
    wr32(c, ctx + 176, eax);
    wr32(c, ctx + 180, c->r[EBP]);
    wr32(c, ctx + 184, eip);
    wr32(c, ctx + 188, 0x1B);
    wr32(c, ctx + 192, 0x202);
    wr32(c, ctx + 196, esp);
    wr32(c, ctx + 200, 0x23);
}

/* Push the dispatcher's registration record at reg and make it the head of fs:[0]. */
static void push_dispatcher_frame(CPU *c, uint32_t reg)
{
    wr32(c, reg, rd32(c, g_teb));
    wr32(c, reg + 4, g_nested_va);
    wr32(c, g_teb, reg);
}

/* Continue the guest at eip with the current registers (ESP already set) when that is not simply this call's return:
 * a transfer, as a lifted `jmp reg` makes one (the target's lifted function runs on top; the frame that owns it returns
 * through the dead frames). */
static void transfer(CPU *c, uint32_t eip)
{
    lift_jump(c, eip);
}

/* Call handler(rec, frame, ctx, dc) (cdecl) with ESP at sp. Returns the disposition, or -1 when the call transferred
 * past the dispatcher (the guest ESP is above entry_sp: this frame is dead). */
static int call_handler(CPU *c, uint32_t handler, uint32_t sp, uint32_t rec, uint32_t frame, uint32_t ctx,
                        uint32_t dc, uint32_t entry_sp, uint32_t ret)
{
    if (handler == g_nested_va)        /* ExceptionNestedHandler: ContinueSearch during an unwind, nested otherwise */
        return (rd32(c, rec + 4) & (EH_UNWINDING | EH_EXIT_UNWIND)) ? 1 : 2;
    c->r[ESP] = sp;
    push32(c, dc);
    push32(c, ctx);
    push32(c, frame);
    push32(c, rec);
    lift_call_ret(c, handler, ret);
    if (c->r[ESP] > entry_sp)
        return -1;
    c->r[ESP] += 16;                   /* cdecl: the dispatcher pops the arguments */
    return (int)c->r[EAX];
}

/* RaiseException(code, flags, nargs, args), stdcall. [sp0] is the return address. */
static int seh_raise(CPU *c)
{
    uint32_t sp0 = c->r[ESP], ret = rd32(c, sp0);
    uint32_t code = rd32(c, sp0 + 4), flags = rd32(c, sp0 + 8), nargs = rd32(c, sp0 + 12), args = rd32(c, sp0 + 16);
    if (!in_stack(sp0) || !in_stack(sp0 - 0x800))
        return 0;
    if (nargs > 15)
        nargs = 15;
    /* layout below the call: dispatcher record sp0-0x20, record sp0-0x80 (80), dc sp0-0xa0, context sp0-0x3a0 */
    uint32_t reg = sp0 - 0x20, rec = sp0 - 0x80, dc = sp0 - 0xa0, ctx = sp0 - 0x3a0, hsp = (sp0 - 0x400) & ~15u;
    wr32(c, rec, code);
    wr32(c, rec + 4, flags);
    wr32(c, rec + 8, 0);
    wr32(c, rec + 12, ret);
    wr32(c, rec + 16, nargs);
    for (uint32_t i = 0; i < nargs; i++)
        wr32(c, rec + 20 + 4 * i, args ? rd32(c, args + 4 * i) : 0);
    capture_context(c, ctx, ret, sp0 + 20, c->r[EAX]);
    NOTE_WRITE(c, dc, 32);
    memset(MEM(c, dc), 0, 32);
    uint32_t saved_regs[8];
    memcpy(saved_regs, c->r, sizeof saved_regs);
    g_raises++;
    if (++g_depth > g_depth_max)
        g_depth_max = g_depth;
    uint32_t frame = rd32(c, g_teb);
    for (int guard = 0; frame != CHAIN_END && in_stack(frame) && guard < CHAIN_MAX; guard++) {
        uint32_t handler = rd32(c, frame + 4);
        push_dispatcher_frame(c, reg);
        int disp = call_handler(c, handler, hsp, rec, frame, ctx, dc, sp0, ret);
        if (disp < 0) {                /* the handler transferred to a continuation, which ran and returned past us */
            g_depth--;
            g_handled++;
            return 1;
        }
        wr32(c, g_teb, rd32(c, reg));  /* handler returned: the dispatcher's record is popped */
        if (disp == 0) {               /* ExceptionContinueExecution: resume from the (maybe edited) context */
            if (flags & EH_NONCONTINUABLE)
                break;
            c->r[EDI] = rd32(c, ctx + 156);
            c->r[ESI] = rd32(c, ctx + 160);
            c->r[EBX] = rd32(c, ctx + 164);
            c->r[EDX] = rd32(c, ctx + 168);
            c->r[ECX] = rd32(c, ctx + 172);
            c->r[EAX] = rd32(c, ctx + 176);
            c->r[EBP] = rd32(c, ctx + 180);
            uint32_t eip = rd32(c, ctx + 184);
            c->r[ESP] = rd32(c, ctx + 196);
            g_depth--;
            g_handled++;
            if (eip != ret || c->r[ESP] != sp0 + 20)
                transfer(c, eip);      /* the context was edited: continue there */
            return 1;
        }
        if (disp != 1)                 /* nested or collided: Python's handler reports it */
            break;
        frame = rd32(c, frame);
    }
    /* no handler took it (or a disposition C does not handle): hand it to Python with the state as it was */
    memcpy(c->r, saved_regs, sizeof saved_regs);
    c->r[ESP] = sp0;
    g_depth--;
    return 0;
}

/* RtlUnwind(target, target_ip, record, retval), stdcall. */
static int seh_unwind(CPU *c)
{
    uint32_t sp0 = c->r[ESP], ret = rd32(c, sp0);
    uint32_t target = rd32(c, sp0 + 4), target_ip = rd32(c, sp0 + 8), record = rd32(c, sp0 + 12);
    uint32_t retval = rd32(c, sp0 + 16);
    if (!in_stack(sp0) || !in_stack(sp0 - 0x800))
        return 0;
    uint32_t reg = sp0 - 0x20, own = sp0 - 0x80, dc = sp0 - 0xa0, ctx = sp0 - 0x3a0, hsp = (sp0 - 0x400) & ~15u;
    if (!record) {
        record = own;
        wr32(c, record, STATUS_UNWIND);
        wr32(c, record + 4, 0);
        wr32(c, record + 8, 0);
        wr32(c, record + 12, ret);
        wr32(c, record + 16, 0);
    }
    uint32_t saved_flags = rd32(c, record + 4);
    wr32(c, record + 4, saved_flags | EH_UNWINDING | (target ? 0 : EH_EXIT_UNWIND));
    capture_context(c, ctx, ret, sp0 + 20, retval);
    NOTE_WRITE(c, dc, 32);
    memset(MEM(c, dc), 0, 32);
    g_unwinds++;
    uint32_t frame = rd32(c, g_teb);
    for (int guard = 0; frame != CHAIN_END && frame != target && in_stack(frame) && guard < CHAIN_MAX; guard++) {
        uint32_t handler = rd32(c, frame + 4);
        push_dispatcher_frame(c, reg);
        if (call_handler(c, handler, hsp, record, frame, ctx, dc, sp0, ret) < 0)
            return 1;                  /* an unwind handler transferred (not seen in MSVC code): we are dead */
        uint32_t nxt = rd32(c, frame);
        wr32(c, g_teb, nxt);           /* the frame is gone once its handler has run */
        frame = nxt;
    }
    wr32(c, record + 4, saved_flags);
    /* RtlUnwind continues at TargetIp (normally the instruction after its call) with EAX = ReturnValue */
    c->r[EAX] = retval;
    c->r[ESP] = sp0 + 20;
    uint32_t eip = target_ip ? target_ip : ret;
    if (eip != ret)
        transfer(c, eip);
    return 1;
}

int lift_seh_direct(CPU *c, uint32_t idx)
{
    if (idx == g_idx_raise)
        return seh_raise(c);
    if (idx == g_idx_unwind)
        return seh_unwind(c);
    return 0;
}
