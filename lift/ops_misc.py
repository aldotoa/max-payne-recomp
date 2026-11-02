"""Odd instructions (M5): cpuid, rdtsc, pushad/popad, pushfd/popfd, MMX movq/emms, int, orps.

Handled here:
  cpuid          -> lift_cpuid(c)           (runtime, lift/runtime/misc.c, same table as Unicorn)
  rdtsc          -> lift_rdtsc(c)           (runtime, monotonic; not the emulator's value)
  pushal/pushad  -> 8 dwords, esp - 32      (pushes the ORIGINAL esp)
  popal/popad    -> 8 dwords, esp slot skipped
  pushaw/popaw   -> the 16-bit forms (0x66 60 / 0x66 61). The game's code uses these, not the
                    32-bit forms: they push and pop 16-bit words and popaw keeps the high halves.
  xlatb          -> al = byte [ebx + al]   (flat model: a segment prefix is rejected)
  pushfd         -> EFLAGS built from the flag bytes, bit 1, and lift_eflags_sys (misc.c): the bits CPU has no
                    field for (TF, IF, IOPL, NT, AC, ID) as the last popfd left them, 0 before any (Unicorn's
                    default: IF clear, nothing else set until popfd).
  popfd          -> the flag bytes from the popped value, the other kept bits into lift_eflags_sys (E5: Unicorn
                    keeps ID, which is how rlmfc's determineProcessorCaps detects cpuid; the native host runs it).
  orps x, x      -> nothing (the same register on both sides changes nothing: determineProcessorCaps' SSE probe).
Rejected (emulator-only): int, other orps forms (an SSE op with no xmm state in CPU), and the xmm forms
of movq.

MMX (CPU.mm, see lift/runtime/cpu.h): movq mm,m64 / movq m64,mm / movq mm,mm and emms. movd is not
handled: nothing the M5 targets (R_Memory::set/copy) uses it.
"""
import x86c
from x86c import Reject, X86_OP_MEM, X86_OP_REG, _ops, _opsize, ea, handler


@handler("cpuid")
def h_cpuid(ctx, ins):
    _ops(ins, 0)
    return ["lift_cpuid(c);"]


@handler("xlatb", "xlat")
def h_xlatb(ctx, ins):
    if any(p in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65) for p in ins.prefix) or ins.addr_size != 4:
        raise Reject("xlatb with a segment or address-size prefix")
    return ["c->r[EAX] = (c->r[EAX] & ~0xffu) | rd8(c, c->r[EBX] + (c->r[EAX] & 0xffu));"]


@handler("rdtsc")
def h_rdtsc(ctx, ins):
    _ops(ins, 0)
    return ["lift_rdtsc(c);"]


@handler("pushal", "pushad")
def h_pushad(ctx, ins):
    _ops(ins, 0)
    return ["{ uint32_t sp = c->r[ESP]; uint32_t v[8] = {c->r[EAX], c->r[ECX], c->r[EDX], "
            "c->r[EBX], sp, c->r[EBP], c->r[ESI], c->r[EDI]};",
            "    for (int i = 0; i < 8; i++) wr32(c, sp - 4u * (uint32_t)(i + 1), v[i]);",
            "    c->r[ESP] = sp - 32u; }"]


@handler("popal", "popad")
def h_popad(ctx, ins):
    _ops(ins, 0)
    return ["{ uint32_t sp = c->r[ESP];",
            "    c->r[EDI] = rd32(c, sp);",
            "    c->r[ESI] = rd32(c, sp + 4u);",
            "    c->r[EBP] = rd32(c, sp + 8u);",
            "    c->r[EBX] = rd32(c, sp + 16u);",
            "    c->r[EDX] = rd32(c, sp + 20u);",
            "    c->r[ECX] = rd32(c, sp + 24u);",
            "    c->r[EAX] = rd32(c, sp + 28u);",
            "    c->r[ESP] = sp + 32u; }"]


@handler("pushaw")
def h_pushaw(ctx, ins):
    _ops(ins, 0)
    return ["{ uint32_t sp = c->r[ESP]; uint16_t v[8] = {(uint16_t)c->r[EAX], (uint16_t)c->r[ECX], "
            "(uint16_t)c->r[EDX], (uint16_t)c->r[EBX], (uint16_t)sp, (uint16_t)c->r[EBP], "
            "(uint16_t)c->r[ESI], (uint16_t)c->r[EDI]};",
            "    for (int i = 0; i < 8; i++) wr16(c, sp - 2u * (uint32_t)(i + 1), v[i]);",
            "    c->r[ESP] = sp - 16u; }"]


@handler("popaw")
def h_popaw(ctx, ins):
    _ops(ins, 0)
    # 16-bit destinations: the high halves of the registers are kept
    return ["{ uint32_t sp = c->r[ESP];",
            "    c->r[EDI] = (c->r[EDI] & 0xffff0000u) | rd16(c, sp);",
            "    c->r[ESI] = (c->r[ESI] & 0xffff0000u) | rd16(c, sp + 2u);",
            "    c->r[EBP] = (c->r[EBP] & 0xffff0000u) | rd16(c, sp + 4u);",
            "    c->r[EBX] = (c->r[EBX] & 0xffff0000u) | rd16(c, sp + 8u);",
            "    c->r[EDX] = (c->r[EDX] & 0xffff0000u) | rd16(c, sp + 10u);",
            "    c->r[ECX] = (c->r[ECX] & 0xffff0000u) | rd16(c, sp + 12u);",
            "    c->r[EAX] = (c->r[EAX] & 0xffff0000u) | rd16(c, sp + 14u);",
            "    c->r[ESP] = sp + 16u; }"]


@handler("pushfd")
def h_pushfd(ctx, ins):
    _ops(ins, 0)
    return ["push32(c, (uint32_t)(0x2u | lift_eflags_sys | c->cf | (c->pf << 2) | (c->af << 4) | (c->zf << 6) | "
            "(c->sf << 7) | (c->df << 10) | (c->of << 11)));"]


@handler("popfd")
def h_popfd(ctx, ins):
    _ops(ins, 0)
    return ["{ uint32_t f = pop32(c);",
            "    c->cf = f & 1u; c->pf = (f >> 2) & 1u; c->af = (f >> 4) & 1u; c->zf = (f >> 6) & 1u;",
            "    c->sf = (f >> 7) & 1u; c->df = (f >> 10) & 1u; c->of = (f >> 11) & 1u;",
            "    lift_eflags_sys = f & LIFT_EFLAGS_SYS; }"]


MMX_TOUCH = "c->top = 0; c->tag = 0;"       # every MMX instruction: TOP = 0, all tags valid (as hardware)


def _mm_index(op):
    """The MMX register number of an operand, or None when it is not an mm register."""
    if op.type == X86_OP_REG:
        name = x86c._MD.reg_name(op.reg)
        if name and name.startswith("mm") and name[2:].isdigit() and int(name[2:]) < 8:
            return int(name[2:])
    return None


@handler("movq")
def h_movq(ctx, ins):
    """movq mm, m64 / movq m64, mm / movq mm, mm. The 8-byte memory operand is a plain rd64/wr64.
    xmm forms are rejected (no xmm state in CPU)."""
    dst, src = _ops(ins, 2)
    dm, sm = _mm_index(dst), _mm_index(src)
    if dm is not None and sm is not None:
        return ["c->mm[%d] = c->mm[%d];" % (dm, sm), "c->mmx_dirty |= 0x%xu;" % (1 << dm), MMX_TOUCH]
    if dm is not None and src.type == X86_OP_MEM:
        x86c._check_size(_opsize(src), 8)
        return ["c->mm[%d] = rd64(c, %s);" % (dm, ea(src)), "c->mmx_dirty |= 0x%xu;" % (1 << dm), MMX_TOUCH]
    if sm is not None and dst.type == X86_OP_MEM:
        x86c._check_size(_opsize(dst), 8)
        return ["wr64(c, %s, c->mm[%d]);" % (ea(dst), sm), MMX_TOUCH]
    raise Reject("movq: only mm/m64 and mm/mm forms (xmm is emulator-only)")


@handler("emms")
def h_emms(ctx, ins):
    _ops(ins, 0)
    return ["c->tag = 0xffu;"]         # all registers empty; mm[] keeps its values, as on the hardware


@handler("orps")
def h_orps(ctx, ins):
    dst, src = _ops(ins, 2)
    if dst.type == X86_OP_REG and src.type == X86_OP_REG and dst.reg == src.reg:
        return ["/* orps x, x: no visible change */"]
    raise Reject("orps: SSE register, CPU has no xmm registers (emulator-only)")


@handler("int")
def h_int(ctx, ins):
    raise Reject("int: software interrupt (emulator-only)")
