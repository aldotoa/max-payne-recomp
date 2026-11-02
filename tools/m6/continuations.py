#!/usr/bin/env python3
"""E3: the continuation entries of the game's modules, found statically (docs/m6-emu-removal.md, x86c.DEAD_FRAMES).

A continuation is an address a non-local transfer lands on with a new ESP/EBP: it becomes an aux entry (lifted, in the
table, never a direct target). Funclets are code the runtime calls by address; they must be lifted entries.

  setjmp     the return point of each call to _setjmp/_setjmp3 (longjmp resumes there)
  catch      MSVC C++ EH: each `mov eax, FuncInfo; jmp __CxxFrameHandler` stub gives a FuncInfo (magic 0x19930520);
             its try map gives the catch funclets, and each funclet returns its continuation in eax
             (`mov eax, imm32` ... `ret`, the address _JumpToContinuation jumps to)
  except     SEH _except_handler3: `push scopetable; push _except_handler3` in a prologue; scope entries
             {enclosing, filter, handler}: with a filter, handler is the __except body (jumped to)
  unwind     the address after each call to RtlUnwind (MSVCRT _global_unwind2 passes it as TargetIp)
Funclets: catch handlers, unwind-map actions, SEH filters and __finally blocks (filter NULL).

Usage: continuations.py [--aux OUT] MODULE[:INVENTORY] ...   (module paths as for lift/build.py --module)
Prints a summary per module and the funclets that are not entries of the inventory; --aux writes every
continuation (one hex VA per line) for build.py --aux-entries-file.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "lift"))

import capstone                                     # noqa: E402
from capstone.x86 import X86_OP_IMM, X86_OP_MEM     # noqa: E402
import x86c                                         # noqa: E402
from functions import NORETURN                      # noqa: E402

EH_MAGIC = 0x19930520
_MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
_MD.detail = True


def _read(img, va, n):
    try:
        return img.read(va, n)
    except ValueError:                  # x86c.PEImage raises outside the image
        return None


def u32(img, va):
    b = _read(img, va, 4) if va is not None else None
    return struct.unpack("<I", b)[0] if b and len(b) == 4 else None


def insn(img, va):
    b = _read(img, va, 16) if va is not None and img.is_code(va) else None
    return next(_MD.disasm(b, va), None) if b else None


def import_targets(img, names):
    """{va: name} of the IAT slots and import thunks for imports whose name (after 'DLL!') is in names, plus the
    image's own exports with those names (MSVCRT itself)."""
    slots = {va: n.split("!", 1)[1] for va, n in img.iat.items() if n.split("!", 1)[1] in names}
    out = {}
    for va, name in img.exports:
        if name in names:
            out[va] = name
    return slots, out


def call_target(img, ins, slots, direct):
    """The import or export a call/jmp instruction reaches: through an IAT slot, a `jmp [slot]` thunk, or directly."""
    if not ins.operands:
        return None
    op = ins.operands[0]
    if op.type == X86_OP_MEM and not op.mem.base and not op.mem.index:
        return slots.get(op.mem.disp & 0xFFFFFFFF)
    if op.type == X86_OP_IMM:
        t = op.imm & 0xFFFFFFFF
        if t in direct:
            return direct[t]
        th = insn(img, t)
        if th is not None and th.mnemonic == "jmp" and th.operands and th.operands[0].type == X86_OP_MEM \
                and not th.operands[0].mem.base and not th.operands[0].mem.index:
            return slots.get(th.operands[0].mem.disp & 0xFFFFFFFF)
    return None


def sweep(img, inv):
    """Every instruction of every inventory function's blocks, in address order (deduplicated)."""
    seen = {}
    for f in inv["functions"]:
        for blk in f.get("blocks", []):
            a, end = int(blk["start"], 16), int(blk["end"], 16)
            while a < end:
                if a in seen:
                    a += seen[a].size
                    continue
                ins = insn(img, a)
                if ins is None:
                    break
                seen[a] = ins
                a += ins.size
    return [seen[a] for a in sorted(seen)]


def funclet_returns(img, va, slots=None, direct=None, limit=2000):
    """The eax constants a catch funclet returns: `mov eax, imm32` reaching a `ret` without another write to eax.
    Follows direct jumps and both arms of conditional ones; calls are stepped over, except a call to a no-return
    import (functions.NORETURN: a `throw;` rethrow is `push 0; push 0; call _CxxThrowException`), which ends the path."""
    out, todo, seen = set(), [(va, None)], set()
    while todo:
        a, eax = todo.pop()
        steps = 0
        while steps < limit and (a, eax) not in seen:
            seen.add((a, eax))
            steps += 1
            ins = insn(img, a)
            if ins is None:
                break
            m = ins.mnemonic
            if m == "mov" and ins.op_str.startswith("eax, ") and ins.operands[1].type == X86_OP_IMM:
                eax = ins.operands[1].imm & 0xFFFFFFFF
            elif ins.operands and ins.operands[0].type == 1 and ins.reg_name(ins.operands[0].reg) == "eax" \
                    and m not in ("cmp", "test", "push"):
                eax = None
            elif m == "call":
                eax = None
                if slots is not None and call_target(img, ins, slots, direct or {}) in NORETURN:
                    break
            if m in ("ret", "retn"):
                if eax is not None:
                    out.add(eax)
                break
            if m == "jmp":
                if ins.operands[0].type == X86_OP_IMM:
                    a = ins.operands[0].imm & 0xFFFFFFFF
                    continue
                break
            if m.startswith("j") and ins.operands[0].type == X86_OP_IMM:
                todo.append((ins.operands[0].imm & 0xFFFFFFFF, eax))
            a += ins.size
    return out


def scan(path, inv_path):
    img = x86c.PEImage(path)
    inv = json.load(open(inv_path))
    entries = {int(f["entry"], 16) for f in inv["functions"]}
    slots, direct = import_targets(img, {"_setjmp", "_setjmp3", "__CxxFrameHandler", "_except_handler3",
                                         "RtlUnwind"} | NORETURN)
    res = {k: set() for k in ("setjmp", "catch", "except", "unwind")}
    funclets = {k: set() for k in ("catch", "unwind_action", "filter", "finally")}
    funcinfos, scopetables = set(), set()
    no_return = set()                     # catch funclets with no continuation found (a rethrow, or not understood)
    insns = sweep(img, inv)
    by_addr = {i.address: k for k, i in enumerate(insns)}
    eh3 = {va for va, n in list(slots.items()) + list(direct.items()) if n == "_except_handler3"}
    for k, ins in enumerate(insns):
        m = ins.mnemonic
        if m == "call":
            t = call_target(img, ins, slots, direct)
            if t in ("_setjmp", "_setjmp3"):
                res["setjmp"].add(ins.address + ins.size)
            elif t == "RtlUnwind":
                res["unwind"].add(ins.address + ins.size)
        elif m == "jmp" and call_target(img, ins, slots, direct) == "__CxxFrameHandler":
            prev = insns[k - 1] if k else None
            if prev is not None and prev.mnemonic == "mov" and prev.op_str.startswith("eax, ") \
                    and prev.operands[1].type == X86_OP_IMM:
                fi = prev.operands[1].imm & 0xFFFFFFFF
                if u32(img, fi) == EH_MAGIC:
                    funcinfos.add(fi)
        elif m == "push" and ins.operands and ins.operands[0].type == X86_OP_IMM:
            # push scopetable ; push offset _except_handler3 (the handler pushed through a thunk or its address)
            nxt = insns[k + 1] if k + 1 < len(insns) else None
            if nxt is not None and nxt.mnemonic == "push" and nxt.operands and nxt.operands[0].type == X86_OP_IMM:
                h = nxt.operands[0].imm & 0xFFFFFFFF
                th = insn(img, h)
                is_eh3 = h in eh3 or (th is not None and call_target(img, th, slots, direct) == "_except_handler3"
                                      and th.mnemonic == "jmp")
                if is_eh3:
                    scopetables.add(ins.operands[0].imm & 0xFFFFFFFF)
    for fi in funcinfos:
        max_state, p_unwind, n_try, p_try = (u32(img, fi + 4), u32(img, fi + 8), u32(img, fi + 12),
                                             u32(img, fi + 16))
        for s in range(max_state or 0):
            act = u32(img, p_unwind + 8 * s + 4)
            if act:
                funclets["unwind_action"].add(act)
        for t in range(n_try or 0):
            e = p_try + 20 * t
            n_catch, p_h = u32(img, e + 12), u32(img, e + 16)
            for h in range(n_catch or 0):
                fn = u32(img, p_h + 16 * h + 12)
                if fn:
                    funclets["catch"].add(fn)
                    rets = funclet_returns(img, fn, slots, direct)
                    res["catch"] |= rets
                    if not rets:
                        no_return.add(fn)
    for st in scopetables:
        # entries until the chain is followed: walk while the enclosing level points inside the table
        seen = set()
        todo = [0]
        n = 0
        while todo and n < 64:
            i = todo.pop()
            if i in seen:
                continue
            seen.add(i)
            n += 1
            enc, flt, hnd = u32(img, st + 12 * i), u32(img, st + 12 * i + 4), u32(img, st + 12 * i + 8)
            if hnd is None or not img.is_code(hnd):
                continue
            if flt:
                if img.is_code(flt):
                    funclets["filter"].add(flt)
                res["except"].add(hnd)
            else:
                funclets["finally"].add(hnd)
            todo.append(i + 1)
            if enc is not None and enc != 0xFFFFFFFF:
                todo.append(enc)
    for k in res:
        res[k] = {va for va in res[k] if img.is_code(va)}
    missing = {k: sorted(v - entries) for k, v in funclets.items()}
    missing.pop("no_return", None)
    funclets["no_return"] = no_return
    return img, res, funclets, missing, len(funcinfos), len(scopetables)


def main(argv):
    aux_out = None
    if "--aux" in argv:
        i = argv.index("--aux")
        aux_out = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    allaux = set()
    for spec in argv:
        path, _, inv = spec.partition(":")
        if not os.path.isabs(path) and not os.path.exists(path):
            path = os.path.join(ROOT, "Max Payne", path)
        stem = os.path.splitext(os.path.basename(path))[0].lower()
        inv = inv or os.path.join(ROOT, "lift-out", stem + "_functions.json")
        img, res, fun, missing, nfi, nst = scan(path, inv)
        aux = set().union(*res.values())
        allaux |= aux
        print("%s: FuncInfo %d, scope tables %d | continuations: setjmp %d, catch %d, except %d, unwind %d | "
              "funclets: catch %d (no continuation found %d), unwind %d, filter %d, finally %d | funclets not "
              "inventory entries: %s" % (
                  os.path.basename(path), nfi, nst, len(res["setjmp"]), len(res["catch"]), len(res["except"]),
                  len(res["unwind"]), len(fun["catch"]), len(fun["no_return"]), len(fun["unwind_action"]),
                  len(fun["filter"]),
                  len(fun["finally"]), {k: len(v) for k, v in missing.items() if v} or "none"))
    if aux_out:
        with open(aux_out, "w") as fh:
            fh.write("# continuation entries (tools/m6/continuations.py)\n")
            fh.write("".join("0x%08x\n" % va for va in sorted(allaux)))
        print("wrote %d continuations to %s" % (len(allaux), aux_out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
