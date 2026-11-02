#!/usr/bin/env python3
"""Recursive-descent x86-32 disassembly of one function from a PE file (no Ghidra).

Usage: disasm.py <module> <va> [--max N] [--names names.json]

Follows direct jumps/branches inside the function, stops at ret. Annotates:
  - direct calls (shows import name when the target is a `jmp [iat]` thunk, or `call [iat]`)
  - x87 loads/arith with absolute memory operands (shows the float/double value)
  - absolute .rdata/.data refs that point at printable strings
Optional names.json: {"0xADDR": "name"} to label call targets (e.g. from RTTI vtables).
"""
import json
import struct
import sys

import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM


def load(path):
    pe = pefile.PE(path)
    data = open(path, "rb").read()
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(base + s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData),
             s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
    iat = {}
    for ent in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in ent.imports:
            nm = imp.name.decode() if imp.name else "#%d" % imp.ordinal
            iat[imp.address] = "%s!%s" % (ent.dll.decode(), nm)
    return pe, data, base, secs, iat


def main():
    args = sys.argv[1:]
    path, va = args[0], int(args[1], 16)
    maxn = 4000
    names = {}
    if "--max" in args:
        maxn = int(args[args.index("--max") + 1])
    if "--names" in args:
        names = json.load(open(args[args.index("--names") + 1]))
    pe, data, base, secs, iat = load(path)

    def rd(a, n):
        for lo, vs, raw, rs in secs:
            if lo <= a < lo + vs and a - lo + n <= rs:
                return data[raw + a - lo: raw + a - lo + n]
        return None

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    def label(t):
        if hex(t) in names:
            return names[hex(t)]
        b = rd(t, 6)
        if b and b[:2] == b"\xff\x25":
            return iat.get(struct.unpack("<I", b[2:6])[0], "thunk")
        return None

    seen, todo, listing = set(), [va], {}
    while todo and len(listing) < maxn:
        a = todo.pop()
        while a not in listing and len(listing) < maxn:
            b = rd(a, 16)
            if not b:
                break
            ins = next(md.disasm(b, a), None)
            if ins is None:
                break
            listing[a] = ins
            if ins.mnemonic == "ret":
                break
            if ins.mnemonic.startswith("j") and ins.operands and ins.operands[0].type == X86_OP_IMM:
                tgt = ins.operands[0].imm
                if tgt not in listing:
                    todo.append(tgt)
                if ins.mnemonic == "jmp":
                    break
            elif ins.mnemonic == "jmp":
                break
            a += ins.size

    for a in sorted(listing):
        ins = listing[a]
        note = ""
        if ins.mnemonic == "call":
            op = ins.operands[0]
            if op.type == X86_OP_IMM:
                nm = label(op.imm)
                note = "-> 0x%x %s" % (op.imm, nm or "")
            elif op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                note = "-> [%s]" % iat.get(op.mem.disp, hex(op.mem.disp))
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0 and op.mem.disp:
                d = op.mem.disp & 0xffffffff
                if ins.mnemonic.startswith("f") and op.size in (4, 8):
                    raw = rd(d, op.size)
                    if raw:
                        v = struct.unpack("<f" if op.size == 4 else "<d", raw)[0]
                        note += " [0x%x]=%r" % (d, v)
                else:
                    raw = rd(d, 24)
                    if raw and 4 <= len(raw.split(b"\0")[0]) < 24 and all(32 <= c < 127 for c in raw.split(b"\0")[0]):
                        note += ' [0x%x]="%s"' % (d, raw.split(b"\0")[0].decode())
        print("%08x  %-6s %-34s %s" % (a, ins.mnemonic, ins.op_str, note))
    print("; %d instructions" % len(listing))


if __name__ == "__main__":
    main()
