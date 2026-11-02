#!/usr/bin/env python3
"""Offline cross-references in one PE module: direct calls/jumps (E8/E9 rel32), absolute data refs
(vtable slots, pushed addresses), and `call [iat]` through imports. Names owners via Ghidra's function list
plus RTTI vtable slots when available.

Usage: xrefs.py <module> <va|import-name> [...]
"""
import bisect, json, os, struct, sys
import pefile

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
mod = sys.argv[1]
pe = pefile.PE(mod); data = open(mod, "rb").read(); base = pe.OPTIONAL_HEADER.ImageBase
name = os.path.basename(mod)
procs = []
pj = os.path.join(root, "census/ghidra/%s_procedures.json" % name.split(".")[0].lower().replace("maxpayne", "exe"))
if os.path.exists(pj):
    procs = sorted(int(i["address"], 16) for i in json.load(open(pj))["normalized_result"] if i["address"].startswith("0x"))
vtj = os.path.join(root, "census/vtables/%s.json" % name)
vtslot = {}
if os.path.exists(vtj):
    for cls, es in json.load(open(vtj)).items():
        for e in es:
            for i, sl in enumerate(e["slots"]):
                vtslot.setdefault(int(sl, 16), []).append("%s slot %d" % (cls[4:-2], i))

def owner(a):
    if not procs: return ""
    f = procs[bisect.bisect_right(procs, a) - 1]
    return "fn 0x%x%s" % (f, " [" + vtslot[f][0] + "]" if f in vtslot else "")

secs = [(base + s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData, s.Name.rstrip(b"\0").decode()) for s in pe.sections]
text = next(s for s in secs if s[3] == ".text")
iat = {}
for ent in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    for imp in ent.imports:
        iat[(imp.name.decode() if imp.name else "#%d" % imp.ordinal)] = imp.address

def va_of(off):
    for va, raw, sz, n in secs:
        if raw <= off < raw + sz: return va + off - raw, n

for arg in sys.argv[2:]:
    if arg.startswith("0x"):
        t = int(arg, 16)
        print("== references to 0x%x" % t)
        code = data[text[1]:text[1] + text[2]]
        for i in range(len(code) - 4):
            if code[i] in (0xE8, 0xE9):
                rel = struct.unpack_from("<i", code, i + 1)[0]
                if text[0] + i + 5 + rel == t:
                    print("  %s 0x%x  %s" % ("call" if code[i] == 0xE8 else "jmp ", text[0] + i, owner(text[0] + i)))
        pat = struct.pack("<I", t); i = 0
        while True:
            i = data.find(pat, i)
            if i < 0: break
            r = va_of(i)
            if r: print("  data ref at 0x%x (%s) %s" % (r[0], r[1], owner(r[0]) if r[1] == ".text" else vtslot.get(r[0], "")))
            i += 1
    else:
        slot = iat.get(arg)
        print("== calls through import %s (iat 0x%x)" % (arg, slot or 0))
        if slot:
            code = data[text[1]:text[1] + text[2]]
            for pre in (b"\xff\x15", b"\xff\x25"):
                pat = pre + struct.pack("<I", slot); i = 0
                while True:
                    i = code.find(pat, i)
                    if i < 0: break
                    print("  %s 0x%x  %s" % ("call" if pre[1] == 0x15 else "jmp ", text[0] + i, owner(text[0] + i)))
                    i += 1
