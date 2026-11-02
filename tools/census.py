#!/usr/bin/env python3
"""M1 census: imports, exports, sections, entry point, opcode classes, RTTI classes.

Usage: census.py <game_dir> <out_dir>
Writes JSON/text under out_dir (gitignored). Reads game files only.
"""
import collections
import json
import os
import re
import sys

import capstone
import pefile

MODULES = [
    "MaxPayne.exe",
    "e2mfc.dll",
    "rlmfc.dll",
    "grphmfc.dll",
    "sndmfc.dll",
    "e2driver/e2_d3d8_driver_mfc.dll",
]
SHIPPED_LIBS = ["MFC42.DLL", "MSVCRT.DLL", "MSVCP60.DLL", "MSVCIRT.DLL"]

X87_GROUPS = {"FPU"}
SSE_GROUPS = {"SSE1", "SSE2", "SSE3", "SSSE3", "SSE41", "SSE42", "AVX"}


def section_of(pe, rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.Name.rstrip(b"\0").decode()
    return None


def imports(pe):
    out = collections.OrderedDict()
    for ent in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = ent.dll.decode()
        names = []
        for imp in ent.imports:
            names.append(imp.name.decode() if imp.name else "#%d" % imp.ordinal)
        out[dll] = names
    return out


def exports(pe):
    out = []
    d = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if d:
        for s in d.symbols:
            out.append({"ordinal": s.ordinal, "rva": s.address,
                        "name": s.name.decode() if s.name else None})
    return out


def opcode_survey(pe, path):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    cnt = collections.Counter()
    groups = collections.Counter()
    notable = collections.Counter()
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode()
        # The retail exe has every section flagged data-only (0xC0000040), so also
        # treat '.text' and the entry-point section as code.
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        has_ep = s.VirtualAddress <= ep < s.VirtualAddress + s.Misc_VirtualSize
        if not (s.Characteristics & 0x20000000 or name == ".text" or has_ep):
            continue
        data = s.get_data()
        base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
        off = 0
        n = 0
        # linear sweep, resync one byte on a decode failure
        while off < len(data):
            got = False
            for ins in md.disasm(data[off:off + 0x4000], base + off):
                got = True
                n += 1
                cnt[ins.mnemonic] += 1
                gnames = {md.group_name(g) for g in ins.groups}
                if gnames & X87_GROUPS or ins.mnemonic.startswith("f"):
                    groups["x87"] += 1
                if gnames & SSE_GROUPS:
                    groups["sse/avx"] += 1
                if "MMX" in gnames:
                    groups["mmx"] += 1
                if "3DNOW" in gnames:
                    groups["3dnow"] += 1
                if ins.mnemonic in ("cpuid", "rdtsc", "int", "int3", "sysenter", "syscall",
                                    "in", "out", "cli", "sti", "lock", "rep", "cmov",
                                    "fldcw", "fnstcw", "fstcw", "fninit", "finit", "emms"):
                    notable[ins.mnemonic] += 1
                if ins.mnemonic.startswith("cmov"):
                    notable["cmovcc"] += 1
                off = ins.address - base + ins.size
            if not got:
                off += 1
            elif off >= len(data):
                break
        groups["instructions_total(%s)" % s.Name.rstrip(b"\0").decode()] = n
    return cnt, groups, notable


def rtti_classes(path):
    data = open(path, "rb").read()
    names = set(m.group(0).decode("latin1")
                for m in re.finditer(rb"\.\?A[VU][A-Za-z0-9_@?$]+@@", data))
    return sorted(names)


def main():
    game, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    report = {}
    for rel in MODULES + SHIPPED_LIBS:
        path = os.path.join(game, rel)
        if not os.path.exists(path):
            continue
        pe = pefile.PE(path, fast_load=False)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry = {
            "file": rel,
            "size": os.path.getsize(path),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "entry_rva": hex(ep),
            "entry_section": section_of(pe, ep),
            "sections": [{"name": s.Name.rstrip(b"\0").decode(),
                          "vsize": s.Misc_VirtualSize, "entropy": round(s.get_entropy(), 2),
                          "flags": hex(s.Characteristics)} for s in pe.sections],
            "has_reloc": any(s.Name.startswith(b".reloc") for s in pe.sections),
            "imports": imports(pe),
            "export_count": len(exports(pe)),
            "tls": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
        }
        entry["import_counts"] = {k: len(v) for k, v in entry["imports"].items()}
        json.dump(exports(pe), open(os.path.join(out, "exports_%s.json" % os.path.basename(rel)), "w"))
        if rel in MODULES:
            cnt, groups, notable = opcode_survey(pe, path)
            entry["opcode_groups"] = dict(groups)
            entry["opcode_notable"] = dict(notable)
            json.dump(cnt.most_common(), open(os.path.join(out, "mnemonics_%s.json" % os.path.basename(rel)), "w"))
            entry["rtti_classes"] = len(rtti_classes(path))
            json.dump(rtti_classes(path), open(os.path.join(out, "rtti_%s.json" % os.path.basename(rel)), "w"))
        report[rel] = entry
        print("done", rel, file=sys.stderr)
    json.dump(report, open(os.path.join(out, "census.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
