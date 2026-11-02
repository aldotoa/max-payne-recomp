#!/usr/bin/env python3
"""Map MSVC RTTI to vtables for one PE module.

For every RTTI TypeDescriptor (".?AV<name>@@"), find the Complete Object Locators that
point at it, then the vtables whose slot -1 points at each locator, then read the vtable
slots (pointers into the code section).

Usage: vtables.py <module> <out.json>
Output: {class_name: [{"vtable": "0x...", "offset": int, "slots": ["0x...", ...]}]}
Works on files with relocations only after rebasing, so this assumes the preferred image
base (the exe has no relocations; DLL slots are reported at their preferred base).
"""
import json
import re
import struct
import sys

import pefile


def main():
    path, out = sys.argv[1], sys.argv[2]
    pe = pefile.PE(path)
    data = open(path, "rb").read()
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.Name.rstrip(b"\0").decode(), base + s.VirtualAddress,
             base + s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData),
             s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]

    def va_to_off(va):
        for _, lo, hi, raw, rsz in secs:
            if lo <= va < hi and va - lo < rsz:
                return raw + (va - lo)
        return None

    def off_to_va(off):
        for _, lo, hi, raw, rsz in secs:
            if raw <= off < raw + rsz:
                return lo + (off - raw)
        return None

    def in_code(va):
        # The retail exe has no execute flags, so use the '.text' name too.
        for name, lo, hi, _, _ in secs:
            if lo <= va < hi and name == ".text":
                return True
        return False

    # 1. TypeDescriptors: [vftable ptr][spare=0][".?AV...@@\0"]
    tds = {}
    for m in re.finditer(rb"\.\?A[VU][A-Za-z0-9_@?$]+@@\x00", data):
        name = m.group(0)[:-1].decode("latin1")
        td_off = m.start() - 8
        if td_off < 0:
            continue
        va = off_to_va(td_off)
        if va is None:
            continue
        if struct.unpack_from("<I", data, td_off + 4)[0] != 0:
            continue
        tds[va] = name

    td_ptr = {struct.pack("<I", va): va for va in tds}

    # 2. COLs: signature 0, offset, cdOffset, pTypeDescriptor, pClassHierarchy
    cols = {}  # col_va -> (td_va, offset)
    for pat, td_va in td_ptr.items():
        i = 0
        while True:
            i = data.find(pat, i)
            if i < 0:
                break
            col_off = i - 12
            if col_off >= 0:
                sig, offs, cdoff = struct.unpack_from("<III", data, col_off)
                if sig == 0 and offs < 0x10000 and cdoff < 0x10000:
                    cva = off_to_va(col_off)
                    if cva is not None:
                        cols[cva] = (td_va, offs)
            i += 1

    # 3. vtables: a 4-byte pointer to a COL, immediately followed by code pointers.
    col_bytes = {struct.pack("<I", c): c for c in cols}
    result = {}
    for pat, cva in col_bytes.items():
        i = 0
        while True:
            i = data.find(pat, i)
            if i < 0:
                break
            va = off_to_va(i)
            if va is not None and va % 4 == 0:
                slots = []
                o = i + 4
                while o + 4 <= len(data):
                    p = struct.unpack_from("<I", data, o)[0]
                    if not in_code(p):
                        break
                    slots.append("0x%x" % p)
                    o += 4
                    if len(slots) > 400:
                        break
                if slots:
                    td_va, offs = cols[cva]
                    result.setdefault(tds[td_va], []).append(
                        {"vtable": "0x%x" % (va + 4), "offset": offs, "slots": slots})
            i += 1

    json.dump(result, open(out, "w"), indent=0)
    n_slots = sum(len(v["slots"]) for vs in result.values() for v in vs)
    print("%s: %d type descriptors, %d COLs, %d classes with vtables, %d slots" %
          (path.split("/")[-1], len(tds), len(cols), len(result), n_slots))


if __name__ == "__main__":
    main()
