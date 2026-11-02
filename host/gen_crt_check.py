"""Write host/crt_check.inc from emu/native.py CRT_HELPERS (the guest bytes each crt.c helper reproduces)."""
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "emu"))
import native  # noqa: E402

out = ["/* The guest code each native MSVCRT helper (lift/runtime/crt.c) reproduces, checked before it is bound: emu/native.py",
       " * CRT_HELPERS, written out by host/gen_crt_check.py (keep the two in step). {name, rva, hex bytes}; one helper may",
       " * have several ranges, all of which must match. */"]
for (mod, name), ranges in native.CRT_HELPERS.items():
    assert mod == "msvcrt.dll"
    for rva, h in ranges:
        parts = [h[i:i + 96] for i in range(0, len(h), 96)]
        out.append('{"%s", 0x%x,\n    %s},' % (name, rva, "\n    ".join('"%s"' % p for p in parts)))
open(os.path.join(ROOT, "host", "crt_check.inc"), "w").write("\n".join(out) + "\n")
