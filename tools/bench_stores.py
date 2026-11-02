"""Store vs load microbenchmark for the Unicorn library the venv loads.

Stock Unicorn 2.1.4 sends every guest store to an executable page through QEMU's slow path, so the store loop
runs about 9x slower than the load loop. With the patched build (tools/build_unicorn.sh) they run at about the
same speed. Uses the same setup as mpemu: memory mapped with all permissions and a global unmapped-access hook.

Run:  .venv/bin/python tools/bench_stores.py            (exit status 1 if stores are more than 2x slower)
"""
import struct
import sys
import time

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED
from unicorn.unicorn_py3.unicorn import uclib

N = 5_000_000
CODE, DATA = 0x100000, 0x200000


def run(op, hook):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(CODE, 0x1000)
    uc.mem_map(DATA, 0x10000)
    body = (bytes([op, 0x83]) + struct.pack("<I", DATA) +    # mov [ebx+DATA], eax  /  mov eax, [ebx+DATA]
            b"\x83\xc3\x04" +                                 # add ebx, 4
            b"\x81\xe3" + struct.pack("<I", 0xFFFC) +         # and ebx, 0xfffc
            b"\x49")                                          # dec ecx
    code = b"\xb9" + struct.pack("<I", N) + body + bytes([0x75, (-(len(body) + 2)) & 0xFF])   # mov ecx, N ... jnz
    uc.mem_write(CODE, code)
    if hook:
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, lambda *a: False)
    t = time.perf_counter()
    uc.emu_start(CODE, CODE + len(code))
    return time.perf_counter() - t


if __name__ == "__main__":
    print(f"unicorn {unicorn.__version__}: {uclib._name}")
    worst = 0
    for hook in (False, True):
        ld, st = run(0x8B, hook), run(0x89, hook)
        worst = max(worst, st / ld)
        print(f"unmapped hook={hook!s:5}  {N:,} loads {ld:.3f} s   {N:,} stores {st:.3f} s   stores/loads {st / ld:.1f}x")
    sys.exit(1 if worst > 2 else 0)
