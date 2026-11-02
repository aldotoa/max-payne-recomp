"""Native (lifted) guest functions inside the emulator: the M5 bridge.

A Native owns one loaded lifted dylib (lift/build.py) for one Emu. install(va) patches the guest function at va
with `jmp <native slot>`; when guest code reaches the slot, the emulator stops, the driver (mpemu._drive) copies
the CPU state into a CPU struct, the lifted function runs through ctypes, and the state is copied back.
Lifted code reaches guest code through CPU.call_guest, a ctypes callback that runs the emulator nested in the
driver (so native -> guest -> native works).

The register sync is C (lift/runtime/runtime.c: lift_sync_from_uc / lift_sync_to_uc), batch calls into the
libunicorn the binding loaded. The x87 and MMX state is synced only for functions whose LiftEntry has the FPU flag
(lift/build.py: a function that uses x87 or MMX, or can reach a call the bridge cannot see through). Register and
flag conventions are in lift/runtime/cpu.h. The x87 stack is converted between Unicorn's 80-bit registers and the
CPU's doubles; a non-empty register whose 80-bit value is not a double is counted in Native.inexact (the lifted
code cannot represent it). _py_uc_to_cpu and _py_cpu_to_uc are the Python versions of the same sync, kept for
the tests (lift/test_bridge.py checks that they agree with the C ones).

Limits (see the M5 report): native code writes guest memory through host pointers, so it does not show up in an
undo log. run_pending refuses to run while an undo log is active. Native code runs with the host's registers
and Python state untouched: an exception or fatal error inside a nested guest call leaves the native code to run
on whatever state it was given until it returns, and the error is then raised from the outermost native call.
The C sync keeps its engine handle in globals, so the Native that was created last owns it; every entry point
re-binds when another Native has taken over.

Differential mode (enable_diff, run_diff): no entry is patched. A code hook on every lifted entry stops the emulator
there; run_diff then runs the function twice from the same state: emulated (the reference, every HLE call recorded
with its register and memory effects, see mpemu.HleRec), then natively with the library built with
-DLIFT_WRITE_LOG (every guest write logged in C), with HLE calls replayed from the record instead of run. The
native result is compared with the reference, and the reference result is put back, so the game always continues
with the emulator's result. See run_diff for the details.
"""
import ctypes
import json
import math
import os
import struct
import sys
from ctypes import CFUNCTYPE, POINTER, Structure, c_double, c_int, c_int32, c_uint8, c_uint16, c_uint32, c_uint64, c_void_p
from fractions import Fraction

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX,
                               UC_X86_REG_EDI, UC_X86_REG_EDX, UC_X86_REG_EFLAGS, UC_X86_REG_EIP, UC_X86_REG_ESI,
                               UC_X86_REG_ESP, UC_X86_REG_FP0, UC_X86_REG_FPCW, UC_X86_REG_FPSW,
                               UC_X86_REG_FPTAG)

import mpemu
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lift"))
from entries import function_entries, parse_va_text  # noqa: E402,F401  (lift/entries.py)
from mpemu import HLE_HALT, STUB_BASE, STUB_STRIDE, TEB, _UndoPage, write_runs


class CPU(Structure):
    """ctypes mirror of lift/runtime/cpu.h `CPU`. Verified against lift_cpu_layout when a Native loads."""
    _fields_ = [("r", c_uint32 * 8), ("eip", c_uint32),
                ("cf", c_uint8), ("pf", c_uint8), ("af", c_uint8), ("zf", c_uint8),
                ("sf", c_uint8), ("of", c_uint8), ("df", c_uint8), ("_pad", c_uint8),
                ("st", c_double * 8), ("top", c_uint32), ("tag", c_uint32),
                ("cw", c_uint16), ("sw", c_uint16), ("fs_base", c_uint32),
                ("mem", c_void_p), ("call_guest", c_void_p), ("user", c_void_p),
                ("mm", c_uint64 * 8), ("mmx_dirty", c_uint32)]


class _LiftEntry(Structure):
    _fields_ = [("va", c_uint32), ("fn", c_void_p), ("flags", c_uint32)]


# Field order of lift_cpu_layout's output after sizeof(CPU).
LAYOUT_FIELDS = ["r", "eip", "cf", "pf", "af", "zf", "sf", "of", "df", "_pad", "st", "top", "tag",
                 "cw", "sw", "fs_base", "mem", "call_guest", "user", "mm", "mmx_dirty"]
LAYOUT_WORDS = 1 + len(LAYOUT_FIELDS) + 3          # sizeof(CPU), the fields, sizeof(LiftEntry), fn, flags

GPR_IDS = [UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
           UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI]     # = CPU.r[] order
FLAG_SHIFTS = (("cf", 0), ("pf", 2), ("af", 4), ("zf", 6), ("sf", 7), ("df", 10), ("of", 11))
FLAG_MASK = sum(1 << s for _, s in FLAG_SHIFTS)
SW_C_MASK = 0x4700          # C0 C1 C2 C3
SW_TOP_MASK = 0x3800        # TOP (bits 11..13)
SW_EXC_MASK = 0x003f        # sticky exception flags IE..PE: carried both ways with the C bits
FPU_FLAG = 1                # LiftEntry.flags bit 0 (LIFT_FLAG_FPU)

# The Unicorn ids the C sync uses, in lift_bridge_regs order (checked when a Native loads).
BRIDGE_REG_IDS = (GPR_IDS + [UC_X86_REG_EFLAGS, UC_X86_REG_FPSW, UC_X86_REG_FPCW, UC_X86_REG_FPTAG]
                  + [UC_X86_REG_FP0 + p for p in range(8)])

_CALL_GUEST_T = CFUNCTYPE(None, POINTER(CPU), c_uint32)
_LIFTED_T = CFUNCTYPE(None, c_void_p)               # a lifted function takes the CPU's address
_FAST_FALLBACK_T = CFUNCTYPE(c_int, POINTER(CPU), c_uint32, c_uint32, c_int)   # runtime.c fast_call_guest
_HLE_DIRECT_T = CFUNCTYPE(c_int, POINTER(CPU), c_uint32)   # runtime.c hle_direct
_ENTRY_HOOK_T = CFUNCTYPE(None, c_uint32)           # runtime.c lift_entry_hook

# Fast native dispatch (install_fast): one 16-byte slot per installed function, in a region of its own. Slot 0 is the
# address nested guest calls return to (never hooked). Unicorn allows 64 nested uc_emu_start levels. The region must
# match FAST_SLOTS in lift/runtime/runtime.c. With the three DLLs lifted there are about 4,800 lifted functions; the
# exe's hot set (M6) raises the region to 64 K slots. [FAST_BASE, FAST_BASE + FAST_SIZE) is free guest space: the
# stub area ends at 0x7F100000, the TEB and PEB start at 0x7FFDB000, the DLLs are below 0x10400000.
FAST_BASE = 0x7F100000
FAST_SIZE = 0x100000
FAST_STRIDE = 16
FAST_SLOTS = FAST_SIZE // FAST_STRIDE          # slot numbers 1..65535 are functions
FAST_MAX_DEPTH = 60                            # runtime.c: deeper nested calls are an error
FAST_COUNTERS = ("calls", "guest_calls", "fallbacks", "max_depth", "too_deep", "inexact",
                 "native_ns", "guest_ns", "unwinds", "dead")   # lift_fast_stats order (runtime.c FS_*)

# Native MSVCRT helpers (lift/runtime/crt.c): calls from lifted code to these imports run C instead of a guest call.
# Each is bound only when the guest bytes at (rva, expected bytes) all match the code crt.c reproduces.
CRT_HELPERS = {
    ("msvcrt.dll", "_ftol"): [(0x1f14, "558bec83c4f49bd97dfe9b668b45fe80cc0c668945fcd96dfcdf7df4d96dfe8b45f48b55f8c9c3")],
    ("msvcrt.dll", "tolower"): [(0x11790, "5333db391d6471037875138b44240883f8417c5483f85a7f4f83c0205bc3"),
                                (0x117f8, "5bc3")],
    # The "C" locale paths of _stricmp and _strnicmp (crt.c), each one contiguous from the prologue to the ret.
    ("msvcrt.dll", "_stricmp"): [(0x10d13, "558bec5756538b750c8b7d088d055c71037883780800753eb0ff8bff0ac0742e8a0646"
                                           "8a274738c474f22c413c1a1ac980e12002c1044186e02c413c1a1ac980e12002c1044138e0"
                                           "74d21ac01cff0fbec05b5e5fc9c3")],
    ("msvcrt.dll", "_strnicmp"): [(0x139f6, "558bec5756538b4d100bc974538b75088b7d0c8d055c710378837808007548b741b35a"
                                            "b6208d49008a260ae48a0774210ac0741d464738fc720638dc770202e638f8720638d8770202"
                                            "c638c475094975d733c938c47409b9ffffffff7202f7d98bc15b5e5fc9c3")],
    # __RTDynamicCast (crt.c crt_rtdynamiccast): the guest's code for the cases it reproduces, with the search functions,
    # PMDtoOffset and strcmp it calls (their ranges are checked too: the helper's writes and registers depend on them).
    ("msvcrt.dll", "__RTDynamicCast"): [
                 (0x1844e, "558bec6aff6840fb02786806ef007864a100000000506489250000000083ec3c5356578965e88b750885f6751133c08b"
                                    "4df064890d000000005f5e5bc9c38365fc0056e8cc000000598bf8897dd48b068b40fc8945dc2b750c8975082bf78975"
                                    "d88b48108b4904f6c101752fff751456ff75105057e8b400000083c4148945e485c0743383c0085057e82b0300005959"
                                    "03c78945e0834dfcffeb94f6c102ff751456ff751050577507e8da000000ebcae8cc010000ebc333c08945e039451874"
                                    "d4c745c42cfb02788d45c4508d4dc8e8282affff68980303788d45c850e8e526ffff8b45ec8b008b0033c93d050000c0"
                                    "0f94c18bc1c38b65e868a0fa02788d4db8e8642bffff68380303788d45b850e8b326ffff"),
                 (0x18562, "8b4c24048b018b50fc8bc12b42048b520885d274042bca0301c3"),
                 (0x1857c, "558bec518365fc00538b5d0c56578b4310837808008b700c76358b3e8b4d188b073bc1741383c10883c0085150e8a5a4"
                                    "feff5985c0597506f64714017418ff45fc8b43108b4dfc83c6043b480872cb33c05f5e5bc9c38bc7ebf7"),
                 (0x185d6, "558bec83ec0c8365fc00538b5d0c56578b4310837808008b780c0f86890000008b378b4d188b063bc1741383c10883c0"
                                    "085150e845a4feff5985c05975568365f400837e04008d47048945f876468b45f88b4d108b188b033bc1741383c10883"
                                    "c0085150e814a4feff5985c059751383c30853ff7508e8b60100003b451459597473ff45f48345f8048b45f43b460472"
                                    "bd8b5d0cff45fc8b43108b4dfc83c7043b48080f8277ffffff8b43108365fc00837808008b780c76358b378b4d188b06"
                                    "3bc1741383c10883c0085150e8aca3feff5985c0597506f64614037418ff45fc8b43108b4dfc83c7043b480872cb33c0"
                                    "5f5e5bc9c38bc6ebf7"),
                 (0x18807, "8b44240833c98b500485d27c118bca8b542404568b70088b1411030c325e8b0003c1c3"),
                 (0x2a53, "8b5424048b4c2408f7c2030000000f8584dc00008b023a0175300ac074293a610175270ae47420c1e8103a4102751b0a"
                                    "c074143a6103751283c10483c2040ae475d2e94adc000033c0c31bc0d1e040c3"),
                 (0x106e4, "8bffe9af23fffff7c20100000074208a02423a010f859f23ffff410ac00f849323fffff7c2020000000f845423ffff66"
                                    "8b0283c2023a010f857c23ffff0ac00f847123ffff3a61010f856b23ffff0ae40f846023ffff83c102e92523ffff")],
    # type_info::name (crt.c crt_typeinfo_name): its entry test and the cached return.
    ("msvcrt.dll", "?name@type_info@@QBEPBDXZ"): [(0xb20f, "578bf9837f04007565"), (0xb27d, "8b47045fc3")],
    # floor (crt.c crt_floor): the function, _ctrlfp and the frndint helper.
    ("msvcrt.dll", "floor"): [
                 (0x2bbf0, "558bec51515356beffff000056ff3514ae0378e870160000dd4508598bd88b450e59516625f07f51663df07fdd1c24"
                                    "755fe81a1500005985c0597e2f83f8027e1c83f8037525dd4508535151dd1c246a0be8db0c000083c4105e5bc9c356"
                                    "53e824160000dd45085959ebeedd4508dc05c0ff0278535151dd1c24dd45085151dd1c246a0b6a08e85a0d000083c4"
                                    "1cebc9e86c160000dd5df8dd45f8dc5d085959dfe09e750e5653e8dc150000dd45f85959eba6f6c32075eddd45f853"
                                    "5151dd1c24dd45085151dd1c246a0b6a10ebb7"),
                 (0x2d278, "558bec519bd97dfc8b450c8bc8234508f7d1234dfc0bc8894d0cd96d0c0fbf45fcc9c3"),
                 (0x2d2f1, "558bec5151dd4508d9fcdd5df8dd45f8c9c3")],
    # _CIfmod (crt.c crt_cifmod): the shared _CI prologue, the fmod entry and its fprem handler, the operand
    # classifier, the result check, and its data: the handler table's first entry and the class table.
    ("msvcrt.dll", "_CIfmod"): [
                 (0x28bb9, "558bec81c430fdffff539bd9bd5cffffff9b833d98920378000f843a380000e838350000808d38fdffff03e84d3800"
                                    "005bc9c3"),
                 (0x28d47, "ba90a60378e968feffffd9c9833d0c7c037801740cd9f89bdfe09b9e7aeeddd9c3e836100000ebef"),
                 (0x2c115, "807a0e050f8580000000668b9d5cffffff80cf0280e7feb33f66899d5effffffd9ad5effffffbb3cae0378d9e58995"
                                    "6cffffff9bddbd60ffffffc68570ffffff00d9c98a8d61ffffffd9e59bddbd60ffffffd9c98aad61ffffffd0e5d0fd"
                                    "d0c58ac5240fd78ae0d0e1d0f9d0c18ac1240fd7d0e4d0e40ac40fbec081e1040400008bda03d883c310ff2366bb3f"
                                    "13eb89"),
                 (0x2c412, "d9c9dd957affffffd9c9dd5582e9b4"),
                 (0x2c436, "833d18b70378000f8586000000dd9530fdffff8a8570ffffff0ac00f84900000003cff74763cfe74720ac074660fbe"
                                    "c0898572ffffff56578b9d6cffffff43899d76fffffff68538fdffff01751afc8d75088dbd7affffffa5a5807b0c01"
                                    "74088d75108d7d82a5a5dd5d8a8d8572ffffff8d9d5cffffff53508b9d6cffffff8a430e0fbec050e8420e000083c4"
                                    "0c5f5edd458ad9ad5cffffff9bc3"),
                 (0x2c4e7, "668b855cffffff6683e02075d59bdfe06683e02074cc"),
                 (0x2c1a5, "ddd8ddd8d9eec3"),
                 (0x3a6a0, "518d027845c20278dec1027845c20278a5c10278"),
                 (0x3ae3c, "080408080804080800040c0800040c08")],
}

_OWNER = [None]             # the Native whose engine handle the C sync has (runtime.c keeps one)
_ONES = b"\x01" * 4096
_FLAG_NAMES = (("cf", 0), ("pf", 2), ("af", 4), ("zf", 6), ("sf", 7), ("df", 10), ("of", 11))
_REG_NAMES = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]     # GPR_IDS order
_FP_IDS = [UC_X86_REG_FP0 + p for p in range(8)]
_CMP_GPR_FLAGS = GPR_IDS + [UC_X86_REG_EFLAGS]
_DIFF_MEM_LIMIT = 10        # differing addresses kept per run
_DIFF_EXAMPLES = 3          # mismatch and divergence details kept per function
# Default instruction budget of one reference run (enable_diff budget=). A run that executes more guest instructions
# is retired as too long and finishes emulated, once, without a comparison (Native._diff_once). Ordinary functions
# finish well inside it; a long-running loop (a loading frame) does not.
DIFF_BUDGET = 20_000_000


class CHeap:
    """The guest heap in C (lift/runtime/heap.c, H44): mpemu.PyHeap's interface and block choices. Made from a PyHeap,
    whose live and free blocks it takes over; Emu.heap then points here, and lifted code's HeapAlloc/HeapFree calls are
    served in C (lift_heap_direct)."""

    def __init__(self, lib, heap):
        self.lib = lib
        self.limit = heap.limit
        lib.lift_heap_reset(heap.next, heap.limit)
        for p, size, cap in heap.live():
            lib.lift_heap_set_live(p, size, cap)
        for p, size in heap.free_blocks():
            lib.lift_heap_add_free(p, size)
        self._reused = c_int()
        self._size, self._cap = c_uint32(), c_uint32()

    def alloc(self, size):
        p = self.lib.lift_heap_alloc(size, ctypes.byref(self._reused))
        if not p:
            raise MemoryError(self.exhausted())
        return p, bool(self._reused.value)

    def stats(self):
        """next, live blocks, live alloc() blocks, their capacity, free bytes, free blocks, direct HeapAlloc and
        HeapFree calls (heap.c lift_heap_stats)."""
        out = (c_uint64 * 8)()
        self.lib.lift_heap_stats(out)
        return list(out)

    def exhausted(self):
        st = self.stats()
        return "guest heap exhausted (%d MB live in %d blocks, %d MB free but fragmented)" % (
            st[3] >> 20, st[2], st[4] >> 20)

    def free(self, p):
        return bool(self.lib.lift_heap_free(p & 0xFFFFFFFF))

    def get(self, p):
        if not 0 < p <= 0xFFFFFFFF or not self.lib.lift_heap_get(p, ctypes.byref(self._size), ctypes.byref(self._cap)):
            return None
        return self._size.value, self._cap.value

    def resize(self, p, size):
        self.lib.lift_heap_set_live(p, size, self.get(p)[1])

    def reserve(self, size, record):
        return self.lib.lift_heap_reserve(size, int(record))

    @property
    def next(self):
        return self.lib.lift_heap_next()

    def __len__(self):
        return self.stats()[1]

    def live(self):
        n = self.lib.lift_heap_export_live(None, 0)
        out = (c_uint32 * (3 * n + 3))()
        self.lib.lift_heap_export_live(out, n)
        return [(out[3 * i], out[3 * i + 1], out[3 * i + 2]) for i in range(n)]

    def free_blocks(self):
        n = self.lib.lift_heap_export_free(None, 0)
        out = (c_uint32 * (2 * n + 2))()
        self.lib.lift_heap_export_free(out, n)
        return [(out[2 * i], out[2 * i + 1]) for i in range(n)]


HEAP_DIRECT = (("KERNEL32.DLL", "HeapAlloc"), ("KERNEL32.DLL", "HeapFree"))   # served by heap.c lift_heap_direct

# HLE handlers in C (lift/runtime/hle_fast.c, H50, H60, H61, H62): stub -> handler kind (the K_* values there)
_D = "D3D8.DLL"
_K = "KERNEL32.DLL"
_DI = "DINPUT.DLL"
_DS = "DSOUND.DLL"
HLE_FAST_KINDS = {
    (_K, "QueryPerformanceCounter"): 1,
    (_D, "IDirect3DDevice8::SetRenderState"): 2,
    (_D, "IDirect3DDevice8::SetTextureStageState"): 3,
    (_D, "IDirect3DDevice8::SetTexture"): 4,
    (_D, "IDirect3DDevice8::SetStreamSource"): 5,
    (_D, "IDirect3DDevice8::SetIndices"): 6,
    (_D, "IDirect3DVertexBuffer8::Lock"): 7,
    (_D, "IDirect3DIndexBuffer8::Lock"): 8,
    (_D, "IDirect3DVertexBuffer8::Unlock"): 9,
    (_D, "IDirect3DIndexBuffer8::Unlock"): 9,
    (_D, "IDirect3DDevice8::DrawIndexedPrimitive"): 10,
    # H60 (libraries without lift_hle_fast_blob have none of these)
    (_K, "TlsGetValue"): 11, (_K, "TlsSetValue"): 12, (_K, "GetLastError"): 13, (_K, "SetLastError"): 14,
    (_K, "InitializeCriticalSection"): 15, (_K, "EnterCriticalSection"): 15, (_K, "LeaveCriticalSection"): 15,
    (_K, "DeleteCriticalSection"): 15,
    (_D, "IDirect3DDevice8::SetVertexShader"): 16,
    (_D, "IDirect3DDevice8::SetTransform"): 17,
    (_D, "IDirect3DDevice8::SetViewport"): 18,
    (_D, "IDirect3DDevice8::Clear"): 19,
    # H61 (libraries without lift_hle_fast_di_new have none of these)
    (_DI, "IDirectInputDevice7A::Acquire"): 20,
    (_DI, "IDirectInputDevice7A::GetDeviceState"): 21,
    (_DI, "IDirectInputDevice7A::GetDeviceData"): 22,
    # H62 (libraries without lift_hle_fast_ds_new have none of these)
    (_DS, "IDirectSoundBuffer::Lock"): 23,
    (_DS, "IDirectSoundBuffer::Unlock"): 24,
    (_DS, "IDirectSoundBuffer::GetCurrentPosition"): 25,
    (_DS, "IDirectSoundBuffer::SetVolume"): 26,
}
HLE_FAST_H50 = 10                             # the last kind a library without lift_hle_fast_blob serves
HLE_FAST_H60 = 19                             # the last kind a library without lift_hle_fast_di_new serves
HLE_FAST_H61 = 22                             # the last kind a library without lift_hle_fast_ds_new serves
TLS_SLOTS = 1088                              # hle_fast.c TLS_SLOTS
CAP_NONE, CAP_SINK, CAP_PYTHON = 0, 1, 2      # hle_fast.c capture modes


class HleFast:
    """The Python side of lift/runtime/hle_fast.c: the D3D8 device state it owns (emu/d3d8.py Recorder reads and writes
    it through set/get), the objects it knows, the capture mode, and the statistics it counts (merge)."""
    OBJ_KINDS = {"IDirect3DTexture8": 1, "IDirect3DVertexBuffer8": 2, "IDirect3DIndexBuffer8": 3}

    def __init__(self, lib, emu):
        self.lib = lib
        self.e = emu
        lib.lift_hle_fast_reset()
        self._v, self._v2 = c_uint32(), c_uint32()
        self.h60 = hasattr(lib, "lift_hle_fast_blob")    # the KERNEL32 state, transforms, viewport and Clear in C
        self._blob = (c_uint32 * 16)()
        if self.h60:
            emu.attach_fast_k32(self)
        self.h61 = hasattr(lib, "lift_hle_fast_di_new")  # DINPUT Acquire and the polls in C
        self._ev = (c_uint32 * 4)()
        if self.h61:
            import dinput
            dinput.attach_fast(emu, self)
        self.h62 = hasattr(lib, "lift_hle_fast_ds_new")  # the DSOUND buffer calls in C
        if self.h62:
            import dsound
            dsound.attach_fast(emu, self)

    def di_new(self, this, kind):
        """hle_fast.c lift_hle_fast_di_new: the device's slot, or -1."""
        return self.lib.lift_hle_fast_di_new(this, kind)

    def di_cfg(self, slot, coop, has_fmt, size, bufsize, objs):
        """hle_fast.c lift_hle_fast_di_cfg; objs: [(kind, instance, offset)]."""
        arr = (c_uint32 * max(1, 3 * len(objs)))(*[v & 0xFFFFFFFF for o in objs for v in o])
        self.lib.lift_hle_fast_di_cfg(slot, coop & 0xFFFFFFFF, int(has_fmt), size, bufsize & 0xFFFFFFFF, len(objs), arr)

    def di_field(self, slot, field, v=None):
        """hle_fast.c lift_hle_fast_di_field: read (v None) or write a run-state field; returns the value."""
        return self.lib.lift_hle_fast_di_field(slot, field, 0 if v is None else 1, 0 if v is None else int(v))

    def di_queue(self, slot, op, i=0, ev=None):
        """hle_fast.c lift_hle_fast_di_queue: op 0 length, 1 append ev, 2 pop, 3 clear (the length after); 4 event i
        as a tuple, or None."""
        if ev is not None:
            self._ev[:] = [v & 0xFFFFFFFF for v in ev]
        r = self.lib.lift_hle_fast_di_queue(slot, op, i, self._ev)
        if op == 4:
            return tuple(self._ev) if r else None
        return r

    def di_keys(self):
        """dinput Input.keys (256 bytes) and buttons (8), in place in hle_fast.c."""
        return memoryview((ctypes.c_uint8 * 264).from_address(self.lib.lift_hle_fast_di_keys())).cast("B")

    def ds_new(self, this):
        """hle_fast.c lift_hle_fast_ds_new: the buffer's slot."""
        return self.lib.lift_hle_fast_ds_new(this)

    def ds_cfg(self, slot, ptr, size, wfx):
        """hle_fast.c lift_hle_fast_ds_cfg: the buffer's layout and format (a dsound wfx dict, or None)."""
        self.lib.lift_hle_fast_ds_cfg(slot, ptr, size, bool(wfx), (wfx or {}).get("avg", 0) & 0xFFFFFFFF,
                                      (wfx or {}).get("align", 0) & 0xFFFFFFFF)

    def ds_field(self, slot, field, v=None):
        """hle_fast.c lift_hle_fast_ds_field: read (v None) or write a run-state field; returns the value."""
        return self.lib.lift_hle_fast_ds_field(slot, field, 0 if v is None else 1, 0.0 if v is None else float(v))

    def ds_gains(self, slot, gl, gr, downmix):
        self.lib.lift_hle_fast_ds_gains(slot, gl, gr, downmix)

    def ds_mixer(self, mx):
        """Register dsound's Mixer (its mpa handle and functions) with hle_fast.c, or none (mx None or closed)."""
        if mx is None or not mx.m:
            self.lib.lift_hle_fast_ds_mixer(None, None, None, None)
            return
        fn = [ctypes.cast(getattr(mx.lib, n), c_void_p) for n in ("mpa_voice_write", "mpa_voice_get_pos", "mpa_voice_set_gain")]
        self.lib.lift_hle_fast_ds_mixer(mx.m, *fn)

    def blob(self, which, a, data=None, clear=False):
        """hle_fast.c lift_hle_fast_blob: which 0 a transform (a = state, 64 bytes), 1 the viewport (24 bytes). Without
        data, the bytes or None when not set (or out of range); with data, sets them (False when out of range)."""
        if clear:
            return bool(self.lib.lift_hle_fast_blob(which, a, 2, self._blob))
        if data is None:
            if not self.lib.lift_hle_fast_blob(which, a, 0, self._blob):
                return None
            return bytes(self._blob)[:64 if which == 0 else 24]
        ctypes.memmove(self._blob, data, len(data))
        return bool(self.lib.lift_hle_fast_blob(which, a, 1, self._blob))

    def set(self, which, a, b, v, v2=0, on=True):
        """hle_fast.c lift_hle_fast_set: False when the key is out of C's range (the caller keeps it)."""
        return bool(self.lib.lift_hle_fast_set(which, a & 0xFFFFFFFF, b & 0xFFFFFFFF, v & 0xFFFFFFFF,
                                                v2 & 0xFFFFFFFF, int(on)))

    def get(self, which, a=0, b=0):
        """(v, v2) when set, else None."""
        if not self.lib.lift_hle_fast_get(which, a & 0xFFFFFFFF, b & 0xFFFFFFFF, ctypes.byref(self._v),
                                          ctypes.byref(self._v2)):
            return None
        return self._v.value, self._v2.value

    def obj(self, addr, iface, ptr=0, fmt=0):
        self.lib.lift_hle_fast_obj(addr, self.OBJ_KINDS.get(iface, 0), ptr or 0, fmt or 0)

    def tex(self, addr, ver, sent):
        """A texture's lock version and the version last sent to the renderer (None: not sent in this capture)."""
        self.lib.lift_hle_fast_tex(addr, ver, sent or 0, int(sent is not None))

    def capture(self, mode, sink=None, r=None, err=None, reset_sent=False):
        self.lib.lift_hle_fast_capture(mode, sink, r, err, int(reset_sent))

    def bind(self, idx, kind):
        if (kind <= HLE_FAST_H50 or (self.h60 and kind <= HLE_FAST_H60) or (self.h61 and kind <= HLE_FAST_H61)
                or self.h62):
            self.lib.lift_hle_fast_bind(idx, kind)

    @property
    def total(self):
        """Calls served in C so far."""
        return int(self.lib.lift_hle_fast_total())

    def merge(self, rec=None):
        """Add the calls and value histograms counted in C to the D3D8 Recorder rec (default e.d3d), dinput's and
        dsound's Recorders and the stubs' call counts, then clear them in C. Called by the Recorders' report."""
        import d3d8
        e = self.e
        rec = rec or getattr(e, "d3d", None)
        di = getattr(e, "di", None)
        ds = getattr(e, "ds", None)
        DIP = {0: ("Acquire", lambda v: "ok"), 1: ("GetDeviceState", lambda v: "ok"),
               2: ("GetDeviceData", lambda v: "%d events" % v if v else "empty"),
               3: ("GetDeviceData", lambda v: "0x%x" % v), 4: ("GetDeviceState", lambda v: "0x%x" % v)}
        cap = 4096
        idx, n = (c_uint32 * cap)(), (c_uint64 * cap)()
        k = self.lib.lift_hle_fast_counts(idx, n, cap)
        for i in range(k):
            key = e.stubs[idx[i]]
            e.stub_counts[key] += n[i]
            if key[0] == _D and rec is not None:
                rec.calls[key[1]] += n[i]
            elif key[0] == _DI and di is not None:
                di.calls[key[1]] += n[i]
            elif key[0] == _DS and ds is not None:
                ds.calls[key[1]] += n[i]
        keys, n = (c_uint64 * 65536)(), (c_uint64 * 65536)()
        k = self.lib.lift_hle_fast_hist(keys, n, 65536)
        for i in range(k):
            kk = keys[i]
            kind, a, b, v = kk >> 60, (kk >> 48) & 0xFFF, (kk >> 32) & 0xFFFF, kk & 0xFFFFFFFF
            if kind == 8:
                if di is not None:
                    name, res = DIP[a]
                    di.polls[("keyboard" if b == 0 else "mouse", name, res(v))] += n[i]
                continue
            if rec is None:
                continue
            if kind == 1:
                rec.render_states[a][v] += n[i]
            elif kind == 2:
                rec.tss[(a, b)][v] += n[i]
            elif kind == 3:
                o = rec.objs.get(v)
                if o and "fmt" in o:
                    rec.sampler_texfmt[(a, d3d8.fmt_name(o["fmt"]))] += n[i]
            elif kind == 4:
                rec.draws["DrawIndexedPrimitive %s" % d3d8.PRIM_NAMES.get(v, v)] += n[i]
            elif kind == 5:
                rec.fvfs[v] += n[i]
            elif kind == 6:
                rec.transforms[v] += n[i]
            elif kind == 7:
                rec.clears[v] += n[i]


class NativeError(RuntimeError):
    pass


# ---------------------------------------------------------------- x87 conversion (Python reference)

def d2x(d):
    """double -> Unicorn 80-bit register value (mantissa, sign|exponent). Exact for every double."""
    bits = struct.unpack("<Q", struct.pack("<d", d))[0]
    sign = (bits >> 63) << 15
    e11 = (bits >> 52) & 0x7FF
    frac = bits & ((1 << 52) - 1)
    if e11 == 0x7FF:
        if frac == 0:
            return (1 << 63, sign | 0x7FFF)
        return ((1 << 63) | (frac << 11), sign | 0x7FFF)     # NaN: payload kept
    if e11 == 0:
        if frac == 0:
            return (0, sign)
        m, ex = math.frexp(abs(d))                             # denormal: normalise
        return (int(m * (1 << 53)) << 11, sign | (ex - 1 + 16383))
    return (((1 << 52) | frac) << 11, sign | (e11 + 15360))


def x2d(mant, exp):
    """Unicorn 80-bit value -> (double, exact). exact is False when the value is not a double."""
    sign = -1.0 if exp & 0x8000 else 1.0
    e = exp & 0x7FFF
    if e == 0x7FFF:
        if mant & ((1 << 63) - 1):
            frac = (mant >> 11) & ((1 << 52) - 1) or (1 << 51)
            bits = ((exp >> 15) << 63) | (0x7FF << 52) | frac
            return struct.unpack("<d", struct.pack("<Q", bits))[0], True
        return sign * math.inf, True
    if mant == 0:
        return sign * 0.0, True
    e_eff = e or 1
    if mant & 0x7FF == 0:                                     # fits in 53 bits: exact through ldexp
        try:
            d = math.ldexp(float(mant >> 11), e_eff - 16383 - 52)
        except OverflowError:
            d = math.inf
        if not math.isinf(d) and d != 0.0 and math.frexp(d)[1] >= -1021:
            return sign * d, True
    try:
        d = float(Fraction(mant) * Fraction(2) ** (e_eff - 16383 - 63))
    except OverflowError:
        d = math.inf
    d = sign * d
    return d, (d2x(d) == (mant, exp))


def _bits(d):
    return struct.pack("<d", d)


def _merge_unseen(log, addr, old):
    """Record old[i] as the old value of guest byte addr+i in log, for the bytes log has not seen yet (mpemu UndoLog)."""
    pages = log.pages
    end = addr + len(old)
    a, k = addr, 0
    while a < end:
        pi = a >> 12
        stop = min(end, (pi + 1) << 12)
        pg = pages.get(pi)
        if pg is None:
            pg = pages[pi] = _UndoPage()
        off = a & 0xFFF
        lim = off + (stop - a)
        seen = pg.seen
        chunk = old[k:k + (stop - a)]
        if seen.find(1, off, lim) < 0:
            pg.old[off:lim] = chunk
            seen[off:lim] = _ONES[:lim - off]
        else:
            for j in range(off, lim):
                if not seen[j]:
                    pg.old[j] = chunk[j - off]
                    seen[j] = 1
        k += stop - a
        a = stop


# ---------------------------------------------------------------- the bridge

def inventory_base(inventory_path):
    """(lower-case module name, load base) that a function inventory (lift/functions.py) was made for."""
    with open(inventory_path) as fh:
        inv = json.load(fh)
    return inv["module"].lower(), int(inv["base"], 16)


class LiftLoader:
    """Installs the lifted functions of each module of the library into the emulator: at setup, for a module that is
    loaded already (add with its mpemu.Module), or at load time, for a deferred one (add without it: a DLL the game
    loads with LoadLibraryA). The load hook is Emu.on_module_loaded, which load_library calls after the image is
    mapped, relocated and its imports resolved, before DllMain.

    mode: "fast" (install_fast), "slow" (install) or "diff" (diff_add; diff_only, a set of va or None, limits the
    hooks). In diff mode, call native.enable_diff(only=set()) before adding modules. Lifted code is specific to the
    base its module was lifted for: a module loaded elsewhere is refused with a NativeError."""

    def __init__(self, native, mode, diff_only=None):
        if mode not in ("fast", "slow", "diff"):
            raise NativeError("LiftLoader: unknown mode %r" % mode)
        self.native = native
        self.mode = mode
        self.diff_only = diff_only
        self.deferred = {}         # lower-case name -> (base, real entries), until the module loads
        self.count = 0             # functions installed (or hooked) so far
        native.e.on_module_loaded.append(self.on_loaded)

    def add(self, inventory_path, mod=None):
        """Register the module of an inventory: installed now if mod (its mpemu.Module) is given, else deferred."""
        name, base = inventory_base(inventory_path)
        real = function_entries(inventory_path)
        if mod is not None:
            if mod.name.lower() != name:
                raise NativeError("inventory %s is for %s, not %s" % (inventory_path, name, mod.name))
            self._install(mod, base, real, "at setup")
        else:
            self.deferred[name] = (base, real)

    def on_loaded(self, mod):
        """The load hook (Emu.on_module_loaded): installs a deferred module's entries."""
        key = mod.name.lower()
        if key in self.deferred:
            base, real = self.deferred.pop(key)
            self._install(mod, base, real, "at load")

    def finish(self):
        """Prints one line per deferred module that never loaded; returns their names."""
        names = sorted(self.deferred)
        for name in names:
            print("[lift] %s: never loaded" % name)
        return names

    def _install(self, mod, base, real, when):
        if mod.base != base:
            raise NativeError("%s was loaded at 0x%08x, but the library was lifted for 0x%08x (lifted code is "
                              "base-specific)" % (mod.name, mod.base, base))
        n = self.native
        vas = [va for va in sorted(n.table) if va in real and mod.base <= va < mod.base + mod.size]
        if self.mode == "diff":
            names = {va: name for name, va in mod.exports.items()}
            hook = vas if self.diff_only is None else [va for va in vas if va in self.diff_only]
            n.diff_add(hook, names)
            print("[lift] %s: %d lifted functions diffed %s" % (mod.name, len(hook), when))
            self.count += len(hook)
            return
        if self.mode == "fast":
            n.install_fast(vas)
        else:
            for va in vas:
                n.install(va)
        print("[lift] %s: %d lifted functions installed %s" % (mod.name, len(vas), when))
        self.count += len(vas)


class Native:
    """Lifted functions for one Emu. Construct once per (Emu, dylib). Sets emu.native."""

    def __init__(self, emu, lib_path, crt=True, thunk_shortcut=True, hle_direct=True, c_heap=True, call_cache=True,
                 c_hle=True, c_seh=True):
        if emu.native is not None:
            raise NativeError("this Emu already has a Native bound")
        self.e = emu
        self.lib_path = lib_path
        self.lib = ctypes.CDLL(lib_path)
        self._setup_lib()
        if hasattr(self.lib, "lift_thunk_shortcut"):            # runtime.c call_fill: calls through import thunks
            self.lib.lift_thunk_shortcut(int(thunk_shortcut))
        else:
            print("native: this library predates the thunk shortcut (rebuild it to get it)")
        if hasattr(self.lib, "lift_call_cache"):                # runtime.c call_resolve: the call-target cache
            self.lib.lift_call_cache(int(call_cache))
        self._verify_layout()
        self._verify_regs()
        self.table, self.flags = self._load_table()
        self.error = None            # exception raised inside call_guest, re-raised by the outermost native call
        self.depth = 0               # active native calls (nested through call_guest)
        self._calls = 0              # native calls dispatched by the slow path (the calls property adds the fast path)
        self._fast = False           # enable_fast has run
        self._fast_undo = False      # the undo-log state mirrored into the C hook (check_undo)
        self.fast_error = None       # the fast path's error, raised by mpemu._drive when the outermost run ends
        self._fast_cb = None         # the ctypes fallback (kept alive: C holds its address)
        self._hle_direct = hle_direct and hasattr(self.lib, "lift_hle_direct_init")   # see enable_fast
        if hle_direct and not self._hle_direct:
            print("native: this library predates direct HLE calls (rebuild it to get them)")
        self._hle_cb = None          # the ctypes callback for direct HLE calls (kept alive: C holds its address)
        self._c_heap = c_heap and self._hle_direct and hasattr(self.lib, "lift_heap_reset")   # see enable_fast
        if c_heap and self._hle_direct and not self._c_heap:
            print("native: this library predates the C heap (rebuild it to get it)")
        self._heap_idx = None        # [HeapAlloc, HeapFree] stub indexes until both are bound in C (_hle_direct_call)
        # RaiseException/RtlUnwind from lifted code in C (seh.c, E3): only with the frame handlers lifted too (see
        # enable_fast), since a handler run by the emulator would discard the C dispatcher's frame under it
        self._c_seh = c_seh and self._hle_direct and hasattr(self.lib, "lift_seh_bind")
        self.c_seh = False           # bound (enable_fast)
        self._c_hle = c_hle and self._hle_direct and hasattr(self.lib, "lift_hle_fast_reset")   # see enable_fast
        if c_hle and self._hle_direct and not self._c_hle:
            print("native: this library predates the C HLE handlers (rebuild it to get them)")
        self.hle_fast = None         # HleFast once the fast path runs (hle_fast.c)
        self._fast_bound = set()     # stub indexes bound to a hle_fast.c handler
        self._fast_slot = {}         # va -> slot number (install_fast)
        self.inexact = 0             # x87 registers that were not exactly a double on the way to the CPU
        self.installed = {}          # va -> (slot, original 5 bytes)
        self._pool = []              # (CPU, address) not in use (nested calls take their own)
        self.has_wlog = hasattr(self.lib, "lift_wlog_begin")
        self.diffing = False         # differential mode (enable_diff): entry hooks, run_diff instead of run_pending
        self.diff_k = 0
        self.diff_budget = 0         # guest instructions per reference run (0: unlimited), see enable_diff
        self.dstats = {}             # va -> per-function statistics (see enable_diff)
        self._diff_hooks = {}        # va -> Unicorn hook handle, while the function is diffed
        self._retired = set()        # functions that stopped being diffed (budget spent, or a mismatch)
        self._flush_pending = False
        self._diff_l2 = None         # undo log of the native run in progress: call_guest merges the C log into it
        self._cb = _CALL_GUEST_T(self._call_guest)     # must stay referenced: C holds its address
        self._cb_addr = ctypes.cast(self._cb, c_void_p)
        # Lifted code calls the C trampoline, which restores round-to-nearest around the Python callback.
        self.lib.lift_set_guest_callback(self._cb_addr)
        self.lib.lift_set_bridge_stop(STUB_BASE)      # the slow bridge's return address (lift_guest keeps it)
        self._tramp_addr = c_void_p(self.lib.lift_guest_trampoline())
        self._bind()
        self.sync_regions()                             # the helpers and the thunk shortcut read guest memory through it
        self.crt = self._bind_crt() if crt else {}     # helper name -> guest va (CRT_HELPERS that were bound)
        emu.native = self

    # -- setup
    def _setup_lib(self):
        lib = self.lib
        lib.lift_bridge_init.argtypes = [c_void_p, c_void_p, c_void_p]
        lib.lift_bridge_init.restype = None
        lib.lift_invoke.argtypes = [c_void_p, c_void_p, c_int]
        lib.lift_invoke.restype = None
        lib.lift_set_guest_callback.argtypes = [c_void_p]
        lib.lift_set_guest_callback.restype = None
        lib.lift_guest_trampoline.argtypes = []
        lib.lift_guest_trampoline.restype = c_void_p
        lib.lift_bridge_regs.argtypes = [POINTER(c_int32)]
        lib.lift_bridge_regs.restype = None
        lib.lift_sync_from_uc.argtypes = [c_void_p, c_int]
        lib.lift_sync_from_uc.restype = c_int
        lib.lift_sync_to_uc.argtypes = [c_void_p, c_int]
        lib.lift_sync_to_uc.restype = None
        lib.lift_conv_d2x.argtypes = [c_double, POINTER(c_uint64), POINTER(c_uint16)]
        lib.lift_conv_d2x.restype = None
        lib.lift_conv_x2d.argtypes = [c_uint64, c_uint16, POINTER(c_int)]
        lib.lift_conv_x2d.restype = c_double
        lib.lift_invoke_checked.argtypes = [c_void_p, c_void_p, c_int]
        lib.lift_invoke_checked.restype = c_int
        lib.lift_diff_abort.argtypes = []
        lib.lift_diff_abort.restype = None
        lib.lift_fast_init.argtypes = [c_void_p] * 7 + [c_uint32, c_uint32, c_void_p, c_void_p, c_uint32]
        lib.lift_fast_init.restype = None
        lib.lift_fast_set.argtypes = [c_uint32, c_uint32]
        lib.lift_fast_set.restype = c_int
        lib.lift_set_bridge_stop.argtypes = [c_uint32]
        lib.lift_set_bridge_stop.restype = None
        lib.lift_is_bridge_ret.argtypes = [c_uint32]
        lib.lift_is_bridge_ret.restype = c_int
        lib.lift_fast_ret_current.argtypes = []
        lib.lift_fast_ret_current.restype = c_uint32
        lib.lift_fast_halt_set.argtypes = [c_int]
        lib.lift_fast_halt_set.restype = None
        lib.lift_fast_undo_set.argtypes = [c_int]
        lib.lift_fast_undo_set.restype = None
        lib.lift_fast_stats.argtypes = [POINTER(c_uint64)]
        lib.lift_fast_stats.restype = None
        lib.lift_fast_slot_counts.argtypes = [POINTER(c_uint64)]
        lib.lift_fast_slot_counts.restype = None
        lib.lift_fast_guest_counts.argtypes = [POINTER(c_uint32), POINTER(c_uint64), c_uint32]
        lib.lift_fast_guest_counts.restype = c_uint32
        lib.lift_fast_entry_callers.argtypes = [POINTER(c_uint32), POINTER(c_uint64), c_uint32]
        lib.lift_fast_entry_callers.restype = c_uint32
        lib.lift_crt_bind.argtypes = [ctypes.c_char_p, c_uint32, c_uint32]
        lib.lift_crt_bind.restype = c_int
        lib.lift_crt_regions.argtypes = [POINTER(c_uint32), c_uint32]
        lib.lift_crt_regions.restype = c_int
        if hasattr(lib, "lift_hle_direct_init"):       # absent from libraries built before H39
            lib.lift_hle_direct_init.argtypes = [c_void_p, c_uint32, c_uint32]
            lib.lift_hle_direct_init.restype = None
            lib.lift_hle_direct_calls.argtypes = []
            lib.lift_hle_direct_calls.restype = c_uint64
        if hasattr(lib, "lift_set_entry_hook"):        # absent from libraries built before H63
            lib.lift_set_entry_hook.argtypes = [c_void_p]
            lib.lift_set_entry_hook.restype = None
        if hasattr(lib, "lift_seh_bind"):              # absent from libraries built before H58
            lib.lift_seh_bind.argtypes = [c_uint32] * 6
            lib.lift_seh_bind.restype = None
            lib.lift_seh_stats.argtypes = [POINTER(c_uint64)]
            lib.lift_seh_stats.restype = None
        if hasattr(lib, "lift_hle_fast_reset"):        # absent from libraries built before H50
            for name, args, res in (("reset", [], None), ("bind", [c_uint32, c_uint32], None),
                                    ("set", [c_int, c_uint32, c_uint32, c_uint32, c_uint32, c_int], c_int),
                                    ("get", [c_int, c_uint32, c_uint32, POINTER(c_uint32), POINTER(c_uint32)], c_int),
                                    ("blob", [c_int, c_uint32, c_int, c_void_p], c_int),
                                    ("di_new", [c_uint32, c_uint32], c_int),
                                    ("di_cfg", [c_int, c_uint32, c_int, c_uint32, c_uint32, c_uint32, c_void_p], None),
                                    ("di_field", [c_int, c_int, c_int, ctypes.c_int64], ctypes.c_int64),
                                    ("di_queue", [c_int, c_int, c_uint32, c_void_p], c_uint32),
                                    ("di_keys", [], c_void_p),
                                    ("ds_new", [c_uint32], c_int),
                                    ("ds_cfg", [c_int, c_uint32, c_uint32, c_int, c_uint32, c_uint32], None),
                                    ("ds_field", [c_int, c_int, c_int, ctypes.c_double], ctypes.c_double),
                                    ("ds_gains", [c_int, ctypes.c_double, ctypes.c_double, c_int], None),
                                    ("ds_mixer", [c_void_p] * 4, None),
                                    ("obj", [c_uint32, c_uint32, c_uint32, c_uint32], None),
                                    ("tex", [c_uint32, c_uint32, c_uint32, c_int], None),
                                    ("capture", [c_int, c_void_p, c_void_p, c_void_p, c_int], None),
                                    ("counts", [POINTER(c_uint32), POINTER(c_uint64), c_uint32], c_uint32),
                                    ("hist", [POINTER(c_uint64), POINTER(c_uint64), c_uint32], c_uint32),
                                    ("total", [], c_uint64)):
                f = getattr(lib, "lift_hle_fast_" + name, None)
                if f is None:                          # blob: absent before H60; di_*: before H61; ds_*: H62
                    continue
                f.argtypes = args
                f.restype = res
        if hasattr(lib, "lift_call_cache"):            # absent from libraries built before H47
            lib.lift_call_cache.argtypes = [c_int]
            lib.lift_call_cache.restype = None
            lib.lift_call_cache_stats.argtypes = [POINTER(c_uint64)]
            lib.lift_call_cache_stats.restype = None
        if hasattr(lib, "lift_heap_reset"):            # absent from libraries built before H44
            for name, args, res in (("reset", [c_uint64, c_uint64], None),
                                    ("set_live", [c_uint32, c_uint32, c_uint32], None),
                                    ("add_free", [c_uint32, c_uint32], None),
                                    ("alloc", [c_uint32, POINTER(c_int)], c_uint32),
                                    ("free", [c_uint32], c_int),
                                    ("get", [c_uint32, POINTER(c_uint32), POINTER(c_uint32)], c_int),
                                    ("reserve", [c_uint32, c_int], c_uint32),
                                    ("next", [], c_uint64),
                                    ("stats", [POINTER(c_uint64)], None),
                                    ("export_live", [POINTER(c_uint32), c_uint32], c_uint32),
                                    ("export_free", [POINTER(c_uint32), c_uint32], c_uint32),
                                    ("direct_bind", [c_uint32, c_uint32], None)):
                f = getattr(lib, "lift_heap_" + name)
                f.argtypes = args
                f.restype = res
        if hasattr(lib, "lift_thunk_shortcut"):        # absent from libraries built before H37
            lib.lift_thunk_shortcut.argtypes = [c_int]
            lib.lift_thunk_shortcut.restype = None
        lib.lift_crt_counts.argtypes = [POINTER(c_uint64), c_uint32]
        lib.lift_crt_counts.restype = c_uint32
        lib.lift_crt_call.argtypes = [c_void_p, c_uint32, c_uint32]
        lib.lift_crt_call.restype = c_int
        lib.lift_crt_name.argtypes = [c_uint32]
        lib.lift_crt_name.restype = ctypes.c_char_p
        if hasattr(lib, "lift_wlog_begin"):
            for fn in ("lift_wlog_begin", "lift_wlog_end", "lift_wlog_clear"):
                getattr(lib, fn).argtypes = []
                getattr(lib, fn).restype = None
            lib.lift_wlog_export.argtypes = [c_void_p, ctypes.c_size_t]
            lib.lift_wlog_export.restype = ctypes.c_size_t

    def _bind(self):
        """Give the C sync this emulator's engine handle and the libunicorn batch functions of the binding."""
        f = self.e.fast
        handle = f.h.value if isinstance(f.h, c_void_p) else int(f.h)
        rrb = ctypes.cast(f.lib.uc_reg_read_batch, c_void_p).value
        wrb = ctypes.cast(f.lib.uc_reg_write_batch, c_void_p).value
        self.lib.lift_bridge_init(handle, rrb, wrb)
        _OWNER[0] = self

    def sync_regions(self):
        """Hand the emulator's mapped regions to the C side (crt.c crt_mapped): the CRT helpers and the thunk shortcut
        (runtime.c) read guest memory only inside them, so the list must never hold more than the emulator maps.
        Returns 0, or -1 when there are too many regions (then nothing is mapped as far as the C side is concerned).
        Called by __init__ and by Emu.map for every region mapped later (DLLs loaded at run time, heap)."""
        pairs = [v for start, size in self.e.regions for v in (start, size)]
        return self.lib.lift_crt_regions((c_uint32 * len(pairs))(*pairs), len(pairs) // 2)

    def _bind_crt(self):
        """Bind the CRT_HELPERS whose module is loaded and whose guest code is the one crt.c reproduces."""
        bound = {}
        mods = {m.name.lower(): m for m in self.e.modules.values()}
        for (mod, name), ranges in CRT_HELPERS.items():
            m = mods.get(mod)
            va = m.exports.get(name) if m else None
            if not va or any(bytes(self.e.rd(m.base + rva, len(h) // 2)).hex() != h for rva, h in ranges):
                continue
            if self.lib.lift_crt_bind(name.encode(), va, m.base) < 0:
                # a library built before this helper existed: the calls stay guest calls
                print("native CRT: %s is not in this library (rebuild it to get the helper)" % name)
                continue
            bound[name] = va
        return bound

    def crt_counts(self):
        """helper name -> calls from lifted code it handled (since it was bound)."""
        n = self.lib.lift_crt_counts(None, 0)
        out = (c_uint64 * n)()
        self.lib.lift_crt_counts(out, n)
        return {self.lib.lift_crt_name(i).decode(): out[i] for i in range(n) if self.lib.lift_crt_name(i).decode() in self.crt}

    def _verify_layout(self):
        out = (c_uint32 * LAYOUT_WORDS)()
        n = self.lib.lift_cpu_layout(out)
        if n != LAYOUT_WORDS:
            raise NativeError("lift_cpu_layout wrote %d words, expected %d" % (n, LAYOUT_WORDS))
        if out[0] != ctypes.sizeof(CPU):
            raise NativeError("sizeof(CPU) is %d in the lifted library and %d in emu/native.py"
                              % (out[0], ctypes.sizeof(CPU)))
        for i, name in enumerate(LAYOUT_FIELDS):
            want = getattr(CPU, name).offset
            if out[1 + i] != want:
                raise NativeError("CPU.%s at offset %d in the lifted library, %d in emu/native.py"
                                  % (name, out[1 + i], want))
        k = 1 + len(LAYOUT_FIELDS)
        if (out[k] != ctypes.sizeof(_LiftEntry) or out[k + 1] != _LiftEntry.fn.offset
                or out[k + 2] != _LiftEntry.flags.offset):
            raise NativeError("LiftEntry layout differs between the library and emu/native.py")

    def _verify_regs(self):
        out = (c_int32 * len(BRIDGE_REG_IDS))()
        self.lib.lift_bridge_regs(out)
        if list(out) != list(BRIDGE_REG_IDS):
            raise NativeError("register ids of the C sync %s differ from unicorn.x86_const %s"
                              % (list(out), BRIDGE_REG_IDS))

    def _load_table(self):
        base = ctypes.addressof(c_uint8.in_dll(self.lib, "lift_table"))
        n = c_uint32.in_dll(self.lib, "lift_table_len").value
        ents = (_LiftEntry * (n + 1)).from_address(base)
        table, flags = {}, {}
        last = -1
        for i in range(n):
            va = ents[i].va
            if va <= last:
                raise NativeError("lift_table is not sorted by va")
            last = va
            table[va] = ents[i].fn
            flags[va] = bool(ents[i].flags & FPU_FLAG)
        return table, flags

    # -- state conversion (C)
    def _pull(self, addr, fpu):
        """C: CPU at addr <- emulator. fpu: also x87 and MMX state."""
        if _OWNER[0] is not self:
            self._bind()
        self.inexact += self.lib.lift_sync_from_uc(addr, 1 if fpu else 0)

    def _push(self, addr, fpu):
        """C: CPU at addr -> emulator."""
        if _OWNER[0] is not self:
            self._bind()
        self.lib.lift_sync_to_uc(addr, 1 if fpu else 0)

    def uc_to_cpu(self, cpu, fpu=True):
        """Copy the emulator's registers, flags and x87 state into cpu."""
        cpu.fs_base = TEB
        cpu.mem = self.e.mem_base
        self._pull(ctypes.addressof(cpu), fpu)

    def cpu_to_uc(self, cpu, fpu=True):
        """Copy cpu back into the emulator. EFLAGS bits other than the six arithmetic flags and DF keep their
        values; the x87 exception bits of FPSW are kept too."""
        self._push(ctypes.addressof(cpu), fpu)

    # -- state conversion (Python reference, the same semantics as the C sync; used by the tests)
    def _py_uc_to_cpu(self, cpu, fpu=True):
        e = self.e
        f = e.fast
        uc = e.uc
        for i, reg in enumerate(GPR_IDS):
            cpu.r[i] = f.get(reg)
        ef = f.get(UC_X86_REG_EFLAGS)
        for name, sh in FLAG_SHIFTS:
            setattr(cpu, name, (ef >> sh) & 1)
        if not fpu:
            return
        sw = uc.reg_read(UC_X86_REG_FPSW)
        cpu.top = (sw >> 11) & 7
        cpu.sw = sw & (SW_C_MASK | SW_EXC_MASK)
        cpu.cw = uc.reg_read(UC_X86_REG_FPCW) & 0xFFFF
        tagw = uc.reg_read(UC_X86_REG_FPTAG)
        tag = 0
        for p in range(8):
            if ((tagw >> (2 * p)) & 3) == 3:
                tag |= 1 << p
        cpu.tag = tag
        for p in range(8):
            mant, exp = uc.reg_read(UC_X86_REG_FP0 + p)
            cpu.mm[p] = mant
            if tag & (1 << p):
                cpu.st[p] = 0.0
                continue
            d, exact = x2d(mant, exp)
            if not exact:
                self.inexact += 1
            cpu.st[p] = d

    def _py_cpu_to_uc(self, cpu, fpu=True):
        e = self.e
        f = e.fast
        uc = e.uc
        for i, reg in enumerate(GPR_IDS):
            f.set(reg, cpu.r[i])
        ef = f.get(UC_X86_REG_EFLAGS)
        bits = 0
        for name, sh in FLAG_SHIFTS:
            if getattr(cpu, name):
                bits |= 1 << sh
        f.set(UC_X86_REG_EFLAGS, (ef & ~FLAG_MASK) | bits)
        fpu = fpu or cpu.mmx_dirty != 0
        if fpu:
            tag = cpu.tag
            for p in range(8):
                bit = 1 << p
                if cpu.mmx_dirty & bit:
                    uc.reg_write(UC_X86_REG_FP0 + p, (cpu.mm[p], 0xFFFF))
                elif tag & bit:
                    continue
                else:
                    cur = x2d(*uc.reg_read(UC_X86_REG_FP0 + p))[0]
                    if _bits(cur) == _bits(cpu.st[p]):
                        continue
                    uc.reg_write(UC_X86_REG_FP0 + p, d2x(cpu.st[p]))
            uc.reg_write(UC_X86_REG_FPCW, cpu.cw & 0xFFFF)
            sw = uc.reg_read(UC_X86_REG_FPSW)
            sw = (sw & ~(SW_TOP_MASK | SW_C_MASK | SW_EXC_MASK)) | ((cpu.top & 7) << 11) | (cpu.sw & (SW_C_MASK | SW_EXC_MASK))
            uc.reg_write(UC_X86_REG_FPSW, sw)
            tagw = uc.reg_read(UC_X86_REG_FPTAG)
            for p in range(8):
                sh = 2 * p
                if tag & (1 << p):
                    tagw |= 3 << sh
                elif ((tagw >> sh) & 3) == 3:
                    tagw &= ~(3 << sh)
            uc.reg_write(UC_X86_REG_FPTAG, tagw & 0xFFFF)
        cpu.mmx_dirty = 0

    # -- native calls
    def _take(self):
        if self._pool:
            return self._pool.pop()
        cpu = CPU()
        cpu.mem = self.e.mem_base
        cpu.call_guest = self._tramp_addr
        cpu.fs_base = TEB
        return cpu, ctypes.addressof(cpu)

    def run_pending(self, va):
        """Run the lifted function of va for the guest call the emulator just stopped on. Called by
        mpemu._run_native_pending, which then continues at the return address."""
        if self.e._undo_stack:
            raise NativeError("native code cannot run while an undo log is active: its memory writes "
                              "bypass the log (0x%08x)" % va)
        fn = self.table.get(va)
        if fn is None:
            raise NativeError("no lifted function at 0x%08x" % va)
        fpu = self.flags[va]
        cpu, addr = self._take()
        try:
            self._pull(addr, fpu)
            self.depth += 1
            self.calls += 1
            try:
                self.lib.lift_invoke(addr, fn, 1 if fpu else 0)    # sets the guest's rounding around the call
            finally:
                self.depth -= 1
            self._push(addr, fpu)
        finally:
            self._pool.append((cpu, addr))
        if self.depth == 0 and self.error is not None:
            err, self.error = self.error, None
            raise err

    def _call_guest(self, cpu_p, addr):
        """CPU.call_guest: run guest code at addr as if called (no return address pushed by the caller).
        ctypes swallows exceptions raised here, so they are kept and raised by the outermost native call.
        The caller may have x87 or MMX state, so both are synced both ways."""
        if self.error is not None or self.e._hle_div is not None:
            # after a divergence the guest cannot run: the native code must stop (differential mode aborts it, see
            # lift_diff_abort), not run on emulating nothing
            self.lib.lift_diff_abort()
            return
        try:
            e = self.e
            if self._diff_l2 is not None:
                self._wl_flush()                    # native writes so far go in before the emulator writes
            cpu = cpu_p.contents
            caddr = ctypes.addressof(cpu)
            self._push(caddr, True)
            sp = (e.fast.get(UC_X86_REG_ESP) - 4) & 0xFFFFFFFF
            e.wr32(sp, STUB_BASE)                   # the guest returns here; _drive stops at STUB_BASE
            e.fast.set(UC_X86_REG_ESP, sp)
            e._drive(addr, 0)
            if e.fatal or e.exit_code is not None:
                raise NativeError("guest code called from native code stopped: %s" % (
                    e.fatal or "process exit"))
            self._pull(caddr, True)
        except BaseException as ex:                 # noqa: BLE001 - re-raised later, see run_pending
            self.error = ex
            self.lib.lift_diff_abort()

    # -- installing lifted functions into the emulator
    def install(self, va):
        """Route guest calls and jumps to va to the lifted function. The first 5 bytes at va become a jmp to a
        native slot; the original bytes are kept for uninstall."""
        if va in self.installed:
            return
        if va not in self.table:
            raise NativeError("no lifted function at 0x%08x" % va)
        e = self.e
        slot = e.native_slot(va)
        orig = bytes(e.rd(va, 5))
        rel = (slot - (va + 5)) & 0xFFFFFFFF
        e.wr(va, b"\xe9" + struct.pack("<I", rel))
        e.uc.ctl_flush_tb()          # translated blocks may hold the old bytes (Unicorn does not see host writes)
        self.installed[va] = (slot, orig)

    def uninstall(self, va):
        if va not in self.installed:
            return
        slot, orig = self.installed.pop(va)
        e = self.e
        e.wr(va, orig)
        e.uc.ctl_flush_tb()

    @property
    def calls(self):
        """Native function calls dispatched: the slow path's count plus the fast path's (C counter, since enable_fast)."""
        return self._calls + (self._fast_stat(0) if self._fast else 0)

    @calls.setter
    def calls(self, value):
        self._calls = value - (self._fast_stat(0) if self._fast else 0)

    def stats(self):
        out = {"calls": self.calls, "inexact": self.inexact, "installed": len(self.installed)}
        if self._fast:
            out["fast"] = self.fast_stats()
        return out

    # -- fast dispatch (C: lift/runtime/runtime.c, "fast native dispatch")
    def _fast_stat(self, k):
        out = (c_uint64 * len(FAST_COUNTERS))()
        self.lib.lift_fast_stats(out)
        return out[k]

    def fast_call_counts(self):
        """va -> calls dispatched through its fast slot since enable_fast (functions never called are left out)."""
        out = (c_uint64 * FAST_SLOTS)()
        self.lib.lift_fast_slot_counts(out)
        return {va: out[slot] for va, slot in self._fast_slot.items() if out[slot]}

    def fast_guest_counts(self):
        """target va -> guest calls made to it from native code since enable_fast (0: targets the C table had no room
        for)."""
        n = self.lib.lift_fast_guest_counts(None, None, 0)
        addrs, counts = (c_uint32 * n)(), (c_uint64 * n)()
        n = self.lib.lift_fast_guest_counts(addrs, counts, n)
        return {addrs[i]: counts[i] for i in range(n)}

    def fast_entry_callers(self):
        """return address -> fast-path entries from there (the caller of a native slot) since enable_fast (0: callers
        the C table had no room for)."""
        n = self.lib.lift_fast_entry_callers(None, None, 0)
        addrs, counts = (c_uint32 * n)(), (c_uint64 * n)()
        n = self.lib.lift_fast_entry_callers(addrs, counts, n)
        return {addrs[i]: counts[i] for i in range(n)}

    def fast_stats(self):
        """The fast path's counters since enable_fast (FAST_COUNTERS): native calls, guest calls made from native code,
        fallbacks (a nested run stopped anywhere but at its return address), the deepest nesting, calls refused for
        depth, and x87 registers that were not exact doubles on the way to the CPU."""
        return {n: self._fast_stat(i) for i, n in enumerate(FAST_COUNTERS)}

    def enable_fast(self):
        """Map the fast slot region and register the code hook (C) on this Emu's engine. Idempotent. One Native owns
        the fast path per process: the C side keeps one engine handle and one slot table (like the sync)."""
        if self._fast:
            return
        e = self.e
        if e.native is not self:
            raise NativeError("enable_fast: this Native is not bound to its Emu")
        if e._undo_stack:
            raise NativeError("enable_fast under an undo log: native code writes would bypass it")
        e.map(FAST_BASE, FAST_SIZE)
        # hlt everywhere (slot 0, and each level's return address at slot offset 8), and `int 0x99` at the start of
        # every slot: the interrupt hook (C) dispatches the slot's lifted function (runtime.c, fast native dispatch)
        slots = bytearray(b"\xf4" * FAST_SIZE)
        for s in range(1, FAST_SLOTS):
            slots[s * FAST_STRIDE:s * FAST_STRIDE + 2] = b"\xcd\x99"
        e.wr(FAST_BASE, bytes(slots))
        f = e.fast

        def addr_of(name):
            return ctypes.cast(getattr(f.lib, name), c_void_p).value
        handle = f.h.value if isinstance(f.h, c_void_p) else int(f.h)
        self._fast_cb = _FAST_FALLBACK_T(self._fast_fallback)
        self.lib.lift_fast_init(handle, addr_of("uc_hook_add"), addr_of("uc_emu_start"),
                                addr_of("uc_reg_read_batch"), addr_of("uc_reg_write_batch"), addr_of("uc_reg_write"),
                                addr_of("uc_emu_stop"), FAST_BASE, FAST_SIZE, ctypes.cast(self._fast_cb, c_void_p),
                                c_void_p(e.mem_base), TEB)
        if self._hle_direct:         # calls from lifted code to HLE stubs in mpemu.HLE_DIRECT skip the emulator
            self._hle_cb = _HLE_DIRECT_T(self._hle_direct_call)
            self.lib.lift_hle_direct_init(ctypes.cast(self._hle_cb, c_void_p), STUB_BASE, STUB_STRIDE)
        if self._c_heap and not isinstance(e.heap, CHeap):   # the heap moves to C: HeapAlloc/HeapFree from lifted code
            e.heap = CHeap(self.lib, e.heap)                  # are served there once their stubs are bound
            self._heap_idx = [0xFFFFFFFF, 0xFFFFFFFF]
        if self._c_seh:
            self._bind_seh()
        if self._c_hle and self.hle_fast is None:            # QPC and the hot D3D8 methods: served in C once bound
            self.hle_fast = e.hle_fast = HleFast(self.lib, e)
            if getattr(e, "d3d", None) is not None:
                e.d3d.attach_fast(e)
        _OWNER[0] = self
        self._fast = True
        e.uc.ctl_flush_tb()           # the hook reaches only code translated after it was added

    SEH_HANDLERS = ("__CxxFrameHandler", "_except_handler3", "_CxxThrowException")

    def _bind_seh(self):
        """RaiseException and RtlUnwind from lifted code go to seh.c when MSVCRT's frame handlers are lifted (the
        library has them and msvcrt.dll is loaded): the chain's handlers then run natively, and their transfers to a
        catch or __except continuation are native too (x86c.DEAD_FRAMES). Otherwise Python serves them as before."""
        e = self.e
        crt = e.find_module("msvcrt.dll")
        if crt is None or not all(crt.exports.get(n) in self.table for n in self.SEH_HANDLERS):
            return
        idx = [(e.stub_for("KERNEL32.DLL", n) - STUB_BASE) // STUB_STRIDE for n in ("RaiseException", "RtlUnwind")]
        self.lib.lift_seh_bind(idx[0], idx[1], e.stub_for("NTDLL.DLL", "ExceptionNestedHandler"), TEB,
                               mpemu.STACK_TOP - mpemu.STACK_SIZE, mpemu.STACK_TOP)
        self.c_seh = True

    def seh_stats(self):
        """seh.c counters: raises, unwinds, raises handled in C, deepest nesting of dispatches."""
        out = (c_uint64 * 4)()
        self.lib.lift_seh_stats(out)
        return dict(zip(("raises", "unwinds", "handled", "depth"), [int(v) for v in out]))

    def install_fast(self, vas):
        """As install, for each va in vas, through the fast path: the entry jumps to a slot whose hook runs the lifted
        function from inside emu_start (see enable_fast). Each slot is bound once per va; the translations are flushed
        once at the end. May be called again later (LiftLoader does, for a module loaded after setup): slot numbers
        are handed out in order of first install (len(_fast_slot) + 1, so they never repeat), and a va already
        installed is skipped."""
        self.enable_fast()
        e = self.e
        for va in vas:
            if va in self.installed:
                continue
            if va not in self.table:
                raise NativeError("no lifted function at 0x%08x" % va)
            slot = self._fast_slot.get(va)
            if slot is None:
                slot = len(self._fast_slot) + 1
                if slot >= FAST_SLOTS:
                    raise NativeError("more than %d fast slots" % (FAST_SLOTS - 1))
                if self.lib.lift_fast_set(slot, va) != 0:
                    raise NativeError("lift_fast_set failed for 0x%08x" % va)
                self._fast_slot[va] = slot
            addr = FAST_BASE + slot * FAST_STRIDE
            orig = bytes(e.rd(va, 5))
            rel = (addr - (va + 5)) & 0xFFFFFFFF
            e.wr(va, b"\xe9" + struct.pack("<I", rel))
            self.installed[va] = (addr, orig)
        e.uc.ctl_flush_tb()

    @property
    def hle_fast_calls(self):
        """Calls from lifted code served by hle_fast.c (QPC, the hot D3D8 methods) since enable_fast."""
        return self.hle_fast.total if self.hle_fast is not None else 0

    @property
    def call_cache_stats(self):
        """(hits, misses) of the call-target cache (runtime.c call_resolve) so far; (0, 0) without one."""
        if not hasattr(self.lib, "lift_call_cache_stats"):
            return 0, 0
        out = (c_uint64 * 2)()
        self.lib.lift_call_cache_stats(out)
        return out[0], out[1]

    @property
    def heap_direct_calls(self):
        """(HeapAlloc, HeapFree) calls from lifted code served in C (heap.c lift_heap_direct) since enable_fast."""
        if not isinstance(self.e.heap, CHeap):
            return 0, 0
        st = self.e.heap.stats()
        return st[6], st[7]

    def set_entry_hook(self, fn):
        """fn(va) runs when lifted code enters a function built with an entry hook (build.py --entry-hook; E4: the
        frame function). It runs inside native code: it must not call guest code, and an exception it raises is
        printed and dropped. None removes it. False when the library has no entry hooks (built before H63)."""
        if not hasattr(self.lib, "lift_set_entry_hook"):
            return False

        def _cb(va):
            try:
                fn(va)
            except BaseException:  # noqa: BLE001 - a ctypes callback cannot raise into C
                __import__("traceback").print_exc()
        self._entry_cb = _ENTRY_HOOK_T(_cb) if fn is not None else None     # C holds its address
        self.lib.lift_set_entry_hook(ctypes.cast(self._entry_cb, c_void_p) if fn is not None else None)
        return True

    @property
    def hle_direct_calls(self):
        """HLE calls lifted code made without the emulator (runtime.c hle_direct) since enable_fast."""
        return int(self.lib.lift_hle_direct_calls()) if self._hle_cb is not None else 0

    def _hle_direct_call(self, cpu_p, idx):
        """C calls this for a call from lifted code to HLE stub idx (runtime.c hle_direct; Emu.hle_direct runs the
        handler). An error is recorded as _fast_fallback records one, and the native frames are dropped (HLE_HALT)."""
        try:
            e = self.e
            if self._heap_idx is not None and idx < len(e.stubs) and e.stubs[idx] in HEAP_DIRECT:
                self._heap_idx[HEAP_DIRECT.index(e.stubs[idx])] = idx    # this call runs in Python; later ones in C
                self.lib.lift_heap_direct_bind(*self._heap_idx)
                if 0xFFFFFFFF not in self._heap_idx:
                    self._heap_idx = None
            if self.hle_fast is not None and idx not in self._fast_bound and idx < len(e.stubs):
                kind = HLE_FAST_KINDS.get(e.stubs[idx])
                # D3D8 handlers need the Recorder's state in C: bound once it is attached (d3d8.Recorder.attach_fast)
                if kind and (e.stubs[idx][0] != _D or getattr(getattr(e, "d3d", None), "_fast", None)):
                    self.hle_fast.bind(idx, kind)      # this call runs in Python; later ones in C
                    self._fast_bound.add(idx)
            r = e.hle_direct(idx, cpu_p.contents)
            if e.fatal or e.exit_code is not None:
                raise NativeError("guest code called from native code stopped: %s" % (e.fatal or "process exit"))
            return r
        except BaseException as ex:  # noqa: BLE001 - re-raised by mpemu._drive through _raise_fast
            if self.fast_error is None:
                self.fast_error = ex
            self.lib.lift_fast_halt_set(1)
            return HLE_HALT

    def _fast_fallback(self, cpu_p, addr, eip, err):
        """C calls this when a nested guest run stopped anywhere but at its return address (an unwind past native frames
        is handled in C): an HLE handler called
        emu_stop (fatal error, process exit, unimplemented import), a timer did, or Unicorn returned an error. When
        nothing is wrong, the driver finishes the guest call from eip; a stop by a timer is then not honoured (native
        frames cannot be suspended). Otherwise the error is recorded and native calls stop. Returns 1 when the guest
        call finished, 0 when an error was recorded.
        err -5: the run stopped past native entries (a dead-frame unwind, runtime.c Dead frames); nothing is driven, the
        C side only needs to know whether a stop was recorded (a fatal stop is not continued)."""
        try:
            e = self.e
            if err == -5:
                if e.fatal or e.exit_code is not None:
                    raise NativeError("guest code called from native code stopped: %s" % (e.fatal or "process exit"))
                return 1
            if err == -3:      # the hook met a native slot under an undo log (no guest state to finish)
                raise NativeError("native code cannot run while an undo log is active: its memory writes bypass the "
                                  "log (0x%08x)" % addr)
            if err == -4:      # an interrupt that is not a bound fast slot (addr is the interrupt number)
                raise NativeError("guest interrupt 0x%x at eip=0x%08x (no handler)" % (addr, eip))
            if err == -2:
                raise NativeError("native code called guest code nested more than %d levels deep" % FAST_MAX_DEPTH)
            if err:
                e.fatal = e.fatal or "UcError %d at eip=0x%08x" % (err, eip)
                raise NativeError("guest code called from native code stopped: %s" % e.fatal)
            if e.fatal or e.exit_code is not None:
                raise NativeError("guest code called from native code stopped: %s" % (e.fatal or "process exit"))
            e._drive(eip, 0, stop=self.lib.lift_fast_ret_current())    # this nesting level's return address
            if e.fatal or e.exit_code is not None:
                raise NativeError("guest code called from native code stopped: %s" % (e.fatal or "process exit"))
            return 1
        except BaseException as ex:  # noqa: BLE001 - re-raised by mpemu._drive through _raise_fast
            if self.fast_error is None:
                self.fast_error = ex
            self.lib.lift_fast_halt_set(1)
            return 0

    def check_undo(self):
        """Called by mpemu._drive: the C hook refuses native slots while an undo log is active (their writes bypass
        the log), as run_pending does. The flag is mirrored only when it changes."""
        if self._fast:
            on = bool(self.e._undo_stack)
            if on != self._fast_undo:
                self._fast_undo = on
                self.lib.lift_fast_undo_set(1 if on else 0)

    def _raise_fast(self):
        """Called by mpemu._drive when the outermost driver loop ends: re-raise the fast path's error, once."""
        if self.fast_error is not None:
            err, self.fast_error = self.fast_error, None
            self.lib.lift_fast_halt_set(0)
            raise err

    # -- differential mode
    def enable_diff(self, k=20, names=None, only=None, budget=DIFF_BUDGET):
        """Diff the first k calls of every lifted function (see run_diff). Adds one code hook per lifted entry.
        names maps va -> name for the report; only (a set of va) limits the hooks to lifted entries (see
        function_entries; None: every lifted entry; an empty set: none yet, see diff_add). budget: guest instructions
        one reference run may execute before the function is retired as too long: the run then finishes emulated, not
        compared (0: no budget).
        Needs a library built with lift/build.py --write-log."""
        if not self.has_wlog:
            raise NativeError("the library has no guest write log: build it with lift/build.py --write-log")
        if not isinstance(budget, int) or budget < 0:
            raise NativeError("enable_diff: budget must be a non-negative instruction count, not %r" % (budget,))
        names = names or {}
        self.e.diff_return_slot()         # allocated now: its write must not land in a caller's undo log
        self.diff_k = k
        self.diff_budget = budget
        self.diffing = True
        for va in self.table:
            self.dstats[va] = {"name": names.get(va, "0x%08x" % va), "calls": 0, "matches": 0, "mismatches": 0,
                               "divergences": 0, "reference_failed": 0, "too_long": 0, "bad": False,
                               "dead_stack_calls": 0, "mismatch_examples": [], "divergence_examples": []}
        self.diff_add([va for va in self.table if only is None or va in only])

    def diff_add(self, vas, names=None):
        """Hook more lifted entries for differential mode (enable_diff must have run): a module loaded after setup
        gets its hooks here. names maps va -> name for the report. Entries already hooked or retired are skipped;
        every va must be a lifted entry."""
        if not self.diffing:
            raise NativeError("diff_add: enable_diff has not run")
        names = names or {}
        for va in vas:
            if va not in self.table:
                raise NativeError("diff_add: no lifted function at 0x%08x" % va)
            if va in self._diff_hooks or va in self._retired:
                continue
            if va in names:
                self.dstats[va]["name"] = names[va]
            self._diff_hooks[va] = self.e.uc.hook_add(UC_HOOK_CODE, self._entry_hook, begin=va, end=va)
        self.e.uc.ctl_flush_tb()          # hooks only reach code translated after they are added

    def _entry_hook(self, uc, address, size, user):
        """A diffed function was entered from the emulator: stop, and let mpemu._drive call run_diff. Inside a diff
        (the reference or the native run) and outside the driver, the function just runs."""
        e = self.e
        if not self.diffing or e._diff_active or e._drive_depth == 0 or address in self._retired:
            return
        e._in_hook = True
        try:
            e._native_pending = address
            uc.emu_stop()
        finally:
            e._in_hook = False

    def run_diff(self, va):
        """Called by mpemu._run_native_pending in differential mode: the guest is at va (the entry instruction not
        run) with the return address at [esp]. Runs the function emulated (the reference, every HLE call recorded),
        then natively from the same state, with the HLE calls replayed from the record. Compares the two, then puts
        the reference's final registers and bytes back, so the game continues with the emulator's result. Returns the
        guest address to continue at (the return address; STUB_BASE when the reference did not return).

        Mechanics: the return address is replaced by the diff return slot during the reference run, so the reference
        stops there. The reference and the native run each have an undo log: the reference is rolled back before the
        native run; the native run's own writes come from the C log, which is merged into its undo log at every
        call_guest and at the end. Comparison: GPRs (esp included), the arithmetic flags, and when the function has
        the FPU flag the x87 status and tag words and the non-empty registers; memory: every byte either run wrote,
        final values. Flags the function leaves undefined are compared too: they are reported, not filtered."""
        e = self.e
        st = self.dstats[va]
        esp0 = e.fast.get(UC_X86_REG_ESP)
        ret = e.rd32(esp0)
        slot = e.diff_return_slot()
        e.wr32(esp0, slot)
        st["calls"] += 1
        e._diff_active = True
        try:
            cont, div, reg_diffs, mem_diffs, mem_count, outcome = self._diff_once(va, st, esp0, ret, slot)
        finally:
            e._diff_active = False
            e._hle_mode = None
            e._hle_rec = None
        if outcome == "too_long":
            # The budget ran out and the emulator finished the call: nothing was compared, and the function is not
            # diffed again (every later call runs emulated). cont is where the guest continues.
            st["too_long"] += 1
            self._retire(va)
            if self._flush_pending:
                self._flush_retired()
            return cont
        if outcome == "ref_failed":
            st["bad"] = True
            self._retire(va)
            if self._flush_pending:
                self._flush_retired()
            return cont                 # where the guest now is (see _diff_once)
        if div is not None:
            st["divergences"] += 1
            if len(st["divergence_examples"]) < _DIFF_EXAMPLES:
                st["divergence_examples"].append(div)
            st["bad"] = True
        elif reg_diffs or mem_count:
            st["mismatches"] += 1
            detail = list(reg_diffs)
            if mem_count:
                detail.append("%d bytes differ: %s" % (mem_count, ", ".join(
                    "0x%08x native 0x%02x ref 0x%02x" % (a, act, exp) for a, exp, act in mem_diffs[:3])))
            if len(st["mismatch_examples"]) < _DIFF_EXAMPLES:
                st["mismatch_examples"].append("; ".join(detail))
            st["bad"] = True
        else:
            st["matches"] += 1
        if st["bad"] or st["calls"] >= self.diff_k:
            self._retire(va)
        if self._flush_pending:
            self._flush_retired()
        return ret

    def _retire(self, va):
        """Stop diffing va: its hook goes now; the translated code that calls it is dropped by _flush_retired."""
        h = self._diff_hooks.pop(va, None)
        if h is not None:
            self.e.uc.hook_del(h)
        self._retired.add(va)
        self._flush_pending = True

    def _flush_retired(self):
        """A deleted hook stays active until a uc_emu_start ends: run an empty one (begin == until, as mpemu does), then
        drop the translated blocks that call the hooks (the cache range of each retired entry)."""
        uc = self.e.uc
        eip = uc.reg_read(UC_X86_REG_EIP)
        uc.emu_start(STUB_BASE, STUB_BASE)
        uc.reg_write(UC_X86_REG_EIP, eip)
        for va in self._retired:
            try:
                uc.ctl_remove_cache(va, va + 1)
            except Exception:           # noqa: BLE001 - not in this binding: flush all translations instead
                uc.ctl_flush_tb()
                break
        self._flush_pending = False

    def _diff_once(self, va, st, esp0, ret, slot):
        """The reference run, the native run and the comparison for one call. Returns (cont, divergence, register
        diffs, [(addr, ref, native)] up to a limit, count of differing bytes, outcome). outcome is None for a compared
        call; "ref_failed": the reference did not return to the call (see the branch below); "too_long": the reference
        used up its instruction budget, and the emulator finished the call from there (cont is where the guest is then:
        the return address, or where the run stopped, as for ref_failed). For both, nothing else is returned but cont."""
        e = self.e
        uc = e.uc
        fn = self.table[va]
        fpu = self.flags[va]

        # reference: emulated, every HLE call recorded with its effects
        log = e.undo_begin()
        rec = []
        e._hle_mode = "record"
        e._hle_rec = rec
        try:
            e._drive(va, self.diff_budget, stop=slot)
        finally:
            e._hle_mode = None
            e._hle_rec = None
        if self.diff_budget and self._over_budget(slot):
            # The budget ran out. Nothing is rolled back: the function is not compared, and the emulator simply goes
            # on with the same run from the stop address, so the function runs once, emulated, and every HLE call it
            # makes from here on is executed normally (the record is dropped). The undo log ends first, so the rest
            # runs at full speed; _diff_active stays set, so no nested diff starts inside it.
            e.undo_end(log)
            e._hle_mode = None
            e._hle_rec = None
            e._drive(uc.reg_read(UC_X86_REG_EIP), 0, stop=slot)
            if e.fatal is None and e.exit_code is None and uc.reg_read(UC_X86_REG_EIP) == slot:
                self._put_back_slot(esp0, slot, ret)
                uc.reg_write(UC_X86_REG_EIP, ret)
                return ret, None, [], [], 0, "too_long"
            # Did not return: as the reference's unwinding branch below, nothing is compared and the guest continues
            # where the run stopped (STUB_BASE after a fatal error or exit).
            if e.fatal is not None or e.exit_code is not None:
                cont = STUB_BASE
            else:
                cont = uc.reg_read(UC_X86_REG_EIP)
            self._put_back_slot(esp0, slot, ret)
            return cont, None, [], [], 0, "too_long"
        returned = e.fatal is None and e.exit_code is None and uc.reg_read(UC_X86_REG_EIP) == slot
        ref_ctx = e._save_cpu()
        e.undo_end(log)
        if not returned:
            # Two ways to get here. A fatal error or exit: the game stops, as it would have. Otherwise the reference
            # left the function without reaching the diff return slot, which happens when an exception unwinds past
            # its frame into an outer handler: the guest's state then is the reference's, and it continues there.
            # Nothing is rolled back and nothing is compared; the caller continues the guest at the stop address.
            st["reference_failed"] += 1
            if e.fatal is not None or e.exit_code is not None:
                msg = "reference did not return: %s" % (e.fatal or "process exit")
                cont = STUB_BASE
            else:
                cont = uc.reg_read(UC_X86_REG_EIP)
                msg = "reference did not return: unwound past the call and continued at 0x%08x (%s)" % (
                    cont, e.module_at(cont))
            if len(st["divergence_examples"]) < _DIFF_EXAMPLES:
                st["divergence_examples"].append(msg)
            self._put_back_slot(esp0, slot, ret)
            return cont, None, [], [], 0, "ref_failed"
        ref_writes = log.writes()
        ref_regs = ref_ctx[1]
        esp_end = ref_regs[UC_X86_REG_ESP]
        e.undo_rollback(log)
        # native: lifted code; HLE calls replayed from rec; every guest write logged (C log, then the undo log)
        l2 = e.undo_begin()
        self.lib.lift_wlog_begin()
        e._hle_mode = "replay"
        e._hle_rec = rec
        e._hle_cursor = 0
        e._hle_div = None
        self._diff_l2 = l2
        cpu, addr = self._take()
        status = 0
        try:
            self._pull(addr, fpu)
            self.depth += 1
            self.calls += 1
            try:
                status = self.lib.lift_invoke_checked(addr, fn, 1 if fpu else 0)
            finally:
                self.depth -= 1
            self._wl_flush()
            self._push(addr, fpu)
        finally:
            self._pool.append((cpu, addr))
            self._diff_l2 = None
            self.lib.lift_wlog_end()
        err, self.error = self.error, None
        div = e._hle_div
        if e.fatal is not None and e.fatal.startswith("diff divergence"):
            e.fatal = None
        if div is None and status == 1:
            div = "native code raised #DE"
        if div is None and err is not None:
            div = "native call failed: %s" % err
        if div is None and status == 2:
            div = "native run aborted"              # the guest could not run: the divergence is in e._hle_div
        if div is None and e._hle_cursor < len(rec):
            left = rec[e._hle_cursor]
            div = "missing HLE calls: %d of the reference's not made natively, next %s!%s" % (
                len(rec) - e._hle_cursor, left.key[0], left.key[1])
        e._hle_div = None
        e._hle_mode = None
        e._hle_rec = None

        e.undo_end(l2)
        reg_diffs, mem_diffs, mem_count, dead_count = [], [], 0, 0
        if div is None:
            nat_regs = {r: uc.reg_read(r) for r in self._cmp_regs(fpu)}
            reg_diffs = self._reg_diffs(nat_regs, ref_regs, fpu)
            nat_writes = l2.writes()
            pages = l2.pages

            def before(a):
                """the byte before the native run: the undo log's old value if the run wrote it, else the current one"""
                pg = pages.get(a >> 12)
                if pg is not None and pg.seen[a & 0xFFF]:
                    return pg.old[a & 0xFFF]
                return e.mem[a]
            for a in sorted(set(ref_writes) | set(nat_writes)):
                exp = ref_writes[a] if a in ref_writes else before(a)
                act = nat_writes[a] if a in nat_writes else before(a)
                if exp != act:
                    if a < esp_end:
                        # Dead stack (below the final esp, no longer part of the call's state). The bridge's call_guest
                        # pushes its own return slot where the emulator's call pushes the real return address, so these
                        # words differ by design. They are counted apart, not as mismatches.
                        dead_count += 1
                        continue
                    mem_count += 1
                    if len(mem_diffs) < _DIFF_MEM_LIMIT:
                        mem_diffs.append((a, exp, act))
        # the call's entry state, then the reference's final state on top of it
        e.undo_rollback(l2)
        for start, data in write_runs(ref_writes):
            e.wr(start, data)
        e._restore_cpu(ref_ctx)
        self._put_back_slot(esp0, slot, ret)
        uc.reg_write(UC_X86_REG_EIP, ret)
        st["dead_stack_calls"] += 1 if dead_count else 0
        return ret, div, reg_diffs, mem_diffs, mem_count, None

    def _over_budget(self, slot):
        """After the reference's _drive: True when it stopped because the instruction budget ran out. Unicorn's count
        stops silently, at the next instruction: not the return slot, and not the host stub at STUB_BASE. The other
        stops of the reference are a fatal error or process exit (fatal / exit_code set), a native call
        (_native_pending, which _drive runs itself) and the stub return, so none of those counts as a budget hit."""
        e = self.e
        if e.fatal is not None or e.exit_code is not None or e._native_pending is not None:
            return False
        eip = e.uc.reg_read(UC_X86_REG_EIP)
        return eip != slot and eip != STUB_BASE

    def _put_back_slot(self, esp0, slot, orig):
        """The word at esp0 was orig (the return address of a call, or a local when the entry was reached by a jump)
        and the diff wrote the slot over it. Put orig back, if the slot is still there: the reference never wrote the
        word, so nothing the guest did is lost."""
        if self.e.rd32(esp0) == slot:
            self.e.wr32(esp0, orig)

    def _cmp_regs(self, fpu):
        return _CMP_GPR_FLAGS + ([UC_X86_REG_FPSW, UC_X86_REG_FPCW, UC_X86_REG_FPTAG] + _FP_IDS if fpu else [])

    def _reg_diffs(self, nat, ref, fpu):
        out = []
        for name, rid in zip(_REG_NAMES, GPR_IDS):
            if nat[rid] != ref[rid]:
                out.append("%s native 0x%08x ref 0x%08x" % (name, nat[rid], ref[rid]))
        ef_n, ef_r = nat[UC_X86_REG_EFLAGS] & FLAG_MASK, ref[UC_X86_REG_EFLAGS] & FLAG_MASK
        if ef_n != ef_r:
            bits = ",".join(n.upper() for n, sh in _FLAG_NAMES if ((ef_n ^ ef_r) >> sh) & 1)
            out.append("eflags %s differ: native 0x%03x ref 0x%03x" % (bits, ef_n, ef_r))
        if fpu:
            if (nat[UC_X86_REG_FPSW] & (SW_TOP_MASK | SW_C_MASK)) != (ref[UC_X86_REG_FPSW] & (SW_TOP_MASK | SW_C_MASK)):
                out.append("fpsw top/C native 0x%04x ref 0x%04x" % (nat[UC_X86_REG_FPSW], ref[UC_X86_REG_FPSW]))
            if (nat[UC_X86_REG_FPTAG] & 0xFFFF) != (ref[UC_X86_REG_FPTAG] & 0xFFFF):
                out.append("fptag native 0x%04x ref 0x%04x" % (nat[UC_X86_REG_FPTAG], ref[UC_X86_REG_FPTAG]))
            tagw = ref[UC_X86_REG_FPTAG]
            for p, rid in enumerate(_FP_IDS):
                if ((tagw >> (2 * p)) & 3) == 3:
                    continue                 # empty in the reference: the raw value is not observable
                if nat[rid] != ref[rid]:
                    out.append("fp%d native (0x%016x,0x%04x) ref (0x%016x,0x%04x)" % (
                        p, nat[rid][0], nat[rid][1], ref[rid][0], ref[rid][1]))
        return out

    def _wl_flush(self):
        """Move the C write log into every active undo log, then clear it. A byte enters a log with the value it had
        before its first write in that log's run: the C side saw only the writes since its last flush, and each log
        has the earlier ones. (Enclosing logs need this too: a native write is invisible to them otherwise.)"""
        lib = self.lib
        n = lib.lift_wlog_export(None, 0)
        if n:
            buf = ctypes.create_string_buffer(n)
            lib.lift_wlog_export(buf, n)
            data = buf.raw
            logs = self.e._undo_stack
            i = 0
            while i < n:
                addr, ln = struct.unpack_from("<II", data, i)
                i += 8
                for log in logs:
                    _merge_unseen(log, addr, data[i:i + ln])
                i += ln
        lib.lift_wlog_clear()

    def report(self):
        """Totals, and per function the calls diffed, the outcomes and the first details. Functions never reached are
        left out."""
        fns = {}
        tot = {"functions_reached": 0, "diffs_run": 0, "functions_fully_matching": 0,
               "functions_with_mismatches": 0, "functions_with_divergences": 0, "functions_retired": 0,
               "functions_too_long": 0, "reference_failed": 0}
        for va in sorted(self.dstats):
            st = self.dstats[va]
            if not st["calls"]:
                continue
            fns["0x%08x" % va] = dict(st, retired=va in self._retired)
            tot["functions_reached"] += 1
            tot["diffs_run"] += st["calls"]
            tot["reference_failed"] += st["reference_failed"]
            if st["too_long"]:
                tot["functions_too_long"] += 1
            if st["mismatches"]:
                tot["functions_with_mismatches"] += 1
            if st["divergences"]:
                tot["functions_with_divergences"] += 1
            if st["matches"] == st["calls"]:
                tot["functions_fully_matching"] += 1
            if va in self._retired:
                tot["functions_retired"] += 1
        return {"k": self.diff_k, "totals": tot, "functions": fns}

    def summary_lines(self):
        rep = self.report()
        t = rep["totals"]
        budget = "%d" % self.diff_budget if self.diff_budget else "unlimited"
        lines = ["differential mode (first %d calls of each function, budget %s instructions per reference run): "
                 "%d functions reached, %d diffs run" % (self.diff_k, budget, t["functions_reached"], t["diffs_run"]),
                 "  fully matching: %d; with mismatches: %d; with divergences: %d; reference did not return: %d; "
                 "no longer diffed (k spent, bad or too long): %d; too long: %d" % (
                     t["functions_fully_matching"], t["functions_with_mismatches"], t["functions_with_divergences"],
                     t["reference_failed"], t["functions_retired"], t["functions_too_long"])]
        if t["functions_too_long"]:
            lines.append("  retired too long (over the budget, emulated from then on): " + ", ".join(
                "%s (x%d)" % (st["name"], st["too_long"]) for st in rep["functions"].values() if st["too_long"]))
        return lines
