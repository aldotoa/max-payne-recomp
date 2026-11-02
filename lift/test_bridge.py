"""Tests for the native bridge (emu/native.py, lift/build.py, lift/runtime): emulator <-> lifted code (M5).

Synthetic guest code is hand-assembled (encodings checked with insnrig.dis) at fixed addresses, so one lifted
library serves every test. The real-DLL test needs the game folder and is skipped without it.

Run:  ../../../.venv/bin/python lift/test_bridge.py          (plain asserts, no pytest)
"""
import ctypes
import json
import math
import os
import random
import struct
import sys
import tempfile
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "emu"))

import build as liftbuild                                   # noqa: E402
import mpemu                                                # noqa: E402
import test_seh as seh                                      # noqa: E402  (Asm and install_frame for the SEH callers)
import x86c                                                 # noqa: E402
from insnrig import dis                                     # noqa: E402
from native import CPU, FAST_BASE, LiftLoader, Native, NativeError, d2x, function_entries, x2d  # noqa: E402
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX,  # noqa: E402
                               UC_X86_REG_ECX, UC_X86_REG_EDI, UC_X86_REG_EDX,
                               UC_X86_REG_EFLAGS, UC_X86_REG_EIP, UC_X86_REG_ESI,
                               UC_X86_REG_ESP, UC_X86_REG_FP0, UC_X86_REG_FPCW,
                               UC_X86_REG_FPSW, UC_X86_REG_FPTAG)

BUILD = os.path.join(ROOT, "build-lift", "test_bridge")
GAME = os.path.join(ROOT, "Max Payne")

# ---------------------------------------------------------------- synthetic module
SYN = 0x00500000                 # fixed guest address of the synthetic code (mapped by each test emulator)
SYN_SIZE = 0x10000
SLOT = SYN + 0x8000              # IAT-style slot holding the address of an HLE stub
F = {
    "leaf_s": SYN + 0x000,       # stdcall int f(a, b) = a + 2b + 5                (lifted)
    "leaf_1": SYN + 0x100,       # cdecl int f(a) = 2a + 1                         (lifted)
    "leaf_t": SYN + 0x200,       # thiscall int f(a) with ecx = this: this + 2a + 5 (lifted)
    "leaf_cd2": SYN + 0x300,     # cdecl int f(a, b) = a + 2b + 5                   (lifted)
    "helper": SYN + 0x400,       # cdecl 2a + 1, emulated only (same bytes as leaf_1)
    "g": SYN + 0x500,            # stdcall g(a): helper(a) (emulated), then call [slot] (HLE), + a
    "a": SYN + 0x600,            # stdcall a(x) = b(x) + x (lifted), b is emulated
    "b": SYN + 0x700,            # cdecl b(x) = leaf_1(x) + x + 3 (emulated)
    "da": SYN + 0x800,           # stdcall da(x) = leaf_1(x) + x, direct lifted-to-lifted call (lifted)
    "caller_s": SYN + 0x900,     # emulated caller of leaf_s (stdcall); returns esp in edx
    "caller_c": SYN + 0xA00,     # emulated caller of leaf_cd2 (cdecl)
    "caller_t": SYN + 0xB00,     # emulated caller of leaf_t (thiscall, ecx = 0x1234)
    "bad": SYN + 0xC00,          # lifted: calls 0x00600000, which is not mapped
    "mmcopy": SYN + 0xD00,       # cdecl copy(dst, src): 32 bytes with movq (MMX), emms (lifted, FPU flag)
    "mmfill": SYN + 0xE00,       # cdecl fill(dst, lo, hi): 32 bytes of the 8-byte value (MMX, emms)
    "mmpair": SYN + 0xF00,       # cdecl pair(dst, src): calls mmcopy; no MMX of its own, FPU flag by closure
    "rdiv": SYN + 0x1000,        # cdecl rdiv(out, data): *out = a / b under the control word data[0] (lifted)
    "loop": SYN + 0x1100,        # emulated: calls leaf_s(3, 4) ESI times (overhead measurement, one e.call)
    # A guest longjmp past native frames (fast path): uw_outer (lifted) calls uw_top (emulated), which saves esp in
    # JB ("setjmp") and calls uw_mid (lifted); uw_mid calls uw_jump (emulated), which restores esp from JB and jumps to
    # uw_cont ("longjmp"). uw_cont returns 0x55 from uw_top's frame, so uw_mid's native frame is dropped.
    "uw_outer": SYN + 0x1200,    # lifted: uw_top() + 1
    "uw_top": SYN + 0x1300,      # emulated: [JB] = esp; uw_mid(); return 1 (never reached)
    "uw_mid": SYN + 0x1400,      # lifted: uw_jump(); return 0x99 (never reached)
    "uw_jump": SYN + 0x1500,     # emulated: esp = [JB]; jmp uw_cont
    "uw_cont": SYN + 0x1600,     # emulated: return 0x55
    # Native MSVCRT helpers (lift/runtime/crt.c): lifted callers of _ftol and tolower through IAT-style slots that
    # point at copies of MSVCRT's code at its real addresses (CRT_BASE, mapped by _map_crt).
    "ftol_t": SYN + 0x1700,      # lifted cdecl ftol_t(data): fldcw [data]; fld qword [data+8]; call [CSLOT_FTOL]
    "ftol_j": SYN + 0x1800,      # lifted cdecl ftol_j(data): the same, with a tail jump: jmp [CSLOT_FTOL]
    "tolower_t": SYN + 0x1900,   # lifted cdecl tolower_t(x): push x; call [CSLOT_TOLOWER]; pop ecx
    # Halt test: lp loops while lp_cb() is nonzero (a guard of 1000000 iterations), storing its count at LP_COUNT.
    # lp_cb returns 1 on its first call and stops the run (a fatal stop, as an HLE handler does) on the second.
    "lp": SYN + 0x1A00,          # lifted cdecl: while (lp_cb()) if (++ebx == 1000000) ebx = -1; return ebx
    "lp_cb": SYN + 0x1B00,       # emulated: first call returns 1; later calls call [SLOT] (GetCurrentThreadId stub)
    # Dead frames: dx_n2 (lifted) calls the guest dx_t, which raises an exception (RaiseException through DX_SLOT_RAISE).
    # dx_n1 (lifted) calls the emulated dx_g, which calls dx_n2. Each native function stores a marker after its guest
    # call, which must never run: the native frame is dead once the guest has returned past its entry.
    "dx_n1": SYN + 0x1C00,       # lifted cdecl: dx_g(); [DX_MARK_N1] = 1
    "dx_g": SYN + 0x1D00,        # emulated: dx_n2(); ret
    "dx_n2": SYN + 0x1E00,       # lifted cdecl: dx_t(); [DX_MARK_N2] = 1
    "dx_t": SYN + 0x1F00,        # emulated: RaiseException(0xE0000001, 0, 0, 0) through [DX_SLOT_RAISE]; ret
    # Return-slot writes by the callee (lift_guest restores the bridge's return address only if the callee left the
    # slot alone). eh is shaped like MSVCRT's _EH_prolog: it overwrites its own return slot, sets ebp to the slot's
    # address and returns through push eax; ret. eh_t (lifted) calls it and then leaves, so the leave loads ebp from
    # the slot eh wrote. ok is a normal callee.
    "eh": SYN + 0x2000,          # emulated: [esp] = EH_MARK; ebp = esp; push eax (the return address); ret
    "eh_t": SYN + 0x2100,        # lifted cdecl: call eh; leave; ret
    "ok": SYN + 0x2200,          # emulated: ret
    "ok_t": SYN + 0x2300,        # lifted cdecl: call ok; ret
    # Import thunks (never lifted: `jmp [slot]`), reached from lifted code through a vtable cell (vt_c, vt_j, vt_f,
    # vt_fj), so the call is a register/memory call that misses lift_find (runtime.c thunk_resolve).
    "thk_l": SYN + 0x2400,       # jmp [CELL_L]: the slot points at leaf_1 (lifted)
    "thk_hle": SYN + 0x2500,     # jmp [SLOT]: the slot points at the GetCurrentThreadId stub
    "thk_g": SYN + 0x2600,       # jmp [CELL_G]: the slot points at helper (emulated guest code)
    "thk_ch2": SYN + 0x2700,     # jmp [CELL_CH]: the slot points at thk_l (a two-thunk chain)
    "thk_crt": SYN + 0x2800,     # jmp [CSLOT_FTOL]: the slot points at the native _ftol copy
    "thk_unm": SYN + 0x2900,     # jmp [UNMAPPED]: the slot itself is in unmapped memory
    "vt_c": SYN + 0x2A00,        # lifted cdecl: push 5; call [VT_C]; pop ecx; ret
    "vt_j": SYN + 0x2B00,        # lifted: mov eax, VT_J; jmp [eax] (a tail jump; the cdecl argument stays at [esp+4])
    "vt_f": SYN + 0x2C00,        # lifted cdecl: the ftol_t shape, through [VT_F]
    "vt_fj": SYN + 0x2D00,       # lifted: the ftol_j shape, then mov eax, VT_FJ; jmp [eax] (a tail jump)
    # The guest heap from lifted code (H44): HeapFree(0, 0, p) and then HeapAlloc(0, 0, size), through IAT slots.
    "hp": SYN + 0x2E00,          # lifted cdecl hp(size, p): HeapFree(0, 0, p); return HeapAlloc(0, 0, size)
    # HLE handlers in C (H50): d3c forwards its eight arguments to the stdcall at [D3SLOT] (any argument count: the
    # ebp frame restores esp after the callee's pop).
    "d3c": SYN + 0x2F00,         # lifted cdecl d3c(a, .., h): return [D3SLOT](a, .., h)
}
LIFTED = ["leaf_s", "leaf_1", "leaf_t", "leaf_cd2", "g", "a", "da", "bad", "mmcopy", "mmfill", "mmpair", "rdiv",
          "uw_outer", "uw_mid", "ftol_t", "ftol_j", "tolower_t", "lp", "dx_n1", "dx_n2", "eh_t", "ok_t",
          "vt_c", "vt_j", "vt_f", "vt_fj", "hp", "d3c"]
EH_MARK = 0x5A1E0F0D             # the value eh writes into its return slot
JB = SYN + 0x8010                # the "jmp_buf" of the unwind test: one saved esp
LP_COUNT = SYN + 0x8030          # lp stores its loop count here (native store, read back by the halt test)
LP_CB_CALLS = SYN + 0x8034       # lp_cb's own call counter
DX_MARK_N1 = SYN + 0x8040       # dx_n1's marker after its guest call (dead frames tests: must stay 0)
DX_MARK_N2 = SYN + 0x8044       # dx_n2's marker after its guest call
DX_SLOT_RAISE = SYN + 0x8048    # holds the address of the RaiseException stub
DX_E1 = SYN + 0x9000            # emulated caller of dx_n2 (SEH frame), written by the dead frames tests
DX_E2 = SYN + 0x9100            # emulated caller of dx_n1 (SEH frame)
UNMAPPED = 0x00600000
CSLOT_FTOL = SYN + 0x8020        # holds the address of the CRT _ftol copy
CSLOT_TOLOWER = SYN + 0x8024     # holds the address of the CRT tolower copy
CRT_BASE = 0x78000000            # MSVCRT.DLL's load base in the game
CRT_LOCALE = CRT_BASE + 0x37164  # __lc_handle[LC_CTYPE]: 0 is the "C" locale
VT_C = SYN + 0x8060              # vtable cells: the call and tail-jump callers of the thunk tests
VT_J = SYN + 0x8064
VT_F = SYN + 0x8068
VT_FJ = SYN + 0x806C
CELL_L = SYN + 0x8074            # the slots of thk_l, thk_g and thk_ch2
CELL_G = SYN + 0x8078
CELL_CH = SYN + 0x807C
HSLOT_A = SYN + 0x8084           # IAT slots of hp: KERNEL32 HeapAlloc and HeapFree
HSLOT_F = SYN + 0x8088
D3SLOT = SYN + 0x808C            # IAT slot of d3c
D3ESP = SYN + 0x8090             # d3c stores esp - ebp here after the call: the callee's stdcall pop


def _rel(at, target):
    return struct.pack("<i", target - (at + 5))


def _code(name):
    """Bytes of every synthetic function, keyed by name (a call to a name is resolved here)."""
    A = F
    out = {}
    out["eh"] = bytes.fromhex("8b0424 c70424") + struct.pack("<I", EH_MARK) + bytes.fromhex("89e5 50 c3")
    out["eh_t"] = bytes.fromhex("e8") + _rel(A["eh_t"], A["eh"]) + bytes.fromhex("c9 c3")
    out["ok"] = bytes.fromhex("c3")
    out["ok_t"] = bytes.fromhex("e8") + _rel(A["ok_t"], A["ok"]) + bytes.fromhex("c3")
    out["thk_l"] = bytes.fromhex("ff25") + struct.pack("<I", CELL_L)
    out["thk_hle"] = bytes.fromhex("ff25") + struct.pack("<I", SLOT)
    out["thk_g"] = bytes.fromhex("ff25") + struct.pack("<I", CELL_G)
    out["thk_ch2"] = bytes.fromhex("ff25") + struct.pack("<I", CELL_CH)
    out["thk_crt"] = bytes.fromhex("ff25") + struct.pack("<I", CSLOT_FTOL)
    out["thk_unm"] = bytes.fromhex("ff25") + struct.pack("<I", UNMAPPED)
    # push [esp+8]; push 0; push 0; call [HSLOT_F]; push [esp+4]; push 0; push 0; call [HSLOT_A]; ret
    out["hp"] = (bytes.fromhex("ff742408 6a00 6a00 ff15") + struct.pack("<I", HSLOT_F) +
                 bytes.fromhex("ff742404 6a00 6a00 ff15") + struct.pack("<I", HSLOT_A) + bytes.fromhex("c3"))
    # push ebp; mov ebp, esp; push [ebp+0x24] .. push [ebp+8]; call [D3SLOT]; mov ecx, esp; sub ecx, ebp;
    # mov [D3ESP], ecx; mov esp, ebp; pop ebp; ret
    out["d3c"] = (bytes.fromhex("55 89e5 ff7524 ff7520 ff751c ff7518 ff7514 ff7510 ff750c ff7508 ff15") +
                  struct.pack("<I", D3SLOT) + bytes.fromhex("89e1 29e9 890d") + struct.pack("<I", D3ESP) +
                  bytes.fromhex("89ec 5d c3"))
    out["vt_c"] = bytes.fromhex("6a05 ff15") + struct.pack("<I", VT_C) + bytes.fromhex("59 c3")
    # mov eax, cell; jmp [eax]: the tail jump through memory the translator takes (jmp [reg+disp]; an absolute
    # jmp [mem] that is not an IAT slot is not translated)
    out["vt_j"] = bytes.fromhex("b8") + struct.pack("<I", VT_J) + bytes.fromhex("ff20")
    out["vt_f"] = bytes.fromhex("8b442404 d928 dd4008 ff15") + struct.pack("<I", VT_F) + bytes.fromhex("c3")
    out["vt_fj"] = bytes.fromhex("8b442404 d928 dd4008 b8") + struct.pack("<I", VT_FJ) + bytes.fromhex("ff20")
    out["leaf_s"] = bytes.fromhex("8b442404 8b4c2408 8d444805 c20800")
    out["leaf_1"] = bytes.fromhex("8b442404 8d440001 c3")
    out["leaf_t"] = bytes.fromhex("8b442404 8d444805 c20400")
    out["leaf_cd2"] = bytes.fromhex("8b442404 8b4c2408 8d444805 c3")
    out["helper"] = bytes.fromhex("8b442404 8d440001 c3")
    # _rel(at, t): the rel32 of an E8 whose opcode is at address `at`
    out["g"] = (bytes.fromhex("8b442404 50 e8") + _rel(A["g"] + 5, A["helper"]) +
                bytes.fromhex("59 50 ff15") + struct.pack("<I", SLOT) +
                bytes.fromhex("59 8d0408 c20400"))
    out["a"] = bytes.fromhex("8b442404 50 e8") + _rel(A["a"] + 5, A["b"]) + bytes.fromhex("59 8d0408 c20400")
    out["b"] = bytes.fromhex("8b442404 50 e8") + _rel(A["b"] + 5, A["leaf_1"]) + bytes.fromhex("59 8d440803 c3")
    out["da"] = bytes.fromhex("8b442404 50 e8") + _rel(A["da"] + 5, A["leaf_1"]) + bytes.fromhex("59 8d0408 c20400")
    out["caller_s"] = bytes.fromhex("6a03 6a04 e8") + _rel(A["caller_s"] + 4, A["leaf_s"]) + bytes.fromhex("89e2 c3")
    out["caller_c"] = bytes.fromhex("6a03 6a04 e8") + _rel(A["caller_c"] + 4, A["leaf_cd2"]) + bytes.fromhex("83c408 89e2 c3")
    out["caller_t"] = bytes.fromhex("b934120000 6a04 e8") + _rel(A["caller_t"] + 7, A["leaf_t"]) + bytes.fromhex("89e2 c3")
    out["bad"] = bytes.fromhex("e8") + _rel(A["bad"], UNMAPPED) + bytes.fromhex("c3")
    # MMX: the forms R_Memory::set and R_Memory::copy use (movq mm,m64 / movq m64,mm / emms), 4 quadwords each
    out["mmcopy"] = bytes.fromhex("8b4c2404 8b542408 0f6f02 0f6f4a08 0f6f5210 0f6f5a18 "
                                  "0f7f01 0f7f4908 0f7f5110 0f7f5918 0f77 c3")
    out["mmfill"] = bytes.fromhex("8b4c2404 0f6f442408 0f7f01 0f7f4908 0f7f5110 0f7f5918 0f77 c3")
    # push [esp+8]; push [esp+8]; call mmcopy; pop; pop; ret
    out["mmpair"] = (bytes.fromhex("ff742408 ff742408 e8") + _rel(A["mmpair"] + 8, A["mmcopy"]) +
                     bytes.fromhex("59 59 c3"))
    # fnstcw [ecx+24]; fldcw [ecx]; fld qword [ecx+8]; fdiv qword [ecx+16]; fstp qword [eax]; fldcw [ecx+24]
    out["rdiv"] = bytes.fromhex("8b442404 8b4c2408 d97918 d929 dd4108 dc7110 dd18 d96918 c3")
    # push esi; mov esi, N; L: push 3; push 4; call leaf_s; dec esi; jnz L; pop esi; ret
    out["loop"] = (bytes.fromhex("56 be") + struct.pack("<I", LOOP_N) + bytes.fromhex("6a03 6a04 e8") +
                   _rel(A["loop"] + 10, A["leaf_s"]) + bytes.fromhex("4e 75 f4 5e c3"))
    out["uw_outer"] = bytes.fromhex("e8") + _rel(A["uw_outer"], A["uw_top"]) + bytes.fromhex("40 c3")
    out["uw_top"] = (bytes.fromhex("8925") + struct.pack("<I", JB) + bytes.fromhex("e8") +
                     _rel(A["uw_top"] + 6, A["uw_mid"]) + bytes.fromhex("b801000000 c3"))
    out["uw_mid"] = bytes.fromhex("e8") + _rel(A["uw_mid"], A["uw_jump"]) + bytes.fromhex("b899000000 c3")
    out["uw_jump"] = (bytes.fromhex("8b25") + struct.pack("<I", JB) + bytes.fromhex("e9") +
                      _rel(A["uw_jump"] + 6, A["uw_cont"]))
    out["uw_cont"] = bytes.fromhex("b855000000 c3")
    out["dx_n1"] = (bytes.fromhex("e8") + _rel(A["dx_n1"], A["dx_g"]) + bytes.fromhex("c705") +
                    struct.pack("<II", DX_MARK_N1, 1) + bytes.fromhex("c3"))
    out["dx_g"] = bytes.fromhex("e8") + _rel(A["dx_g"], A["dx_n2"]) + bytes.fromhex("c3")
    out["dx_n2"] = (bytes.fromhex("e8") + _rel(A["dx_n2"], A["dx_t"]) + bytes.fromhex("c705") +
                    struct.pack("<II", DX_MARK_N2, 1) + bytes.fromhex("c3"))
    # push 0 (lpArguments); push 0 (nNumberOfArguments); push 0 (dwExceptionFlags); push code; call [slot]; ret
    out["dx_t"] = (bytes.fromhex("6a00 6a00 6a00 68") + struct.pack("<I", 0xE0000001) + bytes.fromhex("ff15") +
                   struct.pack("<I", DX_SLOT_RAISE) + bytes.fromhex("c3"))
    out["ftol_t"] = bytes.fromhex("8b442404 d928 dd4008 ff15") + struct.pack("<I", CSLOT_FTOL) + bytes.fromhex("c3")
    out["ftol_j"] = bytes.fromhex("8b442404 d928 dd4008 ff25") + struct.pack("<I", CSLOT_FTOL)
    out["tolower_t"] = (bytes.fromhex("ff742404 ff15") + struct.pack("<I", CSLOT_TOLOWER) + bytes.fromhex("59 c3"))
    # push ebx; xor ebx,ebx; L: call lp_cb; test eax,eax; jz done; inc ebx; mov [LP_COUNT],ebx;
    # cmp ebx,1000000; jl L; mov ebx,-1; done: mov eax,ebx; pop ebx; ret
    out["lp"] = (bytes.fromhex("53 31db e8") + _rel(A["lp"] + 3, A["lp_cb"]) + bytes.fromhex("85c0 7414 43 891d") +
                 struct.pack("<I", LP_COUNT) + bytes.fromhex("81fb 40420f00 7ce8 bbffffffff 89d8 5b c3"))
    # mov eax,[CALLS]; inc eax; mov [CALLS],eax; cmp eax,1; jne stop; mov eax,1; ret; stop: call [SLOT]; ret
    out["lp_cb"] = (bytes.fromhex("a1") + struct.pack("<I", LP_CB_CALLS) + bytes.fromhex("40 a3") +
                    struct.pack("<I", LP_CB_CALLS) + bytes.fromhex("83f801 7506 b801000000 c3 ff15") +
                    struct.pack("<I", SLOT) + bytes.fromhex("c3"))
    return out[name]


LOOP_N = 10000


def _blob():
    """{va: bytes} for every synthetic function."""
    return {F[n]: _code(n) for n in F}


class SynImage:
    """The translator's view of the synthetic module (same interface as x86c.PEImage)."""

    def __init__(self):
        self.base = SYN
        self.path = "<synthetic>"
        self.iat = {SLOT: "KERNEL32.DLL!GetCurrentThreadId", CSLOT_FTOL: "MSVCRT.DLL!_ftol",
                    CSLOT_TOLOWER: "MSVCRT.DLL!tolower", HSLOT_A: "KERNEL32.DLL!HeapAlloc",
                    HSLOT_F: "KERNEL32.DLL!HeapFree", D3SLOT: "D3D8.DLL!Method"}
        self._mem = bytearray(SYN_SIZE)
        for va, b in _blob().items():
            off = va - SYN
            self._mem[off:off + len(b)] = b

    def read(self, va, n):
        off = va - SYN
        if 0 <= off < SYN_SIZE:
            return bytes(self._mem[off:off + n])
        raise ValueError("unmapped %08x" % va)

    def is_code(self, va):
        return SYN <= va < SYN + 0x8000


def build_synthetic():
    """The lifted library for the synthetic module (built once per run, cached in build-lift/test_bridge)."""
    lib = os.path.join(BUILD, "libsynthetic.dylib")
    res = liftbuild.build(SynImage(), sorted(F[n] for n in LIFTED), os.path.join(BUILD, "c"), lib,
                          module="synthetic")
    assert not res["dropped"], res["dropped"]
    assert len(res["lifted"]) == len(LIFTED), res
    return lib


_LIB = None


def new_emu():
    """An emulator with the synthetic module mapped and its IAT slot pointing at GetCurrentThreadId."""
    global _LIB
    if _LIB is None:
        _LIB = build_synthetic()
    e = mpemu.Emu(".")
    e.map(SYN, SYN_SIZE)
    for va, b in _blob().items():
        e.wr(va, b)
    e.wr32(SLOT, e.stub_for("KERNEL32.DLL", "GetCurrentThreadId"))
    n = Native(e, _LIB)
    return e, n


def _regs(e):
    uc = e.uc
    names = dict(eax=UC_X86_REG_EAX, ecx=UC_X86_REG_ECX, edx=UC_X86_REG_EDX, ebx=UC_X86_REG_EBX,
                 esp=UC_X86_REG_ESP, ebp=UC_X86_REG_EBP, esi=UC_X86_REG_ESI, edi=UC_X86_REG_EDI,
                 eflags=UC_X86_REG_EFLAGS)
    out = {k: uc.reg_read(v) for k, v in names.items()}
    out["fpcw"] = uc.reg_read(UC_X86_REG_FPCW)
    out["fpsw"] = uc.reg_read(UC_X86_REG_FPSW)
    out["fptag"] = uc.reg_read(UC_X86_REG_FPTAG)
    for p in range(8):
        out["fp%d" % p] = uc.reg_read(UC_X86_REG_FP0 + p)
    return out


def _uc_fp_regs(e):
    return [e.uc.reg_read(UC_X86_REG_FP0 + p) for p in range(8)]


# ---------------------------------------------------------------- tests

def test_layout():
    """The ctypes CPU mirror agrees with lift_cpu_layout (checked by the constructor; a mismatch raises)."""
    e, n = new_emu()
    assert n.table[F["leaf_s"]] is not None
    assert sorted(n.table) == sorted(F[x] for x in LIFTED)
    assert e.native is n


def test_flag_and_fp_conversions():
    """double <-> 80-bit is exact both ways for doubles, including -0.0, denormals, inf and NaN."""
    vals = [0.0, -0.0, 1.0, -1.0, 1e300, -1e300, 1e-300, 5e-324, 2.5, 0.1, float("inf"), -float("inf")]
    rng = random.Random(1)
    vals += [rng.uniform(-1e6, 1e6) for _ in range(300)]
    for v in vals:
        m, x = d2x(v)
        back, exact = x2d(m, x)
        assert exact, v
        assert struct.pack("<d", back) == struct.pack("<d", v), (v, back)     # bit-exact, sign of zero too
    # NaN payload survives
    nan = struct.unpack("<d", struct.pack("<Q", 0x7ff8000000001234))[0]
    back, _ = x2d(*d2x(nan))
    assert struct.pack("<d", back) == struct.pack("<d", nan)
    # an 80-bit value that is not a double is reported as inexact
    _, exact = x2d(0x8000000000000001, 0x3fff)              # 1 + 2^-63
    assert not exact


def test_state_round_trip():
    """uc -> CPU -> uc keeps GPRs, the six flags, DF, x87 values, TOP, tag, CW and the C bits; EFLAGS bits
    that are not arithmetic flags are untouched."""
    e, n = new_emu()
    uc = e.uc
    # push 3.5, 0.1, -0.0, 1e300 with fld (the stack is then 4 deep), then a fstp-free state
    data = e.alloc(64)
    vals = [1e300, -0.0, 0.1, 3.5]
    for i, v in enumerate(vals):
        e.wr(data + 8 * i, struct.pack("<d", v))
    code = b"".join(b"\xdd\x05" + struct.pack("<I", data + 8 * i) for i in range(4))   # fld qword [data+8i]
    cp = e.alloc(len(code) + 16)
    e.wr(cp, code)
    uc.reg_write(UC_X86_REG_EFLAGS, 0x202 | (1 << 18) | (1 << 21) | 0x41)     # IF, AC, ID and some flags
    uc.reg_write(UC_X86_REG_ECX, 0xdeadbeef)
    uc.emu_start(cp, cp + len(code))
    before = _regs(e)
    fp_before = _uc_fp_regs(e)
    cpu = CPU()
    n.uc_to_cpu(cpu)
    assert n.inexact == 0, n.inexact
    assert cpu.r[1] == 0xdeadbeef and cpu.fs_base == mpemu.TEB and cpu.mem == e.mem_base
    st_logical = [cpu.st[(cpu.top + i) & 7] for i in range(4)]
    assert st_logical[0] == 3.5 and st_logical[1] == 0.1 and str(st_logical[2]) == "-0.0" and st_logical[3] == 1e300, st_logical
    assert cpu.top == before["fpsw"] >> 11 & 7 and cpu.tag == sum(1 << p for p in range(8) if ((before["fptag"] >> (2 * p)) & 3) == 3)
    # change the flags in the CPU, then copy back: only the six flags and DF move
    cpu.cf, cpu.zf, cpu.sf, cpu.of, cpu.pf, cpu.af, cpu.df = 1, 0, 1, 1, 0, 1, 0
    n.cpu_to_uc(cpu)
    ef = uc.reg_read(UC_X86_REG_EFLAGS)
    assert ef & 0x200 and ef & (1 << 18) and ef & (1 << 21) and ef & 2, hex(ef)     # IF, AC, ID, reserved bit
    assert (ef & 1) == 1 and (ef >> 6 & 1) == 0 and (ef >> 7 & 1) == 1 and (ef >> 11 & 1) == 1
    assert (ef >> 2 & 1) == 0 and (ef >> 4 & 1) == 1 and (ef >> 10 & 1) == 0
    # the register contents round trip unchanged
    fp_after = _uc_fp_regs(e)
    assert fp_after == fp_before, (fp_before, fp_after)
    after = _regs(e)
    for k in ("fpcw", "fpsw", "fptag", "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"):
        assert after[k] == before[k], (k, hex(after[k]), hex(before[k]))
    # and the CPU sees the same again
    cpu2 = CPU()
    n.uc_to_cpu(cpu2)
    assert list(cpu2.st) == list(cpu.st) and cpu2.tag == cpu.tag and cpu2.top == cpu.top
    assert cpu2.cf == 1 and cpu2.sf == 1 and cpu2.of == 1 and cpu2.af == 1
    # a value written from the CPU lands in Unicorn exactly (-0.0 stays negative)
    cpu2.st[(cpu2.top + 3) & 7] = -0.0
    n.cpu_to_uc(cpu2)
    cpu3 = CPU()
    n.uc_to_cpu(cpu3)
    assert str(cpu3.st[(cpu3.top + 3) & 7]) == "-0.0"
    assert n.inexact == 0


MODE = ["slow"]      # "fast": the install-based tests dispatch through install_fast (main runs them in both modes)


def _install(n, va):
    """Native.install (the bridge, every call stops emu_start), or install_fast in fast mode."""
    if MODE[0] == "fast":
        n.install_fast([va])
    else:
        n.install(va)


def _call_native(e, n, name, *args, cc="stdcall", ecx=None):
    _install(n, F[name])
    try:
        return e.call(F[name], *args, cc=cc, ecx=ecx)
    finally:
        n.uninstall(F[name])


def test_leaf_stdcall_cdecl_thiscall():
    """A lifted leaf entered from emulated code: result, ESP after the call and the flags for the three
    calling conventions. Emulated run of the same caller is the reference."""
    e, n = new_emu()
    # stdcall: the caller pushes 4, 3 and the callee's ret 8 pops them
    ref = e.call(F["caller_s"])
    ref_esp = e.uc.reg_read(UC_X86_REG_EDX)
    assert ref == 4 + 2 * 3 + 5 and not e.fatal, (ref, e.fatal)
    _install(n, F["leaf_s"])
    c0 = n.calls
    got = e.call(F["caller_s"])
    assert got == ref and not e.fatal, (got, e.fatal)
    assert e.uc.reg_read(UC_X86_REG_EDX) == ref_esp and n.calls == c0 + 1
    n.uninstall(F["leaf_s"])
    # cdecl
    ref = e.call(F["caller_c"])
    ref_esp = e.uc.reg_read(UC_X86_REG_EDX)
    _install(n, F["leaf_cd2"])
    c0 = n.calls
    got = e.call(F["caller_c"])
    assert got == ref == 4 + 2 * 3 + 5 and not e.fatal, (got, ref, e.fatal)
    assert e.uc.reg_read(UC_X86_REG_EDX) == ref_esp and n.calls == c0 + 1
    n.uninstall(F["leaf_cd2"])
    # thiscall: ECX is the this pointer; the caller sets ECX = 0x1234
    ref = e.call(F["caller_t"])
    ref_esp = e.uc.reg_read(UC_X86_REG_EDX)
    assert ref == 4 + 2 * 0x1234 + 5, hex(ref)                       # lea eax,[eax+ecx*2+5]: a + 2*this + 5
    _install(n, F["leaf_t"])
    got = e.call(F["caller_t"])
    assert got == ref and e.uc.reg_read(UC_X86_REG_EDX) == ref_esp and not e.fatal
    n.uninstall(F["leaf_t"])
    # direct call from the emulator, args pushed by call()
    _install(n, F["leaf_s"])
    assert e.call(F["leaf_s"], 10, 20) == 10 + 40 + 5
    assert not e.fatal
    n.uninstall(F["leaf_s"])
    assert e.call(F["leaf_s"], 10, 20) == 10 + 40 + 5


def test_native_calls_emulated_and_hle():
    """Native -> emulated helper (direct call, through call_guest), and native -> HLE import through an IAT
    slot. The emulated reference gives the expected value; the import result is whatever the HLE returns."""
    e, n = new_emu()
    ref = e.call(F["g"], 7)
    assert not e.fatal, e.fatal
    _install(n, F["g"])
    c0 = n.calls
    got = e.call(F["g"], 7)
    assert not e.fatal, e.fatal
    assert got == ref and n.calls == c0 + 1, (hex(got), hex(ref))
    # g = GetCurrentThreadId() + helper(7) = 0x104 + 15
    assert got == 0x104 + 15, hex(got)
    n.uninstall(F["g"])


def test_nesting():
    """native a -> emulated b -> native leaf_1 -> return through all levels; ESP and EAX right."""
    e, n = new_emu()
    ref = e.call(F["a"], 5)
    assert not e.fatal and ref == 4 * 5 + 4, ref
    base = e.uc.reg_read(UC_X86_REG_ESP)
    _install(n, F["a"])
    _install(n, F["leaf_1"])
    c0 = n.calls
    got = e.call(F["a"], 5)
    assert not e.fatal, e.fatal
    assert got == ref, got
    assert n.calls == c0 + 2, n.calls - c0            # a and leaf_1
    assert e.uc.reg_read(UC_X86_REG_ESP) == base
    # native a calling a native leaf directly (lifted to lifted): da, with leaf_1 in the same library
    _install(n, F["da"])
    got = e.call(F["da"], 9)
    assert not e.fatal and got == 3 * 9 + 1, (got, e.fatal)
    n.uninstall(F["da"])
    n.uninstall(F["leaf_1"])
    n.uninstall(F["a"])


def test_undo_refused_and_fatal():
    """Native code under an undo log is refused (its writes would bypass the log). A fatal error in a nested
    guest call stops the native call and is raised by the outermost one."""
    e, n = new_emu()
    _install(n, F["leaf_s"])
    log = e.undo_begin()
    try:
        e.call(F["leaf_s"], 1, 2)
        raise AssertionError("native call under an undo log was not refused")
    except NativeError as ex:
        assert "undo log" in str(ex)
    finally:
        e.undo_end(log)
    e.undo_rollback(log)
    n.uninstall(F["leaf_s"])
    # fatal inside a nested call
    e2, n2 = new_emu()
    _install(n2, F["bad"])
    raised = None
    try:
        e2.call(F["bad"])
    except NativeError as ex:
        raised = ex
    assert raised is not None and "stopped" in str(raised), raised
    assert e2.fatal and "unmapped" in e2.fatal, e2.fatal
    n2.uninstall(F["bad"])


def test_fast_path_basics():
    """Fast dispatch alone: a slot is hooked and runs the lifted function from inside emu_start (no Python stop, no
    call_guest), the entry's jmp lands on the slot, results and ESP match the emulated reference, and the counters
    say so. Native -> guest calls are nested runs (guest_calls, max_depth)."""
    e, n = new_emu()
    ref = e.call(F["g"], 7)
    assert not e.fatal, e.fatal
    n.install_fast([F["leaf_s"], F["g"], F["leaf_1"]])
    slot = n.installed[F["leaf_s"]][0]                       # the entry's jmp target: a slot of the fast region
    assert 0x7F100010 <= slot < 0x7F200000 and (slot - 0x7F100000) % 16 == 0, hex(slot)
    s0 = n.fast_stats()
    assert e.call(F["leaf_s"], 10, 20) == 10 + 40 + 5 and not e.fatal
    s1 = n.fast_stats()
    assert s1["calls"] == s0["calls"] + 1 and s1["guest_calls"] == s0["guest_calls"], (s0, s1)
    assert s1["fallbacks"] == s0["fallbacks"]
    # native g calls the emulated helper through call_guest and an HLE import: nested runs, no fallback
    got = e.call(F["g"], 7)
    s2 = n.fast_stats()
    assert got == ref == 0x104 + 15 and not e.fatal, (hex(got), hex(ref), e.fatal)
    assert s2["guest_calls"] >= s1["guest_calls"] + 2 and s2["fallbacks"] == s1["fallbacks"], (s1, s2)
    assert s2["max_depth"] >= 1
    # the leaf reached from emulated code again, after the nested runs: same result
    assert e.call(F["caller_s"]) == 4 + 2 * 3 + 5 and not e.fatal
    n.uninstall(F["leaf_s"])
    n.uninstall(F["g"])
    n.uninstall(F["leaf_1"])
    assert e.call(F["leaf_s"], 10, 20) == 10 + 40 + 5


def test_dead_stack_matches_emulator():
    """A native call into emulated code leaves the stack below esp as a real call does: the return-address slots of
    g's calls hold g's return addresses, not the bridge's (emulated code can read them back as uninitialised locals).
    Runs in both modes."""
    e, n = new_emu()

    def run():
        e.wr(mpemu.STACK_TOP - 0x1000, b"\xcc" * 0x1000)
        r = e.call(F["g"], 7)
        sp = e.uc.reg_read(UC_X86_REG_ESP)
        return r, e.rd(sp - 0x40, 0x40)
    ref, dead_ref = run()
    _install(n, F["g"])
    got, dead_nat = run()
    n.uninstall(F["g"])
    assert got == ref and not e.fatal, (hex(got), hex(ref), e.fatal)
    assert dead_nat == dead_ref, (dead_nat.hex(), dead_ref.hex())


def test_callee_writes_return_slot():
    """_EH_prolog's shape: a callee overwrites its own return slot (the one lift_guest's bridge filled), sets ebp to
    that slot and returns through push eax; ret. The callee's value must stay in the slot: lift_guest must not restore
    the bridge's return address over it, or the caller's leave loads that address into ebp. Runs in both modes."""
    e, n = new_emu()
    sp0 = e.uc.reg_read(UC_X86_REG_ESP)
    slot = sp0 - 8                   # e.call pushes its return address at sp0 - 4; eh_t's call pushes below that
    _call_native(e, n, "eh_t")
    assert not e.fatal, e.fatal
    assert e.rd32(slot) == EH_MARK, hex(e.rd32(slot))
    assert e.uc.reg_read(UC_X86_REG_EBP) == EH_MARK, hex(e.uc.reg_read(UC_X86_REG_EBP))
    assert e.uc.reg_read(UC_X86_REG_ESP) == sp0, hex(e.uc.reg_read(UC_X86_REG_ESP))


def test_normal_callee_restores_return_slot():
    """A callee that leaves its return slot alone: lift_guest puts the real return address back (the lifted caller's
    next instruction), as before the bridge-return check. Runs in both modes."""
    e, n = new_emu()
    sp0 = e.uc.reg_read(UC_X86_REG_ESP)
    slot = sp0 - 8
    _call_native(e, n, "ok_t")
    assert not e.fatal, e.fatal
    assert e.rd32(slot) == F["ok_t"] + 5, hex(e.rd32(slot))
    assert e.uc.reg_read(UC_X86_REG_ESP) == sp0


def test_bridge_ret_predicate():
    """lift_is_bridge_ret: true for the slow bridge's stop address and for each fast nesting level's return address
    (FAST_BASE + 16 * d + 8, d = 1..60), false for everything else around them."""
    e, n = new_emu()
    lib = n.lib
    assert lib.lift_is_bridge_ret(mpemu.STUB_BASE) == 1
    assert lib.lift_is_bridge_ret(mpemu.STUB_BASE + 1) == 0 and lib.lift_is_bridge_ret(EH_MARK) == 0
    assert lib.lift_is_bridge_ret(0) == 0 and lib.lift_is_bridge_ret(F["ok_t"] + 5) == 0
    n.install_fast([F["leaf_s"]])
    for d in (1, 2, 60):
        assert lib.lift_is_bridge_ret(FAST_BASE + 16 * d + 8) == 1, d
    for v in (FAST_BASE + 8, FAST_BASE + 16 * 61 + 8, FAST_BASE + 16 + 9, FAST_BASE + 16 + 7, FAST_BASE + 16 * 60 + 24):
        assert lib.lift_is_bridge_ret(v) == 0, hex(v)
    n.uninstall(F["leaf_s"])


def test_fast_unwind_past_native():
    """A guest longjmp drops a native frame: uw_jump unwinds to uw_top's frame, past uw_mid (native). The nested run
    of uw_jump returns to uw_top's return address, which belongs to the outer level; the fast path drops uw_mid's
    frame and level 1 returns 0x55 to uw_outer (native), as the emulator does."""
    e, n = new_emu()
    ref = e.call(F["uw_outer"])
    assert ref == 0x56 and not e.fatal, (hex(ref), e.fatal)
    esp_ref = e.uc.reg_read(UC_X86_REG_ESP)
    n.install_fast([F["uw_outer"], F["uw_mid"]])
    u0 = n.fast_stats()["unwinds"]
    got = e.call(F["uw_outer"])
    assert got == 0x56 and not e.fatal and n.fast_error is None, (hex(got), e.fatal, n.fast_error)
    assert e.uc.reg_read(UC_X86_REG_ESP) == esp_ref
    assert n.fast_stats()["unwinds"] == u0 + 1, n.fast_stats()
    # and the path still works for ordinary calls afterwards
    n.install_fast([F["leaf_s"]])
    assert e.call(F["caller_s"]) == 4 + 2 * 3 + 5 and not e.fatal
    n.uninstall(F["leaf_s"])
    n.uninstall(F["uw_mid"])
    n.uninstall(F["uw_outer"])


def test_fast_fallback_stop():
    """A guest call made by native code stops in an HLE handler that calls emu_stop (a stop stub: the same stop a
    fatal error makes). The nested run ends away from its return address, the fallback records the error, native
    calls stop, and the outermost call raises it. The emulator is usable again afterwards. Runs in both modes."""
    e, n = new_emu()
    _install(n, F["g"])
    e.stop_stubs.add(("KERNEL32.DLL", "GetCurrentThreadId"))      # g calls it through the IAT slot
    raised = None
    try:
        e.call(F["g"], 7)
    except NativeError as ex:
        raised = ex
    assert raised is not None and "stopped" in str(raised), raised
    assert e.fatal and "GetCurrentThreadId" in e.fatal, e.fatal
    assert n.fast_error is None and n.error is None
    n.uninstall(F["g"])
    e.stop_stubs.discard(("KERNEL32.DLL", "GetCurrentThreadId"))
    e.fatal = None
    assert e.call(F["leaf_s"], 10, 20) == 10 + 40 + 5 and not e.fatal
    _install(n, F["g"])
    assert e.call(F["g"], 7) == 0x104 + 15 and not e.fatal, e.fatal
    n.uninstall(F["g"])


def test_fast_undo_refused():
    """Fast dispatch under an undo log is refused by the driver (native writes would bypass the log), like the bridge."""
    e, n = new_emu()
    n.install_fast([F["leaf_s"]])
    log = e.undo_begin()
    try:
        e.call(F["leaf_s"], 1, 2)
        raise AssertionError("fast native call under an undo log was not refused")
    except NativeError as ex:
        assert "undo log" in str(ex), ex
    finally:
        e.undo_end(log)
    e.undo_rollback(log)
    n.uninstall(F["leaf_s"])


def test_fast_halt_drops_native_frames():
    """An error recorded in a nested guest call (a fatal stop) halts the fast path. The native loop that made the call
    is dropped, not resumed: its next "call" must not return the stale eax from the call before. The loop stores its
    count after each iteration, so the count shows how far it ran (the guard stops it at 1000000 if it is resumed).
    The fast path works again afterwards, with no unwind counted."""
    e, n = new_emu()
    n.install_fast([F["lp"], F["leaf_s"], F["g"]])
    e.stop_stubs.add(("KERNEL32.DLL", "GetCurrentThreadId"))
    e.wr32(LP_COUNT, 0)
    e.wr32(LP_CB_CALLS, 0)
    s0 = n.fast_stats()
    raised = None
    try:
        e.call(F["lp"])
    except NativeError as ex:
        raised = ex
    s1 = n.fast_stats()
    count = struct.unpack("<I", e.rd(LP_COUNT, 4))[0]
    assert raised is not None and "stopped" in str(raised), raised
    assert e.fatal and "GetCurrentThreadId" in e.fatal, e.fatal
    assert count == 1, "the native loop ran on after the halt: %d iterations" % count
    assert s1["unwinds"] == s0["unwinds"], (s0, s1)
    assert n.fast_error is None
    # the error is cleared: fast native calls (leaf, and g with its nested guest call and HLE stub) work again
    e.fatal = None
    e.stop_stubs.discard(("KERNEL32.DLL", "GetCurrentThreadId"))
    assert e.call(F["leaf_s"], 10, 20) == 10 + 40 + 5 and not e.fatal, e.fatal
    assert e.call(F["g"], 7) == 0x104 + 15 and not e.fatal, e.fatal
    assert e.call(F["caller_s"]) == 4 + 2 * 3 + 5 and not e.fatal, e.fatal
    assert n.fast_error is None and n.fast_stats()["unwinds"] == s0["unwinds"]
    n.uninstall(F["lp"])
    n.uninstall(F["leaf_s"])
    n.uninstall(F["g"])


def _dx_caller(e, base, target, after_cont=False):
    """Emulated caller at base: an SEH frame whose handler does RtlUnwind to this frame and continues at cont (EAX
    0x55), then calls the native function target. A normal return (0x1234) is never reached. after_cont: cont calls
    [SLOT] (the GetCurrentThreadId stub) before it returns."""
    a = seh.Asm(base)
    seh.install_frame(a, "h")
    a.call_abs(target)
    a.mov_eax_imm(0x1234)
    a.emit(0x64, 0x8F, 0x05); a.u32(0)              # pop dword ptr fs:[0]
    a.emit(0x83, 0xC4, 0x04)                        # add esp,4
    a.emit(0xC3)
    a.label("h")
    a.emit(0x8B, 0x5C, 0x24, 0x08)                  # mov ebx,[esp+8]   (EstablisherFrame: this frame)
    a.emit(0x8B, 0x4C, 0x24, 0x04)                  # mov ecx,[esp+4]   (ExceptionRecord)
    a.emit(0x6A, 0x55)                              # push 0x55         (ReturnValue)
    a.emit(0x51)                                    # push ecx
    a.push_label("cont")                            # push TargetIp
    a.emit(0x53)                                    # push ebx          (TargetFrame)
    a.call_abs(e.stub_for("KERNEL32.DLL", "RtlUnwind"))
    a.label("cont")
    a.emit(0x89, 0xDC)                              # mov esp,ebx
    a.emit(0x64, 0x8F, 0x05); a.u32(0)              # pop dword ptr fs:[0]
    a.emit(0x83, 0xC4, 0x04)                        # add esp,4
    if after_cont:
        a.emit(0xFF, 0x15); a.u32(SLOT)             # call [SLOT]: a stop stub (fatal) when the test makes it one
    a.emit(0xC3)
    e.wr(base, a.finish())


def _dx_setup(e):
    e.wr32(DX_SLOT_RAISE, e.stub_for("KERNEL32.DLL", "RaiseException"))
    e.wr32(DX_MARK_N1, 0)
    e.wr32(DX_MARK_N2, 0)


def test_dead_frames_past_entry():
    """Dead frames: an emulated caller (SEH frame) calls the native dx_n2, which calls a guest function that raises. The
    handler unwinds to the caller's frame, which continues and returns normally. The guest has returned past dx_n2's
    entry (no fast_ret was reached), so the native frame is dead: dx_n2 must not resume after its guest call."""
    e, n = new_emu()
    _dx_setup(e)
    _dx_caller(e, DX_E1, F["dx_n2"])
    n.install_fast([F["dx_n2"]])
    s0 = n.fast_stats()
    got = e.call(DX_E1)
    s1 = n.fast_stats()
    assert got == 0x55 and not e.fatal and n.fast_error is None, (hex(got), e.fatal, n.fast_error)
    assert e.rd32(DX_MARK_N2) == 0, "the native frame resumed after its guest call"
    assert s1["dead"] == s0["dead"] + 1, (s0, s1)
    assert e.rd32(mpemu.TEB) == 0xFFFFFFFF
    n.uninstall(F["dx_n2"])
    n.install_fast([F["leaf_s"]])
    assert e.call(F["caller_s"]) == 4 + 2 * 3 + 5 and not e.fatal and n.fast_error is None, e.fatal
    n.uninstall(F["leaf_s"])


def test_dead_frames_two_levels():
    """Dead frames at two levels: E (emulated, SEH frame) -> dx_n1 (native, level 0) -> dx_g (guest) -> dx_n2 (native,
    level 1) -> dx_t raises. The catch is in E, below both entries. Both native frames are dropped; neither resumes,
    and the driver's run continues at E's cont."""
    e, n = new_emu()
    _dx_setup(e)
    _dx_caller(e, DX_E2, F["dx_n1"])
    n.install_fast([F["dx_n1"], F["dx_n2"]])
    s0 = n.fast_stats()
    got = e.call(DX_E2)
    s1 = n.fast_stats()
    assert got == 0x55 and not e.fatal and n.fast_error is None, (hex(got), e.fatal, n.fast_error)
    assert e.rd32(DX_MARK_N1) == 0 and e.rd32(DX_MARK_N2) == 0, "a native frame resumed after its guest call"
    assert s1["dead"] == s0["dead"] + 1, (s0, s1)
    assert e.rd32(mpemu.TEB) == 0xFFFFFFFF
    n.uninstall(F["dx_n1"])
    n.uninstall(F["dx_n2"])
    n.install_fast([F["leaf_s"]])
    assert e.call(F["caller_s"]) == 4 + 2 * 3 + 5 and not e.fatal and n.fast_error is None, e.fatal
    n.uninstall(F["leaf_s"])


def test_dead_frames_fatal():
    """A dead frame whose continuation stops fatally (a stop stub in the emulated caller after its catch): the error is
    recorded (the driver's check, before the frames are dropped), the native frame does not resume, and the error is
    raised by the outermost call. The fast path works again afterwards."""
    e, n = new_emu()
    _dx_setup(e)
    _dx_caller(e, DX_E1, F["dx_n2"], after_cont=True)
    n.install_fast([F["dx_n2"]])
    s0 = n.fast_stats()
    e.stop_stubs.add(("KERNEL32.DLL", "GetCurrentThreadId"))
    raised = None
    try:
        e.call(DX_E1)
    except NativeError as ex:
        raised = ex
    s1 = n.fast_stats()
    assert raised is not None and "stopped" in str(raised), raised
    assert e.fatal and "GetCurrentThreadId" in e.fatal, e.fatal
    assert e.rd32(DX_MARK_N2) == 0, "the native frame resumed after its guest call"
    # a recorded stop is a halt, not a dead-frame unwind: FS_DEAD counts the unwinds only
    assert n.fast_error is None and s1["dead"] == s0["dead"], (s0, s1)
    n.uninstall(F["dx_n2"])
    e.stop_stubs.discard(("KERNEL32.DLL", "GetCurrentThreadId"))
    e.fatal = None
    n.install_fast([F["leaf_s"]])
    assert e.call(F["caller_s"]) == 4 + 2 * 3 + 5 and not e.fatal and n.fast_error is None, e.fatal
    n.uninstall(F["leaf_s"])


def test_overhead():
    """10,000 calls of the stdcall leaf through e.call: emulated and native (both via e.call)."""
    e, n = new_emu()
    N = 10000
    t0 = time.perf_counter()
    for _ in range(N):
        r = e.call(F["leaf_s"], 4, 3)
    t_emu = time.perf_counter() - t0
    assert r == 15 and not e.fatal
    _install(n, F["leaf_s"])
    t0 = time.perf_counter()
    for _ in range(N):
        r2 = e.call(F["leaf_s"], 4, 3)
    t_nat = time.perf_counter() - t0
    assert r2 == 15 and not e.fatal
    n.uninstall(F["leaf_s"])
    print("  overhead: emulated %.1f us/call, native %.1f us/call (%d calls)" % (
        t_emu / N * 1e6, t_nat / N * 1e6, N))
    # The same leaf called LOOP_N times from emulated code inside one e.call: the per-call cost of the dispatch itself
    # (e.call's own Python work is left out).
    n.uninstall(F["leaf_s"])
    t0 = time.perf_counter()
    r_emu_loop = e.call(F["loop"])
    t_loop_emu = time.perf_counter() - t0
    assert not e.fatal, e.fatal
    _install(n, F["leaf_s"])
    c0 = n.calls
    t0 = time.perf_counter()
    r_nat_loop = e.call(F["loop"])
    t_loop_nat = time.perf_counter() - t0
    assert not e.fatal and r_nat_loop == r_emu_loop == 15 and n.calls == c0 + LOOP_N, (r_nat_loop, n.calls - c0)
    n.uninstall(F["leaf_s"])
    print("  in-guest loop: emulated leaf %.2f us/call, fast native leaf %.2f us/call (%d calls)" % (
        t_loop_emu / LOOP_N * 1e6, t_loop_nat / LOOP_N * 1e6, LOOP_N))
    return t_emu / N * 1e6, t_nat / N * 1e6


def _pick_real(img, want=6):
    """Exports of rlmfc that are small getters/tests and translate fully on their own."""
    picks = []
    for va, name in sorted(img.exports, key=lambda t: t[1]):
        if not (name.startswith("?get") or name.startswith("?is") or name.startswith("?Get")):
            continue
        res = x86c.lift_function(img, va, frozenset([va]))
        if not res.ok or len(res.c) > 3000:
            continue
        picks.append((len(res.c), va, name))
    picks.sort()
    return [(va, name) for _, va, name in picks[:want]]


def test_real_dll():
    """rlmfc.dll getters, lifted by lift/build.py and run natively, compared with the emulator from the same state.
    Each run starts from the same undo-reset state; the emulated run's registers, x87 state and written bytes (and
    the 4 KB pages they are in) must match the native run's."""
    rlmfc = os.path.join(GAME, "rlmfc.dll")
    if not os.path.exists(rlmfc):
        print("  skipped: game folder not found (%s)" % GAME)
        return
    img = x86c.PEImage(rlmfc)
    picks = _pick_real(img)
    assert picks, "no getter translates fully"
    lib = os.path.join(BUILD, "librlmfc_lifted.dylib")
    res = liftbuild.build(img, [va for va, _ in picks], os.path.join(BUILD, "rlmfc"), lib, module="rlmfc.dll")
    assert len(res["lifted"]) == len(picks), res["dropped"]
    e = mpemu.boot(GAME, verbose=False)
    n = Native(e, lib)
    rl = e.modules["rlmfc.dll"]
    rng = random.Random(7)
    for va, name in picks:
        assert rl.base + (va - img.base) == va
        obj = e.alloc(256)
        e.wr(obj, bytes(rng.getrandbits(8) for _ in range(256)))
        # emulated, recorded
        log = e.undo_begin()
        r_emu = e.call(va, ecx=obj, max_insns=0)
        assert not e.fatal, (name, e.fatal)
        regs_emu = _regs(e)
        e.undo_end(log)
        writes = log.writes()
        pages = sorted({a >> 12 for a in writes})
        mem_emu = {p: bytes(e.rd(p << 12, 4096)) for p in pages}
        e.undo_rollback(log)
        # native from the same state
        _install(n, va)
        c0 = n.calls
        r_nat = e.call(va, ecx=obj)
        assert not e.fatal, (name, e.fatal)
        assert n.calls == c0 + 1, "the native function did not run"
        regs_nat = _regs(e)
        n.uninstall(va)
        diffs = [k for k in regs_emu if regs_emu[k] != regs_nat[k]]
        mem_diffs = [p for p in pages if bytes(e.rd(p << 12, 4096)) != mem_emu[p]]
        ok = r_emu == r_nat and not diffs and not mem_diffs
        print("  %-44s eax=%08x emu/native %s  writes=%d  x87 st0=%s%s" % (
            name[:44], r_emu & 0xFFFFFFFF, "match" if ok else "DIFFER", len(writes),
            "%g" % (x2d(*regs_emu["fp%d" % ((regs_emu["fpsw"] >> 11) & 7)])[0]),
            "" if ok else "  diffs=%s mem=%s" % (diffs, mem_diffs)))
        assert ok, (name, diffs, mem_diffs, r_emu, r_nat)
    assert n.inexact == 0, n.inexact


REG_NAMES = dict(eax=UC_X86_REG_EAX, ecx=UC_X86_REG_ECX, edx=UC_X86_REG_EDX, ebx=UC_X86_REG_EBX,
                 esp=UC_X86_REG_ESP, ebp=UC_X86_REG_EBP, esi=UC_X86_REG_ESI, edi=UC_X86_REG_EDI,
                 eflags=UC_X86_REG_EFLAGS)


def _restore(e, snap):
    """Write a _regs() snapshot back into the emulator."""
    uc = e.uc
    for k, rid in REG_NAMES.items():
        uc.reg_write(rid, snap[k])
    uc.reg_write(UC_X86_REG_FPCW, snap["fpcw"])
    uc.reg_write(UC_X86_REG_FPSW, snap["fpsw"])
    uc.reg_write(UC_X86_REG_FPTAG, snap["fptag"])
    for p in range(8):
        uc.reg_write(UC_X86_REG_FP0 + p, snap["fp%d" % p])


def _random_x87(rng):
    """A raw 80-bit value: mostly non-double encodings, some with a zero low mantissa (the exact fast path),
    some MMX-style (exponent 0xffff), some zero."""
    mant = rng.getrandbits(64)
    exp = rng.choice([rng.getrandbits(16), 0x7fff, 0xffff, 0, 0x3fff, 0x8000 | rng.randint(0x3c00, 0x43ff)])
    if rng.random() < 0.4:
        mant &= ~0x7ff
    if rng.random() < 0.1:
        mant = 0
    return mant, exp


def _special_doubles(rng):
    specials = [0.0, -0.0, 1.0, -1.0, 2.5, 0.1, 1e300, -1e300, 5e-324, -5e-324, 2.2250738585072009e-308,
                2.2250738585072014e-308, 1.7976931348623157e308, float("inf"), float("-inf")]
    specials += [struct.unpack("<d", struct.pack("<Q", b))[0] for b in (
        0x7ff8000000001234, 0x7ff0000000000001, 0xfff8000000000001, 0x000fffffffffffff, 0x0000000000000001,
        0x8000000000000001, 0x7fefffffffffffff)]
    specials += [struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0] for _ in range(1500)]
    specials += [rng.uniform(-1, 1) * 2.0 ** rng.randint(-1070, 1000) for _ in range(1000)]
    return specials


def test_fpu_flags():
    """LiftEntry.flags: a function gets the FPU flag when it uses x87 or MMX itself, when it makes a call the bridge
    cannot see through (call_guest, lift_call), or when it reaches a flagged function directly."""
    e, n = new_emu()
    want = {"leaf_s": 0, "leaf_1": 0, "leaf_t": 0, "leaf_cd2": 0, "da": 0,   # integer code, lifted calls only
            "g": 1, "a": 1, "bad": 1,                                         # calls outside the lifted set
            "mmcopy": 1, "mmfill": 1, "mmpair": 1}                             # MMX, or reaches mmcopy
    for name, flag in want.items():
        assert n.flags[F[name]] == bool(flag), (name, n.flags[F[name]])


def test_conversions_c_matches_python():
    """The C double <-> 80-bit conversions (runtime.c) agree bit for bit with native.d2x / native.x2d, including
    the exact flag, on specials, random doubles and random 80-bit values that are not doubles."""
    n = new_emu()[1]
    lib = n.lib
    rng = random.Random(21)
    m, x, ex = ctypes.c_uint64(), ctypes.c_uint16(), ctypes.c_int()
    count = 0
    for d in _special_doubles(rng):
        lib.lift_conv_d2x(d, ctypes.byref(m), ctypes.byref(x))
        assert (m.value, x.value) == d2x(d), (d, hex(m.value), hex(x.value), d2x(d))
        mant, exp = m.value, x.value
        v = lib.lift_conv_x2d(mant, exp, ctypes.byref(ex))
        pv, pexact = x2d(mant, exp)
        assert struct.pack("<d", v) == struct.pack("<d", pv) and bool(ex.value) == pexact, d
        assert ex.value == 1, d                                   # a double round-trips exactly
        count += 1
    for _ in range(4000):
        mant, exp = _random_x87(rng)
        v = lib.lift_conv_x2d(mant, exp, ctypes.byref(ex))
        pv, pexact = x2d(mant, exp)
        assert struct.pack("<d", v) == struct.pack("<d", pv), (hex(mant), hex(exp), v, pv)
        assert bool(ex.value) == pexact, (hex(mant), hex(exp), ex.value, pexact)
        count += 1
    print("  %d conversions agree (C and Python)" % count)


def _cpu_fields(c):
    return (list(c.r), c.cf, c.pf, c.af, c.zf, c.sf, c.of, c.df, c.top, c.tag, c.cw, c.sw,
            [struct.pack("<d", v) for v in c.st], list(c.mm), c.mmx_dirty)


def test_sync_c_matches_python():
    """C and Python state syncs give the same CPU from the same emulator state, and the same emulator state
    from the same CPU (x87 values, tags, TOP, C bits, control word, EFLAGS, MMX dirty registers)."""
    e, n = new_emu()
    uc = e.uc
    rng = random.Random(33)
    for trial in range(60):
        for k, rid in REG_NAMES.items():
            uc.reg_write(rid, rng.getrandbits(32) if k != "eflags" else rng.getrandbits(32) | 0x202)
        uc.reg_write(UC_X86_REG_FPCW, rng.getrandbits(16))
        uc.reg_write(UC_X86_REG_FPSW, (rng.randrange(8) << 11) | (rng.getrandbits(16) & 0x4700))
        uc.reg_write(UC_X86_REG_FPTAG, rng.getrandbits(16))
        for p in range(8):
            uc.reg_write(UC_X86_REG_FP0 + p, _random_x87(rng))
        base = _regs(e)
        cc, cp = CPU(), CPU()
        i0 = n.inexact
        n.uc_to_cpu(cc, True)
        i1 = n.inexact
        n._py_uc_to_cpu(cp, True)
        i2 = n.inexact
        assert i1 - i0 == i2 - i1, (i1 - i0, i2 - i1)
        assert _cpu_fields(cc) == _cpu_fields(cp), trial
        # the same change to both CPUs
        for i in range(8):
            cc.r[i] = cp.r[i] = rng.getrandbits(32)
        for name in ("cf", "pf", "af", "zf", "sf", "of", "df"):
            v = rng.getrandbits(1)
            setattr(cc, name, v)
            setattr(cp, name, v)
        cc.top = cp.top = rng.randrange(8)
        cc.cw = cp.cw = rng.getrandbits(16)
        cc.sw = cp.sw = rng.getrandbits(16) & 0x4700
        tag = cc.tag = cp.tag = rng.getrandbits(8)
        for p in range(8):
            if not tag & (1 << p):
                v = rng.choice([rng.uniform(-9, 9), 0.0, -0.0, 1e-310, float("nan"), 2.0 ** 1000])
                cc.st[p] = cp.st[p] = v
            cc.mm[p] = cp.mm[p] = rng.getrandbits(64)
        cc.mmx_dirty = cp.mmx_dirty = rng.getrandbits(8) if trial % 2 else 0
        _restore(e, base)
        n.cpu_to_uc(cc, True)
        after_c = _regs(e)
        _restore(e, base)
        n._py_cpu_to_uc(cp, True)
        after_py = _regs(e)
        assert after_c == after_py, [k for k in after_c if after_c[k] != after_py[k]]
        assert cc.mmx_dirty == 0 and cp.mmx_dirty == 0
        # without x87 (a function with no FPU flag) only GPRs and EFLAGS move
        _restore(e, base)
        n.cpu_to_uc(cc, False)
        after_nofpu = _regs(e)
        assert [after_nofpu["fp%d" % p] for p in range(8)] == [base["fp%d" % p] for p in range(8)]
        assert after_nofpu["fpsw"] == base["fpsw"] and after_nofpu["fptag"] == base["fptag"]
    print("  60 random states: C and Python agree in both directions")


def test_x87_skip_for_flagless_functions():
    """A function without the FPU flag leaves the x87 registers alone and does not decode them: odd raw values
    survive the call and are not counted as inexact."""
    e, n = new_emu()
    assert not n.flags[F["leaf_s"]]
    rng = random.Random(4)
    for p in range(8):
        e.uc.reg_write(UC_X86_REG_FP0 + p, (rng.getrandbits(64) | (1 << 63) | 1, 0x4123))   # not doubles
    before = _regs(e)
    _install(n, F["leaf_s"])
    i0 = n.inexact
    got = e.call(F["leaf_s"], 10, 20)
    n.uninstall(F["leaf_s"])
    assert got == 10 + 40 + 5 and not e.fatal
    assert n.inexact == i0, "x87 registers were decoded for a function without the FPU flag"
    after = _regs(e)
    assert [after["fp%d" % p] for p in range(8)] == [before["fp%d" % p] for p in range(8)]


def _mm_case(e, n, name, args, rng):
    """Run one cdecl MMX function emulated (recorded) and natively from the same state. Returns the mismatches."""
    va = F[name]
    n.uninstall(va)
    log = e.undo_begin()
    r_emu = e.call(va, *args, cc="cdecl")
    assert not e.fatal, (name, e.fatal)
    regs_emu = _regs(e)
    e.undo_end(log)
    pages = sorted({a >> 12 for a in log.writes()})
    mem_emu = {p: bytes(e.rd(p << 12, 4096)) for p in pages}
    e.undo_rollback(log)
    _install(n, va)
    c0 = n.calls
    r_nat = e.call(va, *args, cc="cdecl")
    assert not e.fatal, (name, e.fatal)
    assert n.calls == c0 + 1, "the native function did not run"
    regs_nat = _regs(e)
    n.uninstall(va)
    fp_keys = ["fp%d" % p for p in range(8)]
    diffs = [k for k in regs_emu if k not in fp_keys and regs_emu[k] != regs_nat[k]]
    # The mantissa of every FP register is the mm value. The exponent of a non-empty register must match. The
    # emulator (QEMU) leaves the exponent of an MMX-written register alone, the hardware sets it to 0xffff, and
    # the translated side follows the hardware; after emms the tags are empty and the exponent is not visible.
    for p in range(8):
        a, b = regs_emu[fp_keys[p]], regs_nat[fp_keys[p]]
        empty = ((regs_emu["fptag"] >> (2 * p)) & 3) == 3
        if a[0] != b[0] or (not empty and a[1] != b[1]):
            diffs.append(fp_keys[p])
    mem_diffs = [p for p in pages if bytes(e.rd(p << 12, 4096)) != mem_emu[p]]
    return (r_emu == r_nat and not diffs and not mem_diffs), diffs, mem_diffs, r_emu, r_nat


def test_mmx_native_matches_emulated():
    """movq/emms code (mmcopy, mmfill, and mmpair which calls mmcopy natively) against the emulator from the same
    random x87 state (TOP, tags, raw values) at misaligned buffers. Registers, x87 state, mm (as physical FP
    mantissas) and the written pages must match."""
    e, n = new_emu()
    # the flags, and what the x87 sync is for: mmcopy/mmfill use MMX, mmpair reaches mmcopy
    assert n.flags[F["mmcopy"]] and n.flags[F["mmfill"]] and n.flags[F["mmpair"]]
    rng = random.Random(11)
    buf = e.alloc(256)
    src_data = bytes(rng.getrandbits(8) for _ in range(256))
    e.wr(buf, src_data)
    cases = 0
    for off in (0, 1, 3, 7):
        for _ in range(4):
            for p in range(8):
                e.uc.reg_write(UC_X86_REG_FP0 + p, _random_x87(rng))
            e.uc.reg_write(UC_X86_REG_FPSW, (rng.randrange(8) << 11))
            e.uc.reg_write(UC_X86_REG_FPTAG, rng.getrandbits(16))
            dst, src = buf + 64 + off, buf + 160 + off
            for name, args in (("mmcopy", (dst, src)), ("mmfill", (dst, rng.getrandbits(32), rng.getrandbits(32))),
                               ("mmpair", (dst, src))):
                ok, diffs, mem_diffs, r_emu, r_nat = _mm_case(e, n, name, args, rng)
                assert ok, (name, off, diffs, mem_diffs, r_emu, r_nat)
                cases += 1
    print("  %d MMX calls: native and emulated match (registers, x87, mm, written pages)" % cases)


def _map_crt(e):
    """Copies of MSVCRT's _ftol and tolower (the bytes native.CRT_HELPERS checks) at their real addresses, the
    caller slots pointing at them, and the "C" locale."""
    import native
    e.map(CRT_BASE, 0x3c000)
    for (_, name), ranges in native.CRT_HELPERS.items():
        for rva, h in ranges:
            e.wr(CRT_BASE + rva, bytes.fromhex(h))
    e.wr32(CSLOT_FTOL, CRT_BASE + 0x1f14)
    e.wr32(CSLOT_TOLOWER, CRT_BASE + 0x11790)
    e.wr32(CRT_LOCALE, 0)


def _crt_counts(n):
    k = n.lib.lift_crt_counts(None, 0)
    out = (ctypes.c_uint64 * k)()
    n.lib.lift_crt_counts(out, k)
    return {n.lib.lift_crt_name(i).decode(): out[i] for i in range(k)}


def test_crt_helpers_match_guest():
    """The native _ftol and tolower (lift/runtime/crt.c) leave exactly what MSVCRT's code leaves: registers, flags,
    x87 state and the stack below esp. Each case runs three ways from the same state: emulated, lifted with the
    helpers unbound (a guest call), lifted with them bound. Covers every rounding mode, both precisions, values that
    round in each direction, the int64 limits, out-of-range values, infinities and NaNs (the integer indefinite), and
    a tail jump to _ftol. tolower: the ASCII boundaries, negative and large ints, and a non-"C" locale, which the
    helper leaves to the guest."""
    e, n = new_emu()
    _map_crt(e)
    data = e.alloc(16)
    rng = random.Random(11)
    vals = [0.0, -0.0, 0.5, -0.5, 1.5, -1.5, 2.5, -2.5, 0.49999999999999994, 1e-300, -1e-300, 5e-324,
            2147483647.5, -2147483648.5, 4294967295.75, 2.0 ** 52 + 0.5, 2.0 ** 63, -2.0 ** 63, -2.0 ** 63 - 2048,
            9223372036854774784.0, -9223372036854774784.0, 1e19, -1e19, 1e300, -1e300, float("inf"), float("-inf")]
    vals += [struct.unpack("<d", struct.pack("<Q", b))[0] for b in (0x7ff8000000000000, 0xfff8000000000000,
                                                                   0x7ff0000000000001)]
    vals += [rng.uniform(-1, 1) * 2.0 ** rng.randint(-5, 70) for _ in range(60)]

    def bind(on):
        for name, rva in (("_ftol", 0x1f14), ("tolower", 0x11790)):
            assert n.lib.lift_crt_bind(name.encode(), CRT_BASE + rva if on else 0, CRT_BASE if on else 0) >= 0

    def run(fn, arg):
        e.wr(mpemu.STACK_TOP - 0x1000, b"\xcc" * 0x1000)
        r = e.call(F[fn], arg, cc="cdecl")
        assert not e.fatal, (fn, e.fatal)
        sp = e.uc.reg_read(UC_X86_REG_ESP)
        regs = _regs(e)
        for p in range(8):           # an empty register's raw bits are not state the bridge keeps (lift_sync_to_uc)
            if (regs["fptag"] >> (2 * p)) & 3 == 3:
                regs["fp%d" % p] = "empty"
        return r, regs, bytes(e.rd(sp - 0x40, 0x40))

    def three(fn, arg):
        snap = _regs(e)
        ref = run(fn, arg)
        _install(n, F[fn])
        try:
            out = []
            for on in (False, True):
                bind(on)
                _restore(e, snap)
                c0 = _crt_counts(n)
                out.append(run(fn, arg))
                c1 = _crt_counts(n)
                assert sum(c1.values()) - (sum(c0.values()) if on else 0) == (1 if on else 0), (fn, on, c0, c1)
        finally:
            n.uninstall(F[fn])
            bind(False)
        _restore(e, snap)
        return ref, out[0], out[1]

    cases = 0
    try:
        for cw in (0x027F, 0x067F, 0x0A7F, 0x0E7F, 0x007F, 0x037F, 0x0C7F):
            for v in vals:
                e.wr(data, struct.pack("<H6xd", cw, v))
                for fn in ("ftol_t", "ftol_j"):
                    ref, guest, nat = three(fn, data)
                    assert ref == guest == nat, (fn, hex(cw), v, [(k, ref[1][k], nat[1][k]) for k in ref[1]
                                                                   if ref[1][k] != nat[1][k]],
                                                 ref[2].hex(), nat[2].hex(), hex(ref[0]), hex(nat[0]))
                    cases += 1
        for x in (0, 1, 0x40, 0x41, 0x4d, 0x5a, 0x5b, 0x60, 0x61, 0x7a, 0x7f, 0x80, 0xc1, 0xff, 0x100, 0x7fffffff,
                  0x80000000, 0xffffffff, 0xffffffbf, 0xffffff80):
            ref, guest, nat = three("tolower_t", x)
            assert ref == guest == nat, (hex(x), ref, nat)
            cases += 1
        # another locale: the helper declines without touching anything (the guest's locale path is not mapped here)
        bind(True)
        e.wr32(CRT_LOCALE, 1)
        cpu, _ = n._take()
        esp = cpu.r[4] = mpemu.STACK_TOP - 0x100
        cpu.r[0] = 0x1234
        e.wr(esp - 0x20, b"\xcc" * 0x20)
        assert n.lib.lift_crt_call(ctypes.byref(cpu), CRT_BASE + 0x11790, 0xdeadbeef) == 0
        assert cpu.r[4] == esp and cpu.r[0] == 0x1234 and bytes(e.rd(esp - 0x20, 0x20)) == b"\xcc" * 0x20
    finally:
        bind(False)
        e.wr32(CRT_LOCALE, 0)
    print("  %d cases: emulated, guest call and native helper agree" % cases)


STR_RVA = {"_stricmp": 0x10d13, "_strnicmp": 0x139f6}     # the C-locale paths crt.c reproduces (CRT_HELPERS)


def _map_msvcrt(e):
    """The game's MSVCRT.DLL at CRT_BASE, its sections as x86c.PEImage lays them out. None without the game folder."""
    path = os.path.join(os.environ.get("MP_GAME_DIR") or GAME, "MSVCRT.DLL")
    if not os.path.exists(path):
        return None
    img = x86c.PEImage(path, base=CRT_BASE)
    end = max(va + len(buf) for va, buf in img._spans)
    e.map(CRT_BASE, (end - CRT_BASE + 0xfff) & ~0xfff)
    for va, buf in img._spans:
        e.wr(va, bytes(buf))
    e.wr32(CRT_LOCALE, 0)
    return img


def _str_pairs(rng):
    """Pairs of NUL-free strings: equal, equal ignoring case, prefixes, empty, the case-range edges (@ [ ` {),
    bytes >= 0x80, and random pairs over those characters."""
    alpha = b"abcxyzABCXYZ09 _@[`{\x80\xc1\xe1\xff"

    def rs(maxlen):
        return bytes(rng.choice(alpha) for _ in range(rng.randrange(maxlen + 1)))

    def swap(s):
        return bytes(ch ^ 0x20 if (0x41 <= ch <= 0x5a or 0x61 <= ch <= 0x7a) else ch for ch in s)

    out = [(b"", b""), (b"", b"a"), (b"a", b""), (b"A", b"a"), (b"@", b"`"), (b"[", b"{"), (b"Z", b"z"),
           (b"\x80", b"\x80"), (b"\xc1", b"\xe1"), (b"\xe1", b"\xc1"), (b"abc", b"ABD"), (b"ABC", b"abc")]
    for _ in range(200):
        x = rs(12)
        kind = rng.randrange(6)
        if kind == 0:
            y = x
        elif kind == 1:
            y = swap(x)
        elif kind == 2:
            y = x + rs(4)
        elif kind == 3:
            y = x[:rng.randrange(len(x) + 1)]
        elif kind == 4:
            y = bytearray(x)
            if y:
                y[rng.randrange(len(y))] = rng.choice(alpha)
            y = bytes(y)
        else:
            y = rs(12)
        out.append((x, y))
    return out


def _model_strnicmp(x, y, nn):
    """The C library's strnicmp on NUL-terminated byte strings, in Python (the value only)."""
    def low(c):
        return c + 0x20 if 0x41 <= c <= 0x5a else c
    if nn == 0:
        return 0
    i, fx, fy = 0, 0, 0
    while True:
        cx = x[i] if i < len(x) else 0
        cy = y[i] if i < len(y) else 0
        if cx == 0 or cy == 0:
            fx, fy = cx, cy
            break
        fx, fy = low(cx), low(cy)
        if fx != fy:
            break
        i += 1
        if i == nn:
            break
    return 0 if fx == fy else (-1 if fx < fy else 1)


def test_crt_string_helpers():
    """Native _stricmp and _strnicmp (lift/runtime/crt.c) against the real MSVCRT.DLL's C-locale code, from the same
    state: eax, every GPR, the arithmetic flags, and the guest memory from 0x40 below esp to 0x20 above it (the
    return address, the saved registers, and the argument slots). Strings are placed so that the NUL is the last
    byte of a page, and n covers 0, 1, shorter and longer than the strings, and 0x80000000 and 0xffffffff.
    A locale other than "C" is declined and leaves everything as it was."""
    e, n = new_emu()
    img = _map_msvcrt(e)
    if img is None:
        print("  skipped: game folder not found (MSVCRT.DLL)")
        return
    rng = random.Random(22)
    P = mpemu.STACK_TOP - 0x800               # esp at the call: the arguments are at P, P+4, P+8
    region = e.alloc(0x3000)
    pages = (region + 0xfff) & ~0xfff         # three mapped pages from here: pages, pages+0x1000, +0x2000
    names = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
    uc_ids = [UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP,
              UC_X86_REG_ESI, UC_X86_REG_EDI]
    STACK_LO, STACK_HI = P - 0x40, P + 0x20

    def prep(args, init, ef):
        e.wr(STACK_LO, b"\xcc" * (STACK_HI - STACK_LO))
        for i, a in enumerate(args):
            e.wr32(P + 4 * i, a)
        for rid, v in zip(uc_ids, init):
            e.uc.reg_write(rid, v)
        e.uc.reg_write(UC_X86_REG_EFLAGS, ef)

    def run_both(va, args, init, ef):
        """Emulated, then native from the same state. Returns (eax, emu regs, emu stack, native regs, native flags,
        native stack)."""
        prep(args, init, ef)
        eax = e.call(va, cc="cdecl")
        assert not e.fatal, e.fatal
        emu = _regs(e)
        mem_emu = bytes(e.rd(STACK_LO, STACK_HI - STACK_LO))
        prep(args, init, ef)
        cpu = CPU()
        n.uc_to_cpu(cpu)
        assert n.lib.lift_crt_call(ctypes.byref(cpu), va, mpemu.STUB_BASE) == 1, hex(va)
        nat = [cpu.r[i] for i in range(8)]
        mem_nat = bytes(e.rd(STACK_LO, STACK_HI - STACK_LO))
        return eax, emu, mem_emu, nat, (cpu.cf, cpu.pf, cpu.af, cpu.zf, cpu.sf, cpu.of), mem_nat

    def check(fn, args, init, ef):
        va = CRT_BASE + STR_RVA[fn]
        eax, emu, mem_emu, nat, nflags, mem_nat = run_both(va, args, init, ef)
        order = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
        ef = emu["eflags"]
        eflags = ((ef & 1), (ef >> 2) & 1, (ef >> 4) & 1, (ef >> 6) & 1, (ef >> 7) & 1, (ef >> 11) & 1)
        emu_regs = [emu[k] for k in order]
        nat_regs = [nat[0], nat[1], nat[2], nat[3], nat[4], nat[5], nat[6], nat[7]]
        ctx = (fn, [hex(a) for a in args], [hex(v) for v in init])
        assert emu["eax"] == eax, ctx
        assert emu_regs == nat_regs, (ctx, [(k, hex(a), hex(b)) for k, a, b in zip(order, emu_regs, nat_regs)
                                            if a != b])
        assert eflags == nflags, (ctx, eflags, nflags)
        assert mem_emu == mem_nat, (ctx, [i for i in range(len(mem_emu)) if mem_emu[i] != mem_nat[i]][:8])
        return eax

    def fresh_state():
        init = [rng.getrandbits(32) for _ in range(8)]
        init[4] = P                              # esp
        return init, 0x202 | (rng.getrandbits(32) & 0x8d5)

    _bind_str(n, True)
    cases = 0
    try:
        for x, y in _str_pairs(rng):
            # the NUL of one string as the last byte of a page, the other at a fixed offset
            edge1 = rng.random() < 0.25
            edge2 = not edge1 and rng.random() < 0.25
            a1 = pages + 0x1000 - len(x) - 1 if edge1 else pages + 0x100
            a2 = pages + 0x1000 - len(y) - 1 if edge2 else pages + 0x400
            e.wr(a1, x + b"\0")
            e.wr(a2, y + b"\0")
            init, ef = fresh_state()
            eax = check("_stricmp", (a1, a2), init, ef)
            cases += 1
            # the value: the sign of the first difference in lower case, or of the lengths (0 when equal)
            want = (len(x) > len(y)) - (len(x) < len(y))
            for cx, cy in zip(x.lower(), y.lower()):
                if cx != cy:
                    want = -1 if cx < cy else 1
                    break
            assert (eax if eax < 0x80000000 else eax - 0x100000000) == want, (x, y, eax, want)
            for nn in sorted({0, 1, 2, len(x), len(x) + 1, len(y), max(len(x), len(y)) + 1,
                              rng.randrange(0, 20), 0x80000000, 0xffffffff}):
                init, ef = fresh_state()
                eax = check("_strnicmp", (a1, a2, nn), init, ef)
                cases += 1
                assert eax == _model_strnicmp(x, y, nn) & 0xffffffff, (x, y, nn, eax)
    finally:
        _bind_str(n, False)
    # another locale: declined, nothing changed (registers, flags, memory)
    _bind_str(n, True)
    try:
        e.wr32(CRT_LOCALE, 1)
        for fn in STR_RVA:
            init, ef = fresh_state()
            prep((pages, pages + 0x100, 5), init, ef)
            before = (_regs(e), bytes(e.rd(STACK_LO, STACK_HI - STACK_LO)))
            cpu = CPU()
            n.uc_to_cpu(cpu)
            assert n.lib.lift_crt_call(ctypes.byref(cpu), CRT_BASE + STR_RVA[fn], mpemu.STUB_BASE) == 0, fn
            assert bytes(e.rd(STACK_LO, STACK_HI - STACK_LO)) == before[1] and _regs(e) == before[0], fn
            cases += 1
    finally:
        e.wr32(CRT_LOCALE, 0)
        _bind_str(n, False)
    print("  %d string calls: native and the real MSVCRT.DLL agree (eax, GPRs, flags, stack and memory)" % cases)


def _bind_str(n, on):
    for fn, rva in STR_RVA.items():
        assert n.lib.lift_crt_bind(fn.encode(), CRT_BASE + rva if on else 0, CRT_BASE if on else 0) >= 0


def test_crt_bind_refuses_mismatch():
    """Native.CRT_HELPERS binds _stricmp and _strnicmp only when the guest bytes are the ones crt.c reproduces: one
    changed byte inside a checked range leaves that helper unbound (and lift_crt_call declines), the others bind."""
    e, n = new_emu()
    if _map_msvcrt(e) is None:
        print("  skipped: game folder not found (MSVCRT.DLL)")
        return
    import native as nat_mod
    fake_mod = types.SimpleNamespace(name="MSVCRT.DLL", base=CRT_BASE,
                                     exports={name: CRT_BASE + rva for name, rva in STR_RVA.items()})
    fake_e = types.SimpleNamespace(modules={0: fake_mod}, rd=e.rd, regions=e.regions)
    host = types.SimpleNamespace(e=fake_e, lib=n.lib)
    try:
        bound = nat_mod.Native._bind_crt(host)
        assert set(STR_RVA) <= set(bound), bound
        # the table's own ranges, inside the real image, are the ones the code was checked against
        for key, ranges in nat_mod.CRT_HELPERS.items():
            if key[1] in STR_RVA:
                for rva, h in ranges:
                    assert bytes(e.rd(CRT_BASE + rva, len(h) // 2)).hex() == h
        for fn, rva, off in (("_stricmp", 0x10d13, 0x20), ("_strnicmp", 0x139f6, 0x40)):
            orig = bytes(e.rd(CRT_BASE + rva + off, 1))
            e.wr(CRT_BASE + rva + off, bytes([orig[0] ^ 0x01]))
            _bind_str(n, False)
            bound = nat_mod.Native._bind_crt(host)
            assert fn not in bound and set(STR_RVA) - {fn} <= set(bound), (fn, bound)
            cpu = CPU()
            n.uc_to_cpu(cpu)
            assert n.lib.lift_crt_call(ctypes.byref(cpu), CRT_BASE + rva, mpemu.STUB_BASE) == 0, fn
            e.wr(CRT_BASE + rva + off, orig)
            _bind_str(n, False)
            bound = nat_mod.Native._bind_crt(host)
            assert fn in bound, fn
            _bind_str(n, False)
        print("  binding: a changed byte in a checked range leaves that helper unbound")
    finally:
        _bind_str(n, False)
        for fn in ("_ftol", "tolower"):
            n.lib.lift_crt_bind(fn.encode(), 0, 0)


RT_RVA = 0x1844e                           # __RTDynamicCast (MSVCRT.DLL), the CRT_HELPERS entry
RT_VA = CRT_BASE + RT_RVA
RT_FRAME = mpemu.STACK_TOP - 0x800         # esp before each call: the arguments are at P, P+4, ...
RT_WIN_LO, RT_WIN_HI = RT_FRAME - 0x100, RT_FRAME + 0x20
RT_GPRS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")


def _set_regions(e, n):
    """The emulator's mapped regions, for the helpers (Native._bind_crt hands them over at bind time)."""
    pairs = [v for start, size in e.regions for v in (start, size)]
    assert n.lib.lift_crt_regions((ctypes.c_uint32 * len(pairs))(*pairs), len(pairs) // 2) == 0


def _bind_rt(n, on):
    """Bind (or unbind) __RTDynamicCast: the helper runs for lifted calls to MSVCRT's export."""
    assert n.lib.lift_crt_bind(b"__RTDynamicCast", RT_VA if on else 0, CRT_BASE if on else 0) >= 0


def _mapped(e, a):
    return any(start <= a < start + size for start, size in e.regions)


class _Rtti:
    """Synthetic RTTI in the guest heap, laid out as MSVC emits it for x86: TypeDescriptor {vfptr, spare, name},
    BaseClassDescriptor {TD, numContainedBases, PMD {mdisp, pdisp, vdisp}, attributes}, ClassHierarchyDescriptor
    {signature, attributes, numBaseClasses, pBaseClassArray}, CompleteObjectLocator {signature, offset, cdOffset,
    pTypeDescriptor, pClassDescriptor}, whose pointer sits at vtable-4. Blocks start at random offsets from 16-byte
    alignment, so the names fall at every alignment strcmp handles."""

    def __init__(self, e, rng):
        self.e, self.rng = e, rng

    def block(self, size):
        return self.e.alloc(size + 4) + self.rng.randrange(4)

    def td(self, name):
        a = self.block(8 + len(name) + 1)
        self.e.wr32(a, 0)
        self.e.wr32(a + 4, 0)
        self.e.wr(a + 8, name + b"\0")
        return a

    def hier(self, names, spec, attr):
        """spec: [(class index, numContainedBases, mdisp, BCD attributes[, pdisp])] in array order, the complete class
        first. attr: the CHD attributes. Returns the hierarchy as a dict."""
        e = self.e
        tds = [self.td(nm) for nm in names]
        arr = self.block(4 * len(spec))
        chd = self.block(0x10)
        e.wr32(chd, 0)
        e.wr32(chd + 4, attr)
        e.wr32(chd + 8, len(spec))
        e.wr32(chd + 0xc, arr)
        for k, ent in enumerate(spec):
            cls, num, mdisp, battr = ent[:4]
            pdisp = ent[4] if len(ent) > 4 else -1
            b = self.block(0x18)
            e.wr32(b, tds[cls])
            e.wr32(b + 4, num)
            e.wr32(b + 8, mdisp & 0xffffffff)
            e.wr32(b + 0xc, pdisp & 0xffffffff)
            e.wr32(b + 0x10, 0)
            e.wr32(b + 0x14, battr)
            e.wr32(arr + 4 * k, b)
        return {"tds": tds, "chd": chd, "spec": spec, "names": names}

    def vtable(self, h, mdisp, cd=0):
        """A vtable for a sub-object at mdisp in a complete object of h; its COL is at vtable-4."""
        col = self.block(0x14)
        self.e.wr32(col, 1)
        self.e.wr32(col + 4, mdisp & 0xffffffff)
        self.e.wr32(col + 8, cd)
        self.e.wr32(col + 0xc, h["tds"][h["spec"][0][0]])
        self.e.wr32(col + 0x10, h["chd"])
        x = self.block(8)
        self.e.wr32(x, col)
        self.e.wr32(x + 4, 0x7800dead)                  # vtable[0]: not read
        return x + 4

    def obj(self, h, k, cd=0):
        """A complete object of h, and the pointer to its sub-object for base k (its vfptr is the vtable there)."""
        complete = self.block(0x40)
        mdisp = h["spec"][k][2]
        inptr = complete + mdisp
        self.e.wr32(inptr, self.vtable(h, mdisp, cd))
        return inptr


def _rt_prep(e, args, init, ef):
    """The state before a call: the window around esp filled with 0xcc, the arguments at P, esp = P."""
    e.wr(RT_WIN_LO, b"\xcc" * (RT_WIN_HI - RT_WIN_LO))
    for i, a in enumerate(args):
        e.wr32(RT_FRAME + 4 * i, a)
    for name, v in zip(RT_GPRS, init):
        e.uc.reg_write(GPR_UC[name], v)
    e.uc.reg_write(UC_X86_REG_EFLAGS, ef)


GPR_UC = dict(eax=UC_X86_REG_EAX, ecx=UC_X86_REG_ECX, edx=UC_X86_REG_EDX, ebx=UC_X86_REG_EBX, esp=UC_X86_REG_ESP,
              ebp=UC_X86_REG_EBP, esi=UC_X86_REG_ESI, edi=UC_X86_REG_EDI)


def _rt_emu_state(e):
    """Registers, the six flags, the x87 state and the window, as the emulator holds them."""
    r = _regs(e)
    ef = r["eflags"]
    gpr = {k: r[k] for k in RT_GPRS}
    flags = ((ef & 1), (ef >> 2) & 1, (ef >> 4) & 1, (ef >> 6) & 1, (ef >> 7) & 1, (ef >> 11) & 1)
    fp = {k: r[k] for k in r if k.startswith("fp")}
    return gpr, flags, fp, bytes(e.rd(RT_WIN_LO, RT_WIN_HI - RT_WIN_LO))


def _rt_emulated(e, args, init, ef):
    """The emulated call from the prepared state: (eax, state)."""
    _rt_prep(e, args, init, ef)
    eax = e.call(RT_VA, cc="cdecl")
    assert not e.fatal, e.fatal
    return eax, _rt_emu_state(e)


def _rt_check(e, n, args, init, ef, expect, ctx):
    """expect "handled": the helper returns 1 and the emulated call and the helper agree on eax, every GPR, the six
    flags, the x87 state and the window. expect "declined": the helper returns 0 and the state is the one it was."""
    if expect == "declined":
        _rt_prep(e, args, init, ef)
        before = _rt_emu_state(e)
        cpu = CPU()
        n.uc_to_cpu(cpu)
        assert n.lib.lift_crt_call(ctypes.byref(cpu), RT_VA, mpemu.STUB_BASE) == 0, (ctx, "handled, not declined")
        assert _rt_emu_state(e) == before, (ctx, "a declined call changed the state")
        return None
    eax, emu = _rt_emulated(e, args, init, ef)
    _rt_prep(e, args, init, ef)
    cpu = CPU()
    n.uc_to_cpu(cpu)
    fp_pre = (cpu.top, cpu.tag, list(cpu.st), cpu.cw, cpu.sw)
    assert n.lib.lift_crt_call(ctypes.byref(cpu), RT_VA, mpemu.STUB_BASE) == 1, (ctx, "declined, not handled")
    gpr = {k: cpu.r[i] for i, k in enumerate(RT_GPRS)}
    assert gpr == emu[0], (ctx, [(k, hex(gpr[k]), hex(emu[0][k])) for k in RT_GPRS if gpr[k] != emu[0][k]])
    assert cpu.r[0] == eax, (ctx, hex(cpu.r[0]), hex(eax))
    flags = (cpu.cf, cpu.pf, cpu.af, cpu.zf, cpu.sf, cpu.of)
    assert flags == emu[1], (ctx, flags, emu[1])
    assert (cpu.top, cpu.tag, list(cpu.st), cpu.cw, cpu.sw) == fp_pre, (ctx, "x87 state changed")
    mem = bytes(e.rd(RT_WIN_LO, RT_WIN_HI - RT_WIN_LO))
    assert mem == emu[3], (ctx, [i for i in range(len(mem)) if mem[i] != emu[3][i]][:8])
    return eax


def test_crt_rtdynamiccast():
    """Native __RTDynamicCast (lift/runtime/crt.c) against MSVCRT.DLL's own code, on synthetic RTTI in the guest heap:
    single inheritance (a chain; a base whose attributes bit 0 is set, which the search skips; a base with bits 0 and 1
    set), multiple inheritance (two bases; a class with contained bases, and attribute bits in its second search), type
    names at every alignment, and duplicate type descriptors (strcmp, not pointer equality). Each sub-object is cast to
    every target type, with the static type as SrcType and with a random one, with isReference 0 and 1, and VfDelta 0 or
    another value; NULL too. A failing cast with isReference != 0 is declined (the guest throws bad_cast) and changes
    nothing. Agreement: eax, every GPR, the six flags, the x87 state, and the 0x100 bytes below esp and 0x20 above it."""
    e, n = new_emu()
    if _map_msvcrt(e) is None:
        print("  skipped: game folder not found (MSVCRT.DLL)")
        return
    _set_regions(e, n)
    _bind_rt(n, True)
    try:
        _rt_dyncast_cases(e, n)
    finally:
        _bind_rt(n, False)


def _rt_dyncast_cases(e, n):
    rng = random.Random(25)
    rt = _Rtti(e, rng)
    hs = [
        rt.hier([b".?AVC0@@", b".?AVC1@@", b".?AVC2@@"], [(0, 2, 0, 0), (1, 1, 4, 0), (2, 0, 8, 0)], 0),
        rt.hier([b".?AVD@@", b".?AVA@@", b".?AVB@@"], [(0, 2, 0, 0), (1, 0, 0, 0), (2, 0, 8, 0)], 1),
        rt.hier([b".?AVX@@", b".?AVY@@", b".?AVQ@@", b".?AVZ@@", b".?AVW@@"],
                [(0, 4, 0, 0), (1, 1, 0, 0), (2, 0, 4, 0), (3, 0, 8, 0), (4, 0, 12, 0)], 1),
        rt.hier([b".?AVE@@", b".?AVF@@", b".?AVG@@"], [(0, 2, 0, 0), (1, 1, 4, 1), (2, 0, 8, 3)], 0),
        rt.hier([b".?AVH@@", b".?AVI@@", b".?AVJ@@", b".?AVK@@"],
                [(0, 3, 0, 0), (1, 1, 0, 2), (2, 0, 4, 0), (3, 0, 8, 1)], 1),
    ]
    targets = []
    for h in hs:
        targets += h["tds"]
        targets += [rt.td(nm) for nm in h["names"]]     # duplicates: the same name at another address
    targets.append(rt.td(b".?AVNope@@"))                # unrelated
    all_tds = list(targets)

    def fresh():
        init = [rng.getrandbits(32) for _ in range(8)]
        init[4] = RT_FRAME
        return init, 0x202 | (rng.getrandbits(32) & 0x8d5)

    handled = declined = fails = succs = 0
    for tgt in targets[:4]:                              # NULL reads nothing
        for isref in (0, 1):
            init, ef = fresh()
            _rt_check(e, n, (0, 0, 0, tgt, isref), init, ef, "handled", ("null", isref))
            handled += 1
    for h in hs:
        for k in range(len(h["spec"])):
            inptr = rt.obj(h, k)
            static_src = h["tds"][h["spec"][k][0]]
            for tgt in targets:
                cases = [(static_src, 0, 0), (static_src, 0, 1)]
                src = rng.choice(all_tds)
                vfd = 0 if rng.random() < 0.8 else rng.choice([4, 8, 0xfffffffc])
                cases.append((src, vfd, rng.randrange(2)))
                for src, vfd, isref in cases:
                    args = (inptr, vfd, src, tgt, isref)
                    init, ef = fresh()
                    if isref:
                        # a failing cast with isReference != 0 is the bad_cast path: decided on the isReference-0 answer
                        init0, ef0 = list(init), ef
                        base_eax, _ = _rt_emulated(e, (inptr, vfd, src, tgt, 0), init0, ef0)
                        if base_eax == 0:
                            _rt_check(e, n, args, init, ef, "declined", ("bad", k, tgt))
                            declined += 1
                            continue
                    eax = _rt_check(e, n, args, init, ef, "handled", ("case", k, tgt, src, vfd, isref))
                    handled += 1
                    fails += eax == 0
                    succs += eax != 0
    print("  %d casts handled and %d declined (failing, isReference != 0): native and the real MSVCRT.DLL agree "
          "(eax, GPRs, flags, x87, stack and memory); %d failing, %d succeeding" % (handled, declined, fails, succs))
    assert succs > 0 and fails > 0 and declined > 0


def test_crt_rtdynamiccast_declines():
    """The shapes the helper leaves to the guest return 0 with the state unchanged: a vbtable (cdOffset != 0), a
    virtual base (a BCD with pdisp >= 0), virtual inheritance (CHD attributes bit 1), a failing cast with
    isReference != 0 (bad_cast), an inptr outside the mapped regions, and a vtable or COL outside them. Each has a
    control in the same hierarchy shape without the flaw, which the helper handles (and agrees with the emulator on)."""
    e, n = new_emu()
    if _map_msvcrt(e) is None:
        print("  skipped: game folder not found (MSVCRT.DLL)")
        return
    _set_regions(e, n)
    _bind_rt(n, True)
    try:
        _rt_decline_cases(e, n)
    finally:
        _bind_rt(n, False)


def _rt_decline_cases(e, n):
    rng = random.Random(26)
    rt = _Rtti(e, rng)

    def fresh():
        init = [rng.getrandbits(32) for _ in range(8)]
        init[4] = RT_FRAME
        return init, 0x202 | (rng.getrandbits(32) & 0x8d5)

    plain = rt.hier([b".?AVP0@@", b".?AVP1@@"], [(0, 1, 0, 0), (1, 0, 4, 0)], 0)
    virt_base = rt.hier([b".?AVV0@@", b".?AVV1@@"], [(0, 1, 0, 0), (1, 0, 4, 0, 0)], 0)   # pdisp 0: virtual
    plain_pd = rt.hier([b".?AVV0@@", b".?AVV1@@"], [(0, 1, 0, 0), (1, 0, 4, 0, -1)], 0)
    virt_inh = rt.hier([b".?AVI0@@", b".?AVI1@@"], [(0, 0, 0, 0)], 2)
    virt_inh3 = rt.hier([b".?AVJ0@@", b".?AVJ1@@"], [(0, 0, 0, 0)], 3)
    plain_inh = rt.hier([b".?AVK0@@", b".?AVK1@@"], [(0, 0, 0, 0)], 0)
    unrelated = rt.td(b".?AVNope@@")
    checks = 0

    def run(expect, inptr, vfd, src, tgt, isref, ctx):
        nonlocal checks
        init, ef = fresh()
        _rt_check(e, n, (inptr, vfd, src, tgt, isref), init, ef, expect, ctx)
        checks += 1

    # control: a plain sub-object cast to its base
    run("handled", rt.obj(plain, 1), 0, plain["tds"][1], plain["tds"][0], 0, "plain")
    run("handled", rt.obj(plain_pd, 1), 0, plain_pd["tds"][1], plain_pd["tds"][0], 0, "plain pdisp -1")
    run("handled", rt.obj(plain_inh, 0), 0, plain_inh["tds"][0], plain_inh["tds"][0], 0, "plain inh")
    # a vbtable: cdOffset != 0 in the COL
    run("declined", rt.obj(plain, 1, cd=4), 0, plain["tds"][1], plain["tds"][0], 0, "cdOffset")
    # a virtual base: the BCD of the target has pdisp >= 0
    run("declined", rt.obj(virt_base, 0), 0, virt_base["tds"][1], virt_base["tds"][1], 0, "virtual base")
    run("handled", rt.obj(plain_pd, 0), 0, plain_pd["tds"][0], plain_pd["tds"][1], 0, "pdisp -1 target")
    # virtual inheritance (CHD attributes bit 1)
    run("declined", rt.obj(virt_inh, 0), 0, virt_inh["tds"][0], virt_inh["tds"][0], 0, "virtual inheritance")
    run("declined", rt.obj(virt_inh3, 0), 0, virt_inh3["tds"][0], virt_inh3["tds"][0], 0, "virtual inheritance 3")
    # a failing cast: isReference 0 returns NULL (handled), isReference != 0 throws bad_cast (declined)
    run("handled", rt.obj(plain, 0), 0, plain["tds"][0], unrelated, 0, "failing, isReference 0")
    run("declined", rt.obj(plain, 0), 0, plain["tds"][0], unrelated, 1, "failing, isReference 1")
    # memory outside the regions the emulator maps: the inptr, its vtable, its COL
    unmapped = 0x60000000                      # above the heap (0x20000000..0x40000000), below STUB_BASE
    assert not _mapped(e, unmapped)
    run("declined", unmapped, 0, plain["tds"][0], plain["tds"][0], 0, "inptr unmapped")
    vt_bad = rt.block(8)
    e.wr32(vt_bad, unmapped + 8)                       # the vtable: vtable-4 is unmapped
    run("declined", vt_bad, 0, plain["tds"][0], plain["tds"][0], 0, "vtable unmapped")
    col_bad = rt.block(16)
    e.wr32(col_bad, unmapped)                          # vtable-4 for the vtable at col_bad+4: the COL pointer, unmapped
    e.wr32(col_bad + 8, col_bad + 4)                   # the object's vfptr
    run("declined", col_bad + 8, 0, plain["tds"][0], plain["tds"][0], 0, "COL unmapped")
    print("  %d shapes: handled where the guest path is reproduced, declined (unchanged state) otherwise" % checks)


def test_crt_rtdyn_bind_refuses_mismatch():
    """Native.CRT_HELPERS binds __RTDynamicCast only when the guest bytes of every range are the ones crt.c
    reproduces: a changed byte at the start, middle or end of any range leaves it unbound (lift_crt_call declines)."""
    e, n = new_emu()
    if _map_msvcrt(e) is None:
        print("  skipped: game folder not found (MSVCRT.DLL)")
        return
    import native as nat_mod
    fake_mod = types.SimpleNamespace(name="MSVCRT.DLL", base=CRT_BASE, exports={"__RTDynamicCast": RT_VA})
    fake_e = types.SimpleNamespace(modules={0: fake_mod}, rd=e.rd, regions=e.regions)
    host = types.SimpleNamespace(e=fake_e, lib=n.lib)
    ranges = nat_mod.CRT_HELPERS[("msvcrt.dll", "__RTDynamicCast")]

    def bind():
        n.lib.lift_crt_bind(b"__RTDynamicCast", 0, 0)
        return nat_mod.Native._bind_crt(host)

    try:
        assert "__RTDynamicCast" in bind()
        for rva, h in ranges:
            assert bytes(e.rd(CRT_BASE + rva, len(h) // 2)).hex() == h
        flips = 0
        for rva, h in ranges:
            size = len(h) // 2
            for off in (0, size // 2, size - 1):
                va = CRT_BASE + rva + off
                orig = bytes(e.rd(va, 1))
                e.wr(va, bytes([orig[0] ^ 0x01]))
                assert "__RTDynamicCast" not in bind(), (hex(rva), off)
                cpu = CPU()
                n.uc_to_cpu(cpu)
                assert n.lib.lift_crt_call(ctypes.byref(cpu), RT_VA, mpemu.STUB_BASE) == 0, (hex(rva), off)
                e.wr(va, orig)
                flips += 1
        assert "__RTDynamicCast" in bind()
        print("  binding: a changed byte in any of the %d ranges (%d flips) leaves __RTDynamicCast unbound"
              % (len(ranges), flips))
    finally:
        n.lib.lift_crt_bind(b"__RTDynamicCast", 0, 0)


def test_rounding_control():
    """fldcw in lifted code rounds the host's arithmetic the way x87 would (all four modes, same bits as the
    emulator), and the host is back to round-to-nearest once the native call returns."""
    e, n = new_emu()
    assert n.flags[F["rdiv"]]
    libc = ctypes.CDLL(None)
    out, data = e.alloc(8), e.alloc(32)
    got = {}
    for cw in (0x027F, 0x067F, 0x0A7F, 0x0E7F):        # nearest, down, up, toward zero
        e.wr(data, struct.pack("<H6xdd", cw, 2.0, 3.0))
        e.call(F["rdiv"], out, data, cc="cdecl")
        emu = e.rd(out, 8)
        _call_native(e, n, "rdiv", out, data, cc="cdecl")
        nat = e.rd(out, 8)
        assert emu == nat, (hex(cw), emu.hex(), nat.hex())
        got[cw] = nat
        assert libc.fegetround() == 0, "host rounding left at %d after the native call" % libc.fegetround()
    assert got[0x027F] == got[0x067F] == got[0x0E7F] != got[0x0A7F], {hex(k): v.hex() for k, v in got.items()}
    print("  2/3 (rounds down at 53 bits, so only round-up differs): native matches the emulator; host back to nearest")


def test_real_dll_mmx_status():
    """R_Memory::set and R_Memory::copy (rlmfc.dll) have MMX paths. Report whether this tree can lift them: they
    use integer ALU and x87 instructions that have no handlers here, so the real-DLL MMX comparison waits for
    those families. The MMX forms they use are covered by test_mmx_native_matches_emulated."""
    rlmfc = os.path.join(GAME, "rlmfc.dll")
    if not os.path.exists(rlmfc):
        print("  skipped: game folder not found (%s)" % GAME)
        return
    img = x86c.PEImage(rlmfc)
    for name, va in (("R_Memory::set", 0x10016610), ("R_Memory::copy", 0x10016730)):
        res = x86c.lift_function(img, va, frozenset([va]))
        if res.ok:
            print("  %s lifts: the real-DLL MMX comparison can be added" % name)
        else:
            blockers = sorted({text.split()[0] for _, text in res.unsupported})
            print("  %s not lifted yet (no handler for: %s)" % (name, " ".join(blockers)))


def test_real_dll_mmx_flags():
    """The R_Memory set/copy MMX paths, wherever they are, must get the FPU flag (they contain movq and emms)."""
    rlmfc = os.path.join(GAME, "rlmfc.dll")
    if not os.path.exists(rlmfc):
        return
    img = x86c.PEImage(rlmfc)
    for va in (0x10016610, 0x10016730):
        assert liftbuild.fpu_flags(img, [va])[va], hex(va)


def _entries_of(functions):
    """native.function_entries on an inventory made of the given function records."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"functions": functions}, fh)
    try:
        return function_entries(fh.name)
    finally:
        os.unlink(fh.name)


def test_function_entries_overlap():
    # 5 patched bytes at an entry must not overlap another function's code; a function's own blocks never exclude it.
    fn = lambda entry, *blocks: {"entry": entry, "gap_scan": False,
                                 "blocks": [{"start": s, "end": e} for s, e in blocks]}
    # entries without blocks are only ever excluded by another function's span (their own code is not a span here)
    got = _entries_of([
        fn("0x1000", ("0x1000", "0x1010")),
        fn("0x1004"),                              # inside 0x1000's block: excluded
        fn("0x0ffc"),                              # 0x1000 < 0x0ffc + 5: its 5 bytes reach the block: excluded
        fn("0x0ffb"),                              # 0x0ffb + 5 == 0x1000: ends right before the block: kept
        fn("0x1010"),                              # exactly at 0x1010, the block end: kept
        fn("0x2000", ("0x2000", "0x2020")),        # covered only by its own blocks: kept
        fn("0x2ff8", ("0x2ff8", "0x3002")),        # its own block overlaps 0x3000's block: kept (no other owner hits it)
        fn("0x3000", ("0x3000", "0x3100")),        # its own block is overlapped by 0x2ff8's: excluded
        fn("0x3010"),                              # inside 0x3000's block: excluded
    ])
    assert got == {0x1000, 0x0ffb, 0x1010, 0x2000, 0x2ff8}, sorted(hex(x) for x in got)
    # randomized agreement with the direct definition (any span with lo < va + 5 < hi+5 and owner != va)
    rng = random.Random(7)
    for _ in range(300):
        entries = sorted(rng.sample(range(0x1000, 0x1400), rng.randint(1, 25)))
        funcs = []
        for e in entries:
            blocks = []
            for _ in range(rng.randint(0, 3)):
                lo = rng.randint(0x0F80, 0x1420)
                blocks.append((lo, lo + rng.randint(1, 40)))
            funcs.append(fn(hex(e), *blocks))
        spans = [(b["start"], b["end"], int(f["entry"], 16))
                 for f in funcs for b in f["blocks"]]
        want = {va for va in entries
                if not any(lo < va + 5 and va < hi and owner != va for lo, hi, owner in spans)}
        assert _entries_of(funcs) == want, (entries, sorted(hex(x) for x in want))


# ---------------------------------------------------------------- deferred modules (native.LiftLoader, load hook)
LOAD_STR = 0x00B00000            # a scratch page holding LoadLibraryA's name argument


def _synthetic_inventory(name="synthetic.dll", base=SYN):
    """A function inventory (lift/functions.py format) of the synthetic module's lifted functions."""
    os.makedirs(BUILD, exist_ok=True)
    path = os.path.join(BUILD, "inv_%s.json" % name.replace(".", "_"))
    funcs = [{"entry": "0x%08x" % F[n], "name": n} for n in LIFTED]
    with open(path, "w") as fh:
        json.dump({"module": name, "base": "0x%x" % base, "functions": funcs}, fh)
    return path


def _fake_module(name, base, entry=0):
    """An mpemu.Module with only the header fields the loader and load_library read."""
    pe = types.SimpleNamespace(OPTIONAL_HEADER=types.SimpleNamespace(SizeOfImage=SYN_SIZE, AddressOfEntryPoint=entry))
    return mpemu.Module(name, name, base, pe, b"")


def _lift_mode():
    return "fast" if MODE[0] == "fast" else "slow"


def test_deferred_module():
    """A module the game loads later: LiftLoader defers it; LoadLibraryA (mpemu.load_library) maps it, runs the load
    hook before DllMain (the entries are patched when DllMain is entered), and the lifted functions then dispatch
    natively. A second LoadLibraryA of the module does not run the hook again."""
    global _LIB
    if _LIB is None:
        _LIB = build_synthetic()
    e = mpemu.Emu(".")
    e.map(LOAD_STR, 0x1000)
    e.wr(LOAD_STR, b"synthetic.dll\x00")
    n = Native(e, _LIB)
    loader = LiftLoader(n, _lift_mode())
    inv = _synthetic_inventory()
    loader.add(inv)                                   # not loaded: deferred
    assert loader.count == 0 and list(loader.deferred) == ["synthetic.dll"], loader.deferred
    assert n.installed == {}

    def fake_load_module(rel, base=None):             # the image mapping of Emu.load_module, from the test's code
        e.map(SYN, SYN_SIZE)
        for va, b in _blob().items():
            e.wr(va, b)
        e.wr32(SLOT, e.stub_for("KERNEL32.DLL", "GetCurrentThreadId"))
        mod = _fake_module("synthetic.dll", SYN, entry=F["leaf_1"] - SYN)     # DllMain: a guest call (not run here)
        e.modules[mod.name] = mod
        return mod

    e.load_module = fake_load_module
    e.resolve_imports = lambda mod: None
    old_read_path = mpemu.host_read_path
    mpemu.host_read_path = lambda e_, raw: inv        # the DLL "exists" in the game folder
    try:
        gen = mpemu.load_library(e, LOAD_STR)
        step = next(gen)                              # stops at the DllMain call
        assert isinstance(step, mpemu.GuestCall), step
        for name in LIFTED:
            assert bytes(e.rd(F[name], 1)) == b"\xe9", "%s not patched before DllMain" % name
        assert loader.count == len(LIFTED) and not loader.deferred, loader.count
        try:
            gen.send(1)
            raise AssertionError("LoadLibraryA did not return")
        except StopIteration as stop:
            assert stop.value == SYN, hex(stop.value)
        before = n.calls
        assert e.call(F["leaf_s"], 3, 4, cc="stdcall") == 3 + 2 * 4 + 5
        assert n.calls == before + 1, (before, n.calls)
        assert e.call(F["leaf_1"], 5, cc="cdecl") == 2 * 5 + 1
        cnt = loader.count
        try:
            next(mpemu.load_library(e, LOAD_STR))    # already loaded: returns the base, no hook
            raise AssertionError("second LoadLibraryA ran the load path")
        except StopIteration as stop:
            assert stop.value == SYN, hex(stop.value)
        assert loader.count == cnt
    finally:
        mpemu.host_read_path = old_read_path


def test_deferred_module_base_refused():
    """The module is loaded at another base than the one the library was lifted for: refused, nothing installed."""
    global _LIB
    if _LIB is None:
        _LIB = build_synthetic()
    e = mpemu.Emu(".")
    n = Native(e, _LIB)
    loader = LiftLoader(n, _lift_mode())
    loader.add(_synthetic_inventory())
    try:
        loader.on_loaded(_fake_module("synthetic.dll", SYN + 0x10000))
        raise AssertionError("a module at another base was accepted")
    except NativeError as ex:
        assert "lifted for 0x%08x" % SYN in str(ex), str(ex)
    assert loader.count == 0 and n.installed == {}


def test_deferred_never_loaded():
    global _LIB
    if _LIB is None:
        _LIB = build_synthetic()
    e = mpemu.Emu(".")
    n = Native(e, _LIB)
    loader = LiftLoader(n, "slow")
    loader.add(_synthetic_inventory("gone.dll"))
    loader.add(_synthetic_inventory("gone2.dll"))
    assert loader.finish() == ["gone.dll", "gone2.dll"]
    assert loader.count == 0


def test_fast_install_twice():
    """install_fast may be called again later: slots go on from where they stopped, a va already installed is
    skipped, and the earlier entries still dispatch."""
    e, n = new_emu()
    n.install_fast([F["leaf_s"]])
    slot = n._fast_slot[F["leaf_s"]]
    n.install_fast([F["leaf_1"], F["leaf_s"]])
    assert n._fast_slot[F["leaf_s"]] == slot and len(set(n._fast_slot.values())) == 2, n._fast_slot
    assert len(n.installed) == 2
    assert e.call(F["leaf_s"], 3, 4, cc="stdcall") == 16
    assert e.call(F["leaf_1"], 5, cc="cdecl") == 11
    n.install_fast([F["leaf_1"]])
    assert len(n.installed) == 2


MATH_RVA = {"?name@type_info@@QBEPBDXZ": 0xb20f, "floor": 0x2bbf0, "_CIfmod": 0x28d47}
MATH_P = mpemu.STACK_TOP - 0x800                # esp at the call
MATH_LO, MATH_HI = MATH_P - 0x300, MATH_P + 0x20   # _CIfmod's frame reaches esp - 0x2e0


def test_crt_math_helpers():
    """Native type_info::name, floor and _CIfmod (lift/runtime/crt.c) against the real MSVCRT.DLL's code, from the
    same state: every GPR, the six flags, the x87 state (registers, top, tags, control and status words) and the
    stack from 0x300 below esp to 0x20 above it. floor: integers, fractions of both signs, -0, subnormals, values
    past 2^52, under several control words, and with the precision exception unmasked (an inexact result is
    declined). _CIfmod: exponent gaps from negative to over 1000 (qemu's partial-remainder loop), signs, subnormals,
    equal and integer-multiple operands, both settings of [0x78039298]; a zero, infinite, NaN or empty operand, a
    pending unmasked precision exception and the P5 workaround are declined and change nothing.
    type_info::name: a cached name; an uncached one is declined."""
    e, n = new_emu()
    if _map_msvcrt(e) is None:
        print("  skipped: game folder not found (MSVCRT.DLL)")
        return
    rng = random.Random(31)
    libc = ctypes.CDLL(None)
    obj = e.alloc(0x20)

    def bind(on):
        for fn, rva in MATH_RVA.items():
            assert n.lib.lift_crt_bind(fn.encode(), CRT_BASE + rva if on else 0, CRT_BASE if on else 0) >= 0

    def prep(fp, arg, ecx=None):
        """fp: (top, tag, {i: value}, cw, sw) with st(i) values. Returns the snapshot of the prepared state."""
        e.wr(MATH_LO, bytes(rng.getrandbits(8) for _ in range(MATH_HI - MATH_LO)))
        if arg is not None:
            e.wr(MATH_P, struct.pack("<d", arg))
        cpu = CPU()
        n.uc_to_cpu(cpu)
        for i in range(8):
            cpu.r[i] = rng.getrandbits(32)
        cpu.r[4] = MATH_P
        if ecx is not None:
            cpu.r[1] = ecx
        cpu.cf, cpu.pf, cpu.af, cpu.zf, cpu.sf, cpu.of = (rng.getrandbits(1) for _ in range(6))
        top, tag, vals, cw, sw = fp
        cpu.top, cpu.tag, cpu.cw, cpu.sw = top, tag, cw, sw
        for p in range(8):
            cpu.st[p] = rng.uniform(-9, 9)
        for i, v in vals.items():
            cpu.st[(top + i) & 7] = v
        n.cpu_to_uc(cpu)
        return _regs(e), bytes(e.rd(MATH_LO, MATH_HI - MATH_LO))

    def state():
        r = _regs(e)
        ef = r.pop("eflags")
        r["flags"] = ((ef & 1), (ef >> 2) & 1, (ef >> 4) & 1, (ef >> 6) & 1, (ef >> 7) & 1, (ef >> 11) & 1)
        for p in range(8):           # an empty register's raw bits are not state the bridge keeps
            if (r["fptag"] >> (2 * p)) & 3 == 3:
                r["fp%d" % p] = "empty"
        return r, bytes(e.rd(MATH_LO, MATH_HI - MATH_LO))

    def restore(snap):
        regs, mem = snap
        for k, rid in GPR_UC.items():
            e.uc.reg_write(rid, regs[k])
        e.uc.reg_write(UC_X86_REG_EFLAGS, regs["eflags"])
        e.uc.reg_write(UC_X86_REG_FPCW, regs["fpcw"])
        e.uc.reg_write(UC_X86_REG_FPSW, regs["fpsw"])
        e.uc.reg_write(UC_X86_REG_FPTAG, regs["fptag"])
        for p in range(8):
            e.uc.reg_write(UC_X86_REG_FP0 + p, regs["fp%d" % p])
        e.wr(MATH_LO, mem)

    def native(fn):
        cpu = CPU()
        n.uc_to_cpu(cpu)
        ok = n.lib.lift_crt_call(ctypes.byref(cpu), CRT_BASE + MATH_RVA[fn], mpemu.STUB_BASE)
        libc.fesetround(0)           # the runtime's return to the emulator: the host rounds to nearest again
        if ok:
            n.cpu_to_uc(cpu)
        return ok

    def check(fn, fp, arg=None, ecx=None):
        snap = prep(fp, arg, ecx)
        e.call(CRT_BASE + MATH_RVA[fn])
        assert not e.fatal, (fn, e.fatal)
        emu = state()
        restore(snap)
        assert native(fn) == 1, (fn, "declined", fp, arg)
        nat = state()
        ctx = (fn, arg, fp)
        diff = [(k, emu[0][k], nat[0][k]) for k in emu[0] if emu[0][k] != nat[0][k]]
        assert not diff, (ctx, diff)
        assert emu[1] == nat[1], (ctx, [hex(MATH_LO + i) for i in range(len(emu[1])) if emu[1][i] != nat[1][i]][:8])

    def declined(fn, fp, arg=None, ecx=None):
        snap = prep(fp, arg, ecx)
        before = state()
        assert native(fn) == 0, (fn, "handled", fp, arg)
        assert state() == before, (fn, "a declined call changed the state")

    cases = 0
    bind(True)
    try:
        # type_info::name
        for v in (0x12345678, 0x80000000, 1):
            e.wr32(obj + 4, v)
            check("?name@type_info@@QBEPBDXZ", (0, 0xff, {}, 0x027f, 0), ecx=obj)
            cases += 1
        e.wr32(obj + 4, 0)
        declined("?name@type_info@@QBEPBDXZ", (0, 0xff, {}, 0x027f, 0), ecx=obj)
        # floor
        vals = [0.0, -0.0, 0.5, -0.5, 1.0, -1.0, 1.5, -1.5, 2.5, -2.5, 3.0, 1e-300, -1e-300, 5e-324, -5e-324,
                2.0 ** 52 + 0.5, -(2.0 ** 52) - 0.5, 2.0 ** 53, 1e300, -1e300, 4503599627370495.5, -0.9999999999999999]
        vals += [rng.uniform(-1, 1) * 2.0 ** rng.randint(-30, 60) for _ in range(80)]
        for cw in (0x027f, 0x037f, 0x0e7f, 0x007f, 0x127f):
            for v in vals:
                top = rng.randrange(8)
                tag = 0xff & ~(1 << ((top + 1) & 7))
                check("floor", (top, tag, {1: rng.uniform(-5, 5)}, cw, rng.getrandbits(16) & 0x477f), v)
                cases += 1
        for v in (0.0, -3.0, 2.0 ** 60, -1e300):            # PM clear: exact results are handled
            check("floor", (0, 0xff, {}, 0x025f, 0), v)
            cases += 1
        inf = float("inf")
        for v in (0.5, -1.5, inf, -inf, float("nan")):
            declined("floor", (0, 0xff, {}, 0x025f if abs(v) < inf else 0x027f, 0), v)
        # _CIfmod: ST1 = x, ST0 = y
        pairs = [(5.5, 2.0), (-5.5, 2.0), (5.5, -2.0), (-5.5, -2.0), (1.0, 3.0), (6.0, 3.0), (2.0 ** 1000, 3.0),
                 (-(2.0 ** 1023), 1e-300), (1e300, 7.0), (3.0, 3.0), (5e-324, 3e-324), (1e-310, 3e-320),
                 (2.0 ** 60 + 1e4, 0.1), (123456.789, 0.001), (1.0, 2.0 ** -1074), (7.0, 7.000000000000001),
                 (0.0, 3.0), (-0.0, 3.0), (0.0, -1e-310), (-0.0, -2.0 ** 1000)]
        for _ in range(250):
            x = rng.uniform(-1, 1) * 2.0 ** rng.randint(-60, 1023)
            y = rng.uniform(-1, 1) * 2.0 ** rng.randint(-1074, 300)
            if x and y:
                pairs.append((x, y))
        flag = CRT_BASE + 0x39298
        orig = e.rd32(flag)
        for k, (x, y) in enumerate(pairs):
            e.wr32(flag, 0 if k % 3 == 0 else orig)
            top = rng.randrange(8)
            tag = 0xff & ~((1 << top) | (1 << ((top + 1) & 7)))
            cw = (0x027f, 0x037f, 0x0e7f, 0x007f, 0x025f)[k % 5]
            sw = rng.getrandbits(16) & (0x475f if cw == 0x025f else 0x477f)
            check("_CIfmod", (top, tag, {0: y, 1: x}, cw, sw))
            cases += 1
        e.wr32(flag, orig)
        nan, inf = float("nan"), float("inf")
        for x, y, cw, sw, tag in ((1.0, 0.0, 0x027f, 0, 0xfc), (inf, 2.0, 0x027f, 0, 0xfc), (1.0, inf, 0x027f, 0, 0xfc),
                                  (nan, 2.0, 0x027f, 0, 0xfc), (0.0, 0.0, 0x027f, 0, 0xfc), (1.0, 2.0, 0x027f, 0, 0xfd),
                                  (1.0, 2.0, 0x027f, 0, 0xfe), (1.0, 2.0, 0x025f, 0x20, 0xfc)):
            declined("_CIfmod", (0, tag, {0: y, 1: x}, cw, sw))
        p5 = CRT_BASE + 0x37c0c
        old = e.rd32(p5)
        e.wr32(p5, 1)
        declined("_CIfmod", (0, 0xfc, {0: 2.0, 1: 5.0}, 0x027f, 0))
        e.wr32(p5, old)
    finally:
        bind(False)
    print("  %d calls: native and the real MSVCRT.DLL agree (GPRs, flags, x87, stack)" % cases)


def test_thunk_shortcut():
    """A call or tail jump through an import thunk (`jmp [slot]`, never lifted) from lifted code reaches the slot's target
    directly (runtime.c thunk_resolve), and leaves what the emulated call leaves: GPRs, flags, x87 state and the stack
    below esp. A lifted target runs natively with no guest call, the CRT helper runs natively, an HLE stub and emulated
    guest code stay guest calls, and a two-thunk chain resolves. With lift_thunk_shortcut(0) the lifted and CRT cases are
    guest calls again. Thunk bytes or slots outside the mapped regions fall back to the guest call, which faults the way
    the emulated call does."""
    e, n = new_emu()
    _map_crt(e)
    data = e.alloc(16)
    e.wr(data, struct.pack("<H6xd", 0x027F, 2.75))
    n.sync_regions()                      # the CRT copy and the data were mapped after Native was created
    drives = [0]                          # host-side emulator runs: the top-level call of each case is one
    drive0 = e._drive

    def counted(*a, **k):
        drives[0] += 1
        return drive0(*a, **k)
    e._drive = counted
    snap = _regs(e)

    def case_run(fn, args, cc, cells, native, shortcut=True):
        """(outcome, nested guest calls, _ftol helper calls) of one run of fn, with the vtable cells set first."""
        for a, v in cells:
            e.wr32(a, v)
        _restore(e, snap)
        e.wr(mpemu.STACK_TOP - 0x1000, b"\xcc" * 0x1000)
        n.lib.lift_thunk_shortcut(int(shortcut))
        crt0 = _crt_counts(n).get("_ftol", 0)
        try:
            if native:
                _install(n, F[fn])
            g0, d0 = (n.fast_stats()["guest_calls"] if MODE[0] == "fast" else 0), drives[0]
            err = None
            try:
                r = e.call(F[fn], *args, cc=cc)
                err = e.fatal
            except NativeError as ex:
                err = str(ex) or "stopped"
            g1, d1 = (n.fast_stats()["guest_calls"] if MODE[0] == "fast" else 0), drives[0]
            nested = (g1 - g0) if MODE[0] == "fast" else (d1 - d0 - 1)
        finally:
            if native:
                n.uninstall(F[fn])
            n.lib.lift_thunk_shortcut(1)
        crt = _crt_counts(n).get("_ftol", 0) - crt0
        if err:
            return ("fatal",), nested, crt
        sp = e.uc.reg_read(UC_X86_REG_ESP)
        regs = _regs(e)
        for p in range(8):
            if (regs["fptag"] >> (2 * p)) & 3 == 3:
                regs["fp%d" % p] = "empty"
        return ("ok", r, regs, bytes(e.rd(sp - 0x40, 0x40))), nested, crt

    # (label, lifted caller, args, cc, vtable cells, path). "lifted" and "crt" are the calls the shortcut makes native;
    # "guest" stays a guest call either way.
    cases = [
        ("call -> lifted leaf", "vt_c", (), "cdecl", [(VT_C, F["thk_l"]), (CELL_L, F["leaf_1"])], "lifted"),
        ("tail jump -> lifted leaf", "vt_j", (5,), "cdecl", [(VT_J, F["thk_l"]), (CELL_L, F["leaf_1"])], "lifted"),
        ("two-thunk chain -> lifted leaf", "vt_c", (), "cdecl",
         [(VT_C, F["thk_ch2"]), (CELL_CH, F["thk_l"]), (CELL_L, F["leaf_1"])], "lifted"),
        ("slot -> HLE stub", "vt_c", (), "cdecl", [(VT_C, F["thk_hle"])], "guest"),
        ("slot -> emulated guest code", "vt_c", (), "cdecl", [(VT_C, F["thk_g"]), (CELL_G, F["helper"])], "guest"),
        ("call -> CRT _ftol", "vt_f", (data,), "cdecl", [(VT_F, F["thk_crt"])], "crt"),
        ("tail jump -> CRT _ftol", "vt_fj", (data,), "cdecl", [(VT_FJ, F["thk_crt"])], "crt"),
    ]
    try:
        for label, fn, args, cc, cells, path in cases:
            if path == "crt":
                assert n.lib.lift_crt_bind(b"_ftol", CRT_BASE + 0x1f14, CRT_BASE) >= 0
            ref, _, _ = case_run(fn, args, cc, cells, native=False)
            assert ref[0] == "ok" and not e.fatal, (label, ref)
            for on in (True, False):
                got, nested, crt = case_run(fn, args, cc, cells, native=True, shortcut=on)
                diff = [k for k in ref[2] if got[0] != "ok" or ref[2][k] != got[2][k]] if ref[0] == "ok" else []
                assert got == ref, (label, on, diff, got if got[0] != "ok" else "")
                # the shortcut removes the guest call of a lifted or CRT target; the other calls are guest calls both ways
                assert nested == (0 if on else 1) if path in ("lifted", "crt") else nested == 1, (label, on, nested)
                assert crt == (1 if on and path == "crt" else 0), (label, on, crt)
            if path == "crt":
                n.lib.lift_crt_bind(b"_ftol", 0, 0)
    finally:
        e._drive = drive0
        n.lib.lift_thunk_shortcut(1)
        n.lib.lift_crt_bind(b"_ftol", 0, 0)
    # the lifted leaf's result is the emulated one (2 * 5 + 1), so the shortcut ran the leaf
    ref, _, _ = case_run("vt_c", (), "cdecl", [(VT_C, F["thk_l"]), (CELL_L, F["leaf_1"])], native=False)
    assert ref[1] == 11, ref

    # Thunk bytes or slots outside the mapped regions: the shortcut declines, the call is the guest call, and it faults
    # the way the emulated call does. Each case runs in fresh emulators (a fault leaves the run stopped).
    def fatal_pair(label, cells, prep=None):
        outs = []
        for native in (False, True):
            ef, nf = new_emu()
            if prep:
                prep(ef)
            for a, v in cells:
                ef.wr32(a, v)
            if native:
                _install(nf, F["vt_c"])
            try:
                ef.call(F["vt_c"], cc="cdecl")
                fatal = ef.fatal
            except NativeError as ex:
                fatal = str(ex) or "stopped"
            finally:
                if native:
                    nf.uninstall(F["vt_c"])
            outs.append(fatal)
        assert outs[0] and outs[1], (label, outs)

    fatal_pair("call target unmapped", [(VT_C, UNMAPPED)])
    fatal_pair("thunk bytes straddle the end of the mapping", [(VT_C, SYN + 0xFFFE)],
               prep=lambda ef: ef.wr(SYN + 0xFFFE, b"\xff\x25"))
    fatal_pair("thunk slot unmapped", [(VT_C, F["thk_unm"])])
    print("  %d thunk cases: emulated, shortcut and guest call agree" % (len(cases) + 3))



def test_call_cache():
    """The call-target cache (runtime.c call_resolve): a repeated call through a thunk is a hit; changing the IAT slot
    the thunk reads makes the next call resolve again and follow the new target (lifted leaf_1, then emulated helper,
    then leaf_1 again: the same result, a guest call only for the helper); a direct target is its own entry. With the
    cache off, every call resolves afresh and the results are the same."""
    e, n = new_emu()
    if not hasattr(n.lib, "lift_call_cache"):
        print("  (library predates the call-target cache)")
        return
    _install(n, F["vt_c"])
    fast = MODE[0] == "fast"

    def call():
        h0, m0 = n.call_cache_stats
        g0 = n.fast_stats()["guest_calls"] if fast else 0
        r = e.call(F["vt_c"], cc="cdecl")
        assert not e.fatal, e.fatal
        h1, m1 = n.call_cache_stats
        g1 = n.fast_stats()["guest_calls"] if fast else 0
        return r, h1 - h0, m1 - m0, g1 - g0

    try:
        for on in (True, False):
            n.lib.lift_call_cache(int(on))
            e.wr32(VT_C, F["thk_l"])
            e.wr32(CELL_L, F["leaf_1"])
            steps = [call(), call()]                         # resolve, then a hit
            e.wr32(CELL_L, F["helper"])                      # the IAT slot changes: emulated helper
            steps.append(call())
            e.wr32(CELL_L, F["leaf_1"])                      # and back
            steps.append(call())
            e.wr32(VT_C, F["leaf_1"])                        # a direct target: a new entry, then a hit
            steps += [call(), call()]
            assert all(r == 11 for r, _, _, _ in steps), steps
            if on:
                assert [(h, m) for _, h, m, _ in steps] == [(0, 1), (1, 0), (0, 1), (0, 1), (0, 1), (1, 0)], steps
            else:
                assert all((h, m) == (0, 0) for _, h, m, _ in steps), steps
            if fast:
                assert [g for _, _, _, g in steps] == [0, 0, 1, 0, 0, 0], (on, steps)
    finally:
        n.lib.lift_call_cache(1)
        n.uninstall(F["vt_c"])
    print("  call-target cache: hits, slot change re-resolved, direct target; off gives the same results")

def test_hle_fast_d3d8_matches_python():
    """The D3D8 handlers in C (lift/runtime/hle_fast.c), called from lifted code (d3c), leave what the Python handlers
    leave when the same calls come from emulated code: EAX, the guest writes, every capture record in order (the C
    handlers submit to a C sink, here a ctypes callback; Python ones go through the Writer), the device state and the
    Recorder's report. Covered: render and texture-stage states (one key out of C's range: declined), SetTexture with a
    texture, an index buffer and an unknown object, streams, indices (16 and 32 bit), buffer locks, DrawIndexedPrimitive with a
    texture not yet sent (declined: Python sends it), sent, then locked again (sent again), and with no indices; H60:
    SetVertexShader (an FVF and a shader handle), SetTransform (one state out of C's range: declined) and
    MultiplyTransform on top of it in Python, SetViewport, and Clear with and without rects. In fast mode C serves the
    calls after the first of each method; in slow mode there is no C path."""
    import ctypes
    import d3d8
    d3d8.install(mpemu)                       # as mpemu.boot does (once per process)
    H = lambda name: mpemu.HLE[("D3D8.DLL", name)][0]
    D = "IDirect3DDevice8::"
    SINK_T = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32)

    def run(native):
        e, n = new_emu()
        recs = []
        sink_c = SINK_T(lambda r, t, p, ln: recs.append((t, ctypes.string_at(p, ln))) or 0)
        pp, plr = e.alloc(16), e.alloc(16)
        mats, vps, rects = e.alloc(64 * 3), e.alloc(48), e.alloc(48)
        for i in range(3):                       # small integers: products are exact in f32 (MultiplyTransform)
            e.wr(mats + 64 * i, struct.pack("<16f", *[float((3 * i + k) % 5 - 2) for k in range(16)]))
        e.wr(vps, struct.pack("<IIIIffIIIIff", 0, 0, 640, 480, 0.0, 1.0, 8, 4, 320, 200, 0.25, 0.75))
        e.wr(rects, struct.pack("<12i", 0, 0, 10, 10, 5, 6, 70, 80, -1, 2, 3, 4))
        objs = {}
        for name, fn, args in (("vb", "CreateVertexBuffer", (4096, 0, 0x144, 0)), ("ib", "CreateIndexBuffer", (1024, 0, 101, 0)),
                               ("ib32", "CreateIndexBuffer", (1024, 0, 102, 0)),
                               ("tex", "CreateTexture", (16, 16, 1, 0, 21, 1))):
            H(D + fn)(e, 0, *args, pp)
            objs[name] = e.rd32(pp)
        rng = random.Random(50)
        vbp = d3d8_obj(e, objs["vb"])["ptr"]
        e.wr(vbp, bytes(rng.randrange(256) for _ in range(4096)))
        e.wr(d3d8_obj(e, objs["ib"])["ptr"], struct.pack("<12H", 7, 3, 9, 3, 4, 8, 11, 5, 6, 2, 9, 10))
        e.wr(d3d8_obj(e, objs["ib32"])["ptr"], struct.pack("<6I", 20, 15, 30, 16, 17, 25))
        texp = d3d8_obj(e, objs["tex"])["chain"][0]["ptr"]
        e.wr(texp, bytes(rng.randrange(256) for _ in range(16 * 16 * 4)))
        d3d8.start_capture(e, None, sink=lambda t, p: recs.append((t, bytes(p))),
                           c_sink=(ctypes.cast(sink_c, ctypes.c_void_p).value, 0, 0))
        vb, ib, ib32, tex = objs["vb"], objs["ib"], objs["ib32"], objs["tex"]
        calls = [(D + "SetRenderState", (7, 1)), (D + "SetRenderState", (7, 0)), (D + "SetRenderState", (300, 5)),
                 (D + "SetTextureStageState", (0, 1, 4)), (D + "SetTextureStageState", (0, 1, 2)),
                 (D + "SetTextureStageState", (9, 1, 2)),
                 (D + "SetTexture", (0, tex)), (D + "SetTexture", (1, ib)), (D + "SetTexture", (2, 0x12345678)),
                 (D + "SetTexture", (1, 0)), (D + "SetTexture", (2, 0)),
                 (D + "SetStreamSource", (0, vb, 28)), (D + "SetStreamSource", (0, vb, 28)),
                 (D + "SetIndices", (ib, 3)), (D + "SetIndices", (ib, 3)),
                 ("IDirect3DVertexBuffer8::Lock", (16, 0, pp, 0)), ("IDirect3DVertexBuffer8::Lock", (32, 0, pp + 4, 0)),
                 ("IDirect3DIndexBuffer8::Lock", (8, 0, pp + 8, 0)), ("IDirect3DIndexBuffer8::Lock", (2, 0, pp + 12, 0)),
                 ("IDirect3DVertexBuffer8::Unlock", ()), ("IDirect3DVertexBuffer8::Unlock", ()),
                 (D + "DrawIndexedPrimitive", (4, 0, 12, 0, 2)),        # texture not sent yet: Python sends it
                 (D + "DrawIndexedPrimitive", (4, 0, 12, 0, 2)),
                 (D + "DrawIndexedPrimitive", (5, 0, 12, 2, 3)),
                 ("IDirect3DTexture8::LockRect", (0, plr, 0, 0)),         # the texture changes: sent again
                 (D + "DrawIndexedPrimitive", (4, 0, 12, 3, 1)),
                 (D + "DrawIndexedPrimitive", (4, 0, 12, 3, 1)),
                 (D + "SetIndices", (ib32, 2)), (D + "DrawIndexedPrimitive", (6, 0, 30, 0, 4)),
                 (D + "DrawIndexedPrimitive", (6, 0, 30, 0, 4)),
                 (D + "DrawIndexedPrimitive", (4, 0, 0, 0, 0)),
                 (D + "SetVertexShader", (0x152,)), (D + "SetVertexShader", (0x152,)),
                 (D + "DrawIndexedPrimitive", (4, 0, 12, 0, 2)),
                 (D + "SetVertexShader", (0x80000001,)), (D + "SetVertexShader", (0x2c4,)),
                 (D + "SetTransform", (2, mats)), (D + "SetTransform", (256, mats + 64)),
                 (D + "SetTransform", (3, mats + 128)), (D + "SetTransform", (600, mats)),
                 (D + "MultiplyTransform", (256, mats + 128)), (D + "SetTransform", (2, mats + 64)),
                 (D + "SetViewport", (vps,)), (D + "SetViewport", (vps + 24,)),
                 (D + "Clear", (0, 0, 3, 0xff102030, 0x3f800000, 0)),
                 (D + "Clear", (0, 0, 3, 0xff102030, 0x3f800000, 0)),
                 (D + "Clear", (3, rects, 1, 0x80808080, 0, 7)), (D + "Clear", (2, 0, 2, 0, 0x3f000000, 0))]
        if native:
            _install(n, F["d3c"])
        out = []
        for name, args in calls:
            this = {"IDirect3DVertexBuffer8": vb, "IDirect3DIndexBuffer8": ib,
                    "IDirect3DTexture8": tex}.get(name.split("::")[0], 0x7777)
            e.wr32(D3SLOT, e.stub_for("D3D8.DLL", name))
            a = (this,) + tuple(args) + (0,) * (6 - len(args))
            r = e.call(F["d3c"], *a, cc="cdecl")
            assert not e.fatal, (name, e.fatal)
            out.append((name, r, bytes(e.rd(pp, 16)), e.rd32(D3ESP)))
        rec = e.d3d
        state = (sorted(rec.cur_rs.items()), sorted(rec.cur_tss.items()), sorted(rec.bound_tex.items()),
                 sorted(rec.streams.items()), tuple(rec.indices), rec.cur_vs, sorted(rec.cur_xf.items()),
                 rec.viewport)
        fast_calls = n.hle_fast_calls
        return out, recs, state, rec.report(), fast_calls

    ref = run(False)
    got = run(True)
    for i, (a, b) in enumerate(zip(ref[0], got[0])):
        assert a == b, (i, a, b)
    assert len(ref[1]) == len(got[1]), (len(ref[1]), len(got[1]))
    for i, (a, b) in enumerate(zip(ref[1], got[1])):
        assert a == b, (i, a[0], b[0], a[1][:32].hex(), b[1][:32].hex())
    assert ref[2] == got[2], (ref[2], got[2])
    assert ref[3] == got[3], [l for l in zip(ref[3].split("\n"), got[3].split("\n")) if l[0] != l[1]][:5]
    if MODE[0] == "fast":
        assert got[4] >= 25, got[4]
    else:
        assert got[4] == 0, got[4]
    print("  %d D3D8 calls, %d capture records: C and Python agree; served in C: %d" % (len(ref[0]), len(ref[1]), got[4]))


def d3d8_obj(e, addr):
    return e.d3d.objs[addr]


def test_hle_fast_qpc():
    """QueryPerformanceCounter from lifted code: C serves it after the first call, with the clock Python's handler
    uses (time.perf_counter_ns() // 1000): every value lies between Python's readings around the call, and they never go
    back."""
    import time
    e, n = new_emu()
    p = e.alloc(8)
    e.wr32(D3SLOT, e.stub_for("KERNEL32.DLL", "QueryPerformanceCounter"))
    _install(n, F["d3c"])
    last = 0
    for _ in range(50):
        t0 = time.perf_counter_ns() // 1000
        r = e.call(F["d3c"], p, 0, 0, 0, 0, 0, 0, cc="cdecl")
        t1 = time.perf_counter_ns() // 1000
        v = struct.unpack("<Q", e.rd(p, 8))[0]
        assert r == 1 and t0 <= v <= t1 and v >= last, (r, t0, v, t1, last)
        last = v
    c_calls = n.hle_fast_calls
    assert c_calls == (49 if MODE[0] == "fast" else 0), c_calls
    print("  50 QPC calls: values in Python's clock, monotonic; served in C: %d" % c_calls)


def test_hle_fast_k32_matches_python():
    """TlsGetValue, TlsSetValue, GetLastError, SetLastError and the critical sections in C (H60), called from lifted
    code (d3c), give what the Python handlers give from emulated code: every result, the last error and TLS slots as
    the Python handlers then see them (TlsAlloc and TlsFree stay in Python; a slot past C's range is declined and
    kept in Python), and the last error set by a Python handler (SearchPathA) read back in C."""
    K = "KERNEL32.DLL"

    def run(native):
        e, n = new_emu()
        if native:
            _install(n, F["d3c"])
        cs = e.alloc(24)
        out = []

        def call(name, *args):
            e.wr32(D3SLOT, e.stub_for(K, name))
            r = e.call(F["d3c"], *(tuple(args) + (0,) * (7 - len(args))), cc="cdecl")
            assert not e.fatal, (name, e.fatal)
            out.append((name, args, r, e.rd32(D3ESP)))
            return r

        a, b = call("TlsAlloc"), call("TlsAlloc")
        for _ in range(2):
            call("TlsSetValue", a, 0x1234)
            call("SetLastError", 5)
            call("TlsGetValue", a)                   # sets the last error to 0
            call("GetLastError")
            call("TlsGetValue", b)
            call("SetLastError", 0xC0000005)
            call("GetLastError")
        out.append(("python", e.last_error))
        e.last_error = 87                            # a Python handler's error, read by GetLastError in C
        call("GetLastError")
        call("SearchPathA", 0, 0, 0, 0, 0, 0)        # Python sets 2
        call("GetLastError")
        call("GetLastError")
        call("TlsSetValue", 2000, 9)                 # past C's slots: Python
        call("TlsGetValue", 2000)
        call("TlsGetValue", 2000)
        call("TlsFree", a)
        call("TlsGetValue", a)
        call("TlsGetValue", a)
        for name in ("InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
                     "EnterCriticalSection", "LeaveCriticalSection"):
            call(name, cs)
        out.append(("state", e.last_error, sorted(e.tls.items()), e.tls.get(2000), bytes(e.rd(cs, 24))))
        return out, n.hle_fast_calls

    ref, got = run(False), run(True)
    assert ref[0] == got[0], [x for x in zip(ref[0], got[0]) if x[0] != x[1]][:5]
    if MODE[0] == "fast":
        assert got[1] == 17, got[1]          # each stub's first call runs in Python; slot 2000 is declined
    else:
        assert got[1] == 0, got[1]
    print("  %d KERNEL32 calls: C and Python agree; served in C: %d" % (len(ref[0]), got[1]))

def test_hle_fast_dinput_matches_python():
    """IDirectInputDevice7A Acquire, GetDeviceState and GetDeviceData in C (H61), called from lifted code (d3c), give
    what the Python handlers give from emulated code: every result and every byte written, with host input (keys,
    mouse motion, wheel, buttons) in between. Covered: a device created before the fast path (its state moved to C)
    and one after; Acquire twice; states of the right and wrong size; events with PEEK, INFINITE, no buffer (count
    only) and padded records; a record size too small; buffer overflow; focus loss (INPUTLOST, then reacquired);
    Unacquire in Python (NOTACQUIRED); a Python poll hook (the polls go to Python while it is set). Then the devices'
    run state, the shared key state and dinput's report (C's counts merged) are equal."""
    import dinput
    dinput.install(mpemu)                     # as mpemu.boot does (once per process)
    DI = "DINPUT.DLL"
    V = "IDirectInputDevice7A::"
    clock = [0]

    def fake_ms():
        clock[0] += 7
        return clock[0]

    def run(native):
        clock[0] = 0
        e, n = new_emu()
        pp = e.alloc(4)
        assert e.call(e.stub_for(DI, "DirectInputCreateA"), 0x400000, 0x700, pp, 0) == 0
        di = e.rd32(pp)

        def ecall(this, name, *args):            # through the stub, emulated (setup)
            return e.call(e.stub_for(DI, ("IDirectInput7A::" if this == di else V) + name), this, *args) & 0xFFFFFFFF

        def fmt(entries, size):
            rg = e.alloc(16 * len(entries))
            for i, (g, ofs, typ) in enumerate(entries):
                pg = 0
                if g:
                    pg = e.alloc(16)
                    e.wr(pg, g)
                e.wr(rg + 16 * i, struct.pack("<4I", pg, ofs, typ, 0))
            pf = e.alloc(24)
            e.wr(pf, struct.pack("<6I", 24, 16, 2, size, len(entries), rg))
            return pf

        def device(g, pfmt):
            pg = e.alloc(16)
            e.wr(pg, g)
            assert ecall(di, "CreateDevice", pg, pp, 0) == 0
            d = e.rd32(pp)
            assert ecall(d, "SetDataFormat", pfmt) == 0
            assert ecall(d, "SetCooperativeLevel", 0x10010, 0x16) == 0
            ph = e.alloc(20)
            e.wr(ph, struct.pack("<5I", 20, 16, 0, 0, 16))
            assert ecall(d, "SetProperty", 1, ph) == 0
            return d

        kbd_fmt = fmt([(dinput.GUID_KEY, i, 0x8000000C | (i << 8)) for i in range(256)], 256)
        any_axis, any_btn = 0x00FFFF03, 0x80FFFF0C
        mouse_fmt = fmt([(dinput.GUID_XAXIS, 0, any_axis), (dinput.GUID_YAXIS, 4, any_axis),
                         (dinput.GUID_ZAXIS, 8, any_axis | 0x80000000)] +
                        [(None, 12 + i, any_btn) for i in range(8)], 20)
        kbd = device(dinput.GUID_SYSKEYBOARD, kbd_fmt)          # before the fast path: moved to C
        inp = e.dinput
        inp.key(dinput.DIK_A, True)
        if native:
            _install(n, F["d3c"])
        mouse = device(dinput.GUID_SYSMOUSE, mouse_fmt)        # after: created in C
        st, buf, pn = e.alloc(256), e.alloc(32 * 40), e.alloc(4)
        out = []

        def call(this, name, *args):
            e.wr32(D3SLOT, e.stub_for(DI, V + name))
            e.wr(st, b"\xcc" * 256)
            e.wr(buf, b"\xcc" * (32 * 40))
            r = e.call(F["d3c"], *((this,) + tuple(args) + (0,) * (6 - len(args))), cc="cdecl")
            assert not e.fatal, (name, e.fatal)
            out.append((name, args, r, bytes(e.rd(st, 256)), bytes(e.rd(buf, 32 * 40)), e.rd32(pn), e.rd32(D3ESP)))
            return r

        def data(this, want, cbobj=16, rgdod=None, flags=0):
            e.wr32(pn, want)
            return call(this, "GetDeviceData", cbobj, buf if rgdod is None else rgdod, pn, flags)

        for d in (kbd, mouse, kbd, mouse):
            call(d, "Acquire")
        inp.key(dinput.DIK_W, True)
        inp.key(dinput.DIK_LSHIFT, True)
        inp.key(dinput.DIK_W, False)
        inp.mouse_move(5, -3)
        inp.mouse_wheel(120)
        inp.mouse_button(0, True)
        inp.mouse_move(1 << 33, 0)                       # clamped to int32 in the state
        for _ in range(2):
            call(kbd, "GetDeviceState", 256, st)
            call(mouse, "GetDeviceState", 20, st)
        call(kbd, "GetDeviceState", 255, st)
        data(kbd, 2, flags=1)                            # PEEK
        data(kbd, 2, cbobj=24)                           # padded records
        data(kbd, 0xFFFFFFFF)
        data(kbd, 16)                                    # drained
        data(mouse, 5, rgdod=0)                          # count only: nothing removed
        data(mouse, 5, rgdod=0)
        data(mouse, 16)
        data(mouse, 4, cbobj=8)                          # too small
        for i in range(20):
            inp.key(dinput.DIK_S, i % 2 == 0)
        data(kbd, 32)                                    # DI_BUFFEROVERFLOW
        data(kbd, 32)
        inp.focus_lost()
        call(kbd, "GetDeviceState", 256, st)
        data(kbd, 4)
        call(kbd, "Acquire")
        inp.key(dinput.DIK_D, True)
        data(kbd, 4)
        ecall(mouse, "Unacquire")
        call(mouse, "GetDeviceState", 20, st)
        data(mouse, 4)
        inp.on_poll = lambda e_, kind: inp.key(0x12, kind == "keyboard")
        call(kbd, "GetDeviceState", 256, st)
        data(kbd, 4)
        inp.on_poll = None
        inp.key(0x12, False)
        call(kbd, "GetDeviceState", 256, st)
        data(kbd, 4)
        devs = [(d.kind, d.acquired, d.lost, d.overflow, d.dx, d.dy, d.dz, list(d.queue), d.bufsize, d.coop)
                for d in inp.devices]
        state = (devs, bytes(inp.keys), bytes(inp.buttons), inp.seq, e.di.report())
        return out, state, n.hle_fast_calls

    real_ms = dinput.now_ms
    dinput.now_ms = fake_ms
    try:
        ref, got = run(False), run(True)
    finally:
        dinput.now_ms = real_ms
    assert ref[0] == got[0], [(x[0][:3], x[1][:3]) for x in zip(ref[0], got[0]) if x[0] != x[1]][:5]
    assert ref[1][:4] == got[1][:4], (ref[1][:4], got[1][:4])
    assert ref[1][4] == got[1][4], [l for l in zip(ref[1][4].split("\n"), got[1][4].split("\n")) if l[0] != l[1]][:5]
    if MODE[0] == "fast":
        assert got[2] == 24, got[2]          # each method's first call runs in Python; two polls under the hook
    else:
        assert got[2] == 0, got[2]
    print("  %d DINPUT calls: C and Python agree; served in C: %d" % (len(ref[0]), got[2]))


def test_hle_fast_dsound_matches_python():
    """IDirectSoundBuffer Lock, Unlock, GetCurrentPosition and SetVolume in C (H62), called from lifted code (d3c), give
    what the Python handlers give from emulated code: every result and every byte written, and the same mixer state
    (the output rendered between calls, from a mixer without a device). Covered: a buffer created before the fast path
    (moved to C) and two after (one 3D, its gains changed in Python), the primary buffer (no voice); Lock with a
    wrap-around, ENTIREBUFFER, FROMWRITECURSOR while playing, out of range, null size pointers; Unlock of both regions,
    of a pointer outside the buffer; volumes below silence and above 0; the cursors after a render, after Stop and a
    one-shot that ended. Then the buffers' run state and dsound's report (C's counts merged) are equal."""
    import dsound
    dsound.install(mpemu)
    DS = "DSOUND.DLL"
    B = "IDirectSoundBuffer::"
    T = "IDirectSound3DBuffer::"

    def fb(x): return struct.unpack("<I", struct.pack("<f", x))[0]

    def run(native):
        e, n = new_emu()
        e.audio = "none"                         # a mixer without a device: the test renders
        pp = e.alloc(4)
        assert e.call(e.stub_for(DS, "DirectSoundCreate"), 0, pp, 0) & 0xFFFFFFFF == 0
        ds = e.rd32(pp)

        def ecall(this, name, *args):            # through the stub, emulated (setup)
            iface = "IDirectSound::" if this == ds else T if name.startswith("T:") else B
            return e.call(e.stub_for(DS, iface + name.replace("T:", "")), this, *args) & 0xFFFFFFFF

        def buffer(flags, ch, bits, rate, nbytes):
            align = ch * bits // 8
            wfx = e.alloc(18)
            e.wr(wfx, struct.pack("<HHIIHHH", 1, ch, rate, rate * align, align, bits, 0))
            desc = e.alloc(20)
            e.wr(desc, struct.pack("<5I", 20, flags, nbytes, 0, 0 if flags & 1 else wfx))
            assert ecall(ds, "CreateSoundBuffer", desc, pp, 0) == 0
            return e.rd32(pp)

        a = buffer(0xE0, 2, 16, 22050, 4096)                  # before the fast path: moved to C
        prim = buffer(0x11, 2, 16, 22050, 0)
        if native:
            _install(n, F["d3c"])
        b = buffer(0xF0, 1, 16, 44100, 8192)                  # 3D, after: created in C
        c = buffer(0xE0, 1, 8, 11025, 1024)
        lk, mixed = e.alloc(16), []
        out = []
        mx = dsound.mixer(e)

        def render(k):
            f = (ctypes.c_float * (2 * k))()
            mx.lib.mpa_render(mx.m, f, k)
            mixed.append(bytes(f))

        def call(this, name, *args):
            e.wr32(D3SLOT, e.stub_for(DS, B + name))
            e.wr(lk, b"\xcc" * 16)
            r = e.call(F["d3c"], *((this,) + tuple(args) + (0,) * (7 - len(args))), cc="cdecl") & 0xFFFFFFFF
            assert not e.fatal, (name, e.fatal)
            out.append((name, args, r, bytes(e.rd(lk, 16)), e.rd32(D3ESP)))
            return r

        def fill(this, off, nbytes, flags=0, seed=1):
            r = call(this, "Lock", off, nbytes, lk, lk + 4, lk + 8, lk + 12, flags)
            p1, n1, p2, n2 = struct.unpack("<4I", e.rd(lk, 16))
            if r == 0:
                for p, k in ((p1, n1), (p2, n2)):
                    if p and k:
                        e.wr(p, bytes((seed * 37 + i * 11) & 0xFF for i in range(k)))
                call(this, "Unlock", p1, n1, p2, n2)
            return r

        def pos(this, both=True):
            call(this, "GetCurrentPosition", lk, lk + 4 if both else 0)

        ecall(a, "Play", 0, 0, 1)                             # looping
        ecall(b, "Play", 0, 0, 1)
        fill(a, 1000, 4000, seed=2)                           # wraps
        fill(b, 0, 0, flags=2, seed=3)                        # ENTIREBUFFER
        fill(c, 0, 1024, seed=4)
        ecall(c, "Play", 0, 0, 0)                             # one-shot
        for this in (a, b, c, prim):
            pos(this)
        render(300)
        for this in (a, b, c):
            pos(this)
        fill(a, 0, 512, flags=1, seed=5)                      # FROMWRITECURSOR while playing
        call(a, "Lock", 4096, 16, lk, lk + 4, lk + 8, lk + 12, 0)    # out of range
        call(a, "Lock", 0, 4097, lk, lk + 4, lk + 8, lk + 12, 0)
        call(a, "Lock", 100, 200, lk, 0, lk + 8, 0, 0)        # null size pointers
        call(a, "Unlock", 0x1000, 64, 0, 0)                   # outside the buffer: counted, not written
        for this, v in ((a, -600), (b, -10000), (c, 300), (prim, -100), (b, -1200)):
            call(this, "SetVolume", v & 0xFFFFFFFF)
        render(500)
        q = e.alloc(4)
        e.wr32(q, 0)                                          # the 3D buffer: moved, so its gains change in Python
        p3 = e.alloc(16)
        e.wr(p3, dsound.IID["IDirectSound3DBuffer"])
        assert ecall(b, "QueryInterface", p3, q) == 0
        assert ecall(e.rd32(q), "T:SetPosition", fb(4.0), fb(0.0), fb(2.0), 0) == 0
        call(b, "SetVolume", (-300) & 0xFFFFFFFF)
        render(400)
        for this in (a, b, c):
            pos(this, both=False)
        ecall(b, "Stop")
        fill(c, 0, 1024, seed=6)                              # the one-shot has ended
        render(1500)
        for this in (a, b, c, prim):
            pos(this)
        call(prim, "SetVolume", 0)
        objs = e.ds.objs
        state = [(objs[x]["volume"], objs[x]["playing"], objs[x]["looping"], objs[x]["pos"], objs[x].get("unlocks", 0),
                  objs[x].get("written", 0), objs[x]["voice"]) for x in (a, b, c, prim)]
        return out, mixed, state, e.ds.report(), n.hle_fast_calls

    ref, got = run(False), run(True)
    assert ref[0] == got[0], [(x[0][:3], x[1][:3]) for x in zip(ref[0], got[0]) if x[0] != x[1]][:5]
    assert ref[1] == got[1], [i for i, x in enumerate(zip(ref[1], got[1])) if x[0] != x[1]]
    assert ref[2] == got[2], (ref[2], got[2])
    assert ref[3] == got[3], [l for l in zip(ref[3].split("\n"), got[3].split("\n")) if l[0] != l[1]][:5]
    if MODE[0] == "fast":
        assert got[4] == len(got[0]) - 4, got[4]     # each method's first call runs in Python
    else:
        assert got[4] == 0, got[4]
    print("  %d DSOUND calls: C and Python agree; served in C: %d" % (len(ref[0]), got[4]))


def _heap_state(h):
    return h.next, sorted(h.live()), sorted(h.free_blocks())


def test_c_heap_matches_python():
    """lift/runtime/heap.c against mpemu.PyHeap: the same random alloc/free/resize/reserve sequence gives the same
    pointers, reuse flags, lookups and whole state (bump pointer, live and free blocks). The C heap starts as a copy
    of a Python heap that is already in use (as at enable_fast), and an exhausted heap fails on both sides."""
    import random
    from native import CHeap
    e, n = new_emu()
    if not hasattr(n.lib, "lift_heap_reset"):
        print("  (library predates heap.c)")
        return
    rng = random.Random(44)
    base = mpemu.HEAP_BASE
    py = mpemu.PyHeap(base, base + 0x400000)
    live = []

    def step(h, op, a):
        if op == "alloc":
            try:
                return h.alloc(a)
            except MemoryError:
                return "exhausted"
        if op == "free":
            return h.free(a)
        if op == "resize":
            h.resize(a[0], a[1])
            return h.get(a[0])
        if op == "reserve":
            return h.reserve(a[0], a[1])
        return h.get(a)

    def ops(k):
        for _ in range(k):
            r = rng.random()
            if r < 0.5 or not live:
                yield "alloc", rng.choice([1, 8, 16, 17, 40, 100, 256, 4096, 5000, 65536, rng.randrange(1, 20000)])
            elif r < 0.85:
                yield "free", live.pop(rng.randrange(len(live)))
            elif r < 0.9:
                p = rng.choice(live)
                yield "resize", (p, rng.randrange(1, py.get(p)[1] + 1))
            elif r < 0.93:
                yield "reserve", (rng.choice([0, 1, 4096, 10000]), rng.random() < 0.7)
            else:
                yield "get", rng.choice(live + [0, 0x12345670, base])

    for op, a in ops(3000):                      # the Python heap in use before the move to C
        r = step(py, op, a)
        if op == "alloc" and r != "exhausted":
            live.append(r[0])
    ch = CHeap(n.lib, py)
    assert _heap_state(ch) == _heap_state(py) and len(ch) == len(py)
    for i, (op, a) in enumerate(ops(20000)):
        rp, rc = step(py, op, a), step(ch, op, a)
        assert rp == rc, (i, op, a, rp, rc)
        if op == "alloc" and rp != "exhausted":
            live.append(rp[0])
        if i % 1000 == 0:
            assert _heap_state(ch) == _heap_state(py), i
    assert _heap_state(ch) == _heap_state(py) and len(ch) == len(py)
    st = ch.stats()
    assert st[3] == sum(py.caps.values()) and st[4] == py.free_list.total, (st, py.free_list.total)
    assert py.exhausted() == ch.exhausted()
    print("  23000 heap operations: C and Python agree (%d live, %d free blocks)" % (len(py), len(py.free_list.start)))


def test_c_heap_direct_calls():
    """Lifted code calling HeapAlloc/HeapFree (hp): on the fast path the C heap serves them (after the first call of
    each, which binds its stub), and every call leaves what the emulated run leaves: the pointers, the registers, the
    stack below esp, zeroed reused blocks and the same heap. In slow mode both runs use the Python heap."""
    sizes = [40, 100, 40, 300, 16, 1, 5000, 64, 64, 4000]

    def run(native):
        e, n = new_emu()
        e.wr32(HSLOT_A, e.stub_for("KERNEL32.DLL", "HeapAlloc"))
        e.wr32(HSLOT_F, e.stub_for("KERNEL32.DLL", "HeapFree"))
        if native:
            _install(n, F["hp"])
        out, prev = [], 0
        for i, size in enumerate(sizes * 3):
            if prev:
                e.wr(prev, b"\xaa" * mpemu.align_up(e.heap_blocks[prev], 16))   # dirty: a reuse must zero it
            free_p = prev if i % 3 else 0
            p = e.call(F["hp"], size, free_p, cc="cdecl")
            assert not e.fatal, e.fatal
            sp = e.uc.reg_read(UC_X86_REG_ESP)
            out.append((p, _regs(e), bytes(e.rd(sp - 0x40, 0x40)), bytes(e.rd(p, size))))
            prev = p
        hd = n.heap_direct_calls
        return out, _heap_state(e.heap), hd, type(e.heap).__name__

    ref, ref_heap, _, _ = run(False)
    got, got_heap, hd, kind = run(True)
    for i, (r, g) in enumerate(zip(ref, got)):
        assert r == g, (i, hex(r[0]), hex(g[0]), [k for k in r[1] if r[1][k] != g[1][k]])
        assert g[3] == bytes(len(g[3])), (i, "block not zeroed")
    assert ref_heap == got_heap
    if MODE[0] == "fast":
        assert kind == "CHeap" and hd == (len(ref) - 1, len(ref) - 1), (kind, hd)
    else:
        assert kind == "PyHeap" and hd == (0, 0), (kind, hd)
    print("  %d hp calls: %s heap, same pointers, state and heap as emulated; served in C: %s" % (len(ref), kind, hd))

def test_hle_direct():
    """A call or tail jump from lifted code to an HLE stub in mpemu.HLE_DIRECT runs the handler without the emulator
    (runtime.c hle_direct; fast path only) and leaves what the emulated call leaves: result, GPRs, flags, x87 state, the
    stack below esp and the handler's memory writes. Reached three ways: call [cell] (lift_call_ret), jmp [eax]
    (lift_jump), and call [cell] to an import thunk (the thunk shortcut resolves it to the stub). A handler that returns
    a coroutine is declined and goes through the stub; one that raises stops the run as through the stub. Turned off
    (lift_hle_direct_init(NULL)), every case is a guest call again. In slow mode there are no direct calls."""
    dll = "TESTHLE.DLL"
    out = SYN + 0x8080                    # Inc writes its argument here

    def inc(e, x):
        e.wr32(out, x ^ 0xA5A5A5A5)
        return x + 1

    def coro(e, x):                       # a coroutine that calls no guest code: the stub runs it
        e.wr32(out, x ^ 0x5A5A5A5A)
        return x + 2
        yield                             # noqa: unreachable (makes this a generator function)

    def boom(e, x):
        raise mpemu.Unimplemented("boom")

    handlers = {"Inc": inc, "Coro": coro, "Boom": boom}
    for name, fn in handlers.items():
        mpemu.HLE[(dll, name)] = (fn, 1, "cdecl")
        mpemu.HLE_DIRECT.add((dll, name))
    # (label, lifted caller, args, cells): the cells point the caller at the stub (STUB stands for its address)
    STUB = object()
    shapes = [("call", "vt_c", (), [(VT_C, STUB)]),
              ("tail jump", "vt_j", (5,), [(VT_J, STUB)]),
              ("call through a thunk", "vt_c", (), [(VT_C, F["thk_hle"]), (SLOT, STUB)])]

    def run(name, fn, args, cells, native, direct=True):
        """(outcome, guest calls, direct calls) of fn in a fresh emulator."""
        e, n = new_emu()
        stub = e.stub_for(dll, name)
        for a, v in cells:
            e.wr32(a, stub if v is STUB else v)
        e.wr32(out, 0)
        if native:
            _install(n, F[fn])
            if not direct and n._hle_cb is not None:
                n.lib.lift_hle_direct_init(None, 0, 0)
        fast = MODE[0] == "fast"
        g0, h0 = (n.fast_stats()["guest_calls"] if fast else 0), n.hle_direct_calls
        try:
            r = e.call(F[fn], *args, cc="cdecl")
            err = e.fatal
        except NativeError as ex:
            err = str(ex) or "stopped"
        g1, h1 = (n.fast_stats()["guest_calls"] if fast else 0), n.hle_direct_calls
        prof = e.hle_direct_profile()
        if err:
            return ("fatal",), g1 - g0, h1 - h0, prof
        sp = e.uc.reg_read(UC_X86_REG_ESP)
        log = [l for l in e.apilog if l.startswith(dll)]     # the stub and the direct call log the same line
        return ("ok", r, _regs(e), bytes(e.rd(sp - 0x40, 0x40)), e.rd32(out), log), g1 - g0, h1 - h0, prof

    try:
        for name in handlers:
            for label, fn, args, cells in shapes:
                ref, _, _, _ = run(name, fn, args, cells, native=False)
                assert (ref[0] == "fatal") == (name == "Boom"), (name, label, ref[:2])
                for direct in (True, False):
                    got, guest, hd, prof = run(name, fn, args, cells, native=True, direct=direct)
                    diff = [k for k in ref[2] if got[0] != "ok" or ref[2][k] != got[2][k]] if ref[0] == "ok" else []
                    assert got == ref, (name, label, direct, diff)
                    went_direct = direct and MODE[0] == "fast" and name == "Inc"
                    assert hd == (1 if went_direct else 0), (name, label, direct, hd)
                    # the direct-call profile (H43) counts exactly the calls that went direct
                    assert [(k, c) for k, c, _ in prof] == ([((dll, name), 1)] if went_direct else []), (
                        name, label, direct, prof)
                    if MODE[0] == "fast" and name != "Boom":
                        assert guest == (0 if went_direct else 1), (name, label, direct, guest)
                if name == "Inc":
                    assert ref[1] == 6 and ref[4] == 5 ^ 0xA5A5A5A5, (label, ref[1], ref[4])
                    assert ref[5] == ["TESTHLE.DLL!Inc(0x5) -> 0x6"], (label, ref[5])
    finally:
        for name in handlers:
            mpemu.HLE.pop((dll, name), None)
            mpemu.HLE_DIRECT.discard((dll, name))
    print("  %d direct HLE cases: emulated, direct and stub agree" % (len(handlers) * len(shapes)))

TESTS = [test_layout,test_flag_and_fp_conversions, test_state_round_trip, test_function_entries_overlap,
         test_deferred_module, test_deferred_module_base_refused, test_deferred_never_loaded, test_fast_install_twice,
         test_leaf_stdcall_cdecl_thiscall, test_native_calls_emulated_and_hle, test_nesting,
         test_undo_refused_and_fatal, test_fpu_flags, test_conversions_c_matches_python,
         test_sync_c_matches_python, test_x87_skip_for_flagless_functions, test_mmx_native_matches_emulated,
         test_rounding_control, test_fast_fallback_stop, test_fast_path_basics, test_fast_undo_refused,
         test_fast_unwind_past_native, test_fast_halt_drops_native_frames, test_dead_stack_matches_emulator,
         test_dead_frames_past_entry, test_dead_frames_two_levels, test_dead_frames_fatal,
         test_callee_writes_return_slot, test_normal_callee_restores_return_slot, test_bridge_ret_predicate,
         test_crt_helpers_match_guest, test_crt_string_helpers, test_crt_bind_refuses_mismatch,
         test_crt_rtdynamiccast, test_crt_rtdynamiccast_declines, test_crt_rtdyn_bind_refuses_mismatch,
         test_crt_math_helpers, test_thunk_shortcut, test_call_cache, test_hle_direct, test_c_heap_matches_python,
         test_hle_fast_d3d8_matches_python, test_hle_fast_qpc, test_hle_fast_k32_matches_python,
         test_hle_fast_dinput_matches_python, test_hle_fast_dsound_matches_python,
         test_c_heap_direct_calls,
         test_overhead, test_real_dll, test_real_dll_mmx_status, test_real_dll_mmx_flags]
# Tests that install functions through _install: run again with the fast path (MODE "fast").
FAST_MODE_TESTS = [test_leaf_stdcall_cdecl_thiscall, test_native_calls_emulated_and_hle, test_nesting, test_deferred_module,
                   test_undo_refused_and_fatal, test_x87_skip_for_flagless_functions,
                   test_mmx_native_matches_emulated, test_rounding_control, test_fast_fallback_stop,
                   test_overhead, test_real_dll, test_dead_stack_matches_emulator, test_crt_helpers_match_guest,
                   test_crt_string_helpers, test_callee_writes_return_slot, test_normal_callee_restores_return_slot,
                   test_thunk_shortcut, test_call_cache, test_hle_direct, test_c_heap_direct_calls,
                   test_hle_fast_d3d8_matches_python, test_hle_fast_qpc, test_hle_fast_k32_matches_python,
                   test_hle_fast_dinput_matches_python, test_hle_fast_dsound_matches_python]


if __name__ == "__main__":
    failed = 0
    plan = [(fn, "slow") for fn in TESTS] + [(fn, "fast") for fn in FAST_MODE_TESTS]
    for fn, mode in plan:
        MODE[0] = mode
        label = fn.__name__ + ("" if mode == "slow" else " [fast]")
        t0 = time.time()
        try:
            fn()
            print("PASS %s (%.1fs)" % (label, time.time() - t0))
        except Exception as ex:          # report and carry on
            failed += 1
            import traceback
            traceback.print_exc()
            print("FAIL %s: %s" % (label, ex))
    MODE[0] = "slow"
    print("%d failed" % failed if failed else "all synthetic tests passed")
    sys.exit(1 if failed else 0)
