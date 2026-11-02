"""Per-instruction differential test rig for the x86 -> C translator (lift/x86c.py).

check(code, ...) takes one or more x86-32 instructions, appends `ret`, and runs the snippet on n
random initial states twice: once under Unicorn (the reference emulator) and once as C produced by
x86c.lift_function, compiled with the runtime in lift/runtime. The final states are compared:
GPRs, the arithmetic flags (minus `undefined`), the 64 KB data region, and optionally the x87 state.

    from insnrig import check, enc
    r = check(enc("39 d8"), undefined=())          # cmp eax, ebx
    assert r.ok, r.failures

Helpers:
    enc(hexstr) -> bytes   hex with spaces/commas, e.g. "8b c3". Verify the decoding with
                           dis(enc(...)): there is no assembler installed, so capstone is the check.
    dis(code)  -> str      capstone disassembly, "mov eax, ebx; ret", for messages.

Memory map seen by the snippet (identical on the Unicorn and C sides):
    CODE   0x00401000   the snippet, then ret. Its return address is RET (0x00401800, never executed).
    DATA   0x00200000   64 KB data region, random unless `mem` is given. Compared after the run.
    STACK  0x00208000   initial ESP. The return address is pushed below it (lifted code is entered as
                        if by call). Stack lives inside DATA, so pushes are compared.
Not mapped: fs:, and any address outside DATA. A snippet that touches it fails on the Unicorn side.

x87 (fpu=True): each state starts with fninit, FPCW=0x027F, k=0..8 doubles pushed (special values
mixed with random ones), TOP rotated randomly, FPSW C0..C3 random. The initial state is read back from
Unicorn, so the C side starts from exactly what Unicorn holds. Unicorn FPn is the PHYSICAL register n
(verified: ST(i) == FP[(TOP+i)&7]); FPTAG uses 2 bits per physical register, 11 = empty, 00 = valid,
01 = zero. Values are compared as logical ST(i) for the non-empty slots, bit-exact (NaN == NaN).
Values are doubles; the rig generates only double-exact values.

Translator state (see lift/runtime/cpu.h): flags are one byte each, x87 st[] is physical with
`top` and `tag` (bit p set = physical p empty). The C sw field is compared under the architectural
C0..C3 mask 0x4700 (C0=bit 8, C1=bit 9, C2=bit 10, C3=bit 14).

Run the self-test with:  ../../../.venv/bin/python lift/test_insnrig.py
"""
import glob
import hashlib
import math
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import capstone
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL, UcError
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
    UC_X86_REG_EFLAGS, UC_X86_REG_EIP, UC_X86_REG_FP0, UC_X86_REG_FPCW,
    UC_X86_REG_FPSW, UC_X86_REG_FPTAG,
)

import x86c
from x86c import lift_function

CODE = 0x00401000
RET = CODE + 0x800
DATA = 0x00200000
DATA_SIZE = 0x10000
STACK = DATA + 0x8000
SCRATCH = 0x00300000       # x87 setup operands (Unicorn only)
SETUP = 0x00500000         # x87 setup code, one fresh address per state (Unicorn only)
MAX_INSNS = 1_000_000

CLANG = shutil.which("clang") or "/usr/bin/clang"
CFLAGS = ["-O1", "-std=gnu11", "-Wall", "-Wno-unused-label", "-Wno-unused-variable",
          "-Wno-unused-function", "-I", x86c.RUNTIME]

GPR_NAMES = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]   # = CPU.r[] order
GPR_IDS = [UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
           UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI]
FLAG_ORDER = ["cf", "pf", "af", "zf", "sf", "of", "df"]
FLAG_BIT = {"cf": 0, "pf": 2, "af": 4, "zf": 6, "sf": 7, "of": 11, "df": 10}
CW_FIXED = 0x027F
C_BITS = 0x4700

# C-side state record: must match the Head struct in _HARNESS (184 bytes: 120 bytes of x87/GPR state, then mm[8]).
HEAD_FMT = "<8d8I2I2H8B4x8Q"
HEAD_SIZE = 184
assert struct.calcsize(HEAD_FMT) == HEAD_SIZE

_CS32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


class _RigError(Exception):
    """Something the rig could not run (emulator fault, C build or run failure)."""


# ---------------------------------------------------------------- public helpers

def enc(hexstr):
    """Bytes for a hex string such as "8b c3" (spaces, tabs and commas are ignored)."""
    return bytes.fromhex(re.sub(r"[\s,]", "", hexstr))


def dis(code, va=CODE):
    """capstone disassembly of code, instructions joined with '; '."""
    text = "; ".join(("%s %s" % (i.mnemonic, i.op_str)).strip() for i in _CS32.disasm(bytes(code), va))
    return text or "(undecodable)"


@dataclass
class Result:
    ok: bool
    failures: list                 # readable diffs, at most 5
    n: int                         # states requested
    label: str
    n_failed: int = 0              # states that differed (or 1 when the snippet was never run)
    unsupported: list = field(default_factory=list)   # [(va, insn text)] from the translator
    stage: str = "compare"         # "translate" or "run" when the snippet did not get to compare

    def __str__(self):
        head = "PASS" if self.ok else "FAIL"
        if self.stage == "compare":
            status = "%d/%d states differ" % (self.n_failed, self.n)
        else:
            status = "not run (%s failed)" % self.stage
        lines = ["%s %s: %s" % (head, self.label, status)]
        lines += ["  " + f for f in self.failures]
        return "\n".join(lines)


# ---------------------------------------------------------------- image for the translator

class _SnippetImage:
    """Same interface as x86c.PEImage: read(va, n), base, iat. Holds only the snippet bytes."""

    def __init__(self, blob):
        self._blob = blob
        self.base = CODE
        self.iat = {}

    def read(self, va, n):
        off = va - CODE
        if 0 <= off < len(self._blob):
            return self._blob[off:off + n]
        raise ValueError("unmapped %08x" % va)


# ---------------------------------------------------------------- random states

def _rand_double(rng):
    specials = [0.0, -0.0, 1.0, -1.0, 1e300, -1e300, 1e-300, 5e-324, math.inf, -math.inf,
                math.nan, struct.unpack("<d", struct.pack("<Q", 0x7ff8000000001234))[0]]
    if rng.random() < 0.4:
        return rng.choice(specials)
    return math.ldexp(rng.uniform(-1.0, 1.0), rng.randint(-100, 100))


def _pick(rng, v):
    if isinstance(v, int):
        return v & 0xffffffff
    if isinstance(v, range):
        return rng.choice(v) & 0xffffffff
    return rng.choice(list(v)) & 0xffffffff


def _gen_state(rng, regs, mem, fpu, random_df, mmx=False):
    r = {}
    for name in GPR_NAMES:
        if name == "esp":
            r[name] = STACK
        elif name in regs:
            r[name] = _pick(rng, regs[name])
        else:
            r[name] = rng.getrandbits(32)
    flags = {f: rng.getrandbits(1) for f in ("cf", "pf", "af", "zf", "sf", "of")}
    flags["df"] = rng.getrandbits(1) if random_df else 0
    data = bytearray(rng.randbytes(DATA_SIZE))
    if mem is not None:
        data[:len(mem)] = mem
    st = None
    if fpu:
        k = rng.randint(0, 8)
        c = 0
        for bit, pos in ((0x100, 8), (0x200, 9), (0x400, 10), (0x4000, 14)):
            if rng.getrandbits(1):
                c |= bit
        st = {"vals": [_rand_double(rng) for _ in range(k)],
              "rot": rng.randint(0, 7),
              "c": c}
    mm = [rng.getrandbits(64) for _ in range(8)] if mmx else [0] * 8
    return {"regs": r, "flags": flags, "data": bytes(data), "fpu": st, "mm": mm}


# ---------------------------------------------------------------- Unicorn side

def _round_up(x, m):
    return (x + m - 1) // m * m


def _fp_float(mant, exp):
    """80-bit (mantissa, exponent) as a Python float. Exact for double-exact values."""
    neg = bool(exp & 0x8000)
    e = exp & 0x7fff
    if e == 0x7fff:
        if mant & 0x7fffffffffffffff:
            return math.nan
        return -math.inf if neg else math.inf
    if mant == 0:
        return -0.0 if neg else 0.0
    ex = (e or 1) - 16383 - 63
    try:
        v = float(Fraction(mant) * Fraction(2) ** ex)
    except OverflowError:
        v = math.inf
    return -v if neg else v


def _read_fpu(uc):
    sw = uc.reg_read(UC_X86_REG_FPSW)
    tag = uc.reg_read(UC_X86_REG_FPTAG)
    return {
        "top": (sw >> 11) & 7,
        "c": sw & C_BITS,
        "empty": [((tag >> (2 * p)) & 3) == 3 for p in range(8)],
        "st": [_fp_float(*uc.reg_read(UC_X86_REG_FP0 + p)) for p in range(8)],
    }


def _read_flags(uc):
    ef = uc.reg_read(UC_X86_REG_EFLAGS)
    return {f: (ef >> FLAG_BIT[f]) & 1 for f in FLAG_ORDER}


def _fpu_setup(uc, i, fs):
    """fninit, push fs['vals'], rotate TOP, set FPCW and the C bits. Returns the readback."""
    code = bytearray(b"\xdb\xe3")                       # fninit
    for j, v in enumerate(fs["vals"]):
        addr = SCRATCH + 8 * j
        uc.mem_write(addr, struct.pack("<d", v))
        code += b"\xdd\x05" + struct.pack("<I", addr)  # fld qword ptr [addr]
    code += b"\xd9\xf7" * fs["rot"]                     # fincstp
    at = SETUP + i * 0x100
    uc.mem_write(at, bytes(code))
    uc.emu_start(at, at + len(code), count=10000)
    top = (uc.reg_read(UC_X86_REG_FPSW) >> 11) & 7
    uc.reg_write(UC_X86_REG_FPCW, CW_FIXED)
    uc.reg_write(UC_X86_REG_FPSW, (top << 11) | fs["c"])
    snap = _read_fpu(uc)
    if snap["top"] != top or snap["c"] != fs["c"]:
        raise _RigError("internal: could not set the x87 state (TOP/C bits)")
    return snap


def _run_reference(specs, snippet, fpu, mmx=False):
    """Run every state under Unicorn. Returns [(initial snapshot, final snapshot)]. mmx: the physical FP
    registers are first given the MMX seeds (mantissa, exponent 0xffff), which is how Unicorn keeps mm."""
    n = len(specs)
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(CODE, 0x1000, UC_PROT_ALL)
    uc.mem_map(DATA, DATA_SIZE, UC_PROT_ALL)
    uc.mem_map(SCRATCH, 0x1000, UC_PROT_ALL)
    if fpu:
        uc.mem_map(SETUP, _round_up((n + 1) * 0x100, 0x1000), UC_PROT_ALL)
    uc.mem_write(CODE, snippet)
    out = []
    for i, sp in enumerate(specs):
        fpu_init = _fpu_setup(uc, i, sp["fpu"]) if fpu else None
        if mmx:
            for p in range(8):
                uc.reg_write(UC_X86_REG_FP0 + p, (sp["mm"][p], 0xFFFF))
        for k, name in enumerate(GPR_NAMES):
            uc.reg_write(GPR_IDS[k], sp["regs"][name])
        uc.mem_write(DATA, sp["data"])
        uc.mem_write(STACK - 4, RET.to_bytes(4, "little"))   # return address for the snippet's ret
        uc.reg_write(UC_X86_REG_ESP, STACK - 4)
        ef = 0x2
        for f, b in sp["flags"].items():
            ef |= b << FLAG_BIT[f]
        uc.reg_write(UC_X86_REG_EFLAGS, ef)
        try:
            uc.emu_start(CODE, RET, count=MAX_INSNS)
        except UcError as e:
            raise _RigError("state %d: Unicorn error: %s" % (i, e))
        if uc.reg_read(UC_X86_REG_EIP) != RET:
            raise _RigError("state %d: snippet did not reach its ret (pc=%08x)"
                            % (i, uc.reg_read(UC_X86_REG_EIP)))
        init = {"regs": [sp["regs"][x] for x in GPR_NAMES], "flags": sp["flags"],
                "data": sp["data"], "fpu": fpu_init, "mm": sp["mm"]}
        final = {"regs": [uc.reg_read(r) for r in GPR_IDS], "flags": _read_flags(uc),
                 "data": bytes(uc.mem_read(DATA, DATA_SIZE)),
                 "fpu": _read_fpu(uc) if fpu else None,
                 "mm": [uc.reg_read(UC_X86_REG_FP0 + p)[0] for p in range(8)] if mmx else None}
        out.append((init, final))
    return out


# ---------------------------------------------------------------- C side

_HARNESS = r"""
#include "cpu.h"
#include <stdio.h>
#include <stdlib.h>

#define DATA_BASE 0x00200000u
#define DATA_SIZE 0x10000u
#define RET_ADDR  0x00401800u

typedef struct {
    double st[8];           /* physical x87 registers */
    uint32_t r[8];
    uint32_t top, tag;      /* tag bit p set = physical p empty */
    uint16_t cw, sw;
    uint8_t fl[8];          /* cf pf af zf sf of df, then 0 */
    uint8_t pad[4];
    uint64_t mm[8];         /* MMX registers (CPU.mm) */
} Head;
_Static_assert(sizeof(Head) == 184, "Head layout");

static uint8_t mem[4u << 20];

void @ENTRY@(CPU *c);

static void guest_call(CPU *c, uint32_t a)
{
    (void)c;
    fprintf(stderr, "insnrig: call_guest %08x: calls are not supported by the rig\n", a);
    exit(3);
}

void lift_call(CPU *c, uint32_t t)
{
    (void)c;
    fprintf(stderr, "insnrig: lift_call %08x: indirect calls are not supported by the rig\n", t);
    exit(3);
}

void lift_call_ret(CPU *c, uint32_t t, uint32_t ret)
{
    (void)ret;
    lift_call(c, t);
}

void lift_jump(CPU *c, uint32_t t)
{
    lift_call(c, t);
}

int lift_is_bridge_ret(uint32_t v)
{
    (void)v;
    return 0;
}

void lift_div_fault(CPU *c, uint32_t va)
{
    (void)c;
    fprintf(stderr, "insnrig: DIVIDE_ERROR %08x\n", va);
    exit(4);
}

void lift_unsupported(CPU *c, uint32_t va, const char *what)
{
    (void)c;
    fprintf(stderr, "insnrig: UNSUPPORTED %08x %s\n", va, what);
    exit(3);
}

uint32_t lift_eflags_sys;      /* misc.c: the EFLAGS bits popfd keeps outside CPU (pushfd/popfd) */

int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    FILE *fi = fopen(argv[1], "rb");
    FILE *fo = fopen(argv[2], "wb");
    uint32_t n;
    if (!fi || !fo || fread(&n, 4, 1, fi) != 1)
        return 2;
    for (uint32_t i = 0; i < n; i++) {
        Head h;
        if (fread(&h, sizeof h, 1, fi) != 1)
            return 2;
        if (fread(mem + DATA_BASE, 1, DATA_SIZE, fi) != DATA_SIZE)
            return 2;
        CPU c;
        memset(&c, 0, sizeof c);
        c.mem = mem;
        c.call_guest = guest_call;
        memcpy(c.r, h.r, sizeof c.r);
        c.cf = h.fl[0]; c.pf = h.fl[1]; c.af = h.fl[2]; c.zf = h.fl[3];
        c.sf = h.fl[4]; c.of = h.fl[5]; c.df = h.fl[6];
        c.top = h.top; c.tag = h.tag; c.cw = h.cw; c.sw = h.sw;
        memcpy(c.st, h.st, sizeof c.st);
        memcpy(c.mm, h.mm, sizeof c.mm);
        push32(&c, RET_ADDR);                 /* lifted code is entered as if by call */
        @ENTRY@(&c);
        memcpy(h.r, c.r, sizeof h.r);
        memcpy(h.st, c.st, sizeof h.st);
        memcpy(h.mm, c.mm, sizeof h.mm);
        h.top = c.top; h.tag = c.tag; h.cw = c.cw; h.sw = c.sw;
        h.fl[0] = c.cf; h.fl[1] = c.pf; h.fl[2] = c.af; h.fl[3] = c.zf;
        h.fl[4] = c.sf; h.fl[5] = c.of; h.fl[6] = c.df; h.fl[7] = 0;
        if (fwrite(&h, sizeof h, 1, fo) != 1 || fwrite(mem + DATA_BASE, 1, DATA_SIZE, fo) != DATA_SIZE)
            return 2;
    }
    fclose(fo);
    return 0;
}
"""


def _build(res):
    """Compile the translated function with the harness. Cached by hash of the sources."""
    main_src = _HARNESS.replace("@ENTRY@", res.name)
    # The runtime headers and sources are part of the key: editing one must not reuse a stale binary.
    rt = "".join(open(p).read() for p in sorted(glob.glob(os.path.join(x86c.RUNTIME, "*.[ch]"))))
    key = hashlib.sha256(("\0".join([res.c, main_src, " ".join(CFLAGS), rt])).encode()).hexdigest()[:32]
    # A cache of our own (lift-out/ is git-ignored): binaries in the shared $TMPDIR cache were
    # intermittently killed by AMFI ("code signature validation failed").
    cache = os.path.join(os.path.dirname(HERE), "lift-out", "insnrig-cache")
    os.makedirs(cache, exist_ok=True)
    exe = os.path.join(cache, key)
    if os.path.exists(exe):
        return exe
    work = tempfile.mkdtemp(prefix="build-", dir=cache)
    try:
        f_c = os.path.join(work, "snippet.c")
        m_c = os.path.join(work, "main.c")
        tmp_exe = os.path.join(work, "a.out")
        with open(f_c, "w") as f:
            f.write(res.c)
        with open(m_c, "w") as f:
            f.write(main_src)
        cc = subprocess.run([CLANG] + CFLAGS + ["-o", tmp_exe, m_c, f_c],
                            capture_output=True, text=True)
        if cc.returncode != 0:
            raise _RigError("clang failed:\n" + cc.stderr[:1500])
        os.replace(tmp_exe, exe)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return exe


def _pack_head(init):
    f = init["fpu"]
    if f:
        st, top, csw = f["st"], f["top"], f["c"]
        tag = sum(1 << p for p in range(8) if f["empty"][p])
    else:
        st, top, tag, csw = [0.0] * 8, 0, 0xff, 0
    fl = [init["flags"][k] for k in FLAG_ORDER] + [0]
    return struct.pack(HEAD_FMT, *st, *init["regs"], top, tag, CW_FIXED, csw, *fl, *init["mm"])


def _run_c(res, inits):
    """Run the translated function on each initial snapshot. Returns the final snapshots."""
    exe = _build(res)
    work = tempfile.mkdtemp(prefix="run-")
    try:
        inp = os.path.join(work, "in.bin")
        outp = os.path.join(work, "out.bin")
        with open(inp, "wb") as f:
            f.write(struct.pack("<I", len(inits)))
            for init in inits:
                f.write(_pack_head(init))
                f.write(init["data"])
        proc = subprocess.run([exe, inp, outp], capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise _RigError("translated code exited with %d: %s"
                            % (proc.returncode, (proc.stderr or proc.stdout).strip()[:500]))
        with open(outp, "rb") as f:
            blob = f.read()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    rec = HEAD_SIZE + DATA_SIZE
    if len(blob) != rec * len(inits):
        raise _RigError("translated code wrote %d bytes, expected %d" % (len(blob), rec * len(inits)))
    finals = []
    for i in range(len(inits)):
        base = i * rec
        v = struct.unpack(HEAD_FMT, blob[base:base + HEAD_SIZE])
        st, regs, top, tag, sw, fl, mm = list(v[0:8]), list(v[8:16]), v[16], v[17], v[19], v[20:28], list(v[28:36])
        fpu = None
        if inits[i]["fpu"] is not None:
            fpu = {"top": top & 7, "c": sw & C_BITS,
                   "empty": [bool((tag >> p) & 1) for p in range(8)], "st": st}
        finals.append({"regs": regs,
                       "flags": {k: fl[j] for j, k in enumerate(FLAG_ORDER)},
                       "data": blob[base + HEAD_SIZE:base + rec],
                       "fpu": fpu, "mm": mm})
    return finals


# ---------------------------------------------------------------- comparison

def _same_double(a, b):
    if a != a and b != b:
        return True
    return struct.pack("<d", a) == struct.pack("<d", b)


def _fpu_diffs(exp, got, values=True):
    """values=False (MMX snippets): TOP, C bits and the tags only; the values live in mm, see _mm_diffs."""
    out = []
    if exp["top"] != got["top"]:
        out.append("TOP expected %d, got %d" % (exp["top"], got["top"]))
    if exp["c"] != got["c"]:
        out.append("C0-C3 expected %04x, got %04x" % (exp["c"], got["c"]))
    top = exp["top"]
    for i in range(8):
        p = (top + i) & 7
        ee, ge = exp["empty"][p], got["empty"][p]
        if ee != ge:
            out.append("ST(%d) expected %s, got %s" % (
                i, "empty" if ee else repr(exp["st"][p]), "empty" if ge else repr(got["st"][p])))
        elif values and not ee and not _same_double(exp["st"][p], got["st"][p]):
            out.append("ST(%d) expected %r, got %r" % (i, exp["st"][p], got["st"][p]))
    return out


def _mm_diffs(exp, got):
    """MMX registers: physical FP mantissas in Unicorn, CPU.mm in the translated code. All eight are compared,
    empty or not, since the emulator keeps the data of an emptied register."""
    return ["MM%d expected %016x, got %016x" % (p, exp[p], got[p])
            for p in range(8) if exp[p] != got[p]]


def _state_diffs(ref, got, compared, fpu, mmx=False):
    out = []
    for k, name in enumerate(GPR_NAMES):
        if ref["regs"][k] != got["regs"][k]:
            out.append("%s expected %08x, got %08x" % (name.upper(), ref["regs"][k], got["regs"][k]))
    for f in FLAG_ORDER:
        if f in compared and ref["flags"][f] != got["flags"][f]:
            out.append("%s expected %d, got %d" % (f.upper(), ref["flags"][f], got["flags"][f]))
    if ref["data"] != got["data"]:
        bad = [o for o in range(DATA_SIZE) if ref["data"][o] != got["data"][o]]
        for o in bad[:4]:
            out.append("mem[%08x] expected %02x, got %02x" % (DATA + o, ref["data"][o], got["data"][o]))
        if len(bad) > 4:
            out.append("(%d data bytes differ in all)" % len(bad))
    if mmx:
        out += _fpu_diffs(ref["fpu"], got["fpu"], values=False)
        out += _mm_diffs(ref["mm"], got["mm"])
    elif fpu:
        out += _fpu_diffs(ref["fpu"], got["fpu"])
    return out


def _describe_init(init, fpu):
    regs = " ".join("%s=%08x" % (n, v) for n, v in zip(GPR_NAMES, init["regs"]) if n != "esp")
    flags = " ".join("%s=%d" % (f.upper(), init["flags"][f]) for f in FLAG_ORDER)
    s = "%s %s" % (regs, flags)
    if fpu and init["fpu"]:
        f = init["fpu"]
        vals = [repr(f["st"][(f["top"] + i) & 7]) for i in range(8)
                if not f["empty"][(f["top"] + i) & 7]]
        s += " | TOP=%d ST=[%s]" % (f["top"], ", ".join(vals))
    return s


# ---------------------------------------------------------------- check

def _flag_set(flags, undefined):
    names = set(FLAG_ORDER) if flags == "all" else set(flags)
    bad = (names | set(undefined)) - set(FLAG_ORDER)
    if bad:
        raise ValueError("unknown flag name(s): %s" % ", ".join(sorted(bad)))
    return names - set(undefined)


def check(code, *, n=200, seed=0, flags="all", undefined=(), mem=None, regs=None,
          fpu=False, label=None, random_df=False, mmx=False):
    """Differentially test one snippet of x86-32 code against the translator.

    code       bytes (or a hex string, see enc). One or more instructions, no control flow out.
    n          number of random initial states.
    seed       RNG seed; the same seed gives the same states.
    flags      "all" (CF PF AF ZF SF OF DF) or an iterable of flag names to compare.
    undefined  flag names the Intel manual leaves undefined for this instruction; not compared.
    mem        bytes written at DATA (0x200000) in every state; the rest of DATA is random.
    regs       {"ecx": range(0, 64), "esi": DATA, "edi": DATA + 0x800}: pin or limit registers.
               An int is fixed, a range or sequence is sampled. Other GPRs are random 32-bit.
               ESP is fixed at STACK.
    fpu        also set up and compare x87 state (see module docstring).
    label      text used in messages (default: dis(code)).
    random_df  sample DF instead of always 0.
    mmx        MMX snippet: implies fpu. Every state also gets 8 random mm values, written into the physical FP
               registers (mantissa, exponent 0xffff) before the run. After the run mm is compared (all eight, as
               physical mantissas), with TOP, the C bits and the tags; st[] is not compared, since MMX
               instructions leave it stale on the translated side (see lift/runtime/cpu.h).

    Returns a Result. Unsupported instructions give a failed Result without running anything.
    """
    if isinstance(code, str):
        code = enc(code)
    code = bytes(code)
    if not code or len(code) > 0x700:
        raise ValueError("snippet must be 1..1791 bytes")
    label = label or dis(code)
    compared = _flag_set(flags, undefined)
    regs = dict(regs or {})
    for k in regs:
        if k not in GPR_NAMES:
            raise ValueError("unknown register %r" % k)
        if k == "esp":
            raise ValueError("ESP is fixed at STACK (0x%08x)" % STACK)
    if mem is not None and len(mem) > DATA_SIZE:
        raise ValueError("mem is larger than the %d-byte data region" % DATA_SIZE)

    snippet = code + b"\xc3"
    res = lift_function(_SnippetImage(snippet), CODE)
    reasons = re.findall(r"/\* not translated: (.*?) \*/", res.c)
    if res.unsupported:
        msgs, k = [], 0
        for va, text in res.unsupported:
            if text == "(bad)":
                why = "undecodable bytes"
            else:
                why = reasons[k] if k < len(reasons) else "no reason given"
                k += 1
            msgs.append("unsupported: '%s' at %08x (%s)" % (text, va, why))
        return Result(ok=False, failures=msgs[:5], n=n, label=label, n_failed=len(msgs),
                      unsupported=list(res.unsupported), stage="translate")
    if res.callees:
        msg = "snippet calls out (%s): calls are not supported by the rig" % (
            ", ".join("%08x" % c for c in res.callees))
        return Result(ok=False, failures=[msg], n=n, label=label, n_failed=1, stage="translate")

    fpu = fpu or mmx
    rng = random.Random(seed)
    specs = [_gen_state(rng, regs, mem, fpu, random_df, mmx) for _ in range(n)]
    try:
        pairs = _run_reference(specs, snippet, fpu, mmx)
        finals = _run_c(res, [p[0] for p in pairs])
    except _RigError as e:
        return Result(ok=False, failures=[str(e)], n=n, label=label, n_failed=1, stage="run")

    failures, n_failed = [], 0
    for i, ((init, ref), got) in enumerate(zip(pairs, finals)):
        diffs = _state_diffs(ref, got, compared, fpu, mmx)
        if diffs:
            n_failed += 1
            if len(failures) < 5:
                failures.append("state %d: init %s\n      %s" % (
                    i, _describe_init(init, fpu), "; ".join(diffs)))
    return Result(ok=n_failed == 0, failures=failures, n=n, label=label, n_failed=n_failed)
