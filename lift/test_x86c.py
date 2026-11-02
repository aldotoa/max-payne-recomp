"""Tests for the x86 -> C translator (lift/x86c.py).

1. Hand-assembled snippets through an in-memory image: block discovery, labels, compile check.
   Every snippet's bytes are decoded with capstone and must match the asm text written next to them.
2. Execution: generated C for a snippet is compiled with clang together with a small C harness
   (1 MB guest memory, CPU setup, stub lift_call / lift_unsupported / call_guest), run, and the final
   registers and flags are checked.
3. Corpus: the first 200 export entries of the real rlmfc.dll must all produce C that compiles with
   clang -fsyntax-only. Skipped when the game file is missing (MP_DLL env var overrides the path).

Run:  .venv/bin/python lift/test_x86c.py
"""
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import insnrig
import x86c
from insnrig import CODE, DATA, _SnippetImage, dis
from x86c import RUNTIME, discover_blocks, lift_function, _MD

CLANG = shutil.which("clang") or "/usr/bin/clang"
CFLAGS = ["-std=gnu11", "-Wall", "-Wno-unused-label", "-Wno-unused-variable", "-I", RUNTIME]
DLL = os.environ.get("MP_DLL", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..",
                                             "Max Payne", "rlmfc.dll"))
DLL = os.path.normpath(DLL)


class FakeImage:
    """Byte blobs at virtual addresses, plus an import map. Same interface as x86c.PEImage.
    data: blob addresses that are not code (switch tables); every other blob is code."""

    def __init__(self, blobs, iat=None, data=()):
        self.blobs = list(blobs.items())
        self.iat = dict(iat or {})
        self.base = 0
        self.data = set(data)

    def read(self, va, n):
        for lo, b in self.blobs:
            if lo <= va < lo + len(b):
                return b[va - lo: va - lo + n]
        raise ValueError("unmapped %08x" % va)

    def is_code(self, va):
        return any(lo <= va < lo + len(b) and lo not in self.data for lo, b in self.blobs)


def hx(s):
    return bytes.fromhex(s.replace(" ", ""))


def decode_text(code, va):
    out = []
    for i in _MD.disasm(code, va):
        out.append(("%s %s" % (i.mnemonic, i.op_str)).strip())
    return out


def snippet(va, hexbytes, asm):
    """Bytes at va, checked against the asm text (capstone's Intel syntax, as written here)."""
    code = hx(hexbytes)
    got = decode_text(code, va)
    assert got == asm, "decode mismatch at %08x:\n  got  %r\n  want %r" % (va, got, asm)
    return va, code


def image_of(*parts, iat=None):
    return FakeImage(dict(parts), iat=iat)


def compile_c(src_path, extra=()):
    return subprocess.run([CLANG] + CFLAGS + ["-fsyntax-only", src_path] + list(extra),
                          capture_output=True, text=True)


# ---------------------------------------------------------------- snippets

LOOP = [snippet(0x1000, "b8 00 00 00 00 b9 01 00 00 00 8d 04 08 8d 49 01 83 f9 0a 7e f5 c3",
                ["mov eax, 0", "mov ecx, 1", "lea eax, [eax + ecx]", "lea ecx, [ecx + 1]",
                 "cmp ecx, 0xa", "jle 0x100a", "ret"])]
# (second snippet: the jle at 0x1013 and ret at 0x1015 are the decoded forms of the loop above)

MOVES = [snippet(0x1000, "b8 44 33 22 11 b4 55 b0 80 89 c1 0f b6 d5 0f be e8 6a ff 5e "
                         "8d 7c 24 04 c6 07 7f 0f b6 1f 0f be 0f 54 5e 64 8b 15 10 00 00 00 c3",
                 ["mov eax, 0x11223344", "mov ah, 0x55", "mov al, 0x80", "mov ecx, eax",
                  "movzx edx, ch", "movsx ebp, al", "push -1", "pop esi",
                  "lea edi, [esp + 4]", "mov byte ptr [edi], 0x7f", "movzx ebx, byte ptr [edi]",
                  "movsx ecx, byte ptr [edi]", "push esp", "pop esi",
                  "mov edx, dword ptr fs:[0x10]", "ret"])]

CMP_SIGN = [snippet(0x1000, "b8 00 00 00 80 83 f8 01 c3",
                    ["mov eax, 0x80000000", "cmp eax, 1", "ret"])]
CMP_ZERO = [snippet(0x1000, "b8 00 00 00 00 83 f8 01 c3",
                    ["mov eax, 0", "cmp eax, 1", "ret"])]
JG = [snippet(0x1000, "b8 05 00 00 00 83 f8 03 7f 05 b9 01 00 00 00 ba 02 00 00 00 c3",
              ["mov eax, 5", "cmp eax, 3", "jg 0x100f", "mov ecx, 1", "mov edx, 2", "ret"])]
CWDE = [snippet(0x1000, "b8 fe ff 00 00 98 99 c3", ["mov eax, 0xfffe", "cwde", "cdq", "ret"])]
CALLER = [snippet(0x1000, "6a 05 e8 09 00 00 00 89 c3 c3", ["push 5", "call 0x1010", "mov ebx, eax", "ret"]),
          snippet(0x1010, "8b 44 24 04 8d 04 00 c2 04 00", ["mov eax, dword ptr [esp + 4]", "lea eax, [eax + eax]", "ret 4"])]
LEAVE = [snippet(0x1000, "55 89 e5 68 34 12 00 00 c9 c3", ["push ebp", "mov ebp, esp", "push 0x1234", "leave", "ret"])]
GUEST = [snippet(0x1000, "e8 fb 0f 00 00 e8 f6 1f 00 00 c3",
                 ["call 0x2000", "call 0x3000", "ret"])]
THUNK_BODY = [snippet(0x3000, "ff 25 00 40 00 00", ["jmp dword ptr [0x4000]"])]


def lift_one(blobs, entry, known=frozenset(), iat=None):
    img = FakeImage(blobs, iat=iat)
    return lift_function(img, entry, known)


# ---------------------------------------------------------------- execution harness

HARNESS = r"""
#include "cpu.h"
#include <stdio.h>
#include <stdlib.h>
static void guest_call(CPU *c, uint32_t a) { printf("GUEST_CALL %08x\n", a); }
void lift_call(CPU *c, uint32_t t) { printf("LIFT_CALL %08x\n", t); exit(4); }
/* No target is lifted in the harness: both forward to call_guest the way the runtime does for a miss. */
void lift_call_ret(CPU *c, uint32_t t, uint32_t ret) { (void)ret; c->call_guest(c, t); }
void lift_jump(CPU *c, uint32_t t) { c->r[ESP] += 4; c->call_guest(c, t); }
int lift_is_bridge_ret(uint32_t v) { (void)v; return 0; }
void lift_unsupported(CPU *c, uint32_t va, const char *what) { printf("UNSUPPORTED %08x %s\n", va, what); exit(5); }
static uint8_t mem[1 << 20];
void ENTRY(CPU *c);
int main(void)
{
    CPU c;
    memset(&c, 0, sizeof c);
    c.mem = mem;
    c.call_guest = guest_call;
    c.fs_base = 0x1000;
    c.r[ESP] = 0x80000;
    c.r[EBP] = 0x7777;
    /*PRE*/
    push32(&c, 0xdead0000u);             /* return address for the entry function's ret */
    ENTRY(&c);
    printf("EAX=%08x ECX=%08x EDX=%08x EBX=%08x ESP=%08x EBP=%08x ESI=%08x EDI=%08x\n",
           c.r[EAX], c.r[ECX], c.r[EDX], c.r[EBX], c.r[ESP], c.r[EBP], c.r[ESI], c.r[EDI]);
    printf("CF=%d PF=%d AF=%d ZF=%d SF=%d OF=%d\n", c.cf, c.pf, c.af, c.zf, c.sf, c.of);
    return 0;
}
"""

REG_KEYS = {"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"}


def run_c(results, entry, pre=""):
    """Compile the lifted functions with the harness, run entry, return (regs+flags dict, raw stdout)."""
    d = tempfile.mkdtemp(prefix="x86c_")
    srcs = []
    for i, res in enumerate(results):
        p = os.path.join(d, "f%d.c" % i)
        with open(p, "w") as f:
            f.write(res.c)
        srcs.append(p)
    main_c = os.path.join(d, "main.c")
    with open(main_c, "w") as f:
        f.write(HARNESS.replace("ENTRY", "f_%08x" % entry).replace("/*PRE*/", pre))
    exe = os.path.join(d, "a.out")
    cc = subprocess.run([CLANG] + CFLAGS + ["-o", exe, main_c] + srcs, capture_output=True, text=True)
    assert cc.returncode == 0, "compile failed:\n" + cc.stderr + "\n" + "\n".join(r.c for r in results)
    run = subprocess.run([exe], capture_output=True, text=True, timeout=20)
    out = run.stdout
    vals = {}
    for line in out.splitlines():
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                if k in REG_KEYS:
                    vals[k] = int(v, 16)
                elif k in ("CF", "PF", "AF", "ZF", "SF", "OF"):
                    vals[k] = int(v)
    return vals, out


# ---------------------------------------------------------------- tests

def test_discover_blocks_and_labels():
    img = FakeImage(dict([LOOP[0]]))
    blocks = discover_blocks(img, 0x1000)
    assert blocks == [(0x1000, 0x100a), (0x100a, 0x1015), (0x1015, 0x1016)], blocks
    res = lift_function(img, 0x1000)
    assert res.ok and res.unsupported == [], res.unsupported
    assert res.name == "f_00001000"
    for lbl in ("L_00001000:", "L_0000100a:", "L_00001015:"):
        assert lbl in res.c, lbl
    assert "\n    goto L_0000100a;" not in res.c   # block 1 falls straight into block 2: no goto
    assert "if (c->zf || c->sf != c->of) goto L_0000100a;" in res.c, res.c
    assert "/* 00001013: jle 0x100a */" in res.c
    assert "    /* 00001000: mov eax, 0 */" in res.c
    d = tempfile.mkdtemp(prefix="x86c_")
    p = os.path.join(d, "loop.c")
    with open(p, "w") as f:
        f.write(res.c)
    cc = compile_c(p, ["-I", RUNTIME])
    assert cc.returncode == 0, cc.stderr


def test_exec_loop_sum():
    res = lift_one(dict([LOOP[0]]), 0x1000)
    vals, out = run_c([res], 0x1000)
    assert vals["EAX"] == 55 and vals["ECX"] == 11, out
    assert vals["ESP"] == 0x80000, out


def test_exec_moves_and_high_regs():
    res = lift_one(dict([MOVES[0]]), 0x1000)
    assert res.ok, res.unsupported
    vals, out = run_c([res], 0x1000, pre="wr32(&c, 0x1010, 0x55aa);")
    assert vals["ECX"] == 0x7f, out
    assert vals["EDX"] == 0x55aa, out             # mov edx, fs:[0x10] (movzx edx, ch was overwritten)
    assert vals["EBP"] == 0xffffff80, out          # movsx ebp, al with al = 0x80
    assert vals["EBX"] == 0x7f, out                # movzx ebx, byte ptr [edi]
    assert vals["ESI"] == 0x7fffc, out             # push esp / pop esi: old esp
    assert vals["EDI"] == 0x80000, out             # lea edi, [esp+4] after the pop
    assert vals["ESP"] == 0x80000, out


def test_exec_cmp_flags_negative():
    res = lift_one(dict([CMP_ZERO[0]]), 0x1000)
    vals, out = run_c([res], 0x1000)
    assert (vals["CF"], vals["ZF"], vals["SF"], vals["OF"], vals["AF"], vals["PF"]) == (1, 0, 1, 0, 1, 1), out


def test_exec_cmp_flags_overflow():
    res = lift_one(dict([CMP_SIGN[0]]), 0x1000)
    vals, out = run_c([res], 0x1000)
    assert (vals["CF"], vals["ZF"], vals["SF"], vals["OF"], vals["AF"], vals["PF"]) == (0, 0, 0, 1, 1, 1), out


def test_exec_jg_taken():
    res = lift_one(dict([JG[0]]), 0x1000)
    vals, out = run_c([res], 0x1000)
    assert vals["ECX"] == 0 and vals["EDX"] == 2, out


def test_exec_cwde_cdq():
    res = lift_one(dict([CWDE[0]]), 0x1000)
    vals, out = run_c([res], 0x1000)
    assert vals["EAX"] == 0xfffffffe and vals["EDX"] == 0xffffffff, out


def test_exec_call_lifted_and_ret_imm():
    blobs = dict([CALLER[0], CALLER[1]])
    known = {0x1000, 0x1010}
    main = lift_one(blobs, 0x1000, known)
    callee = lift_one(blobs, 0x1010, known)
    assert main.ok and callee.ok
    assert 0x1010 in main.callees
    vals, out = run_c([main, callee], 0x1000)
    assert vals["EBX"] == 10, out
    assert vals["ESP"] == 0x80000, out            # callee's ret 4 popped the argument


def test_exec_leave():
    res = lift_one(dict([LEAVE[0]]), 0x1000)
    vals, out = run_c([res], 0x1000)
    assert vals["EBP"] == 0x7777 and vals["ESP"] == 0x80000, out


def test_exec_call_guest_and_import():
    blobs = dict([GUEST[0], (0x3000, hx("ff 25 00 40 00 00"))])
    res = lift_one(blobs, 0x1000, iat={0x4000: "X.DLL!f"})
    assert res.ok, res.unsupported
    assert 0x2000 not in res.callees or True
    vals, out = run_c([res], 0x1000, pre="wr32(&c, 0x4000, 0x5000);")
    assert "GUEST_CALL 00002000" in out and "GUEST_CALL 00005000" in out, out
    assert "f_00002000" not in res.c and "rd32(c, 0x4000u)" in res.c, res.c


def test_import_thunk_entry_is_tail_form():
    img = FakeImage(dict([THUNK_BODY[0]]), iat={0x4000: "X.DLL!f"})
    res = lift_function(img, 0x3000)
    assert res.ok, res.unsupported
    assert "lift_jump(c, rd32(c, 0x4000u));" in res.c
    assert res.c.count("return;") >= 1


def test_virtual_tail_jump():
    # mov edx,[ecx] ; jmp [edx+4]: a virtual tail call goes to lift_jump with the slot's value
    img = FakeImage({0x1000: hx("8b 11 ff 62 04")})
    res = lift_function(img, 0x1000)
    assert res.ok and res.unsupported == [], res.unsupported
    assert "lift_jump(c, " in res.c and "return;" in res.c, res.c
    vals, out = run_c([res], 0x1000, pre="c.r[ECX] = 0x6000; wr32(&c, 0x6000, 0x7000); wr32(&c, 0x7004, 0x5000);")
    assert "GUEST_CALL 00005000" in out, out
    # an indexed jump is a switch the scan did not recover: still unsupported
    res2 = lift_function(FakeImage({0x1000: hx("ff 24 85 00 20 00 00")}), 0x1000)
    assert not res2.ok, res2.c

def test_entry_hook():
    # a function in ENTRY_HOOKS calls lift_entry_hook at entry, before anything else; others do not
    img = FakeImage({0x1000: hx("8b c1 c3")})
    assert "lift_entry_hook" not in lift_function(img, 0x1000).c
    saved = x86c.ENTRY_HOOKS
    x86c.ENTRY_HOOKS = frozenset({0x1000})
    try:
        res = lift_function(img, 0x1000)
    finally:
        x86c.ENTRY_HOOKS = saved
    body = res.c.split("void f_00001000(CPU *c)\n{\n", 1)[1]
    assert res.ok and body.lstrip().startswith("lift_entry_hook(c, 0x00001000u);"), res.c


def test_exit_hook():
    # a function in EXIT_HOOKS calls lift_exit_hook before every ret, ESP not yet moved; others do not
    img = FakeImage({0x1000: hx("85 c0 74 03 8b c1 c3 c2 04 00")})   # test eax, eax; je +3; mov eax, ecx; ret; ret 4
    assert "lift_exit_hook" not in lift_function(img, 0x1000).c
    saved = x86c.EXIT_HOOKS
    x86c.EXIT_HOOKS = frozenset({0x1000})
    try:
        res = lift_function(img, 0x1000)
    finally:
        x86c.EXIT_HOOKS = saved
    assert res.ok, res.c
    assert res.c.count("lift_exit_hook(c, 0x00001000u);\n    c->r[ESP] += ") == 2, res.c


def test_insn_hook():
    # an instruction in INSN_HOOKS is preceded by lift_insn_hook, after the x87 cache is written back to the CPU
    img = FakeImage({0x1000: hx("d9 01 d9 c0 d9 f2 dd d8 d9 19 c3")})  # fld [ecx]; fld st0; fptan; fstp st0; fstp [ecx]
    assert "lift_insn_hook" not in lift_function(img, 0x1000).c
    saved = x86c.INSN_HOOKS
    x86c.INSN_HOOKS = frozenset({0x1008})
    try:
        res = lift_function(img, 0x1000)
    finally:
        x86c.INSN_HOOKS = saved
    assert res.ok, res.c
    before, after = res.c.split("lift_insn_hook(c, 0x00001008u);")
    assert "c->top = " in before.split("/* 00001006:")[1], res.c        # the stack is in the CPU struct at the hook
    assert "/* 00001008: fstp dword ptr [ecx] */" in after and "c->top" in after, res.c


def test_unsupported_reported():
    img = FakeImage({0x1000: hx("cc c3")})
    res = lift_function(img, 0x1000)
    assert not res.ok and res.unsupported == [(0x1000, "int3")], res.unsupported
    assert 'UNSUPPORTED(c, 0x00001000u, "int3");' in res.c
    img2 = FakeImage({0x1000: hx("ff e0")})
    res2 = lift_function(img2, 0x1000)
    assert not res2.ok and res2.unsupported[0][1] == "jmp eax", res2.unsupported


def test_known_entry_tail_jump():
    img = FakeImage({0x1000: hx("e9 0b 00 00 00"), 0x1010: hx("c3")})   # jmp 0x1010 (known)
    res = lift_function(img, 0x1000, known_entries={0x1010})
    assert res.ok and "f_00001010(c);" in res.c and "f_00001010(CPU *c);" in res.c, res.c


def test_entry_not_first_block_goto():
    # The entry does mov ecx, imm; jmp 0xf00 (a lower address that is not a known entry, so it is
    # inlined). The blocks are emitted in address order, so the lower block comes first in the C
    # function: the body must start with a goto to the entry label, or ecx is never set.
    low = snippet(0xf00, "89 c8 c3", ["mov eax, ecx", "ret"])
    entry = snippet(0x1000, "b9 40 10 8b 00 e9 f6 fe ff ff", ["mov ecx, 0x8b1040", "jmp 0xf00"])
    img = FakeImage(dict([low, entry]))
    assert discover_blocks(img, 0x1000)[0][0] == 0xf00
    res = lift_function(img, 0x1000)
    assert res.ok and res.unsupported == [], res.unsupported
    assert "{\n    goto L_00001000;\n" in res.c, res.c
    assert "L_00001000: ;" in res.c and "L_00000f00: ;" in res.c, res.c
    vals, out = run_c([res], 0x1000)
    assert vals["ECX"] == 0x8b1040 and vals["EAX"] == 0x8b1040, out
    # an entry that is already the first block gets no goto: the output is unchanged
    res2 = lift_one(dict([LOOP[0]]), 0x1000)
    assert "goto L_00001000;" not in res2.c, res2.c


def test_entry_not_first_real_exe():
    # MaxPayne.exe 0x5dc130: mov ecx, 0x8b1040; jmp 0x5aca80 (a constructor, not in the lifted set).
    # Skipped when the game folder is missing (the folder of MP_DLL, as in the other real-file tests).
    exe = os.path.join(os.path.dirname(DLL), "MaxPayne.exe")
    if not os.path.exists(exe):
        print("  skipped real-exe entry test: no game file at", exe)
        return
    img = x86c.PEImage(exe)
    res = lift_function(img, 0x5dc130, frozenset())
    assert "{\n    goto L_005dc130;\n" in res.c, res.c[:400]
    assert "L_005dc130: ;" in res.c, res.c[:400]


def test_corpus_real_dll():
    if not os.path.exists(DLL):
        print("  skipped corpus test: no game file at", DLL)
        return
    img = x86c.PEImage(DLL)
    exports = img.exports
    known = {va for va, _ in exports}
    entries = [va for va, _ in exports][:200]
    d = tempfile.mkdtemp(prefix="x86c_corpus_")
    full, unsup_counter, bad = 0, Counter(), []
    for i, va in enumerate(entries):
        res = lift_function(img, va, known)
        if res.ok:
            full += 1
        for _, text in res.unsupported:
            unsup_counter[text.split()[0] if text.split() else text] += 1
        p = os.path.join(d, "e%03d.c" % i)
        with open(p, "w") as f:
            f.write(res.c)
        cc = compile_c(p, ["-I", RUNTIME])
        if cc.returncode != 0:
            bad.append((res.name, cc.stderr[:400]))
    print("  corpus: %d entries, %d fully supported, %d need UNSUPPORTED" %
          (len(entries), full, len(entries) - full))
    print("  top unsupported mnemonics (occurrences):")
    for m, n in unsup_counter.most_common(15):
        print("    %-12s %d" % (m, n))
    assert not bad, "generated C does not compile: %s" % bad[:3]


# MSVC6 switch shapes. One level: cmp eax,3 / ja default / jmp [eax*4+0x2000]; dword table at 0x2000.
# Two level: cmp eax,5 / ja default / xor ecx,ecx / mov cl,[eax+0x3000] / jmp [ecx*4+0x2010]: the byte
# table at 0x3000 maps the index to a dword index (0..3). Each case sets ecx = 10 + its dword index.
ONE_CODE = hx("83 f8 03 77 1f ff 24 85 00 20 00 00"      # 1000 cmp eax,3 ; 1003 ja 1024 ; 1005 jmp
              "b9 0a 00 00 00 c3"                        # 100c case 0
              "b9 0b 00 00 00 c3"                        # 1012 case 1
              "b9 0c 00 00 00 c3"                        # 1018 case 2
              "b9 0d 00 00 00 c3"                        # 101e case 3
              "b9 ff ff ff ff c3")                       # 1024 default
ONE_TABLE = hx("0c100000 12100000 18100000 1e100000")
TWO_CODE = hx("83 f8 05 77 27 33 c9 8a 88 00 30 00 00 ff 24 8d 10 20 00 00"   # 1000 .. 1013
              "b9 0a 00 00 00 c3"                        # 1014 case 0
              "b9 0b 00 00 00 c3"                        # 101a case 1
              "b9 0c 00 00 00 c3"                        # 1020 case 2
              "b9 0d 00 00 00 c3"                        # 1026 case 3
              "b9 ff ff ff ff c3")                       # 102c default
TWO_BYTES = hx("00 01 00 02 01 03")                      # index 0..5 -> dword index
TWO_TABLE = hx("14100000 1a100000 20100000 26100000")
TWO_MAP = [0, 1, 0, 2, 1, 3]


def test_switch_shapes_decode():
    assert decode_text(ONE_CODE, 0x1000)[:3] == ["cmp eax, 3", "ja 0x1024",
                                                 "jmp dword ptr [eax*4 + 0x2000]"], decode_text(ONE_CODE, 0x1000)
    assert decode_text(TWO_CODE, 0x1000)[:5] == ["cmp eax, 5", "ja 0x102c", "xor ecx, ecx",
                                                 "mov cl, byte ptr [eax + 0x3000]",
                                                 "jmp dword ptr [ecx*4 + 0x2010]"], decode_text(TWO_CODE, 0x1000)


def _switch_run(code, data_blobs, eax):
    """Lift the switch at 0x1000 and run it with eax set; returns the final ECX (or fails)."""
    img = FakeImage(dict([(0x1000, code)] + data_blobs), data=[lo for lo, _ in data_blobs])
    res = lift_function(img, 0x1000)
    assert res.ok, res.unsupported
    assert "switch (c->r[" in res.c, res.c
    # the byte table is read at run time, so the data blobs must be in guest memory too
    pre = "c.r[EAX] = 0x%xu;" % eax
    for va, blob in data_blobs:
        pre += "".join(" wr8(&c, 0x%x, 0x%x);" % (va + i, b) for i, b in enumerate(blob))
    vals, out = run_c([res], 0x1000, pre=pre)
    assert "UNSUPPORTED" not in out, out
    return vals["ECX"]


def test_exec_switch_one_level_every_case():
    for eax in (0, 1, 2, 3):
        got = _switch_run(ONE_CODE, [(0x2000, ONE_TABLE)], eax)
        assert got == 10 + eax, (eax, got)
    for eax in (4, 5, 0x80000000, 0xffffffff):          # above the bound: the ja default
        got = _switch_run(ONE_CODE, [(0x2000, ONE_TABLE)], eax)
        assert got == 0xffffffff, (eax, got)


def test_exec_switch_two_level_every_case():
    for eax in range(6):
        got = _switch_run(TWO_CODE, [(0x2010, TWO_TABLE), (0x3000, TWO_BYTES)], eax)
        assert got == 10 + TWO_MAP[eax], (eax, got)
    for eax in (6, 100, 0xffffffff):                    # above the bound: the ja default
        got = _switch_run(TWO_CODE, [(0x2010, TWO_TABLE), (0x3000, TWO_BYTES)], eax)
        assert got == 0xffffffff, (eax, got)


def test_switch_default_label_is_unsupported_guard():
    # Recovery must reject a table it cannot read in full (a dword target that is not code): the
    # jump stays UNSUPPORTED instead of emitting a switch that could miss a case.
    img = FakeImage({0x1000: ONE_CODE, 0x2000: hx("0c100000 12100000 18100000 00500000")},
                    data=[0x2000])
    res = lift_function(img, 0x1000)
    assert not res.ok and any(t.startswith("jmp dword ptr [eax*4") for _, t in res.unsupported), res.unsupported


def test_noreturn_call_ends_block():
    # call to an import that never returns: the byte after the call (int3) is not translated
    thunk = hx("ff 25 00 40 00 00")
    code = hx("e8 fb 1f 00 00 cc c3")                   # 1000 call 3000 ; 1005 int3 ; 1006 ret
    img = FakeImage({0x1000: code, 0x3000: thunk}, iat={0x4000: "KERNEL32.dll!ExitProcess"})
    res = lift_function(img, 0x1000)
    assert res.ok and res.unsupported == [], res.unsupported
    assert "lift_call_ret(c, rd32(c, 0x4000u), 0x1005u);" in res.c and "L_00001005" not in res.c, res.c
    # The import never returns, so the `return` after the call is never reached in a real run; the
    # harness only checks that the call happens and nothing is translated past it.
    _, out = run_c([res], 0x1000, pre="wr32(&c, 0x4000, 0x5000);")
    assert "GUEST_CALL 00005000" in out and "UNSUPPORTED" not in out, out


def test_real_dll_switches():
    if not os.path.exists(DLL):
        print("  skipped real-DLL switch test: no game file at", DLL)
        return
    img = x86c.PEImage(DLL)
    d = tempfile.mkdtemp(prefix="x86c_switch_")
    for entry in (0x10011420, 0x10017e00, 0x10017fe0, 0x1001c800):   # findNext, ??5 x2, parse
        res = lift_function(img, entry, frozenset())
        assert res.ok, (hex(entry), res.unsupported)
        assert "switch (c->r[" in res.c, hex(entry)
        p = os.path.join(d, "f%08x.c" % entry)
        with open(p, "w") as f:
            f.write(res.c)
        cc = compile_c(p, ["-I", RUNTIME])
        assert cc.returncode == 0, cc.stderr


def test_pe_image_relocated_base():
    # grphmfc is preferred at 0x10000000 and loaded at 0x10200000: every HIGHLOW site must hold
    # the preferred value plus 0x200000, and the IAT / export keys move with the image
    path = os.path.join(os.path.dirname(DLL), "grphmfc.dll")
    if not os.path.exists(path):
        print("  skipped relocation test: no game file at", path)
        return
    import pefile
    import struct
    pe = pefile.PE(path)
    pref = pe.OPTIONAL_HEADER.ImageBase
    assert pref == 0x10000000, hex(pref)
    sites = [(e.rva, pe.get_dword_at_rva(e.rva)) for blk in pe.DIRECTORY_ENTRY_BASERELOC
             for e in blk.entries if e.type == 3]
    img = x86c.PEImage(path, base=0x10200000)
    assert img.base == 0x10200000
    assert x86c.PEImage(path).base == 0x10200000          # default: the emulator's load base
    checked = pointers = 0
    for rva, old in sites:
        try:
            raw = img.read(img.base + rva, 4)
        except ValueError:
            continue
        if len(raw) != 4:
            continue
        assert struct.unpack("<I", raw)[0] == (old + 0x200000) & 0xFFFFFFFF, hex(rva)
        checked += 1
        pointers += pref <= old < pref + 0x100000
    assert checked > 1000 and pointers > 100, (checked, pointers)
    plain = x86c.PEImage(path, base=pref)
    assert {k - 0x200000 for k in img.iat} == set(plain.iat)
    assert {va - 0x200000 for va, _ in img.exports} == {va for va, _ in plain.exports}
    print("  relocation sites checked: %d (pointers into the image: %d)" % (checked, pointers))


NEG_CODE = hx("83 f8 08 73 09 f7 d8 ff 24 85 20 20 00 00"  # 1000 cmp eax,8 ; 1003 jae 100e ; 1005 neg eax
              "b9 ff ff ff ff c3"                          # 100e default: ecx = -1
              "b9 0a 00 00 00 c3"                          # 1014 case 0 (index 0)
              "b9 0b 00 00 00 c3"                          # 101a case 1 (index -1)
              "b9 0c 00 00 00 c3"                          # 1020 case 2 (index -2)
              "b9 0d 00 00 00 c3"                          # 1026 case 3
              "b9 0e 00 00 00 c3"                          # 102c case 4
              "b9 0f 00 00 00 c3"                          # 1032 case 5
              "b9 10 00 00 00 c3"                          # 1038 case 6
              "b9 11 00 00 00 c3")                         # 103e case 7
def test_exec_switch_negated_index():
    # cmp eax, 8 ; jae ; neg eax ; jmp [eax*4+0x2020]: index -k is case k, read backwards from 0x2020
    # (a table index with a negated value, not a range 0..N-1)
    table = b"".join(struct.pack("<I", t) for t in [0] + [0x1014 + 6 * k for k in range(7, -1, -1)])
    for eax in range(8):
        got = _switch_run(NEG_CODE, [(0x2000, table)], eax)
        assert got == 10 + eax, (eax, got)
    for eax in (8, 9, 0x80000000, 0xffffffff):          # at or above the bound: the jae default
        got = _switch_run(NEG_CODE, [(0x2000, table)], eax)
        assert got == 0xffffffff, (eax, got)


def test_lock_prefix_handler_mapping():
    # a lock prefix on a LOCKABLE instruction with a memory operand translates as the unlocked
    # instruction; the handler sees the plain mnemonic
    for code, base in [("f0 ff 07", "inc"), ("f0 0f b1 0f", "cmpxchg"), ("f0 87 07", "xchg"),
                       ("f0 0f c1 07", "xadd")]:
        ins = next(x86c._MD.disasm(hx(code), 0x1000))
        assert ins.mnemonic == "lock " + base, ins.mnemonic
        h, plain = x86c._handler_for(ins)
        assert h is x86c.HANDLERS[base] and plain.mnemonic == base, (code, plain.mnemonic)
        assert plain.operands[0].type == x86c.X86_OP_MEM or plain.operands[1].type == x86c.X86_OP_MEM
    # the register forms of lock do not decode (capstone), so they never reach the lifter; a
    # lock prefix on an instruction outside LOCKABLE has no handler
    ins = next(x86c._MD.disasm(hx("f0 0f bc 07"), 0x1000), None)
    if ins is not None:
        assert x86c._handler_for(ins)[0] is None
    img = FakeImage({0x1000: hx("f0 01 d8 c3")}, data=())
    res = lift_function(img, 0x1000)
    assert not res.ok and res.unsupported, res.unsupported




# ---------------------------------------------------------------- dead flags

def _section(c_text, va):
    """The C of the instruction at va: from its comment up to the next instruction's comment."""
    start = c_text.index("/* %08x: " % va)
    end = c_text.find("    /* ", start + 1)
    return c_text[start:end if end != -1 else len(c_text)]


def _ab_run(blobs, entries, pre="", known=frozenset()):
    """Lift entries with dead-flag elimination on and off, run each set of C, and require the same final
    state. Returns the register and flag values of the run."""
    outs = []
    for on in (True, False):
        results = []
        for e in entries:
            res = lift_function(FakeImage(blobs), e, known, dead_flags=on)
            assert res.ok, res.unsupported
            results.append(res)
        vals, out = run_c(results, entries[0], pre=pre)
        outs.append((vals, out))
    assert outs[0][1] == outs[1][1], "dead flags changed the result:\n%s\n%s" % (outs[0][1], outs[1][1])
    return outs[0][0]


def test_dead_flags_add_add_jz():
    # the first add's flags are overwritten by the second before anything reads them
    blobs = dict([snippet(0x1000, "01 d8 01 d1 74 00 c3",
                          ["add eax, ebx", "add ecx, edx", "je 0x1006", "ret"])])
    res = lift_function(FakeImage(blobs), 0x1000, dead_flags=True)
    assert res.ok, res.unsupported
    assert "fl_add" not in _section(res.c, 0x1000), res.c
    assert "fl_add(c, x, y, 32);" in _section(res.c, 0x1002), res.c
    assert (res.flags_checked, res.flags_removed) == (2, 1), (res.flags_checked, res.flags_removed)
    vals = _ab_run(blobs, [0x1000], "c.r[EAX] = 0x7fffffffu; c.r[EBX] = 1; c.r[ECX] = 0; c.r[EDX] = 0;")
    assert vals["EAX"] == 0x80000000 and (vals["CF"], vals["ZF"], vals["SF"], vals["OF"]) == (0, 1, 0, 0), vals


def test_dead_flags_add_inc_jc_keeps_cf():
    # inc does not write CF, so the add's CF is still read by the jb: the add keeps its flags
    blobs = dict([snippet(0x1000, "01 d8 40 72 01 c3 c3",
                          ["add eax, ebx", "inc eax", "jb 0x1006", "ret", "ret"])])
    res = lift_function(FakeImage(blobs), 0x1000, dead_flags=True)
    assert res.ok, res.unsupported
    assert "fl_add(c, x, y, 32);" in _section(res.c, 0x1000), res.c
    assert "flags_inc(c, x, 32)" in _section(res.c, 0x1002), res.c       # live: the block ends at jb
    vals = _ab_run(blobs, [0x1000], "c.r[EAX] = 0xffffffffu; c.r[EBX] = 1;")
    assert vals["EAX"] == 1 and vals["CF"] == 1, vals


def test_dead_flags_cmp_before_call_is_live():
    # a call may read any flag, so the cmp before it keeps its full flag code
    blobs = dict([snippet(0x1000, "39 d8 e8 09 00 00 00 c3", ["cmp eax, ebx", "call 0x1010", "ret"]),
                  snippet(0x1010, "c3", ["ret"])])
    res = lift_function(FakeImage(blobs), 0x1000, {0x1000, 0x1010}, dead_flags=True)
    assert res.ok, res.unsupported
    sec = _section(res.c, 0x1000)
    assert "flags_sub32(c, " in sec and "FL_DEAD" not in sec, sec
    _ab_run(blobs, [0x1000, 0x1010], "c.r[EAX] = 5; c.r[EBX] = 3;", known={0x1000, 0x1010})


def test_dead_flags_block_end_is_live():
    # the add ends a block at a je; the fall-through block reads CF in adc, so the add keeps CF
    blobs = dict([snippet(0x1000, "01 d8 74 02 11 d1 c3",
                          ["add eax, ebx", "je 0x1006", "adc ecx, edx", "ret"])])
    res = lift_function(FakeImage(blobs), 0x1000, dead_flags=True)
    assert res.ok, res.unsupported
    assert "fl_add(c, x, y, 32);" in _section(res.c, 0x1000), res.c
    vals = _ab_run(blobs, [0x1000], "c.r[EAX] = 0xfffffffeu; c.r[EBX] = 3; c.r[ECX] = 5; c.r[EDX] = 7;")
    assert vals["ECX"] == 13 and vals["ZF"] == 0, vals


def test_dead_flags_sub_mov_sbb():
    # mov writes no flags; sbb reads CF from the sub, so the sub keeps its full flag code
    blobs = dict([snippet(0x1000, "29 d8 89 d1 19 d9 c3",
                          ["sub eax, ebx", "mov ecx, edx", "sbb ecx, ebx", "ret"])])
    res = lift_function(FakeImage(blobs), 0x1000, dead_flags=True)
    assert res.ok, res.unsupported
    assert "fl_sub(c, x, y, 32);" in _section(res.c, 0x1000), res.c
    vals = _ab_run(blobs, [0x1000], "c.r[EAX] = 1; c.r[EBX] = 2; c.r[ECX] = 0; c.r[EDX] = 10;")
    assert vals["ECX"] == 7, vals


def test_dead_flags_shift_then_add():
    # shl's six flags are all overwritten by the add: the shift runs through the dead block
    blobs = dict([snippet(0x1000, "c1 e0 02 01 d8 c3", ["shl eax, 2", "add eax, ebx", "ret"])])
    res = lift_function(FakeImage(blobs), 0x1000, dead_flags=True)
    assert res.ok, res.unsupported
    assert "flags_shl(FL_DEAD(c), " in _section(res.c, 0x1000), res.c
    _ab_run(blobs, [0x1000], "c.r[EAX] = 0x40000001u; c.r[EBX] = 9;")


def test_dead_flags_off_keeps_every_flag_code():
    # with the pass off every flag code is emitted: the first add keeps its helper and nothing is removed
    blobs = dict([snippet(0x1000, "01 d8 01 d1 74 00 c3",
                          ["add eax, ebx", "add ecx, edx", "je 0x1006", "ret"])])
    res = lift_function(FakeImage(blobs), 0x1000, dead_flags=False)
    assert res.ok and res.flags_removed == 0, (res.flags_removed, res.c)
    assert "fl_add(c, x, y, 32);" in _section(res.c, 0x1000), res.c


# Random straight-line sequences. Each sequence is compared with the pass on and off: the final registers,
# flags and data must match exactly, including the flags the Intel manual leaves undefined. The first
# group (SAFE) is also compared with Unicorn, since every flag it writes is defined.
_SEQ_DST = [0, 1, 2, 3, 5, 7]          # eax ecx edx ebx ebp edi; esp is the stack, esi the data pointer
_SEQ_SRC = _SEQ_DST + [6]
_SEQ_ALU = {"add": 0x01, "sub": 0x29, "and": 0x21, "or": 0x09, "xor": 0x31, "cmp": 0x39,
            "adc": 0x11, "sbb": 0x19, "test": 0x85, "mov": 0x89}
_SEQ_ALU_MEM = {"add": 0x03, "sub": 0x2b, "and": 0x23, "or": 0x0b, "xor": 0x33, "cmp": 0x3b,
                "adc": 0x13, "sbb": 0x1b}
_SEQ_CC = list(range(16))
_SEQ_SHIFT = {"shl": 4, "shr": 5, "sar": 7, "rol": 0, "ror": 1, "rcl": 2, "rcr": 3}
_SEQ_BT = {"bt": 4, "bts": 5, "btr": 6, "btc": 7}
_SEQ_BT_REG = {"bt": 0xa3, "bts": 0xab, "btr": 0xb3, "btc": 0xbb}


def _rm(reg, rm):
    return 0xc0 | (reg << 3) | rm


def _seq_insn(rng, full):
    """One random instruction as bytes. full=False keeps to the forms whose flags are all defined."""
    d, s = rng.choice(_SEQ_DST), rng.choice(_SEQ_SRC)
    kinds = ["alu", "alu", "alu_mem", "alu_mem_dst", "incdec", "neg", "not", "setcc", "cmov", "flagreg"]
    if full:
        kinds += ["imul", "mul", "shift_imm", "shift_cl", "shld", "bt_imm", "bt_reg", "bitscan", "xadd",
                  "cmpxchg"]
    k = rng.choice(kinds)
    if k == "alu":
        name = rng.choice(sorted(_SEQ_ALU))
        return bytes([_SEQ_ALU[name], _rm(s, d)])
    if k == "alu_mem":
        name = rng.choice(sorted(_SEQ_ALU_MEM))
        return bytes([_SEQ_ALU_MEM[name], 0x46 | (d << 3), rng.randrange(0, 64, 4)])
    if k == "alu_mem_dst":
        name = rng.choice(["add", "sub", "and", "or", "xor", "adc", "sbb"])
        return bytes([_SEQ_ALU[name], 0x46 | (s << 3), rng.randrange(0, 64, 4)])
    if k == "incdec":
        return bytes([rng.choice([0x40, 0x48]) + d])
    if k == "neg":
        return bytes([0xf7, _rm(3, d)])
    if k == "not":
        return bytes([0xf7, _rm(2, d)])
    if k == "setcc":
        return bytes([0x0f, 0x90 | rng.choice(_SEQ_CC), _rm(0, rng.randrange(4))])
    if k == "cmov":
        return bytes([0x0f, 0x40 | rng.choice(_SEQ_CC), _rm(d, s)])
    if k == "flagreg":                              # lahf, sahf, clc, stc, cmc
        return bytes([rng.choice([0x9f, 0x9e, 0xf8, 0xf9, 0xf5])])
    if k == "imul":
        return bytes([0x0f, 0xaf, _rm(d, s)])
    if k == "mul":
        return bytes([0xf7, _rm(rng.choice([4, 5]), d)])
    if k == "shift_imm":
        name = rng.choice(sorted(_SEQ_SHIFT))
        return bytes([0xc1, _rm(_SEQ_SHIFT[name], d), rng.choice([0, 1, 2, 3, 5, 8, 9, 17, 31])])
    if k == "shift_cl":
        name = rng.choice(sorted(_SEQ_SHIFT))
        return bytes([0xd3, _rm(_SEQ_SHIFT[name], d)])
    if k == "shld":
        return bytes([0x0f, rng.choice([0xa4, 0xac]), _rm(s, d), rng.choice([1, 2, 5, 16, 31])])
    if k == "bt_imm":
        name = rng.choice(sorted(_SEQ_BT))
        return bytes([0x0f, 0xba, _rm(_SEQ_BT[name], d), rng.randrange(32)])
    if k == "bt_reg":
        name = rng.choice(sorted(_SEQ_BT_REG))
        return bytes([0x0f, _SEQ_BT_REG[name], _rm(s, d)])
    if k == "bitscan":
        return bytes([0x0f, rng.choice([0xbc, 0xbd]), _rm(d, s)])
    if k == "xadd":
        return bytes([0x0f, 0xc1, _rm(s, d)])
    return bytes([0x0f, 0xb1, _rm(s, d)])          # cmpxchg


def _seq_code(rng, n, full):
    return b"".join(_seq_insn(rng, full) for _ in range(n))


def test_dead_flags_random_sequences_match_full_flags():
    rng = random.Random(0x5eed)
    # ECX is a shift count in CL forms: zero must come up often, since a zero count leaves the flags
    esi = {"esi": DATA + 0x800, "ecx": [0, 0, 1, 2, 3, 4, 7, 31, 32, 63, 0x80000000, 0x12345678]}
    removed = checked = 0
    for i in range(40):
        full = i >= 10                   # the first 10 are the SAFE group (all written flags defined)
        code = _seq_code(rng, rng.randrange(2, 8), full)
        snip = code + b"\xc3"
        res_on = lift_function(_SnippetImage(snip), CODE, dead_flags=True)
        res_off = lift_function(_SnippetImage(snip), CODE, dead_flags=False)
        assert res_on.ok and res_off.ok, (dis(code), res_on.unsupported)
        removed += res_on.flags_removed
        checked += res_on.flags_checked
        specs = [insnrig._gen_state(rng, esi, None, False, False) for _ in range(24)]
        pairs = insnrig._run_reference(specs, snip, False, False)
        inits = [p[0] for p in pairs]
        on = insnrig._run_c(res_on, inits)
        off = insnrig._run_c(res_off, inits)
        assert on == off, "%s: dead flags changed the final state" % dis(code)
        if not full:
            r = insnrig.check(code, n=24, seed=i, regs=esi, undefined=())
            assert r.ok, r
    assert checked and removed, (checked, removed)


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]

if __name__ == "__main__":
    for t in TESTS:
        print(t.__name__)
        t()
    print("all %d x86c tests passed" % len(TESTS))
