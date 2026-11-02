"""Differential tests for the string instruction handlers (lift/ops_string.py, lift/runtime/strops.h).

Each case runs under Unicorn and as translated C through insnrig.check. Plain asserts, no pytest.

Run:  ../../../.venv/bin/python lift/test_ops_string.py      (from the worktree root)
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import insnrig
import x86c
from insnrig import check, dis, enc, DATA

N = 200
SRC = range(DATA + 0x100, DATA + 0x200)     # source pointer range, forward walks stay inside
DST = range(DATA + 0x2000, DATA + 0x2100)   # destination pointer range
COUNT = range(0, 64)


def pinned(**extra):
    regs = {"esi": SRC, "edi": DST, "ecx": COUNT}
    regs.update(extra)
    return regs


def assert_ok(r):
    assert r.ok, str(r)


def assert_rejected(code):
    r = check(enc(code), n=5)
    assert not r.ok and r.stage == "translate", "%s should be rejected: %s" % (code, str(r))
    return r


def expect_text(code, text):
    got = dis(enc(code))
    assert got == text, "decode mismatch for %s:\n  got  %r\n  want %r" % (code, got, text)


# ---------------------------------------------------------------- forms

def test_movs_all_forms():
    cases = [("a4", "movsb"), ("a5", "movsd"), ("66 a5", "movsw"),
             ("f3 a4", "rep movsb"), ("f3 a5", "rep movsd"), ("f3 66 a5", "rep movsw")]
    for code, text in cases:
        assert_ok(check(enc(code), n=N, regs=pinned(), random_df=True, label=text))


def test_stos_all_forms():
    cases = [("aa", "stosb"), ("ab", "stosd"), ("66 ab", "stosw"),
             ("f3 aa", "rep stosb"), ("f3 ab", "rep stosd"), ("f3 66 ab", "rep stosw")]
    for code, text in cases:
        assert_ok(check(enc(code), n=N, regs=pinned(), random_df=True, label=text))


def test_lods_all_forms():
    cases = [("ac", "lodsb"), ("ad", "lodsd"), ("66 ad", "lodsw"),
             ("f3 ac", "rep lodsb"), ("f3 ad", "rep lodsd"), ("f3 66 ad", "rep lodsw")]
    for code, text in cases:
        assert_ok(check(enc(code), n=N, regs=pinned(), random_df=True, label=text))


def test_scas_all_forms():
    cases = [("ae", "scasb"), ("af", "scasd"), ("66 af", "scasw"),
             ("f2 ae", "repne scasb"), ("f2 af", "repne scasd"), ("f2 66 af", "repne scasw"),
             ("f3 ae", "repe scasb"), ("f3 af", "repe scasd"), ("f3 66 af", "repe scasw")]
    for code, text in cases:
        assert_ok(check(enc(code), n=N, regs=pinned(), random_df=True, label=text))


def test_cmps_all_forms():
    cases = [("a6", "cmpsb"), ("a7", "cmpsd"), ("66 a7", "cmpsw"),
             ("f3 a6", "repe cmpsb"), ("f3 a7", "repe cmpsd"), ("f3 66 a7", "repe cmpsw"),
             ("f2 a6", "repne cmpsb"), ("f2 a7", "repne cmpsd"), ("f2 66 a7", "repne cmpsw")]
    for code, text in cases:
        assert_ok(check(enc(code), n=N, regs=pinned(), random_df=True, label=text))


def test_prefix_spelling_decodes():
    # the mnemonics the translator dispatches on
    expect_text("f3 a4", "rep movsb byte ptr es:[edi], byte ptr [esi]")
    expect_text("f3 a6", "repe cmpsb byte ptr [esi], byte ptr es:[edi]")
    expect_text("f2 ae", "repne scasb al, byte ptr es:[edi]")


# ---------------------------------------------------------------- counts, flags, direction

def test_ecx_zero_leaves_everything_alone():
    # rep forms with ECX=0 change nothing, flags included (random DF and flags)
    codes = ["f3 a4", "f3 a5", "f3 aa", "f3 ab", "f3 ac", "f3 ad",
             "f2 ae", "f3 ae", "f2 a6", "f3 a6", "f2 a7", "f3 a7"]
    for code in codes:
        assert_ok(check(enc(code), n=N, regs={"ecx": 0, "esi": SRC, "edi": DST},
                        random_df=True, label="ecx=0 " + dis(enc(code))))


def test_single_element_flags_and_pointers():
    # non-rep cmps/scas: flags of the one comparison, pointers step by size (DF random)
    assert_ok(check(enc("a6"), n=N, regs=pinned(), random_df=True))
    assert_ok(check(enc("ae"), n=N, regs=pinned(), random_df=True))
    assert_ok(check(enc("66 a7"), n=N, regs=pinned(), random_df=True))


def test_backward_direction_all_rep_forms():
    # no std handler exists yet, so DF=1 comes from random_df (about half the states). The pointer
    # ranges leave room for 64 elements of size 4 walking down.
    codes = ["f3 a4", "f3 a5", "f3 66 a5", "f3 aa", "f3 ab", "f3 ad",
             "f2 ae", "f2 af", "f3 a6", "f3 a7"]
    for code in codes:
        assert_ok(check(enc(code), n=N, regs=pinned(), random_df=True,
                        label="DF random " + dis(enc(code))))


def test_random_df_mixed():
    for code in ["f3 a4", "f3 a5", "f3 aa", "f3 ab", "f3 ac", "f3 ad",
                 "f2 ae", "f3 af", "f2 a6", "f3 a7"]:
        assert_ok(check(enc(code), n=N, regs=pinned(), random_df=True,
                        label="random DF " + dis(enc(code))))


# ---------------------------------------------------------------- overlap

def test_overlap_movsb_dst_src_plus_1():
    # forward byte copy with dst = src+1 replicates the first byte (element-by-element result)
    assert_ok(check(enc("f3 a4"), n=N, regs={"esi": DATA + 0x100, "edi": DATA + 0x101,
                                             "ecx": COUNT}))
    assert_ok(check(enc("a4"), n=N, regs={"esi": DATA + 0x100, "edi": DATA + 0x101}))


def test_overlap_movsd_dst_src_plus_3():
    assert_ok(check(enc("f3 a5"), n=N, regs={"esi": DATA + 0x100, "edi": DATA + 0x103,
                                             "ecx": COUNT}))
    assert_ok(check(enc("f3 a4"), n=N, regs={"esi": DATA + 0x100, "edi": DATA + 0x103,
                                             "ecx": COUNT}))


def test_overlap_dst_below_src():
    # dst < src: forward copy equals memmove
    assert_ok(check(enc("f3 a4"), n=N, regs={"esi": DATA + 0x101, "edi": DATA + 0x100,
                                             "ecx": COUNT}))
    assert_ok(check(enc("f3 a5"), n=N, regs={"esi": DATA + 0x110, "edi": DATA + 0x100,
                                             "ecx": COUNT}))


def test_overlap_random_pointers_same_window():
    # src and dst both in a 64-byte window: random distances in both directions
    win = range(DATA + 0x100, DATA + 0x140)
    for code in ["f3 a4", "f3 a5", "f3 66 a5", "a4", "a5"]:
        assert_ok(check(enc(code), n=N, regs={"esi": win, "edi": win, "ecx": COUNT},
                        random_df=True, label="overlap " + dis(enc(code))))


def test_overlap_stos_and_lods_pattern():
    # rep stosb over an overlapping window (a stos writes only; lods reads the window)
    assert_ok(check(enc("f3 aa"), n=N, regs={"edi": DATA + 0x200, "ecx": COUNT}))
    assert_ok(check(enc("f3 ac"), n=N, regs={"esi": DATA + 0x200, "ecx": COUNT}))


# ---------------------------------------------------------------- idioms and mem=

def test_strlen_repne_scasb():
    # strlen: al = 0, ecx = -1, scan until the first zero byte
    text = b"Max Payne\x00"
    assert_ok(check(enc("f2 ae"), n=N, regs={"eax": 0, "edi": DATA, "ecx": 0xffffffff},
                    mem=text))
    # a zero at each of several positions, and an empty string
    for k in (0, 1, 7, 40):
        buf = bytearray(b"\x41" * 64)
        buf[k] = 0
        assert_ok(check(enc("f2 ae"), n=N, regs={"eax": 0, "edi": DATA, "ecx": 0xffffffff},
                        mem=bytes(buf), label="strlen zero at %d" % k))


def test_repne_scasb_count_runs_out():
    # no zero in the first 5 bytes: stops with ECX=0 and ZF=0
    assert_ok(check(enc("f2 ae"), n=N, regs={"eax": 0, "edi": DATA, "ecx": 5},
                    mem=b"abcdefgh"))


def test_repe_cmpsb_equal_and_unequal():
    block = bytes(range(0x41, 0x41 + 0x40)) * 4          # 256 bytes, 0x40 distinct values
    equal = bytearray(0x300)
    equal[0x100:0x200] = block
    equal[0x200:0x300] = block
    assert_ok(check(enc("f3 a6"), n=N, regs={"esi": DATA + 0x100, "edi": DATA + 0x200,
                                             "ecx": COUNT}, mem=bytes(equal)))
    unequal = bytearray(equal)
    unequal[0x200 + 20] ^= 0x55                         # first mismatch at element 20
    assert_ok(check(enc("f3 a6"), n=N, regs={"esi": DATA + 0x100, "edi": DATA + 0x200,
                                             "ecx": COUNT}, mem=bytes(unequal)))
    # repe cmpsb with the mismatch at element 20 and a count that passes it
    assert_ok(check(enc("f3 a6"), n=N, regs={"esi": DATA + 0x100, "edi": DATA + 0x200,
                                             "ecx": 64}, mem=bytes(unequal)))


def test_repne_cmpsb_stops_on_match():
    # repne cmpsb stops at the first equal byte
    buf = bytearray(0x300)
    buf[0x100:0x140] = bytes(range(1, 0x41))
    buf[0x200:0x240] = bytes(range(0x80, 0xc0))
    buf[0x200 + 9] = buf[0x100 + 9]                     # first equal pair at element 9
    assert_ok(check(enc("f2 a6"), n=N, regs={"esi": DATA + 0x100, "edi": DATA + 0x200,
                                             "ecx": COUNT}, mem=bytes(buf)))


# ---------------------------------------------------------------- rejected forms

def test_rejected_forms_are_unsupported():
    assert_rejected("f2 a4")            # repne movsb: CPU ignores it, we do not guess
    assert_rejected("f2 ab")            # repne stosd
    assert_rejected("f2 ac")            # repne lodsb
    assert_rejected("64 f3 a5")         # fs: segment override on the source
    assert_rejected("3e f3 a5")         # ds: override (rejected too: no override is emitted)
    assert_rejected("67 f3 a5")         # 16-bit address size
    assert_rejected("f3 f3 a5")         # repeated rep prefix
    assert_rejected("f2 0f c2 c1 00")   # cmpsd xmm0, xmm1, 0 (SSE2), not a string op


def test_rejected_instruction_fails_before_running():
    r = check(enc("64 f3 a5"), n=10)
    assert r.stage == "translate" and r.n_failed == 1 and "segment" in r.failures[0], str(r)


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]

if __name__ == "__main__":
    t0 = time.time()
    for t in TESTS:
        print(t.__name__)
        t()
    print("all %d string-op tests passed in %.2f s" % (len(TESTS), time.time() - t0))
