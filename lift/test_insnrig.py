"""Self-test for the per-instruction differential rig (lift/insnrig.py).

Positive tests: instructions the translator already handles must match Unicorn on random states.
Negative tests: a deliberately wrong handler must be reported, and an unsupported instruction must
give a clean failed Result. Plain asserts, no pytest.

Run:  ../../../.venv/bin/python lift/test_insnrig.py      (from the repo root, or with an absolute path)
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import insnrig
import x86c
from insnrig import check, dis, enc, DATA

ORIG = dict(x86c.HANDLERS)


def expect_text(code, text):
    got = dis(enc(code))
    assert got == text, "decode mismatch for %s:\n  got  %r\n  want %r" % (code, got, text)


def assert_ok(r):
    assert r.ok, str(r)


# ---------------------------------------------------------------- positive tests

def test_mov_family_high_byte_regs():
    code = "8b c3 b4 55 0f b6 cc 0f be df"
    expect_text(code, "mov eax, ebx; mov ah, 0x55; movzx ecx, ah; movsx ebx, bh")
    assert_ok(check(enc(code)))                      # no flag changes: all flags compared


def test_lea_scaled_index():
    expect_text("8d 44 8b 10", "lea eax, [ebx + ecx*4 + 0x10]")
    assert_ok(check(enc("8d 44 8b 10")))


def test_push_pop_esp_forms():
    expect_text("54 8f 44 24 04", "push esp; pop dword ptr [esp + 4]")
    assert_ok(check(enc("54 8f 44 24 04")))


def test_xchg_reg_mem():
    expect_text("87 07", "xchg dword ptr [edi], eax")
    r = check(enc("87 07"), regs={"edi": DATA + 0x100})
    assert_ok(r)


def test_cmp_widths_and_immediates():
    for code, text in [("3c 7f", "cmp al, 0x7f"),
                       ("66 39 d8", "cmp ax, bx"),
                       ("38 cb", "cmp bl, cl"),
                       ("81 f9 00 00 00 80", "cmp ecx, 0x80000000"),
                       ("83 f8 01", "cmp eax, 1")]:
        expect_text(code, text)
        assert_ok(check(enc(code), label=text))


def test_test_af_undefined():
    expect_text("84 d8", "test al, bl")
    assert_ok(check(enc("84 d8"), undefined=("af",)))
    assert_ok(check(enc("a8 80"), undefined=("af",)))


def test_cwde_cdq():
    expect_text("98 99", "cwde; cdq")
    assert_ok(check(enc("98 99")))


def test_jcc_inside_snippet():
    code = "39 d8 7c 05 b9 01 00 00 00 ba 02 00 00 00"
    expect_text(code, "cmp eax, ebx; jl 0x401009; mov ecx, 1; mov edx, 2")
    assert_ok(check(enc(code), n=300))


def test_pinned_memory_store_is_compared():
    # mov dword ptr [esi], eax: the data region must match, not just registers
    assert_ok(check(enc("89 06"), regs={"esi": DATA + 0x40}))


def test_x87_state_round_trip():
    # nop changes nothing: the rig must transfer and compare the x87 state unchanged
    assert_ok(check(enc("90"), n=100, fpu=True))


def test_x87_fld1_positive_and_negative():
    def fld1_good(ctx, ins):
        return ["c->top = (c->top - 1) & 7;",
                "c->st[c->top] = 1.0;",
                "c->tag &= ~(1u << c->top);"]

    def fld1_bad(ctx, ins):
        return ["c->top = (c->top - 1) & 7;",
                "c->st[c->top] = 2.0;",                 # wrong constant
                "c->tag &= ~(1u << c->top);"]

    x86c.HANDLERS["fld1"] = fld1_good
    try:
        assert_ok(check(enc("d9 e8"), n=100, fpu=True, flags=()))
    finally:
        x86c.HANDLERS.clear()
        x86c.HANDLERS.update(ORIG)
    x86c.HANDLERS["fld1"] = fld1_bad
    try:
        r = check(enc("d9 e8"), n=100, fpu=True, flags=())
        assert not r.ok and r.n_failed > 0, str(r)
        assert any("ST(0)" in f for f in r.failures), r.failures
    finally:
        x86c.HANDLERS.clear()
        x86c.HANDLERS.update(ORIG)


# ---------------------------------------------------------------- negative tests

def test_negative_wrong_cmp_carry_is_reported():
    base = ORIG["cmp"]

    def wrong_cf(ctx, ins):
        return base(ctx, ins) + ["c->cf ^= 1;"]          # CF inverted

    x86c.HANDLERS["cmp"] = wrong_cf
    try:
        r = check(enc("39 d8"), n=100)                   # cmp eax, ebx, all flags compared
        assert not r.ok and r.n_failed > 0, str(r)
        assert any("CF expected" in f for f in r.failures), r.failures
        # restricting the comparison to other flags must not report the CF bug
        assert check(enc("39 d8"), n=100, flags=("zf", "sf", "of")).ok
    finally:
        x86c.HANDLERS.clear()
        x86c.HANDLERS.update(ORIG)
    assert_ok(check(enc("39 d8"), n=100))                # restored handler passes again


def test_negative_wrong_flag_respects_undefined():
    base = ORIG["test"]

    def wrong_af(ctx, ins):
        return base(ctx, ins) + ["c->af = 1;"]           # AF is undefined for test: ignored

    x86c.HANDLERS["test"] = wrong_af
    try:
        assert_ok(check(enc("84 d8"), n=100, undefined=("af",)))
        r = check(enc("84 d8"), n=100)                   # without `undefined` the AF mismatch shows
        assert not r.ok and any("AF" in f for f in r.failures), str(r)
    finally:
        x86c.HANDLERS.clear()
        x86c.HANDLERS.update(ORIG)


def test_unsupported_instruction_is_clean_failure():
    r = check(enc("0f c7 0e"), n=50)                     # cmpxchg8b [esi]: no handler
    assert not r.ok and r.n_failed == 1, str(r)
    assert any("cmpxchg8b" in f and "no handler" in f for f in r.failures), r.failures
    assert r.unsupported and r.unsupported[0][0] == 0x00401000, r.unsupported


def test_unsupported_reported_before_running():
    # an indirect jump is rejected by the translator; the rig must not try to run it
    r = check(enc("ff e0"), n=10)
    assert not r.ok and "jmp eax" in r.failures[0], r.failures


def test_bad_arguments_raise():
    for kwargs in ({"flags": ("xf",)}, {"undefined": ("zz",)}, {"regs": {"esp": 0}},
                   {"regs": {"foo": 1}}):
        try:
            check(enc("90"), n=1, **kwargs)
        except ValueError:
            continue
        raise AssertionError("expected ValueError for %r" % (kwargs,))


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]

if __name__ == "__main__":
    t0 = time.time()
    for t in TESTS:
        print(t.__name__)
        t()
    print("all %d insnrig tests passed in %.2f s" % (len(TESTS), time.time() - t0))
