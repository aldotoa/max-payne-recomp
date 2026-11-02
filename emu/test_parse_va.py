"""Unit tests for native.parse_va_text (the --diff-only / --diff-only-file value parser in emu/run_init.py).
No game files needed.

Run:  .venv/bin/python emu/test_parse_va.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import native


def test_hex_forms():
    assert native.parse_va_text("0x401000") == {0x401000}
    assert native.parse_va_text("401000") == {0x401000}
    assert native.parse_va_text("0X4010AB") == {0x4010AB}
    assert native.parse_va_text("0x401000,0x402000") == {0x401000, 0x402000}
    assert native.parse_va_text("401000, 0x402000 ,0x403000") == {0x401000, 0x402000, 0x403000}


def test_lines_comments_blanks():
    text = "# diff these\n\n0x401000   # the first\n  \n402000\n# 0x409999 is commented out\n"
    assert native.parse_va_text(text) == {0x401000, 0x402000}
    assert native.parse_va_text("") == set()
    assert native.parse_va_text("\n\n# only comments\n") == set()


def test_duplicates_collapse():
    assert native.parse_va_text("0x401000,401000\n0X401000") == {0x401000}


def test_bad_tokens_named():
    for text, bad in [("0xZZ", "0xZZ"), ("401000,nope", "nope"), ("-401000", "-401000"),
                      ("+401000", "+401000"), ("0x", "0x"), ("1_000", "1_000"), ("0x12 0x3g", "0x3g")]:
        try:
            native.parse_va_text(text)
        except ValueError as err:
            assert bad in str(err), (text, str(err))
        else:
            raise AssertionError("no ValueError for %r" % text)


def test_all_bad_tokens_listed_together():
    try:
        native.parse_va_text("zz,401000,yy")
    except ValueError as err:
        assert "zz" in str(err) and "yy" in str(err), str(err)
    else:
        raise AssertionError("no ValueError")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("all parse_va tests passed")
