"""Bit-exact check of x87_round (lift/runtime/x87.h, precision control 00) against the previous
implementation, and a timing of old and new. The C side is lift/test_x87_round.c.

Run:  ../../../.venv/bin/python lift/test_x87_round.py          (check; exit 1 on any mismatch)
      ../../../.venv/bin/python lift/test_x87_round.py --bench  (ns per call, old and new)
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(HERE, "runtime")
SRC = os.path.join(HERE, "test_x87_round.c")
CLANG = shutil.which("clang") or "/usr/bin/clang"
CFLAGS = ["-O2", "-std=gnu11", "-Wall", "-Wno-unused-label", "-Wno-unused-variable",
          "-Wno-unused-function", "-I", RUNTIME]


def build():
    exe = os.path.join(tempfile.mkdtemp(prefix="x87round-"), "test_x87_round")
    cc = subprocess.run([CLANG] + CFLAGS + ["-o", exe, SRC, "-lm"], capture_output=True, text=True)
    if cc.returncode != 0:
        raise RuntimeError("clang failed:\n" + cc.stderr)
    return exe


def main(argv):
    exe = build()
    if "--bench" in argv:
        r = subprocess.run([exe, "bench"], capture_output=True, text=True)
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        return r.returncode
    r = subprocess.run([exe], capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0 or "mismatches=0" not in r.stdout.splitlines()[-1]:
        print("FAIL: x87_round differs from the reference")
        return 1
    print("PASS: x87_round is bit-identical to the reference on every case")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
