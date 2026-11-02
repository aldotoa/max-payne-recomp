#!/usr/bin/env python3
"""Translator coverage on one x86-32 DLL: how many functions from the lift/functions.py inventory
translate with no UNSUPPORTED instruction, and which mnemonics block the rest.

Usage:  coverage.py [dll] [--without FAMILY ...]
  dll               default: $MP_DLL, else the game's rlmfc.dll
  --without ops_X   drop the handlers registered by lift/ops_X.py (baseline numbers without a family)

The inventory JSON is written to a temporary directory (removed at exit). Run from the worktree root:
  ../../../.venv/bin/python lift/coverage.py
"""
import collections
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import x86c

DEFAULT_DLL = os.environ.get(
    "MP_DLL", os.path.join(os.path.dirname(HERE), "Max Payne", "rlmfc.dll"))
TOP = 15


def parse(argv):
    dll, drop = DEFAULT_DLL, []
    i = 0
    while i < len(argv):
        if argv[i] == "--without":
            drop.append(argv[i + 1])
            i += 2
        else:
            dll = argv[i]
            i += 1
    return dll, drop


def drop_families(names):
    """Remove the handlers registered by the named ops_* modules (they are imported by x86c)."""
    for fam in names:
        for mnem, fn in list(x86c.HANDLERS.items()):
            if fn.__module__ == fam:
                del x86c.HANDLERS[mnem]


def inventory(dll, outdir):
    """Run lift/functions.py on the DLL and return its JSON."""
    out = os.path.join(outdir, "inventory.json")
    cmd = [sys.executable, os.path.join(HERE, "functions.py"), dll, "-o", out]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit("functions.py failed:\n" + proc.stderr[-1500:])
    with open(out) as f:
        return json.load(f)


def main(argv):
    dll, drop = parse(argv)
    if not os.path.exists(dll):
        print("no such file: %s" % dll, file=sys.stderr)
        return 2
    drop_families(drop)
    tmp = tempfile.mkdtemp(prefix="lift_coverage_")
    try:
        inv = inventory(dll, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    img = x86c.PEImage(dll)
    entries = [int(f["entry"], 16) for f in inv["functions"]]
    known = frozenset(entries)

    full, errors = 0, 0
    unsup_insns = collections.Counter()         # mnemonic -> instructions
    unsup_funcs = collections.defaultdict(set)  # mnemonic -> functions it blocks
    blocked = set()                             # functions with at least one unsupported instruction
    for e in entries:
        try:
            res = x86c.lift_function(img, e, known)
        except Exception:                           # a decode or mapping failure, not a gap in handlers
            errors += 1
            continue
        if res.ok:
            full += 1
        for _va, text in res.unsupported:
            mnem = text.split()[0] if text.split() else text
            unsup_insns[mnem] += 1
            unsup_funcs[mnem].add(e)
            blocked.add(e)

    n = len(entries)
    label = ", ".join(sorted(drop)) or "none"
    print("%s: %d functions in the inventory" % (os.path.basename(dll), n))
    print("dropped handler families: %s" % label)
    print("fully supported: %d of %d (%.1f%%)" % (full, n, 100.0 * full / max(n, 1)))
    print("functions with translator errors: %d" % errors)
    print("functions with unsupported instructions: %d; unsupported instructions: %d"
          % (len(blocked), sum(unsup_insns.values())))
    print("top %d unsupported mnemonics (instructions / functions blocked):" % TOP)
    for mnem, cnt in unsup_insns.most_common(TOP):
        print("  %-12s %6d / %d" % (mnem, cnt, len(unsup_funcs[mnem])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
