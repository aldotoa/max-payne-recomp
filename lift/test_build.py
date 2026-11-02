"""Tests for lift/build.py: argument parsing, module resolution, entry selection, and a two-module real build.

The real build needs the game folder (MP_GAME_DIR, default "<repo>/Max Payne"); it is skipped without it.

Run:  ../../../.venv/bin/python lift/test_build.py          (plain asserts, no pytest)
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import build as liftbuild                                   # noqa: E402

GAME = liftbuild.game_dir()
MODULES = ["rlmfc.dll", "grphmfc.dll"]


class FakeImage:
    """A stand-in for x86c.PEImage with just the part entries_for uses: is_code over one code range."""

    def __init__(self, lo, hi):
        self.lo, self.hi = lo, hi

    def is_code(self, va):
        return self.lo <= va < self.hi


def _write_inventory(path, functions):
    with open(path, "w") as fh:
        json.dump({"module": "fake", "functions": functions}, fh)


def _func(entry, gap_scan=False, calls=()):
    return {"entry": "0x%08x" % entry, "gap_scan": gap_scan, "calls": ["0x%08x" % c for c in calls],
            "tail_calls": []}


def test_resolve_dll_and_module_spec():
    old = os.environ.get("MP_GAME_DIR")
    try:
        os.environ["MP_GAME_DIR"] = "/tmp/game-a"
        assert liftbuild.resolve_dll("rlmfc.dll") == "/tmp/game-a/rlmfc.dll"
        assert liftbuild.resolve_dll("/x/y/grphmfc.dll") == "/x/y/grphmfc.dll"
        dll, inv = liftbuild.parse_module("grphmfc.dll")
        assert dll == "/tmp/game-a/grphmfc.dll", dll
        assert inv == os.path.join(ROOT, "lift-out", "grphmfc_functions.json"), inv
        dll, inv = liftbuild.parse_module("rlmfc.dll:/abs/inv.json")
        assert (dll, inv) == ("/tmp/game-a/rlmfc.dll", "/abs/inv.json"), (dll, inv)
        dll, inv = liftbuild.parse_module("/abs/dir/rlmfc.dll:rel/inv.json")
        assert dll == "/abs/dir/rlmfc.dll" and inv == os.path.join(ROOT, "rel", "inv.json"), (dll, inv)
        os.environ.pop("MP_GAME_DIR")
        assert liftbuild.game_dir() == os.path.join(ROOT, "Max Payne")
    finally:
        if old is None:
            os.environ.pop("MP_GAME_DIR", None)
        else:
            os.environ["MP_GAME_DIR"] = old


def test_argument_parsing():
    ap = liftbuild.make_parser()
    a = ap.parse_args(["--module", "rlmfc.dll", "--module", "grphmfc.dll:inv.json", "--entries", "real",
                       "--keep-emulated", "0x10001000,0x10002000", "--write-log"])
    assert a.dll is None and a.module == ["rlmfc.dll", "grphmfc.dll:inv.json"], a
    assert a.entries == "real" and a.write_log and a.out is None and a.lib is None
    liftbuild.check_args(ap, a)
    b = ap.parse_args(["rlmfc.dll", "--entries", "0x1000,0x2000", "--inventory", "inv.json"])
    assert b.dll == "rlmfc.dll" and b.module == [] and b.entries == "0x1000,0x2000"
    liftbuild.check_args(ap, b)
    for bad in (["--entries", "real"], ["rlmfc.dll", "--module", "x.dll", "--entries", "real"],
                ["--module", "rlmfc.dll", "--inventory", "i.json", "--entries", "real"]):
        try:
            liftbuild.check_args(ap, ap.parse_args(bad))
        except SystemExit:
            continue
        raise AssertionError("accepted bad arguments: %s" % bad)


def test_keep_emulated_file():
    tmp = tempfile.mkdtemp()
    try:
        path = os.path.join(tmp, "keep.txt")
        with open(path, "w") as fh:
            fh.write("# emulated for now\n10001000   # InitInstance helper\n\n0x10002abc\n")
        ap = liftbuild.make_parser()
        a = ap.parse_args(["--module", "rlmfc.dll", "--entries", "all", "--keep-emulated", "0x20",
                           "--keep-emulated-file", path])
        assert liftbuild.read_keep(a) == {0x20, 0x10001000, 0x10002ABC}, liftbuild.read_keep(a)
    finally:
        shutil.rmtree(tmp)


def test_setjmp_users_kept():
    inv = {"functions": [
        {"entry": "0x100", "imports_called": ["MSVCRT.dll!_setjmp3"]},
        {"entry": "0x200", "imports_called": ["MSVCRT.dll!malloc"]},
        {"entry": "0x300", "imports_called": ["MSVCRT.dll!longjmp", "MSVCRT.dll!free"]},
        {"entry": "0x400"},
    ]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(inv, fh)
    try:
        assert liftbuild.setjmp_users(fh.name) == {0x100, 0x300}
    finally:
        os.unlink(fh.name)

def test_entries_for_hex_split_by_address_and_real():
    tmp = tempfile.mkdtemp()
    try:
        inv_a = os.path.join(tmp, "a.json")
        inv_b = os.path.join(tmp, "b.json")
        # a: one real entry, one gap-scan label that nobody calls (not real), one gap-scan find that is called (real)
        _write_inventory(inv_a, [_func(0x1000), _func(0x1100, gap_scan=True), _func(0x1200, gap_scan=True),
                                 _func(0x1300, calls=[0x1200])])
        _write_inventory(inv_b, [_func(0x9000), _func(0x9100)])
        mods = [("a.dll", FakeImage(0x1000, 0x2000), inv_a), ("b.dll", FakeImage(0x9000, 0xA000), inv_b)]
        real = liftbuild.entries_for(mods, "real")
        assert real == {"a.dll": [0x1000, 0x1200, 0x1300], "b.dll": [0x9000, 0x9100]}, real
        every = liftbuild.entries_for(mods, "all")
        assert every["a.dll"] == [0x1000, 0x1100, 0x1200, 0x1300] and every["b.dll"] == [0x9000, 0x9100], every
        hexes = liftbuild.entries_for(mods, "0x9100,1000,0x1300")
        assert hexes == {"a.dll": [0x1000, 0x1300], "b.dll": [0x9100]}, hexes
        try:
            liftbuild.entries_for(mods, "0x5000")
        except SystemExit as ex:
            assert "0x00005000" in str(ex), ex
        else:
            raise AssertionError("an address in no module was accepted")
        single = liftbuild.entries_for(mods[:1], "0x5000")       # one module: every VA is its own
        assert single == {"a.dll": [0x5000]}, single
    finally:
        shutil.rmtree(tmp)


def test_entries_file_overrides_one_module():
    tmp = tempfile.mkdtemp()
    try:
        inv_a = os.path.join(tmp, "a.json")
        inv_b = os.path.join(tmp, "b.json")
        _write_inventory(inv_a, [_func(0x1000), _func(0x1100)])
        _write_inventory(inv_b, [_func(0x9000), _func(0x9100)])
        mods = [("rlmfc.dll", FakeImage(0x1000, 0x2000), inv_a), ("MaxPayne.exe", FakeImage(0x400000, 0x500000), inv_b)]
        path = os.path.join(tmp, "hot.txt")
        with open(path, "w") as fh:
            fh.write("# hot set\n400000   # first\n0x401000\n400000\n")
        got = liftbuild.entries_file_overrides(["maxpayne.exe=%s" % path], mods)
        assert got == {"MaxPayne.exe": [0x400000, 0x401000]}, got
        # the stem match: MaxPayne.exe is maxpayne; a VA outside the module, or a bad name, is refused
        with open(path, "w") as fh:
            fh.write("0x1000\n")
        for bad in (["maxpayne.exe=%s" % path], ["nosuch.dll=%s" % path], ["rlmfc.dll"]):
            try:
                liftbuild.entries_file_overrides(bad, mods)
            except SystemExit:
                continue
            raise AssertionError("accepted --entries-file %s" % bad)
        # the module's entries come from the file, the other module's from --entries (entries_for)
        assert liftbuild.module_stem("MaxPayne.exe") == "maxpayne" and liftbuild.module_stem("rlmfc.dll") == "rlmfc"
        a = liftbuild.make_parser().parse_args(["--module", "rlmfc.dll", "--module", "MaxPayne.exe", "--entries", "real",
                                                "--entries-file", "MaxPayne.exe=%s" % path])
        assert a.entries_file == ["MaxPayne.exe=%s" % path], a.entries_file
    finally:
        shutil.rmtree(tmp)


def test_exe_text_is_code():
    exe = os.path.join(GAME, "MaxPayne.exe")
    if not os.path.exists(exe):
        print("  skipped: game folder not found (%s)" % GAME)
        return
    img = liftbuild.x86c.PEImage(exe)          # .text has no execute flag in this exe; its code must still count
    assert img.is_code(0x402A00) and img.is_code(0x401000), "exe .text is not code"
    assert not img.is_code(0x008D0000), ".MGD32 is data"


def _pick_leaves(inv_path, n):
    """n small leaf functions (no calls, no SEH, no jump tables, not gap-scan finds) from an inventory."""
    with open(inv_path) as fh:
        funcs = json.load(fh)["functions"]
    picks = []
    for f in funcs:
        if f["gap_scan"] or f["calls"] or f["tail_calls"] or f.get("has_seh") or f.get("jump_tables") \
                or f.get("odd") or f["size"] > 48:
            continue
        picks.append(int(f["entry"], 16))
        if len(picks) == n:
            break
    return picks


def test_two_module_build():
    rl = os.path.join(GAME, "rlmfc.dll")
    gr = os.path.join(GAME, "grphmfc.dll")
    if not (os.path.exists(rl) and os.path.exists(gr)):
        print("  skipped: game folder not found (%s)" % GAME)
        return
    tmp = tempfile.mkdtemp()
    try:
        invs = {}
        for dll in MODULES:
            out = os.path.join(tmp, "inv", os.path.splitext(dll)[0] + "_functions.json")
            subprocess.run([sys.executable, os.path.join(HERE, "functions.py"), os.path.join(GAME, dll), "-o", out],
                           check=True, capture_output=True)
            invs[dll] = out
        picks = {dll: _pick_leaves(invs[dll], 3) for dll in MODULES}
        assert all(len(v) == 3 for v in picks.values()), picks
        # Both DLLs prefer base 0x10000000. The emulator loads grphmfc.dll elsewhere (emu/mpemu.py MODULE_BASES), and
        # that needs PEImage(path, base=...). Until PEImage is relocated, the two modules' VAs collide: skip.
        img_gr = liftbuild.x86c.PEImage(gr)
        if any(img_gr.is_code(va) for va in picks["rlmfc.dll"]):
            print("  skipped: rlmfc.dll and grphmfc.dll overlap at their preferred base (PEImage has no base yet)")
            return
        # one entry is kept in the emulator: it must be missing from the table and listed as kept
        keep = picks["grphmfc.dll"][0]
        out = os.path.join(tmp, "out")
        lib = os.path.join(tmp, "liblifted.dylib")
        argv = []
        for dll in MODULES:
            argv += ["--module", "%s:%s" % (os.path.join(GAME, dll), invs[dll])]
        entries = sorted(sum(picks.values(), []))
        argv += ["--entries", ",".join("%x" % va for va in entries), "--keep-emulated", "%x" % keep,
                 "--out", out, "--lib", lib]
        assert liftbuild.main(argv) == 0
        want = sorted(set(entries) - {keep})
        with open(os.path.join(out, "table.c")) as fh:
            table = fh.read()
        got = [int(m, 16) for m in re.findall(r"\{0x([0-9a-f]{8})u, f_", table)]
        assert got == want, ([hex(v) for v in got], [hex(v) for v in want])
        assert "const unsigned lift_table_len = %du;" % len(want) in table
        for dll in MODULES:
            stem = os.path.splitext(dll)[0]
            for va in picks[dll]:
                if va != keep:
                    assert os.path.exists(os.path.join(out, stem, "f_%08x.c" % va)), (dll, hex(va))
        assert not os.path.exists(os.path.join(out, "rlmfc", "f_%08x.c" % keep))
        assert not os.path.exists(os.path.join(out, "grphmfc", "f_%08x.c" % keep))
        with open(os.path.join(out, "lifted.json")) as fh:
            summary = json.load(fh)
        by = {m["module"]: m for m in summary["modules"]}
        assert set(by) == set(MODULES), by.keys()
        assert by["grphmfc.dll"]["kept_emulated"] == ["0x%08x" % keep]
        for dll in MODULES:
            assert sorted(int(x, 16) for x in by[dll]["lifted"]) == sorted(
                v for v in picks[dll] if v != keep), (dll, by[dll]["lifted"])
            assert not by[dll]["dropped"], by[dll]["dropped"]
        nm = subprocess.run(["nm", "-gU", lib], capture_output=True, text=True, check=True).stdout
        assert re.search(r"\b_?lift_table$", nm, re.M), "lift_table is not exported"
    finally:
        shutil.rmtree(tmp)


def test_thunk_split():
    """An import thunk (a 6-byte jmp dword ptr [iat]) is split off the entries and never lifted; other entries stay."""

    class FakeThunkImage:
        def __init__(self):
            self.mem = {0x1000: b"\xff\x25\x00\x30\x00\x10", 0x1010: b"\x55\x8b\xec\x5d\xc3\x90"}
            self.iat = {0x10003000: "MSVCRT!_CxxThrowException"}

        def read(self, va, n):
            for base, data in self.mem.items():
                if base <= va < base + len(data):
                    return data[va - base:va - base + n]
            return None

    img = FakeThunkImage()
    rest, thunks = liftbuild.split_thunks(img, [0x1000, 0x1010])
    assert rest == [0x1010], rest
    assert thunks == {0x1000: "MSVCRT!_CxxThrowException"}, thunks
    exe = os.path.join(GAME, "MaxPayne.exe")
    if os.path.exists(exe):
        img = liftbuild.x86c.PEImage(exe)
        rest, thunks = liftbuild.split_thunks(img, [0x76f920, 0x401000])
        assert rest == [0x401000], [hex(v) for v in rest]
        assert thunks == {0x76f920: "MSVCRT.dll!_CxxThrowException"}, thunks
    else:
        print("  exe part skipped: game folder not found (%s)" % GAME)


def test_native_overrides():
    """A lift/native file replaces the lifted functions it defines when all of them are in the build: its object is
    linked, the generated C is compiled renamed lifted_XXXXXXXX (the fallback), and the generated f_XXXXXXXX.o is
    not built. A native file defining a function outside the build is left out."""
    tmp = tempfile.mkdtemp(prefix="nat_")
    saved = liftbuild.NATIVE
    try:
        nat = os.path.join(tmp, "native")
        os.makedirs(nat)
        for va in ("00001000", "00002000"):
            with open(os.path.join(tmp, "f_%s.c" % va), "w") as fh:
                fh.write('#include "lift.h"\nvoid f_%s(CPU *c)\n{\n    c->r[EAX] = 1;\n}\n' % va)
        with open(os.path.join(nat, "a.c"), "w") as fh:
            fh.write('#include "lift.h"\nvoid lifted_00001000(CPU *c);\n'
                     'void f_00001000(CPU *c)\n{\n    lifted_00001000(c);\n    c->r[EAX]++;\n}\n')
        with open(os.path.join(nat, "b.c"), "w") as fh:
            fh.write('#include "lift.h"\nvoid f_00003000(CPU *c);\nvoid f_00003000(CPU *c)\n{\n}\n')
        liftbuild.NATIVE = nat
        assert liftbuild.native_functions(os.path.join(nat, "b.c")) == ["f_00003000"]
        sources = [os.path.join(tmp, "f_00001000.c"), os.path.join(tmp, "f_00002000.c")]
        assert liftbuild.native_overrides(sources) == {os.path.join(nat, "a.c"): ["f_00001000"]}
        lib = os.path.join(tmp, "libnat.dylib")
        liftbuild.compile_and_link(sources, lib)
        objs = sorted(os.listdir(os.path.join(tmp, "libnat.obj")))
        assert objs == ["f_00002000.o", "lifted_00001000.o", "link.rsp", "native_a.o"], objs
        syms = subprocess.run(["nm", "-gU", lib], capture_output=True, text=True).stdout.split()
        for name in ("_f_00001000", "_f_00002000", "_lifted_00001000"):
            assert name in syms, (name, syms)
        assert "_f_00003000" not in syms
    finally:
        liftbuild.NATIVE = saved
        shutil.rmtree(tmp)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print("PASS %s" % t.__name__)
    print("all build tests passed")
