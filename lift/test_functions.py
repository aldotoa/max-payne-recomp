#!/usr/bin/env python3
"""Tests for lift/functions.py on the real rlmfc.dll (skipped if the DLL is absent).

Run: <repo>/.venv/bin/python lift/test_functions.py
"""
import ast
import bisect
import json
import os
import re
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import capstone  # noqa: E402

import functions as F  # noqa: E402
from modbases import MODULE_BASES  # noqa: E402

REPO = os.path.dirname(HERE)
GAME_DIRS = [
    os.environ.get("MP_GAME_DIR", ""),
    os.path.join(REPO, "Max Payne"),
]
DLL_CANDIDATES = [
    os.environ.get("RLMFC_DLL", ""),
    os.path.join(REPO, "Max Payne", "rlmfc.dll"),
]
# Real export names (from census/exports_rlmfc.dll.json).
KNOWN_NAMES = [
    "?changeDirectory@R_File@@QAEXPBD@Z",
    "??0R_FileStream@@IAE@XZ",
    "??0Chunk@R_MemoryFile@@QAE@XZ",
]
# jmp dword ptr [reg*4 + disp32]: FF 24 (modrm 0x05|reg<<3 with SIB 0x85...) -- the
# no-base SIB form, which is how MSVC emits switch dispatch.
JMP_TABLE_RE = re.compile(rb"\xff\x24[\x85\x8d\x95\x9d\xa5\xad\xb5\xbd]")

_cache = {}


def _missing(name):
    """Under pytest a test that needs an absent game file is skipped (a checkout has no game); run directly, None."""
    if "pytest" in sys.modules:
        import pytest
        pytest.skip("no game file %s (put the game in Max Payne/ or set MP_GAME_DIR)" % name)
    return None


def find_dll():
    for p in DLL_CANDIDATES:
        if p and os.path.isfile(p):
            return p
    return _missing("rlmfc.dll")


def find_game(name):
    for d in GAME_DIRS:
        p = os.path.join(d, name)
        if d and os.path.isfile(p):
            return p
    return _missing(name)


def inventory():
    """rlmfc.dll at the default base."""
    if "inv" not in _cache:
        path = find_dll()
        img, exports, funcs, slots, entry = F.inventory(path)
        _cache["inv"] = (img, exports, F.build_output(img, exports, funcs, slots, entry),
                         funcs)
    return _cache["inv"]


def inventory_at(path, base=None):
    """(img, exports, output, funcs) for `path` mapped at `base` (None: the default). Cached."""
    key = (path, base)
    if key not in _cache:
        img, exports, funcs, slots, entry = F.inventory(path, base)
        _cache[key] = (img, exports, F.build_output(img, exports, funcs, slots, entry), funcs)
    return _cache[key]


def unshift(out, delta):
    """Copy of an inventory output with every address field moved down by delta."""
    def a(s):
        return "0x%x" % (int(s, 16) - delta)
    o = dict(out)
    o["base"] = a(out["base"])
    o["summary"] = dict(out["summary"], entry_point=a(out["summary"]["entry_point"]))
    o["functions"] = []
    for f in out["functions"]:
        g = dict(f)
        g["entry"] = a(f["entry"])
        g["blocks"] = [{"start": a(b["start"]), "end": a(b["end"])} for b in f["blocks"]]
        for k in ("calls", "tail_calls", "indirect_calls", "unresolved_indirect_jumps"):
            g[k] = [a(t) for t in f[k]]
        g["jump_tables"] = [{"at": a(j["at"]), "table": a(j["table"]),
                             "targets": [a(t) for t in j["targets"]],
                             "byte_table": None if j["byte_table"] is None else a(j["byte_table"]),
                             "byte_count": j["byte_count"]} for j in f["jump_tables"]]
        o["functions"].append(g)
    return o


def test_exports_are_entries():
    img, exports, out, funcs = inventory()
    entries = {int(f["entry"], 16) for f in out["functions"]}
    code_exports = [(n, va) for _, n, va in exports if img.is_code(va)]
    assert code_exports, "no code exports found"
    missing = [n for n, va in code_exports if va not in entries]
    assert not missing, "exports not function entries: %s" % missing[:5]
    print("  code exports: %d, all function entries" % len(code_exports))


def test_function_count():
    _, _, out, _ = inventory()
    n = out["summary"]["function_count"]
    print("  functions: %d (Ghidra: 1582)" % n)
    assert 1200 <= n <= 2000, n


def test_blocks_do_not_overlap():
    _, _, out, _ = inventory()
    for f in out["functions"]:
        blocks = sorted((int(b["start"], 16), int(b["end"], 16)) for b in f["blocks"])
        for (s0, e0), (s1, e1) in zip(blocks, blocks[1:]):
            assert e0 <= s1, "overlapping blocks in %s: %x-%x vs %x" % (f["entry"], s0, e0, s1)
        for s, e in blocks:
            assert e > s, "empty block in %s" % f["entry"]
        assert f["size"] == sum(e - s for s, e in blocks), f["entry"]


def test_block_starts_decode():
    img, _, out, _ = inventory()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    checked = 0
    for f in out["functions"]:
        for b in f["blocks"]:
            s = int(b["start"], 16)
            raw = img.read(s, 16)
            assert raw is not None, "block start %s not readable" % b["start"]
            ins = next(md.disasm(raw, s), None)
            assert ins is not None, "block start %s does not decode" % b["start"]
            checked += 1
    print("  block starts checked: %d" % checked)


def test_known_names_present():
    _, _, out, _ = inventory()
    names = {n for f in out["functions"] for n in f["names"]}
    for n in KNOWN_NAMES:
        assert n in names, "missing export name %s" % n


def test_jump_tables_recovered():
    img, _, out, _ = inventory()
    table_jumps = len(JMP_TABLE_RE.findall(img.data))
    recovered = out["summary"]["jump_table_count"]
    print("  switch-style jmp sites in file: %d, jump tables recovered: %d" %
          (table_jumps, recovered))
    if table_jumps:
        assert recovered >= 1, "switch-style jumps present but none recovered"


def test_gap_junk_rule():
    # gap-scan candidates decoding to port I/O, interrupts, es/gs overrides or undecodable bytes
    assert F.is_junk({"mnemonics": ["mov", "in"], "odd": ["in"]})
    assert F.is_junk({"mnemonics": ["add", "int1"], "odd": []})
    assert F.is_junk({"mnemonics": ["add"], "odd": ["undecodable"]})
    assert F.is_junk({"mnemonics": ["add", "call"], "odd": ["segment-override"]})
    # real code of this module: popfd (CPUID ID-flag probe) and cpuid must not be dropped
    assert not F.is_junk({"mnemonics": ["mov", "call"], "odd": ["popfd", "cpuid"]})


def test_module_bases_match_emulator():
    # modbases.py copies emu/mpemu.py's dict; read the source so the test needs no unicorn import
    src = open(os.path.join(REPO, "emu", "mpemu.py")).read()
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "MODULE_BASES"
                                                for t in node.targets):
            emu = ast.literal_eval(node.value)
            break
    else:
        raise AssertionError("MODULE_BASES not found in emu/mpemu.py")
    assert MODULE_BASES == emu, (MODULE_BASES, emu)


def test_rlmfc_base_unchanged():
    # rlmfc's preferred base is its load base, so the default must equal the explicit preferred base
    path = find_dll()
    assert path, "rlmfc.dll not found"
    _, _, out, _ = inventory()
    _, _, pref, _ = inventory_at(path, 0x10000000)
    assert out == pref
    assert out["base"] == "0x10000000"


def test_rlmfc_count_and_address_taken():
    # Address-taken seeds (code pointers in relocations) may add functions, never remove the
    # 1370 found before them. Prints the counts for review.
    _, _, out, _ = inventory()
    n = out["summary"]["function_count"]
    assert n >= 1370, n
    at = [f for f in out["functions"] if f["address_taken"]]
    assert len(at) == out["summary"]["address_taken_count"]
    assert all(not f["gap_scan"] for f in at), "an address-taken seed is a gap-scan find"
    print("  rlmfc functions: %d (was 1370), address-taken: %d, real entries: %d"
          % (n, len(at), sum(1 for f in out["functions"] if not f["gap_scan"])))


def test_grphmfc_shift():
    # grphmfc is preferred at 0x10000000 but the emulator maps it at 0x10200000: relocations
    # applied, so the inventory is the preferred-base one moved up by 0x200000.
    # Every function reached from exports, vtables, the entry point or calls matches exactly.
    # Gap-scan entries (code found by byte scan, not reached) may differ: analysing a candidate
    # walks relocated bytes, and a data-in-code candidate can decode differently per base.
    path = find_game("grphmfc.dll")
    assert path, "grphmfc.dll not found"
    _, _, pref, _ = inventory_at(path, 0x10000000)
    _, _, emu, _ = inventory_at(path, None)
    assert emu["base"] == "0x10200000", emu["base"]
    assert emu["summary"]["function_count"] > 100
    shifted = unshift(emu, 0x200000)
    assert shifted["base"] == pref["base"] and shifted["summary"]["entry_point"] == \
        pref["summary"]["entry_point"]
    assert shifted["summary"]["export_count"] == pref["summary"]["export_count"]
    assert shifted["summary"]["vtable_slot_count"] == pref["summary"]["vtable_slot_count"]

    def reached(out):
        return [f for f in out["functions"] if not f["gap_scan"]]
    assert reached(shifted) == reached(pref)
    gap = {f["entry"] for f in pref["functions"] if f["gap_scan"]} ^ \
        {f["entry"] for f in shifted["functions"] if f["gap_scan"]}
    print("  grphmfc functions: %d (gap-scan entries in only one base: %d), jump tables: %d"
          % (emu["summary"]["function_count"], len(gap), emu["summary"]["jump_table_count"]))
    assert len(gap) <= 20, len(gap)


# grphmfc at its emulator base (0x10200000): code pointers in relocations (see
# test_grphmfc_address_taken_seeds) and the switch tables recovered once they are entries.
GRPH_ADDRESS_TAKEN = [0x10207060, 0x1020c650, 0x10209990, 0x1020f730, 0x1020fe40]
GRPH_SWITCHES = {0x102020e9: 6,    # in 0x10201fb0: cmp eax,5 ; ja ; ~20 x87 insns ; jmp [eax*4+T]
                 0x102070b4: 17,   # byte-index switch (byte table 0x102072dc)
                 0x1020c69c: 8}


def test_grphmfc_address_taken_seeds():
    path = find_game("grphmfc.dll")
    assert path, "grphmfc.dll not found"
    _, _, out, _ = inventory_at(path, None)
    by = {int(f["entry"], 16): f for f in out["functions"]}
    for va in GRPH_ADDRESS_TAKEN:
        f = by.get(va)
        assert f is not None, "0x%x is not a function entry" % va
        assert not f["gap_scan"], "0x%x is a gap-scan find" % va
        assert f["address_taken"] is True, "0x%x not address-taken" % va
    print("  grphmfc address-taken seeds: %d of %d functions"
          % (out["summary"]["address_taken_count"], out["summary"]["function_count"]))


def test_grphmfc_switches_recovered():
    path = find_game("grphmfc.dll")
    assert path, "grphmfc.dll not found"
    _, _, out, _ = inventory_at(path, None)
    jts = {}
    for f in out["functions"]:
        for jt in f["jump_tables"]:
            jts[int(jt["at"], 16)] = jt
    for at, n in GRPH_SWITCHES.items():
        jt = jts.get(at)
        assert jt is not None, "switch jmp at 0x%x not recovered" % at
        assert len(jt["targets"]) == n, (hex(at), len(jt["targets"]))
    assert jts[0x102070b4]["byte_table"] is not None, "0x102070b4 should use a byte index table"
    owner = [f for f in out["functions"] if any(jt["at"] == "0x102020e9" for jt in f["jump_tables"])]
    assert [f["entry"] for f in owner] == ["0x10201fb0"], [f["entry"] for f in owner]


def test_function_entries_address_taken():
    from entries import function_entries
    ns = {"function_entries": function_entries}
    inv = {"functions": [
        {"entry": "0x100", "gap_scan": True, "address_taken": True, "calls": []},
        {"entry": "0x200", "gap_scan": True, "calls": []},
        {"entry": "0x300", "gap_scan": False},
        {"entry": "0x400", "gap_scan": True, "address_taken": False, "calls": []},
        {"entry": "0x500", "gap_scan": True, "calls": ["0x500"]},
    ]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(inv, fh)
    try:
        got = ns["function_entries"](fh.name)
    finally:
        os.unlink(fh.name)
    assert got == {0x100, 0x300, 0x500}, sorted(hex(x) for x in got)
    # the 5 patched bytes must not overlap a real function's code; junk gap finds do not count
    inv = {"functions": [
        {"entry": "0x1000", "gap_scan": False, "blocks": [{"start": "0x1000", "end": "0x1010"}]},
        {"entry": "0x1008", "gap_scan": True, "address_taken": True, "blocks": []},   # label inside 0x1000
        {"entry": "0x0ffd", "gap_scan": False, "blocks": [{"start": "0x0ffd", "end": "0x0ffe"}]},  # spills into 0x1000
        {"entry": "0x2000", "gap_scan": False, "blocks": [{"start": "0x2000", "end": "0x2010"}]},
        {"entry": "0x1ff8", "gap_scan": True, "calls": [], "blocks": [{"start": "0x1ff8", "end": "0x2004"}]},  # junk
    ]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(inv, fh)
    try:
        got = ns["function_entries"](fh.name)
    finally:
        os.unlink(fh.name)
    assert got == {0x1000, 0x2000}, sorted(hex(x) for x in got)


def synthetic_image():
    """A PE-less image: .text with a ret-only function (A), a function (B), junk (C: in al,80),
    and D, plus .rdata holding code pointers and an stxt section holding one more (D's address).
    Only the Image fields that the seeding reads are set."""
    text = bytes([0x55, 0x8B, 0xEC, 0x5D, 0xC3]) + b"\xcc" * 11      # 0x1000 A: push/mov/pop/ret
    text += bytes([0x8B, 0x44, 0x24, 0x04, 0xC3]) + b"\xcc" * 11     # 0x1010 B: mov eax,[esp+4]
    text += bytes([0xE4, 0x80, 0xC3]) + b"\xcc" * 13                 # 0x1020 C: in al,0x80 (junk)
    text += bytes([0x8B, 0xC1, 0xC3])                                # 0x1030 D: mov eax,ecx
    text += b"\xcc" * (0x40 - len(text))
    rdata = struct.pack("<8I", 0x1010, 0x1020, 0x1001, 0x5000, 0x1000, 0, 0, 0)
    stxt = struct.pack("<I", 0x1030) + b"\0" * 12
    img = F.Image.__new__(F.Image)
    img.path, img.base, img.pe = "synthetic", 0, None
    img.data = img.file_data = text + rdata + stxt
    img.secs = [{"name": ".text", "lo": 0x1000, "hi": 0x1040, "raw": 0, "rsize": 0x40, "code": True},
                {"name": ".rdata", "lo": 0x2000, "hi": 0x2020, "raw": 0x40, "rsize": 0x20,
                 "code": False},
                {"name": "stxt774", "lo": 0x3000, "hi": 0x3010, "raw": 0x60, "rsize": 0x10,
                 "code": False}]
    img.thunks, img.iat = {}, {}
    return img


def test_data_pointer_seeds_synthetic():
    img = synthetic_image()
    recs = F.fixed_point(img, {0x1000})
    assert set(recs) == {0x1000}, sorted(hex(x) for x in recs)
    # .rdata: B (uncovered, decodes) yes; C (junk) no; 0x1001 inside A's block no; 0x5000 not
    # code no; A itself yes. stxt774 is never scanned, so D (0x1030) is absent.
    got = F.data_pointer_entries(img, recs, {0x1000}, {})
    assert got == {0x1000, 0x1010}, sorted(hex(x) for x in got)
    assert not F.has_base_relocs(img.pe)
    # the cover helper is strict: interior bytes of a block are covered; its start and the byte
    # after it are not (a block start that is not an entry may still be a function)
    cover = F._block_cover(recs)
    assert F._in_cover(cover, 0x1004) and not F._in_cover(cover, 0x1000)
    assert not F._in_cover(cover, 0x1005) and not F._in_cover(cover, 0x0fff)


def immediate_image():
    """A PE-less image whose only code pointer is an immediate: 0x1000 pushes the address of a
    function (0x1010), calls another (0x1020) and returns. The call target is an entry, but
    immediates that are branch targets are not address-taken seeds."""
    text = bytes([0x68, 0x10, 0x10, 0x00, 0x00])                    # push 0x1010
    text += bytes([0xE8, 0x16, 0x00, 0x00, 0x00, 0xC3])              # call 0x1020 ; ret
    text += b"\xcc" * (0x10 - len(text))
    text += bytes([0x8B, 0x44, 0x24, 0x04, 0xC3]) + b"\xcc" * 11     # 0x1010: mov eax,[esp+4]; ret
    text += bytes([0x8B, 0xC1, 0xC3])                                # 0x1020: mov eax,ecx; ret
    text += b"\xcc" * (0x40 - len(text))
    img = F.Image.__new__(F.Image)
    img.path, img.base, img.pe = "synthetic-imm", 0, None
    img.data = img.file_data = text
    img.secs = [{"name": ".text", "lo": 0x1000, "hi": 0x1040, "raw": 0, "rsize": 0x40, "code": True}]
    img.thunks, img.iat = {}, {}
    return img


def test_immediate_seeds_synthetic():
    img = immediate_image()
    recs = F.fixed_point(img, {0x1000})
    assert set(recs) == {0x1000, 0x1020}, sorted(hex(x) for x in recs)
    assert recs[0x1000]["_imms"] == {0x1010}, recs[0x1000]["_imms"]
    assert F.immediate_entries(img, recs, {0x1000}, {}) == {0x1010}
    assert F.no_reloc_seeds(img, recs, {0x1000}, {}) == {0x1010}
    # the call target is not an immediate candidate (it is in recs already, via the call)
    assert 0x1020 not in F.immediate_entries(img, recs, {0x1000}, {})


def padding_image():
    """A PE-less image like maxpayne.exe 0x4d4554: a data dword (0x1000) points one byte before the previous
    function's `pop ecx; ret`, which decodes as `add [ecx-0x3d], bl`, runs through nop padding and into the real
    function at 0x1008, whose address 0x1010 pushes (an atexit registration)."""
    text = bytes([0x00, 0x59, 0xC3]) + b"\x90" * 5                   # 0x1000: tail of a function, padding
    text += bytes([0x8B, 0xC1, 0xC3]) + b"\x90" * 5                  # 0x1008: mov eax,ecx; ret
    text += bytes([0x68, 0x08, 0x10, 0x00, 0x00, 0xC3])              # 0x1010: push 0x1008; ret
    text += b"\xcc" * (0x40 - len(text))
    rdata = struct.pack("<4I", 0x1000, 0, 0, 0)
    img = F.Image.__new__(F.Image)
    img.path, img.base, img.pe = "synthetic-pad", 0, None
    img.data = img.file_data = text + rdata
    img.secs = [{"name": ".text", "lo": 0x1000, "hi": 0x1040, "raw": 0, "rsize": 0x40, "code": True},
                {"name": ".rdata", "lo": 0x2000, "hi": 0x2010, "raw": 0x40, "rsize": 0x10, "code": False}]
    img.thunks, img.iat = {}, {}
    return img


def test_padding_seed_synthetic():
    # the value that runs through padding is dropped, the function behind it kept: when both are candidates in
    # one round, and when the stray value was accepted in an earlier round (its block covers the real one)
    img = padding_image()
    assert F._after_padding(img, 0x1000, 0x1008)
    assert not F._after_padding(img, 0x1008, 0x1009)          # mid-instruction, no padding: the inner one goes
    recs = F.fixed_point(img, {0x1010})
    assert F.no_reloc_seeds(img, recs, {0x1010}, {}) == {0x1008}
    recs = F.fixed_point(img, {0x1010, 0x1000})
    assert F._in_cover(F._block_cover(recs), 0x1008)
    assert F.no_reloc_seeds(img, recs, {0x1010, 0x1000}, {}) == {0x1008}


def test_maxpayne_exe_dynamic_targets():
    # every call target seen in the 80-frame sweep (lift-out/exe_entries.json, written by
    # emu/run_init.py --record-entries) is an inventory entry, and none lies strictly inside
    # another function's blocks. Skipped when either file is absent.
    path = find_game("MaxPayne.exe")
    truth = os.path.join(REPO, "lift-out", "exe_entries.json")
    if path is None or not os.path.isfile(truth):
        print("  SKIP: MaxPayne.exe or lift-out/exe_entries.json not found")
        return
    _, _, out, _ = inventory_at(path, None)
    entries = {int(f["entry"], 16) for f in out["functions"]}
    calls = [int(k, 16) for k in json.load(open(truth))["calls"]]
    missing = [t for t in calls if t not in entries]
    assert not missing, [hex(t) for t in missing[:5]]
    spans = sorted((int(b["start"], 16), int(b["end"], 16), int(f["entry"], 16))
                   for f in out["functions"] for b in f["blocks"])
    starts = [s for s, _, _ in spans]
    longest = max(e - s for s, e, _ in spans)
    inside = []
    for t in calls:
        j = bisect.bisect_left(starts, t) - 1
        while j >= 0 and starts[j] > t - longest:
            s, e, o = spans[j]
            if s < t < e and o != t:
                inside.append(t)
                break
            j -= 1
    assert not inside, [hex(t) for t in inside[:5]]
    print("  dynamic call targets: %d, all entries, none inside another function" % len(calls))


def test_analyze_cached_matches_fresh():
    # a cached analysis is reused only while its membership tests give the same answers
    img = synthetic_image()
    cache = {}
    F.analyze_cached(img, 0x1000, {0x1000}, cache)
    rec2, _ = F.analyze_cached(img, 0x1000, {0x1000, 0x1010}, cache)
    fresh, _ = F.analyze(img, 0x1000, {0x1000, 0x1010})
    assert rec2 == fresh


def test_maxpayne_exe_inventory():
    # MaxPayne.exe: no exports, no base relocations, seeded from the entry point, vtables, calls
    # and data pointers. Its stxt774/stxt371/.MGD32 sections are never code (never walked).
    path = find_game("MaxPayne.exe")
    if path is None:
        print("  SKIP: MaxPayne.exe not found")
        return
    img, exports, out, funcs = inventory_at(path, None)
    s = out["summary"]
    assert out["base"] == "0x400000", out["base"]
    assert s["export_count"] == 0 and not F.has_base_relocs(img.pe)
    entries = {int(f["entry"], 16) for f in out["functions"]}
    assert int(s["entry_point"], 16) in entries
    assert all(img.sec(va)["name"] == ".text" for va in entries), "entry outside .text"
    assert all(img.sec(int(b["start"], 16))["name"] == ".text"
               for f in out["functions"] for b in f["blocks"]), "block outside .text"
    # The count is printed, not bounded: the gap-scan share of it is not yet validated (see report).
    assert s["function_count"] >= 5000, s["function_count"]
    at = [f for f in out["functions"] if f["address_taken"]]
    assert at, "no data-pointer seeds"
    assert s["address_taken_count"] == len(at)
    # the switch at 0x5aa170 (`cmp eax,7; ja; mov edx,eax; jmp [edx*4+0x5abe08]`) is recovered through the
    # register copy; its case targets are blocks of 0x5a8b90, not entries (0x5ab1d0 was one of them)
    jts = {j["at"]: j for f in out["functions"] for j in f["jump_tables"]}
    assert len(jts["0x5aa170"]["targets"]) == 8, jts.get("0x5aa170")
    owner = next(f for f in out["functions"] if f["entry"] == "0x5a8b90")
    assert not owner["gap_scan"] and owner["jump_tables"], owner["entry"]
    assert 0x5ab1d0 not in entries and 0x5aa230 not in entries
    print("  MaxPayne.exe functions: %d, address-taken (data pointers): %d, gap-scan: %d, "
          "jump tables: %d, has_seh: %d" % (s["function_count"], len(at),
                                           sum(1 for f in out["functions"] if f["gap_scan"]),
                                           s["jump_table_count"], s["has_seh_count"]))


def switch_fixture(seq, n_cases, base=0x1000, table=0x2000):
    """Synthetic switch: `seq` (bytes, placed at base) ends in `jmp dword ptr [R*4 + table]`, and n_cases
    one-byte `ret` targets follow it. Returns (find_switch arguments, expected case targets)."""
    targets = [base + len(seq) + k for k in range(n_cases)]
    code = bytes(seq) + b"\xc3" * n_cases
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    insns = list(md.disasm(code, base))
    order = {i.address: k for k, i in enumerate(insns)}
    by_addr = {i.address: i for i in insns}

    def prev_of(ins):
        k = order[ins.address]
        return insns[k - 1] if k > 0 else None

    rodata = b"".join(struct.pack("<I", t) for t in targets)

    def read(va, n):
        if table <= va and va + n <= table + len(rodata):
            return rodata[va - table:va - table + n]
        if base <= va and va + n <= base + len(code):
            return code[va - base:va - base + n]
        return None

    jmp = next(i for i in insns if i.mnemonic == "jmp")
    args = (read, set(targets).__contains__, by_addr[jmp.address], prev_of)
    return args, targets


def test_switch_follows_register_copies():
    # the exe's switch at 0x5aa170: cmp eax,7; ja default; mov edx,eax; jmp [edx*4+T] (8 entries)
    jmp_edx = bytes([0xFF, 0x24, 0x95]) + struct.pack("<I", 0x2000)
    ja = bytes([0x77, 0x10])
    args, targets = switch_fixture(bytes([0x83, 0xF8, 0x07]) + ja + bytes([0x8B, 0xD0]) + jmp_edx, 8)
    sw = F.find_switch(*args)
    assert sw is not None and sw["targets"] == targets and sw["byte_table"] is None, sw
    # a chain of copies: cmp ecx,3; ja; mov eax,ecx; mov edx,eax; jmp [edx*4+T] (4 entries)
    args, targets = switch_fixture(bytes([0x83, 0xF9, 0x03]) + ja + bytes([0x8B, 0xC1, 0x8B, 0xD0])
                                   + jmp_edx, 4)
    sw = F.find_switch(*args)
    assert sw is not None and sw["targets"] == targets, sw
    # no guard on the copied register: the bound is not found, so no table
    args, _ = switch_fixture(bytes([0x83, 0xF8, 0x07]) + ja + bytes([0x8B, 0xD3]) + jmp_edx, 8)
    assert F.find_switch(*args) is None
    # the source is overwritten between the compare and the copy: not the register that was bounded
    args, _ = switch_fixture(bytes([0x83, 0xF8, 0x07]) + ja + bytes([0x8B, 0xC3, 0x8B, 0xD0]) + jmp_edx, 8)
    assert F.find_switch(*args) is None
    # the copy's source is written by an instruction that is not a copy (add): not followed
    args, _ = switch_fixture(bytes([0x83, 0xF8, 0x07]) + ja + bytes([0x03, 0xC3, 0x8B, 0xD0]) + jmp_edx, 8)
    assert F.find_switch(*args) is None


def test_switch_register_bound():
    # the exe's e2mfc 0x10104280 shape: the bound lives in a callee-saved register, loaded once in
    # the function (here push ebx prologue, mov ebx,8, a call in between), then `cmp eax, ebx`.
    # Bound 8 gives 9 entries. find_switch needs the function entry (the fixture base) for this.
    jmp_eax = bytes([0xFF, 0x24, 0x85]) + struct.pack("<I", 0x2000)
    ja = bytes([0x77, 0x10])
    call_next = bytes([0xE8, 0, 0, 0, 0])
    seq = bytes([0x53]) + bytes([0xBB, 0x08, 0, 0, 0]) + call_next + bytes([0x3B, 0xC3]) + ja + jmp_eax
    args, targets = switch_fixture(seq, 9)
    sw = F.find_switch(*args, 0x1000)
    assert sw is not None and len(sw["targets"]) == 9 and sw["targets"] == targets, sw
    assert sw["byte_table"] is None and sw["table"] == 0x2000, sw
    # without the entry the register bound is not checked, so no table
    assert F.find_switch(*args) is None
    # esi as the bound register (cmp eax, esi), no call in between
    seq = bytes([0xBE, 0x08, 0, 0, 0]) + bytes([0x3B, 0xC6]) + ja + jmp_eax
    args, targets = switch_fixture(seq, 9)
    sw = F.find_switch(*args, 0x1000)
    assert sw is not None and sw["targets"] == targets, sw
    # a bound register outside the callee-saved set (ecx) is not followed: no table here
    seq = bytes([0xB9, 0x08, 0, 0, 0]) + bytes([0x3B, 0xC1]) + ja + jmp_eax
    args, _ = switch_fixture(seq, 9)
    assert F.find_switch(*args, 0x1000) is None


def test_switch_register_bound_unresolved():
    jmp_eax = bytes([0xFF, 0x24, 0x85]) + struct.pack("<I", 0x2000)
    ja = bytes([0x77, 0x10])
    cmp_ebx = bytes([0x3B, 0xC3]) + ja + jmp_eax
    mov8 = bytes([0xBB, 0x08, 0, 0, 0])
    cases = [
        # written twice: the second write decides the bound
        ("twice", mov8 + bytes([0xBB, 0x04, 0, 0, 0]) + cmp_ebx),
        # popped before the jump
        ("pop before jmp", mov8 + bytes([0x5B]) + cmp_ebx),
        # xor and mov from a register are not `mov ebx, imm32`
        ("xor", mov8 + bytes([0x33, 0xDB]) + cmp_ebx),
        ("mov ebx, edx", mov8 + bytes([0x8B, 0xDA]) + cmp_ebx),
        # lea writes ebx
        ("lea", mov8 + bytes([0x8D, 0x5B, 0x01]) + cmp_ebx),
        # no mov at all: nothing defines the bound
        ("no def", bytes([0x90]) + cmp_ebx),
        # a forward jz over the mov reaches the compare without it: the mov does not dominate
        ("jz over mov", bytes([0x74, 0x05]) + mov8 + cmp_ebx),
    ]
    for name, seq in cases:
        args, _ = switch_fixture(seq, 9)
        assert F.find_switch(*args, 0x1000) is None, name


def test_e2mfc_switch_0x10104280():
    # e2mfc.dll P_Text::executeAlways: `cmp eax, ebx; ja; jmp [eax*4+0x10104ddc]` with ebx = 8 set by
    # `mov ebx, 8` at 0x10104351. The 9 case labels must be jump-table targets, never entries.
    path = find_game("e2mfc.dll")
    if path is None:
        print("  SKIP: e2mfc.dll not found (set MP_GAME_DIR)")
        return
    _, _, out, _ = inventory_at(path, None)
    jts = {int(jt["at"], 16): jt for f in out["functions"] for jt in f["jump_tables"]}
    jt = jts.get(0x101043ae)
    assert jt is not None, "switch jmp at 0x101043ae not recovered"
    assert jt["table"] == "0x10104ddc" or jt["table"] == 0x10104ddc, jt["table"]
    targets = [int(t, 16) if isinstance(t, str) else t for t in jt["targets"]]
    assert len(targets) == 9, targets
    assert targets[0] == 0x101043b5 and targets[-1] == 0x1010445a, [hex(t) for t in targets]
    entries = {int(f["entry"], 16) for f in out["functions"]}
    assert not entries & set(targets), [hex(t) for t in entries & set(targets)]
    owner = [f["entry"] for f in out["functions"] if any(j["at"] == "0x101043ae" for j in f["jump_tables"])]
    assert owner == ["0x10104280"], owner
    print("  e2mfc 0x10104280: jump table at 0x10104ddc, %d targets, none is an entry" % len(targets))


def neg_fixture(seq, n_cases, base=0x1000, table=0x2020):
    """Synthetic negated-index switch: `seq` (placed at base) ends in `jmp dword ptr [R*4 + table]`
    with R = -k for case k; case k's target is the one-byte `ret` at base+len(seq)+k, and it is the
    dword at table - 4k (the table is read backwards from its address). Returns (find_switch
    arguments, case targets by k)."""
    targets = [base + len(seq) + k for k in range(n_cases)]
    code = bytes(seq) + b"\xc3" * n_cases
    lo = table - 4 * (n_cases - 1)
    data = bytearray(4 * n_cases)
    for k, t in enumerate(targets):
        struct.pack_into("<I", data, (table - 4 * k) - lo, t)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    insns = list(md.disasm(code, base))
    order = {i.address: k for k, i in enumerate(insns)}
    by_addr = {i.address: i for i in insns}

    def prev_of(ins):
        k = order[ins.address]
        return insns[k - 1] if k > 0 else None

    def read(va, n):
        if lo <= va and va + n <= lo + len(data):
            return bytes(data[va - lo:va - lo + n])
        if base <= va and va + n <= base + len(code):
            return code[va - base:va - base + n]
        return None

    jmp = next(i for i in insns if i.mnemonic == "jmp")
    return (read, set(targets).__contains__, by_addr[jmp.address], prev_of), targets


def mem_fixture(code, base, data_base, data, code_targets):
    """A function's bytes at base (decoded linearly, so the last jmp is the switch) and a data blob
    at data_base. Returns the find_switch arguments without the entry."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    insns = list(md.disasm(code, base))
    order = {i.address: k for k, i in enumerate(insns)}
    by_addr = {i.address: i for i in insns}

    def prev_of(ins):
        k = order[ins.address]
        return insns[k - 1] if k > 0 else None

    def read(va, n):
        if data_base <= va and va + n <= data_base + len(data):
            return data[va - data_base:va - data_base + n]
        if base <= va and va + n <= base + len(code):
            return code[va - base:va - base + n]
        return None

    jmp = [i for i in insns if i.mnemonic == "jmp"][-1]
    return read, set(code_targets).__contains__, by_addr[jmp.address], prev_of


def test_switch_jae_bound():
    # cmp eax, N ; jae default ; jmp [eax*4+T] takes 0..N-1: N entries (ja takes N+1)
    jmp_eax = bytes([0xFF, 0x24, 0x85]) + struct.pack("<I", 0x2000)
    jae = bytes([0x73, 0x10])
    args, targets = switch_fixture(bytes([0x83, 0xF8, 0x08]) + jae + jmp_eax, 8)
    sw = F.find_switch(*args)
    assert sw is not None and sw["targets"] == targets and sw["values"] == list(range(8)), sw
    args, targets = switch_fixture(bytes([0x83, 0xF8, 0x04, 0x73, 0x10]) + jmp_eax, 4)     # jnb
    sw = F.find_switch(*args)
    assert sw is not None and sw["targets"] == targets, sw
    # cmp eax, 0 ; jae: the switch would have no entries at all
    args, _ = switch_fixture(bytes([0x83, 0xF8, 0x00]) + jae + jmp_eax, 1)
    assert F.find_switch(*args) is None


def test_switch_memory_bound():
    # the exe's 0x776e5a: cmp dword ptr [esp+0x58], 5 ; mov [esp+0x28], edi ; ja default ;
    # mov ecx, [esp+0x58] ; jmp [ecx*4+T] (6 entries)
    jmp_ecx = bytes([0xFF, 0x24, 0x8D]) + struct.pack("<I", 0x2000)
    cmp_m = bytes([0x83, 0x7C, 0x24, 0x58, 0x05])
    store_other = bytes([0x89, 0x7C, 0x24, 0x28])
    ja = bytes([0x77, 0x10])
    load = bytes([0x8B, 0x4C, 0x24, 0x58])
    args, targets = switch_fixture(cmp_m + store_other + ja + load + jmp_ecx, 6)
    sw = F.find_switch(*args)
    assert sw is not None and sw["targets"] == targets and sw["values"] == list(range(6)), sw
    # loaded from a different slot than the one compared: no bound
    args, _ = switch_fixture(cmp_m + ja + bytes([0x8B, 0x4C, 0x24, 0x5C]) + jmp_ecx, 6)
    assert F.find_switch(*args) is None
    # the compared slot is stored to before the load
    args, _ = switch_fixture(cmp_m + ja + bytes([0x89, 0x7C, 0x24, 0x58]) + load + jmp_ecx, 6)
    assert F.find_switch(*args) is None
    # a push moves esp between the compare and the load
    args, _ = switch_fixture(cmp_m + ja + bytes([0x50]) + load + jmp_ecx, 6)
    assert F.find_switch(*args) is None


def test_switch_pushpop_bound():
    # MFC42 0x5f44fb10: push 0xc ; dec eax ; pop ecx ; cmp eax, ecx ; ja default ; jmp [eax*4+T] (13 entries)
    jmp_eax = bytes([0xFF, 0x24, 0x85]) + struct.pack("<I", 0x2000)
    ja = bytes([0x77, 0x10])
    tail = bytes([0x59, 0x3B, 0xC1]) + ja + jmp_eax         # pop ecx ; cmp eax, ecx ; ja
    args, targets = switch_fixture(bytes([0x6A, 0x0C, 0x48]) + tail, 13)
    sw = F.find_switch(*args)
    assert sw is not None and sw["targets"] == targets and sw["values"] == list(range(13)), sw
    # jae: push 4 gives 0..3
    args, targets = switch_fixture(bytes([0x6A, 0x04, 0x59, 0x3B, 0xC1, 0x73, 0x10]) + jmp_eax, 4)
    sw = F.find_switch(*args)
    assert sw is not None and sw["targets"] == targets, sw
    # the popped value is not the pushed immediate: push ebx, or another push in between
    for name, pre in (("push reg", bytes([0x53])), ("two pushes", bytes([0x6A, 0x0C, 0x53, 0x5B])),
                      ("call between", bytes([0x6A, 0x0C, 0xE8, 0, 0, 0, 0])),
                      ("ecx written after pop", bytes([0x6A, 0x0C, 0x59, 0x41]))):
        seq = pre + (bytes([0x3B, 0xC1]) + ja + jmp_eax if name == "ecx written after pop" else tail)
        args, _ = switch_fixture(seq, 13)
        assert F.find_switch(*args) is None, name


def test_switch_and_mask():
    # and eax, 2^k-1 directly before the jump: 2^k entries, no compare
    jmp_eax = bytes([0xFF, 0x24, 0x85]) + struct.pack("<I", 0x2000)
    args, targets = switch_fixture(bytes([0x83, 0xE0, 0x03]) + jmp_eax, 4)
    sw = F.find_switch(*args)
    assert sw is not None and sw["targets"] == targets and sw["values"] == [0, 1, 2, 3], sw
    args, targets = switch_fixture(bytes([0x83, 0xE0, 0x3F]) + jmp_eax, 64)
    sw = F.find_switch(*args)
    assert sw is not None and sw["targets"] == targets, sw
    # the mask is not 2^k-1: no bound
    args, _ = switch_fixture(bytes([0x83, 0xE0, 0x05]) + jmp_eax, 6)
    assert F.find_switch(*args) is None
    # a write after the and (add eax, 1): the index is no longer masked
    args, _ = switch_fixture(bytes([0x83, 0xE0, 0x03, 0x83, 0xC0, 0x01]) + jmp_eax, 4)
    assert F.find_switch(*args) is None


def test_switch_negated_index():
    # cmp eax, 8 ; jae default ; neg eax ; jmp [eax*4+T]: index -k for k in 0..7, the case for k at
    # T-4k. The values are 0, -1, ..., -7 (mod 2^32), each with its own target.
    jmp_eax = bytes([0xFF, 0x24, 0x85]) + struct.pack("<I", 0x2020)
    args, targets = neg_fixture(bytes([0x83, 0xF8, 0x08, 0x73, 0x10, 0xF7, 0xD8]) + jmp_eax, 8)
    sw = F.find_switch(*args)
    assert sw is not None and sw["targets"] == targets, sw
    assert sw["values"] == [(-k) & 0xFFFFFFFF for k in range(8)], sw["values"]
    # no guard before the neg: the range is unknown, so no table
    args, _ = neg_fixture(bytes([0xF7, 0xD8]) + jmp_eax, 8)
    assert F.find_switch(*args) is None


def test_switch_sub_jb_entry():
    # memcpy's tail (MSVC): sub ecx, 4 ; jb J ; ret ; J: jmp [ecx*4+T]. J is reached only through
    # the jb, when ecx < 4, and then ecx-4 is -4..-1. The table entries are at T-16..T-4.
    base, data_base = 0x1000, 0x2000
    code_base = bytes.fromhex("83e904 7201 c3") + bytes.fromhex("ff248d 10200000")
    targets = [0x1010, 0x1011, 0x1012, 0x1013]
    data = b"".join(struct.pack("<I", t) for t in targets)
    args = mem_fixture(code_base, base, data_base, data, targets)
    sw = F.find_switch(*args, base)
    assert sw is not None and sw["targets"] == targets, sw
    assert sw["values"] == [0xFFFFFFFC, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF], sw["values"]
    # something falls into J (a nop between the ret and J): no proof
    code_nop = bytes.fromhex("83e904 7202 c3 90") + bytes.fromhex("ff248d 10200000")
    args = mem_fixture(code_nop, base, data_base, data, targets)
    assert F.find_switch(*args, base) is None
    # without the entry the jb cannot be checked
    args = mem_fixture(code_base, base, data_base, data, targets)
    assert F.find_switch(*args) is None



def test_msvcrt_switch_tables():
    # MSVCRT.DLL: the memcpy/memmove tables that the new rules resolve (preferred base 0x78000000).
    path = find_game("MSVCRT.DLL")
    if path is None:
        print("  skipped MSVCRT switch test: no game file")
        return
    img, exports, functions, slots, entry_va = F.inventory(path)
    out = F.build_output(img, exports, functions, slots, entry_va)
    jts = {j["at"]: j for f in out["functions"] for j in f["jump_tables"]}
    unresolved = {a for f in out["functions"] for a in f["unresolved_indirect_jumps"]}
    # memmove 0x78005802: the negated index (cmp ecx,8 ; jae ; neg ecx): 8 entries, values 0,-1,...
    j = jts["0x7800584b"]
    assert len(j["targets"]) == 8 and j["values"][:3] == ["0x0", "0xffffffff", "0xfffffffe"], j
    # memcpy 0x780015fd: cmp ecx,8 ; jae (8 entries, no values key) and and-masked edx (4 entries)
    assert len(jts["0x78001630"]["targets"]) == 8 and "values" not in jts["0x78001630"], jts["0x78001630"]
    # 0x78001651 (`and eax, 3` before its jump): its table's entry 0 is not code; the index is 0 only on a path the
    # alignment test rules out, so it takes 1..3 from SWITCH_HINTS, as memmove's 0x7801076f does
    assert jts["0x78001651"]["values"] == ["0x1", "0x2", "0x3"], jts.get("0x78001651")
    # memcpy's down copy: UnwindDownVec[-ecx] behind the neg at 0x78010f97, 8 entries
    assert len(jts["0x78010f99"]["targets"]) == 8, jts.get("0x78010f99")
    # _output's state table: push 7 ; pop ecx ; cmp eax, ecx ; ja (8 entries)
    assert len(jts["0x780020bf"]["targets"]) == 8, jts.get("0x780020bf")
    memcpy = next(f for f in out["functions"] if f["entry"] == "0x780015fd")
    assert not memcpy["unresolved_indirect_jumps"], memcpy["unresolved_indirect_jumps"]
    # the jb-only entry 0x78001658: sub ecx,4 ; jb J with values -4..-1
    assert jts["0x78001658"]["values"] == ["0xfffffffc", "0xfffffffd", "0xfffffffe", "0xffffffff"], \
        jts.get("0x78001658")
    # 0x780294b4: and eax,0x3f, 64 entries
    assert len(jts["0x780294b4"]["targets"]) == 64, jts.get("0x780294b4")
    # memmove's jumps the local rules cannot prove come from SWITCH_HINTS: the edx switch 0x7800586d (masked before
    # another switch) takes 0..3, and the lead-byte table 0x7801076f takes 1..3 (its entry 0 is the next table, data)
    assert len(jts["0x7800586d"]["targets"]) == 4 and "values" not in jts["0x7800586d"], jts.get("0x7800586d")
    assert jts["0x7801076f"]["values"] == ["0x1", "0x2", "0x3"], jts.get("0x7801076f")
    memmove = next(f for f in out["functions"] if f["entry"] == "0x78005802")
    assert not memmove["unresolved_indirect_jumps"] and "fcos" not in memmove["mnemonics"], memmove["mnemonics"]
    print("  MSVCRT: %d tables, %d unresolved indirect jumps" % (out["summary"]["jump_table_count"],
                                                               out["summary"]["unresolved_indirect_jumps"]))




TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]


if __name__ == "__main__":
    if find_dll() is None:
        print("SKIP: rlmfc.dll not found (set RLMFC_DLL to its path)")
        sys.exit(0)
    failed = 0
    for t in TESTS:
        try:
            t()
            print("PASS %s" % t.__name__)
        except AssertionError as e:
            failed += 1
            print("FAIL %s: %s" % (t.__name__, e))
    print("%d/%d passed" % (len(TESTS) - failed, len(TESTS)))
    sys.exit(1 if failed else 0)
