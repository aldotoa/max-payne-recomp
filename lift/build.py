#!/usr/bin/env python3
"""Lift a set of x86 functions with x86c and build them into one native dylib (M5 bridge).

Usage:
  build.py --module DLL[:INVENTORY] [--module DLL[:INVENTORY] ...] --entries real|all|<hex,...>
           [--keep-emulated HEX,...] [--keep-emulated-file PATH]
           [--out lift-out/lifted] [--lib build-lift/liblifted.dylib] [--write-log]
  build.py <dll> --entries real|all|<hex,...> [--inventory lift-out/rlmfc_functions.json]
           [--out lift-out/rlmfc] [--lib build-lift/librlmfc_lifted.dylib] [--write-log]

--module lifts several modules into one library and one table. DLL names without a directory resolve to
MP_GAME_DIR (default: "<repo>/Max Payne"); absolute paths and paths relative to the repository root also work.
INVENTORY defaults to lift-out/<stem>_functions.json (lift/functions.py writes it).

--entries: real = the function entries of each module's inventory (entries.function_entries, without its patch-overlap
guard, which only the emulator's entry patching needs: non-gap-scan entries,
plus gap-scan entries that some function calls); all = every inventory function; a hex list applies across the
modules by address (each VA goes to the one module whose code contains it).

--keep-emulated / --keep-emulated-file: entries removed before lifting. They stay in the emulator, and no lifted
function calls them directly.

Import thunks: an entry that is a `jmp [iat]` stub (6 bytes, the IAT slot of an import) is never lifted. It is
removed before lifting and listed as "thunk" in lifted.json (with its DLL!name in "thunk_targets"); it stays in the
emulator. Lifted callers resolve calls to the thunk as the import, as before.

Output: one C file per lifted function, <out>/<stem>/f_<va>.c per module (the single-module form writes
<out>/f_<va>.c), <out>/table.c (lift_table, sorted by va, all modules) and <out>/lifted.json (per module: lifted
entries, dropped entries with the reasons, kept-emulated entries, thunks). The C files and lift/runtime/*.c are compiled
into --lib. Object files go to <lib without extension>.obj/ and are reused while their sources are older than
they are.

Dropping: a function whose translation is not ok (it has unsupported instructions) is removed from the set
and the rest are lifted again, so no lifted function calls a dropped one directly. This repeats until the
set is stable. Dropped functions stay in the emulator.

Relative paths resolve against the repository root (the directory above lift/), so the defaults land in
lift-out/ and build-lift/ of the checkout the script runs from.
"""
import argparse
import concurrent.futures
import glob
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import x86c                                   # noqa: E402
from x86c import lift_function                # noqa: E402
from entries import function_entries, parse_va_text  # noqa: E402

RUNTIME = x86c.RUNTIME
NATIVE = os.path.join(HERE, "native")           # hand-written replacements for lifted functions (native_overrides)
CLANG = shutil.which("clang") or "/usr/bin/clang"
CFLAGS = ["-O2", "-std=gnu11", "-fPIC", "-Wall", "-Wno-unused-label", "-Wno-unused-variable",
          "-Wno-unused-function", "-I", RUNTIME]
SENTINEL = "{0xffffffffu, 0}"


def _path(p):
    return p if os.path.isabs(p) else os.path.join(ROOT, p)


def game_dir():
    return _path(os.environ.get("MP_GAME_DIR") or "Max Payne")


def resolve_dll(name):
    """A DLL name without a directory is in the game folder; an absolute path is used as is; any other relative
    path is relative to the repository root."""
    if os.path.isabs(name):
        return name
    if os.path.dirname(name) == "":
        return os.path.join(game_dir(), name)
    return _path(name)


def module_stem(dll):
    """The lower-case file stem: lift/functions.py writes lift-out/<stem>_functions.json with the same rule, so
    MaxPayne.exe -> maxpayne (its inventory is lift-out/maxpayne_functions.json)."""
    return os.path.splitext(os.path.basename(dll))[0].lower()


def parse_module(spec):
    """--module DLL[:INVENTORY] -> (dll path, inventory path). The inventory default is lift-out/<stem>_functions.json."""
    dll, _, inv = spec.partition(":")
    if not dll:
        raise ValueError("--module %r: no DLL name" % spec)
    if not inv:
        inv = os.path.join("lift-out", module_stem(dll) + "_functions.json")
    return resolve_dll(dll), _path(inv)


def read_keep(args):
    """The set of VAs given by --keep-emulated and --keep-emulated-file (one hex VA per line, '#' comments)."""
    keep = set()
    if args.keep_emulated:
        keep.update(int(x, 16) for x in args.keep_emulated.split(",") if x.strip())
    if args.keep_emulated_file:
        with open(_path(args.keep_emulated_file)) as fh:
            for line in fh:
                text = line.split("#", 1)[0].strip()
                if text:
                    keep.add(int(text, 16))
    return keep


# A function that calls setjmp or longjmp (an import thunk for one included) stays emulated: setjmp would save the
# bridge's return slot and the host stack, and a longjmp cannot unwind native frames.
SETJMP = {"_setjmp", "_setjmp3", "setjmp", "longjmp", "_longjmp"}


def setjmp_users(inv_path):
    """Entries of an inventory that call a setjmp/longjmp import, directly or as a `jmp [iat]` thunk."""
    with open(inv_path) as fh:
        inv = json.load(fh)
    return {int(f["entry"], 16) for f in inv["functions"]
            if any(i.split("!", 1)[-1] in SETJMP for i in f.get("imports_called", []))}


def entries_for(modules, spec):
    """modules: [(name, image, inventory path)]. spec: real, all, or a hex list. Returns {name: sorted entries}.
    real and all read each module's own inventory. A hex list is split by address: each VA goes to the one module
    whose code contains it (with one module, every VA goes to it)."""
    if spec in ("real", "all"):
        out = {}
        for name, _, inv in modules:
            if not os.path.exists(inv):
                raise SystemExit("%s: no inventory %s (lift/functions.py writes it)" % (name, inv))
            if spec == "real":
                out[name] = sorted(function_entries(inv, patchable=False))
            else:
                with open(inv) as fh:
                    out[name] = [int(f["entry"], 16) for f in json.load(fh)["functions"]]
        return out
    out = {name: [] for name, _, _ in modules}
    for va in sorted({int(x, 16) for x in spec.split(",") if x.strip()}):
        owners = [name for name, image, _ in modules if len(modules) == 1 or image.is_code(va)]
        if len(owners) != 1:
            raise SystemExit("0x%08x is in %d modules (%s); it needs exactly one" % (
                va, len(owners), ", ".join(owners) or "none"))
        out[owners[0]].append(va)
    return out


def entries_file_overrides(specs, modules):
    """--entries-file MODULE=PATH, repeated: the entries of one module from a file (one hex VA per line, '#' comments)
    instead of --entries. MODULE is matched by stem (MaxPayne.exe is maxpayne). Each VA must be code in that module.
    Returns {module name: sorted entries} for the named modules only."""
    out = {}
    for spec in specs:
        mod, _, path = spec.partition("=")
        names = [name for name, _, _ in modules if module_stem(name) == module_stem(mod)]
        if not mod or not path or len(names) != 1:
            raise SystemExit("--entries-file %r: give MODULE=PATH for one of the --module DLLs" % spec)
        name = names[0]
        image = next(img for n, img, _ in modules if n == name)
        vas = set()
        with open(_path(path)) as fh:
            for line in fh:
                text = line.split("#", 1)[0].strip()
                if text:
                    va = int(text, 16)
                    if not image.is_code(va):
                        raise SystemExit("--entries-file %s: 0x%08x is not code in %s" % (path, va, name))
                    vas.add(va)
        if name in out:
            raise SystemExit("--entries-file: %s given twice" % name)
        out[name] = sorted(vas)
    return out


def split_thunks(image, entries):
    """(rest, thunks): the entries that are import thunks are split off. A thunk is a 6-byte `jmp dword ptr [iat]` at
    the entry (x86c._thunk_slot; the same stubs as functions.Image.thunks). Calls to a thunk are already lifted as
    imports, so a thunk is never lifted and stays in the emulator. thunks = {va: 'DLL!name'}. A delay-import resolver
    stub (x86c.PEImage.delay_stubs) is split off the same way, with the name of the import its slot binds."""
    rest, thunks = [], {}
    delay = getattr(image, "delay_stubs", {})
    for va in entries:
        if va in delay:                       # a delay-import resolver stub: unreachable once the slots are bound
            thunks[va] = delay[va]
            continue
        slot = x86c._thunk_slot(image, va)
        if slot is None:
            rest.append(va)
        else:
            thunks[va] = image.iat[slot]
    return rest, thunks


def lift_set(image, entries, aux=()):
    """Lift entries as one set. Returns (kept, dropped): kept = {va: LiftResult} for the functions whose
    translation is ok with the final set as known_entries; dropped = {va: [reason, ...]}.
    aux: continuation entries (x86c.DEAD_FRAMES), lifted after the set is stable with the set as known_entries but never
    known themselves, so no lifted code reaches them by a direct call or jump (a jump inside the function that owns one
    stays a goto): only lift_jump/lift_call find them, through the table."""
    kept, dropped = _lift_main(image, entries)
    known = frozenset(kept)
    for va in sorted(set(aux) - set(kept)):
        try:
            res = lift_function(image, va, known, aux=True)
        except Exception as ex:
            dropped[va] = ["translator exception: %s" % ex]
            continue
        if res.ok:
            kept[va] = res
        else:
            dropped[va] = ["%08x: %s" % (a, text) for a, text in res.unsupported]
    return kept, dropped


def _lift_main(image, entries):
    todo = set(entries)
    dropped = {}
    while True:
        known = frozenset(todo)
        kept, bad = {}, {}
        for va in sorted(todo):
            try:
                res = lift_function(image, va, known)
            except Exception as ex:          # a bad input must not stop the whole build
                bad[va] = ["translator exception: %s" % ex]
                continue
            if res.ok:
                kept[va] = res
            else:
                bad[va] = ["%08x: %s" % (a, text) for a, text in res.unsupported]
        if not bad:
            return kept, dropped
        for va, reasons in bad.items():
            dropped[va] = reasons
            todo.discard(va)


def _write_if_changed(path, text):
    try:
        if open(path).read() == text:
            return
    except OSError:
        pass
    with open(path, "w") as fh:
        fh.write(text)


def _is_mm(op):
    return op.type == x86c.X86_OP_REG and x86c._MD.reg_name(op.reg).startswith("mm")


def fpu_flags(image, kept):
    """LiftEntry.flags bit 0 (LIFT_FLAG_FPU) for each kept function: the bridge must sync x87 and MMX state
    for it. A function has the flag if its own instructions use x87 (mnemonics starting with f) or MMX (emms, or
    an mm operand), if it makes a call the bridge cannot see through (an indirect call or jump, or a direct call
    or tail jump to a function that is not lifted: call_guest), or if it reaches a flagged kept function
    directly. Calls within the set are followed to a fixed point."""
    known = frozenset(kept)
    own, edges = {}, {}
    for va in kept:
        insns = x86c._scan(image, va, known)[0]
        flag = False
        direct = set()
        for ins in insns.values():
            if ins is None:
                continue
            m = ins.mnemonic
            if m.startswith("f") or m == "emms" or any(_is_mm(op) for op in ins.operands):
                flag = True
            if m in ("call", "jmp"):
                op = ins.operands[0] if ins.operands else None
                if op is not None and op.type == x86c.X86_OP_IMM:
                    t = op.imm & 0xffffffff
                    if t in known and (m == "call" or t != va):
                        direct.add(t)          # lifted call (self included) or tail jump to another lifted function
                    elif m == "call":
                        flag = True            # call of a function that is not lifted: call_guest
                    # other direct jumps stay inside the function (goto), and are scanned already
                else:
                    flag = True                 # indirect call or jump: lift_call or call_guest
        own[va] = flag
        edges[va] = direct
    flags = dict(own)
    changed = True
    while changed:
        changed = False
        for va in kept:
            if not flags[va] and any(flags[t] for t in edges[va]):
                flags[va] = changed = True
    return flags


def write_functions(kept, out_dir, flags=None):
    """f_<va>.c per kept function in out_dir, and removal of stale f_*.c from earlier runs. flags: {va: bool} for
    LiftEntry.flags (LIFT_FLAG_FPU); missing means no flag. Returns the file names written."""
    os.makedirs(out_dir, exist_ok=True)
    keep_names = set()
    for va in sorted(kept):
        fname = kept[va].name + ".c"
        keep_names.add(fname)
        _write_if_changed(os.path.join(out_dir, fname), kept[va].c)
    for stale in glob.glob(os.path.join(out_dir, "f_*.c")):
        if os.path.basename(stale) not in keep_names:
            os.remove(stale)
    return sorted(keep_names)


def write_table(table, out_dir):
    """table.c for every lifted function: table = {va: fpu flag bool}, one lift_table sorted by va."""
    lines = ['#include "lift.h"', ""]
    lines += ["void f_%08x(CPU *c);" % va for va in sorted(table)]
    lines += ["", "const LiftEntry lift_table[] = {"]
    lines += ["    {0x%08xu, f_%08x, %du}," % (va, va, 1 if table[va] else 0) for va in sorted(table)]
    lines += ["    " + SENTINEL + ",", "};", "const unsigned lift_table_len = %du;" % len(table), ""]
    os.makedirs(out_dir, exist_ok=True)
    _write_if_changed(os.path.join(out_dir, "table.c"), "\n".join(lines))
    return "table.c"


def write_sources(kept, out_dir, flags=None):
    """f_<va>.c per kept function and table.c in out_dir (single-module layout). Returns the file names."""
    flags = flags or {}
    names = write_functions(kept, out_dir, flags)
    write_table({va: flags.get(va, False) for va in kept}, out_dir)
    return names + ["table.c"]


def _newest_dep():
    deps = glob.glob(os.path.join(RUNTIME, "*.h")) + [__file__]
    return max(os.path.getmtime(p) for p in deps)


def native_functions(path):
    """The lifted functions a lift/native file defines: lines `void f_XXXXXXXX(CPU *c)` (definitions, not
    declarations)."""
    names = []
    with open(path) as fh:
        for line in fh:
            if line.startswith("void f_") and line.rstrip().endswith("(CPU *c)"):
                names.append(line.split()[1].split("(")[0])
    return names


def native_overrides(sources):
    """{lift/native/*.c: [function names]} for the native files whose every function is among the lifted sources (a
    build without that module leaves the file out). Each such function's generated C is still compiled, renamed
    lifted_XXXXXXXX (the native code's fallback), and the native definition takes its place in the library."""
    stems = {os.path.splitext(os.path.basename(s))[0] for s in sources}
    out = {}
    for path in sorted(glob.glob(os.path.join(NATIVE, "*.c"))):
        names = native_functions(path)
        if names and all(n in stems for n in names):
            out[path] = names
    return out


def compile_and_link(sources, lib, write_log=False, header_deps=True):
    """sources: C files. Compiles in parallel (incremental) and links the dylib. write_log: -DLIFT_WRITE_LOG (the
    guest write log of differential mode, runtime.c); the object directory is per library, so the two kinds of
    build never share objects. Object files are named after the source file name, so names must be unique.
    lift/native files replace the lifted functions they define (native_overrides). header_deps=False: an object is
    stale only when its source is newer (lift/relink.py: objects carried over from another library are kept even
    though the runtime headers or this script changed since)."""
    names = [os.path.basename(src) for src in sources]
    if len(set(names)) != len(names):
        raise ValueError("source file names must be unique (objects are named after them): %s" % names)
    extra = ["-DLIFT_WRITE_LOG"] if write_log else []
    objdir = os.path.splitext(lib)[0] + ".obj"
    os.makedirs(objdir, exist_ok=True)
    os.makedirs(os.path.dirname(lib) or ".", exist_ok=True)
    dep_time = _newest_dep() if header_deps else 0
    natives = native_overrides(sources)
    replaced = {n for ns in natives.values() for n in ns}
    units = []                                  # (source, object, extra flags)
    for src in sources:
        stem = os.path.splitext(os.path.basename(src))[0]
        if stem in replaced:
            units.append((src, os.path.join(objdir, "lifted_" + stem[2:] + ".o"), ["-D%s=lifted_%s" % (stem, stem[2:])]))
        else:
            units.append((src, os.path.join(objdir, stem + ".o"), []))
    for path in natives:
        units.append((path, os.path.join(objdir, "native_" + os.path.splitext(os.path.basename(path))[0] + ".o"), []))
    jobs = []
    objs = []
    for src, obj, flags in units:
        objs.append(obj)
        if os.path.exists(obj) and os.path.getmtime(obj) >= max(os.path.getmtime(src), dep_time):
            continue
        jobs.append((src, obj, flags))

    def cc(job):
        src, obj, flags = job
        r = subprocess.run([CLANG, *CFLAGS, *extra, *flags, "-c", src, "-o", obj], capture_output=True, text=True)
        if r.returncode:
            if os.path.exists(obj):
                os.remove(obj)
            raise RuntimeError("clang failed on %s:\n%s" % (src, r.stderr[-2000:]))

    workers = max(1, (os.cpu_count() or 2))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in concurrent.futures.as_completed([pool.submit(cc, j) for j in jobs]):
            fut.result()
    # Many objects (the exe hot set has ~10k functions) exceed the argument limit: link from a response file.
    rsp = os.path.join(objdir, "link.rsp")
    with open(rsp, "w") as fh:
        fh.write("\n".join('"%s"' % o for o in objs) + "\n")
    r = subprocess.run([CLANG, "-dynamiclib", "-o", lib, "@" + rsp], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError("link failed:\n" + r.stderr[-2000:])
    return {"compiled": len(jobs), "reused": len(objs) - len(jobs)}


def runtime_sources():
    return sorted(glob.glob(os.path.join(RUNTIME, "*.c")))


def build(image, entries, out_dir, lib, module="", write_log=False, aux=()):
    """Single-module build: lift entries from image, write the C into out_dir (flat), compile into lib. Returns the
    summary dict (also written to out_dir/lifted.json). write_log: build with the guest write log (differential
    mode)."""
    entries, thunks = split_thunks(image, entries)
    kept, dropped = lift_set(image, entries, aux)
    flags = fpu_flags(image, sorted(kept)) if kept else {}
    sources = write_sources(kept, out_dir, flags)
    sources = [os.path.join(out_dir, s) for s in sources] + runtime_sources()
    stats = compile_and_link(sources, lib, write_log=write_log)
    summary = {
        "module": module,
        "lib": lib,
        "write_log": write_log,
        "requested": len(entries) + len(thunks),
        "thunk": ["0x%08x" % va for va in sorted(thunks)],
        "thunk_targets": {"0x%08x" % va: thunks[va] for va in sorted(thunks)},
        "lifted": ["0x%08x" % va for va in sorted(kept)],
        "fpu": ["0x%08x" % va for va in sorted(kept) if flags.get(va)],
        "dropped": [{"entry": "0x%08x" % va, "reasons": dropped[va][:20]} for va in sorted(dropped)],
        "build": stats,
    }
    with open(os.path.join(out_dir, "lifted.json"), "w") as fh:
        json.dump(summary, fh, indent=1)
    return summary


def build_modules(modules, out_dir, lib, write_log=False, keep=frozenset(), aux=frozenset()):
    """Multi-module build: modules = [(dll basename, image, entries)]. Each module is lifted as its own set (the
    function sets are disjoint), its C goes to out_dir/<stem>/, and one table.c covers all of them. keep: VAs
    removed from every module's entries before lifting (they stay in the emulator). aux: continuation entries
    (lift_set), each lifted with the module whose code contains it. Returns the summary dict
    (also written to out_dir/lifted.json)."""
    stems = [module_stem(name) for name, _, _ in modules]
    if len(set(stems)) != len(stems):
        raise ValueError("module names must have distinct stems: %s" % stems)
    table, per_module, sources = {}, [], []
    for (name, image, entries), stem in zip(modules, stems):
        emulated = sorted(set(entries) & set(keep))
        todo = sorted(set(entries) - set(keep))
        todo, thunks = split_thunks(image, todo)
        kept, dropped = lift_set(image, todo, [va for va in aux if image.is_code(va)])
        flags = fpu_flags(image, sorted(kept)) if kept else {}
        mod_dir = os.path.join(out_dir, stem)
        names = write_functions(kept, mod_dir, flags)
        sources += [os.path.join(mod_dir, n) for n in names]
        for va in kept:
            if va in table:
                raise ValueError("0x%08x is in two modules" % va)
            table[va] = bool(flags.get(va))
        per_module.append({
            "module": name,
            "requested": len(entries),
            "kept_emulated": ["0x%08x" % va for va in emulated],
            "thunk": ["0x%08x" % va for va in sorted(thunks)],
            "thunk_targets": {"0x%08x" % va: thunks[va] for va in sorted(thunks)},
            "lifted": ["0x%08x" % va for va in sorted(kept)],
            "fpu": ["0x%08x" % va for va in sorted(kept) if flags.get(va)],
            "dropped": [{"entry": "0x%08x" % va, "reasons": dropped[va][:20]} for va in sorted(dropped)],
        })
    write_table(table, out_dir)
    sources = [os.path.join(out_dir, "table.c")] + sources + runtime_sources()
    stats = compile_and_link(sources, lib, write_log=write_log)
    summary = {
        "lib": lib,
        "table": os.path.join(out_dir, "table.c"),
        "table_len": len(table),
        "write_log": write_log,
        "modules": per_module,
        "build": stats,
    }
    with open(os.path.join(out_dir, "lifted.json"), "w") as fh:
        json.dump(summary, fh, indent=1)
    return summary


def make_parser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dll", nargs="?", help="single-module form: the DLL (a name without a directory is in MP_GAME_DIR)")
    ap.add_argument("--module", action="append", default=[], metavar="DLL[:INVENTORY]",
                    help="a module to lift into the same library; repeat for each module")
    ap.add_argument("--entries", required=True,
                    help="real, all, or hex VAs, comma separated (see the module docstring)")
    ap.add_argument("--inventory", help="single-module form: the function inventory (default lift-out/<stem>_functions.json)")
    ap.add_argument("--out", help="output directory (default: lift-out/<stem> for one DLL, lift-out/lifted with --module)")
    ap.add_argument("--lib", help="dylib to build (default: build-lift/lib<stem>_lifted.dylib for one DLL, "
                                  "build-lift/liblifted.dylib with --module)")
    ap.add_argument("--entries-file", action="append", default=[], metavar="MODULE=PATH",
                    help="multi-module form: this module's entries from a file (one hex VA per line) instead of "
                         "--entries; repeat per module, e.g. --entries real --entries-file MaxPayne.exe=hot.txt")
    ap.add_argument("--keep-emulated", default="", metavar="HEX,...",
                    help="entries that stay in the emulator (removed before lifting)")
    ap.add_argument("--keep-emulated-file", metavar="PATH",
                    help="like --keep-emulated, one hex VA per line; '#' starts a comment")
    ap.add_argument("--write-log", action="store_true",
                    help="build with the guest write log (-DLIFT_WRITE_LOG), for emu/run_init.py --diff-lift; "
                         "use a separate --lib name")
    ap.add_argument("--no-dead-flags", action="store_true",
                    help="keep every flag computation (the translator's dead-flag elimination is on by default); "
                         "for A/B comparisons")
    ap.add_argument("--no-x87-locals", action="store_true",
                    help="keep the x87 stack in the CPU struct at every instruction (x87 locals within a block are on "
                         "by default, x86c.X87Cache); for A/B comparisons")
    ap.add_argument("--no-x87-cw-local", action="store_true",
                    help="read c->cw in every x87 arithmetic helper (the control word is kept in a local by default, "
                         "x86c.X87_CW_LOCAL); for A/B comparisons")
    ap.add_argument("--dead-frames", action="store_true",
                    help="native non-local transfers (x86c.DEAD_FRAMES, E3): also lifts the setjmp users, so build "
                         "MSVCRT's _setjmp3/longjmp lifted with them (a lifted call to an emulated _setjmp3 pushes the "
                         "bridge's return address, which setjmp would record)")
    ap.add_argument("--aux-entries-file", metavar="PATH",
                    help="continuation entries (one hex VA per line): lifted, in the table, never direct targets")
    ap.add_argument("--entry-hook", default="", metavar="HEX,...",
                    help="lifted functions that call the host's entry hook at entry (x86c.ENTRY_HOOKS; E4: the frame "
                         "function 0x40c020 for run_init.py --real-entry)")
    ap.add_argument("--exit-hook", default="", metavar="HEX,...",
                    help="lifted functions that call the host's exit hook at every ret (x86c.EXIT_HOOKS; M7: "
                         "P_Camera::validate 0x10114d60 for mphost's Hor+)")
    ap.add_argument("--insn-hook", default="", metavar="HEX,...",
                    help="instructions before which the lifted code calls the host's instruction hook, the x87 stack "
                         "in the CPU struct (x86c.INSN_HOOKS; M7: the portal code's 4:3 tangent, 0x67a148 and "
                         "0x67aec8, for mphost's Hor+)")
    return ap


def check_args(ap, a):
    if bool(a.dll) == bool(a.module):
        ap.error("give either one DLL, or one or more --module DLL[:INVENTORY]")
    if a.module and a.inventory:
        ap.error("--inventory is for the single-module form; with --module use --module DLL:INVENTORY")


def main(argv):
    ap = make_parser()
    a = ap.parse_args(argv)
    check_args(ap, a)
    x86c.DEAD_FLAGS = not a.no_dead_flags
    x86c.X87_LOCALS = not a.no_x87_locals
    x86c.X87_CW_LOCAL = not a.no_x87_cw_local
    x86c.DEAD_FRAMES = a.dead_frames
    x86c.ENTRY_HOOKS = frozenset(int(x, 16) for x in a.entry_hook.split(",") if x.strip())
    x86c.EXIT_HOOKS = frozenset(int(x, 16) for x in a.exit_hook.split(",") if x.strip())
    x86c.INSN_HOOKS = frozenset(int(x, 16) for x in a.insn_hook.split(",") if x.strip())
    keep = read_keep(a)
    aux = set()
    if a.aux_entries_file:
        aux = parse_va_text(open(_path(a.aux_entries_file)).read())
    if a.dll:
        dll = resolve_dll(a.dll)
        stem = module_stem(dll)
        inv = _path(a.inventory or os.path.join("lift-out", stem + "_functions.json"))
        image = x86c.PEImage(dll)
        entries = entries_for([(os.path.basename(dll), image, inv)], a.entries)[os.path.basename(dll)]
        if os.path.exists(inv) and not a.dead_frames:
            keep |= setjmp_users(inv)
        entries = sorted(set(entries) - keep)
        s = build(image, entries, _path(a.out or os.path.join("lift-out", stem)),
                  _path(a.lib or os.path.join("build-lift", "lib%s_lifted.dylib" % stem)),
                  module=os.path.basename(dll), write_log=a.write_log, aux=aux)
        print("%s: requested %d, thunk %d, lifted %d, dropped %d (compiled %d, reused %d)" % (
            s["module"], s["requested"], len(s["thunk"]), len(s["lifted"]), len(s["dropped"]),
            s["build"]["compiled"], s["build"]["reused"]))
        for d in s["dropped"][:10]:
            print("  dropped %s: %s" % (d["entry"], d["reasons"][0] if d["reasons"] else ""))
        print("wrote %s and %s" % (os.path.join(_path(a.out or os.path.join("lift-out", stem)), "table.c"), s["lib"]))
        return 0
    specs = [parse_module(m) for m in a.module]
    modules = [(os.path.basename(dll), x86c.PEImage(dll), inv) for dll, inv in specs]
    per = entries_for(modules, a.entries)
    per.update(entries_file_overrides(a.entries_file, modules))
    for _, _, inv in modules:
        if os.path.exists(inv) and not a.dead_frames:
            keep |= setjmp_users(inv)
    out = _path(a.out or os.path.join("lift-out", "lifted"))
    lib = _path(a.lib or os.path.join("build-lift", "liblifted.dylib"))
    s = build_modules([(name, image, per[name]) for name, image, _ in modules], out, lib,
                      write_log=a.write_log, keep=keep, aux=aux)
    for m in s["modules"]:
        print("%s: requested %d, kept emulated %d, thunk %d, lifted %d, dropped %d" % (
            m["module"], m["requested"], len(m["kept_emulated"]), len(m["thunk"]), len(m["lifted"]),
            len(m["dropped"])))
        for d in m["dropped"][:10]:
            print("  dropped %s: %s" % (d["entry"], d["reasons"][0] if d["reasons"] else ""))
    print("table: %d entries (compiled %d, reused %d)" % (s["table_len"], s["build"]["compiled"],
                                                          s["build"]["reused"]))
    print("wrote %s and %s" % (s["table"], s["lib"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
