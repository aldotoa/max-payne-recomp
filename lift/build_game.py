#!/usr/bin/env python3
"""Build the whole lifted game library from a game folder, from a clean checkout (the recipe behind play.sh's library).

Usage: build_game.py [--game DIR] [--lib build-lift/liblifted_game.dylib] [--check] [--clean]

--game: the Max Payne folder (default: MP_GAME_DIR, else "<repo>/Max Payne"). Its ten modules must match
tools/game-hashes.txt: the lift and its hooks are tied to those exact binaries.
--check: only check the game folder (exit status 0 when it is usable), then stop.
--clean: delete the intermediate C and objects after a successful build (about 700 MB); only --lib is needed to play.

Steps: lift/functions.py writes an inventory for each module into lift-out/game-inv/, then one lift/build.py run
lifts all ten into --lib with the options below. The result matches the incremental H63 -> H64 -> H74..H77 -> H79
chain of libraries, built in one pass (lift/native overrides are applied by build.py itself).
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HASHES = os.path.join(ROOT, "tools", "game-hashes.txt")

# Lift order (the module order of the H63..H79 libraries' lifted.json).
MODULES = ["rlmfc.dll", "grphmfc.dll", "e2mfc.dll", "sndmfc.dll", "e2driver/e2_d3d8_driver_mfc.dll", "MaxPayne.exe",
           "MSVCRT.DLL", "MFC42.DLL", "MSVCP60.DLL", "MSVCIRT.DLL"]
DATA = ["x_data.ras", "x_english.ras", "x_level1.ras", "x_level2.ras", "x_level3.ras", "x_music.ras"]

KEEP_EMULATED_FILE = "lift/keep_crt_h63.txt"
AUX_ENTRIES_FILE = "lift/aux_continuations.txt"
ENTRY_HOOKS = [
    0x40c020,                               # H63: the frame function (dead frames)
    0x4c99f0, 0x4ca2a0, 0x4ca920,           # H75: HUD wrapper constructors (anchored HUD)
    0x10108040, 0x10104280,                 # H75: P_Sprite / P_Text executeAlways (e2mfc as loaded)
    0x4ab8f0,                               # H77: HUD fade layer to the screen edges
]
EXIT_HOOKS = [
    0x10114d60,                             # H74: P_Camera::validate (Hor+)
    0x10108040, 0x10104280,                 # H75: executeAlways
]
INSN_HOOKS = [0x67a148, 0x67aec8]           # H76: the exe's portal tangents


def hexlist(vas):
    return ",".join("0x%x" % va for va in vas)


def find_ci(folder, rel):
    """rel ("e2driver/x.dll") inside folder, matching each path part without regard to case; None if missing."""
    cur = folder
    for part in rel.split("/"):
        try:
            names = os.listdir(cur)
        except OSError:
            return None
        hit = next((n for n in names if n.lower() == part.lower()), None)
        if hit is None:
            return None
        cur = os.path.join(cur, hit)
    return cur


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def expected_hashes():
    out = {}
    with open(HASHES) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                digest, name = line.split(None, 1)
                out[name.lower()] = digest
    return out


def check_game(game):
    """{module: path} for a usable game folder; prints every problem and exits with status 3 otherwise."""
    want = expected_hashes()
    paths, problems = {}, []
    if not os.path.isdir(game):
        problems.append("not a folder: %s" % game)
    else:
        for m in MODULES:
            p = find_ci(game, m)
            if p is None:
                problems.append("missing %s" % m)
            elif sha256(p) != want[m.lower()]:
                problems.append("%s is a different version than the one this project supports" % m)
            else:
                paths[m] = p
        problems += ["missing %s" % d for d in DATA if find_ci(game, d) is None]
    if problems:
        print("The game folder can't be used:\n  " + "\n  ".join(problems), file=sys.stderr)
        print("Point at the folder of an installed Max Payne (retail/store 1.05) that has MaxPayne.exe, the *.dll\n"
              "files, the MSVC runtime DLLs and the x_*.ras archives. Modified or cracked files are not supported.",
              file=sys.stderr)
        sys.exit(3)
    return paths


def run(cmd):
    print("+ " + " ".join(cmd[:4]) + (" ..." if len(cmd) > 4 else ""), flush=True)
    subprocess.run(cmd, check=True, cwd=ROOT)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--game", default=os.environ.get("MP_GAME_DIR") or os.path.join(ROOT, "Max Payne"))
    ap.add_argument("--lib", default=os.path.join(ROOT, "build-lift", "liblifted_game.dylib"))
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--clean", action="store_true")
    a = ap.parse_args(argv)
    game = os.path.abspath(a.game)
    paths = check_game(game)
    print("Game folder OK: %s" % game)
    if a.check:
        return 0

    lib = os.path.abspath(a.lib)
    inv_dir = os.path.join(ROOT, "lift-out", "game-inv")
    out_dir = os.path.join(ROOT, "lift-out", "game")
    obj_dir = os.path.splitext(lib)[0] + ".obj"
    os.makedirs(inv_dir, exist_ok=True)
    # Always a clean object dir: a stale runtime object once went into a library unnoticed (H58).
    shutil.rmtree(obj_dir, ignore_errors=True)
    t0 = time.time()
    py = sys.executable
    specs = []
    for i, m in enumerate(MODULES, 1):
        stem = os.path.splitext(os.path.basename(m))[0].lower()
        inv = os.path.join(inv_dir, stem + "_functions.json")
        print("[%d/%d] inventory of %s" % (i, len(MODULES), m), flush=True)
        run([py, "lift/functions.py", paths[m], "-o", inv])
        specs += ["--module", "%s:%s" % (paths[m], inv)]
    print("Lifting and compiling all modules (this takes 10-20 minutes)...", flush=True)
    run([py, "lift/build.py"] + specs + [
        "--entries", "real", "--keep-emulated-file", KEEP_EMULATED_FILE, "--dead-frames",
        "--aux-entries-file", AUX_ENTRIES_FILE,
        "--entry-hook", hexlist(ENTRY_HOOKS), "--exit-hook", hexlist(EXIT_HOOKS), "--insn-hook", hexlist(INSN_HOOKS),
        "--out", out_dir, "--lib", lib])
    if a.clean:
        shutil.rmtree(out_dir, ignore_errors=True)
        shutil.rmtree(obj_dir, ignore_errors=True)
    print("Built %s in %.0f min" % (lib, (time.time() - t0) / 60))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
