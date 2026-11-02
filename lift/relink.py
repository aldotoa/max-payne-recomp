#!/usr/bin/env python3
"""A new library from an existing one's generated C and objects (the H74-H77 procedure): the objects are hard-linked
into the new library's object directory, sources newer than their objects are compiled (lift/runtime/*.c, lift/native
files and the lifted functions they replace, regenerated f_XXXXXXXX.c), and everything is linked.

Usage: relink.py --from build-lift/liblifted_full_h77.dylib --out lift-out/lifted_full_h77 --lib NEW.dylib

--out is the old library's source directory (table.c and <module>/f_*.c, as build.py --out wrote them). A carried-over
object is kept even when lift/runtime's headers changed since it was compiled: after a header change, build the
library from scratch with build.py."""
import argparse
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import build  # noqa: E402


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--from", dest="src_lib", required=True, help="the existing library")
    ap.add_argument("--out", required=True, help="its source directory (table.c, <module>/f_*.c)")
    ap.add_argument("--lib", required=True, help="the library to build")
    a = ap.parse_args(argv)
    src_lib, out, lib = build._path(a.src_lib), build._path(a.out), build._path(a.lib)
    if os.path.abspath(src_lib) == os.path.abspath(lib):
        ap.error("--lib must differ from --from")
    old_obj = os.path.splitext(src_lib)[0] + ".obj"
    new_obj = os.path.splitext(lib)[0] + ".obj"
    os.makedirs(new_obj, exist_ok=True)
    linked = 0
    for o in glob.glob(os.path.join(old_obj, "*.o")):
        dst = os.path.join(new_obj, os.path.basename(o))
        if not os.path.exists(dst):
            os.link(o, dst)
            linked += 1
    sources = [os.path.join(out, "table.c")] + sorted(glob.glob(os.path.join(out, "*", "f_*.c")))
    stats = build.compile_and_link(sources + build.runtime_sources(), lib, header_deps=False)
    natives = build.native_overrides(sources)
    print("hard-linked %d objects from %s; compiled %d, reused %d; native: %s" % (
        linked, old_obj, stats["compiled"], stats["reused"],
        ", ".join("%s (%s)" % (os.path.basename(p), " ".join(n)) for p, n in natives.items()) or "none"))
    print("wrote", lib)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
