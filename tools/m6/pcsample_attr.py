"""Attribute PC samples (tools/m6/pcsample.c output) inside lifted functions to guest instructions and to the inlined
runtime helper that was running (H54). Needs each function's C (from x86c.lift_function, identical to the library's)
compiled with -g in DIR as f_XXXXXXXX.g.o next to f_XXXXXXXX.c.
Usage: pcsample_attr.py SAMPLES DIR [FUNC ...]   (default: every f_ with a .g.o in DIR)"""
import collections, os, re, subprocess, sys

samples, gdir = sys.argv[1], sys.argv[2]
want = set(sys.argv[3:])
hits = collections.defaultdict(list)            # func -> [(offset, count)]
total = 0
for ln in open(samples):
    if ln.startswith("#"):
        continue
    n, sym, off, _ = ln.split(None, 3)
    total += int(n)
    s = sym.lstrip("_")
    if s.startswith("f_") and os.path.exists(os.path.join(gdir, s + ".g.o")) and (not want or s in want):
        hits[s].append((int(off), int(n)))

GUEST = re.compile(r"/\* ([0-9a-f]{8}): (.*) \*/")
for func, offs in sorted(hits.items(), key=lambda kv: -sum(n for _, n in kv[1])):
    src = open(os.path.join(gdir, func + ".c")).read().split("\n")
    guest_at = {}                                # C line (1-based) -> the guest instruction it belongs to
    cur = None
    for i, l in enumerate(src, 1):
        m = GUEST.search(l)
        if m:
            cur = (m.group(1), m.group(2))
        guest_at[i] = cur
    r = subprocess.run(["atos", "-o", os.path.join(gdir, func + ".g.o"), "-arch", "arm64", "-l", "0", "-i"] +
                       ["0x%x" % o for o, _ in offs], capture_output=True, text=True)
    groups = r.stdout.strip().split("\n\n")
    by_insn, by_helper, by_mnem = collections.Counter(), collections.Counter(), collections.Counter()
    fsum = sum(n for _, n in offs)
    for (off, n), g in zip(offs, groups):
        frames = [l for l in g.split("\n") if l.strip()]
        outer = frames[-1] if frames else ""
        m = re.search(r"\(%s\.c:(\d+)\)" % func, outer)
        ins = guest_at.get(int(m.group(1))) if m else None
        helper = re.match(r"(\S+)", frames[0]).group(1) if len(frames) > 1 else "(inline code)"
        by_insn[ins] += n
        by_helper[helper] += n
        by_mnem[ins[1].split()[0] if ins else "?"] += n
    print("== %s: %d samples (%.1f%% of all %d)" % (func, fsum, 100 * fsum / total, total))
    print("   by guest mnemonic: " + ", ".join("%s %.0f%%" % (k, 100 * v / fsum) for k, v in by_mnem.most_common(12)))
    print("   by inlined helper: " + ", ".join("%s %.0f%%" % (k, 100 * v / fsum) for k, v in by_helper.most_common(10)))
    for ins, v in by_insn.most_common(12):
        print("   %5d %4.1f%%  %s" % (v, 100 * v / fsum, "%s: %s" % ins if ins else "?"))
