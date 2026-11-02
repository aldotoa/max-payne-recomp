# Scratch-grade (M6, 2026-10-20): edit S, W, ALL (the suspect list), D (build modules) and the --lift-modules list.
"""Bisect the exe dynamic set for the function whose lifting breaks InitInstance (Opus, scratch)."""
import os, subprocess, sys, time
S = os.environ["S"]                 # scratch dir: venv/ and game/
W = os.environ["W"]                 # the checkout (worktree) to build in
PY, G = S + "/venv/bin/python", S + "/game"
ALL = [int(l, 16) for l in open(W + "/lift-out/drv_lifted.txt") if l.strip()]
D = ["--module", "rlmfc.dll", "--module", "grphmfc.dll", "--module", "e2mfc.dll", "--module", S + "/game/e2driver/e2_d3d8_driver_mfc.dll", "--module", "MaxPayne.exe",
     "--entries", "real", "--entries-file", "MaxPayne.exe=lift-out/exe_dyn_entries_h15.txt"]
LIB = "build-lift/liblifted_bisd.dylib"
env = dict(os.environ, MP_GAME_DIR=G)
n_test = 0

def fails(lifted):
    """True if the run breaks with only `lifted` (of ALL) lifted in the exe."""
    global n_test
    n_test += 1
    keep = sorted(set(ALL) - set(lifted)) + [0x783860]
    open(S + "/bis_keep.txt", "w").write("\n".join("0x%08x" % v for v in keep) + "\n")
    t = time.time()
    b = subprocess.run([PY, "lift/build.py", *D, "--keep-emulated-file", S + "/bis_keep.txt", "--lib", LIB],
                       cwd=W, env=env, capture_output=True, text=True)
    if b.returncode:
        print("BUILD FAILED", b.stdout[-800:], b.stderr[-800:], flush=True); sys.exit(2)
    tb = time.time() - t
    try:
        r = subprocess.run([PY, "-u", "emu/run_init.py", G, "--frames", "2", "--native-lift", LIB, "--lift-modules",
                            "rlmfc.dll,grphmfc.dll,e2mfc.dll,e2_d3d8_driver_mfc.dll,maxpayne.exe"], cwd=W, env=env, capture_output=True,
                           text=True, timeout=400)
        out = r.stdout + r.stderr
        bad = "InitInstance returned" not in out or "NativeError" in out or "Traceback" in out
        why = next((l for l in out.splitlines() if "NativeError" in l), "rc=%d" % r.returncode)
    except subprocess.TimeoutExpired:
        bad, why = True, "timeout"
    print("test %d: %d lifted -> %s (build %.0fs, total %.0fs) %s" % (n_test, len(lifted), "FAIL" if bad else "ok",
          tb, time.time() - t, why[:160] if bad else ""), flush=True)
    return bad

def search(cands, base):
    """cands: suspects; base: always lifted with them. Returns a minimal failing suspect list."""
    while len(cands) > 1:
        h = len(cands) // 2
        a, b = cands[:h], cands[h:]
        if fails(base + a):
            cands = a
        elif fails(base + b):
            cands = b
        else:                                    # needs both halves: keep one fully lifted, search the other
            print("interaction: splitting with the other half lifted", flush=True)
            ra = search(a, base + b)
            rb = search(b, base + ra)
            return ra + rb
    return cands

if not fails(ALL):
    print("ALL lifted does not fail: nothing to bisect"); sys.exit(0)
res = search(ALL, [])
print("CULPRIT(S):", ["0x%08x" % v for v in res], flush=True)
