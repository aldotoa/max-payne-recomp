#!/usr/bin/env python3
"""Frame-rate regression (M7): the same scripted session at several simulation rates on mphost's virtual clock
(--sim-fps N), compared at matching sim times.

The workload: Resume Game on the main menu (the newest save; the H53 save, Part 1's container yard), then walk,
strafe while turning, a shoot-dodge in bullet time (LShift) and a few shots, all within the ~5 s before the enemy
there engages (combat outcomes depend on the rand() sequence, which per-frame particle emitters consume at a rate
that follows the frame rate, so a fight diverges between rates chaotically; see docs/m7-fps.md). Its frames are
written at 30 fps and counted from the frame that opens the level's .ldb (the anchor). At N fps each anchored frame f becomes f * N / 30, keys and clicks keep their sim times,
and each frame's mouse move is spread over the N / 30 frames that cover it, so the view turns by the same total.

Each run captures MPD3 streams at the same sim times. From each capture: the camera (the VIEW transform that is not
the identity: position and forward vector), the draw count, and for every draw with untransformed vertices (FVF
XYZ) the centroid of its vertices in world space (through the current WORLD transform). Draws are matched by order.

Usage: fps_regress.py DATA_DIR OUT_DIR [--rates 30,60,120] [--frames 700] [--lib LIB]
  DATA_DIR is copied for every run (saves and settings; it is never written). Exit status 1 if a pair of rates
  differs by more than --tol-pos world units in the camera position at any compared time (default 0.35: the
  integration error measured at 120 against 30 fps peaks at 0.29 during the shoot-dodge; Max walks ~3 units).
"""
import argparse
import os
import re
import shutil
import struct
import subprocess
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "emu"))
import d3dcap  # noqa: E402

HOST = os.path.join(ROOT, "build", "mphost")
GAME = os.path.join(ROOT, "Max Payne")
ANCHOR = ".ldb"
ENTER_FRAME = 25                # Enter on the main menu (Resume Game), in 30 fps frames
ANCHOR_30 = 29                  # the frame that opens the .ldb at 30 fps; the workload's frames are relative to it
BULLET_TIME = 130               # LShift: a shoot-dodge


def workload(frames):
    """The 30 fps workload as (frame, action), frames absolute (the level opens in frame ANCHOR_30): within the ~5 s
    before this save's enemy engages, walk forward, turn while strafing, a shoot-dodge (bullet time), fire."""
    a = [(40, "key=11"), (85, "keyup=11"), (90, "key=20"), (125, "keyup=20")]
    a += [(f, "move=%d;0" % (9 if f < 120 else -6)) for f in range(95, 140)]
    a += [(BULLET_TIME, "key=2a"), (BULLET_TIME + 2, "keyup=2a")]
    for f in range(150, min(frames, 180), 12):
        a += [(f, "button=0"), (f + 3, "buttonup=0")]
    return [x for x in a if x[0] < frames]


def input_spec(rate, frames):
    m = rate // 30
    out = ["%d:key=1c" % (ENTER_FRAME * m), "%d:keyup=1c" % (ENTER_FRAME * m + 1)]
    for f, act in workload(frames):
        rel = (f - ANCHOR_30) * m
        if act.startswith("move="):
            dx, dy = (int(v) for v in act[5:].split(";"))
            for i in range(m):             # dx spread over the m frames, integer parts summing to dx
                sx = dx * (i + 1) // m - dx * i // m
                sy = dy * (i + 1) // m - dy * i // m
                if sx or sy:
                    out.append("@%d:move=%d;%d" % (rel + i, sx, sy))
        else:
            out.append("@%d:%s" % (rel, act))
    return ",".join(out)


def run(rate, args, out, sim_times, capture=True):
    """One run at `rate`; returns {sim time (in 30 fps frames after the anchor): capture path} and the anchor frame."""
    m = rate // 30
    data = os.path.join(out, "data_%d" % rate)
    shutil.rmtree(data, ignore_errors=True)
    shutil.copytree(args.data_dir, data)
    cmd = [HOST, GAME, "--lib", args.lib, "--data-dir", data, "--intro", "skip", "--sim-fps", str(rate),
           "--anchor", ANCHOR, "--input", input_spec(rate, args.frames)]
    # the anchor frame is the same in every run at one rate (the clock is virtual): find it, then capture around it
    probe = subprocess.run(cmd + ["--anchor-frames", "0", "--frames", str(100 * m)], capture_output=True, text=True)
    mo = re.search(r"anchor '.*' opened in frame (\d+)", probe.stdout)
    if not mo:
        sys.exit("rate %d: the anchor was never opened:\n%s" % (rate, probe.stdout[-2000:]))
    anchor = int(mo.group(1))
    caps = {t: anchor + t * m for t in sim_times}
    cap_dir = os.path.join(out, "cap_%d" % rate)
    shutil.rmtree(cap_dir, ignore_errors=True)
    shutil.rmtree(data, ignore_errors=True)
    shutil.copytree(args.data_dir, data)
    log = os.path.join(out, "run_%d.log" % rate)
    total = (args.frames - ANCHOR_30) * m + anchor + 1
    with open(log, "w") as f:
        r = subprocess.run(cmd + ["--frames", str(total), "--capture", cap_dir, "--capture-frames",
                                  ",".join(str(v) for v in sorted(caps.values()))], stdout=f, stderr=subprocess.STDOUT)
    if r.returncode:
        sys.exit("rate %d: mphost exited with %d (%s)" % (rate, r.returncode, log))
    return {t: os.path.join(cap_dir, "frame_%03d.mpd3" % fr) for t, fr in caps.items()}, anchor


def summarize(path):
    """camera position and forward, the draw count, the world-space centroids of the XYZ draws"""
    world = np.eye(4)
    cam, draws, cents = None, 0, []
    for typ, p in d3dcap.read(path):
        if typ == d3dcap.TRANSFORM:
            st = struct.unpack_from("<I", p)[0]
            mat = np.array(struct.unpack_from("<16f", p, 4), dtype=np.float64).reshape(4, 4)
            if st == 256:
                world = mat
            elif st == 2 and not np.allclose(mat, np.eye(4)):
                r, t = mat[:3, :3], mat[3, :3]
                cam = (-t @ r.T, r[:, 2].copy())      # row vectors: view = R then t; forward is the view's +z
        elif typ == d3dcap.DRAW:
            draws += 1
            prim, fvf, stride, nv, ni, isz, vb, ib = d3dcap.parse_draw(p)
            if fvf & 0xe == 0x2 and nv:
                v = np.frombuffer(vb, dtype=np.uint8).reshape(nv, stride)[:, :12].copy().view(np.float32)
                c = np.append(v.reshape(nv, 3).astype(np.float64).mean(axis=0), 1.0) @ world
                cents.append(c[:3])
    return cam, draws, np.array(cents)


def compare(a, b):
    (ca, na, pa), (cb, nb, pb) = a, b
    dpos = float(np.linalg.norm(ca[0] - cb[0])) if ca and cb else float("nan")
    dang = float(np.degrees(np.arccos(np.clip(ca[1] @ cb[1] / np.linalg.norm(ca[1]) / np.linalg.norm(cb[1]), -1, 1)))) \
        if ca and cb else float("nan")
    if len(pa) == len(pb) and len(pa):
        d = np.linalg.norm(pa - pb, axis=1)
        obj = "max %.3f median %.3f" % (d.max(), float(np.median(d)))
    else:
        obj = "XYZ draws %d vs %d" % (len(pa), len(pb))
    return dpos, dang, "draws %d/%d, objects %s" % (na, nb, obj)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data_dir")
    ap.add_argument("out")
    ap.add_argument("--rates", default="30,60,120")
    ap.add_argument("--frames", type=int, default=210, help="the workload's length in 30 fps frames")
    ap.add_argument("--lib", default=os.path.join(ROOT, "build-lift", "liblifted_full_h77.dylib"))
    ap.add_argument("--tol-pos", type=float, default=0.35)
    args = ap.parse_args()
    rates = [int(v) for v in args.rates.split(",")]
    assert all(r % 30 == 0 for r in rates), "rates must be multiples of 30"
    os.makedirs(args.out, exist_ok=True)
    rel = lambda f: f - ANCHOR_30      # noqa: E731
    sim_times = [t for t in range(3, args.frames - ANCHOR_30, 3)][:64]
    runs = {}
    for r in rates:
        caps, anchor = run(r, args, args.out, sim_times)
        print("rate %d: anchor in frame %d" % (r, anchor))
        runs[r] = {t: summarize(p) for t, p in caps.items()}
    bad = 0
    base = rates[0]
    for r in rates[1:]:
        print("\n%d fps against %d fps (sim time in s after the level opened)" % (r, base))
        print("  %7s %10s %10s  %s" % ("t", "cam pos", "cam deg", "draws and objects"))
        for t in sim_times:
            dpos, dang, rest = compare(runs[base][t], runs[r][t])
            flag = " <--" if not dpos <= args.tol_pos else ""
            bad += bool(flag)
            print("  %7.2f %10.4f %10.3f  %s%s" % (t / 30.0, dpos, dang, rest, flag))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
