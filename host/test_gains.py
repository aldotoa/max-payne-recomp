"""dsound's gain model in C (host/hle_dsound.c gains_3d, db_gain, the pan gains) against emu/dsound.py's, bit for bit.

The three-frame workload plays its sounds at the listener with full or no volume, so test_host.py's voice log does not
reach the distance, cone, pan and doppler arithmetic; this does: random listeners and 3D buffers (positions,
orientations, velocities, distances, cones, rolloff, doppler and distance factors, the three modes; f32 values as the
game passes them), and random volumes and pans, through both. hle_dsound.c is compiled into a small driver with the
host's services stubbed out.
  .venv/bin/python host/test_gains.py [N]        (default 20000 cases)"""
import math
import os
import random
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "emu"))
import dsound  # noqa: E402

DRIVER = r"""
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "host.h"
CPU g_cpu;
const char *g_game_dir;
uint32_t host_alloc(uint32_t size) { (void)size; return 0; }
uint32_t host_stub_for(const char *dll, const char *name) { (void)dll; (void)name; return 0; }
void host_fatal(const char *fmt, ...) { (void)fmt; exit(9); }
int host_ds_new(uint32_t this) { (void)this; return 0; }
void host_ds_cfg(int s, uint32_t p, uint32_t z, int h, uint32_t a, uint32_t b) { (void)s, (void)p, (void)z, (void)h, (void)a, (void)b; }
double host_ds_field(int s, int f, int set, double v) { (void)s, (void)f, (void)set, (void)v; return 0; }
void host_ds_gains(int s, double l, double r, int d) { (void)s, (void)l, (void)r, (void)d; }
void host_ds_mixer(void *m, void *w, void *p, void *g) { (void)m, (void)w, (void)p, (void)g; }
uint32_t host_guest_call(CPU *c, uint32_t va, int n, const uint32_t *a) { (void)c, (void)va, (void)n, (void)a; return 0; }
#include "hle_dsound.c"
static float rf(void) { uint32_t u; if (scanf("%x", &u) != 1) exit(0); float f; memcpy(&f, &u, 4); return f; }
static uint32_t ru(void) { uint32_t u; if (scanf("%x", &u) != 1) exit(0); return u; }
int main(void)
{
    for (;;) {
        Listener *l = &g_listener;
        for (int i = 0; i < 3; i++) l->position[i] = rf();
        for (int i = 0; i < 3; i++) l->velocity[i] = rf();
        for (int i = 0; i < 3; i++) l->front[i] = rf();
        for (int i = 0; i < 3; i++) l->top[i] = rf();
        l->distance_factor = rf(), l->rolloff_factor = rf(), l->doppler_factor = rf();
        P3 q;
        for (int i = 0; i < 3; i++) q.position[i] = rf();
        for (int i = 0; i < 3; i++) q.velocity[i] = rf();
        for (int i = 0; i < 3; i++) q.cone_orientation[i] = rf();
        q.min_distance = rf(), q.max_distance = rf();
        q.inside_angle = ru(), q.outside_angle = ru(), q.mode = ru(), q.outside_volume = (int32_t)ru();
        int32_t vol = (int32_t)ru(), pan = (int32_t)ru();
        double gl, gr, ratio;
        gains_3d(&q, &gl, &gr, &ratio);
        double pl = pan > 0 ? db_gain(-pan) : 1.0, pr = pan < 0 ? db_gain(pan) : 1.0;
        printf("%a %a %a %a %a %a\n", gl, gr, ratio, db_gain(vol), pl, pr);
    }
}
"""


def f32(x):
    return struct.unpack("<f", struct.pack("<f", x))[0]


def bits(x):
    return "%08x" % struct.unpack("<I", struct.pack("<f", x))[0]


def case(rnd):
    def v(scale):
        return [f32(rnd.uniform(-scale, scale)) if rnd.random() > 0.05 else 0.0 for _ in range(3)]
    lst = dict(position=v(50), velocity=v(10), front=v(1), top=v(1), distance_factor=f32(rnd.choice([1.0, 0.5, 2.0, rnd.uniform(0, 3)])),
               rolloff_factor=f32(rnd.uniform(0, 4)), doppler_factor=f32(rnd.choice([0.0, 1.0, rnd.uniform(0, 3)])))
    mn = f32(rnd.uniform(0, 10))
    q = dict(position=v(60), velocity=v(20), cone_orientation=v(1), min_distance=mn,
             max_distance=f32(rnd.choice([1e9, mn + rnd.uniform(0, 100), rnd.uniform(0, 5)])),
             inside_angle=rnd.choice([360, rnd.randrange(0, 361)]), outside_angle=rnd.randrange(0, 361),
             mode=rnd.choice([0, 0, 1, 2]), outside_volume=rnd.randrange(-10000, 1))
    vol, pan = rnd.randrange(-11000, 100), rnd.randrange(-10000, 10001)
    return lst, q, vol, pan


def line(lst, q, vol, pan):
    w = [bits(x) for k in ("position", "velocity", "front", "top") for x in lst[k]]
    w += [bits(lst[k]) for k in ("distance_factor", "rolloff_factor", "doppler_factor")]
    w += [bits(x) for k in ("position", "velocity", "cone_orientation") for x in q[k]]
    w += [bits(q["min_distance"]), bits(q["max_distance"])]
    w += ["%x" % (q[k] & 0xFFFFFFFF) for k in ("inside_angle", "outside_angle", "mode", "outside_volume")]
    w += ["%x" % (vol & 0xFFFFFFFF), "%x" % (pan & 0xFFFFFFFF)]
    return " ".join(w)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    work = tempfile.mkdtemp(prefix="gains-")
    src, exe = os.path.join(work, "drv.c"), os.path.join(work, "drv")
    open(src, "w").write(DRIVER)
    subprocess.run(["clang", "-O2", "-std=gnu11", "-w", "-I", os.path.join(ROOT, "host"), "-I",
                    os.path.join(ROOT, "lift", "runtime"), "-o", exe, src, "-L", os.path.join(ROOT, "build"), "-lmpaudio",
                    "-Wl,-rpath," + os.path.join(ROOT, "build")], check=True)
    rnd = random.Random(1)
    cases = [case(rnd) for _ in range(n)]
    out = subprocess.run([exe], input="\n".join(line(*c) for c in cases) + "\n", capture_output=True, text=True,
                         check=True).stdout.split("\n")
    bad = 0
    for (lst, q, vol, pan), got in zip(cases, out):
        gl, gr, ratio = dsound.gains_3d(lst, q) if q["mode"] != 2 else (1.0, 1.0, 1.0)
        want = [gl, gr, ratio, dsound.db_gain(vol), *dsound.pan_gains(pan)]
        g = [float.fromhex(x) for x in got.split()]
        if q["mode"] == 2:                       # DISABLE: update_voice does not call gains_3d (the pan gains apply)
            g[:3], want[:3] = [0, 0, 0], [0, 0, 0]
        if g != want:
            bad += 1
            if bad <= 5:
                print("differs:", lst, q, vol, pan, "\n   C ", g, "\n   py", want)
    print("%d cases: %d differ" % (n, bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
