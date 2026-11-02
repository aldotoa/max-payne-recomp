#!/usr/bin/env python3
"""Renderer conformance tests: synthetic MPD3 captures, each exercising one D3D8 feature, rendered by the
reference rasterizer (tools/refrast.py) and by Metal (build/mpreplay) and compared (tools/imgdiff.py).
No game files needed. Build the renderer first: make -C render

Run:  .venv/bin/python tools/test_render.py [--keep DIR]
"""
import os
import struct
import subprocess
import sys
import tempfile

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "emu"))
sys.path.insert(0, HERE)
import d3dcap  # noqa: E402
import imgdiff  # noqa: E402
import refrast  # noqa: E402

W, H = 96, 64
FVF_T1 = 0x144            # XYZRHW | DIFFUSE | TEX1   (stride 28)
FVF_SPEC = 0x1C4          # XYZRHW | DIFFUSE | SPECULAR | TEX1  (stride 32)


def v(x, y, u=0.0, t=0.0, c=0xFFFFFFFF, z=0.5, rhw=1.0):
    return struct.pack("<ffffIff", x, y, z, rhw, c, u, t)


def vs(x, y, u, t, c, spec, z=0.5, rhw=1.0):
    return struct.pack("<ffffIIff", x, y, z, rhw, c, spec, u, t)


def quad_idx():
    return struct.pack("<6H", 0, 1, 2, 0, 2, 3)


def checker(n=8, a=0xFFFF0000, b=0xFF0000FF):
    return b"".join(struct.pack("<I", a if (x + y) % 2 == 0 else b) for y in range(n) for x in range(n))


def gradient565(n=16):
    px = []
    for y in range(n):
        for x in range(n):
            r, g, b = x * 31 // (n - 1), y * 63 // (n - 1), (x + y) * 31 // (2 * n - 2)
            px.append(struct.pack("<H", (r << 11) | (g << 5) | b))
    return b"".join(px)


def argb4444(n=8):
    return b"".join(struct.pack("<H", ((x * 2) << 12) | ((y * 2) << 8) | (15 << 4) | 3) for y in range(n) for x in range(n))


def start(w):
    w.clear(3, 0xFF202830, 1.0, 0, [])


CASES = {}


def case(fn):
    CASES[fn.__name__] = fn
    return fn


@case
def textured_quad_point(w):
    start(w)
    w.render_states([(22, 1), (7, 0)])
    w.texture(1, 21, 8, 8, [(8, 8, 32, checker())])
    w.set_texture(0, 1)
    w.draw(4, FVF_T1, 28, v(-0.5, -0.5, 0, 0) + v(95.5, -0.5, 1, 0) + v(95.5, 63.5, 1, 1) + v(-0.5, 63.5, 0, 1), quad_idx(), 2)


@case
def linear_filter_wrap_and_clamp(w):
    start(w)
    w.render_states([(22, 1), (7, 0)])
    w.texture(2, 23, 16, 16, [(16, 16, 32, gradient565())])
    w.set_texture(0, 2)
    w.tss([(0, 16, 2), (0, 17, 2), (0, 13, 1), (0, 14, 1)])
    w.draw(4, FVF_T1, 28, v(4, 4, -0.5, -0.5) + v(44, 4, 1.5, -0.5) + v(44, 60, 1.5, 1.5) + v(4, 60, -0.5, 1.5), quad_idx(), 2)
    w.tss([(0, 13, 3), (0, 14, 3)])
    w.draw(4, FVF_T1, 28, v(50, 4, -0.5, -0.5) + v(92, 4, 1.5, -0.5) + v(92, 60, 1.5, 1.5) + v(50, 60, -0.5, 1.5), quad_idx(), 2)


@case
def culling_both_ways(w):
    """Rows: CULL_NONE, CULL_CW, CULL_CCW. Each row: a clockwise (green) and a counter-clockwise (red) triangle."""
    start(w)
    w.render_states([(7, 0)])
    w.tss([(0, 1, 3), (0, 4, 3)])                       # select diffuse
    for row, cull in enumerate((1, 2, 3)):
        y = 2 + row * 21
        cw = v(5, y, c=0xFF00FF00) + v(40, y, c=0xFF00FF00) + v(5, y + 18, c=0xFF00FF00)       # clockwise (y down)
        ccw = v(50, y, c=0xFFFF0000) + v(50, y + 18, c=0xFFFF0000) + v(85, y, c=0xFFFF0000)    # counter-clockwise
        w.render_states([(22, cull)])
        w.draw(4, FVF_T1, 28, cw + ccw, struct.pack("<6H", 0, 1, 2, 3, 4, 5), 2)


def shift(vbytes, dx, dy):
    out = bytearray(vbytes)
    for i in range(0, len(out), 28):
        x, y = struct.unpack_from("<ff", out, i)
        struct.pack_into("<ff", out, i, x + dx, y + dy)
    return bytes(out)


@case
def gouraud_and_modulate(w):
    start(w)
    w.render_states([(22, 1), (7, 0)])
    w.texture(3, 26, 8, 8, [(8, 8, 16, argb4444())])
    w.set_texture(0, 3)
    w.tss([(0, 1, 4), (0, 2, 2), (0, 3, 0), (0, 4, 4), (0, 5, 2), (0, 6, 0)])  # modulate texture x diffuse
    # UVs stay off the exact wrap boundary (0.0/1.0 on a pixel centre picks either edge texel by rounding)
    w.draw(4, FVF_T1, 28, v(2, 2, .01, .01, 0xFFFF0000) + v(93, 2, .99, .01, 0xFF00FF00) + v(93, 61, .99, .99, 0xFF0000FF) +
           v(2, 61, .01, .99, 0xFFFFFFFF), quad_idx(), 2)


@case
def alpha_blend_and_test(w):
    start(w)
    w.render_states([(22, 1), (7, 0), (27, 1), (19, 5), (20, 6), (15, 1), (25, 7), (24, 0x60)])
    w.tss([(0, 1, 3), (0, 4, 3)])
    # alpha ramps 0..255 left to right: the left part fails the alpha test, the rest blends
    w.draw(4, FVF_T1, 28, v(2, 2, c=0x00FFFF00) + v(93, 2, c=0xFFFFFF00) + v(93, 61, c=0xFFFFFF00) + v(2, 61, c=0x00FFFF00), quad_idx(), 2)
    w.render_states([(19, 2), (20, 2), (15, 0)])        # additive
    w.draw(4, FVF_T1, 28, v(30, 20, c=0xFF400000) + v(70, 20, c=0xFF400000) + v(70, 44, c=0xFF400000) + v(30, 44, c=0xFF400000), quad_idx(), 2)


@case
def depth_test_and_write(w):
    start(w)
    w.render_states([(22, 1), (7, 1), (14, 1), (23, 4)])
    w.tss([(0, 1, 3), (0, 4, 3)])
    w.draw(4, FVF_T1, 28, v(10, 10, c=0xFFFF0000, z=0.3) + v(60, 10, c=0xFFFF0000, z=0.3) + v(60, 50, c=0xFFFF0000, z=0.3) +
           v(10, 50, c=0xFFFF0000, z=0.3), quad_idx(), 2)
    # a sloped quad from z=0.1 to z=0.6: partly in front, partly behind
    w.draw(4, FVF_T1, 28, v(30, 20, c=0xFF00FF00, z=0.1) + v(90, 20, c=0xFF00FF00, z=0.6) + v(90, 60, c=0xFF00FF00, z=0.6) +
           v(30, 60, c=0xFF00FF00, z=0.1), quad_idx(), 2)
    w.render_states([(14, 0), (23, 8)])                 # no write, always pass
    w.draw(4, FVF_T1, 28, v(0, 0, c=0xFF0000FF) + v(8, 0, c=0xFF0000FF) + v(8, 8, c=0xFF0000FF) + v(0, 8, c=0xFF0000FF), quad_idx(), 2)


@case
def vertex_fog(w):
    start(w)
    w.render_states([(22, 1), (7, 0), (28, 1), (34, 0xFF8090A0)])
    w.tss([(0, 1, 3), (0, 4, 3)])
    w.draw(4, FVF_SPEC, 32, vs(2, 2, 0, 0, 0xFFFF0000, 0xFF000000) + vs(93, 2, 0, 0, 0xFFFF0000, 0x00000000) +
           vs(93, 61, 0, 0, 0xFF00FF00, 0x00000000) + vs(2, 61, 0, 0, 0xFF00FF00, 0xFF000000), quad_idx(), 2)


@case
def perspective_correct(w):
    start(w)
    w.render_states([(22, 1), (7, 0)])
    w.texture(2, 23, 16, 16, [(16, 16, 32, gradient565())])
    w.set_texture(0, 2)
    w.tss([(0, 16, 2), (0, 17, 2)])                   # linear: point-sampled texel edges would be decided by rounding
    # a floor plane in perspective: far edge rhw small
    w.draw(4, FVF_T1, 28, v(40, 10, .1, .1, rhw=0.2) + v(56, 10, 2.9, .1, rhw=0.2) + v(94, 62, 2.9, 2.9, rhw=1.0) +
           v(2, 62, .1, 2.9, rhw=1.0), quad_idx(), 2)


@case
def strip_fan_and_clear_rects(w):
    start(w)
    w.render_states([(22, 1), (7, 0)])
    w.tss([(0, 1, 3), (0, 4, 3)])
    w.draw(5, FVF_T1, 28, v(2, 2, c=0xFFFF8000) + v(2, 30, c=0xFFFF8000) + v(20, 2, c=0xFF8000FF) + v(20, 30, c=0xFF8000FF) +
           v(40, 2, c=0xFF00FF80) + v(40, 30, c=0xFF00FF80), b"", 2)
    w.draw(6, FVF_T1, 28, v(70, 20, c=0xFFFFFFFF) + v(90, 20, c=0xFFFF0000) + v(85, 35, c=0xFF00FF00) +
           v(70, 40, c=0xFF0000FF) + v(55, 35, c=0xFFFFFF00), b"", 2)
    w.clear(1, 0xFF00FFFF, 1.0, 0, [(10, 40, 30, 60), (50, 45, 60, 55)])
    w.viewport(48, 0, 48, 64, 0.0, 1.0)
    w.clear(1, 0xFF404040, 1.0, 0, [(40, 50, 100, 64)])    # clipped to the viewport


@case
def two_stage_blend(w):
    start(w)
    w.render_states([(22, 1), (7, 0)])
    w.texture(1, 21, 8, 8, [(8, 8, 32, checker())])
    w.texture(3, 26, 8, 8, [(8, 8, 16, argb4444())])
    w.set_texture(0, 1)
    w.set_texture(1, 3)
    w.tss([(0, 1, 2), (0, 4, 2), (1, 1, 13), (1, 2, 2), (1, 3, 1), (1, 4, 2), (1, 5, 1), (1, 11, 0)])  # BLENDTEXTUREALPHA
    w.draw(4, FVF_T1, 28, v(2, 2, .01, .01) + v(93, 2, .99, .01) + v(93, 61, .99, .99) + v(2, 61, .01, .99), quad_idx(), 2)


@case
def transformed_xyz_perspective(w):
    """Untransformed vertices (XYZ|DIFFUSE|TEX1): a textured ground plane through World x View x Projection,
    drawn into an offset viewport with a depth range."""
    start(w)
    w.render_states([(22, 1), (7, 1), (14, 1)])
    w.texture(2, 23, 16, 16, [(16, 16, 32, gradient565())])
    w.set_texture(0, 2)
    w.tss([(0, 16, 2), (0, 17, 2), (0, 1, 4), (0, 2, 2), (0, 3, 0)])
    import math
    zn, zf, fov = 1.0, 50.0, math.radians(70)
    ys = 1 / math.tan(fov / 2)
    xs = ys / (80 / 56)
    proj = (xs, 0, 0, 0, 0, ys, 0, 0, 0, 0, zf / (zf - zn), 1, 0, 0, -zn * zf / (zf - zn), 0)   # D3DXMatrixPerspectiveFovLH
    view = (1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, -1.5, 0, 1)      # eye 1.5 above the plane
    world = (1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0.5, 0, 4, 1)
    w.transform(256, world); w.transform(2, view); w.transform(3, proj)
    w.viewport(8, 4, 80, 56, 0.0, 1.0)
    def p(x, y, z, u, t, c): return struct.pack("<fffIff", x, y, z, c, u, t)
    plane = p(-4, 0, 0, .05, .05, 0xFFFFFFFF) + p(4, 0, 0, 2.95, .05, 0xFFFF8080) + p(4, 0, 20, 2.95, 2.95, 0xFF80FF80) + \
        p(-4, 0, 20, .05, 2.95, 0xFF8080FF)
    w.draw(4, 0x142, 24, plane, quad_idx(), 2)
    wall = p(-1, 0, 6, .1, .1, 0xFFFFFF00) + p(1, 0, 6, .9, .1, 0xFFFFFF00) + p(1, 2, 6, .9, .9, 0xFFFFFF00) + p(-1, 2, 6, .1, .9, 0xFFFFFF00)
    w.render_states([(22, 1)])
    w.draw(4, 0x142, 24, wall, struct.pack("<6H", 0, 2, 1, 0, 3, 2), 2)


def run(keep=None):
    replay = os.path.join(ROOT, "build", "mpreplay")
    if not os.path.exists(replay):
        sys.exit("build the renderer first: make -C render")
    out = keep or tempfile.mkdtemp(prefix="mprender-test-")
    os.makedirs(out, exist_ok=True)
    failed = 0
    for name, fn in CASES.items():
        cap = os.path.join(out, name + ".mpd3")
        w = d3dcap.Writer(cap, W, H)
        fn(w)
        w.present()
        w.close()
        ref = refrast.replay(cap)
        refrast.write_png(os.path.join(out, name + ".ref.png"), ref.color)
        metal_png = os.path.join(out, name + ".metal.png")
        r = subprocess.run([replay, cap, metal_png], capture_output=True, text=True)
        if r.returncode:
            print("FAIL %-32s mpreplay: %s" % (name, r.stderr.strip()))
            failed += 1
            continue
        mae, pct, d, bad = imgdiff.compare(ref.color, imgdiff.read_png(metal_png), tol=8)
        ok = pct <= 0.5
        failed += not ok
        print("%s %-32s mean abs error %.3f, pixels off by >8: %.2f%%" % ("ok  " if ok else "FAIL", name, mae, pct))
        if not ok:
            refrast.write_png(os.path.join(out, name + ".diff.png"), np.clip(d * 8, 0, 255).astype(np.uint8))
    print("images in", out)
    if failed:
        sys.exit("%d of %d renderer tests failed" % (failed, len(CASES)))
    print("all %d renderer tests passed" % len(CASES))


if __name__ == "__main__":
    run(sys.argv[sys.argv.index("--keep") + 1] if "--keep" in sys.argv else None)
