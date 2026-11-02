#!/usr/bin/env python3
"""Reference software rasterizer for MPD3 captures (emu/d3dcap.py): turns a captured frame into a PNG.

It implements the Direct3D 8 fixed-function subset Max Payne uses, written straight from the D3D8 rules and
independent of the Metal renderer, so the two can be compared (tools/imgdiff.py):
  - pre-transformed vertices (D3DFVF_XYZRHW + DIFFUSE/SPECULAR/TEXn); pixel centers at integer coordinates,
    top-left fill rule, culling by screen-space winding, perspective-correct attributes (1/w = rhw),
    screen-linear depth;
  - texture stages: D3DTOP_* colour/alpha ops with D3DTA_* arguments (+COMPLEMENT/ALPHAREPLICATE),
    TEXCOORDINDEX, point/linear filtering, wrap/clamp/mirror addressing, mip levels;
  - vertex fog (specular alpha), alpha test, alpha blending (all blend factors/ops), depth test and write,
    CLEAR inside the viewport; textures R5G6B5, X1R5G5B5, A1R5G5B5, A4R4G4B4, X4R4G4B4, A8R8G8B8,
    X8R8G8B8, R8G8B8, A8, L8, A8L8.
The back buffer is X8R8G8B8 (destination alpha reads as 1) and each draw is quantized to 8 bits per channel.

Usage: refrast.py capture.mpd3 [-o out.png] [--frame N] [--dump-textures DIR] [--list]
"""
import argparse
import os
import struct
import sys
import zlib

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "emu"))
import d3dcap  # noqa: E402

# ----------------------------------------------------------------- defaults (D3D8 device creation state)
RS_DEFAULTS = {7: 1, 8: 3, 9: 2, 14: 1, 15: 0, 19: 2, 20: 1, 22: 3, 23: 4, 24: 0, 25: 8, 27: 0, 28: 0,
               29: 0, 34: 0, 60: 0xFFFFFFFF, 137: 1, 168: 0xF, 171: 1}


def tss_default(stage, ty):
    return {1: 4 if stage == 0 else 1, 2: 2, 3: 1, 4: 2 if stage == 0 else 1, 5: 2, 6: 1, 11: stage,
            13: 1, 14: 1, 16: 1, 17: 1, 18: 0, 26: 1, 27: 1, 28: 1}.get(ty, 0)


# ----------------------------------------------------------------- texture decoding -> float RGBA (h, w, 4)
def _bits(v, shift, n):
    return ((v >> shift) & ((1 << n) - 1)).astype(np.float32) / ((1 << n) - 1)


def decode_level(fmt, w, h, pitch, data):
    raw = np.frombuffer(data, np.uint8)
    one = np.ones((h, w), np.float32)
    if fmt in (21, 22):                                       # A8R8G8B8 / X8R8G8B8 (bytes B, G, R, A)
        px = raw[:pitch * h].reshape(h, pitch)[:, :w * 4].reshape(h, w, 4).astype(np.float32) / 255
        a = px[..., 3] if fmt == 21 else one
        return np.stack([px[..., 2], px[..., 1], px[..., 0], a], -1)
    if fmt == 20:                                             # R8G8B8
        px = raw[:pitch * h].reshape(h, pitch)[:, :w * 3].reshape(h, w, 3).astype(np.float32) / 255
        return np.stack([px[..., 2], px[..., 1], px[..., 0], one], -1)
    if fmt in (23, 24, 25, 26, 30, 51):
        v = raw[:pitch * h].reshape(h, pitch)[:, :w * 2].copy().view("<u2").reshape(h, w).astype(np.uint32)
        if fmt == 23:
            return np.stack([_bits(v, 11, 5), _bits(v, 5, 6), _bits(v, 0, 5), one], -1)
        if fmt in (24, 25):
            return np.stack([_bits(v, 10, 5), _bits(v, 5, 5), _bits(v, 0, 5), _bits(v, 15, 1) if fmt == 25 else one], -1)
        if fmt in (26, 30):
            return np.stack([_bits(v, 8, 4), _bits(v, 4, 4), _bits(v, 0, 4), _bits(v, 12, 4) if fmt == 26 else one], -1)
        l, a = _bits(v, 0, 8), _bits(v, 8, 8)                 # A8L8
        return np.stack([l, l, l, a], -1)
    if fmt in (28, 50):                                       # A8 / L8
        v = raw[:pitch * h].reshape(h, pitch)[:, :w].astype(np.float32) / 255
        return np.stack([np.zeros_like(v), np.zeros_like(v), np.zeros_like(v), v], -1) if fmt == 28 else \
            np.stack([v, v, v, one], -1)
    raise NotImplementedError("texture format %d" % fmt)


class Texture:
    def __init__(self, fmt, w, h, levels):
        self.fmt, self.w, self.h = fmt, w, h
        self.levels = [decode_level(fmt, lw, lh, p, d) for lw, lh, p, d in levels]


# ----------------------------------------------------------------- vertex parsing
def position_words(fvf):
    """32-bit words of the position: XYZRHW 4, XYZ 3, XYZB1..XYZB5 3 + blend weights."""
    kind = fvf & 0xE
    if kind == 0x4:
        return 4
    if kind == 0x2 or kind >= 0x6:
        return 3 + max(0, (kind - 0x4) // 2)
    raise NotImplementedError("vertex format without a position (fvf=0x%x)" % fvf)


def parse_vertices(fvf, stride, nv, vb):
    """Returns (pos (nv, 4): x, y, z, rhw for XYZRHW or x, y, z, 1 for untransformed), diffuse, specular, tex."""
    u32 = np.frombuffer(vb, "<u4").reshape(nv, stride // 4)
    f32 = u32.view("<f4")
    col = position_words(fvf)
    if fvf & 0x10:                                            # normal (used only by lighting)
        col += 3
    if fvf & 0x40:
        diffuse = argb_to_float(u32[:, col]); col += 1
    else:
        diffuse = np.ones((nv, 4), np.float32)
    if fvf & 0x80:
        specular = argb_to_float(u32[:, col]); col += 1
    else:
        specular = np.concatenate([np.zeros((nv, 3), np.float32), np.ones((nv, 1), np.float32)], 1)
    ntex = (fvf >> 8) & 0xF
    tex = []
    for t in range(ntex):
        size = {0: 2, 1: 3, 2: 4, 3: 1}[(fvf >> (16 + 2 * t)) & 3]
        tex.append(f32[:, col:col + 2].astype(np.float32))
        col += size
    if fvf & 0xE == 0x4:
        pos = f32[:, 0:4].astype(np.float64)
    else:
        pos = np.concatenate([f32[:, 0:3].astype(np.float64), np.ones((nv, 1))], 1)
    return pos, diffuse, specular, tex


def argb_to_float(v):
    v = v.astype(np.uint32)
    return np.stack([(v >> 16) & 255, (v >> 8) & 255, v & 255, v >> 24], -1).astype(np.float32) / 255


def triangles(prim, ni, ib, nv):
    idx = np.frombuffer(ib, "<u2" if len(ib) == 2 * ni else "<u4").astype(np.int64) if ni else np.arange(nv)
    if prim == 4:
        return idx[:len(idx) // 3 * 3].reshape(-1, 3)
    if prim == 5:
        t = [(idx[i], idx[i + 1], idx[i + 2]) if i % 2 == 0 else (idx[i + 1], idx[i], idx[i + 2]) for i in range(len(idx) - 2)]
        return np.array(t, np.int64).reshape(-1, 3)
    if prim == 6:
        return np.array([(idx[0], idx[i], idx[i + 1]) for i in range(1, len(idx) - 1)], np.int64).reshape(-1, 3)
    return np.zeros((0, 3), np.int64)                         # points/lines: not used by the game


# ----------------------------------------------------------------- the rasterizer
CMP = {1: lambda a, b: np.zeros_like(a, bool), 2: np.less, 3: np.equal, 4: np.less_equal, 5: np.greater,
       6: np.not_equal, 7: np.greater_equal, 8: lambda a, b: np.ones_like(a, bool)}


class Device:
    def __init__(self, w, h):
        self.w, self.h = w, h
        self.color = np.zeros((h, w, 3), np.uint8)
        self.depth = np.ones((h, w), np.float32)
        self.rs, self.tss, self.bound, self.textures = {}, {}, {}, {}
        self.viewport = (0, 0, w, h, 0.0, 1.0)
        self.xf = {}                                          # transform state -> 4x4 (row-major, row vectors)
        self.draws = 0
        self.unsupported = {}

    def r(self, s): return self.rs.get(s, RS_DEFAULTS.get(s, 0))
    def t(self, st, ty): return self.tss.get((st, ty), tss_default(st, ty))

    def note(self, what):
        self.unsupported[what] = self.unsupported.get(what, 0) + 1

    def clip_rect(self):
        x, y, w, h = self.viewport[:4]
        return max(0, x), max(0, y), min(self.w, x + w), min(self.h, y + h)

    def clear(self, flags, color, z, rects):
        x0, y0, x1, y1 = self.clip_rect()
        areas = [(max(x0, a), max(y0, b), min(x1, c), min(y1, d)) for a, b, c, d in rects] or [(x0, y0, x1, y1)]
        rgb = np.array([(color >> 16) & 255, (color >> 8) & 255, color & 255], np.uint8)
        for a, b, c, d in areas:
            if c <= a or d <= b:
                continue
            if flags & 1:
                self.color[b:d, a:c] = rgb
            if flags & 2:
                self.depth[b:d, a:c] = z

    # -------- texture sampling
    def sample(self, stage, uv, lod):
        tex = self.textures.get(self.bound.get(stage, 0))
        n = len(uv)
        if tex is None:
            return np.tile(np.array([0, 0, 0, 1], np.float32), (n, 1))
        mip = self.t(stage, 18)
        level = 0
        if mip and len(tex.levels) > 1:
            level = int(np.clip(np.floor(lod + 0.5) if mip == 1 else np.floor(lod), 0, len(tex.levels) - 1))
            if mip == 2:
                self.note("linear mip filter approximated as nearest level")
        img = tex.levels[level]
        h, w = img.shape[:2]
        filt = self.t(stage, 16) if lod <= 0 else self.t(stage, 17)
        u, v = uv[:, 0] * w, uv[:, 1] * h
        if filt >= 2:                                         # linear (anisotropic treated as linear)
            u0, v0 = np.floor(u - 0.5), np.floor(v - 0.5)
            fu, fv = (u - 0.5 - u0)[:, None], (v - 0.5 - v0)[:, None]
            c00 = self.fetch(stage, img, u0, v0)
            c10 = self.fetch(stage, img, u0 + 1, v0)
            c01 = self.fetch(stage, img, u0, v0 + 1)
            c11 = self.fetch(stage, img, u0 + 1, v0 + 1)
            return (c00 * (1 - fu) + c10 * fu) * (1 - fv) + (c01 * (1 - fu) + c11 * fu) * fv
        return self.fetch(stage, img, np.floor(u), np.floor(v))

    def fetch(self, stage, img, x, y):
        h, w = img.shape[:2]
        x = address(x.astype(np.int64), w, self.t(stage, 13))
        y = address(y.astype(np.int64), h, self.t(stage, 14))
        return img[y, x]

    # -------- texture stage combiner
    def combine(self, diffuse, specular, texc, lods):
        cur = diffuse.copy()
        temp = np.zeros_like(cur)
        tf = argb_to_float(np.array([self.r(60)], np.uint32))[0]
        for st in range(8):
            cop = self.t(st, 1)
            if cop == 1:
                break
            ci = self.t(st, 11) & 0xFFFF
            if ci < len(texc):
                tx = self.sample(st, texc[ci], lods[ci])
            else:
                tx = np.tile(np.array([0, 0, 0, 1], np.float32), (len(cur), 1))

            def arg(a):
                src = {0: diffuse, 1: cur, 2: tx, 3: np.broadcast_to(tf, cur.shape), 4: specular, 5: temp}.get(a & 0xF, cur)
                if a & 0x20:
                    src = np.repeat(src[:, 3:4], 4, 1)
                if a & 0x10:
                    src = 1 - src
                return src
            c = self.op(cop, arg(self.t(st, 2)), arg(self.t(st, 3)), arg(self.t(st, 26)), diffuse, tx, cur, tf)
            aop = self.t(st, 4)
            if aop == 1:
                a = cur[:, 3]
            else:
                a = self.op(aop, arg(self.t(st, 5)), arg(self.t(st, 6)), arg(self.t(st, 27)), diffuse, tx, cur, tf)[:, 3]
            res = np.concatenate([c[:, :3], a[:, None]], 1)
            if self.t(st, 28) == 5:
                temp = res
            else:
                cur = res
        return cur

    def op(self, op, a1, a2, a0, diffuse, tx, cur, tf):
        if op == 2: return a1
        if op == 3: return a2
        if op == 4: return a1 * a2
        if op == 5: return np.clip(a1 * a2 * 2, 0, 1)
        if op == 6: return np.clip(a1 * a2 * 4, 0, 1)
        if op == 7: return np.clip(a1 + a2, 0, 1)
        if op == 8: return np.clip(a1 + a2 - 0.5, 0, 1)
        if op == 9: return np.clip((a1 + a2 - 0.5) * 2, 0, 1)
        if op == 10: return np.clip(a1 - a2, 0, 1)
        if op == 11: return np.clip(a1 + a2 - a1 * a2, 0, 1)
        if op in (12, 13, 14, 16):
            al = {12: diffuse[:, 3:4], 13: tx[:, 3:4], 14: np.broadcast_to(tf[3:4], (len(a1), 1)), 16: cur[:, 3:4]}[op]
            return a1 * al + a2 * (1 - al)
        if op == 15: return np.clip(a1 + a2 * (1 - tx[:, 3:4]), 0, 1)
        if op == 24:
            d = np.clip(((a1[:, :3] - 0.5) * (a2[:, :3] - 0.5)).sum(1, keepdims=True) * 4, 0, 1)
            return np.repeat(d, 4, 1)
        if op == 25: return np.clip(a0 + a1 * a2, 0, 1)
        if op == 26: return a0 * a1 + (1 - a0) * a2
        self.note("texture op %d" % op)
        return a1

    # -------- drawing
    def draw(self, prim, fvf, stride, nv, ni, isz, vb, ib):
        self.draws += 1
        if not nv:
            return
        pos, diffuse, specular, tex = parse_vertices(fvf, stride, nv, vb)
        if fvf & 0xE != 0x4:
            pos = self.transform(pos)
            if self.r(137) and fvf & 0x10:
                self.note("fixed-function lighting not implemented (vertex colours used)")
        tris = triangles(prim, ni, ib, nv)
        if prim not in (4, 5, 6):
            self.note("primitive type %d" % prim)
        for tri in tris:
            self.triangle(tri, pos, diffuse, specular, tex)

    def transform(self, pos):
        """World x View x Projection, perspective divide and D3D's viewport mapping (NDC -1 -> pixel centre X).
        Returns x, y, z, rhw like a pre-transformed vertex; rhw <= 0 marks a vertex behind the eye."""
        eye = np.identity(4)
        m = self.xf.get(256, eye) @ self.xf.get(2, eye) @ self.xf.get(3, eye)
        c = pos @ m
        cw = c[:, 3]
        safe = np.where(np.abs(cw) < 1e-20, 1e-20, cw)
        x0, y0, vw, vh, mnz, mxz = self.viewport
        sx = x0 + (1 + c[:, 0] / safe) * vw / 2
        sy = y0 + (1 - c[:, 1] / safe) * vh / 2
        sz = mnz + c[:, 2] / safe * (mxz - mnz)
        return np.stack([sx, sy, sz, 1 / safe], 1)

    def triangle(self, tri, pos, diffuse, specular, tex):
        p = pos[tri]
        if (p[:, 3] <= 0).any():                              # crosses the eye plane: no clipping here
            self.note("triangle behind the eye skipped (no clipping)")
            return
        x, y = p[:, 0], p[:, 1]
        area = (x[1] - x[0]) * (y[2] - y[0]) - (x[2] - x[0]) * (y[1] - y[0])
        if area == 0:
            return
        cull = self.r(22)
        if (cull == 2 and area > 0) or (cull == 3 and area < 0):    # CULL_CW / CULL_CCW (y points down)
            return
        if area < 0:                                          # make the winding positive for the edge tests
            tri = tri[[0, 2, 1]]
            p = pos[tri]
            x, y = p[:, 0], p[:, 1]
            area = -area
        cx0, cy0, cx1, cy1 = self.clip_rect()
        bx0, bx1 = max(cx0, int(np.ceil(x.min()))), min(cx1 - 1, int(np.floor(x.max())))
        by0, by1 = max(cy0, int(np.ceil(y.min()))), min(cy1 - 1, int(np.floor(y.max())))
        if bx0 > bx1 or by0 > by1:
            return
        gy, gx = np.mgrid[by0:by1 + 1, bx0:bx1 + 1]
        gx = gx.ravel().astype(np.float64)
        gy = gy.ravel().astype(np.float64)
        ws = []
        for i in range(3):                                    # edge opposite vertex i: from j to k
            j, k = (i + 1) % 3, (i + 2) % 3
            ex, ey = x[k] - x[j], y[k] - y[j]
            w = ex * (gy - y[j]) - ey * (gx - x[j])           # equals `area` at vertex i: positive inside
            top_left = (ey == 0 and ex > 0) or ey < 0         # top edge runs right, left edges run up (y down)
            ws.append((w >= 0 if top_left else w > 0, w))
        inside = ws[0][0] & ws[1][0] & ws[2][0]
        if not inside.any():
            return
        b = np.stack([ws[0][1][inside], ws[1][1][inside], ws[2][1][inside]], 1) / area
        px, py = gx[inside].astype(np.int64), gy[inside].astype(np.int64)
        z = (b * p[:, 2]).sum(1)
        rhw = p[:, 3]
        pw = b * rhw
        pw /= pw.sum(1, keepdims=True)                        # perspective-correct weights
        if self.r(7):
            zf = self.r(23)
            ok = CMP[zf](z.astype(np.float32), self.depth[py, px])
            if not ok.any():
                return
            px, py, z, pw, b = px[ok], py[ok], z[ok], pw[ok], b[ok]
        flat = self.r(9) == 1
        dif = np.repeat(diffuse[tri[0]][None], len(pw), 0) if flat else pw @ diffuse[tri]
        spe = pw @ specular[tri] if not flat else np.repeat(specular[tri[0]][None], len(pw), 0)
        texc, lods = [], []
        for t in tex:
            uv = t[tri].astype(np.float64)
            texc.append(pw @ uv)
            lods.append(self.lod(uv, p, self.max_tex_size(len(texc) - 1)))
        col = self.combine(dif.astype(np.float32), spe.astype(np.float32), texc, lods)
        if self.r(28):                                        # vertex fog: factor in specular alpha
            f = spe[:, 3:4]
            fog = argb_to_float(np.array([self.r(34)], np.uint32))[0][:3]
            col = np.concatenate([col[:, :3] * f + fog * (1 - f), col[:, 3:]], 1)
        if self.r(15):                                        # alpha test against ALPHAREF (0..255)
            a8 = np.round(np.clip(col[:, 3], 0, 1) * 255)
            ok = CMP[self.r(25)](a8, float(self.r(24) & 255))
            px, py, z, col = px[ok], py[ok], z[ok], col[ok]
            if not len(px):
                return
        col = np.clip(col, 0, 1)
        if self.r(27):
            dst = self.color[py, px].astype(np.float32) / 255
            dst4 = np.concatenate([dst, np.ones((len(dst), 1), np.float32)], 1)
            sf = blend_factor(self.r(19), col, dst4)
            df = blend_factor(self.r(20), col, dst4)
            s, d = col[:, :3] * sf, dst * df
            bo = self.r(171)
            out = {1: s + d, 2: s - d, 3: d - s, 4: np.minimum(col[:, :3], dst), 5: np.maximum(col[:, :3], dst)}.get(bo, s + d)
        else:
            out = col[:, :3]
        mask = self.r(168)
        q = np.round(np.clip(out, 0, 1) * 255).astype(np.uint8)
        if mask & 7 != 7:
            cur = self.color[py, px]
            q = np.where(np.array([mask & 1, mask & 2, mask & 4], bool), q, cur)
        self.color[py, px] = q
        if self.r(7) and self.r(14):
            self.depth[py, px] = z.astype(np.float32)

    def max_tex_size(self, coord_set):
        for st in range(8):
            if self.t(st, 1) == 1:
                break
            if self.t(st, 11) & 0xFFFF == coord_set:
                tx = self.textures.get(self.bound.get(st, 0))
                if tx:
                    return tx.w, tx.h
        return 1, 1

    @staticmethod
    def lod(uv, p, size):
        """Per-triangle mip LOD: log2 of texels per pixel (from the texture-space vs screen-space area ratio)."""
        w, h = size
        tu, tv = uv[:, 0] * w, uv[:, 1] * h
        ta = abs((tu[1] - tu[0]) * (tv[2] - tv[0]) - (tu[2] - tu[0]) * (tv[1] - tv[0]))
        sa = abs((p[1, 0] - p[0, 0]) * (p[2, 1] - p[0, 1]) - (p[2, 0] - p[0, 0]) * (p[1, 1] - p[0, 1]))
        if sa <= 0 or ta <= 0:
            return 0.0
        return 0.5 * np.log2(ta / sa)


def address(i, n, mode):
    if mode == 3:                                             # CLAMP
        return np.clip(i, 0, n - 1)
    if mode == 2:                                             # MIRROR
        m = np.mod(i, 2 * n)
        return np.where(m < n, m, 2 * n - 1 - m)
    return np.mod(i, n)                                       # WRAP (and BORDER, approximated)


def blend_factor(f, src, dst4):
    n = len(src)
    sa, da = src[:, 3:4], dst4[:, 3:4]
    return {1: np.zeros((n, 1)), 2: np.ones((n, 1)), 3: src[:, :3], 4: 1 - src[:, :3], 5: sa, 6: 1 - sa,
            7: da, 8: 1 - da, 9: dst4[:, :3], 10: 1 - dst4[:, :3], 11: np.minimum(sa, 1 - da)}.get(f, np.ones((n, 1)))


# ----------------------------------------------------------------- replay
def replay(path, frame=0, on_texture=None, listing=False):
    """Render frame `frame` (0 = first PRESENT) of a capture. Returns the Device."""
    it = d3dcap.read(path)
    _, (w, h) = next(it)
    dev = Device(w, h)
    nframe = 0
    for typ, pl in it:
        if typ == d3dcap.TEXTURE:
            tid, fmt, tw, th, levels = d3dcap.parse_texture(pl)
            try:
                dev.textures[tid] = Texture(fmt, tw, th, levels)
            except NotImplementedError as ex:
                dev.note(str(ex))
                continue
            if on_texture:
                on_texture(tid, dev.textures[tid])
        elif typ == d3dcap.RENDERSTATE:
            n = struct.unpack_from("<I", pl)[0]
            for i in range(n):
                s, v = struct.unpack_from("<II", pl, 4 + 8 * i)
                dev.rs[s] = v
        elif typ == d3dcap.TSS:
            n = struct.unpack_from("<I", pl)[0]
            for i in range(n):
                st, ty, v = struct.unpack_from("<III", pl, 4 + 12 * i)
                dev.tss[(st, ty)] = v
        elif typ == d3dcap.SETTEXTURE:
            st, tid = struct.unpack("<II", pl)
            dev.bound[st] = tid
        elif typ == d3dcap.VIEWPORT:
            dev.viewport = struct.unpack("<IIIIff", pl)
        elif typ == d3dcap.CLEAR:
            flags, color, z, stencil, n = struct.unpack_from("<IIfII", pl)
            rects = [struct.unpack_from("<iiii", pl, 20 + 16 * i) for i in range(n)]
            if nframe == frame:
                dev.clear(flags, color, z, rects)
        elif typ == d3dcap.DRAW:
            d = d3dcap.parse_draw(pl)
            if nframe == frame:
                if listing:
                    print("draw %3d: prim=%d fvf=0x%x verts=%d indices=%d tex0=0x%x blend=%d(%d,%d) atest=%d z=%d/%d cull=%d op0=%d/%d op1=%d fog=%d" % (
                        dev.draws, d[0], d[1], d[3], d[4], dev.bound.get(0, 0), dev.r(27), dev.r(19), dev.r(20),
                        dev.r(15), dev.r(7), dev.r(14), dev.r(22), dev.t(0, 1), dev.t(0, 4), dev.t(1, 1), dev.r(28)))
                dev.draw(*d)
        elif typ == d3dcap.TRANSFORM:
            v = struct.unpack("<I16f", pl)
            dev.xf[v[0]] = np.array(v[1:], np.float64).reshape(4, 4)
        elif typ == d3dcap.PRESENT:
            if nframe == frame:
                return dev
            nframe += 1
    return dev


def write_png(path, rgb):
    h, w = rgb.shape[:2]
    ch = rgb.shape[2]
    raw = b"".join(b"\0" + rgb[y].tobytes() for y in range(h))
    def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6 if ch == 4 else 2, 0, 0, 0)) + \
        chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("capture")
    ap.add_argument("-o", "--out")
    ap.add_argument("--frame", type=int, default=0)
    ap.add_argument("--dump-textures")
    ap.add_argument("--list", action="store_true", help="print each draw's main state")
    a = ap.parse_args()
    dump = None
    if a.dump_textures:
        os.makedirs(a.dump_textures, exist_ok=True)

        def dump(tid, t):
            write_png(os.path.join(a.dump_textures, "tex_%08x_%dx%d.png" % (tid, t.w, t.h)),
                      np.round(t.levels[0] * 255).astype(np.uint8))
    dev = replay(a.capture, a.frame, dump, a.list)
    out = a.out or os.path.splitext(a.capture)[0] + ".ref.png"
    write_png(out, dev.color)
    print("%s: %d draws, %d textures -> %s" % (a.capture, dev.draws, len(dev.textures), out))
    for k, v in dev.unsupported.items():
        print("  not exact: %s (x%d)" % (k, v))


if __name__ == "__main__":
    main()
