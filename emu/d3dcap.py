"""D3D8 command stream ("MPD3"): what the game draws, as a self-contained byte stream.

The emulator's Direct3D layer writes it (emu/d3d8.py, capture mode); the reference rasterizer (tools/refrast.py)
and the Metal renderer (render/, libmprender) read it. The same records are what the native host will feed the
renderer live, so this file is the contract between the game side and the renderer. render/mpd3.h mirrors it.

Layout (all little-endian):
    header   : b"MPD3", u32 version (1), u32 backbuffer width, u32 backbuffer height
    records  : u32 type, u32 payload length, payload

Record types and payloads:
    TEXTURE     1  u32 id, u32 D3DFORMAT, u32 width, u32 height, u32 levels,
                   then per level: u32 w, u32 h, u32 pitch, u32 size, size bytes (D3D memory layout).
                   Sent before the first draw that samples the texture, and again whenever its contents change.
    RENDERSTATE 2  u32 n, n x (u32 D3DRENDERSTATETYPE, u32 value)
    TSS         3  u32 n, n x (u32 stage, u32 D3DTEXTURESTAGESTATETYPE, u32 value)
    SETTEXTURE  4  u32 stage, u32 texture id (0 = none)
    VIEWPORT    5  u32 x, u32 y, u32 w, u32 h, f32 minz, f32 maxz
    CLEAR       6  u32 flags (1 target, 2 z, 4 stencil), u32 ARGB color, f32 z, u32 stencil, u32 nrects,
                   nrects x (i32 x1, y1, x2, y2)
    DRAW        7  u32 D3DPRIMITIVETYPE, u32 FVF, u32 stride, u32 nverts, u32 nindices (0: not indexed),
                   u32 index size (2 or 4), nverts*stride vertex bytes, nindices*index size index bytes.
                   Indices are rebased so 0 is the first vertex sent.
    PRESENT     8  (empty) end of a frame
    TRANSFORM   9  u32 D3DTRANSFORMSTATETYPE (2 VIEW, 3 PROJECTION, 256 WORLD, ...), 16 f32 (D3DMATRIX, row-major)
"""
import struct
import zlib

MAGIC = b"MPD3"
VERSION = 1
TEXTURE, RENDERSTATE, TSS, SETTEXTURE, VIEWPORT, CLEAR, DRAW, PRESENT, TRANSFORM = range(1, 10)
NAMES = {TEXTURE: "TEXTURE", RENDERSTATE: "RENDERSTATE", TSS: "TSS", SETTEXTURE: "SETTEXTURE",
         VIEWPORT: "VIEWPORT", CLEAR: "CLEAR", DRAW: "DRAW", PRESENT: "PRESENT", TRANSFORM: "TRANSFORM"}


def index_count(prim, count):
    return {1: count, 2: 2 * count, 3: count + 1, 4: 3 * count, 5: count + 2, 6: count + 2}.get(prim, 0)


class Writer:
    """Appends records to a file, or hands each one to `sink(type, payload)` (live rendering, emu/live.py).
    Texture contents are sent only when new or changed (CRC per texture id)."""
    def __init__(self, path, width, height, sink=None):
        self.sink = sink
        self.f = None
        if sink is None:
            self.f = open(path, "wb")
            self.f.write(MAGIC + struct.pack("<III", VERSION, width, height))
        self.sent = {}                 # texture id -> crc of the contents last sent
        self.tex_ver = {}              # texture id -> lock count when last sent (kept by the game side, emu/d3d8.py)
        self.counts = {}

    def rec(self, typ, payload):
        if self.sink:
            self.sink(typ, payload)
        else:
            self.f.write(struct.pack("<II", typ, len(payload)) + payload)
        self.counts[typ] = self.counts.get(typ, 0) + 1

    def texture(self, tid, fmt, w, h, levels):
        """levels: list of (w, h, pitch, bytes). Writes only if the contents changed since the last send."""
        blob = b"".join(struct.pack("<IIII", lw, lh, p, len(d)) + d for lw, lh, p, d in levels)
        crc = zlib.crc32(blob)
        if self.sent.get(tid) == crc:
            return
        self.sent[tid] = crc
        self.rec(TEXTURE, struct.pack("<IIIII", tid, fmt, w, h, len(levels)) + blob)

    def render_states(self, pairs):
        if pairs:
            self.rec(RENDERSTATE, struct.pack("<I", len(pairs)) + b"".join(struct.pack("<II", s, v & 0xFFFFFFFF) for s, v in pairs))

    def tss(self, triples):
        if triples:
            self.rec(TSS, struct.pack("<I", len(triples)) + b"".join(struct.pack("<III", a, b, c & 0xFFFFFFFF) for a, b, c in triples))

    def set_texture(self, stage, tid):
        self.rec(SETTEXTURE, struct.pack("<II", stage, tid))

    def viewport(self, x, y, w, h, minz, maxz):
        self.rec(VIEWPORT, struct.pack("<IIIIff", x, y, w, h, minz, maxz))

    def clear(self, flags, color, z, stencil, rects):
        self.rec(CLEAR, struct.pack("<IIfII", flags, color, z, stencil, len(rects)) +
                 b"".join(struct.pack("<iiii", *r) for r in rects))

    def draw(self, prim, fvf, stride, vbytes, ibytes, isize):
        nverts = len(vbytes) // stride if stride else 0
        self.rec(DRAW, struct.pack("<IIIIII", prim, fvf, stride, nverts, len(ibytes) // isize if ibytes else 0, isize)
                 + vbytes + ibytes)

    def present(self):
        self.rec(PRESENT, b"")

    def transform(self, state, m16):
        self.rec(TRANSFORM, struct.pack("<I16f", state, *m16))

    def close(self):
        if self.f:
            self.f.close()


def read(path):
    """Yield (type, payload) records; the first item is ('header', (width, height))."""
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == MAGIC, "not an MPD3 capture"
    ver, w, h = struct.unpack_from("<III", data, 4)
    assert ver == VERSION, ver
    yield "header", (w, h)
    p = 16
    while p + 8 <= len(data):
        typ, n = struct.unpack_from("<II", data, p)
        yield typ, data[p + 8:p + 8 + n]
        p += 8 + n


def parse_texture(payload):
    tid, fmt, w, h, n = struct.unpack_from("<IIIII", payload)
    p, levels = 20, []
    for _ in range(n):
        lw, lh, pitch, size = struct.unpack_from("<IIII", payload, p)
        levels.append((lw, lh, pitch, payload[p + 16:p + 16 + size]))
        p += 16 + size
    return tid, fmt, w, h, levels


def parse_draw(payload):
    prim, fvf, stride, nv, ni, isz = struct.unpack_from("<IIIIII", payload)
    vb = payload[24:24 + nv * stride]
    ib = payload[24 + nv * stride:24 + nv * stride + ni * isz]
    return prim, fvf, stride, nv, ni, isz, vb, ib
