"""Logging Direct3D 8 for the emulator (first step of M3).

Provides Direct3DCreate8 and fake COM objects (IDirect3D8, IDirect3DDevice8, textures, surfaces, vertex and
index buffers) that live in guest memory with correct vtable layouts and stdcall argument counts. Every call
is recorded; the answers are plausible (adapter, caps, display modes, formats) and locks hand out real backing
memory, so the game can run on. The recorder's report is the specification for the Metal layer: exactly which
methods, render states, texture-stage states, formats, vertex formats, shaders and draw calls the game uses.

NOTE: the capability values are invented-but-plausible DX8-era hardware values. The game's feature detection is
driven by them, so they decide which code paths run; replace them with what Metal can really do later.

Usage: d3d8.install(mpemu_module) once, before running guest code (mpemu.boot does this).
"""
import collections
import struct
import time

# ------------------------------------------------------------------ vtable layouts (DirectX 8.0 headers)
# (method name, number of parameters excluding `this`); slot order is the vtable order.
_IUNKNOWN = [("QueryInterface", 2), ("AddRef", 0), ("Release", 0)]

IDIRECT3D8 = _IUNKNOWN + [
    ("RegisterSoftwareDevice", 1), ("GetAdapterCount", 0), ("GetAdapterIdentifier", 3),
    ("GetAdapterModeCount", 1), ("EnumAdapterModes", 3), ("GetAdapterDisplayMode", 2),
    ("CheckDeviceType", 5), ("CheckDeviceFormat", 6), ("CheckDeviceMultiSampleType", 5),
    ("CheckDepthStencilMatch", 5), ("GetDeviceCaps", 3), ("GetAdapterMonitor", 1), ("CreateDevice", 6),
]

IDIRECT3DDEVICE8 = _IUNKNOWN + [
    ("TestCooperativeLevel", 0), ("GetAvailableTextureMem", 0), ("ResourceManagerDiscardBytes", 1),
    ("GetDirect3D", 1), ("GetDeviceCaps", 1), ("GetDisplayMode", 1), ("GetCreationParameters", 1),
    ("SetCursorProperties", 3), ("SetCursorPosition", 3), ("ShowCursor", 1),
    ("CreateAdditionalSwapChain", 2), ("Reset", 1), ("Present", 4), ("GetBackBuffer", 3),
    ("GetRasterStatus", 1), ("SetGammaRamp", 2), ("GetGammaRamp", 1), ("CreateTexture", 7),
    ("CreateVolumeTexture", 8), ("CreateCubeTexture", 6), ("CreateVertexBuffer", 5),
    ("CreateIndexBuffer", 5), ("CreateRenderTarget", 6), ("CreateDepthStencilSurface", 5),
    ("CreateImageSurface", 4), ("CopyRects", 5), ("UpdateTexture", 2), ("GetFrontBuffer", 1),
    ("SetRenderTarget", 2), ("GetRenderTarget", 1), ("GetDepthStencilSurface", 1), ("BeginScene", 0),
    ("EndScene", 0), ("Clear", 6), ("SetTransform", 2), ("GetTransform", 2), ("MultiplyTransform", 2),
    ("SetViewport", 1), ("GetViewport", 1), ("SetMaterial", 1), ("GetMaterial", 1), ("SetLight", 2),
    ("GetLight", 2), ("LightEnable", 2), ("GetLightEnable", 2), ("SetClipPlane", 2), ("GetClipPlane", 2),
    ("SetRenderState", 2), ("GetRenderState", 2), ("BeginStateBlock", 0), ("EndStateBlock", 1),
    ("ApplyStateBlock", 1), ("CaptureStateBlock", 1), ("DeleteStateBlock", 1), ("CreateStateBlock", 2),
    ("SetClipStatus", 1), ("GetClipStatus", 1), ("GetTexture", 2), ("SetTexture", 2),
    ("GetTextureStageState", 3), ("SetTextureStageState", 3), ("ValidateDevice", 1), ("GetInfo", 3),
    ("SetPaletteEntries", 2), ("GetPaletteEntries", 2), ("SetCurrentTexturePalette", 1),
    ("GetCurrentTexturePalette", 1), ("DrawPrimitive", 3), ("DrawIndexedPrimitive", 5),
    ("DrawPrimitiveUP", 4), ("DrawIndexedPrimitiveUP", 8), ("ProcessVertices", 5),
    ("CreateVertexShader", 4), ("SetVertexShader", 1), ("GetVertexShader", 1), ("DeleteVertexShader", 1),
    ("SetVertexShaderConstant", 3), ("GetVertexShaderConstant", 3), ("GetVertexShaderDeclaration", 3),
    ("GetVertexShaderFunction", 3), ("SetStreamSource", 3), ("GetStreamSource", 3), ("SetIndices", 2),
    ("GetIndices", 2), ("CreatePixelShader", 2), ("SetPixelShader", 1), ("GetPixelShader", 1),
    ("DeletePixelShader", 1), ("SetPixelShaderConstant", 3), ("GetPixelShaderConstant", 3),
    ("GetPixelShaderFunction", 3), ("DrawRectPatch", 3), ("DrawTriPatch", 3), ("DeletePatch", 1),
]

_RESOURCE = _IUNKNOWN + [("GetDevice", 1), ("SetPrivateData", 4), ("GetPrivateData", 3),
                         ("FreePrivateData", 1), ("SetPriority", 1), ("GetPriority", 0), ("PreLoad", 0),
                         ("GetType", 0)]
_BASETEX = _RESOURCE + [("SetLOD", 1), ("GetLOD", 0), ("GetLevelCount", 0)]
IDIRECT3DTEXTURE8 = _BASETEX + [("GetLevelDesc", 2), ("GetSurfaceLevel", 2), ("LockRect", 4),
                                ("UnlockRect", 1), ("AddDirtyRect", 1)]
IDIRECT3DSURFACE8 = _IUNKNOWN + [("GetDevice", 1), ("SetPrivateData", 4), ("GetPrivateData", 3),
                                 ("FreePrivateData", 1), ("GetContainer", 2), ("GetDesc", 1),
                                 ("LockRect", 3), ("UnlockRect", 0)]
IDIRECT3DVERTEXBUFFER8 = _RESOURCE + [("Lock", 4), ("Unlock", 0), ("GetDesc", 1)]
IDIRECT3DINDEXBUFFER8 = _RESOURCE + [("Lock", 4), ("Unlock", 0), ("GetDesc", 1)]
# volume/cube textures are not needed until the game asks for them: create fails with D3DERR_NOTAVAILABLE.

INTERFACES = {
    "IDirect3D8": IDIRECT3D8, "IDirect3DDevice8": IDIRECT3DDEVICE8, "IDirect3DTexture8": IDIRECT3DTEXTURE8,
    "IDirect3DSurface8": IDIRECT3DSURFACE8, "IDirect3DVertexBuffer8": IDIRECT3DVERTEXBUFFER8,
    "IDirect3DIndexBuffer8": IDIRECT3DINDEXBUFFER8,
}

# The engine names each driver after the adapter description, and the game's saved "Driver" setting must match it.
ADAPTER_DESCRIPTION = "Apple GPU (Metal), Direct3D 8 emulation"
D3D_OK = 0
D3DERR_NOTAVAILABLE = 0x8876086A
D3DERR_INVALIDCALL = 0x8876086C
E_NOINTERFACE = 0x80004002

# ------------------------------------------------------------------ readable names for the report
RS_NAMES = {7: "ZENABLE", 8: "FILLMODE", 9: "SHADEMODE", 14: "ZWRITEENABLE", 15: "ALPHATESTENABLE",
            16: "LASTPIXEL", 19: "SRCBLEND", 20: "DESTBLEND", 22: "CULLMODE", 23: "ZFUNC", 24: "ALPHAREF",
            25: "ALPHAFUNC", 26: "DITHERENABLE", 27: "ALPHABLENDENABLE", 28: "FOGENABLE",
            29: "SPECULARENABLE", 34: "FOGCOLOR", 35: "FOGTABLEMODE", 36: "FOGSTART", 37: "FOGEND",
            38: "FOGDENSITY", 47: "ZBIAS", 48: "RANGEFOGENABLE", 52: "STENCILENABLE", 53: "STENCILFAIL",
            54: "STENCILZFAIL", 55: "STENCILPASS", 56: "STENCILFUNC", 57: "STENCILREF", 58: "STENCILMASK",
            59: "STENCILWRITEMASK", 60: "TEXTUREFACTOR", 136: "CLIPPING", 137: "LIGHTING", 139: "AMBIENT",
            140: "FOGVERTEXMODE", 141: "COLORVERTEX", 142: "LOCALVIEWER", 143: "NORMALIZENORMALS",
            145: "DIFFUSEMATERIALSOURCE", 146: "SPECULARMATERIALSOURCE", 147: "AMBIENTMATERIALSOURCE",
            148: "EMISSIVEMATERIALSOURCE", 151: "VERTEXBLEND", 152: "CLIPPLANEENABLE",
            153: "SOFTWAREVERTEXPROCESSING", 154: "POINTSIZE", 155: "POINTSIZE_MIN", 156: "POINTSPRITEENABLE",
            157: "POINTSCALEENABLE", 161: "MULTISAMPLEANTIALIAS", 162: "MULTISAMPLEMASK", 166: "POINTSIZE_MAX",
            168: "COLORWRITEENABLE", 171: "BLENDOP"}
RS_NAMES.update({128 + i: "WRAP%d" % i for i in range(8)})
TSS_NAMES = {1: "COLOROP", 2: "COLORARG1", 3: "COLORARG2", 4: "ALPHAOP", 5: "ALPHAARG1", 6: "ALPHAARG2",
             7: "BUMPENVMAT00", 8: "BUMPENVMAT01", 9: "BUMPENVMAT10", 10: "BUMPENVMAT11", 11: "TEXCOORDINDEX",
             13: "ADDRESSU", 14: "ADDRESSV", 15: "BORDERCOLOR", 16: "MAGFILTER", 17: "MINFILTER",
             18: "MIPFILTER", 19: "MIPMAPLODBIAS", 20: "MAXMIPLEVEL", 21: "MAXANISOTROPY",
             22: "BUMPENVLSCALE", 23: "BUMPENVLOFFSET", 24: "TEXTURETRANSFORMFLAGS", 25: "ADDRESSW",
             26: "COLORARG0", 27: "ALPHAARG0", 28: "RESULTARG"}
TS_NAMES = {2: "VIEW", 3: "PROJECTION", 256: "WORLD"}
TS_NAMES.update({16 + i: "TEXTURE%d" % i for i in range(8)})
PRIM_NAMES = {1: "POINTLIST", 2: "LINELIST", 3: "LINESTRIP", 4: "TRIANGLELIST", 5: "TRIANGLESTRIP",
              6: "TRIANGLEFAN"}


def _fourcc(s): return struct.unpack("<I", s.encode())[0]


FMT_NAMES = {0: "UNKNOWN", 20: "R8G8B8", 21: "A8R8G8B8", 22: "X8R8G8B8", 23: "R5G6B5", 24: "X1R5G5B5",
             25: "A1R5G5B5", 26: "A4R4G4B4", 27: "R3G3B2", 28: "A8", 29: "A8R3G3B2", 30: "X4R4G4B4",
             41: "P8", 50: "L8", 51: "A8L8", 52: "A4L4", 60: "V8U8", 61: "L6V5U5", 62: "X8L8V8U8",
             63: "Q8W8V8U8", 64: "V16U16", 65: "W11V11U10", 70: "D16_LOCKABLE", 71: "D32", 73: "D15S1",
             75: "D24S8", 77: "D24X8", 79: "D24X4S4", 80: "D16", 100: "VERTEXDATA", 101: "INDEX16",
             102: "INDEX32", _fourcc("DXT1"): "DXT1", _fourcc("DXT2"): "DXT2", _fourcc("DXT3"): "DXT3",
             _fourcc("DXT4"): "DXT4", _fourcc("DXT5"): "DXT5"}
BPP = {20: 24, 21: 32, 22: 32, 23: 16, 24: 16, 25: 16, 26: 16, 27: 8, 28: 8, 29: 16, 30: 16, 41: 8, 50: 8,
       51: 16, 52: 8, 60: 16, 61: 16, 62: 32, 63: 32, 64: 32, 65: 32, 70: 16, 71: 32, 73: 16, 75: 32,
       77: 32, 79: 32, 80: 16}
POOL_NAMES = {0: "DEFAULT", 1: "MANAGED", 2: "SYSTEMMEM", 3: "SCRATCH"}


def fmt_name(f): return FMT_NAMES.get(f, "fmt#%d" % f)


def level_layout(w, h, fmt):
    """(pitch in bytes, total bytes) of one surface level."""
    dxt = {_fourcc("DXT1"): 8, _fourcc("DXT2"): 16, _fourcc("DXT3"): 16, _fourcc("DXT4"): 16,
           _fourcc("DXT5"): 16}
    if fmt in dxt:
        bw, bh = max(1, (w + 3) // 4), max(1, (h + 3) // 4)
        return bw * dxt[fmt], bw * bh * dxt[fmt]
    pitch = w * (BPP.get(fmt, 32) // 8)
    return pitch, pitch * h


# ------------------------------------------------------------------ the recorder
class _FastMap:
    """A Recorder state dict whose entries live in lift/runtime/hle_fast.c (native.HleFast) once the fast path runs:
    get/set by key, items() in key order. Keys outside the C arrays stay in a Python dict (extra)."""

    def __init__(self, fast, which, keys, split, pack, unpack):
        self.fast, self.which, self.keys, self.split, self.pack, self.unpack = fast, which, keys, split, pack, unpack
        self.extra = {}

    def __setitem__(self, k, v):
        a, b = self.split(k)
        x, y = self.pack(v)
        if not self.fast.set(self.which, a, b, x, y):
            self.extra[k] = v

    def get(self, k, default=None):
        a, b = self.split(k)
        r = self.fast.get(self.which, a, b)
        if r is not None and k not in self.extra:
            return self.unpack(r)
        return self.extra.get(k, default)

    def __getitem__(self, k):
        v = self.get(k, _MISSING)
        if v is _MISSING:
            raise KeyError(k)
        return v

    def __contains__(self, k):
        return self.get(k, _MISSING) is not _MISSING

    def items(self):
        out = []
        for k in self.keys:
            r = self.fast.get(self.which, *self.split(k))
            if r is not None:
                out.append((k, self.unpack(r)))
        return out + list(self.extra.items())

    def __iter__(self):
        return iter([k for k, _ in self.items()])

    def __len__(self):
        return len(self.items())


_MISSING = object()


class _FastXf:
    """Recorder.cur_xf once the transforms live in hle_fast.c (H60): state -> 16 floats, stored there as f32 bits."""

    def __init__(self, fast):
        self.fast, self.extra = fast, {}

    def __setitem__(self, k, m):
        if not self.fast.blob(0, k, struct.pack("<16f", *m)):
            self.extra[k] = m

    def get(self, k, default=None):
        b = self.fast.blob(0, k)
        return struct.unpack("<16f", b) if b is not None else self.extra.get(k, default)

    def items(self):
        out = []
        for k in range(512):
            b = self.fast.blob(0, k)
            if b is not None:
                out.append((k, struct.unpack("<16f", b)))
        return out + list(self.extra.items())


class Recorder:
    def __init__(self, screen):
        self._fast = None                  # native.HleFast once the D3D8 state lives in C (attach_fast)
        self._indices, self._cur_vs, self._viewport = (0, 0), 0, None
        self.screen = screen
        self.calls = collections.Counter()
        self.render_states = collections.defaultdict(collections.Counter)
        self.tss = collections.defaultdict(collections.Counter)
        self.transforms = collections.Counter()
        self.formats = collections.defaultdict(collections.Counter)    # context -> Counter(format)
        self.textures = []
        self.buffers = []
        self.fvfs = collections.Counter()
        self.draws = collections.Counter()                              # (kind, prim name) -> count
        self.draw_by_vs = collections.Counter()
        self.vshaders, self.pshaders = [], []
        self.clears = collections.Counter()
        self.lights = 0
        self.present_params = []
        self.device_caps_queries = 0
        self.checks = collections.Counter()
        self.objs = {}
        self.cur_vs = 0
        self.cur_ps = 0
        self.bound_tex = {}
        self.streams = {}
        self.sampler_texfmt = collections.Counter()
        # current device state (for frame capture, see start_capture)
        self.cur_rs, self.cur_tss = {}, {}
        self.viewport = None
        self.indices = (0, 0)              # (index buffer object, BaseVertexIndex)
        self.cur_xf = {}                   # D3DTRANSFORMSTATETYPE -> 16 floats (row-major)
        self.capture = None                # d3dcap.Writer while capturing
        self.statements = []

    # The index buffer and vertex shader: in C with the other state once attached.
    @property
    def indices(self):
        return self._fast.get(4) if self._fast else self._indices

    @indices.setter
    def indices(self, v):
        if self._fast:
            self._fast.set(4, 0, 0, v[0], v[1])
        else:
            self._indices = v

    @property
    def viewport(self):
        if self._fast and self._fast.h60:
            b = self._fast.blob(1, 0)
            return struct.unpack("<IIIIff", b) if b is not None else None
        return self._viewport

    @viewport.setter
    def viewport(self, v):
        if self._fast and self._fast.h60:
            if v is None:
                self._fast.blob(1, 0, clear=True)
            else:
                self._fast.blob(1, 0, struct.pack("<IIIIff", *v))
        else:
            self._viewport = v

    @property
    def cur_vs(self):
        return self._fast.get(5)[0] if self._fast else self._cur_vs

    @cur_vs.setter
    def cur_vs(self, v):
        if self._fast:
            self._fast.set(5, 0, 0, v)
        else:
            self._cur_vs = v

    def attach_fast(self, e):
        """Move the device state the C handlers use (lift/runtime/hle_fast.c) into C: render and texture-stage states,
        bound textures, streams, indices, vertex shader; register the objects and the capture mode."""
        fast = e.hle_fast
        if self._fast is fast:
            return
        maps = (("cur_rs", 0, range(256), lambda k: (k, 0), lambda v: (v, 0), lambda r: r[0]),
                ("cur_tss", 1, [(s, t) for s in range(8) for t in range(32)], lambda k: k, lambda v: (v, 0),
                 lambda r: r[0]),
                ("bound_tex", 2, range(8), lambda k: (k, 0), lambda v: (v, 0), lambda r: r[0]),
                ("streams", 3, range(16), lambda k: (k, 0), lambda v: v, lambda r: r))
        for name, which, keys, split, pack, unpack in maps:
            old = getattr(self, name)
            view = _FastMap(fast, which, keys, split, pack, unpack)
            for k, v in old.items():
                view[k] = v
            setattr(self, name, view)
        fast.set(4, 0, 0, self._indices[0], self._indices[1])
        fast.set(5, 0, 0, self._cur_vs)
        if fast.h60:                       # H60: the transforms and the viewport too (SetTransform, SetViewport in C)
            xf = _FastXf(fast)
            for k, m in self.cur_xf.items():
                xf[k] = m
            self.cur_xf = xf
            if self._viewport is not None:
                fast.blob(1, 0, struct.pack("<IIIIff", *self._viewport))
        tex_ver = self.capture.tex_ver if self.capture else {}
        for addr, o in self.objs.items():
            fast.obj(addr, o["iface"], o.get("ptr"), o.get("fmt"))
            if o["iface"] == "IDirect3DTexture8":
                fast.tex(addr, o.get("ver", 0), tex_ver.get(addr))
        self._fast = fast
        self._fast_capture()

    def _fast_capture(self, reset_sent=False):
        """Tell the C handlers how to capture: not at all, through the live renderer's C sink, or leave it to Python."""
        import native
        if not self._fast:
            return
        cap = self.capture
        if cap is None:
            self._fast.capture(native.CAP_NONE, reset_sent=reset_sent)
        elif getattr(cap, "c_sink", None):
            self._fast.capture(native.CAP_SINK, *cap.c_sink, reset_sent=reset_sent)
        else:
            self._fast.capture(native.CAP_PYTHON, reset_sent=reset_sent)

    def report(self):
        if self._fast:
            self._fast.merge(self)             # what the C handlers counted
        L = ["# Direct3D 8 usage recorded from Max Payne (emulated run)", ""]
        L.append("Generated by `emu/d3d8.py` from a run of `emu/run_init.py`. Values the game was *given* "
                 "(caps, formats, modes) are invented-but-plausible, see the module docstring.\n")
        L.append("## Device creation / presentation parameters")
        for p in self.present_params:
            L.append("- " + p)
        L.append("")
        L.append("## Methods called (%d distinct)" % len(self.calls))
        for k, v in sorted(self.calls.items(), key=lambda kv: (-kv[1], kv[0])):
            L.append("- `%s` x%d" % (k, v))
        L.append("\n## Capability and format queries")
        for k, v in sorted(self.checks.items()):
            L.append("- %s x%d" % (k, v))
        L.append("\n## Render states set (state: values seen)")
        for st in sorted(self.render_states):
            vals = ", ".join("%s x%d" % (hex(v) if v > 255 else v, c) for v, c in self.render_states[st].most_common(8))
            L.append("- %s (%d): %s" % (RS_NAMES.get(st, "state#%d" % st), st, vals))
        L.append("\n## Texture-stage states set ((stage, type): values seen)")
        for (stg, ty) in sorted(self.tss):
            vals = ", ".join("%s x%d" % (hex(v) if v > 255 else v, c) for v, c in self.tss[(stg, ty)].most_common(8))
            L.append("- stage %d %s (%d): %s" % (stg, TSS_NAMES.get(ty, "type#%d" % ty), ty, vals))
        L.append("\n## Transforms set")
        for k, v in sorted(self.transforms.items()):
            L.append("- %s x%d" % (TS_NAMES.get(k, "state#%d" % k), v))
        L.append("\n## Surface / texture / buffer formats")
        for ctx in sorted(self.formats):
            L.append("- %s: %s" % (ctx, ", ".join("%s x%d" % (fmt_name(f), c) for f, c in self.formats[ctx].most_common())))
        L.append("\n## Textures created (first 40)")
        for t in self.textures[:40]:
            L.append("- " + t)
        L.append("\n## Vertex and index buffers created (first 40)")
        for b in self.buffers[:40]:
            L.append("- " + b)
        L.append("\n## Vertex formats (FVF codes) used with SetVertexShader / buffers")
        for k, v in sorted(self.fvfs.items()):
            L.append("- 0x%x x%d%s" % (k, v, " " + _fvf_text(k)))
        L.append("\n## Draw calls by primitive type")
        for k, v in sorted(self.draws.items()):
            L.append("- %s x%d" % (k, v))
        L.append("\n## Vertex shaders created: %d" % len(self.vshaders))
        for s in self.vshaders:
            L.append("- " + s)
        L.append("\n## Pixel shaders created: %d" % len(self.pshaders))
        for s in self.pshaders:
            L.append("- " + s)
        L.append("\n## Clear flags")
        for k, v in sorted(self.clears.items()):
            L.append("- 0x%x x%d" % (k, v))
        L.append("\n- Lights set: %d" % self.lights)
        return "\n".join(L) + "\n"


def _fvf_text(f):
    parts = []
    pos = f & 0x0E
    parts.append({0x02: "XYZ", 0x04: "XYZRHW", 0x06: "XYZB1", 0x08: "XYZB2", 0x0A: "XYZB3", 0x0C: "XYZB4",
                  0x0E: "XYZB5"}.get(pos, "pos?"))
    if f & 0x10: parts.append("NORMAL")
    if f & 0x20: parts.append("PSIZE")
    if f & 0x40: parts.append("DIFFUSE")
    if f & 0x80: parts.append("SPECULAR")
    parts.append("TEX%d" % ((f >> 8) & 0xF))
    return "(" + "|".join(parts) + ")"


# ------------------------------------------------------------------ installation
def display_modes(m):
    """The display modes the adapter offers (EnumAdapterModes): common modes plus the desktop (mpemu.SCREEN)."""
    return sorted({(640, 480), (800, 600), (1024, 768), (1280, 720), (1280, 1024), (1600, 1200), (1920, 1080),
                   tuple(m.SCREEN)})


def backbuffer_size(e):
    dev = next((o for o in e.d3d.objs.values() if o.get("iface") == "IDirect3DDevice8"), None)
    return (dev["params"][0], dev["params"][1]) if dev else (0, 0)


def start_capture(e, path, sink=None, c_sink=None):
    """Write everything drawn from now on as an MPD3 stream (emu/d3dcap.py), starting with the current state:
    to a file, or record by record to `sink(type, payload)` for live rendering. c_sink: (submit, renderer, last_error)
    C addresses that do what sink does (emu/live.py), so the C handlers (lift/runtime/hle_fast.c) can submit too."""
    import d3dcap
    r = e.d3d
    w, h = backbuffer_size(e)
    cap = d3dcap.Writer(path, w, h, sink)
    cap.render_states(sorted(r.cur_rs.items()))
    cap.tss([(st, ty, v) for (st, ty), v in sorted(r.cur_tss.items())])
    if r.viewport:
        cap.viewport(*r.viewport)
    for state, mat in sorted(r.cur_xf.items()):
        cap.transform(state, mat)
    for stage, tex in sorted(r.bound_tex.items()):
        cap.set_texture(stage, tex)
    cap.c_sink = c_sink
    r.capture = cap
    r._fast_capture(reset_sent=True)       # a new Writer has sent no textures yet
    return cap


def stop_capture(e):
    cap, e.d3d.capture = e.d3d.capture, None
    if cap:
        cap.close()
    e.d3d._fast_capture()
    return cap


def install(m):
    """Register the Direct3D 8 handlers with the emulator module `m` (mpemu)."""
    if getattr(m, "_d3d8_installed", False):
        return
    m._d3d8_installed = True
    hle, GuestCall = m.hle, m.GuestCall
    DLL = "D3D8.DLL"

    def rec(e):
        if not hasattr(e, "d3d"):
            e.d3d = Recorder(m.SCREEN)
            if getattr(e, "hle_fast", None) is not None:
                e.d3d.attach_fast(e)
        return e.d3d

    # -------- object model
    def vtable(e, iface):
        vtables = e.__dict__.setdefault("_vtables_" + DLL, {})    # per emulator (id(e) gets reused)
        if iface not in vtables:
            methods = INTERFACES[iface]
            p = e.alloc(4 * len(methods))
            for i, (name, _) in enumerate(methods):
                e.wr32(p + 4 * i, e.stub_for(DLL, "%s::%s" % (iface, name)))
            vtables[iface] = p
        return vtables[iface]

    def new_obj(e, iface, **state):
        a = e.alloc(16)
        e.wr32(a, vtable(e, iface))
        e.wr32(a + 4, 1)
        state["iface"] = iface
        state["addr"] = a
        r = rec(e)
        r.objs[a] = state
        if r._fast:
            r._fast.obj(a, iface, state.get("ptr"), state.get("fmt"))
        return a

    def obj(e, this): return rec(e).objs.get(this, {})

    def out32(e, p, v):
        if p:
            e.wr32(p, v)

    # -------- caps / identifiers / modes
    def fill_caps(e, p):
        c = [0] * 53
        c[0] = 1                     # D3DDEVTYPE_HAL
        c[2] = 0x20000               # Caps: READ_SCANLINE
        c[3] = 0x20000000 | 0x80000  # Caps2: DYNAMICTEXTURES | CANRENDERWINDOWED
        c[4] = 0x20 | 0x80           # Caps3: ALPHA_FULLSCREEN_FLIP_OR_DISCARD | COPY_TO_VIDMEM-ish
        c[5] = 0x1 | 0x80000000      # PresentationIntervals: IMMEDIATE|ONE (approx)
        c[7] = 0x1BBFF0              # DevCaps (HW T&L, DrawPrimitives2Ex, pure device...)
        c[8] = 0x7F0 | 0x1000        # PrimitiveMiscCaps
        c[9] = 0x7F5FF               # RasterCaps (approx: fog, zbias, anisotropy, mipmap lod bias...)
        c[10] = 0xFF                 # ZCmpCaps
        c[11] = 0x3FFF; c[12] = 0x3FFF   # Src/Dest blend caps
        c[13] = 0xFF                 # AlphaCmpCaps
        # ShadeCaps: COLORGOURAUDRGB | SPECULARGOURAUDRGB | ALPHAGOURAUDBLEND (the driver drops vertex alpha
        # without it) | FOGGOURAUD
        c[14] = 0x2 | 0x8 | 0x20 | 0x200 | 0x4000 | 0x80000
        c[15] = 0x1 | 0x2 | 0x4 | 0x8 | 0x40 | 0x80 | 0x100 | 0x400 | 0x800 | 0x4000   # TextureCaps
        # TextureFilterCaps: MIN point/linear/anisotropic (0x700), MIP point/linear (0x30000), MAG point/linear/
        # anisotropic (0x7000000). Metal does all of these; advertising less makes the engine fall back to point.
        c[16] = 0x07030700
        c[19] = 0x1F                 # TextureAddressCaps
        c[21] = 0x7                  # LineCaps
        c[22] = c[23] = 4096         # MaxTextureWidth/Height
        c[24] = 256; c[25] = 32768; c[26] = 4096; c[27] = 16
        c[28] = struct.unpack("<I", struct.pack("<f", 1e10))[0]            # MaxVertexW
        for i, v in zip(range(29, 33), (-8192.0, -8192.0, 8192.0, 8192.0)):
            c[i] = struct.unpack("<I", struct.pack("<f", v))[0]            # GuardBandLeft/Top/Right/Bottom
        c[34] = 0xFF                 # StencilCaps
        c[35] = 0x8 | 0x10000 | 0x8000 | 0x2   # FVFCaps: 8 tex coords sets (low bits), DO_NOT_STRIP...
        c[36] = 0x3FFFFFF            # TextureOpCaps
        c[37] = 8; c[38] = 8         # MaxTextureBlendStages / MaxSimultaneousTextures
        c[39] = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80   # VertexProcessingCaps
        c[40] = 8; c[41] = 6; c[42] = 4; c[43] = 255
        c[44] = struct.unpack("<I", struct.pack("<f", 64.0))[0]            # MaxPointSize
        c[45] = 0xFFFFF; c[46] = 0xFFFFF; c[47] = 16; c[48] = 256
        c[49] = 0xFFFE0101           # VertexShaderVersion 1.1
        c[50] = 96
        c[51] = 0xFFFF0104           # PixelShaderVersion 1.4
        c[52] = struct.unpack("<I", struct.pack("<f", 1.0))[0]
        e.wr(p, struct.pack("<53I", *c))

    MODES = display_modes(m)

    def reg_method(iface, name, nparams, fn):
        hle(DLL, "%s::%s" % (iface, name), 1 + nparams)(fn)

    def logged(iface, name, extra=None, ret=D3D_OK):
        key = "%s::%s" % (iface, name)

        def fn(e, this, *a):
            rec(e).calls[key] += 1
            if extra:
                r = extra(e, this, *a)
                return ret if r is None else r
            return ret
        return fn

    # -------- generic IUnknown
    for iface in INTERFACES:
        def addref(e, this, _i=iface):
            n = e.rd32(this + 4) + 1
            e.wr32(this + 4, n)
            rec(e).calls["%s::AddRef" % _i] += 1
            return n

        def release(e, this, _i=iface):
            n = max(e.rd32(this + 4) - 1, 0)
            e.wr32(this + 4, n)
            rec(e).calls["%s::Release" % _i] += 1
            return n

        def qi(e, this, riid, ppv, _i=iface):
            rec(e).calls["%s::QueryInterface" % _i] += 1
            out32(e, ppv, 0)
            return E_NOINTERFACE
        reg_method(iface, "AddRef", 0, addref)
        reg_method(iface, "Release", 0, release)
        reg_method(iface, "QueryInterface", 2, qi)

    # -------- Direct3DCreate8
    @hle(DLL, "Direct3DCreate8", 1)
    def direct3d_create8(e, version):
        r = rec(e)
        r.calls["Direct3DCreate8"] += 1
        r.present_params.append("Direct3DCreate8(SDKVersion=%d)" % version)
        return new_obj(e, "IDirect3D8")

    # -------- IDirect3D8
    I = "IDirect3D8"

    def adapter_identifier(e, this, adapter, flags, p):
        buf = bytearray(1068)
        buf[0:12] = b"metal-d3d8\0\0"
        desc = ADAPTER_DESCRIPTION.encode("latin1")
        buf[512:512 + len(desc)] = desc
        struct.pack_into("<QIIII", buf, 1024, 0x0001000100010001, 0x106B, 0x0001, 0, 1)
        e.wr(p, bytes(buf))
    reg_method(I, "GetAdapterIdentifier", 3, logged(I, "GetAdapterIdentifier", adapter_identifier))
    reg_method(I, "GetAdapterCount", 0, logged(I, "GetAdapterCount", ret=1))
    reg_method(I, "GetAdapterModeCount", 1, logged(I, "GetAdapterModeCount", ret=len(MODES)))
    reg_method(I, "RegisterSoftwareDevice", 1, logged(I, "RegisterSoftwareDevice", ret=D3DERR_NOTAVAILABLE))
    reg_method(I, "GetAdapterMonitor", 1, logged(I, "GetAdapterMonitor", ret=0x7000))

    def enum_modes(e, this, adapter, idx, p):
        if idx >= len(MODES):
            return D3DERR_INVALIDCALL
        w, h = MODES[idx]
        e.wr(p, struct.pack("<IIII", w, h, 60, 22))     # X8R8G8B8 at 60 Hz
    reg_method(I, "EnumAdapterModes", 3, logged(I, "EnumAdapterModes", enum_modes))

    def cur_mode(e, this, adapter, p):
        w, h = m.SCREEN
        e.wr(p, struct.pack("<IIII", w, h, 60, 22))
    reg_method(I, "GetAdapterDisplayMode", 2, logged(I, "GetAdapterDisplayMode", cur_mode))

    def check_type(e, this, adapter, ctype, dfmt, bfmt, windowed):
        rec(e).checks["CheckDeviceType display=%s backbuffer=%s windowed=%d" % (fmt_name(dfmt), fmt_name(bfmt), windowed)] += 1
    reg_method(I, "CheckDeviceType", 5, logged(I, "CheckDeviceType", check_type))

    def check_format(e, this, adapter, dtype, afmt, usage, rtype, cfmt):
        rec(e).checks["CheckDeviceFormat adapter=%s usage=0x%x rtype=%d format=%s" % (fmt_name(afmt), usage, rtype, fmt_name(cfmt))] += 1
    reg_method(I, "CheckDeviceFormat", 6, logged(I, "CheckDeviceFormat", check_format))

    def check_ms(e, this, adapter, dtype, sfmt, windowed, mst):
        rec(e).checks["CheckDeviceMultiSampleType type=%d format=%s" % (mst, fmt_name(sfmt))] += 1
        return D3D_OK if mst == 0 else D3DERR_NOTAVAILABLE
    reg_method(I, "CheckDeviceMultiSampleType", 5, logged(I, "CheckDeviceMultiSampleType", check_ms))

    def check_ds(e, this, adapter, dtype, afmt, rfmt, dsfmt):
        rec(e).checks["CheckDepthStencilMatch rt=%s depth=%s" % (fmt_name(rfmt), fmt_name(dsfmt))] += 1
    reg_method(I, "CheckDepthStencilMatch", 5, logged(I, "CheckDepthStencilMatch", check_ds))

    def d3d_caps(e, this, adapter, dtype, p):
        rec(e).device_caps_queries += 1
        fill_caps(e, p)
    reg_method(I, "GetDeviceCaps", 3, logged(I, "GetDeviceCaps", d3d_caps))

    def create_device(e, this, adapter, dtype, hwnd, behavior, ppp, ppdev):
        r = rec(e)
        pp = struct.unpack("<13I", e.rd(ppp, 52))
        names = ("BackBufferWidth", "BackBufferHeight", "BackBufferFormat", "BackBufferCount", "MultiSampleType",
                 "SwapEffect", "hDeviceWindow", "Windowed", "EnableAutoDepthStencil", "AutoDepthStencilFormat",
                 "Flags", "FullScreen_RefreshRateInHz", "FullScreen_PresentationInterval")
        txt = ", ".join("%s=%s" % (n, fmt_name(v) if "Format" in n else (hex(v) if v > 9999 else v)) for n, v in zip(names, pp))
        r.present_params.append("CreateDevice(adapter=%d, devtype=%d, hFocusWindow=0x%x, behavior=0x%x): %s" % (
            adapter, dtype, hwnd, behavior, txt))
        r.formats["backbuffer"][pp[2]] += 1
        if pp[8]:
            r.formats["auto depth-stencil"][pp[9]] += 1
        dev = new_obj(e, "IDirect3DDevice8", d3d=this, params=pp, hwnd=hwnd)
        out32(e, ppdev, dev)
    reg_method(I, "CreateDevice", 6, logged(I, "CreateDevice", create_device))

    # -------- resources
    def make_level_chain(e, w, h, levels, fmt):
        if levels == 0:
            levels = max(w, h).bit_length()
        chain = []
        for i in range(levels):
            lw, lh = max(1, w >> i), max(1, h >> i)
            pitch, size = level_layout(lw, lh, fmt)
            chain.append({"w": lw, "h": lh, "pitch": pitch, "size": size, "ptr": e.alloc(max(size, 16))})
        return chain

    D = "IDirect3DDevice8"

    def create_texture(e, this, w, h, levels, usage, fmt, pool, pp):
        r = rec(e)
        chain = make_level_chain(e, w, h, levels, fmt)
        r.formats["texture"][fmt] += 1
        r.textures.append("%dx%d levels=%d usage=0x%x format=%s pool=%s" % (
            w, h, len(chain), usage, fmt_name(fmt), POOL_NAMES.get(pool, pool)))
        out32(e, pp, new_obj(e, "IDirect3DTexture8", w=w, h=h, fmt=fmt, usage=usage, pool=pool, chain=chain))
    reg_method(D, "CreateTexture", 7, logged(D, "CreateTexture", create_texture))

    def create_surface_obj(e, w, h, fmt, usage=0, pool=2, container=None, chain=None, ptr=None, pitch=None):
        if ptr is None:
            pitch, size = level_layout(w, h, fmt)
            ptr = e.alloc(max(size, 16))
        return new_obj(e, "IDirect3DSurface8", w=w, h=h, fmt=fmt, usage=usage, pool=pool, ptr=ptr, pitch=pitch,
                       container=container)

    def create_vb(e, this, length, usage, fvf, pool, pp):
        r = rec(e)
        if fvf:
            r.fvfs[fvf] += 1
        r.buffers.append("VertexBuffer length=%d usage=0x%x fvf=0x%x pool=%s" % (length, usage, fvf, POOL_NAMES.get(pool, pool)))
        out32(e, pp, new_obj(e, "IDirect3DVertexBuffer8", length=length, usage=usage, fvf=fvf, pool=pool,
                             ptr=e.alloc(max(length, 16))))
    reg_method(D, "CreateVertexBuffer", 5, logged(D, "CreateVertexBuffer", create_vb))

    def create_ib(e, this, length, usage, fmt, pool, pp):
        r = rec(e)
        r.formats["index buffer"][fmt] += 1
        r.buffers.append("IndexBuffer length=%d usage=0x%x format=%s pool=%s" % (length, usage, fmt_name(fmt), POOL_NAMES.get(pool, pool)))
        out32(e, pp, new_obj(e, "IDirect3DIndexBuffer8", length=length, usage=usage, fmt=fmt, pool=pool,
                             ptr=e.alloc(max(length, 16))))
    reg_method(D, "CreateIndexBuffer", 5, logged(D, "CreateIndexBuffer", create_ib))

    def create_rt(e, this, w, h, fmt, ms, lockable, pp):
        rec(e).formats["render target"][fmt] += 1
        out32(e, pp, create_surface_obj(e, w, h, fmt, usage=1, pool=0))
    reg_method(D, "CreateRenderTarget", 6, logged(D, "CreateRenderTarget", create_rt))

    def create_ds(e, this, w, h, fmt, ms, pp):
        rec(e).formats["depth-stencil surface"][fmt] += 1
        out32(e, pp, create_surface_obj(e, w, h, fmt, usage=2, pool=0))
    reg_method(D, "CreateDepthStencilSurface", 5, logged(D, "CreateDepthStencilSurface", create_ds))

    def create_image(e, this, w, h, fmt, pp):
        rec(e).formats["image surface"][fmt] += 1
        out32(e, pp, create_surface_obj(e, w, h, fmt))
    reg_method(D, "CreateImageSurface", 4, logged(D, "CreateImageSurface", create_image))
    reg_method(D, "CreateVolumeTexture", 8, logged(D, "CreateVolumeTexture", ret=D3DERR_NOTAVAILABLE))
    reg_method(D, "CreateCubeTexture", 6, logged(D, "CreateCubeTexture", ret=D3DERR_NOTAVAILABLE))

    # -------- texture / surface / buffer methods
    T = "IDirect3DTexture8"
    reg_method(T, "GetLevelCount", 0, logged(T, "GetLevelCount", lambda e, this: None) if False else
               (lambda e, this: (rec(e).calls.update([T + "::GetLevelCount"]), len(obj(e, this)["chain"]))[1]))

    def tex_level_desc(e, this, level, p):
        o = obj(e, this)
        lv = o["chain"][level]
        e.wr(p, struct.pack("<8I", o["fmt"], 3, o["usage"], o["pool"], lv["size"], 0, lv["w"], lv["h"]))
    reg_method(T, "GetLevelDesc", 2, logged(T, "GetLevelDesc", tex_level_desc))

    def tex_surface_level(e, this, level, pp):
        o = obj(e, this)
        lv = o["chain"][level]
        out32(e, pp, create_surface_obj(e, lv["w"], lv["h"], o["fmt"], o["usage"], o["pool"], container=this,
                                        ptr=lv["ptr"], pitch=lv["pitch"]))
    reg_method(T, "GetSurfaceLevel", 2, logged(T, "GetSurfaceLevel", tex_surface_level))

    def touch(e, o):
        """A texture's contents may change: the guest locked one of its levels. Captures re-read only these."""
        o["ver"] = o.get("ver", 0) + 1
        r = rec(e)
        if r._fast:
            r._fast.tex(o["addr"], o["ver"], r.capture.tex_ver.get(o["addr"]) if r.capture else None)

    def tex_lock(e, this, level, plr, prect, flags):
        o = obj(e, this)
        touch(e, o)
        lv = o["chain"][level]
        ptr = lv["ptr"]
        if prect:
            left, top = struct.unpack("<ii", e.rd(prect, 8))
            ptr += top * lv["pitch"] + left * (BPP.get(o["fmt"], 32) // 8)
        e.wr(plr, struct.pack("<II", lv["pitch"], ptr))
    reg_method(T, "LockRect", 4, logged(T, "LockRect", tex_lock))
    reg_method(T, "UnlockRect", 1, logged(T, "UnlockRect"))
    reg_method(T, "AddDirtyRect", 1, logged(T, "AddDirtyRect"))
    reg_method(T, "SetLOD", 1, logged(T, "SetLOD"))
    reg_method(T, "GetLOD", 0, logged(T, "GetLOD"))
    reg_method(T, "PreLoad", 0, logged(T, "PreLoad"))
    reg_method(T, "GetType", 0, logged(T, "GetType", ret=3))
    for nm, np_ in (("GetDevice", 1), ("SetPrivateData", 4), ("GetPrivateData", 3), ("FreePrivateData", 1),
                    ("SetPriority", 1), ("GetPriority", 0)):
        reg_method(T, nm, np_, logged(T, nm))

    S = "IDirect3DSurface8"

    def surf_lock(e, this, plr, prect, flags):
        o = obj(e, this)
        if o.get("container"):
            touch(e, obj(e, o["container"]))
        ptr = o["ptr"]
        if prect:
            left, top = struct.unpack("<ii", e.rd(prect, 8))
            ptr += top * o["pitch"] + left * (BPP.get(o["fmt"], 32) // 8)
        e.wr(plr, struct.pack("<II", o["pitch"], ptr))
    reg_method(S, "LockRect", 3, logged(S, "LockRect", surf_lock))
    reg_method(S, "UnlockRect", 0, logged(S, "UnlockRect"))

    def surf_desc(e, this, p):
        o = obj(e, this)
        e.wr(p, struct.pack("<8I", o["fmt"], 1, o["usage"], o["pool"], o["pitch"] * o["h"], 0, o["w"], o["h"]))
    reg_method(S, "GetDesc", 1, logged(S, "GetDesc", surf_desc))
    for nm, np_ in (("GetDevice", 1), ("SetPrivateData", 4), ("GetPrivateData", 3), ("FreePrivateData", 1),
                    ("GetContainer", 2)):
        reg_method(S, nm, np_, logged(S, nm))

    for iface, rtype in (("IDirect3DVertexBuffer8", 6), ("IDirect3DIndexBuffer8", 7)):
        def buf_lock(e, this, off, size, ppdata, flags):
            e.wr32(ppdata, obj(e, this)["ptr"] + off)

        def buf_desc(e, this, p, _i=iface):
            o = obj(e, this)
            if _i == "IDirect3DVertexBuffer8":
                e.wr(p, struct.pack("<6I", 100, 6, o["usage"], o["pool"], o["length"], o["fvf"]))
            else:
                e.wr(p, struct.pack("<5I", o["fmt"], 7, o["usage"], o["pool"], o["length"]))
        reg_method(iface, "Lock", 4, logged(iface, "Lock", buf_lock))
        reg_method(iface, "Unlock", 0, logged(iface, "Unlock"))
        reg_method(iface, "GetDesc", 1, logged(iface, "GetDesc", buf_desc))
        reg_method(iface, "GetType", 0, logged(iface, "GetType", ret=rtype))
        for nm, np_ in (("GetDevice", 1), ("SetPrivateData", 4), ("GetPrivateData", 3), ("FreePrivateData", 1),
                        ("SetPriority", 1), ("GetPriority", 0), ("PreLoad", 0)):
            reg_method(iface, nm, np_, logged(iface, nm))

    # -------- device: state tracking
    def set_rs(e, this, state, value):
        r = rec(e)
        r.render_states[state][value] += 1
        r.cur_rs[state] = value
        if r.capture:
            r.capture.render_states([(state, value)])
    reg_method(D, "SetRenderState", 2, logged(D, "SetRenderState", set_rs))

    def set_tss(e, this, stage, ty, value):
        r = rec(e)
        r.tss[(stage, ty)][value] += 1
        r.cur_tss[(stage, ty)] = value
        if r.capture:
            r.capture.tss([(stage, ty, value)])
    reg_method(D, "SetTextureStageState", 3, logged(D, "SetTextureStageState", set_tss))

    def set_tex(e, this, stage, tex):
        r = rec(e)
        o = r.objs.get(tex)
        r.bound_tex[stage] = tex
        if o:
            r.sampler_texfmt[(stage, fmt_name(o["fmt"]))] += 1
        if r.capture:
            r.capture.set_texture(stage, tex if (o or {}).get("iface") == "IDirect3DTexture8" else 0)
    reg_method(D, "SetTexture", 2, logged(D, "SetTexture", set_tex))

    IDENTITY = (1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1)

    def set_transform(e, this, state, pm, multiply=False):
        r = rec(e)
        r.transforms[state] += 1
        mat = struct.unpack("<16f", e.rd(pm, 64))
        if multiply:                       # D3D: new = pMatrix x current
            cur = r.cur_xf.get(state, IDENTITY)
            mat = tuple(sum(mat[4 * i + k] * cur[4 * k + j] for k in range(4)) for i in range(4) for j in range(4))
        r.cur_xf[state] = mat
        if r.capture:
            r.capture.transform(state, mat)
    reg_method(D, "SetTransform", 2, logged(D, "SetTransform", set_transform))
    reg_method(D, "MultiplyTransform", 2, logged(D, "MultiplyTransform",
               lambda e, this, state, pm: set_transform(e, this, state, pm, True)))

    def set_light(e, this, idx, p):
        rec(e).lights += 1
    reg_method(D, "SetLight", 2, logged(D, "SetLight", set_light))

    def clear(e, this, count, rects, flags, color, z, stencil):
        r = rec(e)
        r.clears[flags] += 1
        if r.capture:
            rl = [struct.unpack("<4i", e.rd(rects + 16 * i, 16)) for i in range(count)] if rects else []
            r.capture.clear(flags, color, struct.unpack("<f", struct.pack("<I", z))[0], stencil, rl)
    reg_method(D, "Clear", 6, logged(D, "Clear", clear))

    def set_vs(e, this, handle):
        r = rec(e)
        r.cur_vs = handle
        if not (handle & 0x80000000):
            r.fvfs[handle] += 1
    reg_method(D, "SetVertexShader", 1, logged(D, "SetVertexShader", set_vs))

    def create_vs(e, this, decl, func, phandle, usage):
        r = rec(e)
        toks = []
        p = decl
        while len(toks) < 256:
            t = e.rd32(p)
            toks.append(t)
            p += 4
            if t == 0xFFFFFFFF:
                break
        ftoks = []
        if func:
            p = func
            while len(ftoks) < 512:
                t = e.rd32(p)
                ftoks.append(t)
                p += 4
                if t == 0x0000FFFF:
                    break
        handle = 0x80000001 + len(r.vshaders)
        r.vshaders.append("handle 0x%x usage=0x%x declaration=%d tokens, function=%s (version token 0x%x)" % (
            handle, usage, len(toks), ("%d tokens" % len(ftoks)) if func else "none (fixed-function declaration only)",
            ftoks[0] if ftoks else 0) + (" first=%s" % " ".join("%08x" % t for t in ftoks[:12]) if ftoks else ""))
        out32(e, phandle, handle)
    reg_method(D, "CreateVertexShader", 4, logged(D, "CreateVertexShader", create_vs))

    def create_ps(e, this, func, phandle):
        r = rec(e)
        toks = []
        p = func
        while len(toks) < 512:
            t = e.rd32(p)
            toks.append(t)
            p += 4
            if t == 0x0000FFFF:
                break
        handle = 0x80001001 + len(r.pshaders)
        r.pshaders.append("handle 0x%x %d tokens version token 0x%x first=%s" % (
            handle, len(toks), toks[0], " ".join("%08x" % t for t in toks[:12])))
        out32(e, phandle, handle)
    reg_method(D, "CreatePixelShader", 2, logged(D, "CreatePixelShader", create_ps))

    def set_ps(e, this, handle):
        rec(e).cur_ps = handle
    reg_method(D, "SetPixelShader", 1, logged(D, "SetPixelShader", set_ps))

    def set_stream(e, this, n, vb, stride):
        rec(e).streams[n] = (vb, stride)
    reg_method(D, "SetStreamSource", 3, logged(D, "SetStreamSource", set_stream))

    def set_indices(e, this, ib, base):
        rec(e).indices = (ib, base)
    reg_method(D, "SetIndices", 2, logged(D, "SetIndices", set_indices))

    def set_viewport(e, this, p):
        x, y, w, h, mnz, mxz = struct.unpack("<IIIIff", e.rd(p, 24))
        r = rec(e)
        r.viewport = (x, y, w, h, mnz, mxz)
        if r.capture:
            r.capture.viewport(*r.viewport)
    reg_method(D, "SetViewport", 1, logged(D, "SetViewport", set_viewport))

    import d3dcap

    def send_textures(e, r):
        for stage, tex in sorted(r.bound_tex.items()):
            o = r.objs.get(tex)
            if not o or o.get("iface") != "IDirect3DTexture8":
                continue
            if r.capture.tex_ver.get(tex) == o.get("ver", 0):
                continue                          # not locked since it was last sent: skip reading it back
            r.capture.tex_ver[tex] = o.get("ver", 0)
            if r._fast:
                r._fast.tex(tex, o.get("ver", 0), o.get("ver", 0))
            r.capture.texture(tex, o["fmt"], o["w"], o["h"],
                              [(lv["w"], lv["h"], lv["pitch"], e.rd(lv["ptr"], lv["size"])) for lv in o["chain"]])

    def capture_draw(e, prim, count, vdata, stride, idata=None, isize=2, base=0):
        """vdata(first, n) -> vertex bytes; idata: raw index bytes or None. Rebases indices to the vertices sent."""
        r = rec(e)
        fvf = r.cur_vs if not r.cur_vs & 0x80000000 else 0
        send_textures(e, r)
        n = d3dcap.index_count(prim, count)
        if idata is None:
            r.capture.draw(prim, fvf, stride, vdata(base, n), b"", 2)
            return
        fmt = "<%d%s" % (n, "H" if isize == 2 else "I")
        idx = struct.unpack(fmt, idata[:n * isize])
        lo, hi = (min(idx), max(idx)) if idx else (0, -1)
        reb = struct.pack(fmt, *[i - lo for i in idx])
        r.capture.draw(prim, fvf, stride, vdata(base + lo, hi - lo + 1), reb, isize)

    def stream_reader(e, r):
        vb, stride = r.streams.get(0, (0, 0))
        o = r.objs.get(vb, {})
        return (lambda first, n: e.rd(o["ptr"] + first * stride, n * stride)), stride

    def draw_common(e, kind, prim, count):
        r = rec(e)
        r.draws["%s %s" % (kind, PRIM_NAMES.get(prim, prim))] += 1

    def draw_prim(e, this, prim, start, count):
        draw_common(e, "DrawPrimitive", prim, count)
        r = rec(e)
        if r.capture:
            rd, stride = stream_reader(e, r)
            capture_draw(e, prim, count, rd, stride, base=start)
    reg_method(D, "DrawPrimitive", 3, logged(D, "DrawPrimitive", draw_prim))

    def draw_indexed(e, this, prim, mn, nv, si, count):
        draw_common(e, "DrawIndexedPrimitive", prim, count)
        r = rec(e)
        if r.capture:
            rd, stride = stream_reader(e, r)
            ib, base = r.indices
            io = r.objs.get(ib, {})
            isize = 4 if io.get("fmt") == 102 else 2
            n = d3dcap.index_count(prim, count)
            capture_draw(e, prim, count, rd, stride, e.rd(io["ptr"] + si * isize, n * isize), isize, base)
    reg_method(D, "DrawIndexedPrimitive", 5, logged(D, "DrawIndexedPrimitive", draw_indexed))

    def draw_up(e, this, prim, count, data, stride):
        draw_common(e, "DrawPrimitiveUP", prim, count)
        if rec(e).capture:
            capture_draw(e, prim, count, lambda first, n: e.rd(data + first * stride, n * stride), stride)
    reg_method(D, "DrawPrimitiveUP", 4, logged(D, "DrawPrimitiveUP", draw_up))

    def draw_indexed_up(e, this, prim, mn, nv, count, idx, ifmt, data, stride):
        draw_common(e, "DrawIndexedPrimitiveUP", prim, count)
        if rec(e).capture:
            isize = 4 if ifmt == 102 else 2
            capture_draw(e, prim, count, lambda first, n: e.rd(data + first * stride, n * stride), stride,
                         e.rd(idx, d3dcap.index_count(prim, count) * isize), isize)
    reg_method(D, "DrawIndexedPrimitiveUP", 8, logged(D, "DrawIndexedPrimitiveUP", draw_indexed_up))

    # -------- device: queries and cooperative level
    reg_method(D, "TestCooperativeLevel", 0, logged(D, "TestCooperativeLevel"))
    reg_method(D, "GetAvailableTextureMem", 0, logged(D, "GetAvailableTextureMem", ret=256 * 1024 * 1024))

    def dev_caps(e, this, p):
        fill_caps(e, p)
    reg_method(D, "GetDeviceCaps", 1, logged(D, "GetDeviceCaps", dev_caps))

    def dev_display(e, this, p):
        w, h = m.SCREEN
        e.wr(p, struct.pack("<IIII", w, h, 60, 22))
    reg_method(D, "GetDisplayMode", 1, logged(D, "GetDisplayMode", dev_display))

    def dev_creation_params(e, this, p):
        o = obj(e, this)
        e.wr(p, struct.pack("<IIII", 0, 1, o.get("hwnd", 0), 0x40))
    reg_method(D, "GetCreationParameters", 1, logged(D, "GetCreationParameters", dev_creation_params))

    def get_d3d(e, this, pp):
        d3d = obj(e, this)["d3d"]
        e.wr32(d3d + 4, e.rd32(d3d + 4) + 1)
        out32(e, pp, d3d)
    reg_method(D, "GetDirect3D", 1, logged(D, "GetDirect3D", get_d3d))

    def get_backbuffer(e, this, idx, typ, pp):
        o = obj(e, this)
        if "backbuffer" not in o:
            w, h, fmt = o["params"][0], o["params"][1], o["params"][2]
            w, h = (w or m.SCREEN[0]), (h or m.SCREEN[1])
            o["backbuffer"] = create_surface_obj(e, w, h, fmt or 22, usage=1, pool=0)
        out32(e, pp, o["backbuffer"])
    reg_method(D, "GetBackBuffer", 3, logged(D, "GetBackBuffer", get_backbuffer))

    def present(e, this, a, b, c, d):
        r = rec(e)
        if not hasattr(r, "frames"):
            r.frames = 0
        r.frames += 1
        if r.capture:
            r.capture.present()
    reg_method(D, "Present", 4, logged(D, "Present", present))

    def reset(e, this, ppp):
        pp = struct.unpack("<13I", e.rd(ppp, 52))
        rec(e).present_params.append("Reset: BackBuffer %dx%d format=%s windowed=%d" % (pp[0], pp[1], fmt_name(pp[2]), pp[7]))
    reg_method(D, "Reset", 1, logged(D, "Reset", reset))

    # remaining device methods: logged, success
    handled = {k for (d, k) in m.HLE if d == DLL}
    for iface, methods in INTERFACES.items():
        for name, np_ in methods:
            key = "%s::%s" % (iface, name)
            if (DLL, key) not in m.HLE:
                reg_method(iface, name, np_, logged(iface, name))

    # every D3D8 handler is ordinary (no coroutine, no register access, no emu_stop): lifted code calls them
    # without the emulator (mpemu.HLE_DIRECT, runtime.c hle_direct)
    m.HLE_DIRECT.update(k for k in m.HLE if k[0] == DLL)
