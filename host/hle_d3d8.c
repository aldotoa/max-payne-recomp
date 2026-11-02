/* Direct3D 8 for the native host (E6): a port of emu/d3d8.py, the logging Direct3D 8 of a headless run: the COM
 * objects with their vtable layouts, the adapter (caps, modes, format checks), the device and its resources (textures
 * with their level chains, surfaces, vertex and index buffers, whose locks hand out real guest memory), and the device
 * state. The objects live in guest memory as in Python: a 16-byte object (vtable, reference count), and per interface
 * one vtable of stubs named "Interface::Method", made with the interface's first object (so the stubs and the heap
 * addresses come in the emulator's order). As in a native run of the emulator, hle_fast.c serves the hot device calls
 * (render and texture-stage states, textures, streams, indices, buffer locks, draws, the vertex shader, transforms,
 * the viewport, Clear: mphost.c binds them) and owns that state; it knows every object (host_fast_obj), and what it
 * declines comes here. The capture (emu/d3dcap.py's MPD3 records, to a file or to the renderer, host/live.c) is here
 * too; the Recorder's report counters are kept only where a result depends on them. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "host.h"

#define D "D3D8.DLL"
#define H(name) static uint32_t name(CPU *c, const uint32_t *a)
#define UNUSED (void)c, (void)a

#define D3D_OK 0u
#define D3DERR_NOTAVAILABLE 0x8876086Au
#define D3DERR_INVALIDCALL 0x8876086Cu
#define E_NOINTERFACE 0x80004002u
#define ADAPTER_DESCRIPTION "Apple GPU (Metal), Direct3D 8 emulation"
#define XF_STATES 512                   /* hle_fast.c: transforms held in C */

static const uint32_t SCREEN[2] = {HOST_SCREEN_W, HOST_SCREEN_H};

/* ---------------------------------------------------------------- vtable layouts (DirectX 8.0 headers; method,
 * number of parameters without `this`), as emu/d3d8.py INTERFACES */
typedef struct { const char *name; uint8_t nparams; } Meth;
static const Meth IDIRECT3D8[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"RegisterSoftwareDevice", 1}, {"GetAdapterCount", 0},
    {"GetAdapterIdentifier", 3}, {"GetAdapterModeCount", 1}, {"EnumAdapterModes", 3}, {"GetAdapterDisplayMode", 2},
    {"CheckDeviceType", 5}, {"CheckDeviceFormat", 6}, {"CheckDeviceMultiSampleType", 5}, {"CheckDepthStencilMatch", 5},
    {"GetDeviceCaps", 3}, {"GetAdapterMonitor", 1}, {"CreateDevice", 6}, {NULL, 0}};
static const Meth IDIRECT3DDEVICE8[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"TestCooperativeLevel", 0}, {"GetAvailableTextureMem", 0},
    {"ResourceManagerDiscardBytes", 1}, {"GetDirect3D", 1}, {"GetDeviceCaps", 1}, {"GetDisplayMode", 1},
    {"GetCreationParameters", 1}, {"SetCursorProperties", 3}, {"SetCursorPosition", 3}, {"ShowCursor", 1},
    {"CreateAdditionalSwapChain", 2}, {"Reset", 1}, {"Present", 4}, {"GetBackBuffer", 3}, {"GetRasterStatus", 1},
    {"SetGammaRamp", 2}, {"GetGammaRamp", 1}, {"CreateTexture", 7}, {"CreateVolumeTexture", 8}, {"CreateCubeTexture",
    6}, {"CreateVertexBuffer", 5}, {"CreateIndexBuffer", 5}, {"CreateRenderTarget", 6}, {"CreateDepthStencilSurface",
    5}, {"CreateImageSurface", 4}, {"CopyRects", 5}, {"UpdateTexture", 2}, {"GetFrontBuffer", 1}, {"SetRenderTarget",
    2}, {"GetRenderTarget", 1}, {"GetDepthStencilSurface", 1}, {"BeginScene", 0}, {"EndScene", 0}, {"Clear", 6},
    {"SetTransform", 2}, {"GetTransform", 2}, {"MultiplyTransform", 2}, {"SetViewport", 1}, {"GetViewport", 1},
    {"SetMaterial", 1}, {"GetMaterial", 1}, {"SetLight", 2}, {"GetLight", 2}, {"LightEnable", 2}, {"GetLightEnable", 2},
    {"SetClipPlane", 2}, {"GetClipPlane", 2}, {"SetRenderState", 2}, {"GetRenderState", 2}, {"BeginStateBlock", 0},
    {"EndStateBlock", 1}, {"ApplyStateBlock", 1}, {"CaptureStateBlock", 1}, {"DeleteStateBlock", 1},
    {"CreateStateBlock", 2}, {"SetClipStatus", 1}, {"GetClipStatus", 1}, {"GetTexture", 2}, {"SetTexture", 2},
    {"GetTextureStageState", 3}, {"SetTextureStageState", 3}, {"ValidateDevice", 1}, {"GetInfo", 3},
    {"SetPaletteEntries", 2}, {"GetPaletteEntries", 2}, {"SetCurrentTexturePalette", 1}, {"GetCurrentTexturePalette",
    1}, {"DrawPrimitive", 3}, {"DrawIndexedPrimitive", 5}, {"DrawPrimitiveUP", 4}, {"DrawIndexedPrimitiveUP", 8},
    {"ProcessVertices", 5}, {"CreateVertexShader", 4}, {"SetVertexShader", 1}, {"GetVertexShader", 1},
    {"DeleteVertexShader", 1}, {"SetVertexShaderConstant", 3}, {"GetVertexShaderConstant", 3},
    {"GetVertexShaderDeclaration", 3}, {"GetVertexShaderFunction", 3}, {"SetStreamSource", 3}, {"GetStreamSource", 3},
    {"SetIndices", 2}, {"GetIndices", 2}, {"CreatePixelShader", 2}, {"SetPixelShader", 1}, {"GetPixelShader", 1},
    {"DeletePixelShader", 1}, {"SetPixelShaderConstant", 3}, {"GetPixelShaderConstant", 3}, {"GetPixelShaderFunction",
    3}, {"DrawRectPatch", 3}, {"DrawTriPatch", 3}, {"DeletePatch", 1}, {NULL, 0}};
static const Meth IDIRECT3DTEXTURE8[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"GetDevice", 1}, {"SetPrivateData", 4}, {"GetPrivateData",
    3}, {"FreePrivateData", 1}, {"SetPriority", 1}, {"GetPriority", 0}, {"PreLoad", 0}, {"GetType", 0}, {"SetLOD", 1},
    {"GetLOD", 0}, {"GetLevelCount", 0}, {"GetLevelDesc", 2}, {"GetSurfaceLevel", 2}, {"LockRect", 4}, {"UnlockRect",
    1}, {"AddDirtyRect", 1}, {NULL, 0}};
static const Meth IDIRECT3DSURFACE8[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"GetDevice", 1}, {"SetPrivateData", 4}, {"GetPrivateData",
    3}, {"FreePrivateData", 1}, {"GetContainer", 2}, {"GetDesc", 1}, {"LockRect", 3}, {"UnlockRect", 0}, {NULL, 0}};
static const Meth IDIRECT3DVERTEXBUFFER8[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"GetDevice", 1}, {"SetPrivateData", 4}, {"GetPrivateData",
    3}, {"FreePrivateData", 1}, {"SetPriority", 1}, {"GetPriority", 0}, {"PreLoad", 0}, {"GetType", 0}, {"Lock", 4},
    {"Unlock", 0}, {"GetDesc", 1}, {NULL, 0}};
static const Meth IDIRECT3DINDEXBUFFER8[] = {
    {"QueryInterface", 2}, {"AddRef", 0}, {"Release", 0}, {"GetDevice", 1}, {"SetPrivateData", 4}, {"GetPrivateData",
    3}, {"FreePrivateData", 1}, {"SetPriority", 1}, {"GetPriority", 0}, {"PreLoad", 0}, {"GetType", 0}, {"Lock", 4},
    {"Unlock", 0}, {"GetDesc", 1}, {NULL, 0}};

enum { I_D3D8, I_DEVICE8, I_TEXTURE8, I_SURFACE8, I_VB8, I_IB8, NIFACES };
static struct {
    const char *name;
    const Meth *m;
    uint32_t fast_kind;         /* native.HleFast.OBJ_KINDS */
    uint32_t vtable;            /* 0 until the first object */
} g_ifaces[NIFACES] = {
    {"IDirect3D8", IDIRECT3D8, 0, 0},
    {"IDirect3DDevice8", IDIRECT3DDEVICE8, 0, 0},
    {"IDirect3DTexture8", IDIRECT3DTEXTURE8, 1, 0},
    {"IDirect3DSurface8", IDIRECT3DSURFACE8, 0, 0},
    {"IDirect3DVertexBuffer8", IDIRECT3DVERTEXBUFFER8, 2, 0},
    {"IDirect3DIndexBuffer8", IDIRECT3DINDEXBUFFER8, 3, 0},
};

static inline uint32_t r32(uint32_t p) { uint32_t v; memcpy(&v, gptr(p), 4); return v; }
static inline void w32(uint32_t p, uint32_t v) { memcpy(gptr(p), &v, 4); }
static inline void out32(uint32_t p, uint32_t v) { if (p) w32(p, v); }
static inline uint32_t f32bits(float f) { uint32_t v; memcpy(&v, &f, 4); return v; }

/* ---------------------------------------------------------------- formats */
static uint32_t fourcc(const char *s) { return (uint32_t)s[0] | (uint32_t)s[1] << 8 | (uint32_t)s[2] << 16 | (uint32_t)s[3] << 24; }

/* bits per pixel (d3d8.BPP; 32 when unknown) */
static uint32_t bpp(uint32_t f)
{
    switch (f) {
    case 20: return 24;
    case 21: case 22: case 62: case 63: case 64: case 65: case 71: case 75: case 77: case 79: return 32;
    case 23: case 24: case 25: case 26: case 29: case 30: case 51: case 60: case 61: case 70: case 73: case 80:
        return 16;
    case 27: case 28: case 41: case 50: case 52: return 8;
    }
    return 32;
}

/* level_layout: pitch and size of one level */
static void level_layout(uint32_t w, uint32_t h, uint32_t fmt, uint32_t *pitch, uint32_t *size)
{
    uint32_t block = fmt == fourcc("DXT1") ? 8 : (fmt == fourcc("DXT2") || fmt == fourcc("DXT3") ||
                                                 fmt == fourcc("DXT4") || fmt == fourcc("DXT5")) ? 16 : 0;
    if (block) {
        uint32_t bw = (w + 3) / 4 ? (w + 3) / 4 : 1, bh = (h + 3) / 4 ? (h + 3) / 4 : 1;
        *pitch = bw * block;
        *size = bw * bh * block;
        return;
    }
    *pitch = w * (bpp(fmt) / 8);
    *size = *pitch * h;
}

/* ---------------------------------------------------------------- objects */
typedef struct { uint32_t w, h, pitch, size, ptr; } Level;
typedef struct {
    uint32_t addr;
    int iface;
    uint32_t w, h, fmt, usage, pool, ptr, pitch, container, length, fvf, ver;
    Level *chain;
    uint32_t nlevels;
    uint32_t params[13], hwnd, d3d, backbuffer;
    /* a texture in the current capture: the version last sent (has_sent), the CRC of the contents last sent */
    int has_sent, has_crc;
    uint32_t sent_ver, crc;
} Obj;

static Obj **g_obj;                     /* open addressing on the address */
static uint32_t g_obj_mask, g_obj_n;

static uint32_t ohash(uint32_t a) { return (a >> 4) * 0x9E3779B1u; }

static Obj *obj(uint32_t a)
{
    if (!g_obj)
        return NULL;
    for (uint32_t i = ohash(a) & g_obj_mask;; i = (i + 1) & g_obj_mask) {
        if (!g_obj[i])
            return NULL;
        if (g_obj[i]->addr == a)
            return g_obj[i];
    }
}

/* the object a method is called on (Python's obj(e, this)[...] fails on any other) */
static Obj *self(uint32_t a, int iface)
{
    Obj *o = obj(a);
    if (!o || (iface >= 0 && o->iface != iface))
        host_fatal("D3D8: 0x%x is no %s", a, iface >= 0 ? g_ifaces[iface].name : "object");
    return o;
}

static void obj_put(Obj *o)
{
    if (2 * (g_obj_n + 1) > g_obj_mask + 1) {
        uint32_t cap = g_obj ? 2 * (g_obj_mask + 1) : 1024;
        Obj **old = g_obj;
        uint32_t oldcap = g_obj ? g_obj_mask + 1 : 0;
        g_obj = calloc(cap, sizeof *g_obj);
        g_obj_mask = cap - 1;
        for (uint32_t i = 0; i < oldcap; i++)
            if (old[i])
                for (uint32_t j = ohash(old[i]->addr) & g_obj_mask;; j = (j + 1) & g_obj_mask)
                    if (!g_obj[j]) {
                        g_obj[j] = old[i];
                        break;
                    }
        free(old);
    }
    for (uint32_t j = ohash(o->addr) & g_obj_mask;; j = (j + 1) & g_obj_mask)
        if (!g_obj[j]) {
            g_obj[j] = o;
            g_obj_n++;
            return;
        }
}

static uint32_t vtable(int i)
{
    if (!g_ifaces[i].vtable) {
        uint32_t n = 0;
        while (g_ifaces[i].m[n].name)
            n++;
        uint32_t p = host_alloc(4 * n);
        for (uint32_t k = 0; k < n; k++) {
            char name[128];
            snprintf(name, sizeof name, "%s::%s", g_ifaces[i].name, g_ifaces[i].m[k].name);
            w32(p + 4 * k, host_stub_for(D, name));
        }
        g_ifaces[i].vtable = p;
    }
    return g_ifaces[i].vtable;
}

/* new_obj: the object, then (the first time) its vtable; registered with hle_fast.c. The caller fills o. */
static Obj *new_obj(int iface, uint32_t ptr, uint32_t fmt)
{
    uint32_t a = host_alloc(16);
    w32(a, vtable(iface));
    w32(a + 4, 1);
    Obj *o = calloc(1, sizeof *o);
    o->addr = a;
    o->iface = iface;
    o->ptr = ptr;
    o->fmt = fmt;
    obj_put(o);
    host_fast_obj(a, g_ifaces[iface].fast_kind, ptr, fmt);
    return o;
}

static Obj *new_surface(uint32_t w, uint32_t h, uint32_t fmt, uint32_t usage, uint32_t pool, uint32_t container,
                        uint32_t ptr, uint32_t pitch)
{
    if (!ptr) {
        uint32_t size;
        level_layout(w, h, fmt, &pitch, &size);
        ptr = host_alloc(size > 16 ? size : 16);
    }
    Obj *o = new_obj(I_SURFACE8, ptr, fmt);
    o->w = w, o->h = h, o->usage = usage, o->pool = pool, o->pitch = pitch, o->container = container;
    return o;
}

/* touch: a texture's contents may change (one of its levels was locked) */
static void touch(Obj *t)
{
    t->ver++;
    host_fast_tex_sent(t->addr, t->ver, t->sent_ver, t->has_sent);
}

/* ---------------------------------------------------------------- IUnknown, the same for every interface */
H(AddRef)
{
    UNUSED;
    uint32_t n = r32(a[0] + 4) + 1;
    w32(a[0] + 4, n);
    return n;
}

H(Release)
{
    UNUSED;
    uint32_t n = r32(a[0] + 4);
    n = n ? n - 1 : 0;
    w32(a[0] + 4, n);
    return n;
}

H(QueryInterface)
{
    UNUSED;
    out32(a[2], 0);
    return E_NOINTERFACE;
}

H(Ok) { UNUSED; return D3D_OK; }
H(NotAvailable) { UNUSED; return D3DERR_NOTAVAILABLE; }

/* ---------------------------------------------------------------- Direct3DCreate8 and IDirect3D8 */
H(Direct3DCreate8) { UNUSED; return new_obj(I_D3D8, 0, 0)->addr; }

H(GetAdapterCount) { UNUSED; return 1; }
H(GetAdapterMonitor) { UNUSED; return 0x7000; }

/* display_modes: the common modes plus the desktop, sorted (the desktop is the last, 2560x1600) */
static const uint32_t MODES[][2] = {{640, 480}, {800, 600}, {1024, 768}, {1280, 720}, {1280, 1024}, {1600, 1200},
                                    {1920, 1080}, {HOST_SCREEN_W, HOST_SCREEN_H}};
#define NMODES (sizeof MODES / sizeof *MODES)

int host_d3d_mode(unsigned i, uint32_t *w, uint32_t *h)
{
    if (i >= NMODES)
        return 0;
    *w = MODES[i][0];
    *h = MODES[i][1];
    return 1;
}

H(GetAdapterModeCount) { UNUSED; return NMODES; }

H(GetAdapterIdentifier)
{
    UNUSED;
    uint8_t *p = gptr(a[3]);
    memset(p, 0, 1068);
    memcpy(p, "metal-d3d8", 10);
    memcpy(p + 512, ADAPTER_DESCRIPTION, sizeof ADAPTER_DESCRIPTION - 1);
    uint64_t version = 0x0001000100010001ull;
    uint32_t ids[4] = {0x106B, 0x0001, 0, 1};    /* VendorId, DeviceId, SubSysId, Revision */
    memcpy(p + 1024, &version, 8);
    memcpy(p + 1032, ids, 16);
    return D3D_OK;
}

static void put_mode(uint32_t p, uint32_t w, uint32_t h)
{
    uint32_t v[4] = {w, h, 60, 22};             /* X8R8G8B8 at 60 Hz */
    memcpy(gptr(p), v, 16);
}

H(EnumAdapterModes)
{
    UNUSED;
    if (a[2] >= NMODES)
        return D3DERR_INVALIDCALL;
    put_mode(a[3], MODES[a[2]][0], MODES[a[2]][1]);
    return D3D_OK;
}

H(GetAdapterDisplayMode)
{
    UNUSED;
    put_mode(a[2], SCREEN[0], SCREEN[1]);
    return D3D_OK;
}

H(CheckDeviceMultiSampleType) { UNUSED; return a[5] == 0 ? D3D_OK : D3DERR_NOTAVAILABLE; }

/* fill_caps: D3DCAPS8, invented-but-plausible DX8-era values (see emu/d3d8.py) */
static void fill_caps(uint32_t p)
{
    uint32_t k[53] = {0};
    k[0] = 1;                                   /* D3DDEVTYPE_HAL */
    k[2] = 0x20000;                             /* Caps: READ_SCANLINE */
    k[3] = 0x20000000 | 0x80000;                /* Caps2: DYNAMICTEXTURES | CANRENDERWINDOWED */
    k[4] = 0x20 | 0x80;                         /* Caps3 */
    k[5] = 0x1 | 0x80000000u;                   /* PresentationIntervals */
    k[7] = 0x1BBFF0;                            /* DevCaps */
    k[8] = 0x7F0 | 0x1000;                      /* PrimitiveMiscCaps */
    k[9] = 0x7F5FF;                             /* RasterCaps */
    k[10] = 0xFF;                               /* ZCmpCaps */
    k[11] = k[12] = 0x3FFF;                     /* Src/Dest blend caps */
    k[13] = 0xFF;                               /* AlphaCmpCaps */
    k[14] = 0x2 | 0x8 | 0x20 | 0x200 | 0x4000 | 0x80000;   /* ShadeCaps */
    k[15] = 0x1 | 0x2 | 0x4 | 0x8 | 0x40 | 0x80 | 0x100 | 0x400 | 0x800 | 0x4000;   /* TextureCaps */
    k[16] = 0x07030700;                         /* TextureFilterCaps */
    k[19] = 0x1F;                               /* TextureAddressCaps */
    k[21] = 0x7;                                /* LineCaps */
    k[22] = k[23] = 4096;                       /* MaxTextureWidth/Height */
    k[24] = 256, k[25] = 32768, k[26] = 4096, k[27] = 16;
    k[28] = f32bits(1e10f);                     /* MaxVertexW */
    k[29] = f32bits(-8192.0f), k[30] = f32bits(-8192.0f), k[31] = f32bits(8192.0f), k[32] = f32bits(8192.0f);
    k[34] = 0xFF;                               /* StencilCaps */
    k[35] = 0x8 | 0x10000 | 0x8000 | 0x2;       /* FVFCaps */
    k[36] = 0x3FFFFFF;                          /* TextureOpCaps */
    k[37] = 8, k[38] = 8;                       /* MaxTextureBlendStages / MaxSimultaneousTextures */
    k[39] = 0xFF;                               /* VertexProcessingCaps */
    k[40] = 8, k[41] = 6, k[42] = 4, k[43] = 255;
    k[44] = f32bits(64.0f);                     /* MaxPointSize */
    k[45] = 0xFFFFF, k[46] = 0xFFFFF, k[47] = 16, k[48] = 256;
    k[49] = 0xFFFE0101;                         /* VertexShaderVersion 1.1 */
    k[50] = 96;
    k[51] = 0xFFFF0104;                         /* PixelShaderVersion 1.4 */
    k[52] = f32bits(1.0f);
    memcpy(gptr(p), k, sizeof k);
}

H(D3DGetDeviceCaps)
{
    UNUSED;
    fill_caps(a[3]);
    return D3D_OK;
}

H(CreateDevice)
{
    UNUSED;
    uint32_t pp[13];
    memcpy(pp, gptr(a[5]), 52);
    Obj *dev = new_obj(I_DEVICE8, 0, 0);
    dev->d3d = a[0];
    dev->hwnd = a[3];
    memcpy(dev->params, pp, sizeof pp);
    out32(a[6], dev->addr);
    return D3D_OK;
}

/* ---------------------------------------------------------------- device: resources */
H(CreateTexture)
{
    UNUSED;
    uint32_t w = a[1], h = a[2], levels = a[3];
    if (levels == 0)                            /* a full chain: max(w, h).bit_length() */
        for (uint32_t m = w > h ? w : h; m; m >>= 1)
            levels++;
    Level *chain = calloc(levels ? levels : 1, sizeof *chain);
    for (uint32_t i = 0; i < levels; i++) {
        Level *lv = &chain[i];
        lv->w = i < 32 && (w >> i) ? w >> i : 1;
        lv->h = i < 32 && (h >> i) ? h >> i : 1;
        level_layout(lv->w, lv->h, a[5], &lv->pitch, &lv->size);
        lv->ptr = host_alloc(lv->size > 16 ? lv->size : 16);
    }
    Obj *t = new_obj(I_TEXTURE8, 0, a[5]);
    t->w = w, t->h = h, t->usage = a[4], t->pool = a[6], t->chain = chain, t->nlevels = levels;
    out32(a[7], t->addr);
    return D3D_OK;
}

static uint32_t new_buffer(int iface, const uint32_t *a, uint32_t fmt, uint32_t fvf)
{
    uint32_t ptr = host_alloc(a[1] > 16 ? a[1] : 16);
    Obj *b = new_obj(iface, ptr, fmt);
    b->length = a[1], b->usage = a[2], b->fvf = fvf, b->pool = a[4];
    out32(a[5], b->addr);
    return D3D_OK;
}

H(CreateVertexBuffer) { UNUSED; return new_buffer(I_VB8, a, 0, a[3]); }
H(CreateIndexBuffer) { UNUSED; return new_buffer(I_IB8, a, a[3], 0); }

H(CreateRenderTarget)
{
    UNUSED;
    out32(a[6], new_surface(a[1], a[2], a[3], 1, 0, 0, 0, 0)->addr);
    return D3D_OK;
}

H(CreateDepthStencilSurface)
{
    UNUSED;
    out32(a[5], new_surface(a[1], a[2], a[3], 2, 0, 0, 0, 0)->addr);
    return D3D_OK;
}

H(CreateImageSurface)
{
    UNUSED;
    out32(a[4], new_surface(a[1], a[2], a[3], 0, 2, 0, 0, 0)->addr);
    return D3D_OK;
}

/* ---------------------------------------------------------------- textures, surfaces, buffers */
static Level *level(Obj *t, uint32_t i)
{
    if (i >= t->nlevels)
        host_fatal("D3D8: level %u of the %u-level texture 0x%x", i, t->nlevels, t->addr);
    return &t->chain[i];
}

H(GetLevelCount) { UNUSED; return self(a[0], I_TEXTURE8)->nlevels; }

H(GetLevelDesc)
{
    UNUSED;
    Obj *t = self(a[0], I_TEXTURE8);
    Level *lv = level(t, a[1]);
    uint32_t v[8] = {t->fmt, 3, t->usage, t->pool, lv->size, 0, lv->w, lv->h};
    memcpy(gptr(a[2]), v, 32);
    return D3D_OK;
}

H(GetSurfaceLevel)
{
    UNUSED;
    Obj *t = self(a[0], I_TEXTURE8);
    Level *lv = level(t, a[1]);
    out32(a[2], new_surface(lv->w, lv->h, t->fmt, t->usage, t->pool, t->addr, lv->ptr, lv->pitch)->addr);
    return D3D_OK;
}

static void put_locked(uint32_t plr, uint32_t pitch, uint32_t ptr, uint32_t prect, uint32_t fmt)
{
    if (prect) {
        int32_t lt[2];
        memcpy(lt, gptr(prect), 8);
        ptr += (uint32_t)(lt[1] * (int32_t)pitch + lt[0] * (int32_t)(bpp(fmt) / 8));
    }
    uint32_t v[2] = {pitch, ptr};
    memcpy(gptr(plr), v, 8);
}

H(TexLockRect)
{
    UNUSED;
    Obj *t = self(a[0], I_TEXTURE8);
    touch(t);
    Level *lv = level(t, a[1]);
    put_locked(a[2], lv->pitch, lv->ptr, a[3], t->fmt);
    return D3D_OK;
}

H(TexGetType) { UNUSED; return 3; }

H(SurfLockRect)
{
    UNUSED;
    Obj *s = self(a[0], I_SURFACE8);
    if (s->container)
        touch(self(s->container, -1));
    put_locked(a[1], s->pitch, s->ptr, a[2], s->fmt);
    return D3D_OK;
}

H(SurfGetDesc)
{
    UNUSED;
    Obj *s = self(a[0], I_SURFACE8);
    uint32_t v[8] = {s->fmt, 1, s->usage, s->pool, s->pitch * s->h, 0, s->w, s->h};
    memcpy(gptr(a[1]), v, 32);
    return D3D_OK;
}

/* Lock(offset, size, ppbData, flags); hle_fast.c serves it unless the object is unknown */
H(BufLock)
{
    UNUSED;
    w32(a[3], self(a[0], -1)->ptr + a[1]);
    return D3D_OK;
}

H(VbGetDesc)
{
    UNUSED;
    Obj *b = self(a[0], I_VB8);
    uint32_t v[6] = {100, 6, b->usage, b->pool, b->length, b->fvf};
    memcpy(gptr(a[1]), v, 24);
    return D3D_OK;
}

H(IbGetDesc)
{
    UNUSED;
    Obj *b = self(a[0], I_IB8);
    uint32_t v[5] = {b->fmt, 7, b->usage, b->pool, b->length};
    memcpy(gptr(a[1]), v, 20);
    return D3D_OK;
}

H(VbGetType) { UNUSED; return 6; }
H(IbGetType) { UNUSED; return 7; }

/* ---------------------------------------------------------------- the capture (d3d8.py start_capture, the Recorder's
 * capture paths and d3dcap.Writer): the MPD3 records of what the game draws, to a sink (a file, or the renderer). C's
 * handlers submit their own records to the same sink (CAP_SINK) and decline a draw whose textures must be sent first. */
#define CAP_NONE 0
#define CAP_SINK 1
enum { MPD3_TEXTURE = 1, MPD3_RENDERSTATE, MPD3_TSS, MPD3_SETTEXTURE, MPD3_VIEWPORT, MPD3_CLEAR, MPD3_DRAW, MPD3_PRESENT,
       MPD3_TRANSFORM };

static struct {
    HostSink sink;
    void *ctx;                                  /* NULL sink: not capturing */
    uint32_t counts[10];
} g_cap;

/* the Recorder's state that C does not hold: keys out of its ranges (Python's _FastMap / _FastXf extras), in the
 * order they were first set */
static struct { uint32_t key, key2, v; } g_xrs[64], g_xtss[64], g_xtex[64];
static uint32_t g_nxrs, g_nxtss, g_nxtex;
static struct { uint32_t state; float m[16]; } g_xxf[64];
static uint32_t g_nxxf;

static void extra_put(void *arr, uint32_t *n, uint32_t key, uint32_t key2, uint32_t v)
{
    struct { uint32_t key, key2, v; } *x = arr;
    for (uint32_t i = 0; i < *n; i++)
        if (x[i].key == key && x[i].key2 == key2) {
            x[i].v = v;
            return;
        }
    if (*n == 64)
        host_fatal("D3D8: too many states out of hle_fast.c's range");
    x[*n].key = key, x[*n].key2 = key2, x[*n].v = v;
    (*n)++;
}

static float *xf_extra(uint32_t state, int make)
{
    for (uint32_t i = 0; i < g_nxxf; i++)
        if (g_xxf[i].state == state)
            return g_xxf[i].m;
    if (!make)
        return NULL;
    if (g_nxxf == 64)
        host_fatal("D3D8: too many transforms out of hle_fast.c's range");
    g_xxf[g_nxxf].state = state;
    return g_xxf[g_nxxf++].m;
}

static void rec(uint32_t type, const void *p, uint32_t len)
{
    if (!g_cap.sink)
        return;
    g_cap.counts[type < 10 ? type : 0]++;
    g_cap.sink(g_cap.ctx, type, p, len);
}

/* the sink C's handlers call: counted like the host's own records */
static int cap_sink(void *ctx, uint32_t type, const void *p, uint32_t len)
{
    (void)ctx;
    rec(type, p, len);
    return 0;
}

static uint8_t *g_rb;
static size_t g_rb_cap;

static uint8_t *rbuf(size_t n)
{
    if (n > g_rb_cap) {
        g_rb_cap = 2 * n;
        g_rb = realloc(g_rb, g_rb_cap);
    }
    return g_rb;
}

static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

static void rec_rs(uint32_t n, const uint32_t (*pairs)[2])
{
    if (!n)
        return;
    uint8_t *p = rbuf(4 + 8 * (size_t)n);
    put32(p, n);
    memcpy(p + 4, pairs, 8 * (size_t)n);
    rec(MPD3_RENDERSTATE, p, 4 + 8 * n);
}

static void rec_tss(uint32_t n, const uint32_t (*t)[3])
{
    if (!n)
        return;
    uint8_t *p = rbuf(4 + 12 * (size_t)n);
    put32(p, n);
    memcpy(p + 4, t, 12 * (size_t)n);
    rec(MPD3_TSS, p, 4 + 12 * n);
}

static void rec_settex(uint32_t stage, uint32_t tex)
{
    uint32_t v[2] = {stage, tex};
    rec(MPD3_SETTEXTURE, v, 8);
}

static void rec_xf(uint32_t state, const float *m)
{
    uint8_t p[68];
    put32(p, state);
    memcpy(p + 4, m, 64);
    rec(MPD3_TRANSFORM, p, 68);
}

static int cmp_pair(const void *x, const void *y)
{
    const uint32_t *a = x, *b = y;
    return a[0] != b[0] ? (a[0] < b[0] ? -1 : 1) : 0;
}

static int cmp_triple(const void *x, const void *y)
{
    const uint32_t *a = x, *b = y;
    if (a[0] != b[0])
        return a[0] < b[0] ? -1 : 1;
    return a[1] != b[1] ? (a[1] < b[1] ? -1 : 1) : 0;
}

void host_d3d_backbuffer(uint32_t *w, uint32_t *h)
{
    *w = *h = 0;
    for (uint32_t i = 0; g_obj && i <= g_obj_mask; i++)
        if (g_obj[i] && g_obj[i]->iface == I_DEVICE8) {
            *w = g_obj[i]->params[0], *h = g_obj[i]->params[1];
            return;
        }
}

/* start_capture: the current state first (render states, texture-stage states, the viewport, the transforms, the bound
 * textures, each sorted), then C submits too; every texture counts as not sent (a new Writer) */
void host_d3d_start_capture(HostSink sink, void *ctx)
{
    memset(g_cap.counts, 0, sizeof g_cap.counts);
    g_cap.sink = sink, g_cap.ctx = ctx;
    uint32_t v, v2;
    static uint32_t pairs[256 + 64][2], trip[256 + 64][3];
    uint32_t n = 0;
    for (uint32_t k = 0; k < 256; k++)
        if (host_fast_get(0, k, 0, &v, &v2))
            pairs[n][0] = k, pairs[n][1] = v, n++;
    for (uint32_t i = 0; i < g_nxrs; i++)
        pairs[n][0] = g_xrs[i].key, pairs[n][1] = g_xrs[i].v, n++;
    qsort(pairs, n, sizeof *pairs, cmp_pair);
    rec_rs(n, pairs);
    n = 0;
    for (uint32_t st = 0; st < 8; st++)
        for (uint32_t ty = 0; ty < 32; ty++)
            if (host_fast_get(1, st, ty, &v, &v2))
                trip[n][0] = st, trip[n][1] = ty, trip[n][2] = v, n++;
    for (uint32_t i = 0; i < g_nxtss; i++)
        trip[n][0] = g_xtss[i].key, trip[n][1] = g_xtss[i].key2, trip[n][2] = g_xtss[i].v, n++;
    qsort(trip, n, sizeof *trip, cmp_triple);
    rec_tss(n, trip);
    uint32_t vp[6];
    if (host_fast_blob(1, 0, 0, vp))
        rec(MPD3_VIEWPORT, vp, 24);
    float m[16];
    for (uint32_t k = 0; k < XF_STATES; k++)
        if (host_fast_blob(0, k, 0, m))
            rec_xf(k, m);
    n = 0;
    for (uint32_t i = 0; i < g_nxxf; i++)           /* (sorted after the in-range ones: larger states) */
        pairs[n][0] = g_xxf[i].state, pairs[n][1] = i, n++;
    qsort(pairs, n, sizeof *pairs, cmp_pair);
    for (uint32_t i = 0; i < n; i++)
        rec_xf(pairs[i][0], g_xxf[pairs[i][1]].m);
    n = 0;
    for (uint32_t st = 0; st < 8; st++)
        if (host_fast_get(2, st, 0, &v, &v2))
            pairs[n][0] = st, pairs[n][1] = v, n++;
    for (uint32_t i = 0; i < g_nxtex; i++)
        pairs[n][0] = g_xtex[i].key, pairs[n][1] = g_xtex[i].v, n++;
    qsort(pairs, n, sizeof *pairs, cmp_pair);
    for (uint32_t i = 0; i < n; i++)
        rec_settex(pairs[i][0], pairs[i][1]);
    for (uint32_t i = 0; g_obj && i <= g_obj_mask; i++)
        if (g_obj[i])
            g_obj[i]->has_sent = 0, g_obj[i]->has_crc = 0;
    host_fast_capture(CAP_SINK, (void *)cap_sink, NULL, NULL, 1);
}

/* stop_capture; the record counts (by MPD3 type) of the capture that ends */
const uint32_t *host_d3d_stop_capture(void)
{
    g_cap.sink = NULL;
    host_fast_capture(CAP_NONE, NULL, NULL, NULL, 0);
    return g_cap.counts;
}

/* send_textures: every bound texture locked since it was last sent; the TEXTURE record only when its contents
 * changed (d3dcap.Writer.texture, a CRC of the level headers and bytes) */
static void send_textures(void)
{
    uint32_t stage[8 + 64], tex[8 + 64], n = 0, v, v2;
    for (uint32_t st = 0; st < 8; st++)
        if (host_fast_get(2, st, 0, &v, &v2))
            stage[n] = st, tex[n] = v, n++;
    for (uint32_t i = 0; i < g_nxtex; i++)
        stage[n] = g_xtex[i].key, tex[n] = g_xtex[i].v, n++;
    for (uint32_t i = 1; i < n; i++)                /* sorted by stage */
        for (uint32_t j = i; j > 0 && stage[j - 1] > stage[j]; j--) {
            uint32_t s = stage[j], t = tex[j];
            stage[j] = stage[j - 1], tex[j] = tex[j - 1], stage[j - 1] = s, tex[j - 1] = t;
        }
    for (uint32_t i = 0; i < n; i++) {
        Obj *t = obj(tex[i]);
        if (!t || t->iface != I_TEXTURE8 || (t->has_sent && t->sent_ver == t->ver))
            continue;
        t->has_sent = 1, t->sent_ver = t->ver;
        host_fast_tex_sent(t->addr, t->ver, t->ver, 1);
        size_t len = 20;
        for (uint32_t k = 0; k < t->nlevels; k++)
            len += 16 + t->chain[k].size;
        uint8_t *p = rbuf(len);
        uint32_t hd[5] = {t->addr, t->fmt, t->w, t->h, t->nlevels};
        memcpy(p, hd, 20);
        size_t o = 20;
        for (uint32_t k = 0; k < t->nlevels; k++) {
            Level *lv = &t->chain[k];
            uint32_t lh[4] = {lv->w, lv->h, lv->pitch, lv->size};
            memcpy(p + o, lh, 16);
            memcpy(p + o + 16, gptr(lv->ptr), lv->size);
            o += 16 + lv->size;
        }
        uint32_t crc = (uint32_t)crc32(0, p + 20, (uInt)(len - 20));
        if (t->has_crc && t->crc == crc)
            continue;
        t->has_crc = 1, t->crc = crc;
        rec(MPD3_TEXTURE, p, (uint32_t)len);
    }
}

static uint32_t index_count(uint32_t prim, uint32_t count)
{
    switch (prim) {
    case 1: return count;
    case 2: return 2 * count;
    case 3: return count + 1;
    case 4: return 3 * count;
    case 5: case 6: return count + 2;
    }
    return 0;
}

/* capture_draw: the vertices from vbase (+ first * stride), the indices (idx: n x isize bytes, or none) rebased so 0
 * is the first vertex sent */
static void capture_draw(uint32_t prim, uint32_t count, uint32_t vbase, uint32_t stride, uint32_t base,
                         const uint8_t *idx, uint32_t isize)
{
    uint32_t vs, v2;
    host_fast_get(5, 0, 0, &vs, &v2);
    uint32_t fvf = (vs & 0x80000000u) ? 0 : vs;
    send_textures();
    uint32_t n = index_count(prim, count), first = base, nv = n;
    uint32_t lo = 0, hi = 0;
    if (idx) {
        lo = UINT32_MAX;
        for (uint32_t i = 0; i < n; i++) {
            uint32_t x = 0;
            memcpy(&x, idx + isize * i, isize);
            lo = x < lo ? x : lo;
            hi = x > hi ? x : hi;
        }
        if (!n)
            lo = 0;
        first = base + lo, nv = n ? hi - lo + 1 : 0;
    }
    size_t vlen = (size_t)nv * stride, ilen = idx ? (size_t)n * isize : 0;
    uint8_t *p = rbuf(24 + vlen + ilen);
    uint32_t hd[6] = {prim, fvf, stride, stride ? (uint32_t)(vlen / stride) : 0, idx && n ? n : 0, idx ? isize : 2};
    memcpy(p, hd, 24);
    if (vlen)
        memcpy(p + 24, gptr(vbase + first * stride), vlen);
    for (uint32_t i = 0; idx && i < n; i++) {
        uint32_t x = 0;
        memcpy(&x, idx + isize * i, isize);
        x -= lo;
        memcpy(p + 24 + vlen + isize * i, &x, isize);
    }
    rec(MPD3_DRAW, p, (uint32_t)(24 + vlen + ilen));
}

/* stream_reader: stream 0's vertex buffer and stride */
static void stream0(uint32_t *ptr, uint32_t *stride)
{
    uint32_t vb = 0, st = 0;
    host_fast_get(3, 0, 0, &vb, &st);
    *stride = st;
    Obj *o = obj(vb);
    if (!o)
        host_fatal("D3D8: draw from stream 0 = 0x%x, which is no vertex buffer", vb);
    *ptr = o->ptr;
}

/* ---------------------------------------------------------------- device: state, and what hle_fast.c declined (keys
 * out of its range, kept here as Python keeps them in its dicts; a draw whose textures must be sent first) */
H(SetRenderState)
{
    UNUSED;
    if (a[1] >= 256 || !host_fast_set(0, a[1], 0, a[2]))
        extra_put(g_xrs, &g_nxrs, a[1], 0, a[2]);
    uint32_t pr[1][2] = {{a[1], a[2]}};
    rec_rs(1, pr);
    return D3D_OK;
}

H(SetTextureStageState)
{
    UNUSED;
    if (a[1] >= 8 || a[2] >= 32 || !host_fast_set(1, a[1], a[2], a[3]))
        extra_put(g_xtss, &g_nxtss, a[1], a[2], a[3]);
    uint32_t t[1][3] = {{a[1], a[2], a[3]}};
    rec_tss(1, t);
    return D3D_OK;
}

H(SetTexture)
{
    UNUSED;
    if (a[1] >= 8 || !host_fast_set(2, a[1], 0, a[2]))
        extra_put(g_xtex, &g_nxtex, a[1], 0, a[2]);
    Obj *o = obj(a[2]);
    rec_settex(a[1], o && o->iface == I_TEXTURE8 ? a[2] : 0);
    return D3D_OK;
}

H(SetTransform)
{
    UNUSED;
    if (a[1] < XF_STATES)
        host_fast_blob(0, a[1], 1, gptr(a[2]));
    else
        memcpy(xf_extra(a[1], 1), gptr(a[2]), 64);
    rec_xf(a[1], (const float *)gptr(a[2]));
    return D3D_OK;
}

/* new = pMatrix x current, in doubles from the f32 values, stored as f32 (as the Python store into C does) */
H(MultiplyTransform)
{
    UNUSED;
    float m[16], cur[16], out[16];
    memcpy(m, gptr(a[2]), 64);
    float *x = a[1] >= XF_STATES ? xf_extra(a[1], 0) : NULL;
    if (x)
        memcpy(cur, x, 64);
    else if (a[1] >= XF_STATES || !host_fast_blob(0, a[1], 0, cur))
        for (int i = 0; i < 16; i++)
            cur[i] = (i % 5) == 0;              /* identity */
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            double s = 0;
            for (int k = 0; k < 4; k++)
                s += (double)m[4 * i + k] * (double)cur[4 * k + j];
            out[4 * i + j] = (float)s;
        }
    if (a[1] < XF_STATES)
        host_fast_blob(0, a[1], 1, out);
    else
        memcpy(xf_extra(a[1], 1), out, 64);
    rec_xf(a[1], out);
    return D3D_OK;
}

H(SetViewport)
{
    UNUSED;
    host_fast_blob(1, 0, 1, gptr(a[1]));
    rec(MPD3_VIEWPORT, gptr(a[1]), 24);
    return D3D_OK;
}

/* Clear(count, rects, flags, color, z, stencil) */
H(Clear)
{
    UNUSED;
    uint32_t n = a[2] ? a[1] : 0;
    uint8_t *p = rbuf(20 + 16 * (size_t)n);
    uint32_t hd[5] = {a[3], a[4], a[5], a[6], n};
    memcpy(p, hd, 20);
    if (n)
        memcpy(p + 20, gptr(a[2]), 16 * (size_t)n);
    rec(MPD3_CLEAR, p, 20 + 16 * n);
    return D3D_OK;
}

/* DrawPrimitive(prim, start, count) */
H(DrawPrimitive)
{
    UNUSED;
    if (g_cap.sink) {
        uint32_t ptr, stride;
        stream0(&ptr, &stride);
        capture_draw(a[1], a[3], ptr, stride, a[2], NULL, 2);
    }
    return D3D_OK;
}

/* DrawIndexedPrimitive(prim, min, nverts, start index, count) */
H(DrawIndexedPrimitive)
{
    UNUSED;
    if (g_cap.sink) {
        uint32_t ptr, stride, ib, base;
        stream0(&ptr, &stride);
        host_fast_get(4, 0, 0, &ib, &base);
        Obj *io = obj(ib);
        if (!io)
            host_fatal("D3D8: DrawIndexedPrimitive with indices 0x%x, which is no index buffer", ib);
        uint32_t isize = io->fmt == 102 ? 4 : 2;
        capture_draw(a[1], a[5], ptr, stride, base, gptr(io->ptr + a[4] * isize), isize);
    }
    return D3D_OK;
}

/* DrawPrimitiveUP(prim, count, data, stride) */
H(DrawPrimitiveUP)
{
    UNUSED;
    if (g_cap.sink)
        capture_draw(a[1], a[2], a[3], a[4], 0, NULL, 2);
    return D3D_OK;
}

/* DrawIndexedPrimitiveUP(prim, min, nverts, count, indices, index format, data, stride) */
H(DrawIndexedPrimitiveUP)
{
    UNUSED;
    if (g_cap.sink) {
        uint32_t isize = a[6] == 102 ? 4 : 2;
        capture_draw(a[1], a[4], a[7], a[8], 0, gptr(a[5]), isize);
    }
    return D3D_OK;
}

static uint32_t g_frames;

H(Present)
{
    UNUSED;
    g_frames++;
    rec(MPD3_PRESENT, NULL, 0);
    return D3D_OK;
}

static uint32_t g_vshaders, g_pshaders, g_cur_ps;

H(CreateVertexShader)
{
    UNUSED;
    out32(a[3], 0x80000001u + g_vshaders++);
    return D3D_OK;
}

H(CreatePixelShader)
{
    UNUSED;
    out32(a[2], 0x80001001u + g_pshaders++);
    return D3D_OK;
}

H(SetPixelShader)
{
    UNUSED;
    g_cur_ps = a[1];
    return D3D_OK;
}

/* ---------------------------------------------------------------- device: queries */
H(GetAvailableTextureMem) { UNUSED; return 256u * 1024 * 1024; }

H(DevGetDeviceCaps)
{
    UNUSED;
    fill_caps(a[1]);
    return D3D_OK;
}

H(GetDisplayMode)
{
    UNUSED;
    put_mode(a[1], SCREEN[0], SCREEN[1]);
    return D3D_OK;
}

H(GetCreationParameters)
{
    UNUSED;
    uint32_t v[4] = {0, 1, self(a[0], I_DEVICE8)->hwnd, 0x40};
    memcpy(gptr(a[1]), v, 16);
    return D3D_OK;
}

H(GetDirect3D)
{
    UNUSED;
    uint32_t d3d = self(a[0], I_DEVICE8)->d3d;
    w32(d3d + 4, r32(d3d + 4) + 1);
    out32(a[1], d3d);
    return D3D_OK;
}

H(GetBackBuffer)
{
    UNUSED;
    Obj *dev = self(a[0], I_DEVICE8);
    if (!dev->backbuffer) {
        uint32_t w = dev->params[0] ? dev->params[0] : SCREEN[0], h = dev->params[1] ? dev->params[1] : SCREEN[1];
        dev->backbuffer = new_surface(w, h, dev->params[2] ? dev->params[2] : 22, 1, 0, 0, 0, 0)->addr;
    }
    out32(a[3], dev->backbuffer);
    return D3D_OK;
}

/* GetFrontBuffer(pDestSurface): the screenshot behind a save's thumbnail (taken as the in-game menu opens, into an
 * A8R8G8B8 image surface of the display mode's size). The live renderer's last frame, scaled to the surface if the
 * sizes differ; headless (no renderer) the surface is left as it is. */
H(GetFrontBuffer)
{
    UNUSED;
    Obj *s = self(a[1], I_SURFACE8);
    uint32_t fw, fh;
    const uint8_t *f = host_live_read_frame(&fw, &fh);
    if (!f || (s->fmt != 21 && s->fmt != 22))
        return D3D_OK;
    for (uint32_t y = 0; y < s->h; y++) {
        const uint8_t *src = f + (size_t)((uint64_t)y * fh / s->h) * fw * 4;
        uint8_t *dst = gptr(s->ptr + y * s->pitch);
        for (uint32_t x = 0; x < s->w; x++, dst += 4) {
            const uint8_t *p = src + (size_t)((uint64_t)x * fw / s->w) * 4;
            dst[0] = p[2], dst[1] = p[1], dst[2] = p[0], dst[3] = 255;
        }
    }
    return D3D_OK;
}

/* ---------------------------------------------------------------- the table: every method of every interface,
 * D3D_OK unless it has a handler below (as Python's "remaining methods: logged, success") */
static const struct { int iface; const char *name; HleFn fn; } SPECIAL[] = {
    {I_D3D8, "RegisterSoftwareDevice", NotAvailable}, {I_D3D8, "GetAdapterCount", GetAdapterCount},
    {I_D3D8, "GetAdapterIdentifier", GetAdapterIdentifier}, {I_D3D8, "GetAdapterModeCount", GetAdapterModeCount},
    {I_D3D8, "EnumAdapterModes", EnumAdapterModes}, {I_D3D8, "GetAdapterDisplayMode", GetAdapterDisplayMode},
    {I_D3D8, "CheckDeviceMultiSampleType", CheckDeviceMultiSampleType}, {I_D3D8, "GetDeviceCaps", D3DGetDeviceCaps},
    {I_D3D8, "GetAdapterMonitor", GetAdapterMonitor}, {I_D3D8, "CreateDevice", CreateDevice},
    {I_DEVICE8, "CreateTexture", CreateTexture}, {I_DEVICE8, "CreateVertexBuffer", CreateVertexBuffer},
    {I_DEVICE8, "CreateIndexBuffer", CreateIndexBuffer}, {I_DEVICE8, "CreateRenderTarget", CreateRenderTarget},
    {I_DEVICE8, "CreateDepthStencilSurface", CreateDepthStencilSurface},
    {I_DEVICE8, "CreateImageSurface", CreateImageSurface}, {I_DEVICE8, "CreateVolumeTexture", NotAvailable},
    {I_DEVICE8, "CreateCubeTexture", NotAvailable},
    {I_DEVICE8, "SetTransform", SetTransform}, {I_DEVICE8, "MultiplyTransform", MultiplyTransform},
    {I_DEVICE8, "SetViewport", SetViewport}, {I_DEVICE8, "SetRenderState", SetRenderState},
    {I_DEVICE8, "SetTextureStageState", SetTextureStageState}, {I_DEVICE8, "SetTexture", SetTexture},
    {I_DEVICE8, "Clear", Clear}, {I_DEVICE8, "DrawPrimitive", DrawPrimitive},
    {I_DEVICE8, "DrawIndexedPrimitive", DrawIndexedPrimitive}, {I_DEVICE8, "DrawPrimitiveUP", DrawPrimitiveUP},
    {I_DEVICE8, "DrawIndexedPrimitiveUP", DrawIndexedPrimitiveUP}, {I_DEVICE8, "Present", Present}, {I_DEVICE8, "CreateVertexShader", CreateVertexShader},
    {I_DEVICE8, "CreatePixelShader", CreatePixelShader}, {I_DEVICE8, "SetPixelShader", SetPixelShader},
    {I_DEVICE8, "GetAvailableTextureMem", GetAvailableTextureMem}, {I_DEVICE8, "GetDeviceCaps", DevGetDeviceCaps},
    {I_DEVICE8, "GetDisplayMode", GetDisplayMode}, {I_DEVICE8, "GetCreationParameters", GetCreationParameters},
    {I_DEVICE8, "GetDirect3D", GetDirect3D}, {I_DEVICE8, "GetBackBuffer", GetBackBuffer},
    {I_DEVICE8, "GetFrontBuffer", GetFrontBuffer},
    {I_TEXTURE8, "GetLevelCount", GetLevelCount}, {I_TEXTURE8, "GetLevelDesc", GetLevelDesc},
    {I_TEXTURE8, "GetSurfaceLevel", GetSurfaceLevel}, {I_TEXTURE8, "LockRect", TexLockRect},
    {I_TEXTURE8, "GetType", TexGetType},
    {I_SURFACE8, "LockRect", SurfLockRect}, {I_SURFACE8, "GetDesc", SurfGetDesc},
    {I_VB8, "Lock", BufLock}, {I_VB8, "GetDesc", VbGetDesc}, {I_VB8, "GetType", VbGetType},
    {I_IB8, "Lock", BufLock}, {I_IB8, "GetDesc", IbGetDesc}, {I_IB8, "GetType", IbGetType},
};

static char g_names[200][64];
HleDef hle_d3d8[200];

__attribute__((constructor)) static void build_table(void)
{
    int n = 0;
    hle_d3d8[n++] = (HleDef){D, "Direct3DCreate8", 1, STDCALL, Direct3DCreate8};
    for (int i = 0; i < NIFACES; i++)
        for (const Meth *m = g_ifaces[i].m; m->name; m++) {
            HleFn fn = Ok;
            if (!strcmp(m->name, "QueryInterface"))
                fn = QueryInterface;
            else if (!strcmp(m->name, "AddRef"))
                fn = AddRef;
            else if (!strcmp(m->name, "Release"))
                fn = Release;
            for (size_t s = 0; s < sizeof SPECIAL / sizeof *SPECIAL; s++)
                if (SPECIAL[s].iface == i && !strcmp(SPECIAL[s].name, m->name))
                    fn = SPECIAL[s].fn;
            snprintf(g_names[n], sizeof g_names[n], "%s::%s", g_ifaces[i].name, m->name);
            hle_d3d8[n] = (HleDef){D, g_names[n], (uint8_t)(1 + m->nparams), STDCALL, fn};
            n++;
        }
    hle_d3d8[n] = (HleDef){NULL, NULL, 0, 0, NULL};
}
