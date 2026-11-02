// libmprender: the MPD3 command stream (emu/d3dcap.py) rendered with Metal. See mprender.h for the API and the
// supported Direct3D 8 subset. Objective-C with ARC; shaders are compiled from source at startup, so no offline
// Metal toolchain is needed.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#import <AppKit/NSScreen.h>
#include <mach/mach_time.h>
#include <os/lock.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mprender.h"

static char g_error[512];
static void set_error(NSString *s) { strlcpy(g_error, s.UTF8String ?: "?", sizeof g_error); }
const char *mpr_last_error(void) { return g_error; }

// ------------------------------------------------------------------ shaders
// Uniform layouts must match the MSL structs below (all 4-byte scalars; float4 members first, 16-byte aligned).
typedef struct {
    float m[16];                    // World x View x Projection, D3D row-major = MSL column-major transpose
    float vp[4];                    // D3D viewport X, Y, W, H
    float minz, maxz, width, height;
    uint32_t stride, diffuse, specular, ntex;
    uint32_t tex[8];
    uint32_t xyz, pad[3];           // 1: untransformed (XYZ) vertices
} VSU;
typedef struct { uint32_t cop, ca1, ca2, ca0, aop, aa1, aa2, aa0, tci, result, hastex, pad; } StageU;
typedef struct { float tfactor[4]; float fogcolor[4]; uint32_t fog, atest, afunc, aref; StageU st[8]; } FSU;
typedef struct { float rect[4]; float color[4]; float z, pad[3]; } ClearU;

static NSString *const kShaders = @R"MSL(
#include <metal_stdlib>
using namespace metal;
struct VSU { float4x4 m; float4 vp; float minz, maxz, width, height; uint stride, diffuse, specular, ntex; uint tex[8];
             uint xyz, pad0, pad1, pad2; };
struct StageU { uint cop, ca1, ca2, ca0, aop, aa1, aa2, aa0, tci, result, hastex, pad; };
struct FSU { float4 tfactor; float4 fogcolor; uint fog, atest, afunc, aref; StageU st[8]; };
struct ClearU { float4 rect; float4 color; float z; float3 pad; };
struct V2F {
    float4 pos [[position]];
    float4 dif; float4 spe;
    float2 t0; float2 t1; float2 t2; float2 t3; float2 t4; float2 t5; float2 t6; float2 t7;
};

static float4 argb(uint c) {
    return float4(float((c >> 16) & 255u), float((c >> 8) & 255u), float(c & 255u), float(c >> 24)) / 255.0;
}

// D3D pre-transformed vertex: x, y in pixels (pixel centres at integers), z in [0,1], rhw = 1/w.
// Untransformed vertex: clip = (x, y, z, 1) x World x View x Projection, then D3D's viewport mapping
// (NDC -1 -> pixel centre X) gives the same screen-space x, y, z and w = clip w.
vertex V2F vs_main(device const uint *vb [[buffer(0)]], constant VSU &u [[buffer(1)]], uint vid [[vertex_id]]) {
    device const uint *v = vb + vid * u.stride;
    float x = as_type<float>(v[0]), y = as_type<float>(v[1]), z = as_type<float>(v[2]), w;
    if (u.xyz != 0u) {
        float4 c = u.m * float4(x, y, z, 1.0);
        w = c.w;
        float iw = 1.0 / c.w;
        x = u.vp.x + (1.0 + c.x * iw) * u.vp.z * 0.5;
        y = u.vp.y + (1.0 - c.y * iw) * u.vp.w * 0.5;
        z = u.minz + c.z * iw * (u.maxz - u.minz);
    } else {
        float rhw = as_type<float>(v[3]);
        w = (rhw > 0.0 && isfinite(1.0 / rhw)) ? 1.0 / rhw : 1.0;
    }
    float nx = (x + 0.5) / u.width * 2.0 - 1.0;          // Metal pixel centres are at +0.5
    float ny = 1.0 - (y + 0.5) / u.height * 2.0;
    V2F o;
    o.pos = float4(nx * w, ny * w, z * w, w);
    o.dif = u.diffuse != 0xFFFFFFFFu ? argb(v[u.diffuse]) : float4(1.0);
    o.spe = u.specular != 0xFFFFFFFFu ? argb(v[u.specular]) : float4(0.0, 0.0, 0.0, 1.0);
    float2 t[8];
    for (uint i = 0; i < 8; i++)
        t[i] = i < u.ntex ? float2(as_type<float>(v[u.tex[i]]), as_type<float>(v[u.tex[i] + 1])) : float2(0.0);
    o.t0 = t[0]; o.t1 = t[1]; o.t2 = t[2]; o.t3 = t[3]; o.t4 = t[4]; o.t5 = t[5]; o.t6 = t[6]; o.t7 = t[7];
    return o;
}

static float4 sel_arg(uint a, float4 dif, float4 cur, float4 tx, float4 tf, float4 spe, float4 temp) {
    float4 s;
    switch (a & 15u) {
        case 0: s = dif; break;  case 1: s = cur; break;  case 2: s = tx; break;
        case 3: s = tf; break;   case 4: s = spe; break;  case 5: s = temp; break;
        default: s = cur; break;
    }
    if (a & 0x20u) s = float4(s.a);
    if (a & 0x10u) s = 1.0 - s;
    return s;
}

static float4 tex_op(uint op, float4 a1, float4 a2, float4 a0, float4 dif, float4 tx, float4 cur, float4 tf) {
    switch (op) {
        case 2: return a1;
        case 3: return a2;
        case 4: return a1 * a2;
        case 5: return saturate(a1 * a2 * 2.0);
        case 6: return saturate(a1 * a2 * 4.0);
        case 7: return saturate(a1 + a2);
        case 8: return saturate(a1 + a2 - 0.5);
        case 9: return saturate((a1 + a2 - 0.5) * 2.0);
        case 10: return saturate(a1 - a2);
        case 11: return saturate(a1 + a2 - a1 * a2);
        case 12: return mix(a2, a1, dif.a);
        case 13: return mix(a2, a1, tx.a);
        case 14: return mix(a2, a1, tf.a);
        case 15: return saturate(a1 + a2 * (1.0 - tx.a));
        case 16: return mix(a2, a1, cur.a);
        case 24: return float4(saturate(dot(a1.rgb - 0.5, a2.rgb - 0.5) * 4.0));
        case 25: return saturate(a0 + a1 * a2);
        case 26: return a0 * a1 + (1.0 - a0) * a2;
        default: return a1;
    }
}

static bool cmp(uint f, float a, float b) {
    switch (f) {
        case 1: return false;    case 2: return a < b;   case 3: return a == b;  case 4: return a <= b;
        case 5: return a > b;    case 6: return a != b;  case 7: return a >= b;  default: return true;
    }
}

fragment float4 fs_main(V2F in [[stage_in]], constant FSU &u [[buffer(0)]],
                        array<texture2d<float>, 8> tex [[texture(0)]], array<sampler, 8> smp [[sampler(0)]]) {
    float2 tc[8] = { in.t0, in.t1, in.t2, in.t3, in.t4, in.t5, in.t6, in.t7 };
    float4 dif = in.dif, spe = in.spe, cur = in.dif, temp = float4(0.0), tf = u.tfactor;
    for (uint s = 0; s < 8; s++) {
        StageU st = u.st[s];
        if (st.cop == 1u) break;
        float4 tx = st.hastex ? tex[s].sample(smp[s], tc[st.tci & 7u]) : float4(0.0, 0.0, 0.0, 1.0);
        float4 c = tex_op(st.cop, sel_arg(st.ca1, dif, cur, tx, tf, spe, temp), sel_arg(st.ca2, dif, cur, tx, tf, spe, temp),
                          sel_arg(st.ca0, dif, cur, tx, tf, spe, temp), dif, tx, cur, tf);
        float a = st.aop == 1u ? cur.a :
                  tex_op(st.aop, sel_arg(st.aa1, dif, cur, tx, tf, spe, temp), sel_arg(st.aa2, dif, cur, tx, tf, spe, temp),
                         sel_arg(st.aa0, dif, cur, tx, tf, spe, temp), dif, tx, cur, tf).a;
        float4 res = float4(c.rgb, a);
        if (st.result == 5u) temp = res; else cur = res;
    }
    if (u.fog != 0u) cur.rgb = mix(u.fogcolor.rgb, cur.rgb, spe.a);
    if (u.atest != 0u && !cmp(u.afunc, round(saturate(cur.a) * 255.0), float(u.aref & 255u))) discard_fragment();
    return saturate(cur);
}

// Profiling variants (MPR_PROFILE=flatfs / tex1): the vertex colour only; stage 0's texture times the vertex colour.
fragment float4 fs_flat(V2F in [[stage_in]]) { return saturate(in.dif); }
fragment float4 fs_tex1(V2F in [[stage_in]], texture2d<float> t0 [[texture(0)]], sampler s0 [[sampler(0)]]) {
    return saturate(t0.sample(s0, in.t0) * in.dif);
}

// Clears: a full-target triangle limited by the scissor rectangle.
struct ClearOut { float4 pos [[position]]; };
vertex ClearOut clear_vs(constant ClearU &u [[buffer(0)]], uint vid [[vertex_id]]) {
    float2 p = float2((vid << 1) & 2u, vid & 2u) * 2.0 - 1.0;
    ClearOut o; o.pos = float4(p, u.z, 1.0); return o;
}
fragment float4 clear_fs(constant ClearU &u [[buffer(0)]]) { return u.color; }
)MSL";

// ------------------------------------------------------------------ renderer state
struct mpr_renderer {
    void *impl;   // MPRImpl, retained via CFBridgingRetain
};

@interface MPRImpl : NSObject {
@public
    id<MTLDevice> dev;
    id<MTLCommandQueue> queue;
    id<MTLLibrary> lib;
    id<MTLTexture> color, depth, white, black;
    uint32_t width, height, frames;
    uint32_t rs[256];
    uint32_t tss[8][32];
    uint32_t bound[8];
    float viewport[6];
    float world[16], view[16], proj[16];
    NSMutableDictionary<NSNumber *, id<MTLTexture>> *textures;
    NSMutableDictionary<NSNumber *, id<MTLRenderPipelineState>> *pipelines;
    NSMutableDictionary<NSNumber *, id<MTLDepthStencilState>> *depthStates;
    NSMutableDictionary<NSNumber *, id<MTLSamplerState>> *samplers;
    NSMutableOrderedSet<NSString *> *notes;
    NSString *notesText;
    id<MTLCommandBuffer> cmd;
    id<MTLRenderCommandEncoder> enc;
    NSMutableArray<id<MTLBuffer>> *arena;   // this frame's upload buffers: arenas[slot]
    NSUInteger arenaIndex, arenaOffset;
    // Frames in flight: PRESENT commits the frame without waiting for the GPU; the next frame writes its uploads into
    // the next of MPR_INFLIGHT arenas, after the frame that last used it has completed (inflight semaphore; command
    // buffers on one queue complete in order). MPR_SYNC=1 in the environment waits for every frame instead (the old
    // behaviour, for comparisons).
    NSMutableArray<NSMutableArray<id<MTLBuffer>> *> *arenas;
    NSUInteger slot;
    dispatch_semaphore_t inflight;
    BOOL sync;
    uint64_t waitTicks, drawableTicks, presentTicks;
    uint32_t resizes;                                   // times present_to_layer set the layer's drawableSize   // mach ticks: GPU wait in PRESENT, nextDrawable, whole present_to_layer
    struct GpuStats *gpu;                               // GPU time per command buffer (completed handlers)
    // MPR_PROFILE (read at create, comma-separated): flatfs / tex1 replace the fragment shader, tiny scissors every
    // draw to one pixel, noblend turns blending off, split gives every draw and clear its own render pass with GPU
    // timestamps at the vertex and fragment stage boundaries (and waits for the GPU at every PRESENT).
    NSString *fsName;
    BOOL tiny, noblend, split;
    id<MTLCounterSampleBuffer> samples;
    NSMutableData *passes;                              // PassInfo per split pass this frame
    NSMutableData *passSums;                            // PassSum per pass index, summed over profiled frames
    uint32_t profFrames;
    MTLTimestamp cpu0, gpu0;                            // timestamp correlation for counter values
    NSString *profText;
    FILE *frameLog;                                     // MPR_FRAME_LOG: one line per frame event (see mprender.h)
    double lastPresentEnd;                              // CACurrentMediaTime at the end of the last present_to_layer
}
@end
@implementation MPRImpl
@end

#define MPR_INFLIGHT 3

// GPU time per command buffer, recorded by completed handlers (Metal's thread) and read by mpr_gpu_timing.
#define GPU_BUCKETS 400                                 // 0.25 ms each
typedef struct GpuStats {
    os_unfair_lock lock;
    uint64_t frames, blits, pending;
    double frameSum, frameMax, blitSum, first, last;    // seconds on the GPU clock (CFTimeInterval)
    uint32_t hist[GPU_BUCKETS];
} GpuStats;

static void gpu_record(GpuStats *g, id<MTLCommandBuffer> cb, int blit) {
    double s = cb.GPUStartTime, e = cb.GPUEndTime, d = e - s;
    os_unfair_lock_lock(&g->lock);
    if (s > 0 && e >= s) {
        if (blit) { g->blits++; g->blitSum += d; }
        else {
            g->frames++; g->frameSum += d;
            if (d > g->frameMax) g->frameMax = d;
            g->hist[MIN((NSUInteger)(d * 4000), (NSUInteger)GPU_BUCKETS - 1)]++;
        }
        if (g->first == 0 || s < g->first) g->first = s;
        if (e > g->last) g->last = e;
    }
    g->pending--;
    os_unfair_lock_unlock(&g->lock);
}

static void gpu_watch(GpuStats *g, id<MTLCommandBuffer> cb, int blit) {
    os_unfair_lock_lock(&g->lock);
    g->pending++;
    os_unfair_lock_unlock(&g->lock);
    [cb addCompletedHandler:^(id<MTLCommandBuffer> c) { gpu_record(g, c, blit); }];
}

typedef struct { uint32_t kind, prim, fvf, nv, ni, blend, src, dst, atest, stages, tex0w, tex0h, scw, sch, zfunc, zwrite; } PassInfo;
typedef struct { PassInfo info; double vs, fs; } PassSum;   // seconds, summed over profFrames

static double ticks_s(uint64_t t) {
    static mach_timebase_info_data_t tb;
    if (!tb.denom) mach_timebase_info(&tb);
    return (double)t * tb.numer / tb.denom / 1e9;
}

static void note(MPRImpl *m, NSString *s) { [m->notes addObject:s]; }

static void reset_state(MPRImpl *m) {
    memset(m->rs, 0, sizeof m->rs);
    // D3D8 defaults (with an auto depth buffer: ZENABLE = TRUE)
    m->rs[7] = 1; m->rs[8] = 3; m->rs[9] = 2; m->rs[14] = 1; m->rs[19] = 2; m->rs[20] = 1; m->rs[22] = 3;
    m->rs[23] = 4; m->rs[25] = 8; m->rs[60] = 0xFFFFFFFF; m->rs[137] = 1; m->rs[168] = 0xF; m->rs[171] = 1;
    for (int s = 0; s < 8; s++) {
        memset(m->tss[s], 0, sizeof m->tss[s]);
        m->tss[s][1] = s == 0 ? 4 : 1; m->tss[s][2] = 2; m->tss[s][3] = 1;
        m->tss[s][4] = s == 0 ? 2 : 1; m->tss[s][5] = 2; m->tss[s][6] = 1; m->tss[s][11] = s;
        m->tss[s][13] = m->tss[s][14] = 1; m->tss[s][16] = m->tss[s][17] = 1; m->tss[s][26] = m->tss[s][27] = 1;
        m->tss[s][28] = 1; m->tss[s][21] = 1;
        m->bound[s] = 0;
    }
    m->viewport[0] = m->viewport[1] = 0; m->viewport[2] = m->width; m->viewport[3] = m->height;
    m->viewport[4] = 0; m->viewport[5] = 1;
    static const float I[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
    memcpy(m->world, I, sizeof I); memcpy(m->view, I, sizeof I); memcpy(m->proj, I, sizeof I);
}

static void matmul(const float *a, const float *b, float *out) {   // row-major 4x4: out = a x b
    float t[16];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            t[i * 4 + j] = a[i * 4] * b[j] + a[i * 4 + 1] * b[4 + j] + a[i * 4 + 2] * b[8 + j] + a[i * 4 + 3] * b[12 + j];
    memcpy(out, t, sizeof t);
}

static id<MTLTexture> solid_texture(MPRImpl *m, uint32_t bgra) {
    MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                                                                 width:1 height:1 mipmapped:NO];
    id<MTLTexture> t = [m->dev newTextureWithDescriptor:d];
    [t replaceRegion:MTLRegionMake2D(0, 0, 1, 1) mipmapLevel:0 withBytes:&bgra bytesPerRow:4];
    return t;
}

mpr_renderer *mpr_create(uint32_t width, uint32_t height) {
    @autoreleasepool {
        if (!width || !height) { set_error(@"zero-sized back buffer"); return NULL; }
        MPRImpl *m = [MPRImpl new];
        m->dev = MTLCreateSystemDefaultDevice();
        if (!m->dev) { set_error(@"no Metal device"); return NULL; }
        m->queue = [m->dev newCommandQueue];
        NSError *err = nil;
        MTLCompileOptions *opt = [MTLCompileOptions new];
        m->lib = [m->dev newLibraryWithSource:kShaders options:opt error:&err];
        if (!m->lib) { set_error([NSString stringWithFormat:@"shader compile failed: %@", err]); return NULL; }
        m->width = width; m->height = height;
        MTLTextureDescriptor *cd = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                                                                      width:width height:height mipmapped:NO];
        cd.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
        cd.storageMode = MTLStorageModePrivate;
        m->color = [m->dev newTextureWithDescriptor:cd];
        MTLTextureDescriptor *dd = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatDepth32Float
                                                                                      width:width height:height mipmapped:NO];
        dd.usage = MTLTextureUsageRenderTarget;
        dd.storageMode = MTLStorageModePrivate;
        m->depth = [m->dev newTextureWithDescriptor:dd];
        m->white = solid_texture(m, 0xFFFFFFFF);
        m->black = solid_texture(m, 0xFF000000);
        m->textures = [NSMutableDictionary new];
        m->pipelines = [NSMutableDictionary new];
        m->depthStates = [NSMutableDictionary new];
        m->samplers = [NSMutableDictionary new];
        m->notes = [NSMutableOrderedSet new];
        m->arenas = [NSMutableArray new];
        for (int i = 0; i < MPR_INFLIGHT; i++) [m->arenas addObject:[NSMutableArray new]];
        m->arena = m->arenas[0];
        // MPR_INFLIGHT - 1 free arenas (frame 0 holds arena 0). Created at 0 and raised: libdispatch aborts when a
        // semaphore is freed below its creation value, and one arena is always held.
        m->inflight = dispatch_semaphore_create(0);
        for (int i = 1; i < MPR_INFLIGHT; i++) dispatch_semaphore_signal(m->inflight);
        const char *sync = getenv("MPR_SYNC");
        m->sync = sync && *sync && strcmp(sync, "0");
        const char *fl = getenv("MPR_FRAME_LOG");
        if (fl && *fl) {
            m->frameLog = fopen(fl, "w");
            if (m->frameLog) { setvbuf(m->frameLog, NULL, _IOLBF, 0); fprintf(m->frameLog, "# times in ms on the CACurrentMediaTime clock\n"); }
        }
        m->gpu = calloc(1, sizeof *m->gpu);
        m->gpu->lock = OS_UNFAIR_LOCK_INIT;
        m->fsName = @"fs_main";
        NSString *prof = @(getenv("MPR_PROFILE") ?: "");
        for (NSString *o in [prof componentsSeparatedByString:@","]) {
            if ([o isEqual:@"flatfs"]) m->fsName = @"fs_flat";
            else if ([o isEqual:@"tex1"]) m->fsName = @"fs_tex1";
            else if ([o isEqual:@"tiny"]) m->tiny = YES;
            else if ([o isEqual:@"noblend"]) m->noblend = YES;
            else if ([o isEqual:@"split"]) m->split = YES;
            else if (o.length) { set_error([NSString stringWithFormat:@"unknown MPR_PROFILE option %@", o]); return NULL; }
        }
        if (m->split) {
            id<MTLCounterSet> ts = nil;
            for (id<MTLCounterSet> cs in m->dev.counterSets) if ([cs.name isEqual:MTLCommonCounterSetTimestamp]) ts = cs;
            if (!ts || ![m->dev supportsCounterSampling:MTLCounterSamplingPointAtStageBoundary]) {
                set_error(@"MPR_PROFILE=split: no stage-boundary timestamps on this GPU"); return NULL;
            }
            MTLCounterSampleBufferDescriptor *sd = [MTLCounterSampleBufferDescriptor new];
            sd.counterSet = ts;
            sd.storageMode = MTLStorageModeShared;
            sd.sampleCount = 4 * 1024;                     // the most a sample buffer may hold (32 KB)
            m->samples = [m->dev newCounterSampleBufferWithDescriptor:sd error:&err];
            if (!m->samples) { set_error([NSString stringWithFormat:@"counter sample buffer: %@", err]); return NULL; }
            m->passes = [NSMutableData new];
            m->passSums = [NSMutableData new];
            m->sync = YES;
            [m->dev sampleTimestamps:&m->cpu0 gpuTimestamp:&m->gpu0];
        }
        reset_state(m);
        // initial contents: black with alpha 1 (X8R8G8B8 reads alpha as 1), depth 1
        MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
        rp.colorAttachments[0].texture = m->color;
        rp.colorAttachments[0].loadAction = MTLLoadActionClear;
        rp.colorAttachments[0].clearColor = MTLClearColorMake(0, 0, 0, 1);
        rp.colorAttachments[0].storeAction = MTLStoreActionStore;
        rp.depthAttachment.texture = m->depth;
        rp.depthAttachment.loadAction = MTLLoadActionClear;
        rp.depthAttachment.clearDepth = 1.0;
        rp.depthAttachment.storeAction = MTLStoreActionStore;
        id<MTLCommandBuffer> cb = [m->queue commandBuffer];
        [[cb renderCommandEncoderWithDescriptor:rp] endEncoding];
        [cb commit];
        mpr_renderer *r = calloc(1, sizeof *r);
        r->impl = (void *)CFBridgingRetain(m);
        return r;
    }
}

void mpr_destroy(mpr_renderer *r) {
    if (!r) return;
    MPRImpl *m = CFBridgingRelease(r->impl);
    if (m->enc) [m->enc endEncoding];
    if (m->cmd) [m->cmd commit];
    id<MTLCommandBuffer> last = [m->queue commandBuffer];   // completes after every frame still in flight
    [last commit];
    [last waitUntilCompleted];
    while (m->gpu->pending) usleep(100);                 // the handlers hold m->gpu
    free(m->gpu);
    if (m->frameLog) fclose(m->frameLog);
    free(r);
}

static MPRImpl *impl(const mpr_renderer *r) { return (__bridge MPRImpl *)r->impl; }
uint32_t mpr_frame_count(const mpr_renderer *r) { return impl(r)->frames; }

const char *mpr_notes(const mpr_renderer *r) {
    MPRImpl *m = impl(r);
    m->notesText = [m->notes.array componentsJoinedByString:@"\n"];
    return m->notesText.UTF8String;
}

// ------------------------------------------------------------------ uploads
static id<MTLBuffer> arena_alloc(MPRImpl *m, const void *bytes, NSUInteger len, NSUInteger *offset) {
    const NSUInteger chunk = 4u << 20;
    if (len > chunk / 2) {                               // big upload: its own buffer
        *offset = 0;
        id<MTLBuffer> b = [m->dev newBufferWithBytes:bytes length:len options:MTLResourceStorageModeShared];
        [m->arena insertObject:b atIndex:m->arena.count];   // kept alive until the frame is done
        return b;
    }
    for (;;) {
        if (m->arenaIndex >= m->arena.count)
            [m->arena addObject:[m->dev newBufferWithLength:chunk options:MTLResourceStorageModeShared]];
        id<MTLBuffer> b = m->arena[m->arenaIndex];
        NSUInteger off = (m->arenaOffset + 255) & ~(NSUInteger)255;
        if (b.length == chunk && off + len <= chunk) {
            memcpy((char *)b.contents + off, bytes, len);
            m->arenaOffset = off + len;
            *offset = off;
            return b;
        }
        m->arenaIndex++;
        m->arenaOffset = 0;
    }
}

static uint8_t expand(uint32_t v, int bits) { return (uint8_t)((v * 255u + ((1u << bits) - 1) / 2) / ((1u << bits) - 1)); }

// One D3D surface level -> BGRA8 (B, G, R, A bytes). Returns NO for unsupported formats.
static BOOL to_bgra(uint32_t fmt, uint32_t w, uint32_t h, uint32_t pitch, const uint8_t *src, uint8_t *dst) {
    for (uint32_t y = 0; y < h; y++) {
        const uint8_t *row = src + (size_t)y * pitch;
        uint8_t *o = dst + (size_t)y * w * 4;
        for (uint32_t x = 0; x < w; x++, o += 4) {
            uint32_t r, g, b, a = 255;
            switch (fmt) {
                case 21: case 22: { const uint8_t *p = row + x * 4; b = p[0]; g = p[1]; r = p[2]; a = fmt == 21 ? p[3] : 255; break; }
                case 20: { const uint8_t *p = row + x * 3; b = p[0]; g = p[1]; r = p[2]; break; }
                case 23: { uint32_t v = row[x * 2] | (row[x * 2 + 1] << 8); r = expand(v >> 11, 5); g = expand((v >> 5) & 63, 6); b = expand(v & 31, 5); break; }
                case 24: case 25: { uint32_t v = row[x * 2] | (row[x * 2 + 1] << 8); r = expand((v >> 10) & 31, 5); g = expand((v >> 5) & 31, 5); b = expand(v & 31, 5); a = fmt == 25 ? ((v >> 15) ? 255 : 0) : 255; break; }
                case 26: case 30: { uint32_t v = row[x * 2] | (row[x * 2 + 1] << 8); r = ((v >> 8) & 15) * 17; g = ((v >> 4) & 15) * 17; b = (v & 15) * 17; a = fmt == 26 ? (v >> 12) * 17 : 255; break; }
                case 28: r = g = b = 0; a = row[x]; break;
                case 50: r = g = b = row[x]; break;
                case 51: r = g = b = row[x * 2]; a = row[x * 2 + 1]; break;
                default: return NO;
            }
            o[0] = (uint8_t)b; o[1] = (uint8_t)g; o[2] = (uint8_t)r; o[3] = (uint8_t)a;
        }
    }
    return YES;
}

static int rd_u32(const uint8_t *p, uint32_t len, uint32_t off, uint32_t *v) {
    if (off + 4 > len) return -1;
    memcpy(v, p + off, 4);
    return 0;
}

static int on_texture(MPRImpl *m, const uint8_t *p, uint32_t len) {
    uint32_t hdr[5];
    if (len < 20) { set_error(@"short TEXTURE"); return -1; }
    memcpy(hdr, p, 20);
    uint32_t tid = hdr[0], fmt = hdr[1], w = hdr[2], h = hdr[3], nlev = hdr[4];
    if (!w || !h || !nlev || nlev > 16) { set_error(@"bad TEXTURE header"); return -1; }
    MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                                                                 width:w height:h mipmapped:nlev > 1];
    d.mipmapLevelCount = nlev;
    id<MTLTexture> t = [m->dev newTextureWithDescriptor:d];
    uint32_t off = 20;
    NSMutableData *tmp = [NSMutableData new];
    for (uint32_t i = 0; i < nlev; i++) {
        uint32_t lv[4];
        if (off + 16 > len) { set_error(@"short TEXTURE level"); return -1; }
        memcpy(lv, p + off, 16);
        off += 16;
        if (off + lv[3] > len || (uint64_t)lv[2] * lv[1] > lv[3] + (uint64_t)lv[2]) { set_error(@"TEXTURE level overruns"); return -1; }
        tmp.length = (NSUInteger)lv[0] * lv[1] * 4;
        if (!to_bgra(fmt, lv[0], lv[1], lv[2], p + off, tmp.mutableBytes)) {
            note(m, [NSString stringWithFormat:@"texture format %u not supported (texture drawn as black)", fmt]);
            [m->textures removeObjectForKey:@(tid)];
            return 0;
        }
        [t replaceRegion:MTLRegionMake2D(0, 0, lv[0], lv[1]) mipmapLevel:i withBytes:tmp.bytes bytesPerRow:lv[0] * 4];
        off += lv[3];
    }
    m->textures[@(tid)] = t;
    return 0;
}

// ------------------------------------------------------------------ cached state objects
static MTLBlendFactor blend_factor(uint32_t f) {
    switch (f) {
        case 1: return MTLBlendFactorZero;                case 2: return MTLBlendFactorOne;
        case 3: return MTLBlendFactorSourceColor;         case 4: return MTLBlendFactorOneMinusSourceColor;
        case 5: return MTLBlendFactorSourceAlpha;         case 6: return MTLBlendFactorOneMinusSourceAlpha;
        case 7: return MTLBlendFactorDestinationAlpha;    case 8: return MTLBlendFactorOneMinusDestinationAlpha;
        case 9: return MTLBlendFactorDestinationColor;    case 10: return MTLBlendFactorOneMinusDestinationColor;
        case 11: return MTLBlendFactorSourceAlphaSaturated;
        default: return MTLBlendFactorOne;
    }
}

static MTLBlendOperation blend_op(uint32_t o) {
    switch (o) {
        case 2: return MTLBlendOperationSubtract;  case 3: return MTLBlendOperationReverseSubtract;
        case 4: return MTLBlendOperationMin;       case 5: return MTLBlendOperationMax;
        default: return MTLBlendOperationAdd;
    }
}

// kind 0: draw pipeline; 1: clear pipeline. Alpha is never written (X8R8G8B8 back buffer).
static id<MTLRenderPipelineState> pipeline(MPRImpl *m, int kind, BOOL blend, uint32_t src, uint32_t dst, uint32_t op, uint32_t mask) {
    uint32_t key = (uint32_t)kind | (blend ? 2u : 0u) | ((src & 15) << 2) | ((dst & 15) << 6) | ((op & 7) << 10) | ((mask & 15) << 13);
    id<MTLRenderPipelineState> ps = m->pipelines[@(key)];
    if (ps) return ps;
    MTLRenderPipelineDescriptor *d = [MTLRenderPipelineDescriptor new];
    d.vertexFunction = [m->lib newFunctionWithName:kind ? @"clear_vs" : @"vs_main"];
    d.fragmentFunction = [m->lib newFunctionWithName:kind ? @"clear_fs" : m->fsName];
    d.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
    d.depthAttachmentPixelFormat = MTLPixelFormatDepth32Float;
    MTLColorWriteMask wm = 0;                        // D3DCOLORWRITEENABLE: 1 R, 2 G, 4 B (alpha never)
    if (mask & 1) wm |= MTLColorWriteMaskRed;
    if (mask & 2) wm |= MTLColorWriteMaskGreen;
    if (mask & 4) wm |= MTLColorWriteMaskBlue;
    d.colorAttachments[0].writeMask = wm;
    if (blend) {
        d.colorAttachments[0].blendingEnabled = YES;
        d.colorAttachments[0].sourceRGBBlendFactor = blend_factor(src);
        d.colorAttachments[0].destinationRGBBlendFactor = blend_factor(dst);
        d.colorAttachments[0].rgbBlendOperation = blend_op(op);
        d.colorAttachments[0].sourceAlphaBlendFactor = MTLBlendFactorOne;
        d.colorAttachments[0].destinationAlphaBlendFactor = MTLBlendFactorZero;
    }
    NSError *err = nil;
    ps = [m->dev newRenderPipelineStateWithDescriptor:d error:&err];
    if (!ps) { set_error([NSString stringWithFormat:@"pipeline: %@", err]); return nil; }
    m->pipelines[@(key)] = ps;
    return ps;
}

static id<MTLDepthStencilState> depth_state(MPRImpl *m, BOOL test, BOOL write, uint32_t func) {
    uint32_t key = (test ? 1u : 0u) | (write ? 2u : 0u) | ((func & 15) << 2);
    id<MTLDepthStencilState> s = m->depthStates[@(key)];
    if (s) return s;
    MTLDepthStencilDescriptor *d = [MTLDepthStencilDescriptor new];
    // D3DCMP_NEVER..ALWAYS (1..8) are MTLCompareFunctionNever..Always (0..7) in the same order
    d.depthCompareFunction = test ? (MTLCompareFunction)((func >= 1 && func <= 8) ? func - 1 : 7) : MTLCompareFunctionAlways;
    d.depthWriteEnabled = test && write;           // D3D: no depth writes while ZENABLE is FALSE
    s = [m->dev newDepthStencilStateWithDescriptor:d];
    m->depthStates[@(key)] = s;
    return s;
}

static MTLSamplerAddressMode address_mode(uint32_t a) {
    switch (a) {
        case 2: return MTLSamplerAddressModeMirrorRepeat;  case 3: return MTLSamplerAddressModeClampToEdge;
        case 4: return MTLSamplerAddressModeClampToBorderColor; case 5: return MTLSamplerAddressModeMirrorClampToEdge;
        default: return MTLSamplerAddressModeRepeat;
    }
}

static id<MTLSamplerState> sampler(MPRImpl *m, int stage) {
    uint32_t *t = m->tss[stage];
    uint32_t mag = t[16], min = t[17], mip = t[18], au = t[13], av = t[14], an = t[21];
    uint32_t key = (mag & 7) | ((min & 7) << 3) | ((mip & 3) << 6) | ((au & 7) << 8) | ((av & 7) << 11) | ((MIN(an, 16u) & 31) << 14);
    id<MTLSamplerState> s = m->samplers[@(key)];
    if (s) return s;
    MTLSamplerDescriptor *d = [MTLSamplerDescriptor new];
    d.magFilter = mag >= 2 ? MTLSamplerMinMagFilterLinear : MTLSamplerMinMagFilterNearest;
    d.minFilter = min >= 2 ? MTLSamplerMinMagFilterLinear : MTLSamplerMinMagFilterNearest;
    d.mipFilter = mip == 0 ? MTLSamplerMipFilterNotMipmapped : mip == 1 ? MTLSamplerMipFilterNearest : MTLSamplerMipFilterLinear;
    d.sAddressMode = address_mode(au);
    d.tAddressMode = address_mode(av);
    if (min == 3 || mag == 3) d.maxAnisotropy = MAX(1u, MIN(an, 16u));
    s = [m->dev newSamplerStateWithDescriptor:d];
    m->samplers[@(key)] = s;
    return s;
}

// ------------------------------------------------------------------ encoding
// MPR_PROFILE=split: end the current pass and start one for this draw or clear, with timestamps at its stage boundaries.
static void split_pass(MPRImpl *m, const PassInfo *pi) {
    if (!m->split || m->passes.length / sizeof(PassInfo) >= 1024) return;   // out of samples: the rest share the last pass
    if (m->enc) { [m->enc endEncoding]; m->enc = nil; }
    [m->passes appendBytes:pi length:sizeof *pi];
}

static id<MTLRenderCommandEncoder> encoder(MPRImpl *m) {
    if (m->enc) return m->enc;
    if (!m->cmd) m->cmd = [m->queue commandBuffer];
    MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
    if (m->split && m->passes.length) {
        NSUInteger i = m->passes.length / sizeof(PassInfo) - 1;
        MTLRenderPassSampleBufferAttachmentDescriptor *sa = rp.sampleBufferAttachments[0];
        sa.sampleBuffer = m->samples;
        sa.startOfVertexSampleIndex = 4 * i; sa.endOfVertexSampleIndex = 4 * i + 1;
        sa.startOfFragmentSampleIndex = 4 * i + 2; sa.endOfFragmentSampleIndex = 4 * i + 3;
    }
    rp.colorAttachments[0].texture = m->color;
    rp.colorAttachments[0].loadAction = MTLLoadActionLoad;
    rp.colorAttachments[0].storeAction = MTLStoreActionStore;
    rp.depthAttachment.texture = m->depth;
    rp.depthAttachment.loadAction = MTLLoadActionLoad;
    rp.depthAttachment.storeAction = MTLStoreActionStore;
    m->enc = [m->cmd renderCommandEncoderWithDescriptor:rp];
    [m->enc setDepthClipMode:MTLDepthClipModeClamp];
    MTLViewport vp = {0, 0, m->width, m->height, 0, 1};  // vertices are already in pixels
    [m->enc setViewport:vp];
    return m->enc;
}

// Scissor = D3D viewport rectangle (intersected with `r` when given). Returns NO if empty.
static BOOL scissor(MPRImpl *m, id<MTLRenderCommandEncoder> e, const int32_t *r) {
    int64_t x0 = (int64_t)m->viewport[0], y0 = (int64_t)m->viewport[1];
    int64_t x1 = x0 + (int64_t)m->viewport[2], y1 = y0 + (int64_t)m->viewport[3];
    if (r) { x0 = MAX(x0, r[0]); y0 = MAX(y0, r[1]); x1 = MIN(x1, r[2]); y1 = MIN(y1, r[3]); }
    x0 = MAX(x0, 0); y0 = MAX(y0, 0); x1 = MIN(x1, (int64_t)m->width); y1 = MIN(y1, (int64_t)m->height);
    if (x1 <= x0 || y1 <= y0) return NO;
    MTLScissorRect s = {(NSUInteger)x0, (NSUInteger)y0, (NSUInteger)(x1 - x0), (NSUInteger)(y1 - y0)};
    [e setScissorRect:s];
    return YES;
}

static int on_clear(MPRImpl *m, const uint8_t *p, uint32_t len) {
    if (len < 20) { set_error(@"short CLEAR"); return -1; }
    uint32_t flags, color, stencil, n;
    float z;
    memcpy(&flags, p, 4); memcpy(&color, p + 4, 4); memcpy(&z, p + 8, 4); memcpy(&stencil, p + 12, 4); memcpy(&n, p + 16, 4);
    if (20 + (uint64_t)n * 16 > len) { set_error(@"CLEAR rects overrun"); return -1; }
    if (!(flags & 3)) return 0;
    if (m->split) {
        PassInfo pi = {.kind = 1, .nv = n, .zwrite = (flags & 2) != 0, .scw = (uint32_t)m->viewport[2], .sch = (uint32_t)m->viewport[3]};
        split_pass(m, &pi);
    }
    id<MTLRenderCommandEncoder> e = encoder(m);
    id<MTLRenderPipelineState> ps = pipeline(m, 1, NO, 0, 0, 0, (flags & 1) ? 7 : 0);
    if (!ps) return -1;
    [e setRenderPipelineState:ps];
    [e setDepthStencilState:depth_state(m, YES, (flags & 2) != 0, 8)];
    [e setCullMode:MTLCullModeNone];
    ClearU u;
    memset(&u, 0, sizeof u);
    u.color[0] = ((color >> 16) & 255) / 255.0f; u.color[1] = ((color >> 8) & 255) / 255.0f;
    u.color[2] = (color & 255) / 255.0f; u.color[3] = 1;
    u.z = z;
    [e setVertexBytes:&u length:sizeof u atIndex:0];
    [e setFragmentBytes:&u length:sizeof u atIndex:0];
    for (uint32_t i = 0; i < (n ? n : 1); i++) {
        int32_t rect[4];
        if (n) memcpy(rect, p + 20 + i * 16, 16);
        if (scissor(m, e, n ? rect : NULL))
            [e drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
    }
    return 0;
}

static int on_draw(MPRImpl *m, const uint8_t *p, uint32_t len) {
    uint32_t h[6];
    if (len < 24) { set_error(@"short DRAW"); return -1; }
    memcpy(h, p, 24);
    uint32_t prim = h[0], fvf = h[1], stride = h[2], nv = h[3], ni = h[4], isz = h[5];
    uint64_t need = 24 + (uint64_t)nv * stride + (uint64_t)ni * isz;
    if (need > len || (ni && isz != 2 && isz != 4) || stride % 4) { set_error(@"bad DRAW sizes"); return -1; }
    if (!nv) return 0;
    uint32_t kind = fvf & 0xE;
    if (!kind) { note(m, [NSString stringWithFormat:@"FVF 0x%x without a position (draw skipped)", fvf]); return 0; }
    // vertex layout (in 32-bit words) from the FVF: XYZRHW 4 words, XYZ 3, XYZB1..5 3 + blend weights
    VSU vu;
    memset(&vu, 0, sizeof vu);
    vu.width = m->width; vu.height = m->height; vu.stride = stride / 4;
    uint32_t pos_words = kind == 0x4 ? 4 : 3 + (kind >= 0x6 ? (kind - 0x4) / 2 : 0);
    if (kind != 0x4) {
        vu.xyz = 1;
        float wv[16];
        matmul(m->world, m->view, wv);
        matmul(wv, m->proj, vu.m);
        memcpy(vu.vp, m->viewport, sizeof vu.vp);
        vu.minz = m->viewport[4]; vu.maxz = m->viewport[5];
        if (m->rs[137] && (fvf & 0x10)) note(m, @"fixed-function lighting not implemented (vertex colours used)");
        if (m->rs[151]) note(m, @"vertex blending ignored");
    }
    uint32_t col = pos_words + ((fvf & 0x10) ? 3 : 0);
    vu.diffuse = (fvf & 0x40) ? col++ : 0xFFFFFFFF;
    vu.specular = (fvf & 0x80) ? col++ : 0xFFFFFFFF;
    vu.ntex = MIN((fvf >> 8) & 15, 8u);
    for (uint32_t t = 0; t < vu.ntex; t++) {
        uint32_t sz = (uint32_t[]){2, 3, 4, 1}[(fvf >> (16 + 2 * t)) & 3];
        vu.tex[t] = col;
        col += sz;
    }
    if (col > vu.stride) { set_error(@"FVF larger than stride"); return -1; }
    if (m->rs[9] == 1) note(m, @"flat shading drawn as Gouraud");
    if (m->rs[52]) note(m, @"stencil test ignored");

    // fragment uniforms: texture stages
    FSU fu;
    memset(&fu, 0, sizeof fu);
    uint32_t tfc = m->rs[60], fogc = m->rs[34];
    float tf[4] = {((tfc >> 16) & 255) / 255.0f, ((tfc >> 8) & 255) / 255.0f, (tfc & 255) / 255.0f, (tfc >> 24) / 255.0f};
    memcpy(fu.tfactor, tf, sizeof tf);
    fu.fogcolor[0] = ((fogc >> 16) & 255) / 255.0f; fu.fogcolor[1] = ((fogc >> 8) & 255) / 255.0f; fu.fogcolor[2] = (fogc & 255) / 255.0f;
    fu.fog = m->rs[28] != 0; fu.atest = m->rs[15] != 0; fu.afunc = m->rs[25]; fu.aref = m->rs[24];
    if (m->split) {
        PassInfo pi = {.kind = 0, .prim = prim, .fvf = fvf, .nv = nv, .ni = ni, .blend = m->rs[27] != 0, .src = m->rs[19],
                       .dst = m->rs[20], .atest = m->rs[15] != 0, .zfunc = m->rs[7] ? m->rs[23] : 0, .zwrite = m->rs[7] && m->rs[14],
                       .scw = (uint32_t)m->viewport[2], .sch = (uint32_t)m->viewport[3]};
        for (int s = 0; s < 8 && m->tss[s][1] != 1; s++) pi.stages++;
        id<MTLTexture> t0 = m->bound[0] ? m->textures[@(m->bound[0])] : nil;
        if (t0) { pi.tex0w = (uint32_t)t0.width; pi.tex0h = (uint32_t)t0.height; }
        split_pass(m, &pi);
    }
    id<MTLRenderCommandEncoder> e = encoder(m);
    for (int s = 0; s < 8; s++) {
        uint32_t *t = m->tss[s];
        StageU *st = &fu.st[s];
        st->cop = t[1]; st->ca1 = t[2]; st->ca2 = t[3]; st->ca0 = t[26];
        st->aop = t[4]; st->aa1 = t[5]; st->aa2 = t[6]; st->aa0 = t[27];
        st->tci = t[11] & 0xFFFF; st->result = t[28];
        if (t[11] >> 16) note(m, @"TEXCOORDINDEX texture-coordinate generation ignored");
        if (t[24]) note(m, @"texture transforms ignored");
        id<MTLTexture> tex = m->bound[s] ? m->textures[@(m->bound[s])] : nil;
        st->hastex = tex != nil;
        [e setFragmentTexture:tex ?: m->black atIndex:s];
        [e setFragmentSamplerState:sampler(m, s) atIndex:s];
        if (st->cop == 1) {                           // later stages are unused
            for (int r = s + 1; r < 8; r++) { [e setFragmentTexture:m->black atIndex:r]; [e setFragmentSamplerState:sampler(m, r) atIndex:r]; }
            break;
        }
    }

    id<MTLRenderPipelineState> ps = pipeline(m, 0, m->rs[27] != 0 && !m->noblend, m->rs[19], m->rs[20], m->rs[171], m->rs[168]);
    if (!ps) return -1;
    [e setRenderPipelineState:ps];
    [e setDepthStencilState:depth_state(m, m->rs[7] != 0, m->rs[14] != 0, m->rs[23])];
    // Culling. D3D: CULL_CW (2) / CULL_CCW (3) remove triangles whose screen-space winding (y down) is clockwise /
    // counter-clockwise. Metal judges winding in the same y-down window space, so "front" = clockwise and
    // CULL_CCW culls back faces (verified against tools/refrast.py by tools/test_render.py).
    uint32_t cull = m->rs[22];
    [e setFrontFacingWinding:MTLWindingClockwise];
    [e setCullMode:cull == 2 ? MTLCullModeFront : cull == 3 ? MTLCullModeBack : MTLCullModeNone];
    [e setTriangleFillMode:m->rs[8] == 2 ? MTLTriangleFillModeLines : MTLTriangleFillModeFill];
    if (!scissor(m, e, NULL)) return 0;
    if (m->tiny) [e setScissorRect:(MTLScissorRect){0, 0, 1, 1}];

    NSUInteger voff;
    id<MTLBuffer> vb = arena_alloc(m, p + 24, (NSUInteger)nv * stride, &voff);
    [e setVertexBuffer:vb offset:voff atIndex:0];
    [e setVertexBytes:&vu length:sizeof vu atIndex:1];
    [e setFragmentBytes:&fu length:sizeof fu atIndex:0];

    const uint8_t *ib = p + 24 + (size_t)nv * stride;
    MTLPrimitiveType mt;
    switch (prim) {
        case 1: mt = MTLPrimitiveTypePoint; break;
        case 2: mt = MTLPrimitiveTypeLine; break;
        case 3: mt = MTLPrimitiveTypeLineStrip; break;
        case 5: mt = MTLPrimitiveTypeTriangleStrip; break;
        default: mt = MTLPrimitiveTypeTriangle; break;   // lists, and fans converted below
    }
    if (prim == 6) {                                     // triangle fan -> list (32-bit indices)
        uint32_t n = ni ? ni : nv;
        if (n < 3) return 0;
        NSMutableData *li = [NSMutableData dataWithLength:(n - 2) * 3 * 4];
        uint32_t *o = li.mutableBytes;
        for (uint32_t i = 1; i + 1 < n; i++) {
            uint32_t a = 0, b = i, c = i + 1;
            if (ni) {
                a = isz == 2 ? ((const uint16_t *)ib)[0] : ((const uint32_t *)ib)[0];
                b = isz == 2 ? ((const uint16_t *)ib)[i] : ((const uint32_t *)ib)[i];
                c = isz == 2 ? ((const uint16_t *)ib)[i + 1] : ((const uint32_t *)ib)[i + 1];
            }
            *o++ = a; *o++ = b; *o++ = c;
        }
        NSUInteger ioff;
        id<MTLBuffer> ibuf = arena_alloc(m, li.bytes, li.length, &ioff);
        [e drawIndexedPrimitives:MTLPrimitiveTypeTriangle indexCount:(n - 2) * 3 indexType:MTLIndexTypeUInt32 indexBuffer:ibuf indexBufferOffset:ioff];
    } else if (ni) {
        NSUInteger ioff;
        id<MTLBuffer> ibuf = arena_alloc(m, ib, (NSUInteger)ni * isz, &ioff);
        [e drawIndexedPrimitives:mt indexCount:ni indexType:isz == 2 ? MTLIndexTypeUInt16 : MTLIndexTypeUInt32 indexBuffer:ibuf indexBufferOffset:ioff];
    } else {
        [e drawPrimitives:mt vertexStart:0 vertexCount:nv];
    }
    if (prim < 4) note(m, @"points/lines drawn without D3D point size or line rules");
    return 0;
}

// MPR_PROFILE=split, after the frame completed: add each pass's vertex and fragment time to passSums (by pass index;
// a replayed frame has the same passes every time).
static void split_collect(MPRImpl *m) {
    NSUInteger n = m->passes.length / sizeof(PassInfo);
    if (!n) return;
    NSData *d = [m->samples resolveCounterRange:NSMakeRange(0, 4 * n)];
    MTLTimestamp cpu1, gpu1;
    [m->dev sampleTimestamps:&cpu1 gpuTimestamp:&gpu1];
    double scale = gpu1 > m->gpu0 ? (cpu1 - m->cpu0) * 1e-9 / (double)(gpu1 - m->gpu0) : 1e-9;   // seconds per GPU tick (CPU side in ns)
    const MTLCounterResultTimestamp *ts = d.bytes;
    const PassInfo *pi = m->passes.bytes;
    if (m->passSums.length < n * sizeof(PassSum)) m->passSums.length = n * sizeof(PassSum);
    PassSum *sum = m->passSums.mutableBytes;
    for (NSUInteger i = 0; i < n && d; i++) {
        uint64_t v0 = ts[4 * i].timestamp, v1 = ts[4 * i + 1].timestamp, f0 = ts[4 * i + 2].timestamp, f1 = ts[4 * i + 3].timestamp;
        sum[i].info = pi[i];
        if (v0 != MTLCounterErrorValue && v1 >= v0) sum[i].vs += (v1 - v0) * scale;
        if (f0 != MTLCounterErrorValue && f1 >= f0) sum[i].fs += (f1 - f0) * scale;
    }
    m->profFrames++;
    m->passes.length = 0;
}

static void present(MPRImpl *m) {
    if (m->enc) { [m->enc endEncoding]; m->enc = nil; }
    if (m->cmd) {
        dispatch_semaphore_t sem = m->inflight;
        gpu_watch(m->gpu, m->cmd, 0);
        if (m->frameLog) {
            FILE *f = m->frameLog;
            uint32_t idx = m->frames;
            [m->cmd addCompletedHandler:^(id<MTLCommandBuffer> cb) {
                fprintf(f, "G %u %.3f %.3f\n", idx, cb.GPUStartTime * 1e3, cb.GPUEndTime * 1e3);
            }];
        }
        [m->cmd addCompletedHandler:^(id<MTLCommandBuffer> cb) { dispatch_semaphore_signal(sem); }];
        [m->cmd commit];
        uint64_t t = mach_absolute_time();
        if (m->sync) [m->cmd waitUntilCompleted];
        if (m->split) split_collect(m);
        m->cmd = nil;
        // the next frame's arena: wait until the frame that used it last is done with its uploads
        m->slot = (m->slot + 1) % MPR_INFLIGHT;
        dispatch_semaphore_wait(m->inflight, DISPATCH_TIME_FOREVER);
        m->waitTicks += mach_absolute_time() - t;
        m->arena = m->arenas[m->slot];
    }
    // reuse the arena (drop one-off big buffers)
    NSIndexSet *big = [m->arena indexesOfObjectsPassingTest:^BOOL(id<MTLBuffer> b, NSUInteger i, BOOL *stop) { return b.length != (4u << 20); }];
    [m->arena removeObjectsAtIndexes:big];
    m->arenaIndex = 0;
    m->arenaOffset = 0;
    m->frames++;
}

void mpr_timing(const mpr_renderer *r, double *out) {
    MPRImpl *m = (__bridge MPRImpl *)r->impl;
    out[0] = ticks_s(m->waitTicks);
    out[1] = ticks_s(m->drawableTicks);
    out[2] = ticks_s(m->presentTicks);
    out[3] = m->sync;
    out[4] = m->resizes;
}

static double gpu_percentile(const GpuStats *g, double q) {
    uint64_t want = (uint64_t)(g->frames * q), seen = 0;
    for (int i = 0; i < GPU_BUCKETS; i++) if ((seen += g->hist[i]) > want) return (i + 0.5) * 0.25;
    return GPU_BUCKETS * 0.25;
}

void mpr_gpu_timing(const mpr_renderer *r, double *out, int reset) {
    MPRImpl *m = impl(r);
    for (int i = 0; i < 20000 && m->gpu->pending; i++) usleep(100);   // let completed handlers run (up to 2 s)
    GpuStats *g = m->gpu;
    os_unfair_lock_lock(&g->lock);
    out[0] = g->frames; out[1] = g->frameSum; out[2] = g->frameMax * 1e3;
    out[3] = g->blits; out[4] = g->blitSum; out[5] = g->last > g->first ? g->last - g->first : 0;
    out[6] = gpu_percentile(g, 0.5); out[7] = gpu_percentile(g, 0.95);
    if (reset) { uint64_t p = g->pending; memset((char *)g + sizeof g->lock, 0, sizeof *g - sizeof g->lock); g->pending = p; }
    os_unfair_lock_unlock(&g->lock);
}

const char *mpr_profile_report(const mpr_renderer *r) {
    MPRImpl *m = impl(r);
    if (!m->split || !m->profFrames) return "";
    NSUInteger n = m->passSums.length / sizeof(PassSum);
    const PassSum *s = m->passSums.bytes;
    double k = 1e6 / m->profFrames;                     // microseconds per frame
    NSMutableString *o = [NSMutableString stringWithFormat:@"# %u frames; per pass, microseconds per frame\n"
                          "pass\tkind\tvs_us\tfs_us\tprim\tfvf\tnv\tni\tblend\tsrc\tdst\tatest\tstages\ttex0\tviewport\tzfunc\tzwrite\n", m->profFrames];
    for (NSUInteger i = 0; i < n; i++) {
        const PassInfo *p = &s[i].info;
        [o appendFormat:@"%lu\t%@\t%.1f\t%.1f\t%u\t0x%x\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%ux%u\t%ux%u\t%u\t%u\n", (unsigned long)i,
                        p->kind ? @"clear" : @"draw", s[i].vs * k, s[i].fs * k, p->prim, p->fvf, p->nv, p->ni, p->blend, p->src, p->dst,
                        p->atest, p->stages, p->tex0w, p->tex0h, p->scw, p->sch, p->zfunc, p->zwrite];
    }
    m->profText = o;
    return m->profText.UTF8String;
}

int mpr_submit(mpr_renderer *r, uint32_t type, const void *payload, uint32_t len) {
    @autoreleasepool {
        MPRImpl *m = impl(r);
        const uint8_t *p = payload;
        switch (type) {
            case MPD3_TEXTURE: return on_texture(m, p, len);
            case MPD3_RENDERSTATE: case MPD3_TSS: {
                uint32_t n;
                if (rd_u32(p, len, 0, &n)) { set_error(@"short state record"); return -1; }
                uint32_t each = type == MPD3_TSS ? 12 : 8;
                if (4 + (uint64_t)n * each > len) { set_error(@"state record overrun"); return -1; }
                for (uint32_t i = 0; i < n; i++) {
                    uint32_t v[3];
                    memcpy(v, p + 4 + i * each, each);
                    if (type == MPD3_RENDERSTATE) { if (v[0] < 256) m->rs[v[0]] = v[1]; }
                    else if (v[0] < 8 && v[1] < 32) m->tss[v[0]][v[1]] = v[2];
                }
                return 0;
            }
            case MPD3_SETTEXTURE: {
                uint32_t v[2];
                if (len < 8) { set_error(@"short SETTEXTURE"); return -1; }
                memcpy(v, p, 8);
                if (v[0] < 8) m->bound[v[0]] = v[1];
                return 0;
            }
            case MPD3_VIEWPORT: {
                if (len < 24) { set_error(@"short VIEWPORT"); return -1; }
                uint32_t v[4];
                memcpy(v, p, 16);
                for (int i = 0; i < 4; i++) m->viewport[i] = v[i];
                memcpy(&m->viewport[4], p + 16, 8);
                return 0;
            }
            case MPD3_CLEAR: return on_clear(m, p, len);
            case MPD3_DRAW: return on_draw(m, p, len);
            case MPD3_PRESENT: present(m); return 0;
            case MPD3_TRANSFORM: {                       // TRANSFORM: u32 state, 16 floats
                if (len < 68) { set_error(@"short TRANSFORM"); return -1; }
                uint32_t st;
                memcpy(&st, p, 4);
                float *dst = st == 256 ? m->world : st == 2 ? m->view : st == 3 ? m->proj : NULL;
                if (dst) memcpy(dst, p + 4, 64);
                else if (st >= 16 && st < 24) note(m, @"texture transform matrices ignored");
                return 0;
            }
            default: set_error([NSString stringWithFormat:@"unknown record type %u", type]); return -1;
        }
    }
}

int mpr_read_rgba(mpr_renderer *r, uint8_t *out) {
    @autoreleasepool {
        MPRImpl *m = impl(r);
        if (m->enc || m->cmd) present(m);
        NSUInteger row = (NSUInteger)m->width * 4;
        id<MTLBuffer> buf = [m->dev newBufferWithLength:row * m->height options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cb = [m->queue commandBuffer];
        id<MTLBlitCommandEncoder> bl = [cb blitCommandEncoder];
        [bl copyFromTexture:m->color sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0)
                 sourceSize:MTLSizeMake(m->width, m->height, 1) toBuffer:buf destinationOffset:0
        destinationBytesPerRow:row destinationBytesPerImage:row * m->height];
        [bl endEncoding];
        [cb commit];
        [cb waitUntilCompleted];
        const uint8_t *s = buf.contents;
        for (NSUInteger i = 0; i < (NSUInteger)m->width * m->height; i++) {
            out[i * 4 + 0] = s[i * 4 + 2]; out[i * 4 + 1] = s[i * 4 + 1]; out[i * 4 + 2] = s[i * 4 + 0]; out[i * 4 + 3] = 255;
        }
        return 0;
    }
}

// The frame-rate cap (M7): MPR_MAX_FPS (default 60; 0 = the display's rate). On a display faster than the cap (ProMotion,
// 120/144 Hz) each drawable is held on screen for at least 1/cap s; at or below the cap plain vsync already paces it.
// The screen is the one with the key window, read again every 120 frames (the window may move).
static double min_present_interval(uint32_t frame) {
    static double interval = -1;
    if (interval >= 0 && frame % 120) return interval;
    const char *e = getenv("MPR_MAX_FPS");
    int cap = e ? atoi(e) : 60;
    NSInteger hz = NSScreen.mainScreen.maximumFramesPerSecond;
    interval = cap > 0 && hz > cap + 1 ? 1.0 / cap : 0;
    return interval;
}

int mpr_present_to_layer(mpr_renderer *r, void *layer_ptr) {
    @autoreleasepool {
        MPRImpl *m = impl(r);
        uint64_t t0 = mach_absolute_time();
        double c0 = CACurrentMediaTime();
        uint32_t idx = m->frames;                       // the frame being shown (present() below counts it)
        if (m->enc || m->cmd) present(m);
        CAMetalLayer *layer = (__bridge CAMetalLayer *)layer_ptr;
        if (layer.device != m->dev) {
            layer.device = m->dev;
            layer.pixelFormat = MTLPixelFormatBGRA8Unorm;
            layer.framebufferOnly = NO;
            layer.contentsGravity = kCAGravityResizeAspect;
        }
        // Drawables in the queue: 2 by default (MPR_DRAWABLES=3 for CAMetalLayer's default). With 3, a frame that beats
        // vsync reaches the screen about 57 ms after PRESENT; with 2 about 38 ms, at the same frame rate (H52).
        const char *nd = getenv("MPR_DRAWABLES");
        NSUInteger want_n = nd && atoi(nd) == 3 ? 3 : 2;
        if (layer.maximumDrawableCount != want_n) layer.maximumDrawableCount = want_n;
        const char *ds = getenv("MPR_DISPLAY_SYNC");        // 0: no vsync (for measuring CPU-bound frame times; tears)
        if (ds && !strcmp(ds, "0") && layer.displaySyncEnabled) layer.displaySyncEnabled = NO;
        CGSize want = CGSizeMake(m->width, m->height);
        if (!CGSizeEqualToSize(layer.drawableSize, want)) {
            if (getenv("MPR_DEBUG_PRESENT") && m->resizes < 5)
                fprintf(stderr, "[mpr] drawableSize %gx%g -> %gx%g\n", layer.drawableSize.width, layer.drawableSize.height, want.width, want.height);
            layer.drawableSize = want;
            m->resizes++;
        }
        uint64_t t1 = mach_absolute_time();
        id<CAMetalDrawable> d = [layer nextDrawable];
        uint64_t dt = mach_absolute_time() - t1;
        m->drawableTicks += dt;
        if (getenv("MPR_DEBUG_PRESENT") && m->frames < 400)
            fprintf(stderr, "[mpr] frame %u nextDrawable %.3f ms\n", m->frames, ticks_s(dt) * 1e3);
        if (!d) { set_error(@"no drawable"); return -1; }
        if (m->frameLog) {
            FILE *f = m->frameLog;
            // F frame, entry time, CPU time since the last present_to_layer returned, nextDrawable wait
            fprintf(f, "F %u %.3f %.3f %.3f\n", idx, c0 * 1e3, m->lastPresentEnd ? (c0 - m->lastPresentEnd) * 1e3 : 0, ticks_s(dt) * 1e3);
            [d addPresentedHandler:^(id<MTLDrawable> dr) { fprintf(f, "P %u %.3f\n", idx, dr.presentedTime * 1e3); }];
        }
        id<MTLCommandBuffer> cb = [m->queue commandBuffer];
        id<MTLBlitCommandEncoder> bl = [cb blitCommandEncoder];
        [bl copyFromTexture:m->color toTexture:d.texture];
        [bl endEncoding];
        double minDur = layer.displaySyncEnabled ? min_present_interval(idx) : 0;
        if (minDur > 0)
            [cb presentDrawable:d afterMinimumDuration:minDur];
        else
            [cb presentDrawable:d];
        gpu_watch(m->gpu, cb, 1);
        [cb commit];
        m->presentTicks += mach_absolute_time() - t0;
        m->lastPresentEnd = CACurrentMediaTime();
        return 0;
    }
}
