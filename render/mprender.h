/* libmprender: Max Payne's Direct3D 8 subset on Metal.
 *
 * The renderer consumes the MPD3 command stream (record types and payload layouts are defined in emu/d3dcap.py;
 * the constants below mirror it). The emulator can capture that stream to a file (offline replay with
 * mpreplay) and the native host will submit the same records live.
 *
 * Supported (what the game uses, see docs/d3d8-usage.md): pre-transformed vertices (D3DFVF_XYZRHW) and
 * untransformed ones (XYZ: World x View x Projection + viewport, no lighting) with DIFFUSE/SPECULAR/TEX0..8,
 * triangle lists/strips/fans (+ points/lines), 16/32-bit indices, the fixed-function texture-stage combiner (D3DTOP_*, D3DTA_* with COMPLEMENT/ALPHAREPLICATE, TEMP result), point/linear/mip
 * filtering, wrap/mirror/clamp addressing, vertex fog, alpha test, all D3DBLEND factors and D3DBLENDOP ops,
 * depth test/write, culling, colour write mask, viewport-limited clears. Textures: R8G8B8, A8R8G8B8, X8R8G8B8,
 * R5G6B5, X1R5G5B5, A1R5G5B5, A4R4G4B4, X4R4G4B4, A8, L8, A8L8.
 */
#ifndef MPRENDER_H
#define MPRENDER_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    MPD3_TEXTURE = 1, MPD3_RENDERSTATE = 2, MPD3_TSS = 3, MPD3_SETTEXTURE = 4, MPD3_VIEWPORT = 5,
    MPD3_CLEAR = 6, MPD3_DRAW = 7, MPD3_PRESENT = 8, MPD3_TRANSFORM = 9
};

typedef struct mpr_renderer mpr_renderer;

/* Create a renderer with an offscreen back buffer of width x height (X8R8G8B8 semantics). NULL on failure;
 * mpr_last_error() says why. */
mpr_renderer *mpr_create(uint32_t width, uint32_t height);
void mpr_destroy(mpr_renderer *r);

/* Submit one MPD3 record. Returns 0, or -1 for a malformed record (see mpr_last_error()). PRESENT ends a frame:
 * the GPU work is committed (not waited for: up to 3 frames run behind the CPU; MPR_SYNC=1 waits) and the frame
 * becomes readable through mpr_read_rgba, which waits for it. */
int mpr_submit(mpr_renderer *r, uint32_t type, const void *payload, uint32_t length);

/* Copy the last presented frame as tightly packed RGBA8 (width*height*4 bytes). Returns 0 or -1. */
int mpr_read_rgba(mpr_renderer *r, uint8_t *out);

/* Show the last presented frame in a CAMetalLayer (e.g. from SDL_Metal_GetLayer). The layer is configured on
 * first use (device, BGRA8, drawable size = back buffer; the layer scales it to its bounds keeping the aspect).
 * Returns 0, or -1 if no drawable was available. */
int mpr_present_to_layer(mpr_renderer *r, void *ca_metal_layer);

/* Number of PRESENT records processed so far. */
uint32_t mpr_frame_count(const mpr_renderer *r);

/* Features the stream asked for that are approximated or ignored (one line each), for diagnostics. */
const char *mpr_notes(const mpr_renderer *r);

/* Environment: MPR_SYNC=1 waits for the GPU at every PRESENT (the old behaviour); MPR_DISPLAY_SYNC=0 turns the
 * layer's vsync off (CPU-bound frame times, with tearing); MPR_DRAWABLES=3 queues three drawables (CAMetalLayer's
 * default) instead of two (more latency, same frame rate); MPR_DEBUG_PRESENT=1 prints drawable resizes and the first
 * 400 nextDrawable times to stderr; MPR_FRAME_LOG=path writes per-frame lines (ms, CACurrentMediaTime clock):
 * "F frame entry cpu wait" from mpr_present_to_layer (cpu = time since the previous call returned, wait = nextDrawable),
 * "G frame gpu_start gpu_end" when the frame's command buffer completes, "P frame presented" when the drawable reaches
 * the screen (presented 0: never shown); MPR_MAX_FPS=N caps the frame rate on displays faster than N Hz (default 60;
 * 0: the display's rate).
 *
 * Seconds spent so far: out[0] waiting at PRESENT (for the GPU with MPR_SYNC=1, otherwise only while MPR_INFLIGHT
 * frames are in flight), out[1] in nextDrawable, out[2] in mpr_present_to_layer as a whole; out[3] is 1 under
 * MPR_SYNC; out[4] counts the times the layer's drawableSize had to be set (out has 5 entries). */
void mpr_timing(const mpr_renderer *r, double *out);

/* GPU time, from the command buffers' GPUStartTime/GPUEndTime (out has 8 entries): out[0] frames timed, out[1] their
 * GPU seconds in total, out[2] the longest frame in ms, out[3] present blits timed (mpr_present_to_layer), out[4] their
 * GPU seconds, out[5] seconds from the first GPU start to the last GPU end (so (out[1] + out[4]) / out[5] is the
 * fraction of time the GPU was busy), out[6] and out[7] the median and 95th percentile frame in ms (0.25 ms
 * buckets). Waits up to 2 s for command buffers still in flight. reset != 0 starts the counts again.
 *
 * MPR_PROFILE (environment, read by mpr_create, comma-separated) changes the rendering to find where the GPU time
 * goes: flatfs (fragment shader = vertex colour), tex1 (stage 0 texture x vertex colour), tiny (every draw scissored
 * to one pixel: vertex work only), noblend, split (a render pass per draw and clear with stage-boundary timestamps;
 * waits for every frame; mpr_profile_report gives the per-pass times). */
void mpr_gpu_timing(const mpr_renderer *r, double *out, int reset);

/* MPR_PROFILE=split: tab-separated vertex and fragment microseconds per pass, averaged over the frames so far ("" when
 * not profiling). */
const char *mpr_profile_report(const mpr_renderer *r);

const char *mpr_last_error(void);

#ifdef __cplusplus
}
#endif
#endif
