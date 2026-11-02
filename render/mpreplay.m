// mpreplay: replay an MPD3 capture (emu/d3dcap.py) through libmprender and write a frame as PNG.
// Usage: mpreplay capture.mpd3 out.png [--frame N] [--bench K]
//   N = index of the PRESENT to stop at (default 0). --bench K then submits that frame's records K more times and
//   prints its GPU time per frame (mpr_gpu_timing); with MPR_PROFILE=split also the time per pass (mpr_profile_report).
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#include <stdio.h>
#include <string.h>
#include "mprender.h"

static int write_png(const char *path, const uint8_t *rgba, uint32_t w, uint32_t h) {
    CGColorSpaceRef cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGContextRef ctx = CGBitmapContextCreate((void *)rgba, w, h, 8, w * 4, cs, kCGImageAlphaNoneSkipLast | kCGBitmapByteOrderDefault);
    CGImageRef img = CGBitmapContextCreateImage(ctx);
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
    CGImageDestinationRef dst = CGImageDestinationCreateWithURL(url, (__bridge CFStringRef)UTTypePNG.identifier, 1, NULL);
    int ok = dst != NULL;
    if (dst) { CGImageDestinationAddImage(dst, img, NULL); ok = CGImageDestinationFinalize(dst); CFRelease(dst); }
    CFRelease(url); CGImageRelease(img); CGContextRelease(ctx); CGColorSpaceRelease(cs);
    return ok ? 0 : -1;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 3) { fprintf(stderr, "usage: %s capture.mpd3 out.png [--frame N]\n", argv[0]); return 2; }
        int frame = 0, bench = 0;
        for (int i = 3; i + 1 < argc; i++) {
            if (!strcmp(argv[i], "--frame")) frame = atoi(argv[i + 1]);
            if (!strcmp(argv[i], "--bench")) bench = atoi(argv[i + 1]);
        }
        NSData *data = [NSData dataWithContentsOfFile:@(argv[1])];
        const uint8_t *p = data.bytes;
        if (data.length < 16 || memcmp(p, "MPD3", 4)) { fprintf(stderr, "%s: not an MPD3 capture\n", argv[1]); return 1; }
        uint32_t ver, w, h;
        memcpy(&ver, p + 4, 4); memcpy(&w, p + 8, 4); memcpy(&h, p + 12, 4);
        mpr_renderer *r = mpr_create(w, h);
        if (!r) { fprintf(stderr, "renderer: %s\n", mpr_last_error()); return 1; }
        NSDate *t0 = [NSDate date];
        size_t off = 16, frame_start = 16;
        unsigned draws = 0;
        while (off + 8 <= data.length) {
            uint32_t type, len;
            memcpy(&type, p + off, 4); memcpy(&len, p + off + 4, 4);
            if (off + 8 + len > data.length) { fprintf(stderr, "truncated record at %zu\n", off); break; }
            if (type == MPD3_DRAW) draws++;
            if (mpr_submit(r, type, p + off + 8, len)) { fprintf(stderr, "record %u at %zu: %s\n", type, off, mpr_last_error()); return 1; }
            off += 8 + len;
            if (type == MPD3_PRESENT && (int)mpr_frame_count(r) > frame) break;
            if (type == MPD3_PRESENT) frame_start = off;
        }
        double ms = -[t0 timeIntervalSinceNow] * 1000;
        if (bench > 0) {
            double g[8];
            mpr_gpu_timing(r, g, 1);
            NSDate *b0 = [NSDate date];
            for (int k = 0; k < bench; k++)
                for (size_t o = frame_start; o + 8 <= off; ) {
                    uint32_t type, len;
                    memcpy(&type, p + o, 4); memcpy(&len, p + o + 4, 4);
                    if (mpr_submit(r, type, p + o + 8, len)) { fprintf(stderr, "bench: %s\n", mpr_last_error()); return 1; }
                    o += 8 + len;
                }
            mpr_gpu_timing(r, g, 0);
            double wall = -[b0 timeIntervalSinceNow];
            printf("bench: %d frames, wall %.2f ms/frame; GPU %.0f frames, mean %.3f ms, median %.2f, p95 %.2f, max %.2f ms; "
                   "GPU busy %.0f%% of %.2f s\n", bench, wall * 1e3 / bench, g[0], g[0] ? g[1] * 1e3 / g[0] : 0, g[6], g[7], g[2],
                   g[5] > 0 ? 100 * (g[1] + g[4]) / g[5] : 0, g[5]);
            const char *rep = mpr_profile_report(r);
            if (rep && *rep) fputs(rep, stdout);
        }
        NSMutableData *px = [NSMutableData dataWithLength:(NSUInteger)w * h * 4];
        mpr_read_rgba(r, px.mutableBytes);
        if (write_png(argv[2], px.bytes, w, h)) { fprintf(stderr, "could not write %s\n", argv[2]); return 1; }
        printf("%s: %u draws, %ux%u, %.1f ms -> %s\n", argv[1], draws, w, h, ms, argv[2]);
        const char *notes = mpr_notes(r);
        if (notes && *notes) printf("notes:\n%s\n", notes);
        mpr_destroy(r);
        return 0;
    }
}
