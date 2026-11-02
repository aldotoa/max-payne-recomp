// libmpmovie: decodes the game's movies (MPEG-1 video + MPEG audio layer II in an MPEG-1 system stream) with
// AVFoundation, for the emulator's DirectShow layer (emu/dshow.py), and shows decoded frames in a CAMetalLayer.
//
// Video comes out frame by frame as tightly packed BGRA with its presentation time; audio is decoded in one go to
// interleaved signed 16-bit PCM at the track's own rate (the caller hands it to the mixer as a single voice).
#import <AVFoundation/AVFoundation.h>
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static char last_error[512];
const char *mpm_last_error(void) { return last_error; }
static void set_error(NSString *s) { snprintf(last_error, sizeof last_error, "%s", s.UTF8String); }

typedef struct mpm {
    void *asset;          // AVURLAsset (retained)
    void *reader;         // AVAssetReader for video (retained)
    void *output;         // AVAssetReaderTrackOutput (retained)
    int width, height;
    double duration, fps;
    int audio_rate, audio_channels;
} mpm;

static AVAssetTrack *first_track(AVURLAsset *a, AVMediaType type) {
    for (AVAssetTrack *t in a.tracks)
        if ([t.mediaType isEqualToString:type]) return t;
    return nil;
}

static int start_video(mpm *m, double from) {
    AVURLAsset *a = (__bridge AVURLAsset *)m->asset;
    if (m->reader) CFRelease(m->reader);
    if (m->output) CFRelease(m->output);
    m->reader = m->output = NULL;
    AVAssetTrack *v = first_track(a, AVMediaTypeVideo);
    if (!v) return 0;
    NSError *err = nil;
    AVAssetReader *r = [AVAssetReader assetReaderWithAsset:a error:&err];
    if (!r) { set_error(err.description); return -1; }
    if (from > 0)
        r.timeRange = CMTimeRangeMake(CMTimeMakeWithSeconds(from, 90000), kCMTimePositiveInfinity);
    AVAssetReaderTrackOutput *o = [AVAssetReaderTrackOutput assetReaderTrackOutputWithTrack:v
        outputSettings:@{(id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA)}];
    o.alwaysCopiesSampleData = NO;
    [r addOutput:o];
    if (![r startReading]) { set_error(r.error.description ?: @"startReading failed"); return -1; }
    m->reader = (void *)CFBridgingRetain(r);
    m->output = (void *)CFBridgingRetain(o);
    return 0;
}

mpm *mpm_open(const char *path) {
    @autoreleasepool {
        AVURLAsset *a = [AVURLAsset URLAssetWithURL:[NSURL fileURLWithPath:@(path)] options:nil];
        if (!a.readable) { set_error([NSString stringWithFormat:@"%s: not readable by AVFoundation", path]); return NULL; }
        mpm *m = calloc(1, sizeof *m);
        m->asset = (void *)CFBridgingRetain(a);
        m->duration = CMTimeGetSeconds(a.duration);
        AVAssetTrack *v = first_track(a, AVMediaTypeVideo);
        if (v) {
            m->width = (int)v.naturalSize.width;
            m->height = (int)v.naturalSize.height;
            m->fps = v.nominalFrameRate;
        }
        AVAssetTrack *s = first_track(a, AVMediaTypeAudio);
        if (s && s.formatDescriptions.count) {
            const AudioStreamBasicDescription *d = CMAudioFormatDescriptionGetStreamBasicDescription(
                (__bridge CMAudioFormatDescriptionRef)s.formatDescriptions.firstObject);
            if (d) {
                m->audio_rate = (int)d->mSampleRate;
                m->audio_channels = d->mChannelsPerFrame > 2 ? 2 : (int)d->mChannelsPerFrame;
            }
        }
        if (start_video(m, 0) < 0) {
            CFRelease(m->asset);
            free(m);
            return NULL;
        }
        return m;
    }
}

void mpm_info(mpm *m, int *w, int *h, double *duration, double *fps, int *audio_rate, int *audio_channels) {
    *w = m->width;
    *h = m->height;
    *duration = m->duration;
    *fps = m->fps;
    *audio_rate = m->audio_rate;
    *audio_channels = m->audio_channels;
}

// Next video frame into bgra (width*height*4 bytes). Returns 1 with *pts set, 0 at the end, -1 on error.
int mpm_next_frame(mpm *m, uint8_t *bgra, double *pts) {
    @autoreleasepool {
        if (!m->output) return 0;
        AVAssetReaderTrackOutput *o = (__bridge AVAssetReaderTrackOutput *)m->output;
        for (;;) {
            CMSampleBufferRef s = [o copyNextSampleBuffer];
            if (!s) {
                AVAssetReader *r = (__bridge AVAssetReader *)m->reader;
                if (r.status == AVAssetReaderStatusFailed) { set_error(r.error.description); return -1; }
                return 0;
            }
            CVPixelBufferRef px = CMSampleBufferGetImageBuffer(s);
            if (!px) { CFRelease(s); continue; }     // a sample without an image (end-of-stream marker)
            *pts = CMTimeGetSeconds(CMSampleBufferGetPresentationTimeStamp(s));
            CVPixelBufferLockBaseAddress(px, kCVPixelBufferLock_ReadOnly);
            const uint8_t *src = CVPixelBufferGetBaseAddress(px);
            size_t stride = CVPixelBufferGetBytesPerRow(px);
            int w = (int)CVPixelBufferGetWidth(px), h = (int)CVPixelBufferGetHeight(px);
            if (w > m->width) w = m->width;
            if (h > m->height) h = m->height;
            for (int y = 0; y < h; y++)
                memcpy(bgra + (size_t)y * m->width * 4, src + y * stride, (size_t)w * 4);
            CVPixelBufferUnlockBaseAddress(px, kCVPixelBufferLock_ReadOnly);
            CFRelease(s);
            return 1;
        }
    }
}

// Restart video at time t (seconds): the first frame returned is the one shown at t.
int mpm_seek(mpm *m, double t) {
    @autoreleasepool { return start_video(m, t); }
}

// Decode the whole audio track to interleaved s16 at its own rate. *out is malloc'ed (free with mpm_free).
// Returns 0, with *frames = 0 when the movie has no audio; -1 on error.
int mpm_read_audio(mpm *m, int16_t **out, uint32_t *frames) {
    @autoreleasepool {
        *out = NULL;
        *frames = 0;
        AVURLAsset *a = (__bridge AVURLAsset *)m->asset;
        AVAssetTrack *t = first_track(a, AVMediaTypeAudio);
        if (!t || !m->audio_rate) return 0;
        NSError *err = nil;
        AVAssetReader *r = [AVAssetReader assetReaderWithAsset:a error:&err];
        if (!r) { set_error(err.description); return -1; }
        AVAssetReaderTrackOutput *o = [AVAssetReaderTrackOutput assetReaderTrackOutputWithTrack:t outputSettings:@{
            AVFormatIDKey: @(kAudioFormatLinearPCM), AVLinearPCMBitDepthKey: @16, AVLinearPCMIsFloatKey: @NO,
            AVLinearPCMIsBigEndianKey: @NO, AVLinearPCMIsNonInterleaved: @NO,
            AVSampleRateKey: @(m->audio_rate), AVNumberOfChannelsKey: @(m->audio_channels)}];
        [r addOutput:o];
        if (![r startReading]) { set_error(r.error.description ?: @"audio startReading failed"); return -1; }
        size_t cap = (size_t)(m->duration + 1) * m->audio_rate * m->audio_channels * 2 + 65536, len = 0;
        uint8_t *buf = malloc(cap);
        CMSampleBufferRef s;
        while ((s = [o copyNextSampleBuffer])) {
            CMBlockBufferRef b = CMSampleBufferGetDataBuffer(s);
            size_t n = b ? CMBlockBufferGetDataLength(b) : 0;
            if (len + n > cap) {
                cap = (len + n) * 2;
                buf = realloc(buf, cap);
            }
            if (n) CMBlockBufferCopyDataBytes(b, 0, n, buf + len);
            len += n;
            CFRelease(s);
        }
        if (r.status == AVAssetReaderStatusFailed) { set_error(r.error.description); free(buf); return -1; }
        *out = (int16_t *)buf;
        *frames = (uint32_t)(len / (2 * m->audio_channels));
        return 0;
    }
}

void mpm_free(void *p) { free(p); }

void mpm_close(mpm *m) {
    if (m->reader) CFRelease(m->reader);
    if (m->output) CFRelease(m->output);
    CFRelease(m->asset);
    free(m);
}

// Show a BGRA image in a CAMetalLayer, scaled to fit (the layer's aspect gravity letterboxes it).
int mpm_present_bgra(void *layer_ptr, const uint8_t *bgra, int w, int h) {
    @autoreleasepool {
        static id<MTLDevice> dev;
        static id<MTLCommandQueue> queue;
        static id<MTLTexture> tex;
        CAMetalLayer *layer = (__bridge CAMetalLayer *)layer_ptr;
        if (!dev) {
            dev = layer.device ?: MTLCreateSystemDefaultDevice();
            queue = [dev newCommandQueue];
        }
        if (layer.device != dev) {
            layer.device = dev;
            layer.pixelFormat = MTLPixelFormatBGRA8Unorm;
            layer.framebufferOnly = NO;
            layer.contentsGravity = kCAGravityResizeAspect;
        }
        if (!tex || (int)tex.width != w || (int)tex.height != h) {
            MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                                                                         width:w height:h mipmapped:NO];
            d.storageMode = MTLStorageModeShared;
            tex = [dev newTextureWithDescriptor:d];
        }
        [tex replaceRegion:MTLRegionMake2D(0, 0, w, h) mipmapLevel:0 withBytes:bgra bytesPerRow:(NSUInteger)w * 4];
        CGSize want = CGSizeMake(w, h);
        if (!CGSizeEqualToSize(layer.drawableSize, want)) layer.drawableSize = want;
        id<CAMetalDrawable> drawable = [layer nextDrawable];
        if (!drawable) { set_error(@"no drawable"); return -1; }
        id<MTLCommandBuffer> cb = [queue commandBuffer];
        id<MTLBlitCommandEncoder> bl = [cb blitCommandEncoder];
        [bl copyFromTexture:tex toTexture:drawable.texture];
        [bl endEncoding];
        [cb presentDrawable:drawable];
        [cb commit];
        return 0;
    }
}
