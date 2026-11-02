// pcsample: an in-process PC sampler for one thread (H54). A helper thread suspends the target thread at a fixed
// rate, reads its program counter and resumes it; pcs_stop writes "count symbol offset image" lines, most samples
// first. Load it with ctypes (tools/m6/pcsample_probe.py does this from a run_init --probe).
// Build: clang -O2 -dynamiclib -o build/libpcsample.dylib tools/m6/pcsample.c
#include <dlfcn.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_SAMPLES (1u << 22)

static thread_act_t target;
static uint64_t *pcs;
static volatile uint32_t npcs, running;
static pthread_t sampler;
static uint32_t period_us;

static void *loop(void *arg) {
    (void)arg;
    struct timespec ts = {0, (long)period_us * 1000};
    while (running && npcs < MAX_SAMPLES) {
        if (thread_suspend(target) == KERN_SUCCESS) {
            arm_thread_state64_t st;
            mach_msg_type_number_t n = ARM_THREAD_STATE64_COUNT;
            if (thread_get_state(target, ARM_THREAD_STATE64, (thread_state_t)&st, &n) == KERN_SUCCESS)
                pcs[npcs++] = arm_thread_state64_get_pc(st);
            thread_resume(target);
        }
        nanosleep(&ts, NULL);
    }
    return NULL;
}

// Start sampling the calling thread every period microseconds. Returns 0, or -1 if already running.
int pcs_start(uint32_t period) {
    if (running) return -1;
    if (!pcs) pcs = malloc(MAX_SAMPLES * sizeof *pcs);
    target = mach_thread_self();
    period_us = period ? period : 500;
    npcs = 0;
    running = 1;
    return pthread_create(&sampler, NULL, loop, NULL) ? -1 : 0;
}

static int by_pc(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

typedef struct { uint64_t pc; uint32_t n; } Hit;
static int by_count(const void *a, const void *b) { return (int)((const Hit *)b)->n - (int)((const Hit *)a)->n; }

// Stop and write the histogram to path. Returns the number of samples.
int pcs_stop(const char *path) {
    if (!running) return -1;
    running = 0;
    pthread_join(sampler, NULL);
    qsort(pcs, npcs, sizeof *pcs, by_pc);
    Hit *h = malloc((npcs + 1) * sizeof *h);
    uint32_t nh = 0;
    for (uint32_t i = 0; i < npcs; i++) {
        if (nh && h[nh - 1].pc == pcs[i]) h[nh - 1].n++;
        else h[nh++] = (Hit){pcs[i], 1};
    }
    qsort(h, nh, sizeof *h, by_count);
    FILE *f = fopen(path, "w");
    if (!f) { free(h); return -1; }
    fprintf(f, "# %u samples, %u us period\n", npcs, period_us);
    for (uint32_t i = 0; i < nh; i++) {
        Dl_info di;
        if (dladdr((void *)h[i].pc, &di) && di.dli_sname)
            fprintf(f, "%u %s %lu %s\n", h[i].n, di.dli_sname, (unsigned long)(h[i].pc - (uint64_t)di.dli_saddr),
                    strrchr(di.dli_fname, '/') ? strrchr(di.dli_fname, '/') + 1 : di.dli_fname);
        else
            fprintf(f, "%u ? 0x%llx ?\n", h[i].n, (unsigned long long)h[i].pc);
    }
    fclose(f);
    free(h);
    return (int)npcs;
}
