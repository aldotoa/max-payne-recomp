/* cpuid and rdtsc for lifted code (M5). See misc.h.
 *
 * The cpuid table is what the Unicorn emulator (qemu32 model, unicorn 2.1.4) returns, recorded by
 * running `mov eax, leaf; mov ecx, sub; cpuid` in Unicorn for each leaf. Lifted and emulated runs
 * therefore see the same CPU. Leaves in the table with `any` set ignore ecx (the emulator returns
 * the same values for ecx = 0, 1, 7 for leaves 0, 1, 2, 0x80000000..0x80000006). Leaves above the
 * highest basic leaf (0xd) or above the highest extended leaf (0x80000008) return the values of
 * leaf 0xd, as the emulator does. Any other leaf returns zeros. */
#include "misc.h"

#include <mach/mach_time.h>

typedef struct {
    uint32_t leaf, sub;
    uint8_t any;               /* 1: ecx is ignored for this leaf */
    uint32_t v[4];             /* eax, ebx, ecx, edx */
} CpuidEnt;

static const CpuidEnt CPUID_TAB[] = {
    {0x00000000, 0, 1, {0x0000000d, 0x756e6547, 0x6c65746e, 0x49656e69}},
    {0x00000001, 0, 1, {0x000306c4, 0x00000800, 0xced82203, 0x078bfbfd}},
    {0x00000002, 0, 1, {0x00000001, 0x00000000, 0x00000000, 0x002c307d}},
    {0x00000004, 0, 0, {0x00000121, 0x01c0003f, 0x0000003f, 0x00000001}},
    {0x00000004, 1, 0, {0x00000122, 0x01c0003f, 0x0000003f, 0x00000001}},
    {0x00000004, 2, 0, {0x00000143, 0x03c0003f, 0x00000fff, 0x00000001}},
    {0x00000007, 0, 0, {0x00000000, 0x00000389, 0x00000000, 0x00000000}},
    {0x0000000d, 0, 0, {0x00000007, 0x00000240, 0x00000340, 0x00000000}},
    {0x80000000, 0, 1, {0x80000008, 0x756e6547, 0x6c65746e, 0x49656e69}},
    {0x80000001, 0, 1, {0x000306c4, 0x00000000, 0x00000021, 0x28100800}},
    {0x80000002, 0, 1, {0x65746e49, 0x6f43206c, 0x50206572, 0x65636f72}},
    {0x80000003, 0, 1, {0x726f7373, 0x61482820, 0x6c657773, 0x0000296c}},
    {0x80000005, 0, 1, {0x01ff01ff, 0x01ff01ff, 0x40020140, 0x40020140}},
    {0x80000006, 0, 1, {0x00000000, 0x42004200, 0x02008140, 0x00000000}},
    {0x80000008, 0, 1, {0x00003028, 0x00000000, 0x00000000, 0x00000000}},
};

uint32_t lift_eflags_sys;

#define CPUID_BASIC_MAX 0xdu
#define CPUID_EXT_MAX   0x80000008u

static const CpuidEnt *cpuid_find(uint32_t leaf, uint32_t sub)
{
    for (size_t i = 0; i < sizeof CPUID_TAB / sizeof CPUID_TAB[0]; i++) {
        const CpuidEnt *e = &CPUID_TAB[i];
        if (e->leaf == leaf && (e->any || e->sub == sub))
            return e;
    }
    return NULL;
}

void lift_cpuid(CPU *c)
{
    uint32_t leaf = c->r[EAX], sub = c->r[ECX];
    uint32_t out[4] = {0, 0, 0, 0};
    const CpuidEnt *e;

    if ((leaf > CPUID_BASIC_MAX && leaf < 0x80000000u) || leaf > CPUID_EXT_MAX)
        leaf = CPUID_BASIC_MAX, sub = 0;           /* out of range: the emulator returns leaf 0xd */
    e = cpuid_find(leaf, sub);
    if (e)
        memcpy(out, e->v, sizeof out);
    c->r[EAX] = out[0];
    c->r[EBX] = out[1];
    c->r[ECX] = out[2];
    c->r[EDX] = out[3];
}

/* Monotonic counter: mach_absolute_time scaled to nanoseconds, i.e. cycles at an assumed 1 GHz.
 * Not bit-compatible with the emulator, whose rdtsc returns a constant. */
void lift_rdtsc(CPU *c)
{
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0)
        mach_timebase_info(&tb);
    uint64_t ns = mach_absolute_time() * tb.numer / tb.denom;
    c->r[EAX] = (uint32_t)ns;
    c->r[EDX] = (uint32_t)(ns >> 32);
}
