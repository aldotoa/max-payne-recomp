/* Runtime helpers for the odd instructions (M5): cpuid and rdtsc. Implemented in misc.c.
 * Both take the CPU struct and write their results to the registers the instruction writes. */
#ifndef LIFT_MISC_H
#define LIFT_MISC_H

#include "cpu.h"

/* cpuid: input eax (leaf) and ecx (subleaf); output eax, ebx, ecx, edx. Returns the same values
 * as the Unicorn emulator for the leaves in the table in misc.c (zeros for leaves not in it). */
void lift_cpuid(CPU *c);

/* rdtsc: edx:eax = a monotonic counter at an assumed 1 GHz. Not the emulator's value (Unicorn
 * returns a constant), so timing code sees different numbers than under emulation. */
void lift_rdtsc(CPU *c);

/* The EFLAGS bits a popfd set that CPU has no field for: TF, IF, IOPL, NT, AC and ID (LIFT_EFLAGS_SYS). pushfd pushes
 * them back, as Unicorn does (rlmfc's determineProcessorCaps detects cpuid by toggling ID); 0 until the first popfd. */
#define LIFT_EFLAGS_SYS 0x00247300u
extern uint32_t lift_eflags_sys;

#endif
