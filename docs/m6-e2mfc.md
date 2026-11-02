# M6: e2mfc lifted to native

## Result
`e2mfc.dll` (the engine) is lifted to native C. It runs with rlmfc and grphmfc in one native library. In the three-module differential game run, every function reached matches the emulator except two: `getProcessorSpeed`, which is expected, and `P_Device::P_Device`, which the differential mode cannot replay. The native game run is stable. Speed is about the same as before, because almost all calls into native code come from the exe (see Speed).

| Check | Result |
|---|---|
| Lifted | e2mfc: 2,755 of 2,772 real entries. The other 17 stay emulated: 16 use `fsin`, which the lifter does not support, and `0x10104280` has an unresolved jump table. With rlmfc (1,648) and grphmfc (409): 4,812 entries in `build-lift/liblifted.dylib`. |
| Same behaviour | Differential run (80 frames, first 50 calls of each function): 858 functions reached, 38,476 calls compared, 856 match exactly. The two that do not: `R_System::getProcessorSpeed` (rdtsc, as in M5), and `P_Device::P_Device`, a divergence "unreplayable HLE KERNEL32.DLL!LoadLibraryA". LoadLibraryA runs the driver's DllMain as guest code, which the replay cannot reproduce. This is a limit of the differential mode, not a lifter finding. No reference failures. |
| Native run | 80-frame workload: 4 of 4 runs clean, 0 fallbacks, 0 unwinds. |
| Tests | `lift/test_bridge.py`, `test_build.py`, `test_diff.py`, `test_functions.py`, `test_ops_x87.py`: 74 passed. |

Commands:
```
lift/functions.py "Max Payne/e2mfc.dll"   # and rlmfc, grphmfc as before
lift/build.py --module rlmfc.dll --module grphmfc.dll --module e2mfc.dll --entries real --lib build-lift/liblifted.dylib [--write-log --lib build-lift/liblifted_wlog.dylib]
emu/run_init.py "Max Payne" --frames 80 --input "25:key=1c,26:keyup=1c" --native-lift build-lift/liblifted.dylib --lift-modules rlmfc.dll,grphmfc.dll,e2mfc.dll
emu/run_init.py ... --diff-lift build-lift/liblifted_wlog.dylib --lift-modules rlmfc.dll,grphmfc.dll,e2mfc.dll --diff-k 50 --diff-report lift-out/diff_e2mfc_final.json
```

## Speed
80-frame workload, same machine, runs back to back (`lift-out/time_e2mfc_*.log`).

| | InitInstance | Main loop | Entries into native code (main loop) | Guest calls from native code (main loop) |
|---|---|---|---|---|
| Fully emulated | 9.9 s | 27.4 s | none | none |
| rlmfc + grphmfc native | 13.5 s | 29.4 s | 8.02 M | 0.32 M |
| rlmfc + grphmfc + e2mfc native, run 1 | 14.2 s | 32.0 s | 9.15 M | 2.15 M |
| rlmfc + grphmfc + e2mfc native, run 2 | 13.0 s | 29.0 s | 9.15 M | 2.14 M |

Runs vary by about 10% on this machine, so lifting e2mfc made no measurable difference. Two things explain it.

**Who calls into native code.** The fast path now counts entries into native code by return address (`lift_fast_entry_callers`). `run_init.py` prints the main loop's totals per module and the top callers (`--caller-top N`). With all three modules native:

| Caller module | Entries |
|---|---|
| `maxpayne.exe` | 8,748,987 (96%) |
| `e2_d3d8_driver_mfc.dll` | 183,385 |
| `grphmfc.dll` | 98,701 |
| `msvcrt.dll` | 52,179 |
| `e2mfc.dll` | 41,940 (157,575 before e2mfc was lifted) |
| `sndmfc.dll` | 8,969 |

The exe's hottest call sites call small rlmfc functions through the IAT: the `R_MemoryFile >>` stream readers (bool, float, `M_Vector3`, `M_Matrix4x3`), `std::rs::_Freeze`, string `operator<`, and `~R_Memory`. Each does little work, so the interrupt and register sync of every entry dominate. The exe has no function inventory yet, so the caller's function shows as "unknown".

**New guest calls from e2mfc.** e2mfc fills vertex and index buffers through the d3d8 driver's virtual setters. The driver is still emulated, so these became guest calls from native code: `P_D3DDDIndexBuffer::setIndex` 546 k, `P_D3DDDVertexBuffer::setTextureCoordinate2D` 385 k, `setTransformedPosition` 247 k, `setDiffuseRGB` 243 k, `setFog` 229 k. Main-loop guest calls rose from 0.32 M to 2.15 M.

**What is left.**
- Lifting the exe turns the exe's ~8.7 M entries into native-to-native calls. It is the large remaining step (4.9 MB, `stxt*` sections, R1).
- Lifting `e2_d3d8_driver_mfc.dll` removes the vertex-setter guest calls.
- `sndmfc.dll` is small and little called.

## What changed, and why
- **More fast slots:** the fast path had 4,095 slots, which is too few for 4,812 functions. `FAST_SLOTS` is now 16,384 (`emu/native.py` `FAST_SIZE` 0x40000, `runtime.c`).
- **Diff mode stops native code at a divergence.** The first three-module diff aborted with "write log full (65536 pages)" in `P_Device::P_Device`. The cause was not a lifter bug:
  - After the HLE replay diverged (the unreplayable `LoadLibraryA`), every later guest call from native code returned at once, without popping stdcall arguments or setting a result.
  - A lifted loop of guest calls in the constructor then never ended. Each iteration leaked stack, esp walked down 256 MB through address 0, and the pushes filled the write log.
  - Now `_call_guest` calls `lift_diff_abort`, and the guest trampoline longjmps back to `lift_invoke_checked` when no Python callback is active. `lift_invoke_checked` returns 0 (returned), 1 (#DE) or 2 (aborted after a divergence).
  - Tests: `test_diff.py` checks that a lifted loop of guest calls matches the emulator, and that a forced divergence stops it at once.
- **x87 exception bits follow the emulator.** `P_Camera::setFOV`, `setFrontPlane` and `setBackPlane` read the status word with `fnstsw ax` after a divide by zero. The reference had ZE (0x0004) set, and the lifted code did not. Probing Unicorn 2.1.4 (qemu 5 era) over the arithmetic, compare, load and integer-store instructions showed:
  - A divide with a zero divisor sets ZE, whatever the dividend (0/0 and NaN/0 included). `x87_div_flags` now does the same.
  - Nothing else sets an exception bit: overflow, underflow, inexact, inf−inf, 0·inf, sqrt(−1), inf/inf, and out-of-range or NaN `fist`/`fistp` (m16/m32/m64) and msvcrt `_ftol` all leave the status word alone. `x87_ival` and the `_ftol` helper set IE before; they no longer do. The `docs/m6-grphmfc.md` line that says the `_ftol` helper sets IE is out of date.
  - The sticky bits IE..PE are now synced both ways with the C bits. Before, the sync dropped them, so native code never saw inherited bits and the emulator never saw native ones.
  - Real x87 hardware differs: it sets IE for 0/0, inf/inf and invalid integer stores, and no ZE for 0/0. The emulator is the oracle while it exists. When it is removed, decide whether to keep the emulator's behaviour, which is what the game was tested against here, or switch to the hardware's, which is what the game was written for.

## How it was done
Opus chose the work, triaged each result, and reviewed and merged every change. Haiku agents did the work in separate worktrees:
- **H7:** counted entries into native code per caller.
- **H8:** e2mfc inventory, build and runs. Opus diagnosed the write-log overflow from H8's register and page-range dumps (esp at 0xf0302000, after a descending wrap), and H8 then implemented the abort and the x87 probes and fixes.

## Open
- **`fsin`:** 16 e2mfc functions stay emulated until the lifter has `fsin`, which must match the emulator's result bit for bit.
- **`P_Device::P_Device` is never compared:** LoadLibraryA cannot be replayed. A narrower check is possible: compare the code before the LoadLibraryA call, or record DllMain as a nested call.
- **Abort inside nested native runs:** the abort longjmps only when no Python callback is active. A native function run from inside a guest call that was itself called from native code keeps running after a divergence until control returns to the outer level. No such case was seen.
- **`setAlphaReference`:** one diff run reported "reference did not return", with the emulator stopped at the function's own entry. It did not recur in the final run and was not explained.
- **x87 exception policy** after the emulator is removed (see above).
