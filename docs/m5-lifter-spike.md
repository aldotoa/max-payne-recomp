# M5: lifter spike, design and findings

## Goal and done-when
Lift `rlmfc.dll` to native arm64 with a custom x86 → C translator, link it back into the emulated process, and differential-test it function by function against the emulator. Done when rlmfc runs lifted with the same behaviour over a recorded workload and performance is acceptable (PLAN.md §5).

## Pieces
| Piece | Where |
|---|---|
| Guest CPU contract | `lift/runtime/cpu.h` |
| Flag helpers | `lift/runtime/flags.h` |
| Function inventory | `lift/functions.py` → `lift-out/rlmfc_functions.json` |
| Translator | `lift/x86c.py`; instruction families in `lift/ops_*.py` |
| Per-instruction differential rig | `lift/insnrig.py` |
| Guest memory in one host buffer | `Emu.mem`, `Emu.mem_base`, `Emu.map` |
| Emulator undo log | `Emu.undo_begin/undo_end/undo_rollback` |
| Build of the lifted module | `lift/build.py` → `build-lift/librlmfc.dylib` (`--write-log` for diff mode) |
| Bridge and fast path | `emu/native.py`, `lift/runtime/runtime.c` |
| Differential mode | `Native.run_diff`; `emu/run_init.py --diff-lift` |
| Native game run | `emu/run_init.py --native-lift` (fast path), `--native-lift-slow` |
| Benchmark | `lift/bench_native.py` |

## Decision: GO
The custom x86 → C lifter works on real code and makes it much faster. M6 (lift everything) should go ahead with it; no switch to a JIT/DBT end state is needed.

| Check | Result |
|---|---|
| Translation | 1,369 of 1,370 rlmfc functions translate with no unsupported instruction. The exception is `determineProcessorCaps` (`popfd` ID-bit probe), which runs once and stays emulated. |
| Same behaviour | Differential game run: the first 50 calls of each function, 10,850 calls in 237 functions. 236 match exactly (registers, flags, x87, every byte written). The one that doesn't is `getProcessorSpeed`, which is rdtsc-based by design. No divergences. |
| Lifted code speed | On equal work, from the same inputs, with identical outputs: `R_Memory::copy` of 4 MB takes 0.77 ms native against 16.6 ms emulated (21.7×). A 3×3 matrix times 200,000 vectors (x87) takes 4.2 ms against 48.3 ms (11.4×). Unoptimised C with eager flags, `-O2`. |
| Game with rlmfc native | 80-frame scripted run, fast path, 9.2M native calls. Main loop 31.8 s against 27.9 s emulated; InitInstance 26.9 s against 9.8 s. |

The game run is slower even though the lifted code is faster. rlmfc is only about 5% of the game's work (1.6 s of the main loop is lifted code), and nearly every call into it crosses the boundary from emulated code. That boundary costs about 0.33 µs per call through the C fast path, against 0.02 µs for an emulated call. InitInstance loads the archives through many small `R_MemoryFile` reads, so it pays the most. The slowdown is a cost of running mixed, not of the lifted code. Two things follow:
- In M6, calls between lifted modules become plain C calls and the boundary disappears. The 11–22× applies to the whole program, not to 5% of it.
- Lifting module by module (M6's plan) is only faster per step for modules whose callers are already lifted. Lift in caller-first order (exe and e2mfc together with rlmfc), or accept slower intermediate builds. Don't judge progress by the speed of half-lifted builds.

Frame 60 of the native-rlmfc run against the emulated run: mean error 0.33, 1.2% of pixels off by more than 8. The game runs on the host clock, so these runs reach different game times and this comparison can't show identity. The differential run is the evidence for that.

### What M6 has to add
- **Exceptions through lifted frames:** the MSVC frame-handler protocol. `_except_handler3` scope tables and `__CxxFrameHandler` FuncInfo, run by the runtime against the guest-memory SEH chain. A throw from an emulated or HLE callee into a lifted caller has to unwind host frames too: setjmp at each lifted function that registers a frame, longjmp to the handler's frame. Not exercised in M5; nothing threw through native code in the workload.
- **Indirect calls across modules:** one global address → function table for all lifted modules. `lift_call` already falls back to the emulator for addresses outside it.
- **A clean `MaxPayne.exe` (R1)** before lifting the exe.
- **Optimisation:** compute flags lazily instead of eagerly (most are dead), and keep x87 values in locals across a block. Not needed for correctness; both make the C smaller and faster.
- **Emulator regressions to revisit while it remains the fallback:** the host-buffer memory costs 8%. A timer stop that lands inside native code is not honoured until the call returns. Nesting is limited to 60 levels.

## Memory model
All guest memory is one 4 GB anonymous host mapping, and every emulator region is mapped into it with `uc_mem_map_ptr`. Guest address A is host address `mem_base + A`, so lifted code reads and writes guest memory directly. The guest stack, TEB (the `fs:[0]` SEH chain) and heap are shared with the emulator and need no syncing.

Cost: the 80-frame scripted run's main loop went from 26.4 s to 28.7 s, and InitInstance from 9.5 s to 10.1 s (means of three alternating runs). The cause is not known yet. The Unicorn patches don't depend on how a RAM block was allocated. Revisit this if the emulator stays on the critical path.

## Calling convention between lifted code and the emulator
- A lifted function is `void f_<va>(CPU *c)`. It is entered with the return address already at `[esp]` and leaves the guest stack exactly as the original would. Lifted-to-lifted direct calls push the real return address and call the C function. `ret N` discards it and adds N.
- `c->call_guest(c, addr)` runs guest code at `addr` in the emulator. The caller does **not** push a return address: the bridge pushes its own return slot, runs until the guest returns there, and syncs registers back. Stdcall arguments are popped by the guest's own `ret N`. A tail jump to an import is therefore `esp += 4; call_guest(...); return;`.
- `lift_call(c, target)` handles calls only known at run time. It uses the lifted function for `target` if one exists (pushing a dummy return address first), and otherwise falls back to `call_guest`.

## Bridge (emulator → lifted → emulator)
- An entry patched to native gets `jmp <native slot>`, where a native slot is a `hlt` slot in the stub range, as for imports.
- When the guest reaches a slot, the stub hook records the target and calls `emu_stop`. The Python driver (`Emu.call`/`resume`) sees the pending native call after `emu_start` returns. It copies Unicorn's registers into a `CPU`, calls the C function through ctypes, copies back, and sets EIP to the popped return address before resuming.
- `call_guest` is a ctypes callback. It copies the CPU into Unicorn, pushes the return-to-host slot, and runs `emu_start` from the target until that slot. The Python driver loop handles nested native calls by recursion. `emu_start` is never re-entered from inside a hook.

## Differential mode (record, then replay)
The per-function check cannot snapshot host state (heap allocator, handles, open files), and copying memory is too slow. So:
1. **Emulated run, recorded.** At a call to function F: `undo_begin`, then run F in the emulator. Every call F makes out of rlmfc (imports, HLE stubs, code in other modules) is recorded as an *external call*: its target, the registers on entry, the argument words, the registers on return, and the memory it wrote (an undo log nested inside the outer one). Then `undo_end` gives F's final registers and memory writes.
2. **Rollback**, then **native run, replayed.** Run lifted F with `call_guest` in replay mode. Each external call must match the next recorded one (same target and arguments). Instead of running it again, replay applies the recorded registers and memory writes. A mismatch, an extra call or a missing call is reported as a divergence.
3. **Compare** registers, flags (minus flags the last instruction leaves undefined), x87 and the full set of written bytes.
4. **Continue with the emulator's result.** Roll back the native run and re-apply the emulator's final state, so a wrong lifted function never corrupts the game. F is marked emulator-only after its first mismatch.

Calls from F into other lifted rlmfc functions stay inside the native run, so the comparison covers whole call trees. Recursion into the exe (virtual calls back into game code) counts as an external call.

## Exceptions (SEH and C++ EH)
The SEH chain lives in guest memory, so lifted code that links frames through `fs:[0]` works unchanged. For M5, an exception raised while a native frame is on the host stack is caught at the bridge, the function is marked emulator-only, and the call is replayed in the emulator. A real implementation of the frame-handler protocol is M6 work and is designed in the findings below.

## Findings

### Function inventory
- `lift/functions.py` finds 1,386 functions; Ghidra counts 1,582.
  - All 907 code exports are function entries. The other 73 exports are vtable data.
  - 780 vtable slots. 155 functions set up SEH frames.
  - Seeding from exports, vtables and direct calls alone finds 1,068 functions. A gap scan adds the rest.
- Switch tables: 4 switch-style `jmp` sites. Two are recovered; the other two use a byte index table first.

### Translator coverage (rlmfc, after the integer, string, x87 and odd-instruction families)
1,371 of 1,386 functions (98.9%) translate with no unsupported instruction, and none fail to translate. The 15 left:
- `R_Memory::set` and `R_Memory::copy`: MMX `movq`/`emms`. These are the hot memset and memcpy, gated by the CPU caps.
- `R_System::determineProcessorCaps`: `popfd` with the ID-bit (bit 21) toggle, and an `orps` inside the cpuid-gated path. It runs once.
- 5 functions with switch jump tables.
- A few gap-scan "functions" that are really data: `int`, `in`, `outsd`, `int1`, `(bad)`.

### x87 on doubles
Checked instruction by instruction against Unicorn with random stacks. The double model matches Unicorn except in these cases:
- **Exponent range:** a product or quotient that overflows double stays finite in the 80-bit registers. This shows up only for random inputs near 1e308. The game's values are nowhere near that.
- **`fcomi` family:** the SDM clears OF, SF and AF; Unicorn leaves them. The lifted code follows the SDM. Compiled code never reads those flags after `fcomi`.
- **Stack faults** (reading an empty register, pushing onto a full stack): modelled the way Unicorn behaves, not as the SDM describes. Correct code never does this.
- **`fldcw`** sets the host rounding mode with `fesetround`, so arithmetic under truncation rounds the way x87 does. The bridge must set host rounding from `cw` on entry to native code and restore round-to-nearest on exit (to do).
- **Precision control 24-bit:** results are rounded to float. 64-bit precision is treated as 53-bit; the game never asks for it.

### Odd instructions
- `cpuid` returns a table of Unicorn's answers (its qemu32 model), so lifted and emulated runs see the same CPU.
- `rdtsc` (in `R_Profile::readTickCount`) is monotonic host time. It does not match the emulator, which returns a constant.
- `pusha`/`popa`: rlmfc uses the 16-bit forms (`66 60`/`66 61`); both widths are implemented.
- `pushfd` is implemented. `popfd` is rejected: Unicorn keeps IF, IOPL, NT, AC and ID through it, and the CPU struct has no place for them.

### Differential run of the game (the M5 correctness evidence)
Workload: the standard scripted run (start-up, menu, Enter, tutorial level, 80 frames), command `emu/run_init.py "Max Payne" --frames 80 --input "25:key=1c,26:keyup=1c" --diff-lift build-lift/librlmfc_wlog.dylib --diff-inventory lift-out/rlmfc_functions.json --diff-k 50`.
- Setup: 1,369 of 1,370 rlmfc functions lifted, and 1,071 real entry points hooked.
- Calls compared: the first 50 calls of each function, which came to 10,850 calls in the 237 functions the run reaches.
- **Results:** 236 of the 237 functions match exactly, with no divergences and no reference failures. Each comparison covers registers, all six arithmetic flags plus DF, x87 state and every byte written. The one exception is `R_System::getProcessorSpeed`, which times the CPU with `rdtsc`; the emulator's `rdtsc` is constant, so this mismatch is expected.
- The first run found 19 functions that differed only in AF. Matching Unicorn (qemu) on the flags the manual leaves undefined fixed them, and checking every form then showed the same kind of difference in shr/shrd/rcl/rcr OF and in 16-bit shld/shrd counts above 16 (see `lift/runtime/flags.h`). Each ALU form now matches Unicorn on every flag over random states.
- Not covered:
  - Functions the run never reaches (about 1,130 of the 1,369). The instruction rig and the synthetic tests are the only checks on those.
  - Exceptions thrown through lifted frames, which did not occur.
- Timing of the run: InitInstance 143 s, main loop 47 s (normally 10 s and 28 s). Diff mode is a test mode and is expected to be slow.

### Emulator costs and quirks found on the way
- **Host-buffer memory** costs about 8% in the emulator's main loop (see Memory model).
- **Deleted hooks:** Unicorn keeps a deleted hook working until the next `uc_emu_start` ends, and translated blocks keep calling it. The store slow path stayed about 6× slower after `undo_end` until `_remove_undo_hook` ran an empty `emu_start` and flushed the translation cache.
- **Host writes:** Unicorn does not invalidate translated blocks when the host writes guest memory directly. Installing or removing a native entry therefore flushes the translation cache.
- **Undo-log cost:** with a log active, each guest store costs about 0.7 µs extra (Python hook). Rolling back 64 KB takes under 1 ms.
- **Bridge cost:** the first bridge took 72 µs per native call against 13 µs emulated, mostly register sync through the Python binding. Moving the sync to C, and syncing x87 only for functions that can touch it, brought it to 16 µs. The fast path dispatches inside a C code hook and uses nested `uc_emu_start` for guest calls (Unicorn 2.1.4 allows 64 levels), bringing it to 0.33 µs. An in-guest emulated call costs 0.02 µs.
- **EIP from a C hook:** set it with a single `uc_reg_write`. `uc_reg_write_batch` doesn't set `skip_sync_pc_on_exit`, and Unicorn then resets EIP to the hooked address.
