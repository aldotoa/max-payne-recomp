# M6: grphmfc lifted to native

## Result
`grphmfc.dll` (image loading: JPG, TGA, PCX, DDS, SCX) is lifted to native C and runs with `rlmfc.dll` in one native library. The rlmfc+grphmfc differential game run matches the emulator in every function it reaches, except `getProcessorSpeed`, which is expected. The native game run is stable.

| Check | Result |
|---|---|
| Lifted | grphmfc: 409 of 411 real entries (the other 2 call setjmp and stay emulated). rlmfc: 1,648 of 1,649. One library: `build-lift/liblifted.dylib`, 2,057 entries. |
| Same behaviour | Differential run with the native CRT helpers (80 frames, first 50 calls of each function): 386 functions reached, 17,934 calls compared, 385 match exactly, no divergences, no reference failures. The one mismatch is `R_System::getProcessorSpeed` (rdtsc, as in M5). This run reached 4 functions the earlier run (382) did not: `R_Exception` members called from the exe's intro-movie error path (`VFW_E_NOT_FOUND`). Plain emulation reaches that path too. Why the earlier run did not reach it was not looked into. |
| Native run | InitInstance: 6 of 6 runs clean. The full 80-frame workload completes. |

Commands:
```
lift/functions.py "Max Payne/rlmfc.dll"; lift/functions.py "Max Payne/grphmfc.dll"
lift/build.py --module rlmfc.dll --module grphmfc.dll --entries real --lib build-lift/liblifted.dylib [--write-log --lib build-lift/liblifted_wlog.dylib]
emu/run_init.py "Max Payne" --frames 80 --input "25:key=1c,26:keyup=1c" --native-lift build-lift/liblifted.dylib --lift-modules rlmfc.dll,grphmfc.dll
emu/run_init.py ... --diff-lift build-lift/liblifted_wlog.dylib --lift-modules rlmfc.dll,grphmfc.dll --diff-k 50 --diff-report lift-out/diff.json
```
The `.venv` must have the patched libunicorn (`tools/build_unicorn.sh`). The native fast path depends on `tools/unicorn-2.1.4-jit-guard.patch`.

## Speed
80-frame workload, same machine, runs back to back (lift-out/time_*.log). "CRT helpers" means native `_ftol` and `tolower` (see below).

| | InitInstance | Main loop | Guest calls from native code (main loop) |
|---|---|---|---|
| Fully emulated | 9.0 s | 24.2 s | none |
| rlmfc native, no CRT helpers | 26.7 s | 36.1 s | 0.52 M |
| rlmfc native, CRT helpers | 14.1 s | 32.7 s | 0.30 M |
| rlmfc + grphmfc native, no CRT helpers | 34.5 s | 63.5 s | 19.4 M |
| rlmfc + grphmfc native, CRT helpers | 13.2 s | 28.3 s | 0.32 M |

The earlier table (11.1/30.5 s emulated, 26.9/34.7 s rlmfc native, 34.4/57.8 s both native) came from a slower day on the same machine. Compare rows within one table only.

**Where the guest calls came from.** The fast path now counts guest calls from native code per target. `run_init.py` prints the main loop's top targets. Before the helpers, in the main loop (both modules native):

| Target | Calls |
|---|---|
| `msvcrt.dll!_ftol` | 18,846,610 (97%) |
| `msvcrt.dll!tolower` | 214,966 |
| `mfc42.dll+0x3877` | 100,821 |
| `msvcrt.dll!free` | 72,918 |
| `msvcrt.dll!_stricmp` | 55,943 |
| `msvcrt.dll!memmove` | 31,117 |

rlmfc's MMX `R_Memory::copy` and `R_Memory::set` were never among them: both are lifted, and grphmfc reaches them natively through `lift_call_ret`.

**Native CRT helpers** (`lift/runtime/crt.c`):
- `lift_call_ret` and `lift_jump` run a C helper when the target is a bound MSVCRT import. Otherwise they make a guest call, as before.
- Each helper does exactly what the guest code does on the path it handles: registers, flags, x87 state, and the bytes it leaves below esp (return address, saved registers, locals).
- `_ftol`: truncates `st(0)` the way `fistp qword` does under the caller's control word with RC = chop, then pops the x87 stack. Out of range or NaN gives `0x8000000000000000` (edx `0x80000000`). (It set IE at first; it no longer does, matching the emulator: see `docs/m6-e2mfc.md`.) The flags are those of `or ah, 0xc`. The host rounding mode is not touched.
- `tolower`: handles only the "C" locale path (`__lc_handle[LC_CTYPE]` = 0). Any other locale goes to the guest.
- `emu/native.py` `CRT_HELPERS` binds a helper only when the guest bytes at its address match the code it reproduces.
- `--no-native-crt` turns the helpers off.
- `lift/test_bridge.py` `test_crt_helpers_match_guest` checks 1,280 cases three ways (emulated, guest call, helper) in both dispatch modes. The cases cover all rounding modes, both precisions, values at the int32 and int64 limits, infinities and NaNs, a tail jump to `_ftol`, the ASCII boundaries for `tolower`, and the non-"C" locale, which the helper declines.

**Profile counters.** `native_ns` and `guest_ns` are now exclusive times. Each hook subtracts only the guest calls it made itself. A native call inside a guest run is not counted as that run's guest time. In the last row, 3.18 s native plus 3.01 s guest is the time spent inside native calls.

**What is left.** With the helpers, the main loop is 17% slower than the emulator, down from 2.6 times slower. Guest calls from native code are no longer the main cost: 0.32 M calls take 3.0 s, and much of that is real work (`free`, `_stricmp`, file I/O). The main cost now is entering native code: 8.0 M fast-path calls from emulated code, each an interrupt plus a register sync. The next candidates are:
- Lift the hottest emulated callers, so those calls become native-to-native.
- Make the per-call sync cheaper.
- `mfc42.dll+0x3877`, `free` and `_stricmp` are the next helpers if guest calls matter again.

## What changed, and why
- **Rebase** (`lift/modbases.py`): the lifter maps each DLL at the emulator's load base and applies its base relocations. grphmfc prefers 0x10000000, the same as rlmfc, but the emulator loads it at 0x10200000.
- **Multi-module build** (`lift/build.py --module`, `run_init.py --lift-modules`): one library, one `lift_table`. The runtime keeps per-library state, and `Native` binds one library per emulator.
- **Calls between lifted modules:** IAT calls and indirect calls go through `lift_call_ret` / `lift_jump`, which run a lifted target directly and push the real return address. `jmp [reg+disp]` (an MSVC virtual tail call) is lifted the same way.
- **Function inventory:**
  - The switch bounds check is found up to 40 instructions before the jump (was 12).
  - Every relocated pointer into code seeds a function entry ("address-taken"). This finds 220 grphmfc functions reached only through stored code pointers.
  - An entry whose 5 patched bytes would overlap another real function's code stays emulated (6 entries across both modules).
- **setjmp/longjmp:** a function that calls them (loadJPG and its `_setjmp3` thunk) stays emulated (`build.py` SETJMP). Lifted, setjmp saved the bridge's return slot.
- **The return-address slot:** a real `call` leaves the return address in the slot below the caller's esp. The bridge left its own return address there. Emulated game code copies such slots as uninitialised locals (`saveBufferTGA`, the `G_Image` file buffers), and every remaining diff mismatch came from this. `lift_guest`, `lift_call_ret` and `lift_jump` now restore the slot.
- **Guest unwinds past native frames:** each nesting level returns to its own address (`fast_ret`). A guest longjmp or throw that returns to an outer level's address drops the native frames in between, one level at a time.
- **Interrupt dispatch** (the intermittent native crash):
  - The cause: the fast path ran native code from a `UC_HOOK_CODE` hook, inside the guest's translated block, and returned into it. Unicorn flushes its translation cache when the code buffer fills. A flush during a nested run left that return address pointing at reused memory: SIGILL, SIGSEGV or SIGBUS depending on timing (found with lldb, `tb_gen_code → tb_flush` under `fast_call_guest`).
  - The fix: slots now start with `int 0x99`, dispatched by a `UC_HOOK_INTR` hook. Unicorn calls it with no translated code live on the host stack.
  - On Apple Silicon this needed `unicorn-2.1.4-jit-guard.patch`. Unicorn's hook guard restored the thread's JIT mode but not its cached copy, so the next block ran with the JIT area writable.

## How it was done
Opus designed the work and reviewed and merged every change. Haiku agents did well-specified pieces in separate worktrees or as read-only investigations:
- **H1:** rebase.
- **H2:** multi-module build.
- **H3:** classified the unresolved indirect jumps with capstone.
- **H4:** switch bounds and address-taken seeding.
- **H5:** traced the remaining diff mismatches to the return-address slot.
- **H6:** bisected the native crash and showed it was intermittent rather than tied to one function.

## Open
- **Code-buffer fill rate:** Unicorn's 1 GB code buffer fills (and flushes) several times per InitInstance. That is no longer a correctness problem, but it is unexplained and costs retranslation time.
- **Unreached functions:** about 1,700 lifted functions are never reached by the workload. The instruction rig and the synthetic tests are the only checks on them.
- **Exceptions:** C++ exceptions through lifted frames still rely on the guest unwinding and on the fast path dropping native frames. The MSVC frame-handler protocol (M5 findings) is not implemented.
