# M6: removing the emulator

End state (PLAN.md M6): one native process with no Unicorn and no Python. The guest image, the lifted code and the
HLE layer are all C/Objective-C. The emulator stays as an offline oracle (diff runs, `run_init.py`), not in the
shipped process.

## Where it stands (2026-10-24, main after H54)
- **Lifted:** the five game modules (rlmfc, grphmfc, e2mfc, sndmfc, the D3D8 driver) and the exe (`--entries real`),
  plus 61 MSVCRT and 18 MFC42 functions (`lift/msvcrt_entries.txt`, `lift/mfc42_entries.txt`).
- **Still emulated:** the exe entry point 0x76fb04 and WinMain 0x783860 (`--keep-emulated`; `run_init.py` stops at
  AfxWinMain and calls `CMaxPayneApp::InitInstance` directly, then drives the main loop itself); the rest of MSVCRT,
  all of MFC42 but the heap entry points, all of MSVCP60 and MSVCIRT; the setjmp users (8 driver functions,
  `G_Image::loadJPG`); the MSVCRT EH/SEH set (`lift-out/keep_crt.txt`: `_setjmp*`, `longjmp`, `_EH_prolog`,
  `__CxxFrameHandler`, `_CxxThrowException`, `_except_handler2/3`, `_global_unwind2`, `_local_unwind2`); 2 grphmfc
  functions (`lift/keep_emulated.txt`); the drops listed below.
- **HLE in Python:** 546 handlers in `emu/mpemu.py` (KERNEL32 208, USER32 199, GDI32 113, ADVAPI32 14, MFC42 6,
  OLE32 3, SHELL32, WINMM, NTDLL), plus the COM layers `emu/d3d8.py`, `dsound.py`, `dinput.py`, `dshow.py`, the
  window and message system `winsys.py` and `launcher.py`. In C already: the hot D3D8 calls (`hle_fast.c`), the
  guest heap (`heap.c`), the renderer (`render/mprender.m`) and the mixer (`audio/mpaudio.c`).
- **Who calls Win32:** mostly the runtime DLLs. MFC42 imports 426 USER32/GDI32/KERNEL32 functions, MSVCRT 144
  KERNEL32; the game modules import about 190 Win32 functions between them.

## Dry lift of the runtime DLLs (H55, `lift-out/runtime_dlls_dryrun.json`)
All real entries of each inventory, lifted without compiling (keep lists not applied):

| Module | Entries | Thunks | Lifted | Dropped | Drop causes |
|---|---|---|---|---|---|
| MSVCRT.DLL | 1,279 | 5 | 1,240 | 34 | x87 `fprem`/`fprem1` (8: `sin`, `cos`, `tan`, `_adj_fprem*`, `fmod` internals), `fscale` (6), `frndint` (4), `fnsave` (`pow`); `xlatb` (2); `jmp eax` (4, EH funclet calls at 0x7800ac4f..0x7800ac8a); `int3`/`int 6` (`_assert`, `_chkesp`, `_adj_fdiv_r`); port I/O (`_inp*`/`_outp*`, never called) |
| MSVCP60.DLL | 3,199 | 31 | 3,168 | 0 | |
| MSVCIRT.DLL | 547 | 11 | 536 | 0 | |
| MFC42.DLL | 10,064 | 16 | 9,688 | 360 | all delay-load stubs: `jmp eax` (275, the resolver's tail) and `jmp [slot]` (85, the bound slot) |

So the lifter is not what blocks the runtime DLLs: four x87 instructions and `xlatb`, binding MFC42's delay imports
at load (the stubs then never run), and the exception machinery.

## Phases, in order
**E1. Indirect jumps (H55, done).** Of the exe's "18 unresolved indirect jumps" (16 in today's inventory), 14 are
virtual tail calls `jmp [reg+disp]`, which the lifter already emits as `lift_jump`; 0x4618fc is a pointer seed into
data; the one real switch, 0x776e5a, now resolves. See H55 in `docs/m6-exe-progress.md`.

**E2. The rest of MSVCRT, MSVCP60, MSVCIRT and MFC42 lifted (H56, done but for the diff run).** All four lift with
only E3's EH funclets and never-called functions dropped; the overlap guard no longer limits the lift; MFC42's delay
imports are bound at load. The main loop's guest code is now `_EH_prolog` and `loadJPG` only. Left: a diff run. The
original items:
- x87 `fprem`, `fprem1`, `frndint`, `fscale`, `fnsave` in the lifter (qemu 5 semantics, checked against Unicorn as
  H38/H40 did); `xlatb`.
- MFC42 delay imports bound at load (the loader writes the final target into each delay IAT slot), so the 360 stubs
  are unreachable; then keep them out of the lift set like import thunks.
- The patch-overlap guard's exclusions (112 MSVCRT, 376 MFC42 entries, H31) re-checked against the current
  inventories.
- Done when: `--entries real` for all four with only never-called functions dropped, and a diff run clean.

**E3. Exceptions and setjmp in native code (PLAN R3). Done: design H57, implementation H58, a real-game throw and catch verified in H59.** The MSVCRT
EH/SEH set and the setjmp users cannot stay emulated. Lifted code runs on the host stack, and a lifted `ret` is
`ESP += 4; return`: control flow lives in the C frames. A guest `throw`, `longjmp` or `__except` sets ESP/EBP and jumps
into the middle of a function whose frame is further up, so those C frames must go too.

*Design (H57, `x86c.DEAD_FRAMES`, `build.py --dead-frames`), no host longjmp:*
- **Continuation entries.** Every address a transfer lands on is lifted as an *aux entry*: a function starting there,
  in the table, never known to the lifter as a direct call or jump target (so a loop inside the owning function stays
  a goto, and nothing recurses). The transfer is a `lift_jump` to it (`jmp reg` lifts as lift_jump under the flag:
  MSVCRT `_JumpToContinuation` 0x7800ac4f, `_CallMemberFunction0..2`). All guest state is in `CPU` and guest memory
  at a block boundary, so running the rest of the function from a separate C function is exact.
- **Dead-frame return.** Each lifted function keeps a frame bound (`xesp0`: its entry ESP; after an explicit ESP
  load, and for a continuation entry from the start, at least EBP + 4, the owner's entry ESP, H59) and after every call
  returns at once if the guest ESP is above it (`if (c->r[ESP] > xesp0) return;`): the guest discarded the frame. A live frame's ESP
  after a call is at or below its entry ESP. So the continuation runs *on top* of the host stack; when it returns
  (its `ret` pops the owning function's return address), the C frames between the transfer and the caller the guest
  returns to are dead and fall through one by one, and that caller is live and continues after its call, exactly
  where the guest returns.
- **What lands where.** Catch: `__CxxFrameHandler` runs the catch funclet (`_CallSettingFrame`, a call), which returns
  the continuation; `_JumpToContinuation` sets ESP/EBP and jumps. `__except`: `_except_handler3` restores ESP/EBP and
  jumps to the scope entry's handler. longjmp: restores EBP/ESP and jumps to the saved return point of the setjmp call.
  `RtlUnwind` resumes at TargetIp (the return point after its own call in `_global_unwind2`). Funclets (catch, unwind
  actions, filters, `__finally`) are called by address and are ordinary entries.
- **Found statically** (`tools/m6/continuations.py`, list in `lift/aux_continuations.txt`): FuncInfo stubs
  (`mov eax, FuncInfo; jmp __CxxFrameHandler`) -> try map -> catch funclets -> the `mov eax, cont ... ret` they return;
  scope tables pushed with `_except_handler3`; calls to `_setjmp`/`_setjmp3`/`RtlUnwind`. 10 modules: **369
  continuations** (catch 319, `__except` 47, setjmp 4, RtlUnwind 2) over 6,633 FuncInfo and 49 scope tables; ~25k
  funclets, **all already inventory entries**. Of the exe's 657 catch funclets 622 return nowhere: every path is a
  `throw;` rethrow (checked), so the exe's list is complete.
- **Checked:** `lift/test_dead_frames.py`, every function lifted: a catch-shaped transfer into a label that only the
  transfer reaches, and setjmp/longjmp three times over (continuation also reached by normal flow, nesting on the host
  stack), both fully native (one fast-path entry, 0 guest calls) and equal to the emulated reference in result,
  markers, ESP and stores. The whole game built with the check (`liblifted_full_h57df`, H56 config, EH set still
  emulated): 80 frames clean twice, guest calls unchanged (15.0 k: the check never fires falsely), **native time +4%**
  (5.52/5.46 s vs 5.30/5.24 s, alternating).
- **Limits.** Each throw caught in a frame that stays live nests one continuation deeper on the host stack until that
  frame returns; fine for the rare throws here, fatal for a loop that throws every iteration (count the depth and
  stop with a message; if it ever matters, a setjmp only in the functions that own continuations). In the hybrid a
  native transfer cannot cross the Python `RaiseException` coroutine (it would resume on a stale guest state), and
  setjmp users must stay emulated (a lifted call to the emulated `_setjmp3` pushes the bridge's return address), so
  the real game's throws stay emulated until the next step.

*Implementation (H58, done):* `RaiseException` and `RtlUnwind` in C (the two passes of `emu/mpemu.py`'s coroutines, the
dispatcher's own registration record around each handler call: m2-progress, `test_seh.py`), calling the lifted
handlers through lift_call; then lift the MSVCRT EH set (`_EH_prolog`, `__CxxFrameHandler`, `_CxxThrowException`,
`_except_handler3`, `_global_unwind2`, `_local_unwind2`, `longjmp`, `_setjmp3`) and the setjmp users with
`--dead-frames --aux-entries-file lift/aux_continuations.txt`; a host-stack depth guard.
- Done when: `test_seh.py`'s scenarios and the M2 throw scenario (R_FileException from `changeDirectory`) pass with
  no guest code emulated.

**E4. The entry point and WinMain lifted (H63, done).** Lift 0x76fb04 and 0x783860 and run the CRT start-up, the static
constructors and `AfxWinMain` natively: `InitInstance` and then `CWinApp::Run`'s message pump in lifted MFC42,
instead of `run_init.py` calling `InitInstance` and driving the frame loop from Python. Needs E2 (MFC42) and the
message loop in the HLE (GetMessage/PeekMessage/DispatchMessage through `winsys.py` today).
- Done when: the 80-frame workload and the H53 gameplay workload run from the real entry point under the emulator
  harness, with no emulated guest code left.

*Implementation (H63):* `CMaxPayneApp::Run` (0x40bcd0) is `while (frame()) {}` with its own message pump in the frame
function (0x40c020), then `ExitInstance`, so MFC's `CWinThread::Run` pump is never used. `run_init.py --real-entry` calls
the exe entry point and runs its per-frame work (input script, live view, captures, probes, the frame report) when
the frame function is entered: through an entry hook in the lifted library (`build.py --entry-hook 0x40c020`,
`x86c.ENTRY_HOOKS`, runtime.c `lift_entry_hook`, `Native.set_entry_hook`) or, under the emulator, a code hook. It
stops the run the way the game stops, with WM_QUIT (`winsys.host_post_quit`): the frame that sees it is the last,
then `ExitInstance`, the static destructors and `ExitProcess`. `--guest-blocks` counts the blocks the emulator runs
inside the module images (patched entries aside): 0 for both workloads. What native code still reaches through the
emulator is HLE stubs outside `HLE_DIRECT` (files, registry, PeekMessageA, a few USER32 calls): E6. Found on the way:
`AfxWinInit` names the registry profile after the app title (`LoadStringA` of AFX_IDS_APP_TITLE, "Max Payne"), so
the settings live under `Remedy Entertainment\Max Payne` as on Windows (`launcher.APP_KEY`); the stray-pointer
inventory entries in front of three atexit/static-constructor thunks; `type_info::name` lifted behind its CRT helper.
See H63 in `docs/m6-exe-progress.md`.

**E5. The native host (H64, done).** A C/Objective-C executable that does what `mpemu.boot` and `run_init.py` do: reserve the
4 GB guest space, map and relocate the PE images at the `MODULE_BASES`, resolve imports to HLE stubs, set up the
TEB/PEB/FS, guest stack and heap, call the DLL entry points and the exe entry point, and dispatch HLE stubs to C
handlers (the `hle_direct` path without Python). Any guest code reached that is not lifted is a fatal error with the
address. The Python `Emu` keeps working on the same lifted library, so both run side by side until E6 is done.
Since E4 this is the `--real-entry` path of `run_init.py` without Python: the host calls the exe entry point and the
game runs to `ExitProcess`.

*Implementation (H64):* `build/mphost GAME_DIR --lib LIB [--trace FILE] [--data-dir DIR] [--window] [--frames N]`
(`host/`, `make -C host`). It dlopens a lifted library and runs it with no Unicorn and no Python, at the emulator's
addresses: the 4 GB mapping, stack, TEB/PEB, stub region and heap as `mpemu.Emu` lays them out; the four runtime DLLs,
the four game DLLs and the exe loaded, relocated and linked in `boot`'s order (exports, then stubs handed out in the
emulator's order, MFC42's delay imports bound); the CRT helpers bound after the same byte checks
(`host/crt_check.inc`, written from `native.CRT_HELPERS` by `host/gen_crt_check.py`); the DLL entry points, then
RaiseException/RtlUnwind bound to `seh.c`, then the exe entry point. Runtime (`runtime.c`): `lift_host_init` gives
`hle_direct` the host CPU's `call_guest` (a fatal stop naming the address) and the host's dispatcher, which serves
every stub call that `heap.c`, `seh.c` and `hle_fast.c` decline; `lift_host_call` enters lifted code from the host in
the guest's rounding. The handlers are C ports of the Python ones (`host/hle_kernel32.c`, `hle_files.c`,
`hle_user32.c`: KERNEL32's process, module, memory, string, code page, time, resource and file calls, the USER32/GDI32
calls MFC's start-up makes before a window exists); a stub without one stops the host with its name, caller and
arguments and the last API calls. `--dump-images` writes the linked images: **byte for byte `mpemu.boot`'s** (all
nine). `--trace` writes the API log in `ApiLog.line`'s format, and `tools/m6/api_trace.py` records the emulator's
whole log (`py`) and compares the two call by call (`cmp`; the calls the runtime serves in C left out, clocks and
coroutines compared by their arguments). **The host runs all eight DLL entry points and the exe's CRT start-up and
static constructors natively, into `AfxWinMain`/`AfxWinInit`, and its first 2,126 calls agree with the emulator's**
(arguments, results, heap addresses, handles, file reads: rlmfc finds and opens the .ras archives through
`hle_files.c`); it stops at `USER32!SetWindowsHookExA`, the first call into `emu/winsys.py`'s window manager (E6).
`host/test_host.py` checks both (images; trace against a fresh emulator trace of the same library).
Found on the way: the DLL entry points never ran natively before (the emulator runs them before the library is
installed), and rlmfc's `R_System::determineProcessorCaps` (0x100255d0, called from grphmfc's static constructor
through `R_RemedyInit`) was the one rlmfc function the lifter dropped (`popfd`, `orps`). `popfd` is now lifted: the
flag bytes, and TF/IF/IOPL/NT/AC/ID into `lift_eflags_sys` (`misc.c`), which `pushfd` pushes back, as Unicorn keeps
them (the function detects cpuid by toggling ID; `test_ops_misc.py` checks both against Unicorn); `orps x, x` (the
SSE probe) changes nothing visible and lifts as nothing. Library `build-lift/liblifted_full_h64.dylib` (table 66,530):
H63's objects hard-linked, `runtime.c`, `misc.c`, `table.c`, determineProcessorCaps, its caller R_System::R_System
(0x10024a40, a guest call before) and the exe's two pushfd users recompiled. Under `run_init.py --real-entry` it
runs as H63 (80 frames, exit code 0, 0 guest blocks; H63 rerun the same day: the same frames and times).

**E6. The Python handlers in C (begun in H60: TLS, last error, critical sections, D3D8 SetTransform/SetViewport/SetVertexShader/Clear; H61: DINPUT Acquire/GetDeviceState/GetDeviceData; H62: DSOUND buffer Lock/Unlock/GetCurrentPosition/SetVolume onto `mpaudio.c`; H65: the window manager and the registry in the host; H66: Direct3DCreate8 and IDirect3D8 in the host; H67: DirectShow and the D3D8 device in the host; H68: DSOUND in the host, without the mixer; H69: DINPUT in the host, which then runs the one-frame workload to ExitProcess; H70: the live view in the host; H71: the mixer in the host).** Port by what a full session actually calls (the H43 API log over the 80-frame
and gameplay workloads plus the menu, save/load and movie paths), not all 546: whatever is never reached becomes a
logged fatal stub. Order by area: KERNEL32 (files, time, TLS, sync, modules), the COM layers (D3D8 onto
`mprender.m` and `hle_fast.c`, DSOUND onto `mpaudio.c`, DINPUT, DirectShow for the movies), USER32/GDI32 for MFC
(windows, messages, DCs, the few GDI calls), ADVAPI32 (the registry in the data dir), `launcher.py`'s settings. Each
area can be checked by an API-trace comparison: the same workload under the Python HLE and the C HLE, call by call.
Since E5 that comparison is `host/test_host.py` (mphost `--trace` against `tools/m6/api_trace.py py`): port the call
the host stops at, rebuild (`make -C host`), and the agreeing prefix grows. Done in H65: `emu/winsys.py`
(`host/hle_winsys.c`; the DINPUT side of the pump left for DINPUT), wsprintfA, the registry and the launcher's
`--real-entry` settings (`host/hle_advapi32.c`, the same registry.json; the `--resolution`/`--set` overrides not yet):
2,335 calls agree. H66: Direct3DCreate8 and IDirect3D8 (`host/hle_d3d8.c`), and a coroutine's guest calls 0x100
below the HLE frame as in `Emu._advance`: 5,004 calls agree, the host stops at `CoInitialize`, the intro movie. H67:
DirectShow (`host/hle_dshow.c`, the headless skip through the DINPUT key state, `host/hle_dinput.c`) and the D3D8
device (hle_fast.c's D3D8 kinds bound as in a native emulator run): 14,646 calls agree, the host stops at
DirectSoundCreate. H68: DSOUND (`host/hle_dsound.c`) on hle_fast.c's buffer state, no mixer: 14,766 calls agree, the
host stops at DirectInputCreateA. H69: DINPUT (`host/hle_dinput.c`) and `--frames N` ending the run with WM_QUIT as
`run_init.py --real-entry` does: **the host runs the one-frame workload from the DLL entry points to `ExitProcess(0)`
with no emulator and no Python, every API call the emulator's** (exact up to the streaming sound's clock-driven file
offset, which differs between emulator runs too; `host/test_host.py` checks both). H70: `mphost --window`
(`host/live.c`): the Metal window, the capture streamed into libmprender (byte for byte the emulator's MPD3 streams
for frames 0-2, `host/test_host.py`), input from the window, the intro movie's frames; the intro and the main menu
render. H71: the mixer (voices, gains bit for bit with Python, the movie's soundtrack). H72: scripted input (`mphost --input`,
`--anchor`, `--anchor-frames` as `run_init.py`'s; its path through the game checked against the emulator's) and the
longer workloads in the host: the 80-frame run and the H53 gameplay workload run to `ExitProcess(0)`. Left from E6:
the launcher's `--resolution`/`--set` (the saved settings are used as they are). The handlers that call guest code (Python coroutines: LoadLibraryA's DllMain, window procedures,
the enumeration callbacks) call it directly in C (`host_guest_call`, flag `HLE_CORO`).

**E7. Unicorn and Python out of the process (H72, done).** The native host is the game. The emulator, `run_init.py` and the
diff mode stay for tests and new investigations.

*Implementation (H72):* `./play.sh [mphost options]` builds the host and plays the game in its window (`build/mphost
"Max Payne" --lib build-lift/liblifted_full_h64.dylib --window`): no Unicorn and no Python in the process (mphost links
libmprender, libmpaudio, libmpmovie, SDL3 and the system; the lifted library only libSystem). Headless, the 80-frame
workload runs in 5.5 s (`run_init.py --real-entry`: 14.8 s) and the H53 gameplay workload (Resume Game, walking,
turning, firing; 700 frames) in 12.5 s, both to `ExitProcess(0)`, with no guest code and no stub without a handler;
its captures render the corridor, Max firing and the HUD. In the window, the same workload (1,000 frames, frames 400
on, 1920x1080, vsync): **CPU 7.4 ms per frame** (p50 6.7, p90 9.1, p99 9.9; H53 under the emulator harness 12.05),
GPU 5.0 ms, 671 of 675 frames on the next vsync. Checks: `host/test_host.py` (images, the one-frame trace, scripted
input, captures, the mixer) and `tools/test_render.py` (11 of 11) pass. Not done: a comparison of whole multi-frame
traces (after the first frame the clock orders the streaming sound's mutex calls differently in every run) and the
reference screenshots of a real Windows run, which have never been taken.

Done for M6 when the game runs with no emulator in the process, the diff suite and the reference screenshots pass,
and frame time stays under 16 ms (PLAN.md).
