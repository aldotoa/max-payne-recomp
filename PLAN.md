# Max Payne → macOS arm64 recompilation: project plan

## 1. Context

**Goal:** a native macOS arm64 build of Max Payne (2001, Remedy), playable at **60 fps** and at the **native resolution of the user's monitor**, built by recompiling the original x86 binaries, not by wrapping them in Wine.

**Why recompile instead of Wine/CrossOver:** the user wants a native port. Wine is kept only as a *reference* (what the game should look and behave like) and as a quick fallback.

**Hard constraints**
- Needs the user's own legitimately obtained copy of the game. The repo contains **tooling only**: no game assets, no original binaries, and no generated C that is a direct translation of the binaries. The user runs the lift locally on their own files.
- The binary analysed must be a **clean, DRM-free build** (see Risk R1).

**Status so far**
- REA 6.5.0 is registered with Claude Code. Ghidra 12.1.4 is installed at `~/Tools/ghidra/ghidra_12.1.4_PUBLIC`, with a self-built arm64 native decompiler (REA doctor healthy). This session's REA MCP tools are stale; the CLI works:
  `GHIDRA_INSTALL_DIR=~/Tools/ghidra/ghidra_12.1.4_PUBLIC JAVA_HOME=<jdk25> npx rea-agents@6.5.0 analyze|decompile <file> --provider ghidra`
- Game folder: `Max Payne/` in the repo (ignored by git) (retail 1.05-era files; 6 PE32 x86 modules, 1.1 GB of data).
- `e2_d3d8_driver_mfc.dll` analysed with Ghidra: 2,580 functions, `DRV_*` methods decompile cleanly.

## 2. What we know about the binaries

| Module | Role | Named exports |
|---|---|---|
| `MaxPayne.exe` (4.9 MB, base 0x400000) | Game logic, MFC app shell | none (imports 276 from e2mfc, 209 rlmfc, 70 sndmfc, 147 MFC42 ordinals) |
| `e2mfc.dll` | Engine: objects, materials, camera, abstract `P_Driver` | 1200 |
| `rlmfc.dll` | Core: memory, files, math, timers, script, FPU control | 980 |
| `grphmfc.dll` | Images (JPG, PCX, DDS, SCX) | 70 |
| `sndmfc.dll` | Sound over DirectSound | 203 |
| `e2driver/e2_d3d8_driver_mfc.dll` | Direct3D 8 renderer (`P_D3D : P_Driver`) | 271 |

- All DLLs are MSVC 6 C++ with **full mangled export names**: about 2,700 functions come with names and class names for free.
- Platform dependencies: D3D8, DirectInput (`DINPUT.dll`), DirectSound, DirectShow (`CoCreateInstance` in exe, for `intro.mpg`), MFC42, MSVCRT, MSVCP60, MSVCIRT, kernel32/user32/gdi32/advapi32/winmm.
- Data: `.ras` archives (Remedy's format), read through `R_File` / `R_MemoryFile` in rlmfc.
- Renderer seam: every draw goes through `P_Driver::DRV_*` virtuals (beginScene, allocateMap, createVertexShader/PixelShader, …). `DRV_beginScene` keeps the D3D device at `this+0xd0` and present params at `this+0xd8`.
- Timing is centralized in `rlmfc.dll` (`R_Timer::sample`, `timeGetTime`).
- `MaxPayne.exe` has sections `stxt774`, `stxt371`, `.MGD32` that look like copy-protection remnants.

## 3. Architecture (end state)

```
 ┌────────────── macOS arm64 process ──────────────┐
 │ Lifted game code (C → clang → arm64):           │
 │   MaxPayne.exe, e2mfc, rlmfc, grphmfc, sndmfc,  │
 │   (and the D3D8 driver DLL, see §5 decision D2) │
 │        │ guest ABI: 32-bit address space, x87   │
 │ ┌──────┴───────────── host runtime ───────────┐ │
 │ │ Win32/CRT/STL/MFC shims  │ file/.ras VFS    │ │
 │ │ D3D8-subset → Metal      │ DirectSound→Core │ │
 │ │ DirectInput → mouse/kbd/ │  Audio           │ │
 │ │   GameController         │ MPEG-1 movie     │ │
 │ │ timing, save paths, config                  │ │
 │ └─────────────────────────────────────────────┘ │
 └─────────────────────────────────────────────────┘
```

Guest memory: one 4 GB reservation; guest address = `base + addr32`. Heap/stack/PE images are mapped at their original addresses so absolute pointers, vtables and relocations stay valid.

## 4. Key decisions (recommended)

- **D1. Execution strategy: emulate first, then lift.** Static recompilation of 32-bit MSVC6 C++ (vtables, SEH, C++ exceptions, x87) is the high-risk part. So first run the original DLLs under an embedded x86 emulator (Unicorn, which runs on Apple Silicon) with HLE'd imports. This gets a playable build early. The emulator then serves as the **oracle for differential testing** of the lifter. The end state removes the emulator.
- **D2. Renderer: keep the original driver DLL and implement a D3D8 subset on Metal** ("HLE d3d8.dll"). Fidelity comes free and nothing about `P_D3D` has to be reverse-engineered. Scope the subset by **instrumenting** which D3D8 calls and states the game actually uses.
  - Alternative (rejected for now): re-implement `P_D3D`'s 271 exports natively. This needs the full class layouts and gains little.
- **D3. Lifter:** evaluate `remill` (x86 → LLVM IR) vs a custom Ghidra-p-code → C emitter in a spike (M5). Pick whichever handles flags, x87 and indirect calls with less glue. Unresolved indirect targets fall back to the emulator.
  - **Decided in M5:** a custom capstone-based x86 → C translator (`lift/x86c.py`). remill was not installed and needs a pinned LLVM. See `docs/m5-lifter-spike.md` for the GO decision and its evidence.
- **D4. Platform libs:** lift the **shipped** `MSVCRT.DLL` / `MSVCP60.DLL` / `MSVCIRT.DLL` (they need only kernel32). Decide MFC42 after studying which MFC the exe really uses; the likely path is HLE of the startup dialog and window, bypassing `CWinApp`. The engine DLLs import only MFC #823/#825, which look like allocator ordinals (verify).
- **D5. Host stack:** C++20, CMake, clang; SDL3 for window/input/gamepad (Metal layer via `SDL_Metal`), Metal-cpp for rendering, CoreAudio (via SDL3 audio or miniaudio) for sound, `pl_mpeg` or AVFoundation for the intro movie.

## 5. Phases and milestones

Each milestone has a "done when" check. Order de-risks the unknowns first.

**M0: Environment and reference baseline**
- `git init` a new source repo (separate from the game folder; `.gitignore` all game files and generated lift output).
- Obtain a **DRM-free `MaxPayne.exe`** from a store copy the user owns (R1). Record SHA-256s of all six modules.
- Run the game once in CrossOver/Wine for **reference captures**: screenshots at fixed spots, intro movie timing, frame-time notes.
- Done when: repo exists, binaries hashed, reference screenshots/video saved outside the repo.

**M1: Static inventory and census** (REA/Ghidra CLI + small scripts)
- Per-module: import table census (what has to be shimmed), export table → symbol map, relocation info, opcode survey (which instructions: x87? SSE? 3DNow!? self-modifying?), indirect-call/vtable inventory, SEH/EH frames.
- Identify MFC usage in the exe and the WinMain/startup path; find the engine main loop, `R_Timer` consumers, tick-rate constants.
- Done when: a `docs/census.md` lists every external function the game needs, grouped by subsystem, with call counts; the opcode survey is complete.

**M2: Bring-up under emulation**
- PE loader (map sections, apply relocations, resolve imports to host thunks), Unicorn-based CPU, TLS/FS (SEH chain), HLE kernel32/CRT basics, case-insensitive path layer for `.ras` and data.
- Run `rlmfc` + `grphmfc` init, then `e2mfc` init, then the exe up to window creation.
- Done when: `MaxPayne.exe` runs under the emulator until it first calls the renderer, with a call-trace log.

**M3: Metal renderer (D3D8 subset)**
- IDirect3D8/IDirect3DDevice8 (+ texture, vertex/index buffer, surface objects) implemented in the host, backed by Metal: fixed-function emulation in generated MSL, D3D8 vertex/pixel shader 1.x → MSL translation (if the instrumented run shows they are used), texture formats (DXT, A8R8G8B8, …), render states, viewport/scissor.
- Done when: the main menu and first-level frame render and visually match the M0 reference screenshots.

**M4: Playable via emulation** (feature complete HLE)
- DirectInput → mouse/keyboard (+ GameController), DirectSound → CoreAudio (including 3D listener/positional sources as the game uses them), DirectShow movie → MPEG-1 decoder, registry/config/save-game locations → `~/Library/Application Support/...`, startup dialog replaced by native options, window/fullscreen/cursor handling.
- Done when: full chapter 1 plays start to finish with sound, music, movies, save/load; no crashes in a 1-hour soak.

**M5: Lifter spike (decision gate)**
- Lift `rlmfc.dll` (smallest dependency-free core) with the candidate lifter; link back into the emulated process, **differential-test** function by function against the emulator (registers, memory, flags, x87 state).
- Settle x87 strategy (see R2), SEH/C++-EH strategy, indirect-call dispatch table, memory model.
- Done when: rlmfc runs lifted with identical behavior over a recorded workload, and performance is acceptable. If the spike fails, fall back to a JIT/DBT-based end state and re-plan.

**M6: Full lift**
- Lift remaining modules (grphmfc, e2mfc, sndmfc, driver DLL, exe, shipped CRT/STL), module by module, keeping the emulator as fallback and oracle; then remove the emulator.
- Done when: the game runs with no emulator in the process; the differential suite and reference screenshots pass; frame time on an M-series Mac is comfortably under 16 ms at 1080p.
- Progress: grphmfc lifted with rlmfc into one library, differential run clean (381 of 382, rdtsc the exception); see `docs/m6-grphmfc.md`.
- Emulator removal: phases in `docs/m6-emu-removal.md` (E1-E5 done by H64: indirect jumps, the runtime DLLs, exceptions, the real entry point, the native host `build/mphost`; E6 (the HLE in C) and E7 (Unicorn and Python out) done by H72: `./play.sh` plays the game in the native host, with no emulator and no Python in the process; gameplay at 7.4 ms of CPU per frame at 1080p; the host's tests and the renderer tests pass. Left for M6: real-Windows reference screenshots (never taken) and the launcher's `--resolution`/`--set` in the host).
- Progress: e2mfc lifted with rlmfc and grphmfc (4,812 functions), differential run clean (856 of 858: rdtsc, and LoadLibraryA which the diff cannot replay); no speed gain, since 96% of entries into native code come from the exe; see `docs/m6-e2mfc.md`.

**M7: 60 fps and native resolution** (can start after M4 in parallel with M5/M6)
- *Resolution:* create the drawable at the monitor's native pixel size; pass the real size through `P_DisplayMode`; fix viewport/projection; **Hor+ widescreen** FOV; scale and anchor the 2D layer (menus, HUD, text) from the 640×480 virtual space (pillarbox menus first, true anchored HUD later).
- *60 fps:* study the main loop and `R_Timer`; determine whether simulation is variable-dt or fixed-tick and whether animation/physics/bullet-time depend on frame rate. If variable-dt: remove the cap and vsync to 60. If fixed-tick: run sim at its native tick and **interpolate render state** (or re-tune safely).
- Progress (2026-10-25, `docs/m7-resolution.md`): the desktop is 2560×1600 in the host and the emulator, and the game runs at it. The engine's view is a fixed 4:3 frustum (70.0° × 55.4°), stretched 1.2× horizontally at 16:10, with the 2D layer stretched the same way. H74: Hor+ (80.1° × 55.4° at 16:10; `mphost --view hor+`, the default) by widening `P_Camera::validate`'s horizontal tangent after it runs. The camera-placed menus and HUD follow it, so the menus are now pillarboxed at the right aspect. H75: the HUD's corner elements are anchored to the real screen edges (hooks on the HUD wrappers and `executeAlways`). H76: the exe's portal code (0x679e80, 0x67a9f0) computed its own 4:3 tangent, so rooms seen through doors near the screen edges were clipped; instruction hooks widen it too. H77: full-screen overlays checked: the HUD fade layer (fades and flashes) was pillarboxed and is now widened to the screen edges; the graphic-novel pages and the menu shown while loading keep their 4:3 art, pillarboxed; bullet time draws no tint. Next: the 60 fps work.
- Progress (2026-10-30, `docs/m7-fps.md`): **variable-dt confirmed**, so no fixed tick or interpolation. `mphost --sim-fps N` runs the game on a virtual clock (deterministic: same-rate runs are byte-identical). `tools/m7/fps_regress.py` plays one scripted session at 30/60/120 fps: walk, strafe-turn, a shoot-dodge in bullet time and fire stay within 0.29 units of camera position, with the same view angle. Fights diverge between rates because per-frame (dt-correct) particle emitters consume `rand()` at the frame rate, which changes the random sequence; the expected behavior is unchanged. `render/mprender.m` caps presentation at 60 on faster displays (`MPR_MAX_FPS`). Not yet locked at 2560×1600: about 50 fps, CPU p50 14.6 ms / p90 23 ms, GPU 11.3 ms. Next: performance at the native resolution.
- Done when: 60 fps locked at the monitor's resolution; physics, bullet-time, ragdolls, and scripted sequences behave the same as the reference at 60 and at 30 (regression capture).

**M8: Polish and packaging**
- Controller mapping, options UI, aspect/FOV settings, anisotropic filtering/MSAA, proper `.app` bundle, notarization-friendly signing, "point at your game folder" first-run flow.
- Regression suite in CI (differential tests + reference-frame comparisons + save-game load tests).

## 6. Risks

| # | Risk | Mitigation |
|---|---|---|
| R1 | The current `MaxPayne.exe` shows copy-protection remnants (`stxt*` sections); a wrapped exe can't be analysed or lifted reliably. | Use a clean DRM-free build from a store copy you own. Do not use cracking tools. DLLs are unaffected. |
| R2 | **x87 precision**: heavy x87 use. **Reduced by M1 finding:** the game requires 53-bit precision and round-to-nearest and checks it every frame (see `docs/census.md` §7), so a `double` model is bit-exact for basic arithmetic. Remaining: transcendental last-bit differences, exponent-range edge cases, `fldcw` truncation sites. | M5 spike validates the `double` model against the emulator, including `fsin`/`fcos`/`fpatan`/`f2xm1`/`fyl2x`; soft-float only for functions that diverge. |
| R3 | SEH (`_except_handler3`) and C++ exceptions (`_CxxThrowException`) in lifted code. | Implement the MSVC frame-handler protocol in the runtime; emulator oracle for tests. |
| R4 | Indirect calls/vtables not discovered statically. | Vtable inventory from Ghidra + RTTI (`.?AV` names present); runtime fallback to emulator; logging of unresolved targets. |
| R5 | D3D8 shader/state coverage larger than expected. | Instrument first; implement only what the game uses; golden-frame tests. |
| R6 | MFC42 surface too large to HLE. | Bypass `CWinApp` startup natively; if impossible, lift the shipped MFC42 and shim user32/gdi32 subset. |
| R7 | Frame-rate-coupled gameplay (fixed tick, timing in scripts). | Gate in M7; interpolation fallback. |
| R8 | Legal: generated code is derivative of the original. | Never commit or publish generated sources or game data; users lift locally. |
| R9 | Unknown unknowns in a 2001 engine (self-modifying code, hacks). | Emulator-first path keeps the game runnable while these are found. |

## 7. Verification (applies throughout)

- **Differential tests:** lifted function vs emulator on recorded inputs (regs, memory, flags, FPU state).
- **Reference frames:** fixed save games and camera positions rendered under Wine (M0) vs native; image diff with tolerance, in 4:3 and widescreen.
- **Determinism/regression:** load the same saves, run scripted input for N seconds at 30 and 60 fps, compare positions/health/enemy states.
- **Performance:** frame-time capture (average, 99th percentile) at native resolution on the user's Mac; target locked 60 fps.
- **Soak:** one-hour play sessions, memory and crash checks.

## 8. Open questions for the user

1. ~~Monitor resolution/aspect?~~ **Answered 2026-10-25: 2560×1600 (16:10).** M7's native resolution, Hor+ FOV and HUD scaling target this; 640×480 menus pillarbox to it.
2. Minimum macOS version to support (this machine reports Darwin 27).
3. Controller support wanted at launch, or keyboard and mouse only?
4. Should the repo be public (tooling only), or private?
5. Is Max Payne 2 a later goal? Its engine is similar, so design the lifter and runtime to be reusable.

## 9. Immediate next steps after approval

1. Copy this plan to `PLAN.md` in the project folder (outside the game folder) and `git init` the project repo.
2. Ask you for the clean store build of `MaxPayne.exe` (R1) and start **M1** (census) with the REA CLI.
