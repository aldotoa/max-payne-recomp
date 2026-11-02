# M4: playable via emulation, progress notes

## Emulator speed (first slice)

### The instruction-count budget was most of the cost
Every `Emu.call` passed an instruction budget (`emu_start(..., count=N)`) so that a hang could not run forever. Unicorn implements `count` by adding an internal code hook that runs on **every instruction**, and with any other code hook present (the emulator always has one on the host-stub range) each instruction also walks the hook list. A microbenchmark (an x87 + integer loop, 33 million instructions) shows the cost:

| `emu_start` options | time |
|---|---|
| no count | 0.09 s |
| no count, plus a ranged code hook | 0.09 s |
| count | 0.51 s |
| count, plus a ranged code hook (what the emulator did) | 1.74 s |

Budgets are now **host-time timeouts** (`Emu.call(..., timeout=seconds)`): a `threading.Timer` calls `uc.emu_stop()`, which costs nothing per instruction. (Unicorn's own `emu_start(timeout=...)` was tried first. It also costs nothing per instruction, but its watchdog thread wakes every 2 µs and keeps a second core busy.) A timeout that runs out behaves like the old budget: `budget_exhausted` is set, the guest stays where it is, and `Emu.resume()` continues it. `max_insns` is still accepted for an exact count, but it is slow. `run_init.py`: `--timeout SEC` (InitInstance, default 1200) and `--frame-slice SEC` (default 60) replace `--frame-cap`; `--cap N` is now an opt-in instruction budget.

### Host calls
`_on_stub` (every import call: Win32, Direct3D, DirectInput, ...) took about 29 µs, mostly Python-binding overhead: about eight register or memory accesses through `unicorn_py3`'s wrappers. `FastUc` calls the Unicorn C library directly with preallocated buffers, and the stub reads the return address and all arguments in one memory read. That brought a host call down to about 9 µs. `Emu.rd` uses the same path for reads up to 256 bytes.

### Texture uploads while capturing
Captures and the live view used to read back every bound texture's whole mip chain on **every draw** and CRC it to decide whether to re-send it. `d3d8.py` now keeps a lock counter per texture (texture `LockRect`, and `LockRect` on a surface from `GetSurfaceLevel`); a texture is read back only if it has been locked since it was last sent. The CRC check remains behind that. The game creates no textures through `CopyRects`/`UpdateTexture`, which are not implemented.

### Result (same scripted run: start-up, menu, Enter, level)
| | before | after |
|---|---|---|
| CRT + `InitInstance` | 115 s | 24 s |
| level load (one frame) | 250 s | 48 s |
| level frame (~132 draws) | 0.9 s | 0.17–0.2 s |
| whole run: start-up, 80 frames including the level load | about 7 min | 84 s |

Captured frames are unchanged. The menu frame is pixel-identical. Level frames differ only where the game is time-based (snow particles, a sub-pixel camera drift): the game runs on the host clock, so a given frame number now falls at an earlier game time. Because of that, **frame 38 is now black.** The level opens with a fade-in, an opaque full-screen quad whose vertex colour starts at black, and frame 38 now falls inside it. The documented capture command uses frame 60 instead.

### Where a level frame's time went (native profile, stock Unicorn)
`sample` on the process during level frames, main thread, 6,684 samples:

| Where | Share |
|---|---|
| guest **stores** through QEMU's slow path (`store_helper`, about half of it in `notdirty_write`/`tb_invalidate_phys_page_fast`) | 40% |
| x87 soft-float helpers (`floatx80_*`, `helper_f*`) | 18% |
| per-block exit-request checks (`helper_check_exit_request`) | 10% |
| Python host calls (`ffi_closure` → `_on_stub`) | 9% |
| the rest: translated code itself, TB lookup | ~23% |

What the store finding means:
- **It is not self-modifying code.** `run_init.py --smc-scan F` records the pages executed in frame F and counts guest writes into them in frame F+1: 406 code pages, **0 writes**.
- **Unicorn sends every store through the slow path.** A microbenchmark of a store loop runs 10x slower than the same loop with loads, with or without hooks, in a page far from any code. In upstream QEMU a page's "not dirty" state ends at its first write. Unicorn 2.1.4 (the newest release) never ends it for the game's memory; see "Patched Unicorn" below for why.
- **`UC_TLB_VIRTUAL` is not the fix.** It makes stores fast in the microbenchmark, but on the game it is slower overall (`InitInstance` 65 s instead of 29 s, a level frame 0.45 s instead of 0.17 s), so it is not used.
- **The real fix is patching Unicorn's dirty tracking.** Done: see "Patched Unicorn: fast guest stores" below.

Note for diagnostics: Unicorn applies a hook only to code translated after the hook is added, so options that add hooks mid-run (`--smc-scan`, `--fpu-watch`, `--precision-callers`) now flush the translation cache (`uc.ctl_flush_tb()`).

### Host-side profile
`--profile F` (`run_init.py`) profiles the host side from frame F. Over 40 level frames: about **0.15 s per frame inside Unicorn running guest code** and about 0.025 s in host calls (about 2,500 per frame at about 9 µs each, half of them Direct3D methods). Guest execution is now the limit, at about 5–6 frames per second.

## Emulator speed: patched Unicorn (fast guest stores)

### Why every store was slow
Each softmmu TLB entry has a `TLB_NOTDIRTY` flag that forces writes through `store_helper` → `notdirty_write`. Stock Unicorn 2.1.4 sets it on every TLB fill (its dirty bitmap is stubbed out, `cpu_physical_memory_is_clean()` always returns true) and clears it in `notdirty_write` (`tlb_set_dirty`) only if all of these hold:
- the TLB entry has no code address (`addr_code == -1`), meaning the page is **not executable**. Every page the emulator maps is `UC_PROT_ALL`, so this never held;
- no memory hook covers the address, **including `UC_HOOK_MEM_*_UNMAPPED`**. The emulator has a global unmapped-access hook, so this never held either.

So every guest store paid for `notdirty_write`, a memory-region lookup and `tb_invalidate_phys_page_fast`, even on pages that had never held code.

### The patch
`tools/unicorn-2.1.4-fast-stores.patch` (4 files in Unicorn's `qemu/` tree) makes the decision the way upstream QEMU does, by whether the page holds translated code:
- `tb_invalidate_phys_page_fast` now returns whether the page still has TBs after the invalidation. `notdirty_write` marks the entry dirty (fast) when it has none, instead of refusing for every executable page.
- `tlb_protect_code`, which `tb_link_page` calls when a page gets its first TB (for both pages of a TB that crosses a page boundary), now resets `TLB_NOTDIRTY` on every TLB entry that maps that host page (`tlb_reset_dirty`). Writes to a page with code go back through `notdirty_write`, so self-modifying code is still caught. This replaces Unicorn's per-TB `tlb_reset_dirty_by_vaddr` in `tb_gen_code`, which covered only the current virtual mapping and scanned the whole TLB for every translated block.
- The hook check ignores `*_UNMAPPED` hooks (new `uc_mem_hook_installed_mapped`): a page with a TLB entry is mapped, so they can never fire for it. `UC_HOOK_MEM_READ`/`WRITE` and `*_PROT` hooks still keep stores on the slow path, as before, so those hooks still see every access. The snapshot (copy-on-write) condition is unchanged.

### Building and installing it
`tools/build_unicorn.sh` clones the 2.1.4 tag into `~/Tools/unicorn-src` (override with `UNICORN_SRC`; checks the tag's commit), applies the patch, builds only the x86 target with cmake + ninja (from `PATH`, or pip-installed into `~/Tools/buildtools-venv`), copies `libunicorn.2.dylib` into `.venv`'s `unicorn/lib/` (the wheel's library is kept as `libunicorn.2.dylib.orig`; `--restore` puts it back), and runs `tools/bench_stores.py`. **Re-run it after recreating the venv or reinstalling `unicorn`**, or the emulator silently runs at about half speed. `LIBUNICORN_PATH=~/Tools/unicorn-src/build` also selects the patched library without installing it. No Unicorn sources or binaries are in the repo.

`tools/bench_stores.py` times 5 million guest stores and loads (memory mapped `UC_PROT_ALL`, with and without a global unmapped hook, as in `mpemu`) and fails if stores are more than 2x slower:

| | loads | stores |
|---|---|---|
| stock 2.1.4 (wheel, or built from the tag) | 0.015 s | 0.13–0.15 s |
| patched | 0.015 s | 0.015 s |

`emu/test_emu.py` has a self-modifying-code test: code patched by guest stores from another page (often enough that QEMU switches to its per-page code bitmap), a page written as data first (so its TLB entry is already fast), then filled with code, run and rewritten, and an instruction that rewrites the next instruction in its own block. It passes on the stock and the patched library, and fails on a build with the `tlb_protect_code` reset removed, so it covers the dangerous case.

### Result (same scripted run)
`run_init.py "Max Payne" --frames 80 --input "25:key=1c,26:keyup=1c" --capture DIR --capture-frames 5,60 --profile 40`, both measured on the same day:

| | stock Unicorn | patched |
|---|---|---|
| CRT + `InitInstance` | 23.8 s | 11.5 s |
| level load (one frame) | 48.0 s | 19.1 s |
| level frame (`--profile` over 40 frames) | 0.175 s (0.150 s in Unicorn) | 0.108 s (0.083 s in Unicorn) |
| whole run | 83 s | 37 s |

A level frame now takes about 0.11 s, about 9 frames per second. `test_emu`, `test_seh`, `test_dinput` and `test_render` pass. Frame 60: `refrast` and `mpreplay` agree (mean error 0.18, 0.027% of pixels off by more than 8, the same as on stock Unicorn). It shows the same tutorial scene as on stock Unicorn with the intro camera a little further along: the level loaded at frame 37 instead of 34, because the game runs on the host clock.

### Where a level frame's time goes now
`sample` over 8 s of level frames, main thread, 6,610 samples (inclusive):

| Where | Share |
|---|---|
| x87 soft-float helpers (`floatx80_*`, `float32_*`, `helper_f*`) | 32% |
| per-block exit-request checks (`helper_check_exit_request`) | 19% |
| Python host calls (`ffi_closure` → `_on_stub`) | 13% |
| stores through the slow path (`store_helper`: TLB misses, stores to pages with code; `notdirty_write` 3.6%) | 8.5% |
| TB lookup (`helper_lookup_tb_ptr`) | 3.4% |
| the rest: translated code itself | ~24% |

## Emulator speed: no exit check after every load and store

### What the check was
Unicorn emits a call to `helper_check_exit_request` at the start of every translated block, after every code hook, and **after every guest load and store** (`check_exit_request()` at the end of `tcg_gen_qemu_ld/st_i32/i64`, `qemu/tcg/tcg-op.c`). Each call also makes TCG write the guest registers back to `env` first. The check after a memory access exists so that a memory hook that calls `uc_emu_stop` stops the guest at once. Unmapped and protection faults do not need it: the softmmu helper already leaves the block itself (`cpu_exit` + `cpu_loop_exit_restore` in `cputlb.c`), and `mpemu`'s unmapped hook always returns False.

### The patch
`tools/unicorn-2.1.4-exit-checks.patch` (only `tcg-op.c`): the load/store call sites use `check_exit_request_ldst()`, which emits the check only if a `UC_HOOK_MEM_READ`, `UC_HOOK_MEM_WRITE` or `UC_HOOK_MEM_READ_AFTER` hook exists when the block is translated. The block-start check and the check after code hooks are unchanged, so `emu_stop` from the host timer, from host stubs, and EIP changes in hooks behave as before. Diagnostics that add memory hooks mid-run (`--smc-scan`) already flush the translation cache, so their blocks get the check again. `tools/build_unicorn.sh` now applies every `tools/unicorn-2.1.4-*.patch`.

### Result (same scripted run, same day)
| | before | after |
|---|---|---|
| CRT + `InitInstance` | 12.7 s | 9.1–10.3 s |
| level load (one frame) | 37.7 s | 21–26 s |
| level frame (`--profile` over 40 frames) | 0.080 s (0.068 s in Unicorn) | 0.049–0.062 s (0.038–0.051 s in Unicorn) |

Run-to-run spread on this machine is about ±20%, so the ranges are from five runs. `test_emu`, `test_seh`, `test_dinput` and `test_render` pass. Frame 60: `refrast` and `mpreplay` agree (mean error 0.198, 0.079% of pixels off by more than 8; 0.200 / 0.082% before the patch).

### Tried and not kept: x87 on host doubles
Before this patch the profile showed about 40% of samples in x87 softfloat (`float32_to_floatx80`, `roundAndPackFloatx80`, `floatx80_mul/add/sub`, `roundAndPackFloat32`, ...). A patch to `target/i386/fpu_helper.c` computed add/sub/mul/div/sqrt, compares, float32/float64 loads and `fst m32/m64` in host `double` whenever that is bit-exact: round-to-nearest, operands exact doubles, result normal, precision control 53 bits, or 24 bits with an FMA/TwoSum error term to settle results that fall on a float midpoint. The game spends most of its x87 time at **24-bit precision**: `fldcw 0x003f` (rlmfc.dll+0xabd3) about 90 times per frame, although the per-frame check requires 53-bit precision at frame boundaries. A test compared about 55,000 cases (4 control words, constructed midpoints) byte for byte against softfloat. A mutation run with the midpoint fix disabled made 74 lines differ, so the test does catch that bug.

Softfloat disappeared from the profile, but **frame time did not change** (A/B on the same build with `UC_X87_FAST=0/1`: both 0.049–0.062 s). The new helpers took the same share of samples as softfloat had. The cost is in going through a helper call (and the register spill around it) for each x87 instruction, not in the arithmetic. The patch and its test are kept outside the repo (`~/Tools/x87-fast-experiment/`). A real x87 speed-up needs the translator to generate x87 code inline (keeping the stack in host FP registers across a block) instead of one helper call per instruction.

## Sound output (DirectSound through a native mixer)

### What the game does with DirectSound
`census/dsound_usage.md` now also gets written after the main loop (before, it was written only after `InitInstance`, before any sound played), and it ends with a per-buffer table. In the scripted run (menu, Enter, about 12 s of the tutorial):
- **Ten stereo 16-bit 44.1 kHz buffers with `CTRL3D`** (0.5 s each) are created at start-up and **never written or played**: a pool, or a capability probe.
- The audible sound goes through **8-bit buffers**: two looping **streams** (stereo 22.05 kHz, 0.5 s) that the game refills every frame with `GetCurrentPosition` → `Lock` → `Unlock` (113 unlocks in 113 level frames), two static one-shots, and one mono 22.05 kHz **3D** buffer whose position, velocity, cone and distances are set every frame, with deferred settings and `CommitDeferredSettings`.
- The listener stays at the origin facing +z. The game seems to give 3D positions relative to the camera already (an inference; it is not traced).

### The mixer: `audio/mpaudio.c` → `build/libmpaudio.dylib` (`make -C audio`, needs SDL3)
Each secondary buffer is a mixer voice: a copy of its PCM (8-bit unsigned or 16-bit signed, mono or stereo, any rate), a position, a playback rate and final left/right gains. Voices are resampled linearly and mixed into float stereo at 44.1 kHz, then played through an SDL3 audio stream on the default device (CoreAudio, 512-frame device buffer). The voice position **is** the DirectSound play cursor, so streams see their cursor move exactly as fast as their sound is consumed. The write cursor stays 768 frames (about 17 ms) ahead while playing. Other outputs: a "null device" (consumed at the real-time rate, silent), and `mpa_render` on demand for tests. Any of them can also write the mix to a WAV file.

`emu/dsound.py` does the DirectSound semantics and leaves the mixer only arithmetic:
- `Unlock` copies the written regions to the voice. `Lock` supports `DSBLOCK_FROMWRITECURSOR` (previously ignored) and `ENTIREBUFFER`.
- Volume (hundredths of a dB), pan (attenuates the opposite channel) and frequency (0 = original).
- `Play`/`Stop`/`SetCurrentPosition`/`GetStatus` come from the voice. One-shots stop at the end and reset to 0.
- DS3D: distance rolloff (`min / (min + rolloff·(d − min))`, constant past the maximum distance), cones (outside volume beyond the outer angle, interpolated in dB between), listener orientation, head-relative and disabled modes, doppler from both velocities (speed of sound / distance factor), `DS3D_DEFERRED` with `CommitDeferredSettings`, and all getters. Panning is an approximation of DirectSound's software 3D: the far ear drops by up to 12 dB for a source directly to the side, with no HRTF. 3D voices are mixed to mono first.
- Releases: a buffer stops sounding when it and its 3D interface are both released, and releasing the DirectSound object frees its buffers. Also fixed: `QueryInterface` gave the new 3D, listener and notify interfaces a reference count of 2, so they never reached 0.

`run_init.py`: `--audio device|null|off` (default `device` with `--window`, otherwise off, which keeps the old host-clock cursor and no mixer) and `--audio-wav FILE`.

### Checks
- `emu/test_dsound.py` drives buffers through their COM methods as the game does and checks the mixed samples: volume, pan, frequency, play and write cursors, one-shot end, 8-bit stereo, streaming, `FROMWRITECURSOR`, the DS3D model (distance, maximum distance, rolloff, pan, orientation, head-relative, cones, doppler), deferred settings, downmix, getters, release rules, `DuplicateSoundBuffer` and WAV output. `test_emu`, `test_seh`, `test_dinput` and `test_render` still pass.
- Scripted game run (150 frames, `--audio-wav`): silence in the menu except a short sound at Enter, then continuous tutorial sound from the end of the level load. Peak 0.22, nothing clipped, largest sample-to-sample step 0.022: no clicks.
- **Starvation check.** The mixer stamps every 64-frame block with the lap it was written for, and counts frames played from blocks that are stale for the current lap. In steady state the streams keep up at about 9 frames per second (0.5 s buffers, refilled every 0.11 s). Each stream replays **one lap (500 ms)** of old data once, right after it starts: the game starts its streams at the end of the level load, and the next frame comes about 0.9 s later under emulation. This goes away as the emulator gets faster.
- On the real device: an 80-frame run took 31 s (37 s silent, same day, earlier run), and no `dsound` function appears in the host profile's top 25. Copying PCM and taking the mixer lock cost nothing measurable.
- **Not yet checked by ear in the live window**, and not compared against the game on Windows (no M0 reference recordings exist).

### Not done (sound)
- Music: none played in this run (the menu is silent too). It may arrive through the same streams later. The only DirectShow use is the intro movie (below).
- `IDirectSoundNotify` positions are accepted but never signalled. The game uses none in this run.
- The ten-buffer pool's stereo 3D behaviour (downmixed to mono here) has not been exercised.

## Movies (DirectShow → AVFoundation)

### What the game does
Ghidra (`tools/rea_decompile.sh`; decompile kept in `census/decomp/exe_0x409ac0.c`) shows one movie player, maxpayne.exe+0x409ac0. `InitInstance` (0x415dc0) calls it for `movies\intro.mpg`, the only movie the game ships, after showing the main window and **before the Direct3D device exists**. It is skipped with `-skipstartup` (that flag also gates 0x42a4e0, so it is not a pure intro switch), with the parental lock, or when an `Advanced Settings` profile value is 0 (default 1).

The sequence:
1. `CoCreateInstance(CLSID_FilterGraph, IID_IGraphBuilder)`, then QueryInterface for IMediaControl, IMediaSeeking, IMediaPosition, IVideoWindow and IBasicVideo. A missing interface throws an `R_Exception`.
2. `RenderFile`, then `IVideoWindow::get_Visible`. A failure throws, so the file must contain video.
3. In its own window: `put_Owner`, `put_WindowStyle(WS_CHILD|WS_CLIPSIBLINGS|WS_CLIPCHILDREN)`, `put_MessageDrain`, `IBasicVideo::GetVideoSize`, `SetWindowPosition`, `put_FullScreenMode(OATRUE)`.
4. `IMediaSeeking::SetPositions(0)`, `Run`, `IMediaPosition::get_Duration`.
5. The loop: PeekMessage (any `WM_KEYDOWN`/`WM_SYSKEYDOWN` skips the movie), `get_CurrentPosition`, `Sleep(50)`, until the position reaches the duration.
6. `put_Visible(0)`, `Stop`, `put_Owner(0)`, then Release on everything.

The game never touches a frame: DirectShow draws into the window. `intro.mpg` is an MPEG-1 system stream: 640×480 at 25 fps, MPEG audio layer II at 48 kHz stereo, 36.96 s.

### Implementation
- **`movie/mpmovie.m` → `build/libmpmovie.dylib`** (`make -C movie`). AVFoundation's `AVAssetReader` decodes MPEG-1 and MP2 natively, so there is no new dependency (all 925 frames in 0.87 s). It returns video frame by frame as BGRA with presentation times, supports seeking (a reader time range), decodes the whole audio track to s16, and can show a BGRA frame in a CAMetalLayer (aspect-fit).
- **`emu/dshow.py`:** the filter graph is one object with the six interfaces (plus IBasicAudio) and a shared reference count, with exact vtable layouts and stack-argument counts (doubles and `LONGLONG`s count as two slots). RenderFile opens the file. The whole audio track becomes **one mixer voice** (libmpaudio), started by Run. The movie clock is the host clock from Run. Each `get_CurrentPosition` and each guest `Sleep` decodes up to the clock and shows the newest frame. `Sleep` waits for real while a movie runs (it used to return at once), so frames come out on time even though the game sleeps 50 ms between polls. The position stops at the duration, which is the game's loop exit. Missing files and movies without video fail the way the game expects.
- **`mpemu.py`:** a COM class table (`COM_CLASSES`), so DirectSound and DirectShow each register their classes instead of replacing `CoCreateInstance`. Also `SLEEP_HOOKS`.
- **`live.py`:** the window can open before the Direct3D device exists. `run_init.py --window` opens it before `InitInstance` so the intro shows, and attaches the Direct3D renderer afterwards. Window events, including keys that skip the movie, are pumped while the movie runs. `dinput.input_state(e)` creates the input state early for that.
- **`run_init.py --intro play|skip`.** The default is `play` with `--window`, `skip` headless. A headless skip presses Space when the movie starts, as a player would, so scripted runs keep their timing.

### Checks
- `emu/test_dshow.py` drives the game's own sequence through the vtables:
  - the setup calls and their results, then Run;
  - one second of the `get_CurrentPosition` / `Sleep(50)` loop: 23–27 frames shown, no gap over 60 ms, window pumped throughout;
  - the movie's audio in the mixer;
  - Stop freezing the clock, seeking to 30 s landing on the 30 s frame, GetState, 100 ns times;
  - E_NOINTERFACE for IMediaEventEx, full release (voice and file closed);
  - position stopping at the duration, the headless key press and release, missing-file failures.
  
  The other test suites still pass.
- `--intro play` headless with `--audio-wav`: `InitInstance` takes 49 s instead of 9 s. All 925 frames were shown and the movie stopped at 36.96 s; the game polled 711 times (about every 52 ms) and then went on to the menu. The recorded audio matches the decoded track sample for sample after resampling (correlation 1.0000, level ratio 1.000) and lasts the full 36.9 s. A decoded frame at 12 s is correct: colors, geometry, presentation time.
- The standard 80-frame scripted run (headless, intro skipped) still loads the tutorial at frame 37 and takes 37.5 s.
- **Not yet watched in the live window** (`run_init.py --window`), and A/V sync there not checked by eye. The clock and the audio voice both start at Run, and the device adds a few tens of ms of audio latency.

## Per-user data: registry, saved games, written files

### What the game stores where
- **Settings live in the registry**, under `HKCU\Software\Remedy Entertainment`. That covers Video Settings (driver, resolution, depth, gamma, LOD/mipmap bias, frame-rate smoothness), Advanced Settings (texture detail, filtering, shadows, ... read with defaults, written by the dialog), Audio Settings, Other Settings (tips, crosshair, auto-aim, ...), Input Settings, Save Game (`Last Saved Game Filename`), Game Level and Parental Lock. Input Settings is 296 values: 32 actions × 4 bindings (type 1 = DirectInput key code) plus mouse/joystick sensitivities, written on the first run. No INI files are used. The game also registers `.mps` → `maxpayne.savegame` under HKCR.
- **Saved games** are `%s\savegame%03i.mps` (`.mds` in the demo; maxpayne.exe+0x410f20). The folder comes from 0x40f9e0: `LoadLibrary("shell32.dll")` → `SHGetSpecialFolderPathA(0, buf, CSIDL_PERSONAL, TRUE)` + `\Max Payne Savegames`, with the game folder's `savegames` as the fallback. This is why the shipped `savegames\Where are my saved games.txt` says "My Documents". Before this slice `shell32.dll` failed to load, so saves would have gone into the game folder.
- **Saving needs a real game:** in the tutorial the menu's *Save* is greyed out. v1.05 binds no quicksave key by default (none of the 32 actions is a save). The save/load request goes through a pending-request field (`+0xb4`, 1 = new game, 2 = load, 3 = save to slot, 4 = save to the quick/auto slot) that 0x451960 carries out in the main loop.

### Implementation (`emu/mpemu.py`)
- **`data_dir(e)`:** `e.data_dir`, else `$MAXPAYNE_DATA`, else `~/Library/Application Support/Max Payne Recomp`. `run_init.py --data-dir DIR`. It holds:
  - `registry.json`: the registry, loaded at the first registry access and **written through on every change** (atomic replace). DWORDs and strings are stored readably, anything else as hex.
  - `game/`: the copy-on-write overlay for writes into the game folder (`C:\MaxPayne`). This replaces the repo-local `emu_data/`; the shipped game folder is never written.
  - `C/…`: the rest of the guest's C: drive. The game's "My Documents" is `C/My Documents`, so saves land in `<data>/C/My Documents/Max Payne Savegames/`.
- **Path mapping:** `_locate` splits a guest path into the game folder or the drive (relative paths use the current directory, `\x` is drive-rooted, `..` is resolved textually). All file APIs go through `host_read_path`/`host_write_path`, and names are matched case-insensitively. Before this, any path outside `C:\MaxPayne` was silently mapped *into the game folder*.
- **Registry fixes:**
  - `RegCreateKeyEx` creates the missing parent keys, as Windows does.
  - Handles come from a counter. Before, they were `0x5000 + 4 × open handles`, so a key opened after a close could get the handle of one still open.
  - `RegDeleteValueA` and `RegDeleteKeyA` (refused while subkeys exist) actually delete.
  - `registry_seed` only fills missing values, and the new `registry_overrides` replaces them.
- **`shell32.dll`** is now one of the placeholder DLLs, with `SHGetSpecialFolderPathA` (Personal, AppData, Local AppData, Desktop, Common AppData; `fCreate` creates the folder).

## Startup dialog replaced by launcher options (`emu/launcher.py`)
The dialog has been bypassed since M2 (`-nodialog` plus complete saved Video Settings, maxpayne.exe+0x407190). The launcher turns its choices into options that persist the way the dialog's OK would:
- `--resolution WxH`: Display Width/Height, checked against the modes the D3D layer offers (now `d3d8.display_modes`).
- `--set "Section/Value=N"`: any value the dialogs store, e.g. `"Advanced Settings/Fogging=0"`. Numbers become DWORDs, anything else a string. They are written as registry overrides and so persist.
- `--fullscreen` / `--windowed`: the Mac window, remembered in `<data>/launcher.json`.
- `--game-mode fullscreen|windowed`: the game's own mode, remembered. **The default is now `fullscreen`, the game's normal path:** the back buffer is exactly the chosen mode (1920×1080, `Windowed=0`, two back buffers, presentation interval 1), Windows would hide the cursor, and the game draws its own. `windowed` passes `-window` (the old default), where the game sizes its back buffer from its window's client area (1922×1063 before).
- `--settings` prints the stored settings (Remedy keys and host options) and exits.

The values the game needs in order to skip the dialog (Driver = the adapter description, resolution, depth, CPU driver, HW acceleration) are seeded only when missing, so the game's own changes survive.

## Window, fullscreen and cursor (`emu/live.py`)
- The window opens at the chosen resolution × 0.66 and keeps the frame's aspect ratio when resized.
- `--fullscreen`, Cmd+Return or Cmd+Ctrl+F switch to macOS fullscreen (desktop-sized, scaled to fit); the choice is remembered.
- **The mouse follows the game.** While the window has focus and the game holds the mouse exclusively (DirectInput `DISCL_EXCLUSIVE`, acquired), the pointer is captured in relative mode and hidden; on Windows the game also hides it and draws its own. Before, the first click captured it. Losing focus releases it. Cmd+Esc releases it until the next click, which is swallowed. Cmd+key presses no longer reach the game, but key-ups still do, so no key gets stuck.

## Checks (this slice)
- `emu/test_platform.py`, each test in its own temporary data folder:
  - the registry persists across emulator instances; delete value and delete key, refused with subkeys;
  - seeds fill missing values only, overrides replace and persist; no handle reuse;
  - `SHGetSpecialFolderPathA` through `LoadLibrary`/`GetProcAddress` as the exe calls it; saves written to, read from (case-insensitive) and listed in `<data>/C/My Documents/Max Payne Savegames`, and still there in the next run;
  - writes into the game folder land in the overlay (copy-on-write, merged listings) with the shipped file untouched; other C: paths and rooted paths are per-user;
  - launcher options persist and bad options are refused.
  
  All other suites pass.
- Scripted runs: the game creates `C:\My Documents` through `shell32`. The first run writes its whole input configuration, audio, other and video settings to `registry.json`, and later runs read them back (`--settings`). The game's fullscreen path renders the tutorial correctly.
- **An in-game save and load has not been done yet.**
  - The tutorial disables Save.
  - In a new game, the graphic novel pages are drawn black, and the first page change used to run the guest heap out (`guest heap exhausted`). The heap now reuses freed memory and the novel reaches chapter 1. The black pages are fixed (Finding 3). See "Graphic novel (prologue)" below.
  - What *is* verified: the save folder the game computes, file I/O there, and the registry that holds `Last Saved Game Filename` (tests above).
- **Live window:** fullscreen toggling and cursor capture are not yet tried by hand.

## Graphic novel (prologue): heap, timing, and the black pages

### Symptom
In scripted headless runs the novel at the start of a new game showed every page black, did not advance with no input and advanced only once with Enter, so chapter 1 was never reached.

### Finding 1 (fixed): the guest heap never freed anything
`Emu.alloc` was a bump allocator: `HeapFree`, MFC `operator delete` (#825) and `Local/GlobalFree` dropped the bookkeeping but never reused memory. The level loads before the novel used up the 512 MB heap, so the first page-to-page load raised `guest heap exhausted`.
- Fix: `mpemu.FreeList` holds free blocks in address order, coalesced with their neighbours, in power-of-two size classes. `alloc` takes the lowest fitting block and splits it, and reused memory is zeroed. `Emu.free` returns blocks. Unknown pointers (VirtualAlloc, file views, host objects, double frees) are ignored as before. `HeapReAlloc`/`LocalReAlloc` grow or shrink in place when the block's capacity allows, honour `HEAP_REALLOC_IN_PLACE_ONLY`, and free the old block after a move.
- Effect: the heap top for the whole run up to chapter 1 is 89 MB (about 80 MB live, 296k blocks), against more than 512 MB before.
- Test: `emu/test_emu.py` `test_heap_reuse`.

### Finding 2 (not an emulator bug): the novel runs on wall-clock time
`MaxPayne_GraphicNovelMode` (vtable 0x7ce920, update 0x49b6d0) and `MaxPayne_GraphicNovelPage` (update 0x4a8b50) advance with the frame dt from the host clock (QueryPerformanceCounter). A page moves on when its narration ends, about 9.4 s for P1L0a_001, then fades over about 0.25 s (+0xbb on the mode object). Headless novel frames take about 1.5 ms, so "3000 frames" was only about 4.5 s of game time. With `--probe` sleeping 50 ms per frame and the heap fix, the run goes through P1L0a_001, a scene load (P0L1), 003, 004, 005cine, 005, then the level start and its autosave (savegame000.mps), and reaches gameplay in Max's house without any input. Scripted runs therefore need wall time, not frame counts, in the novel. A virtual clock for headless runs would make them deterministic (not done).

### Finding 3 (fixed): the pages are drawn black because the D3D8 driver drops vertex alpha
Each page `.kf2` has a `Background` object (the page image) and `Black_NN` cover objects, one per panel and slightly larger than it. Their materials get `setAlphaSource(1)` and `setLightingColorSource(4)` from the page's MaterialCallback (0x4a8aa0). Every frame the page code evaluates each object's opacity curve and writes `opacity*255` into the vertex diffuse alpha. The animation is correct: `Background` goes 0→1 and `Black_01` 1→0 over about 6 s.

The driver (`e2_d3d8_driver_mfc.dll`, loaded at 0x10400000, with e2mfc at 0x10100000; both prefer 0x10000000, so hooks must use module base + RVA) turns that into no blending at all. Its own material log (`P_Device::materialVerbose`, gated by device bytes +0xa0/+0xa1, which a probe can force on) shows for the cover: layer `VERTEX_ALPHA | TEXTURE0 UV0` → "trying texture, try 1: color SELECTARG1(TEXTURE), alpha SELECTARG1(TEXTURE)" → `D3D_OK` → "opaque", blend OFF. The panel material gets color MODULATE(TEXTURE, DIFFUSE) and alpha SELECTARG1(TEXTURE), also opaque. Consequences:
- `P_D3DMaterialInfo::endValidation` (0x10003a40) sets info+0x24 bit 0x1000 only when a stage reads diffuse. The cover has 0x8000 only, so `requestVertices` (0x10018140) builds its vertex buffer without D3DFVF_DIFFUSE (FVF 0x184 against 0x1c4 for the page).
- The covers are nearer than the panels (rhw 1.3004 against 1.2987) and are drawn after them with z-writes off, so they cover the page completely.

Ruled out:
- `CheckDeviceFormat` answers (all OK).
- `ValidateDevice`: `P_D3DMaterialInfo::validate(int)` (0x10003830) checks only the HRESULT.
- The material callbacks: they run and set the alpha source before validation.

Cause and fix: the driver's caps test (0x10027456) sets its vertex-alpha flag (caps struct byte +0x79) only when `ShadeCaps` has `D3DPSHADECAPS_ALPHAGOURAUDBLEND` (0x4000). Our `fill_caps` did not advertise it, so `validate` (0x10004a6c) cleared the layer's 0x600000 VERTEX_ALPHA bits, `setStages` took the no-alpha branch, and the pass was opaque. Fix: `fill_caps` now sets ShadeCaps to COLORGOURAUDRGB | SPECULARGOURAUDRGB | ALPHAGOURAUDBLEND | FOGGOURAUD (keeping the old bits). Test: `emu/test_emu.py` `test_device_caps_vertex_alpha`.

Verification: a scripted run with a fresh data dir (`--anchor P1L0a_001.kf2`, anchor in frame 1312, `--probe` sleeping 50 ms per frame) captured @60, @200 and @380 and rendered them with `build/mpreplay`. Before the change these pages were all black. Now @60 shows the full P1L0a_001 splash page with its narration boxes. @200 and @380 show the next page's first panel (artwork and speech bubbles) with the rest of the page still black. That fits the page revealing its panels one by one as the narration advances, but this run did not show a later panel fading in, so panel-to-panel fades are not verified yet.

### Tooling added to `run_init.py`
- `--anchor TEXT`: frame numbers written `@N` count from the frame in which the game first opens a file whose name contains TEXT. They work in `--input`, `--dump-api` and `--capture-frames`.
- `--anchor-frames N`: stop N frames after the anchor.
- `--dump-api F,...`: print every HLE call made in those frames.
- `--probe FILE`: run a Python file after every frame, with `e`, `i`, `anchor_frame` and `mpemu` in scope (hooks, memory dumps, `time.sleep` to give the game wall time).

Example: `run_init.py "Max Payne" --frames 6000 --anchor P1L0a_001.kf2 --anchor-frames 1500 --probe slow.py --capture-frames @60,@700 --input "25:key=d0,26:keyup=d0,28:key=1c,29:keyup=1c,40:key=1c,41:keyup=1c"`
