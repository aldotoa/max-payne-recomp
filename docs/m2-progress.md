# M2 bring-up: progress

Prototype emulator in Python + Unicorn (`emu/mpemu.py`). The loader/HLE design is meant to be ported to the C++ host later.

## What works (verified by running it)
- **PE loader:** maps modules, applies base relocations (the five game DLLs all prefer `0x10000000`, so they are placed at 0x10000000/0x10100000/0x10200000/0x10300000/0x10400000), and resolves imports across loaded modules by name or ordinal. Everything else becomes an HLE stub (16-byte slots at `0x7f000000`); landing on a stub runs a Python handler and returns with the right calling convention (stdcall pops args, cdecl does not).
- **CPU environment:** x86-32 flat segments plus an FS segment pointing at a TEB (SEH chain head, stack bounds, PEB pointer, TLS slots), a 2 MB stack, a 512 MB guest heap, and the FPU control word set to 53-bit precision / round-to-nearest (the mode the game checks every frame).
- **HLE:** 154 handlers: process/thread/heap/TLS/critical sections, strings and code pages, time (`QueryPerformanceCounter` and `timeGetTime` from the host clock), a full file and directory layer (reads come from the game folder, **writes go to an `emu_data/` overlay**, so game files are never modified), and MFC `operator new`/`delete` (`#823`/`#825`).
- **Milestone reached:** the shipped `MSVCRT.DLL`, `MSVCIRT.DLL`, `MSVCP60.DLL` and the game's `rlmfc`, `grphmfc`, `e2mfc`, `sndmfc` all run their `DllMain` (CRT init and C++ static constructors) to completion.
- **Engine code actually executes:** `emu/smoke_timer.py` constructs `R_RemedyInit` and `R_Timer` through their real exports and reads the clock: 76 µs, then 60 ms after a 50 ms host sleep, `getAge` 0.060 s.

## Lessons / gotchas found on the way
- Unicorn 32-bit ignores `FS_BASE`; FS has to be loaded through a GDT (and CS/DS/ES/SS then need explicit flat descriptors, ring 0, or SS ends up 16-bit and the stack faults at truncated addresses).
- `pefile` import slot addresses are relative to the file's preferred base, not our load base; patch the IAT at `mod.base + (imp.address - ImageBase)`.
- Unicorn's `reg_read(ST0)` returns only the 64-bit mantissa. Read x87 return values by running `fstp qword ptr [mem]` in the guest (`Emu.fp_return`).
- `R_Timer` needs the global `R_System` (`Sys`), which `R_RemedyInit` creates; without it every sample is 0.

## Exe loaded (second slice)
- `emu/run_exe.py` loads `MaxPayne.exe` at its preferred base `0x400000`, resolves its imports against the loaded DLLs (everything else becomes an HLE stub), runs the DLL entry points, then runs the exe's **real CRT start-up and all of its C++ static constructors** (about 3 s in Python) and stops when the exe's `WinMain` calls `AfxWinMain` (MFC42 `#1576`).
- MFC is not loaded. For unknown MFC ordinals there is a **lenient bring-up mode**: log the call, return 0, and pop the callee-cleaned bytes read from the `ret N` of that ordinal in `MFC42.DLL` (`Emu.mfc_ret_bytes`, 6,136 ordinals). Only one such call happened before `AfxWinMain` (`#561` from `0xa1f8`). `#1168` needed a real handler: it returns a pointer to a per-module state block, and the exe writes a flag at `+0x14` and a code page at `+0x1040` (`0x783878`).
- **Findings about the app shell** (disassembly with `tools/disasm.py`, listings in `census/decomp/exe_app_*.txt`):
  - `CMaxPayneApp` vtable (`0x7cb77c`, 41 slots) overrides only slots 1-4, 12, 22, 23, 28, 29. Slot 12 is `GetMessageMap` (2-instruction stub), which fits the MFC `CCmdTarget` layout. Slot 22 (`0x40b7a0`, 36 instr) sets the sound listener's update mechanism/interval/thread priority; slot 28 (`0x40b900`) calls `RedrawWindow`; slot 29 (`0x40c590`, 105 instr) does string building. **None of them is an obvious `InitInstance` that sets up the engine**, so the real start-up sequence still has to be traced.
  - `0x40b930` is a **DirectX probe**: `LoadLibraryA(<string at 0x867770>)`, `FreeLibrary`, returns a bool (this is what produces the "requires DirectX 8" error).
  - `0x40f9e0` (326 instr) points the `R_File` layer at a directory (`setArchiveHandling`, `changeDirectory`), calls `LoadLibraryA`, `GetProcAddress`, **calls the exported function, then `FreeLibrary`**: this looks like the startup dialog enumerating the driver DLLs in `e2driver\`.
  - The per-frame function `0x40c020` is not in the `CMaxPayneApp` vtable; its caller is still to be found (it reads a window pointer from `this+0xf9`, so it may belong to `CMaxPayneGameWindow`, 48 slots, or be reached from the app's `Run`).
- A scan for call sites of `DirectInputCreateA` and `RegSetValueA` found 17 and 20 sites in dialog-class code, which is not plausible for a game; treat that scan as unreliable until checked (possibly protection-wrapper code reusing those import slots).


## Startup sequence traced, and InitInstance run directly (third slice)
New tools: `tools/xrefs.py` (offline call/data/import cross-references with owner function and RTTI vtable slot), `emu/run_init.py` (boots, runs the exe's CRT + static constructors, stops at `AfxWinMain`, then calls `CMaxPayneApp::InitInstance` directly).

**The app's control flow (all confirmed in disassembly):**
- `CMaxPayneApp` vtable (`0x7cb77c`): slot 22 = `InitInstance` (`0x40b7a0`), slot 23 = `Run` (`0x40bcd0`), slot 12 = `GetMessageMap`.
- `Run` is `do {} while (0x40c020())`: the per-frame function (found earlier) returns 0 on `WM_QUIT`; afterwards `Run` does shutdown work and calls a virtual at `+0x70`. **`0x40c020` has exactly one caller: `Run`.**
- `InitInstance`: sets up the sound listener (update mechanism/interval/thread priority), `SetThreadPriority`, then three steps: `0x40b500` -> `0x40a4c0` (command line, verbosity, profiling, `R_MemoryFile` access method, `P_Map::setAutomaticPreload(false)`, DirectX probe `0x40b930`, startup dialog `0x405610`, exception handling, driver DLL enumeration `0x40f9e0`), `0x40b5e0` -> `0x40b470` (small), and `0x40b670` -> `0x40b1b0` (**engine set-up**: `M_FPUControl::setPrecision(0x200)` + `setRounding(0)` stored in the app object at `+0x118`, `GetDC/GetDeviceCaps` for the desktop size, window object creation, `R_Timer::reset`).
- The game stores settings with `CWinApp::GetProfileInt/String` (MFC `#3521`/`#3522`) and parses the command line with `CCommandLineInfo` (`#296` ctor, `#5214` ParseCommandLine), after `#6117` (probably `SetRegistryKey`).

**Decision change (D4 refined): run the real MFC42.DLL inside the emulator.**
- Guessing MFC behaviour call by call (`CString`, `CCommandLineInfo`, `GetProfileString`...) does not scale. The genuine `MFC42.DLL` ships with the game, loads at `0x5f400000`, and its `DllMain` runs once about 250 USER32/GDI32/kernel32 functions have handlers. Window and GDI calls are inert stubs with documented argument counts (no real windows exist yet); registry reads behave like an empty registry so every setting takes its default.
- We still bypass `CWinApp::Run` and the message loop: after the exe's static constructors we call `InitInstance` ourselves.
- End state is unchanged: MFC42 is lifted like any other module; only its window/GDI imports need real implementations, and only for the paths the game uses.

**Where it stops now:** `InitInstance` runs through the command-line step, profiling, process priority, the DirectX probe (a placeholder `D3D8.DLL` module satisfies it), and into the startup dialog's constructor, then throws `R_FileException_DirectoryNotFound` from `R_File::changeDirectory("data")`. Cause so far:
- `changeDirectory` first asks the real file system (`GetFileAttributesA("C:\\MaxPayne\\data")`, no such folder) and then the **`.ras` archive directory table** (`0x10010230`), which is empty: `R_File::loadArchives` (private; called from the `R_File` constructor, `setFileSystemRoot` and `setSecondaryArchiveSearchPath`) never runs a `FindFirstFileA` scan in our run. `R_File::RASArchiveList` and `Sys` exist, so the engine globals are constructed.
- **Next:** find why the archive scan does not happen (is the `R_File` singleton created lazily with a flag we have not set, does the exe call `setArchiveHandling`/`setSecondaryArchiveSearchPath` earlier in the real flow, or does the scan use an API we answer wrongly?), make the `.ras` archives register, and re-run.
- The thrown exception also shows that C++ exception unwinding (SEH frame handlers, `RtlUnwind`) is needed as soon as any code catches an exception, which is normal in this engine.

## SEH and C++ exception unwinding (fourth slice) - done
- **How it works:** the real `MSVCRT.DLL` already contains the C++ and SEH frame handlers (`__CxxFrameHandler`, `_except_handler3`), so only the OS half is emulated: `RaiseException` (first pass: walk the `fs:[0]` registration chain, calling each handler) and `RtlUnwind` (second pass: call handlers with `EH_UNWINDING`, unlink frames, resume at `TargetIp` with `EAX=ReturnValue`). Handler frames are guest code, and Unicorn cannot safely re-enter itself from a hook, so both are **generator coroutines** (`Coro`, `GuestCall`, `ResumeAt` in `emu/mpemu.py`): the dispatcher yields "call this guest function", the emulator runs it, and a dedicated return stub (stub 1) resumes the coroutine with the result. Coroutines whose HLE frame was abandoned by a catch continuation (guest `ESP` above their frame) are reaped on the next host entry.
- **Fidelity detail that mattered:** while a handler runs, real Windows keeps the *dispatcher's own registration record* at the head of `fs:[0]`. MSVC's `_UnwindNestedFrames` saves `fs:[0]` on entry and re-links that record after `RtlUnwind` (`[saved] = fs:[0]; fs:[0] = saved`). Without the record the CRT linked the user's try-frame to itself and the chain looped forever. `_push_dispatcher_frame` now pushes the record (handler `ExceptionNestedHandler`: `ContinueSearch` during unwinds, nested-exception otherwise) around every handler call, in both `RaiseException` and `RtlUnwind`.
- **Tests:** `emu/test_seh.py` (hand-assembled guest code, no game files needed): continue-execution, unhandled exception report, and a two-frame two-pass unwind (inner handler sees flags `[0, 2]`, resume at the target frame with `eax=0x55`, chain restored, no stale coroutines). All pass.
- **End-to-end proof:** the engine's `R_FileException_DirectoryNotFound` is thrown in `rlmfc`, rethrown and caught through nested frames in `rlmfc` and the exe (five raises, eight handler frames, catch-guard frames), and finally handled by the game's own code, which calls `MessageBoxA` with **"Exception in startupInit: Directory \data not found"**. `InitInstance` then returns FALSE cleanly (no fault).
- **Not implemented:** hardware exceptions (access violation, divide by zero, `int3`) are not converted into SEH; a bad memory access still stops the emulator with a diagnostic. `ExceptionCollidedUnwind` and nested-exception dispositions stop with a message. Neither has been needed so far.

**Where it stops now (updated):** `InitInstance` runs to the startup dialog's setup and fails at the same root cause as before, but now through the game's own error path: `R_File::changeDirectory("data")` finds neither a real folder nor an archive directory called `data`, because the `.ras` archives were never registered (no `FindFirstFileA` scan happens). Next: find why `R_File::loadArchives` does not run (the exe never calls `setFileSystemRoot`; `R_File`'s constructor and `setSecondaryArchiveSearchPath` are the other callers) and make the archives register.

## M2 milestone reached: the exe runs until it first calls the renderer (fifth slice)
`emu/run_init.py` boots every module, runs the exe's real CRT start-up and static constructors, stops at `AfxWinMain`, and calls `CMaxPayneApp::InitInstance` directly. It now runs all the way to the first Direct3D 8 call:

1. command line parsing (`CCommandLineInfo`, real MFC), profiling set-up, process priority, `R_System` verbosity;
2. DirectX probe (`LoadLibraryA("D3D8.DLL")`, satisfied by the placeholder module);
3. the startup script load: `R_File::changeDirectory("data")` finds `data` **inside the `.ras` archives** and the dialog texts load;
4. the game loads its renderer: `LoadLibraryA("e2driver\\e2_d3d8_driver_mfc.dll")` loads the real driver DLL on demand at `0x10400000` and runs its `DllMain`;
5. the driver calls **`Direct3DCreate8(D3D_SDK_VERSION = 120)`** (DirectX 8.0, not 8.1) from `e2_d3d8_driver_mfc.dll+0x25e52`. That import is unimplemented, so the run stops there. This is the boundary with M3.

**What fixed the archive problem** (root cause was in the emulator, not the game): `R_File`'s constructor does call `loadArchives`, which scans `*.RAS` in the current directory with `FindFirstFileA`. My path helper returned the write overlay (`emu_data/`, which always exists and is empty) for the game root, so the scan found nothing. Fixed: the root maps to the game folder, and directory listings are the union of the game folder and the overlay (overlay entries shadow game files).

**`LoadLibraryA` is now a real dynamic loader** (a coroutine): loaded module -> its base; placeholder system DLLs (`d3d8`, `dinput`, `dsound`, `advapi32`); a DLL that exists in the game folder -> map, relocate, resolve imports, run `DllMain`; anything else -> NULL with `GetLastError=126`.

**Regression checks after these changes:** `emu/test_seh.py` passes (3/3) and `emu/smoke_timer.py` still reads a plausible clock (0.0537 s after a 50 ms sleep).

**Next (start of M3):** make `D3D8.DLL` a real HLE module instead of a placeholder. First step, per the plan: implement `Direct3DCreate8` returning a COM object whose methods are logging stubs, so the first run records **exactly which `IDirect3D8`/`IDirect3DDevice8` methods, render states, texture formats and shaders the game uses**. That log defines the subset the Metal layer has to implement. The same run needs `DirectInputCreateA` and DirectSound (`DSOUND #2`) answered later, once the window and renderer exist.

## Logging Direct3D 8 layer (`emu/d3d8.py`), first run (sixth slice)
**What it is:** `Direct3DCreate8` plus fake COM objects living in guest memory with the real DirectX 8.0 vtable layouts and stdcall argument counts: `IDirect3D8` (16 slots), `IDirect3DDevice8` (97), `IDirect3DTexture8`, `IDirect3DSurface8`, `IDirect3DVertexBuffer8`, `IDirect3DIndexBuffer8`. Textures, surfaces and buffers have real guest backing memory with correct pitches (DXT and 8/16/24/32-bit formats), so `Lock*` returns usable pointers. A `Recorder` logs every method, render state, texture-stage state, transform, format, FVF, shader (declaration and instruction tokens), draw call and clear. `Emu.d3d.report()` renders it as Markdown (`census/d3d8_usage.md`; a snapshot is in `docs/d3d8-usage-startup.md`).
**Caveat that matters:** the capabilities, display modes and format answers the game receives (`fill_caps`) are *invented but plausible* DX8-era GPU values. They decide which code paths the game takes, so they must later be replaced by what the Metal layer really supports.

**What the first run recorded** (the driver's capability sweep for the startup dialog, before any device exists):
- `Direct3DCreate8(120)`: DirectX 8.0. Methods used so far: `CheckDeviceFormat` x1440, `CheckDeviceMultiSampleType` x600, `CheckDepthStencilMatch` x320, `CheckDeviceType` x40, `EnumAdapterModes` x35, `GetAdapterDisplayMode`/`GetAdapterModeCount` x5, `GetDeviceCaps` x3, `GetAdapterIdentifier`, `GetAdapterCount`.
- **Texture formats probed:** A8R8G8B8, X8R8G8B8, R8G8B8, R5G6B5, X1R5G5B5, A1R5G5B5, A4R4G4B4, X4R4G4B4, R3G3B2, A8R3G3B2, **DXT1, DXT3, DXT5**, and the **bump-map formats V8U8, L6V5U5, Q8W8V8U8, X8L8V8U8, V16U16, W11V11U10** (the game probes for environment-bump-mapping support). Render targets: X8R8G8B8, R8G8B8.
- **Depth/stencil probed:** D15S1, D16, D16_LOCKABLE, D24S8, D24X4S4, D24X8, D32. **Multisampling** is probed up to type 16 (the layer says "none only").
- No device has been created yet, so there are no render states, shaders or draw calls on record.

**Why it stops:** the startup path needs a window system. `CreateWindowExA` (the game's main window) and `CreateDialogIndirectParamA` (the startup dialog) are still stubs that return 0, so MFC concludes the dialog failed and `InitInstance` returns FALSE. Two separate pieces are needed:
1. **A minimal Win32 window manager** (HWND table, `RegisterClassA` wndprocs, `CreateWindowExA` that honours MFC's CBT hook (`SetWindowsHookEx(WH_CBT)` -> `HCBT_CREATEWND`) and sends `WM_NCCREATE`/`WM_CREATE`, `Get/SetWindowLong`, `DefWindowProc`, `SendMessage`/`PostMessage`, a message queue for `PeekMessage`). Needed for the game window and any MFC window.
2. **Bypass the startup dialog** natively (it is a settings screen: driver, resolution, options; a native launcher replaces it): find what the code after the dialog reads from it (selected driver/mode/flags) and set those directly, then run the engine set-up steps (`0x40b5e0`, `0x40b670` -> `0x40b1b0`).

## Startup dialog bypassed natively, window manager built, device created (seventh slice)

### How the startup dialog is bypassed (no dialog code runs)
Reading step B (`maxpayne.exe+0x40b470`) showed the dialog is *conditional*, not mandatory:
- `app+0xfe` (a flag from the command line) forces it; otherwise `0x407190` checks that the **saved settings are complete** and, if so, skips the dialog and copies the saved values into the app (`app+0x104..0x114`).
- The flag is cleared by the switch **`-nodialog`** (`CMaxPayneCommandLine::ParseParam`, `0x40cb90`, matches `window`, `nodialog`, `screenshot`, `profile`, `developer`, ... ). It is parsed by MFC's `ParseCommandLine` from the *process* command line. (The "Save Game \ Additional Parameters" setting is only read when a save-game file name is given.)
- The "saved settings" live in the registry under `HKCU\Software\Remedy Entertainment\Video Settings`: `Driver` (string), `Display Width`, `Display Height`, `Display Bits Per Pixel`, `CPU Driver` (int, -1 = unset), `HW Acceleration Level` (int, -1 = unset); plus `Parental Lock\Password` and `Customized Game\Customized Game` (both optional). The check requires a non-empty `Driver` and no unset/zero values.
- **`Driver` must equal the registered driver's name, and the engine names a driver after the Direct3D adapter description** (`P_D3D` takes it from `GetAdapterIdentifier`). The comparison is in `0x40db80`; with a wrong name it throws `X_RendererImplementationException_PlatformNotSelected` and step C shows "You have to select a platform from the Max Payne startup dialog". The description string is now one shared constant (`d3d8.ADAPTER_DESCRIPTION`) used both by the fake adapter and the seed.
- So the native launcher contract is: **pass `-nodialog` on the command line and provide those registry values.** `emu/run_init.py` does exactly that (`Emu.command_line`, `Emu.registry_seed`), with `-window` for windowed mode.

### Emulated settings stores
- **Registry** (`RegCreateKeyExA`, `RegOpenKeyA`, `RegQueryValueExA`, `RegSetValueExA`, ...): an in-memory store with the standard `HKCU\Software` / `HKLM\Software` roots present (MFC gives up silently if `HKCU\Software` is missing; this cost an hour to find), a log (`Emu.reg_log`) and a seed hook.
- **INI files** (`GetPrivateProfile*`, `WritePrivateProfileStringA`, `GetProfileIntA`): same, for completeness (not used by this game).

### Minimal Win32 window manager (`emu/winsys.py`)
Window table and class registry (built-in `BUTTON`, `STATIC`, `EDIT`, `COMBOBOX`, `LISTBOX`, `SCROLLBAR`, `#32770`); `CreateWindowExA` that **calls MFC's CBT hook** (`SetWindowsHookEx(WH_CBT)`, `HCBT_CREATEWND`) so MFC can subclass the window, then sends `WM_NCCREATE`, `WM_CREATE`, `WM_SIZE`, `WM_MOVE`, `WM_SHOWWINDOW`; a native `DefWindowProc`; `SendMessage` / `PostMessage` / `CallWindowProc` / `DispatchMessage` with a message queue; `Get/SetWindowLong`, props, text, rectangles, focus/activation, `ShowWindow`, `MoveWindow`, `SetWindowPos`, `AdjustWindowRectEx`. Every call into a guest window procedure is a coroutine step, so window procedures can themselves create windows and throw C++ exceptions. Dialog templates, child controls, painting, firing timers and real input are not implemented.
- The game window now exists: class `AFX:0:3`, title **"Max Payne v1.05"**, style `0xca0000`, handle `0x10010`.

### Result: the game creates its Direct3D device and renders
With the dialog skipped, startup proceeds through driver registration (the engine's `P_Device` loads every DLL in the driver folder; the Direct3D driver registers a `P_D3D` driver object when its DLL loads), `CreateDevice`, texture/vertex-buffer/index-buffer creation and **8 indexed draw calls and a `Present`** (see `docs/d3d8-usage.md`, now 43 distinct Direct3D methods). Startup then continues into long engine initialization (script and level loading): about 140,000 host calls (mostly `HeapAlloc`, `QueryPerformanceCounter`, `HeapFree`, critical sections) in the first 400 million instructions, so it is slow under emulation, not stuck.

### Where the full startup run stops now (8 billion instruction budget, 56 s)
Startup completes through device creation and into engine initialization, then stops at **`DirectSoundCreate` (`DSOUND.DLL` ordinal 2), called from `sndmfc.dll+0x1651`**: the next missing system layer (audio). By then the recorder has **16 indexed triangle-list draws in 2 presented frames** and no clears, lights, shaders or transforms.

**What the game really asks of Direct3D so far** (all from `docs/d3d8-usage.md`; remember the caps it was *given* are invented):
- Device: windowed, `X8R8G8B8` back buffer sized to the window (1922x1063 here, from the emulated window rectangle), 1 back buffer, `SwapEffect` 1 (discard), **auto depth-stencil `D32`**, behaviour flags `0x20` (`D3DCREATE_SOFTWARE_VERTEXPROCESSING` is 0x20: the engine requests software vertex processing and does its own transform/clipping/lighting), no multisampling.
- Pipeline: **fixed function only so far** (no vertex or pixel shaders created, `SetVertexShader` with an FVF, `SetPixelShader(0)`), `DrawIndexedPrimitive` triangle lists, `SetStreamSource` + `SetIndices`, 8 textures created.
- Render states seen: Z enable/write/func (4 and 8), cull mode (1 and 3), alpha-blend on/off with `SRCBLEND` 2/5 and `DESTBLEND` 1/6 (i.e. one-zero style and src-alpha/inv-src-alpha style blends), alpha test off, fog off, lighting off, specular off, stencil off, `NORMALIZENORMALS`/`LOCALVIEWER` on, `BLENDOP` add.
- Texture stages: stage 0 uses colour/alpha ops 2 (select arg1) and 3 (select arg2), clamp addressing (3), point filtering (1) and **max anisotropy 16**; stages 1 to 7 are reset to "disabled" (op 1) with texcoord indices 1..7. So the engine initializes up to 8 stages but this frame uses one.
- Formats probed earlier: DXT1/3/5, bump-map formats, D15S1/D16/D16_LOCKABLE/D24S8/D24X4S4/D24X8/D32, multisample types up to 16.

**Next:** (1) a DirectInput layer (see the next section), (2) look at what is drawn (the first frames are probably the loading/logo screens: dump the framebuffer contents), (3) speed: host calls (heap, timer, critical sections) are the bottleneck, so implement the hottest ones as tiny guest-code stubs instead of Python hooks, (4) the hardware-exception to SEH conversion is still missing.

## DirectSound layer (`emu/dsound.py`, eighth slice)
**Correction:** `DSOUND.dll` ordinal 2 is **`DirectSoundEnumerateA(callback, context)`**, not `DirectSoundCreate` (ordinal 1). The call site pushes two arguments; my earlier note was wrong.

**What it provides:** `DirectSoundEnumerateA` (a coroutine that calls the game's `BOOL CALLBACK(guid, description, module, context)` once for the default device and once for a named one), `DirectSoundCreate` (`#1`), `CoCreateInstance` for `CLSID_DirectSound`/`DirectSound8` (other CLSIDs, such as DirectShow's `CLSID_FilgraphManager`, still return `REGDB_E_CLASSNOTREG`), and fake COM objects in guest memory with the real vtable layouts and stdcall counts: `IDirectSound`, `IDirectSoundBuffer`, `IDirectSound3DListener`, `IDirectSound3DBuffer`, `IDirectSoundNotify`. `QueryInterface` returns the 3D listener (primary buffer with `CTRL3D`), 3D buffers, and notify objects. Buffers have real guest backing memory; `Lock` returns the usual two regions with wrap-around, and `Unlock` keeps whatever was written. A **play cursor advances on the host clock** while a buffer is playing (looping or one-shot), so streaming code sees a moving cursor. Recorder report: `docs/dsound-usage.md`.

**What the game does with audio (first run):**
- Enumerates devices, then creates the DirectSound object **five times through COM** (`CoCreateInstance(CLSID_DirectSound, IID_IDirectSound)`), calling `Initialize` with the default device and the named one, `SetCooperativeLevel(EXCLUSIVE)` on the desktop handle first and then on the game window.
- **Primary buffer:** `PRIMARYBUFFER|CTRL3D`, format set to **44.1 kHz, 2 channels, 16-bit PCM**. The 3D listener gets orientation, position, rolloff and velocity.
- **Ten secondary buffers**, each **88,200 bytes = 0.5 s** of 44.1 kHz stereo 16-bit, flags `CTRL3D|CTRLFREQUENCY|CTRLPAN|CTRLVOLUME|STICKYFOCUS|GLOBALFOCUS` (not `STATIC`: streamed or looping voices), each queried for `IDirectSound3DBuffer`.
- No `Play` calls yet, so nothing audible is requested at this point of startup. The intro movie's DirectShow graph (`CLSID_FilgraphManager`) is the only unprovided COM class so far.

**Where startup stops now:** `DirectInputCreateA` (`DINPUT.dll`), called from `maxpayne.exe+0x11a72e`: the next missing system layer (input). The run still reaches 16 draws and 2 frames.

## DirectInput layer (`emu/dinput.py`, ninth slice)
**What the game asks for** (read from `maxpayne.exe+0x51a6c0` creation, `+0x517e70` keyboard, `+0x518c40` mouse): `DirectInputCreateA(hinst, 0x0700)` (DirectInput 7, stored at `0x8ac6bc`, reference-counted), then two devices:
- **Keyboard:** `GUID_SysKeyboard`, `c_dfDIKeyboard` (256 bytes), `NONEXCLUSIVE|FOREGROUND|NOWINKEY`, 16-entry event buffer.
- **Mouse:** `GUID_SysMouse`, `c_dfDIMouse2` (`DIMOUSESTATE2`, 20 bytes: X/Y/wheel plus 8 buttons), `EXCLUSIVE|FOREGROUND` (so the host must capture the cursor and use relative motion), 16-entry buffer, `GetCapabilities`, and `GetProperty(GRANULARITY)` on the wheel (answered `WHEEL_DELTA` = 120).
- Per frame the code reads both `GetDeviceState` (immediate) and `GetDeviceData` (buffered, 16-byte DirectX 7 `DIDEVICEOBJECTDATA`), re-acquiring on `DIERR_INPUTLOST`.
- Outside DirectInput the game also reads the keyboard through USER32: `GetAsyncKeyState` (Ctrl at `+0x40a441`, Escape at `+0x43a85b`), `GetKeyNameTextA` (key names for the controls menu, `+0x519b80`), and a **`WH_KEYBOARD` hook** (`+0x518360`) that turns key presses into typed characters with `GetKeyboardState` + `ToAscii`.

**What it provides:** `DirectInputCreateA`/`Ex`, `IDirectInput7A` (`CreateDevice`, `EnumDevices` as a coroutine with guest callbacks, `GetDeviceStatus`) and `IDirectInputDevice7A` (one object answers every interface version). `SetDataFormat` matches each `DIOBJECTDATAFORMAT` to a device object the way DirectInput does (GUID, type, `ANYINSTANCE`, `OPTIONAL`), so immediate and buffered data use the game's own offsets. Acquire/unacquire, `DIERR_NOTACQUIRED`/`DIERR_INPUTLOST`, buffer size, `DI_BUFFEROVERFLOW`, `DIGDD_PEEK`, global sequence numbers and `GetTickCount`-clock timestamps follow DirectInput. Mouse axes are relative and accumulate between `GetDeviceState` calls. `GetAsyncKeyState`, `GetKeyState`, `GetKeyboardState`, `ToAscii` (US layout) and `GetKeyNameTextA` read the same key state, so every keyboard path agrees.

**Host side:** `e.dinput.key(dik, down)`, `mouse_move(dx, dy)`, `mouse_wheel(dz)`, `mouse_button(n, down)`, `focus_lost()`, and an `on_poll(e, device)` callback called before every read (for scripted input in tests and replays). The SDL3 window layer will call these. Tests: `.venv/bin/python emu/test_dinput.py` (keyboard and mouse state, buffers, overflow, focus loss, `EnumDevices` callbacks, USER32 queries). Recorder report: `docs/dinput-usage.md`.

**Not done:** no joystick or force feedback. (Keyboard messages and the `WH_KEYBOARD` hook: done in the tenth slice.)

**Where startup stops now:** nowhere. **`CMaxPayneApp::InitInstance` returns TRUE with no fault** after about 115 s and 514,000 host calls. The recorder now has **96 draw calls in 12 presented frames**. No missing imports were hit. Both input devices are created and acquired but never read, because the per-frame code runs from the message loop (`CWinApp::Run`), which `run_init.py` does not run yet.

**Next:** run the main loop (done in the tenth slice, below).

## Main loop under emulation (tenth slice)
**How the game loops:** `CMaxPayneApp::Run` (vtable slot 23, `maxpayne.exe+0x40bcd0`) is `while (frame()) {}` followed by `ExitInstance`. The frame function is `+0x40c020`: it checks the FPU control word, samples the timer, runs the engine update (`+0x601250`), renders (`+0x6014d0`), then drains the message queue (`PeekMessage(PM_REMOVE)` → `PreTranslateMessage` → `TranslateMessage`/`DispatchMessage`), and returns FALSE on `WM_QUIT`. `emu/run_init.py --frames N` calls it N times after `InitInstance`. `--input "F:action,..."` injects host input before frame F (`key=`/`keyup=` DIK hex, `move=dx;dy`, `wheel=`, `button=`/`buttonup=`, `focus=0|1`).

**Fixes this needed:**
- **Activation.** The game renders only when the app is active: the byte at `app+0xff`, set by the game window's `OnActivateApp` (`+0x40d270` → gain focus `+0x40baf0`, which also resumes the timer and sound). `winsys` now sends the Windows activation sequence (`WM_ACTIVATEAPP`, `WM_NCACTIVATE`, `WM_ACTIVATE`, `WM_SETFOCUS`/`WM_KILLFOCUS`) from `ShowWindow`, `SetActiveWindow`, `SetForegroundWindow` and `SetFocus`. Before this, frames ran with no draws at all. `winsys.host_set_app_active(e, bool)` is the host's focus-change call; losing focus also unacquires the DirectInput devices.
- **Keyboard messages.** Host key presses are also posted as `WM_KEYDOWN`/`WM_KEYUP` (`WM_SYSKEY*` with Alt or F10) to the focus window. `PeekMessage`/`GetMessage` pass them through `WH_KEYBOARD` hooks (the game's typed-text hook at `+0x518360` now runs). `TranslateMessage` adds `WM_CHAR`.
- **Long frames.** Unicorn stops *silently* when an `emu_start` instruction count runs out. A level load is one frame of about 6 billion instructions, and the runner's 2-billion budget cut it off; the next call then started a new frame on top of the half-finished one. That left stale SEH registrations, and a 24-bit FPU precision setting whose `M_FPUControl` destructor never ran, which tripped the game's own precision check (`MaxPayneAppException_InvalidFPUPrecision`). `Emu.call` now sets `budget_exhausted` and leaves the guest where it is, and `Emu.resume()` continues it. (Diagnostics kept in `run_init.py`: `--fpu-watch` hooks every `fldcw`; `--precision-callers` hooks `M_FPUControl`.)
- The Direct3D, DirectSound and DirectInput layers cached vtables by `id(emu)`; a later emulator could reuse the id and get a stale vtable (it broke a unit test). The cache now lives on the emulator.

**Result (scripted run, see `docs/dinput-usage.md`):**
- Main menu: 16 draws per frame, about 30 ms per frame emulated.
- **Enter** on the menu starts a new game. The load runs in one frame (6 billion instructions, about 250 s, 1,235 file opens, 57 progress-screen presents).
- **The first level then runs:** 43–44 draws per frame, about 0.3 s per frame emulated, input polled every frame, no faults.
- **Escape** in the level returns to the main menu.
- Mouse motion and buttons arrive as buffered DirectInput events.
- What is on screen is still unknown, because the D3D8 layer only records calls.

**Next:** see what is drawn: done in M3 (`docs/m3-renderer.md`). Two fake-caps bugs made everything invisible or point-filtered until then; with them fixed a level frame is 132 draws. Speed matters now too: a level frame costs about 2,500 host calls and 0.9 s.

## Not done yet (next)
- **Imports still without handlers** for the modules loaded so far: DSOUND `#2`; GDI32 `CreateDIBSection`, `DeleteObject`, `GetDIBits`, `GetDeviceCaps`; USER32 `GetActiveWindow`, `GetDC`, `GetDesktopWindow`, `MessageBoxA`, `ReleaseDC`, `SystemParametersInfoA`; OLE32 (3, the movie player); kernel32 threads/process/console calls (not on the startup path); MFC42 `#349 #350 #860 #940 #1100 #1105 #1832 #2740 #2801 #2919 #3663 #5440 #6383` (rlmfc/sndmfc, **names unknown**, see census).
- (SEH / C++ exceptions: done, see above.)
- **Bypassing MFC (D4) is not finished.** The exe loads and starts, but the engine start-up sequence (window creation, driver loading and `DRV_init`, input, game mode creation) lives in code reached from `CWinApp::Run`/the main window, not in an obvious `InitInstance`. Next: find the callers of `0x40c020` and of the driver-loading code (xrefs, the `CMaxPayneGameWindow` vtable) and read the order of engine calls, then replace the MFC glue with native code that makes the same calls.
- **D3D8:** the driver DLL `LoadLibrary`/`GetProcAddress`es `d3d8.dll`; that needs the HLE Direct3D layer (M3). Not loaded yet.
- Performance: measured and improved in M4, see `docs/m4-progress.md` (a level frame went from 0.9 s to about 0.2 s).
