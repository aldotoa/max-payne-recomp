# Max Payne Recomp

A native **Apple Silicon macOS** port of *Max Payne* (Remedy, 2001), made by **statically recompiling** the original
32-bit x86 Windows game to arm64. It is not Wine and it is not an emulator. Every game module (the exe, the engine
DLLs, the Direct3D 8 driver and the MSVC runtime) is translated to C and compiled with clang. A small native host
stands in for Windows: Direct3D 8 runs on Metal, DirectSound and DirectInput on SDL3, and the intro movies play
through AVFoundation.

- Native resolution with Hor+ widescreen, and a HUD anchored to the real screen edges
- Variable frame rate up to 60 fps (the simulation is variable-dt)
- Saves, settings and save thumbnails work as on Windows

> **You need your own copy of the game.** This repository contains only tools and source code: no game files and
> no code generated from the game. The recompilation runs on your Mac, using your files.

## Quick start

```bash
git clone https://github.com/aldotoa/max-payne-recomp.git
```
```bash
cd max-payne-recomp
```
```bash
./make-app.sh
```

A Finder window asks for your Max Payne folder (the one with `MaxPayne.exe` in it). The script then:

1. checks your Mac and installs anything that is missing, asking you first (SDL3 and, if needed, Python, through Homebrew);
2. checks that your game files are the supported version;
3. recompiles the game for your Mac, which takes **10–20 minutes**;
4. writes **`dist/Max Payne.app`** and opens the folder.

Drag the app to Applications and double-click it. The app contains a copy of your game (about 1.2 GB), so you can
delete or move the original folder afterwards.

Options: `./make-app.sh --game "/path/to/Max Payne"` skips the folder picker. `--dmg` also makes
`dist/Max Payne.dmg`. `--skip-lift` reuses the recompiled library from an earlier run. `-y` installs missing tools
without asking.

> The app you build contains the game. It is for your own use, so please don't share it.

## Requirements

- A Mac with Apple Silicon (M1 or later), on macOS 13 Ventura or later
- Xcode Command Line Tools: `xcode-select --install` (the script offers it)
- [Homebrew](https://brew.sh)
- About 3 GB of free disk space while building (about 1.3 GB once it is done)
- Your own copy of **Max Payne 1.05** for Windows (see below)

## Providing the game files

The game itself is not in this repository and is never downloaded by it. You point `make-app.sh` at a Max Payne
folder you already have, and everything happens locally on your Mac: nothing is uploaded.

**Where to get it.** Any legitimate Windows copy works once it is at version 1.05:

- A digital store copy (for example Steam) ships as 1.05. Install it on a Windows PC, or in CrossOver or a Windows
  VM, and copy the installed folder to your Mac. With Steam you can find it with *Manage → Browse local files*. The
  version check below tells you if your store build differs.
- A retail CD: install it on Windows and apply the official 1.05 patch, then copy the folder.
- An existing Windows install: copy its whole `Max Payne` folder (USB stick, network share, cloud drive).

**What the folder needs.** `MaxPayne.exe`, `rlmfc.dll`, `grphmfc.dll`, `e2mfc.dll`, `sndmfc.dll`,
`e2driver/e2_d3d8_driver_mfc.dll`, the four runtime DLLs (`MSVCRT.DLL`, `MFC42.DLL`, `MSVCP60.DLL`, `MSVCIRT.DLL`)
and the `x_*.ras` archives. Copying the whole installed folder gives you all of these; extra files don't hurt.

**The version check.** The recompilation is tied to the exact binaries. The script checks every module against
[`tools/game-hashes.txt`](tools/game-hashes.txt) and tells you which file differs. Other versions (older patches,
cracked or repackaged executables, no-CD patches) are not supported. To check a folder without building anything:

```bash
python3 lift/build_game.py --game "/path/to/Max Payne" --check
```

**For development** (`./play.sh`, the tests), put the folder or a symlink to it at `Max Payne/` in the checkout, or
set `MP_GAME_DIR`. It is listed in `.gitignore`, so it can't be committed by accident.

## Playing

- Saves and settings: `~/Library/Application Support/Max Payne Recomp`. They are kept when you rebuild the app.
- Launch options: edit `~/Library/Application Support/Max Payne Recomp/launch-options` (the file is created the first
  time you start the app). Put the options on one line, for example:
  - `--resolution 1920x1080`: the display mode (by default, your screen's)
  - `--game-mode windowed`: play in a window (the default is `fullscreen`)
  - `--intro skip`: skip the intro movies
  - `--audio off`: no sound
  - `--view stretch`: the original 4:3 view, stretched (the default is `hor+`)
- Log: `~/Library/Logs/Max Payne Recomp.log`. If the game stops with an error, an alert shows the end of this log.

From a checkout you can also run the game without building the app: `./play.sh [options]`.

## Troubleshooting

| Problem | Fix |
|---|---|
| "is a different version than the one this project supports" | Use the 1.05 retail or store files. The message names the file that differs. |
| "the Xcode Command Line Tools are needed" | Finish the installer that opened, then run `./make-app.sh` again. |
| The build stops partway through | Run `./make-app.sh` again. `--keep-intermediate` keeps the generated C so you can look at it. |
| The app won't open ("damaged" or "unidentified developer") | Apps you build on your own Mac aren't quarantined. If you copied the app from somewhere else, rebuild it on this Mac. |

## How it works

| Directory | What it is |
|---|---|
| `lift/` | The x86 → C translator (`x86c`), the function inventory (`functions.py`), the build (`build.py`, `build_game.py`) and the guest runtime (`lift/runtime/`: CPU state, x87, SEH, heap) |
| `host/` | `mphost`: loads the recompiled game, maps its 32-bit address space and implements the Win32, D3D8, DirectSound, DirectInput and DirectShow calls the game makes |
| `render/`, `audio/`, `movie/` | Metal renderer, SDL3 sound mixer, AVFoundation movie player |
| `emu/` | The Unicorn-based emulator used during development, as the reference for differential testing |
| `docs/` | Milestone notes: census, renderer, lifter spike, emulator removal, resolution, 60 fps |
| `tools/` | Analysis, packaging (`package_app.sh`) and regression tools |

[`PLAN.md`](PLAN.md) has the full plan and its status.

### Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```
```bash
.venv/bin/python -m pytest lift emu
```

Tests that need the game look in `Max Payne/` in the checkout (or `MP_GAME_DIR`) and skip when it isn't there. The
emulator is much faster with the patched Unicorn from `tools/build_unicorn.sh`.

## Contributing

Bug reports and pull requests are welcome: see [`CONTRIBUTING.md`](CONTRIBUTING.md). Above all, never post game
files, generated C or decompiler output in issues or pull requests.

## Legal

The code in this repository is under the [MIT license](LICENSE). *Max Payne* and its content are the property of
their owners (Remedy Entertainment / Rockstar Games). This project is not affiliated with or endorsed by them. No
game data, original binaries, or code generated from them is distributed here. The only game-specific C in the
repository is `lift/native/`: hand-written, faster replacements for a few hot engine functions, made for
interoperability and checked against the recompiled originals.
