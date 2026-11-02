# Contributing

Thanks for helping. Bug reports, fixes, performance work and better docs are all welcome. Please read the first
section before anything else: it is the one rule that keeps this project possible.

## The one hard rule: no game content

This repository contains tools and source code only. Never commit, attach or paste:

- game files: `MaxPayne.exe`, the DLLs, the `x_*.ras` archives, movies, or anything extracted from them;
- generated code: the C the lifter writes (`lift-out/`, `build-lift/`), its objects and libraries;
- decompiler output (Ghidra, IDA, …) of the game's code;
- captures, save games or screenshots that embed game assets in bulk.

This applies to pull requests, issues, comments and links. [`.gitignore`](.gitignore) already excludes the usual
paths; check `git status` before you commit anyway. Pull requests that include such content are closed, and the
history is rewritten if it lands by mistake. The background is risk R8 in [`PLAN.md`](PLAN.md): the generated code is
a derivative of the original, so every player lifts their own copy locally.

`lift/native/` is the one place with game-specific C. It holds **hand-written** replacements for a few hot engine
functions. A new one must be written from an understanding of what the function does, not pasted from a
decompiler, and must be checked against the recompiled original (see the existing ones for how).

## Setting up

You need everything from the README's [Requirements](README.md#requirements), including your own Max Payne 1.05.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```
```bash
make -C host
```

Put (or symlink) your game folder at `Max Payne/` in the checkout, or set `MP_GAME_DIR`. Then
`.venv/bin/python lift/build_game.py` builds the lifted library and `./play.sh --game-mode windowed` runs it.

The emulator in `emu/` is the reference for differential testing. It is about twice as fast with the patched Unicorn
from `tools/build_unicorn.sh`.

## Tests

```bash
.venv/bin/python -m pytest lift emu
```

Tests that need the game skip when it isn't there. CI (`.github/workflows/ci.yml`) runs the ones that don't need
it, builds the host and checks the packaging scripts. It must pass before a pull request is merged.

For changes to the host, renderer, audio or lifter, also play the part of the game you touched and say in the pull
request what you checked (which level, which resolution, windowed or fullscreen).

## Pull requests

- One topic per pull request; keep unrelated cleanups out.
- Write code like the code around it: same naming, comment density and idiom.
- Commit subjects follow the history: `Area: what changed`, with the milestone in parentheses when there is one,
  e.g. `HUD under Hor+: sniper scope reaches the screen edges (M7)`.
- Explain *why* in the description, and link the issue it fixes.
- Update the README or `docs/` when behaviour or options change.

## Reporting bugs

Use the bug report form. Include your Mac model, macOS version, the launch options you use, what you were doing in
the game, and the end of `~/Library/Logs/Max Payne Recomp.log`. Only Max Payne **1.05** is supported; if
`make-app.sh` says a file differs, that is not a bug in this project.

## License

By contributing you agree that your contribution is licensed under the [MIT license](LICENSE).
