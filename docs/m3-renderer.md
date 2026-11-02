# M3: Metal renderer (D3D8 subset)

## Status
- **The main menu and the first level (the tutorial) render through Metal**, and agree with an independent reference rasterizer:
  - menu: mean error 0.08 (0–255 scale), 0.000% of pixels off by more than 8;
  - tutorial frame: mean error 0.17, 0.06% of pixels off by more than 8, all on triangle edges and texel boundaries.
- Metal replays a menu frame in about 5 ms and a level frame (132 draws) in about 13 ms at 1922×1063.
- **Live view:** `emu/run_init.py --window` shows the emulated game in a native window (SDL3 + CAMetalLayer) and passes keyboard and mouse input to the game.
- Not done against the plan's "done when": no comparison with real Windows screenshots (M0 references were never taken). The reference rasterizer stands in for them: it is written straight from the D3D8 rules and shares no code with the Metal path.

## Pieces
| Path | What |
|---|---|
| `emu/d3dcap.py` | The **MPD3 command stream**: the contract between the game side and the renderer. Records: TEXTURE, RENDERSTATE, TSS, SETTEXTURE, VIEWPORT, CLEAR, DRAW (vertex/index bytes), PRESENT, TRANSFORM. Has a writer (file or live sink) and a reader. |
| `emu/d3d8.py` | Tracks the current device state and, while capturing, emits records: `start_capture(e, path)` / `stop_capture(e)`. Texture contents are re-sent only when their CRC changes; vertex and index data are copied per draw for the referenced vertex range, with rebased indices. |
| `emu/run_init.py` | `--capture DIR --capture-frames 5,38` writes `frame_NNN.mpd3`; `--window` runs the live view. |
| `tools/refrast.py` | Reference software rasterizer (numpy): capture → PNG. `--list` prints per-draw state; `--dump-textures DIR` writes every texture. |
| `render/mprender.h`, `render/mprender.m` | **libmprender**: Metal renderer with a C API (`mpr_create`, `mpr_submit(type, payload)`, `mpr_read_rgba`, `mpr_present_to_layer`). Shaders are compiled from source at startup, so it needs only the Command Line Tools. |
| `render/mpreplay.m` | Replays a capture offscreen and writes a PNG. |
| `emu/live.py` | SDL3 window, a live sink feeding libmprender, and SDL keyboard/mouse/focus mapped to DirectInput DIK codes and WM_ACTIVATEAPP. |
| `tools/test_render.py` | 11 synthetic conformance tests (no game files): Metal vs reference for each feature. |
| `tools/imgdiff.py` | Image comparison (mean error, % of pixels over a tolerance, difference image). |

Build and check:
```bash
make -C render
```
```bash
.venv/bin/python tools/test_render.py
```
Capture and compare (game files needed; output goes to the git-ignored `captures/`):
```bash
.venv/bin/python emu/run_init.py "Max Payne" --frames 61 --input "25:key=1c,26:keyup=1c" --capture captures --capture-frames 5,60
```
```bash
.venv/bin/python tools/refrast.py captures/frame_060.mpd3 && build/mpreplay captures/frame_060.mpd3 captures/frame_060.metal.png && .venv/bin/python tools/imgdiff.py captures/frame_060.ref.png captures/frame_060.metal.png
```
Play live: startup takes about 25 seconds and a level load about 50 seconds under emulation, then about 5 frames per second in the level (see `docs/m4-progress.md`). Click the window to capture the mouse; Cmd+Esc releases it.
```bash
.venv/bin/python emu/run_init.py "Max Payne" --window
```

## What the renderer implements (what the game uses)
- **Vertices:**
  - pre-transformed `XYZRHW`: pixel centres at integers, shifted +0.5 for Metal; `w = 1/rhw` for perspective-correct interpolation; screen-linear depth;
  - untransformed `XYZ`/`XYZBn`: `v × World × View × Projection`, then D3D's viewport mapping (NDC −1 → pixel centre X; depth into MinZ..MaxZ). The engine puts its whole camera matrix in VIEW and never sets WORLD or PROJECTION;
  - attributes: `DIFFUSE`, `SPECULAR`, up to 8 texture coordinate sets. Vertex pulling in the shader, so every FVF uses one pipeline.
- **Primitives:** triangle lists, strips and fans (fans converted to lists), points and lines; 16/32-bit indices.
- **Pixels:**
  - the texture-stage combiner: `D3DTOP_*` 2–16 and 24–26, `D3DTA_*` arguments with COMPLEMENT/ALPHAREPLICATE, `RESULTARG` TEMP, `TEXCOORDINDEX`;
  - vertex fog (specular alpha) and alpha test (8-bit compare against ALPHAREF);
  - blending with every `D3DBLEND` factor and `D3DBLENDOP`, depth test and write, culling, `COLORWRITEENABLE`;
  - clears limited to the viewport and rects.
- **Back buffer:** BGRA8 with alpha writes masked off, so destination alpha reads 1, as with X8R8G8B8.
- **Textures:** R8G8B8, A8R8G8B8, X8R8G8B8, R5G6B5, X1R5G5B5, A1R5G5B5, A4R4G4B4, X4R4G4B4, A8, L8, A8L8, converted to BGRA8 with mip levels. Samplers: point, linear and anisotropic min/mag; none, point and linear mip; wrap, mirror, clamp, border and mirror-once.
- **Not implemented** (reported by `mpr_notes`/refrast, none seen in the captured frames):
  - fixed-function lighting (every draw so far has `LIGHTING` off);
  - vertex blending, texture transforms and texcoord generation;
  - stencil, flat shading, DXT textures.

## Bugs found by looking at the frames
- **Guard band caps** (`emu/d3d8.py` `fill_caps`): all four `GuardBand*` values were +8192. The engine clamps screen x/y into [GuardBandLeft, GuardBandRight], so **every vertex collapsed to (8192, 8192)** and nothing the game drew would have been visible. Left/Top are now −8192. With the fix, the level issues 132 draws per frame instead of 44: the engine's own culling had been rejecting most of the scene.
- **Texture filter caps:** `TextureFilterCaps` advertised no linear minification or mip filtering, so the engine chose point sampling everywhere (blocky walls). It now advertises what Metal supports, and the engine uses bilinear filtering.
- **Culling direction:** the first Metal version culled the wrong faces. The synthetic culling test caught it before any game frame was compared.

## Differences between the two renderers (accepted)
- Mip level choice: the reference uses one LOD per triangle; Metal uses per-pixel derivatives.
- Point-sampled texels and triangle edges at exact boundaries round differently (float32 on the GPU, float64 in numpy). Tests keep texture coordinates off exact wrap boundaries for this reason.

## Next
- Real-Windows reference screenshots (the plan's M0) for the same scenes, to validate the reference rasterizer itself.
- Speed is the bottleneck for playing live: about 0.2 s per level frame under emulation (was 1 s; see `docs/m4-progress.md`).
- Fixed-function lighting and DXT once a scene uses them; the renderer notes will say so.
