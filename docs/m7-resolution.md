# M7: native resolution (target 2560×1600, 16:10)

The user's target display is 2560×1600 (PLAN.md open question 1, 2026-10-25).

## The desktop at 2560×1600
The desktop the game sees is 2560×1600 on both sides. In the emulator it is `mpemu.SCREEN` (also the source of `d3d8.display_modes`, the launcher's Video Settings seed, `GetSystemMetrics` and the window rects). In the host it is `HOST_SCREEN_W`/`HOST_SCREEN_H` in `host/host.h`, used by `hle_d3d8.c` (adapter mode, `MODES`), `hle_user32.c`, `hle_winsys.c`, the registry seed in `hle_advapi32.c` and the live window's default in `live.c`. The adapter offers 640×480 … 1920×1080 as before, with 2560×1600 last. Saved Video Settings are used as they are, so an existing data dir keeps its resolution until it changes there. `mphost --resolution WxH` (and `./play.sh --resolution WxH`) picks one of the adapter's modes and writes it to the data dir's Video Settings, as the launcher's `--resolution` does; any other size is refused with the list of modes. `host/test_host.py` passes 5 of 5 with the new desktop: images, the one-frame trace (35,960 calls), scripted input, the captures of frames 0-2, the mixer.

## The game at 2560×1600
The test run used a copy of the data dir with both Video Settings keys set to 2560×1600 and the H53 gameplay workload, 700 frames, headless. The back buffer and viewport are 2560×1600. The run ends with exit code 0, and the captures render the main menu and the Part 1 corridor.

## FOV and HUD at 16:10: fixed 4:3, stretched
- **The engine projects almost everything itself.** Nearly every draw is pre-transformed (`XYZRHW`: FVF 0x104, 0x144, 0x1c4, 0x284, 0x2c4). One draw per gameplay frame (FVF 0x152, XYZ|NORMAL) goes through D3D's projection. That matrix is `_11` 1.4281, `_22` 1.9042 (`_22/_11` = 4/3) at both 1920×1080 and 2560×1600. That is a 4:3 view: 70.0° horizontal, 55.4° vertical.
- **The 3D view does not adapt to the aspect.** The comparison was frame 170 of the same run at 1920×1080 and at 2560×1600: Resume Game, no mouse input, so the camera comes from the save. Over about 4,000 matched vertices, the positions relative to the screen centre are the same on both axes: the median ratio is 1.0000, p10 and p90 within 0.0002. The engine maps a fixed 4:3 frustum onto whatever back buffer it gets, so the picture is **stretched horizontally by 1.2× at 16:10** (1.333× at 16:9). Hor+ at 16:10 would keep the 55.4° vertical FOV and widen the horizontal one to **80.1°** (projection `_11` = 1.1901).
- **The 2D layer (menus, HUD, text) is stretched too.** It is laid out in the 640×480 virtual space and scaled per axis to the back buffer. The menu background tiles come out 1016 × 846.7 px, a 1.2 ratio, so the art fills the full width. The HUD's normalized positions match the 3D view's, so the health figure and the ammo counter stay in the bottom corners, but their glyphs are 1.2× wide. A pillarboxed 4:3 menu at 2560×1600 would be 2133 px wide with 213 px bars.

## Hor+ (H74)
**Where the engine sets its view.** `P_Camera::validate` (e2mfc 0x10014d60, 0x10114d60 as loaded) runs while the camera's dirty bit (+0xe0 bit 0x40, set by `setFOV` and `setViewport`) is set. It caches two tangents: +0x200 = tan(fov / 2) from the FOV at +0x110 (70.0°, horizontal), and +0x204 = +0x200 × (y1 − y0) / (x1 − x0) of the camera's viewport (+0x1c4 x0, +0x1c8 x1, +0x1cc y0, +0x1d0 y1). That viewport is in the 640×480 virtual space, so the view is always 4:3. `P_Camera::prepare` (0x10014db0) builds the projection and the frustum from the two tangents, and the engine's own vertex transform and `getViewportCoordinate` read them too. `P_Text`, `P_2DLineObject` and `P_Sprite::executeAlways` (0x10004280, 0x10005eb0, 0x10008040) recompute the same 4:3 tangents from the FOV to place 2D objects in camera space. Neither `EnableWideScreen` nor `ChangeFOV` had to be used.

**The change.** After validate, the host widens +0x200 by k = (W / H) / (4 / 3) of the back buffer (1.2 at 2560×1600). The vertical tangent and FOV stay the same. Pieces:
- Lifter: `x86c.EXIT_HOOKS` (`build.py --exit-hook`), the counterpart of `ENTRY_HOOKS`: a hooked function calls `lift_exit_hook(c, va)` before each `ret`, with ESP still at the return address. Test: `lift/test_x86c.py` `test_exit_hook`.
- Runtime: `lift_set_exit_hook(cb)`, where cb gets the CPU and the VA and runs in round-to-nearest.
- Host (`host/mphost.c`): `on_exit_hook` scales the float at camera +0x200 when the dirty bit is set, with k from the device's back buffer at that moment (a mode change applies to a camera once its projection is next recomputed). `--view hor+|stretch` (default `hor+`); `stretch` keeps the 4:3 view stretched. A library without `lift_set_exit_hook` prints a note and plays stretched.
- Library `build-lift/liblifted_full_h74.dylib` (now the default for `play.sh` and `host/test_host.py`): H64's sources and objects hard-linked (`lift-out/lifted_full_h74`), with `f_10114d60` regenerated with the hook and `lift/runtime` recompiled. The regenerated function differs from H64's only by the hook line.

**Checks** (data dir copy at 2560×1600, H53 gameplay workload, headless, `--view hor+` against `--view stretch`):
- The D3D projection in frame 400 is `_11` 1.1901, `_22` 1.9042 (80.1° × 55.4°) against 1.4281 / 1.9042 (70.0° × 55.4°).
- The frames show more of the room at both sides, and Max and the props are no longer wide. Frames 170 and 400 (turning, firing) show no culling gaps or pop-in at the new edges.
- **The 2D layer follows the camera.** The menu and the HUD are camera-placed (the three `executeAlways` above), so under Hor+ they shrink by k toward the centre: correct proportions, inside the central 4:3 area. The main menu is therefore pillarboxed (art 2,133 px wide at 2560×1600, as the plan wanted). The HUD corners (health, ammo, weapon name) sit at the 4:3 edges, not at the screen edges.
- The mouse cursor maps through the camera the same way: moved hard left, it stops at the 4:3 edge (x ≈ 213 px of 2560). It hovers the same item in both views, so the menu's hit-testing still matches what is drawn.
- `host/test_host.py` 5/5 (its capture comparison with the emulator runs the host with `--view stretch`, since the emulator has no Hor+). `tools/test_render.py` 11/11. `lift/test_x86c.py` and `lift/test_build.py` pass.
- Not done: a hand-played session in the window, and other aspects (16:9, 4:3, where k = 1 and nothing changes).

## The HUD's corners (H75)
**How the HUD is built.** Each HUD element is an e2mfc object owned by an exe wrapper, stored at wrapper +0x1e:
- `MaxPayne_HUDSprite` (constructor 0x4c99f0) owns an `X_AdvSprite` (vtable 0x7d1500, a `P_Sprite`).
- `MaxPayne_HUDSpriteWindow` (0x4ca2a0) owns a `P_Sprite`.
- `MaxPayne_HUDText` (0x4ca920) owns a `P_Text`.

The positions come from the HUD scripts, in 640×480 virtual pixels: sprite x/y at +0x188/+0x18c, text x/y at +0x16c/+0x170. Every frame, `P_Sprite::executeAlways` (0x10008040) and `P_Text::executeAlways` (0x10004280) map that position into camera space at a fixed depth with the 4:3 tangent. So under Hor+ the HUD keeps its 4:3 layout in the middle of the screen.

**The change.** In those units, the real screen edges are 320 (k − 1) virtual pixels outside 0 and 640 (64 at 16:10).
- Entry hooks on the three constructors record the wrappers.
- An entry hook on the two `executeAlways` functions checks whether the object belongs to a recorded wrapper. If it does, x moves by 320 (k − 1) towards the nearer edge: left third left, right third right. The middle third stays.
- An exit hook puts x back. If an `executeAlways` leaves without its `ret`, the next frame puts x back.
- Library `build-lift/liblifted_full_h75.dylib` (H74 hard-linked, with the five hooked functions recompiled; the regenerated sources differ from H74's only by the hook lines; `0x40c020` and `0x10114d60` regenerate byte for byte). It is now the default for `play.sh` and `host/test_host.py`.
- `MPHOST_HUD_LOG=1` prints each HUD object and its move the first time.
- `emu/run_init.py --real-entry` now ignores entry hooks other than the frame function's. Without that, the H75 library's HUD hooks counted as frames in the emulator, and `test_host`'s trace comparison failed.

**Checks** (2560×1600, the H53 workload, headless):
- The HUD objects of the Part 1 save move as expected:
  - health figure (x 25 → −39), its layers (49 → −15), painkillers (69 → 5) to the left;
  - weapon name (597 → 661), ammo (582 → 646), the ammo icon (625 → 689) and a top-right text (575 → 639) to the right.
- In frames 170 and 400 the health figure and painkillers sit in the bottom-left corner and the weapon name in the bottom-right, at their own proportions, with about the original margins.
- The menu (frame 22) is byte for byte H74's stream.
- `host/test_host.py` 5/5, `tools/test_render.py` 11/11, the lifter tests and `emu/test_emu.py` pass.

**Not checked:**
- The ammo counter and icon with a gun: the save only has the bat.
- The objectives window and the tips, which are in the middle third and should stay.
- A hand-played session.

## The sniper scope and the weapon row (host only)
**The bug** (reported from play): with the sniper zoom on under Hor+, the scene showed through two bands beside the scope (x ≈ 333..550 and 2010..2227 at 2560×1600).

**The cause.** The scope is the HUD's `[Overlay]`: four circle quarters at (320, 240) and twelve black paddings, all `MaxPayne_HUDSpriteWindow`s. The left paddings sit at x 100 (reference point on their right edge, width 100), the right ones at x 540 (left edge, width 100). H75 moved them by 64 towards the screen edges, but the circle and the top and bottom paddings are in the middle third and stayed, so a 64-unit gap opened on each side.

**The change** (`hud_enter`, `host/mphost.c`; no library change). For a HUD sprite with no rotation (+0x14c), the host computes its extent from the reference point (+0x160: 0-2 left edge, 3, 7, 8 centre, 4-6 right edge, as `P_Sprite::executeAlways` uses it) and the width (+0x144). A sprite that reaches x 0 or 640 is widened to the real screen edge (width + 320 (k − 1) per edge, put back on exit) instead of moved. Of the HUD seen in the hotel save, only the six side paddings match; every other element moves as before.

**Checks** (2560×1600, headless, the hotel save: Resume, key 6, click, Enter for the zoom, frame 435): the scope's black reaches both screen edges, and the HUD log is H75's except for the six paddings (now at x 100 and 540 with width 164). `host/test_host.py` 5/5.

**The weapon row.** The weapon inventory (the slots shown at the top while choosing a weapon: a frame at x 120, slot numbers and weapon icons at x 170 … 470, 60 apart) is one centred group, but H75 moved slots 1, 2 and 6 by 64 and left 3 to 5, so the spacing was uneven. Its pieces are `HUDSpriteWindow`s made by three calls in the HUD loader 0x4b0680: the frame (0x4b2e5f), the slot numbers (0x4b3024) and the slot weapons (0x4bdbac, in 0x4bdb50). The entry hook on 0x4ca2a0 reads the constructor 0x4ca1c0's return address at esp + 48 and marks those windows to stay in their 4:3 layout. Checked in the same run: the six slots are evenly spaced (about 200 px apart at 2560×1600), and the HUD log lost exactly the inventory's pieces. `host/test_host.py` 5/5.

## Rooms seen through doors (H76)
**The bug** (reported from play, Hor+ only): graphical anomalies near corners and doors. Under Hor+ the room behind an opening near a screen edge was clipped: a black void where its walls should be (the warehouse save, frame 170, the opening at the left edge).

**The cause.** The exe's portal code computes its own 4:3 tangent from the camera's FOV and viewport (`fld [cam + 0x242]; fmul 0.5; fptan; fstp st(0)`, then the vertical tangent from the viewport, the same arithmetic as validate's), so it never sees the host's widening:
- `0x679e80` builds the window that portals are clipped against (globals `0x8b4608..0x8b4614`: ±tanH, ±tanV).
- `0x67a9f0` maps a portal's extent to screen space and passes it to `P_Camera::setSubViewport` for the room behind it.

At 16:10 both put the portal 1.2× off where the widened camera draws it. `0x680500` only copies the FOV.

**The change.**
- Lifter: `x86c.INSN_HOOKS` (`build.py --insn-hook`): before a hooked instruction the x87 cache is flushed and the lifted code calls `lift_insn_hook(c, va)`, so the host sees the x87 stack in `st[]`/`top`. Test: `lift/test_x86c.py` `test_insn_hook`.
- Runtime: `lift_set_insn_hook(cb)`, as the exit hook.
- Host: `on_insn_hook` multiplies the horizontal tangent by the same k as validate's, once the vertical one is computed from it (both functions derive it as validate does, so it must stay 4:3-based): at `0x67a148` the float at `[ebp - 0x10]`, at `0x67aec8` st(1) (st(0) is the vertical tangent). A first version widened tan(fov / 2) right after `fptan`, which widened the vertical tangent too: looking up and down still left holes (the report after the first fix). A library without the hook prints a note and keeps the 4:3 portals. `--view stretch` sets no hook.
- Library `build-lift/liblifted_full_h76.dylib` (H75 hard-linked, `lift-out/lifted_full_h76`; `f_00679e80` and `f_0067a9f0` regenerated with the hooks, the runtime recompiled; both regenerate byte for byte from H75 without hooks, and the hooked C differs only by the flush and hook lines). It is now the default for `play.sh` and `host/test_host.py`.

**Checks** (2560×1600, the H53 workload, headless, H75 against H76): frame 170 (before the scripted input) differs only at the left-edge opening, where H76 draws the room behind it (45 draws against 39). `host/test_host.py` 5/5, `tools/test_render.py` 11/11, `lift/test_x86c.py` and `lift/test_build.py` 46. Your latest save (`savegame003`, the hotel), looking up and down while turning, 700 frames, every 20th captured: pixels left at the clear colour (0,0,0) up to 3.14% of the screen with H75 (frame 480: black wedges beside the doorways), at most 0.03% with H76 (the same as before any input). Not checked: a hand-played session.

## Full-screen overlays (H77)
**The survey** (2560×1600, headless, H76 under `--view hor+` against `--view stretch`). The runs:
- the H53 workload, plus LShift at frame 300 (a shoot-dodge in bullet time);
- New Game (Down, Down, Enter, Enter on Fugitive) for 2,600 frames;
- New Game for 30,000 frames with Enter every 600 frames from frame 18,000, to step through the graphic-novel pages.

The XYZRHW draws in the captures were sorted by their x extent: the full width (0..2560), the 4:3 band (213..2347), or neither.

| Overlay | What draws it | Stretch | Hor+ (H76) | Change |
|---|---|---|---|---|
| Fades and flashes (`MaxPayne_HUDFadeLayer`, 0x4ab8f0) | one `P_Sprite` at layer +0xad, 640×480 virtual, FVF 0x144 | 0..2560 | 213..2347: unfaded bands at the sides | widened (below) |
| Graphic-novel pages | the page's `.kf2` (FVF 0x1c4), its control bar a sprite (FVF 0x144) | page 35..2530, 1.2× too wide | page 243..2321, bar 213..2347, black at the sides | none: the art keeps its proportions, pillarboxed like the menus |
| Loading | the menu stays on screen until the level fades in; no separate loading picture was drawn in either run | stretched menu | pillarboxed menu | none |
| Bullet time | no full-screen draw at all during the shoot-dodge (frame 340): Max Payne 1 has no tint | – | – | none |
| Cutscene letterbox | full-width bars | 0..2560 | 0..2560 | none |

The New Game run uses the fade layer for the fade from black after the menu and for the long white fade at the start of the prologue. With H76 both stopped at the 4:3 edges.

**The change.**
- An entry hook on the fade layer's constructor (0x4ab8f0) records the layer (ECX).
- On entry to `P_Sprite::executeAlways` (already hooked by H75), the layer's sprite (layer +0xad) is widened to the real screen edges:
  - x (+0x188) becomes −320 (k − 1);
  - width (+0x144) becomes 640 k.
- Both fields go on H75's restore list, so they are put back on exit, or at the next frame if the function exits without its `ret`.
- `--view stretch` changes nothing, as before.
- Library `build-lift/liblifted_full_h77.dylib` (`lift-out/lifted_full_h77`):
  - H76's sources and objects are hard-linked, with only `f_004ab8f0` regenerated with `--entry-hook`.
  - It regenerates byte for byte from H76 without the hook (`DEAD_FRAMES` on, as in the full build), and the hooked C differs only by the `lift_entry_hook` line.
  - It is now the default for `play.sh` and `host/test_host.py`.
  - With an older library the hook never runs and the fades stay 4:3.

**Checks:**
- The New Game run with H77 under Hor+: each of the 49 fade quads in the 64 captured frames spans 0..2560, as under stretch, and the rendered frames have no bands at the sides.
- The H53 workload, H76 against H77:
  - the menu (frame 22) is byte for byte the same stream;
  - in frames 170 and 400 the HUD draws are identical.
  - The 3D geometry in those frames differs slightly, but two H77 runs differ the same way (wall-clock timing), so the difference is not H77's.
- `host/test_host.py` 5/5, `tools/test_render.py` 11/11, `lift/test_x86c.py` and `lift/test_build.py` 46, `emu/test_emu.py` 8.

**Not checked:**
- The damage and death flashes. They use the same layer (`FlashToColor`, `FadeToColor`), but no scripted run reached them.
- The separate loading picture (`MenuLoadingScreen`), if longer loads show one.
- A hand-played session.

## Save thumbnails (host only)
**The bug** (reported from play): in the Save menu an existing slot showed a black box where its picture belongs, and in the Load menu manual and quick saves showed no picture at all (the autosave did). Not Hor+: the same under `--view stretch`.

**The cause.** Every manual and quick save held a 147,456-byte run of zeros, a 256×192 RGB thumbnail. The game takes it when the in-game menu opens: `GetDisplayMode`, `CreateImageSurface` (display-mode size, A8R8G8B8), `GetFrontBuffer`, then a read-only `LockRect` on the surface. The host's `GetFrontBuffer` was the table's default (D3D_OK, nothing copied), so the surface stayed zero.

**The change.** `GetFrontBuffer` (`host/hle_d3d8.c`) fills the surface from the live renderer's last presented frame (`host_live_read_frame` in `host/live.c`, over `mpr_read_rgba`), RGBA to B,G,R,A bytes, scaled nearest if the sizes differ. Nothing is drawn between that Present and the call, so the last frame is the front buffer. Headless runs have no renderer and leave the surface as before (black thumbnails, the captures unchanged). The emulator is unchanged. Saves made before the fix keep their black thumbnails.

**Checks:** a windowed run (Resume, Esc, Save, an empty slot) wrote `savegame006` with no zero run; the extracted thumbnail is the corridor with the HUD, its mean colour within 10% of the gameplay frame's on each channel, and the Load menu shows it for that slot. `host/test_host.py` 5/5.

## Next
1. `--resolution` is in the host (H78). Checked headless with the H53 workload:
   - At 1920×1080 the back buffer is 1920×1080 and Hor+ widens the view to 16:9.
   - At 1280×1024 (5:4, narrower than 4:3) the view narrows to 5:4 with the same vertical FOV.
   - At both, the HUD corners are at the screen edges, and the mode is saved to Video Settings.
   - Not done yet: the launcher's `--set "Section/Value=N"` (other dialog settings).
2. The emulator has no Hor+, no HUD anchoring and no fade widening (`emu/native.py` could set the same hooks). It is only needed if emulator runs should match the host's default.
