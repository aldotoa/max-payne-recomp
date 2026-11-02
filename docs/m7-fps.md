# M7: 60 fps

## Verdict
**The simulation is variable-dt, so 60 fps needs no fixed tick and no interpolation.** The sim runs at the presented rate and the renderer caps presentation at 60.

- Static reading (docs/census.md §8): the main loop `0x40c020` takes `R_Timer::sample`, clamps it to 0.1 s, averages it over a ring buffer and publishes it once per frame (`X_TimeUpdate`). Every traced update steps once per frame with that dt.
- Added in M7: the enemy shooting timer counts down by dt (`0x50035a`) and re-rolls a random interval when it expires; the reaction timer (`+0x60e`) also counts down by dt.
- Measured: the same session at 30, 60 and 120 fps on a virtual clock (below) gives the same player motion, view and bullet time, within integration error.
- No frame limiter in the game. The host was already paced by CAMetalLayer vsync, which on this Mac's 60 Hz panel is 60 fps.

## The virtual clock: `mphost --sim-fps N`
- Each main-loop frame (the entry of `0x40c020`) advances the guest clock by exactly 1/N s. Until the first frame, every read advances it by 1 ms, so start-up waits still finish.
- It drives every guest clock: `QueryPerformanceCounter`, `timeGetTime`/`GetTickCount`, the system time (from a fixed epoch), the DSOUND play cursors and the DINPUT timestamps.
- The runtime's fast handlers for QPC and the DSOUND cursor (`hle_fast.c` kinds 1, 23–25) read the wall clock, so they aren't bound under `--sim-fps`. The host's handlers serve those calls instead.
- Sound is off unless `--audio` is given. With a mixer, the voices' cursors follow the mixer in real time.
- Two runs at the same N are byte-identical: the H53 workload at 30, MPD3 captures of 7 frames.
- Without the flag nothing changes: `host/test_host.py` 5/5, `tools/test_render.py` 11/11.

## The regression: `tools/m7/fps_regress.py`
- Each rate's run resumes the newest save, the H53 container yard. The script is written at 30 fps and counted from the frame that opens the level's `.ldb`.
  - At N fps each frame f becomes f·N/30, and each frame's mouse move is split over those frames.
  - Within the 5 s before the enemy engages: walk (W), strafe right (Space) while turning, a shoot-dodge (LShift, bullet time), fire.
- Compared every 0.1 s of sim time: the camera (from the VIEW transform), the draw count, and the world-space centroids of the XYZ draws.

| | max camera offset | view angle at rest |
|---|---|---|
| 60 vs 30 fps | 0.16 units (strafe/turn, 3.2 s) | 0.000° |
| 120 vs 30 fps | 0.29 units (shoot-dodge, 3.2 s) | 0.000° |

- The offset is variable-dt integration error. It appears where Max accelerates (walk start 0.4–1.0 s, strafe 2.3 s, dodge 3.1 s) and ends at 0.09 units (60) and 0.16 units (120) after about 3 units of travel.
- The view turns by exactly the same angle at every rate (mouse deltas are applied per event, not per frame).
- The tool fails above 0.35 units (`--tol-pos`).

## Why fights diverge between rates (and why it isn't a bug)
- With no input, the enemy in this save kills Max 7.6 s after the load at 30 fps, but 5.5–7.3 s at 60 and 120. The time also depends on how long the menu ran before the load (60 fps: 5.63 or 7.23–7.33 s).
- **`rand()` calls per sim second** were counted by logging MSVCRT's LCG state each frame (`MPH_RAND_LOG`, `tools/m7/rand_steps.py`): 2,562 at 30 fps, 2,801 at 60, 2,975 at 120. So nearly all randomness is drawn per unit of time.
- **The one caller whose calls per second follow the frame rate** was found by hooking `rand` (entry hook on MSVCRT `0x7801f40b`, `MPH_RAND_CALLERS`): return address `0x78377d`, about 3.6 calls per frame at any rate.
  - That caller is the particle emitter `0x77c060` (called from `0x77d0f0`).
  - Each frame it integrates its emission-rate curve over the frame's normalized time interval (`0x783510`: the interval's width times the curve at its midpoint), picks a random value between the min and max curves, and emits `floor()` particles, keeping the fraction.
  - The expected particles per second don't depend on frame rate. Only the rand() sequence it consumes does.
- So the rand() sequence differs between rates, and with it spreads and shot outcomes. A fight is chaotic, so its outcome diverges. It would also diverge between two 30 fps PCs with different frame-time jitter. The design is the same as the original game's.
- The AI's "Random ≤ p" condition (`0x4ffef0` case 0x1a) would roll once per evaluation. It isn't evaluated in this scene: an entry-hook probe saw only condition type 0x1c, once per frame. **Not checked:** scenes whose AI scripts use it. If one evaluates it every frame, that condition fires more often at 60 fps.

## The 60 fps cap (`render/mprender.m`)
- `MPR_MAX_FPS` (default 60; 0 = the display's rate).
- On a display faster than the cap (`NSScreen.mainScreen.maximumFramesPerSecond`, read every 120 frames), each drawable is presented with `presentDrawable:afterMinimumDuration:1/cap`. At or below the cap, vsync alone paces frames.
- Checked on this 60 Hz panel with `MPR_MAX_FPS=30`: 94 of 97 on-screen intervals were 2 vsyncs (33.3 ms). No faster display was available to test the 60 cap on 120 Hz.

## Performance at 2560×1600 (not yet locked)
H53 workload plus a shoot-dodge, windowed, back buffer 2560×1600, `MPR_FRAME_LOG`, 701 frames after the load (`tools/frame_log.py`):
- **Frame interval: mean 20.2 ms (about 50 fps).** 548 of 691 frames shown one vsync after the previous one, 140 after two.
- CPU per frame: p50 14.6 ms, p90 23.3 ms (36% over 16.7 ms).
- GPU per frame: mean 11.3 ms, p99 17.1 ms. At 1920×1080 (H51) it was 4–5 ms, so GPU time grows with the pixel count.
- So both CPU and GPU are close to the 16.7 ms budget at this resolution. This is performance work, not a timing issue.

The game renders nothing while its window is inactive. A measurement run therefore needs `--input "1:focus=1,..."` or the window in front.

## Probes (for later investigations)
- `MPH_RAND_LOG=path`: MSVCRT's rand state per frame.
- `MPH_AI_LOG=path` and `MPH_RAND_CALLERS=path` need a library with entry hooks on `0x4ffef0` and `0x7801f40b`. Build it from H77's objects with only those functions regenerated (`x86c.ENTRY_HOOKS`, same `known` set as `lift-out/lifted_full_h77/table.c`; each regenerates byte for byte without the hook). The probe library isn't kept in the repo.
