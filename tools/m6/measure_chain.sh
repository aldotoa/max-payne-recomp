#!/bin/bash
# M6 measurement chain (Opus, 2026-10-20): builds, then timed native runs one at a time with a per-run perl alarm cap.
# Scratch-grade: S, the worktree path and the module lists are hard-coded; edit them before use. Logs: lift-out/c4_*.log.
# Opus: 3 DLLs vs +exe dyn vs +exe dyn +d3d8 driver; sequential, perl-alarm caps.
S=${S:?set S to a scratch dir with venv/ and game/}
cd "${W:?set W to the checkout to build in}" || exit 1
PY=$S/venv/bin/python; G=$S/game; export MP_GAME_DIR=$G
D="--module rlmfc.dll --module grphmfc.dll --module e2mfc.dll"
DRV="--module $G/e2driver/e2_d3d8_driver_mfc.dll"
X="--module MaxPayne.exe --entries-file MaxPayne.exe=lift-out/exe_dyn_entries_h15.txt --keep-emulated 0x783860"
cap() { perl -e '$t=shift; $p=fork; if(!$p){exec @ARGV} $SIG{ALRM}=sub{kill 9,$p; print STDERR "CAP KILLED\n"}; alarm $t; waitpid $p,0; exit($?>>8)' "$@"; }
ts() { while IFS= read -r l; do printf '%s %s\n' "$(date +%H:%M:%S)" "$l"; done; }
step() { echo "$(date +%H:%M:%S) STEP $1"; }
step build3;  $PY lift/build.py $D --entries real --lib build-lift/liblifted3.dylib 2>&1 | tail -2
step builddyn; $PY lift/build.py $D --entries real $X --lib build-lift/liblifted_dyn.dylib 2>&1 | tail -2
step build4dyn; $PY lift/build.py $D $DRV --entries real $X --lib build-lift/liblifted4_dyn.dylib 2>&1 | tail -8
R="--frames 80 --input 25:key=1c,26:keyup=1c --caller-top 20"
M3=rlmfc.dll,grphmfc.dll,e2mfc.dll
step base; cap 900 $PY -u emu/run_init.py $G $R --native-lift build-lift/liblifted3.dylib --lift-modules $M3 2>&1 | ts > lift-out/c4_base.log
step dyn; cap 900 $PY -u emu/run_init.py $G $R --native-lift build-lift/liblifted_dyn.dylib --lift-modules $M3,maxpayne.exe 2>&1 | ts > lift-out/c4_dyn.log
for n in 1 2; do step dyn4_$n; cap 900 $PY -u emu/run_init.py $G $R --native-lift build-lift/liblifted4_dyn.dylib --lift-modules $M3,e2_d3d8_driver_mfc.dll,maxpayne.exe 2>&1 | ts > lift-out/c4_dyn4_$n.log; done

step build4w; $PY lift/build.py $D $DRV --entries real $X --write-log --lib build-lift/liblifted4_dyn_wlog.dylib 2>&1 | tail -2
step diff4; cap 7200 $PY -u emu/run_init.py $G $R --diff-lift build-lift/liblifted4_dyn_wlog.dylib --lift-modules $M3,e2_d3d8_driver_mfc.dll,maxpayne.exe --diff-k 50 --diff-report lift-out/c4_diff.json 2>&1 | ts > lift-out/c4_diff.log
step done
