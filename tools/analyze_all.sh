#!/bin/bash
# Analyze every game module with Ghidra via REA and keep a snapshot + overview per module.
# Usage: analyze_all.sh <game_dir> <out_dir>   (needs GHIDRA_INSTALL_DIR and JAVA_HOME exported)
set -u
game="$1"; out="$2"; mkdir -p "$out"
for rel in MaxPayne.exe e2mfc.dll rlmfc.dll grphmfc.dll sndmfc.dll e2driver/e2_d3d8_driver_mfc.dll; do
  name=$(basename "$rel")
  start=$(date +%s)
  npx --yes rea-agents@6.5.0 analyze "$game/$rel" --provider ghidra --snapshot "$out/$name.snapshot" --format json > "$out/$name.overview.json" 2> "$out/$name.err"
  echo "$name exit=$? secs=$(( $(date +%s) - start ))"
done
