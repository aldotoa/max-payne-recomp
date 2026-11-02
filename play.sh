#!/bin/sh
# Play Max Payne in the native host (E7): build/mphost runs the lifted game with no emulator and no Python, in a
# Metal window with sound, keyboard and mouse. Saves and settings live in the data dir (MAXPAYNE_DATA, by default
# ~/Library/Application Support/Max Payne Recomp), as in the emulator.
#   ./play.sh [mphost options]       e.g. --game-mode windowed, --intro skip, --audio off, --data-dir DIR, --resolution 1920x1080
# MP_GAME_DIR is the game folder (default: "Max Payne" here), MP_LIB the lifted library (default: lift/build_game.py's,
# else H79's). To make a double-clickable app instead, run ./make-app.sh.
set -e
ROOT=$(cd "$(dirname "$0")" && pwd)
GAME=${MP_GAME_DIR:-"$ROOT/Max Payne"}
LIB=${MP_LIB:-"$ROOT/build-lift/liblifted_game.dylib"}
[ -f "$LIB" ] || [ -n "$MP_LIB" ] || LIB="$ROOT/build-lift/liblifted_full_h79.dylib"
[ -f "$LIB" ] || { echo "play.sh: no lifted library $LIB (lift/build_game.py; or set MP_LIB)" >&2; exit 2; }
make -s -C "$ROOT/host"
exec "$ROOT/build/mphost" "$GAME" --lib "$LIB" --window "$@"
