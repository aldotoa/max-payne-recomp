#!/bin/sh
# Build Max Payne.app from your own copy of the game, in one command:
#   ./make-app.sh                     asks for the Max Payne folder in a Finder window
#   ./make-app.sh --game DIR          or give it here (MP_GAME_DIR also works)
# Options: --dmg (also make dist/Max Payne.dmg), --skip-lift (reuse the lifted library already built),
#          --keep-intermediate (keep the ~700 MB of generated C and objects), -y (install missing tools without asking)
# Result: dist/Max Payne.app. It holds a copy of your game, so it is for your own use: don't share it.
set -e
ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"
GAME=${MP_GAME_DIR:-}
DMG=0 SKIP_LIFT=0 CLEAN=--clean YES=0
LIB="$ROOT/build-lift/liblifted_game.dylib"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }
ask()  { [ $YES = 1 ] && return 0; printf '%s [Y/n] ' "$1"; read -r a; case $a in [nN]*) return 1;; esac; }

while [ $# -gt 0 ]; do
    case $1 in
        --game) GAME=${2:?--game needs a folder}; shift;;
        --dmg) DMG=1;;
        --skip-lift) SKIP_LIFT=1;;
        --keep-intermediate) CLEAN=;;
        -y|--yes) YES=1;;
        -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
        *) fail "unknown option $1 (see ./make-app.sh --help)";;
    esac
    shift
done

say "Checking this Mac"
[ "$(uname -m)" = arm64 ] || fail "this needs an Apple Silicon Mac (M1 or later)."
MACOS=$(sw_vers -productVersion | cut -d. -f1)
[ "$MACOS" -ge 13 ] || fail "this needs macOS 13 (Ventura) or later; this Mac has $(sw_vers -productVersion)."
if ! xcode-select -p >/dev/null 2>&1 || ! command -v clang >/dev/null 2>&1; then
    xcode-select --install >/dev/null 2>&1 || true
    fail "the Xcode Command Line Tools are needed. An installer window should have opened: finish it, then run ./make-app.sh again."
fi
if ! command -v brew >/dev/null 2>&1; then
    [ -x /opt/homebrew/bin/brew ] && eval "$(/opt/homebrew/bin/brew shellenv)"
fi
command -v brew >/dev/null 2>&1 || fail "Homebrew is needed (https://brew.sh). Install it with:
  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"
then run ./make-app.sh again."
if ! brew list sdl3 >/dev/null 2>&1; then
    ask "SDL3 (window, input and sound library) is missing. Install it with Homebrew?" || fail "SDL3 is needed: brew install sdl3"
    brew install sdl3
fi
PY=
for p in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v $p >/dev/null 2>&1 && $p -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
        PY=$(command -v $p); break
    fi
done
if [ -z "$PY" ]; then
    ask "Python 3.10 or later is missing. Install it with Homebrew?" || fail "Python 3.10+ is needed: brew install python@3.13"
    brew install python@3.13
    PY="$(brew --prefix)/bin/python3.13"
fi
echo "OK: $(sw_vers -productName) $(sw_vers -productVersion), $(clang --version | head -n 1), $($PY --version)"

say "Finding your Max Payne folder"
if [ -z "$GAME" ]; then
    if [ -f "$ROOT/Max Payne/MaxPayne.exe" ]; then
        GAME="$ROOT/Max Payne"
    else
        echo "Pick the folder of your installed Max Payne (the one with MaxPayne.exe in it)."
        GAME=$(osascript -e 'POSIX path of (choose folder with prompt "Choose your Max Payne folder (the one with MaxPayne.exe)")' 2>/dev/null) \
            || fail "no folder chosen. You can also run: ./make-app.sh --game \"/path/to/Max Payne\""
    fi
fi
GAME=${GAME%/}
echo "Using: $GAME"

say "Setting up the build tools (Python packages)"
VENV="$ROOT/.venv-build"
[ -x "$VENV/bin/python" ] || "$PY" -m venv "$VENV"
"$VENV/bin/python" -m pip install -q --disable-pip-version-check -r "$ROOT/requirements.txt"

say "Checking the game files"
"$VENV/bin/python" lift/build_game.py --game "$GAME" --check || exit 1

say "Building the host (renderer, sound, movies)"
make -s -C host

if [ $SKIP_LIFT = 1 ] && [ -f "$LIB" ]; then
    say "Reusing the lifted game library ($LIB)"
else
    say "Recompiling the game for this Mac (10-20 minutes; it's fine to leave it running)"
    "$VENV/bin/python" lift/build_game.py --game "$GAME" --lib "$LIB" $CLEAN
fi

say "Making Max Payne.app"
tools/package_app.sh "$GAME" "$LIB" "$ROOT/dist"

if [ $DMG = 1 ]; then
    say "Making Max Payne.dmg"
    T=$(mktemp -d)
    cp -R "$ROOT/dist/Max Payne.app" "$T/"
    ln -s /Applications "$T/Applications"
    rm -f "$ROOT/dist/Max Payne.dmg"
    hdiutil create -quiet -volname "Max Payne" -srcfolder "$T" -format UDZO "$ROOT/dist/Max Payne.dmg"
    rm -rf "$T"
    echo "Done: $ROOT/dist/Max Payne.dmg"
fi

say "All done"
echo "Your app: $ROOT/dist/Max Payne.app"
echo "Drag it to Applications and double-click it. Saves and settings are in ~/Library/Application Support/Max Payne Recomp."
open "$ROOT/dist" 2>/dev/null || true
