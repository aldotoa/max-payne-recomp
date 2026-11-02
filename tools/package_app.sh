#!/bin/sh
# Assemble a self-contained, double-clickable Max Payne.app from the built host (make -C host), a lifted library
# (lift/build_game.py) and the user's game folder. make-app.sh runs this; it also works on its own:
#   tools/package_app.sh GAME_DIR LIB [OUT_DIR]        (OUT_DIR default: dist)
# The game folder is copied into the app (Contents/Resources/game). Saves and settings stay in
# ~/Library/Application Support/Max Payne Recomp, so rebuilding the app keeps them. The app is for personal use
# only: it contains the game.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GAME=${1:?usage: package_app.sh GAME_DIR LIB [OUT_DIR]}
LIB=${2:?usage: package_app.sh GAME_DIR LIB [OUT_DIR]}
OUT=${3:-"$ROOT/dist"}
BUILD="$ROOT/build"
SDL_PREFIX=${SDL:-$(brew --prefix 2>/dev/null || echo /opt/homebrew)}
SDL_LIB="$SDL_PREFIX/opt/sdl3/lib/libSDL3.0.dylib"
[ -f "$SDL_LIB" ] || SDL_LIB="$SDL_PREFIX/lib/libSDL3.0.dylib"

for f in "$BUILD/mphost" "$BUILD/libmprender.dylib" "$BUILD/libmpaudio.dylib" "$BUILD/libmpmovie.dylib" "$LIB" "$SDL_LIB"; do
    [ -f "$f" ] || { echo "package_app.sh: missing $f" >&2; exit 2; }
done

APP="$OUT/Max Payne.app"
C="$APP/Contents"
echo "Assembling $APP"
rm -rf "$APP"
mkdir -p "$C/MacOS" "$C/Resources"

# Binaries; SDL3 comes along and every reference to it goes through @rpath (= Contents/MacOS).
cp "$BUILD/mphost" "$BUILD/libmprender.dylib" "$BUILD/libmpaudio.dylib" "$BUILD/libmpmovie.dylib" "$C/MacOS/"
cp "$LIB" "$C/MacOS/liblifted_game.dylib"
cp -L "$SDL_LIB" "$C/MacOS/libSDL3.0.dylib"
chmod u+w "$C/MacOS/"*
install_name_tool -id @rpath/libSDL3.0.dylib "$C/MacOS/libSDL3.0.dylib" 2>/dev/null
install_name_tool -id @rpath/liblifted_game.dylib "$C/MacOS/liblifted_game.dylib"
for bin in "$C/MacOS/mphost" "$C/MacOS/libmpaudio.dylib"; do
    old=$(otool -L "$bin" | awk '/libSDL3/ {print $1; exit}')
    [ -n "$old" ] && install_name_tool -change "$old" @rpath/libSDL3.0.dylib "$bin"
    for rp in $(otool -l "$bin" | awk '/LC_RPATH/ {getline; getline; print $2}'); do
        [ "$rp" = "@executable_path" ] || install_name_tool -delete_rpath "$rp" "$bin"
    done
done
otool -l "$C/MacOS/libmpaudio.dylib" | grep -q "@executable_path" || \
    install_name_tool -add_rpath @executable_path "$C/MacOS/libmpaudio.dylib"

# Launcher: the bundle's main executable. Extra mphost options can go in launch-options (one line of options).
cat > "$C/MacOS/Max Payne" <<'EOF'
#!/bin/sh
HERE=$(cd "$(dirname "$0")" && pwd)
DATA=${MAXPAYNE_DATA:-"$HOME/Library/Application Support/Max Payne Recomp"}
LOG="$HOME/Library/Logs/Max Payne Recomp.log"
mkdir -p "$DATA" "$(dirname "$LOG")"
[ -f "$DATA/launch-options" ] || cat > "$DATA/launch-options" <<'OPT'
# mphost options for Max Payne.app, on one line below (lines starting with # are ignored). Examples:
#   --resolution 1920x1080      --game-mode windowed      --intro skip      --audio off
OPT
OPTS=$(grep -v '^[[:space:]]*#' "$DATA/launch-options" | tr '\n' ' ')
cd "$HERE"
# shellcheck disable=SC2086
"$HERE/mphost" "$HERE/../Resources/game" --lib "$HERE/liblifted_game.dylib" --window $OPTS "$@" >"$LOG" 2>&1
status=$?
if [ $status -ne 0 ]; then
    msg=$(tail -n 5 "$LOG" | tr '"\\' "'/")
    osascript -e "display alert \"Max Payne stopped with an error (code $status)\" message \"$msg

Full log: ~/Library/Logs/Max Payne Recomp.log\"" >/dev/null 2>&1
fi
exit $status
EOF
chmod +x "$C/MacOS/Max Payne"

# The game, without the Windows installer leftovers.
echo "Copying the game files (about 1 GB)..."
rsync -a --exclude 'unins000.*' --exclude 'DirectX' --exclude '.DS_Store' "$GAME/" "$C/Resources/game/"

# Icon from the game's own .ico.
ICO=$(find "$GAME" -maxdepth 1 -iname '*.ico' | head -n 1)
ICON_KEY=""
if [ -n "$ICO" ]; then
    T=$(mktemp -d)
    mkdir "$T/AppIcon.iconset"
    sips -s format png "$ICO" --out "$T/icon.png" >/dev/null
    for s in 16 32 128 256 512; do
        sips -z $s $s "$T/icon.png" --out "$T/AppIcon.iconset/icon_${s}x${s}.png" >/dev/null
        d=$((s * 2))
        sips -z $d $d "$T/icon.png" --out "$T/AppIcon.iconset/icon_${s}x${s}@2x.png" >/dev/null
    done
    iconutil -c icns "$T/AppIcon.iconset" -o "$C/Resources/AppIcon.icns" && ICON_KEY="<key>CFBundleIconFile</key><string>AppIcon</string>"
    rm -rf "$T"
fi

VERSION=$(git -C "$ROOT" describe --always --dirty 2>/dev/null || echo dev)
cat > "$C/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Max Payne</string>
    <key>CFBundleDisplayName</key><string>Max Payne</string>
    <key>CFBundleIdentifier</key><string>io.github.aldotoa.maxpayne-recomp</string>
    <key>CFBundleExecutable</key><string>Max Payne</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    $ICON_KEY
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSArchitecturePriority</key><array><string>arm64</string></array>
    <key>LSApplicationCategoryType</key><string>public.app-category.action-games</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

# Ad-hoc signature: Apple Silicon needs one, and an app built on this Mac is not quarantined.
echo "Signing..."
codesign --force --deep --sign - "$APP"
echo "Done: $APP"
