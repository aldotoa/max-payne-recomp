#!/bin/bash
# Build Unicorn 2.1.4 with every tools/unicorn-2.1.4-*.patch and install it into the repo's .venv.
#
# The patches: unicorn-2.1.4-fast-stores.patch (see below) and unicorn-2.1.4-exit-checks.patch, which drops the
# exit-check helper call after every guest load and store unless a data memory hook is installed. See
# docs/m4-progress.md.
#
# Why: stock Unicorn never lets a guest page leave QEMU's "not dirty" state, so every store to memory mapped
# executable (all of the game's memory) takes the slow path and calls tb_invalidate_phys_page_fast. The patch
# makes a page's stores fast after the first one while the page holds no translated code, and puts them back on
# the slow path when code is translated from it, so self-modifying code still works. See docs/m4-progress.md.
#
# unicorn-2.1.4-addr-hooks.patch indexes single-address UC_HOOK_CODE hooks (begin == end, as differential mode
# installs one per lifted entry) by address, instead of walking one linear list per translated instruction and per
# executed hooked instruction. Ranged code hooks are unchanged. Hooks at one address run after the ranged code hooks
# at that instruction (before, they ran in insertion order). See the patch for the details.
#
# Usage:  tools/build_unicorn.sh            build (if needed) and install into .venv
#         tools/build_unicorn.sh --restore  put the wheel's original library back
#
# Sources and build stay outside the repo, in $UNICORN_SRC (default ~/Tools/unicorn-src). cmake and ninja come
# from PATH, or are installed with pip into ~/Tools/buildtools-venv. The original library is kept next to the
# installed one as libunicorn.2.dylib.orig. Without installing, LIBUNICORN_PATH=$UNICORN_SRC/build also works.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${UNICORN_SRC:-$HOME/Tools/unicorn-src}"
TAG=2.1.4
TAG_COMMIT=8028ec436f2d9376525352dd38ed9ed6b9f6be10
PY="$REPO/.venv/bin/python"
LIBDIR="$("$PY" -c 'import importlib.util, os; print(os.path.join(os.path.dirname(importlib.util.find_spec("unicorn").origin), "lib"))')"
LIB="$LIBDIR/libunicorn.2.dylib"

if [[ "${1:-}" == "--restore" ]]; then
    [[ -f "$LIB.orig" ]] && mv "$LIB.orig" "$LIB" && echo "restored the original $LIB" || echo "nothing to restore"
    exit 0
fi

ver="$("$PY" -c 'import unicorn; print(unicorn.__version__)')"
[[ "$ver" == "$TAG" ]] || { echo "the venv has unicorn $ver; this patch is for $TAG" >&2; exit 1; }

if [[ ! -d "$SRC/.git" ]]; then
    git clone --depth 1 --branch "$TAG" https://github.com/unicorn-engine/unicorn.git "$SRC"
fi
[[ "$(git -C "$SRC" rev-parse HEAD)" == "$TAG_COMMIT" ]] || { echo "$SRC is not at unicorn $TAG" >&2; exit 1; }
# Patches apply in name order, except unicorn-2.1.4-addr-hooks.patch, which goes last: it is written against the
# tree with the others applied.
PATCHES=()
for PATCH in "$REPO"/tools/unicorn-2.1.4-*.patch; do
    [[ "$(basename "$PATCH")" == unicorn-2.1.4-addr-hooks.patch ]] && continue
    PATCHES+=("$PATCH")
done
[[ -f "$REPO/tools/unicorn-2.1.4-addr-hooks.patch" ]] && PATCHES+=("$REPO/tools/unicorn-2.1.4-addr-hooks.patch")
for PATCH in "${PATCHES[@]}"; do
    if git -C "$SRC" apply --reverse --check "$PATCH" 2>/dev/null; then
        echo "patch already applied in $SRC: $(basename "$PATCH")"
    else
        git -C "$SRC" apply "$PATCH"
        echo "applied $(basename "$PATCH") in $SRC"
    fi
done

if ! command -v cmake >/dev/null || ! command -v ninja >/dev/null; then
    if [[ ! -x "$HOME/Tools/buildtools-venv/bin/cmake" ]]; then
        python3 -m venv "$HOME/Tools/buildtools-venv"
        "$HOME/Tools/buildtools-venv/bin/pip" install -q cmake ninja
    fi
    export PATH="$HOME/Tools/buildtools-venv/bin:$PATH"
fi
# Only the x86 target: the emulator needs nothing else, and it builds in seconds.
cmake -S "$SRC" -B "$SRC/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DUNICORN_ARCH=x86 \
      -DCMAKE_POLICY_VERSION_MINIMUM=3.5 >/dev/null
ninja -C "$SRC/build" unicorn

[[ -f "$LIB.orig" ]] || cp "$LIB" "$LIB.orig"
cp "$SRC/build/libunicorn.2.dylib" "$LIB"
echo "installed patched libunicorn into $LIBDIR"
"$PY" "$REPO/tools/bench_stores.py"
