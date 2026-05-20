#!/bin/bash
# Build sqlite3 fuzzing harness for crash replay: gcc + ASAN + debug info,
# no fuzzer (AFL/libFuzzer) instrumentation. Drives discovered crash inputs
# through LLVMFuzzerTestOneInput via the standalone afl_driver main loop.
#
# Run inside a Singularity container based on aflplusplus_lto_asan's
# preinstall.sh plus sqlite3's preinstall.sh (autotools, tcl, zlib1g-dev).
#
# Required env (defaults for the standard magma container):
#   TARGET   path to /magma/targets/sqlite3
#   MAGMA    path to /magma/magma
#   OUT      output dir for binaries (writeable)
#   SHARED   shared dir (canaries.raw goes here)
#
# $TARGET/build.sh appends sqlite-specific -D flags (MAX_LENGTH, DEBUG, ...)
# to CFLAGS internally, so we don't add them here.
#
# Output binary lands in $OUT/targets/sqlite3_fuzz.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

: "${TARGET:=/magma/targets/sqlite3}"
: "${MAGMA:=/magma/magma}"
: "${OUT:=/magma_out}"
: "${SHARED:=/magma_shared}"

# Redirect all replay artifacts under $OUT/replay/<target> so the campaign's
# AFL-instrumented fuzzing binaries in $OUT/targets/ remain untouched.
OUT="$OUT/replay/$(basename "$TARGET")"
export TARGET MAGMA OUT SHARED

mkdir -p "$OUT" "$SHARED"

export CC=/usr/bin/gcc
export CXX=/usr/bin/g++
export AS=/usr/bin/as
export AR=/usr/bin/ar
export LD=/usr/bin/ld
export NM=/usr/bin/nm
export RANLIB=/usr/bin/ranlib

ASAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"
MAGMA_FLAGS="-include $MAGMA/src/canary.h -DMAGMA_ENABLE_CANARIES -DMAGMA_ENABLE_FREE_CANARIES"

export CFLAGS="$MAGMA_FLAGS $ASAN_FLAGS"
export CXXFLAGS="$MAGMA_FLAGS $ASAN_FLAGS"
export LDFLAGS="-L$OUT -fsanitize=address -static-libasan -g"
export LIBS="-l:magma.o -lrt -l:afl_driver.o -lstdc++"

"$MAGMA/build.sh"

"$CXX" $CXXFLAGS -std=c++11 -c "$SCRIPT_DIR/afl_driver.cpp" -fPIC -o "$OUT/afl_driver.o"

if [ -f "$TARGET/repo/Makefile" ]; then
    make -C "$TARGET/repo" distclean 2>/dev/null || \
        make -C "$TARGET/repo" clean 2>/dev/null || true
fi
rm -rf "$OUT/targets"

"$TARGET/build.sh"

echo "Done. Binaries in $OUT/targets/"
