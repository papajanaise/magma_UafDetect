#!/bin/bash
set -e

##
# Pre-requirements:
# - env MAGMA: path to Magma support files
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
##

# Use system compiler with clean flags to avoid contamination from
# fuzzer-specific environment (e.g. -l:magma.o in LDFLAGS).
PREBUILD_CC="gcc"
PREBUILD_CFLAGS=""
PREBUILD_LDFLAGS=""
PREBUILD_LIBS=""

MAGMA_STORAGE="$SHARED/canaries.raw"

$PREBUILD_CC $PREBUILD_CFLAGS -D"MAGMA_STORAGE=\"$MAGMA_STORAGE\"" -c "$MAGMA/src/storage.c" \
    -fPIC -I "$MAGMA/src/" -o "$OUT/pre_storage.o" $PREBUILD_LDFLAGS

$PREBUILD_CC $PREBUILD_CFLAGS -g -O0 -D"MAGMA_STORAGE=\"$MAGMA_STORAGE\"" "$MAGMA/src/monitor.c" \
    "$OUT/pre_storage.o" -I "$MAGMA/src/" -o "$OUT/monitor" $PREBUILD_LDFLAGS $PREBUILD_LIBS

rm "$OUT/pre_storage.o"
