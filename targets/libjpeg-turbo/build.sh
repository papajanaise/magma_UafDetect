#!/bin/bash

# SPDX-License-Identifier: Apache-2.0

##
# Build libjpeg-turbo and all fuzzer harnesses for Magma.
#
# Magma environment variables used:
#   $TARGET   - path to this target's configuration directory
#   $OUT      - path where compiled binaries must be placed
#   $CC       - C compiler (set by the fuzzer's instrument.sh)
#   $CXX      - C++ compiler
#   $CFLAGS   - C compiler flags (includes Magma instrumentation flags)
#   $CXXFLAGS - C++ compiler flags
#   $LDFLAGS  - linker flags
#   $LIBS     - additional libraries to link
##

set -e

cd "$TARGET/repo"

# Create a clean build directory to avoid stale CMake cache entries.
rm -rf build && mkdir -p build && cd build

export MAGMA_JOBS=${MAGMA_JOBS:-$(( $(nproc) < 16 ? $(nproc) : 16 ))}

# Configure libjpeg-turbo as a static library.
# SIMD is disabled to avoid NASM version issues in some environments;
# re-enable it (remove -DWITH_SIMD=FALSE) for better performance if NASM >= 2.10
# is available.
cmake .. \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \
    ${AR:+-DCMAKE_AR="$AR"} \
    ${RANLIB:+-DCMAKE_RANLIB="$RANLIB"} \
    ${NM:+-DCMAKE_NM="$NM"} \
    -DENABLE_SHARED=FALSE \
    -DENABLE_STATIC=TRUE \
    -DWITH_SIMD=FALSE \
    -DCMAKE_BUILD_TYPE=Release

# Fix clock skew: touch all source files so Make does not get confused.
find .. -type f -exec touch {} +

# Build only the libraries (skip CLI tools to speed up the build).
make -j"${MAGMA_JOBS:-$(nproc)}" jpeg-static turbojpeg-static

# -------------------------------------------------------------------------
# Build all fuzzer harnesses, matching corpus directories.
# -------------------------------------------------------------------------

INCLUDES="-I$TARGET/repo -I$TARGET/repo/build"
FUZZ_DIR="$TARGET/repo/fuzz"
BUILD_DIR="$TARGET/repo/build"

TARGET_DIR="$OUT/targets"
mkdir -p "$TARGET_DIR"

for corpus_dir in "$TARGET/corpus"/*_fuzzer; do
    [ -d "$corpus_dir" ] || continue
    fuzzer_name="$(basename "$corpus_dir")"

    extra_defines=""
    source_file=""
    link_lib="$BUILD_DIR/libturbojpeg.a"
    extra_sources=""

    case "$fuzzer_name" in
        cjpeg_fuzzer)
            source_file="$FUZZ_DIR/cjpeg.cc"
            link_lib="$BUILD_DIR/libjpeg.a"
            extra_defines="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
            extra_sources="$TARGET/repo/cdjpeg.c $TARGET/repo/rdbmp.c $TARGET/repo/rdgif.c $TARGET/repo/rdppm.c $TARGET/repo/rdswitch.c $TARGET/repo/rdtarga.c"
            ;;
        compress_fuzzer)
            source_file="$FUZZ_DIR/compress.cc"
            ;;
        compress12_fuzzer)
            source_file="$FUZZ_DIR/compress.cc"
            extra_defines="-DBITS_IN_JSAMPLE=12"
            ;;
        compress16_lossless_fuzzer)
            source_file="$FUZZ_DIR/compress.cc"
            extra_defines="-DBITS_IN_JSAMPLE=16 -DC_LOSSLESS_SUPPORTED"
            ;;
        compress12_lossless_fuzzer)
            source_file="$FUZZ_DIR/compress.cc"
            extra_defines="-DBITS_IN_JSAMPLE=12 -DC_LOSSLESS_SUPPORTED"
            ;;
        compress_lossless_fuzzer)
            source_file="$FUZZ_DIR/compress.cc"
            extra_defines="-DC_LOSSLESS_SUPPORTED"
            ;;
        compress_yuv_fuzzer)
            source_file="$FUZZ_DIR/compress_yuv.cc"
            ;;
        libjpeg_turbo_fuzzer)
            source_file="$FUZZ_DIR/decompress.cc"
            ;;
        decompress_yuv_fuzzer)
            source_file="$FUZZ_DIR/decompress_yuv.cc"
            ;;
        transform_fuzzer)
            source_file="$FUZZ_DIR/transform.cc"
            ;;
        *)
            echo "WARNING: unknown fuzzer target '$fuzzer_name', skipping" >&2
            continue
            ;;
    esac

    # Compile extra C sources separately to preserve C linkage (avoids
    # C++ name mangling issues with LTO).
    extra_objs=""
    for csrc in $extra_sources; do
        obj="$BUILD_DIR/$(basename "${csrc%.c}.o")"
        $CC $CFLAGS $INCLUDES $extra_defines -c "$csrc" -o "$obj"
        extra_objs="$extra_objs $obj"
    done

    $CXX $CXXFLAGS $INCLUDES $extra_defines \
        "$source_file" $extra_objs \
        "$link_lib" \
        $LDFLAGS $LIBS \
        -o "$TARGET_DIR/$fuzzer_name"
done
