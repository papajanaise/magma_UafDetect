#!/bin/bash
# Build libexpat and compile all fuzzer harnesses for Magma
#
# Environment (set by Magma captain):
#   CC, CXX          - compiler with fuzzer/sanitizer flags baked in
#   CFLAGS, CXXFLAGS - includes -fsanitize=address,fuzzer-no-link etc.
#   LDFLAGS          - linker flags
#   LIBS             - extra libs (contains $OUT/magma.o)
#   OUT              - output directory for final binaries
#   TARGET           - this target's root directory ($TARGET/repo is the source)
set -e

cd "$TARGET/repo/expat"

# --- configure & build libexpat as a static library ---
make distclean 2>/dev/null || true

./buildconf.sh

./configure \
    CC="$CC" \
    CXX="$CXX" \
    CFLAGS="$CFLAGS" \
    CXXFLAGS="$CXXFLAGS" \
    LDFLAGS="$LDFLAGS" \
    --enable-static \
    --disable-shared \
    --without-docbook \
    --prefix="$TARGET/install"

make -j"$(nproc)" install

LIB_DIR="$TARGET/install/lib"
INC_DIR="$TARGET/install/include"

# --- compile all fuzzer harnesses ---
# Two fuzzer sources × multiple encodings, matching corpus directories.
FUZZ_DIR="$TARGET/repo/expat/fuzz"
ENCODINGS="UTF-8 UTF-16 UTF-16LE UTF-16BE ISO-8859-1 US-ASCII"

TARGET_DIR="$OUT/targets"
mkdir -p "$TARGET_DIR"

for fuzzer_src in xml_parse_fuzzer xml_parsebuffer_fuzzer; do
    for enc in $ENCODINGS; do
        output_name="${fuzzer_src}_${enc}"
        # Only build if a corresponding corpus directory exists
        if [ ! -d "$TARGET/corpus/${output_name}" ]; then
            continue
        fi
        $CC $CFLAGS \
            -I"$INC_DIR" \
            -I"$FUZZ_DIR" \
            -I"$TARGET/repo/expat/lib" \
            -DENCODING_FOR_FUZZING="${enc}" \
            "$FUZZ_DIR/${fuzzer_src}.c" \
            -o "$TARGET_DIR/${output_name}" \
            $LDFLAGS \
            -L"$LIB_DIR" -lexpat \
            $LIBS \
            -lm
    done
done
