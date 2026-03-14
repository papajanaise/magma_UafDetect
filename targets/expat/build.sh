#!/bin/bash
# Build libexpat and compile the fuzzer harness for Magma
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
./buildconf.sh

# Reset timestamps to avoid clock-skew errors in Singularity containers.
# Must run after buildconf.sh/autoreconf so generated files are also touched.
find . -exec touch {} +

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

# --- compile one fuzzer binary per encoding, matching the corpus layout ---
# Encodings mirror the corpus subdirectory names: xml_parse_fuzzer_<ENC>
ENCODINGS=(UTF-8 UTF-16 UTF-16BE UTF-16LE ISO-8859-1 US-ASCII)

for ENC in "${ENCODINGS[@]}"; do
    $CC $CFLAGS \
        -DENCODING_FOR_FUZZING="$ENC" \
        -I"$INC_DIR" \
        -I"$TARGET/repo/expat/lib" \
        "$TARGET/repo/expat/fuzz/xml_parse_fuzzer.c" \
        -o "$OUT/xml_parse_fuzzer_${ENC}" \
        $LDFLAGS \
        -L"$LIB_DIR" -lexpat \
        $LIBS \
        -lm

    $CC $CFLAGS \
        -DENCODING_FOR_FUZZING="$ENC" \
        -I"$INC_DIR" \
        -I"$TARGET/repo/expat/lib" \
        "$TARGET/repo/expat/fuzz/xml_parsebuffer_fuzzer.c" \
        -o "$OUT/xml_parsebuffer_fuzzer_${ENC}" \
        $LDFLAGS \
        -L"$LIB_DIR" -lexpat \
        $LIBS \
        -lm
done
