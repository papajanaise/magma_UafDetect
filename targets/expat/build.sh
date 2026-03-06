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

# --- compile the fuzzer harness ---
# libexpat ships its own OSS-Fuzz harness under fuzz/xml.c (or xmlparse_fuzzer.c)
# depending on version; adapt path as needed.
FUZZ_SRC="$TARGET/repo/expat/fuzz/xml.c"
if [ ! -f "$FUZZ_SRC" ]; then
    FUZZ_SRC="$TARGET/repo/expat/fuzz/xmlparse_fuzzer.cc"
fi

$CC $CFLAGS \
    -I"$INC_DIR" \
    "$FUZZ_SRC" \
    -o "$OUT/expat_fuzzer" \
    $LDFLAGS \
    -L"$LIB_DIR" -lexpat \
    $LIBS \
    -lm
