#!/bin/bash
set -e

##
# Pre-requirements:
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, FLAGS, LIBS, etc...
##

if [ ! -d "$TARGET/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

# build the libpng library
cd "$TARGET/repo"
find . -exec touch {} +
autoreconf -f -i
find . -exec touch {} +
./configure --with-libpng-prefix=MAGMA_ --disable-shared
find . -exec touch {} +
make -j${MAGMA_JOBS:-1} clean
make -j${MAGMA_JOBS:-1} libpng16.la

cp .libs/libpng16.a "$OUT/"

TARGET_DIR="$OUT/targets"
mkdir -p "$TARGET_DIR"

# build libpng_simplified_read_fuzzer (exercises png_image_* simplified API,
# the CVE-2019-7317 trigger path; replaces libpng_read_fuzzer).
# Source lives in $TARGET/src/ because fetch.sh re-clones repo/ and would
# wipe anything dropped under repo/contrib/oss-fuzz/.
$CXX $CXXFLAGS -std=c++11 -include stdlib.h -I. \
     "$TARGET/src/libpng_simplified_read_fuzzer.cc" \
     -o "$TARGET_DIR/libpng_simplified_read_fuzzer" \
     $LDFLAGS .libs/libpng16.a $LIBS -lz