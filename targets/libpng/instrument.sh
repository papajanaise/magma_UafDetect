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
autoreconf -f -i
./configure --with-libpng-prefix=MAGMA_ --disable-shared
make -j$(nproc) clean
make -j$(nproc) libpng16.la

cp .libs/libpng16.a "$OUT/"

# compile and link target into one bit code file
clang-13 -O0 -g -emit-llvm -std=c++11 -I. \
     contrib/oss-fuzz/libpng_read_fuzzer.cc -o - | \
     llvm-link - .libs/libpng16.a $LIBS -lz > $OUT/libpng_read_fuzzer/libpng_linked_bitcode.bc

#run SVF Driver on libpng_read_fuzzer
/magma/fuzzers/afl_uaf_detect/repo/SVF_drivers/build/svf-icfg-driver --input-bc $OUT/libpng_read_fuzzer/libpng_linked_bitcode.bc