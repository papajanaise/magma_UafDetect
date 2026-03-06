#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

if [ ! -d "$FUZZER/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

cd "$FUZZER/repo"
export CC=clang
export CXX=clang++
export AFL_NO_X86=1
export PYTHON_INCLUDE=/
# Clear Magma instrumentation flags so they don't pollute the AFL++ build
unset CFLAGS CXXFLAGS LDFLAGS LIBS
# Use lld for LTO linking instead of the default gold plugin
export LDFLAGS="-fuse-ld=lld"
make -j$(nproc) || exit 1
make -C utils/aflpp_driver || exit 1

# Ensure LTO symlinks exist (afl-cc handles mode based on argv[0])
cd "$FUZZER/repo"
ln -sf afl-cc afl-clang-lto
ln -sf afl-cc afl-clang-lto++

mkdir -p "$OUT/afl" "$OUT/cmplog"
