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
# Clear Magma instrumentation flags so they don't pollute the AFL++ build
unset CFLAGS CXXFLAGS LDFLAGS LIBS

export CC=clang-16
export CXX=clang++-16
export LLVM_CONFIG=llvm-config-16
export AFL_NO_X86=1
export PYTHON_INCLUDE=/
make -j$(nproc) ASAN_BUILD=1 || exit 1
make -C utils/aflpp_driver || exit 1

mkdir -p "$OUT/afl" "$OUT/cmplog"
