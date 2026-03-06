#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

if [ ! -d "/magma/fuzzers/afl_uaf_detect/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

cd "/magma/fuzzers/afl_uaf_detect/repo"

unset CFLAGS CXXFLAGS LDFLAGS LIBS

export CC=clang-16
export CXX=clang++-16
export LLVM_CONFIG=llvm-config-16
export AFL_NO_X86=1
export PYTHON_INCLUDE=/
export AFL_USE_UAF_DETECT=1
make clean
make -j$(nproc) || exit 1
make -C utils/aflpp_driver || exit 1

mkdir -p "$OUT/afl" "$OUT/cmplog"
