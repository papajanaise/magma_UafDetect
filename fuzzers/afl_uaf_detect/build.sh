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
CC=clang make all -j $(nproc) AFL_MAP_SIZE=73728 LLVM_CONFIG=llvm-config-13 AFL_USE_UAF_DETECT=1 AFL_DEBUG=1 AFL_DEBUG_CHILD=1
#CC=clang make -j $(nproc) -C llvm_mode-13

pwd
ls | grep "afl-llvm-uaf-pass.so"

# compile afl_driver.cpp
"./afl-clang-fast++" $CXXFLAGS -fsanitize=address -std=c++11 -c "afl_driver.cpp" -fPIC -o "$OUT/afl_driver.o"

#build SVF Driver
SVF_DRIVER_SRC=/magma/fuzzers/afl_uaf_detect/repo/SVF_drivers
SVF_DRIVER_BUILD=${SVF_DRIVER_SRC}/build

rm -rf "${SVF_DRIVER_BUILD}"
cmake -S "${SVF_DRIVER_SRC}" -B "${SVF_DRIVER_BUILD}" -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build "${SVF_DRIVER_BUILD}" -- -j"$(nproc)" VERBOSE=1