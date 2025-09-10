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
CC=clang make all -j $(nproc) AFL_MAP_SIZE=73728 LLVM_CONFIG=llvm-config-13 AFL_USE_UAF_DETECT=1
#CC=clang make -j $(nproc) -C llvm_mode-13

pwd
ls | grep "afl-llvm-uaf-pass.so"
PASS_SO="$(pwd)/afl-llvm-uaf-pass.so"

# compile afl_driver.cpp
"./afl-clang-fast++" $CXXFLAGS -fsanitize=address -Xclang -load -Xclang "$PASS_SO" -Xclang -fpass-plugin="$PASS_SO" -c "afl_driver.cpp" -fPIC -o "$OUT/afl_driver.o"
