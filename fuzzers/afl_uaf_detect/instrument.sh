#!/bin/bash
set -euo pipefail

mkdir -p "$SHARED/log"
exec > >(tee -a "$SHARED/log/afl_uaf_detect_libpng_build.log") 2>&1

##
## PHASE 1: Build target with gclang to get normal binaries + embedded bitcode
##

# Tell gllvm to use vanilla clang underneath
export LLVM_COMPILER_PATH="/usr/lib/llvm-14/bin"  # adjust to your LLVM
export LLVM_CC_NAME="clang"
export LLVM_CXX_NAME="clang++"

##
## PHASE 3: Compile instrumented .bc with afl-clang-fast + link driver
##

export CC="$FUZZER/repo/afl-clang-fast"
export CXX="$FUZZER/repo/afl-clang-fast++"

for bc_file in "$OUT/"*_instr.bc; do

    # afl-clang-fast accepts .bc input — it will:
    #   1. Run AFL's instrumentation pass on the bitcode
    #   2. Compile to native code
    #   3. Link everything together
    #
    # The .bc already contains magma symbols (from get-bc/llvm-link),
    # so do NOT re-link magma.o. Only add system libs not in the bitcode.
    $CXX \
        "$bc_file" \
        "$FUZZER/repo/libAFLDriver.a" \
        $LDFLAGS \
        -lpthread -lm -lz -lrt -lstdc++ \
        -o "$OUT/afl/${PROGRAM}"

    echo "[*] Final binary: $OUT/afl/${PROGRAM}"
done
