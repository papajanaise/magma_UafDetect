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
## PHASE 3: Compile instrumented .bc with afl-clang-lto + link driver
##

LLVM_PATH="/usr/lib/llvm-16/bin"
export CC="$FUZZER/repo/afl-clang-lto"
export CXX="$FUZZER/repo/afl-clang-lto++"
export AS="${LLVM_PATH}/llvm-as"
export RANLIB="${LLVM_PATH}/llvm-ranlib"
export AR="${LLVM_PATH}/llvm-ar"
export LD="${LLVM_PATH}/ld.lld"
export NM="${LLVM_PATH}/llvm-nm"
unset AFL_LLVM_CMPLOG

mkdir -p "$OUT/afl"
for bc_file in "$OUT/targets/"*_instr.bc; do
    [ -f "$bc_file" ] || continue
    PROGRAM="$(basename "${bc_file%_instr.bc}")"

    # afl-clang-lto accepts .bc input — it will:
    #   1. Run AFL's LTO instrumentation pass on the bitcode
    #   2. Compile to native code with deterministic edge IDs
    #   3. Link everything together
    #
    # The .bc already contains magma + SVF symbols (from get-bc/llvm-link),
    # so do NOT re-link magma.o. Only add system libs not in the bitcode.
    $CXX \
        "$bc_file" \
        "$FUZZER/repo/libAFLDriver.a" \
        $LDFLAGS \
        -lpthread -lm -lz -lrt -lstdc++ \
        -o "$OUT/afl/${PROGRAM}"

    echo "[*] Final binary: $OUT/afl/${PROGRAM}"
done

##
## PHASE 4: Build CmpLog binaries for comparison solving
##

export AFL_LLVM_CMPLOG=1
mkdir -p "$OUT/cmplog"
for bc_file in "$OUT/targets/"*_instr.bc; do
    [ -f "$bc_file" ] || continue
    PROGRAM="$(basename "${bc_file%_instr.bc}")"

    $CXX \
        "$bc_file" \
        "$FUZZER/repo/libAFLDriver.a" \
        $LDFLAGS \
        -lpthread -lm -lz -lrt -lstdc++ \
        -o "$OUT/cmplog/${PROGRAM}"

    echo "[*] CmpLog binary: $OUT/cmplog/${PROGRAM}"
done
unset AFL_LLVM_CMPLOG
