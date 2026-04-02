#!/bin/bash
set -euo pipefail

mkdir -p "$OUT/log"
exec > >(tee -a "$OUT/log/afl_uaf_detect_libpng_build.log") 2>&1

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
export AFL_USE_ASAN=1
unset AFL_LLVM_CMPLOG

mkdir -p "$OUT/afl"
for bc_file in "$OUT/targets/"*_instr.bc; do
    [ -f "$bc_file" ] || continue
    PROGRAM="$(basename "${bc_file%_instr.bc}")"

    # Skip non-fuzzer binaries (no LLVMFuzzerTestOneInput)
    if ! grep -q "LLVMFuzzerTestOneInput" "$bc_file"; then
        echo "[*] Skipping $PROGRAM (not a fuzzer harness)"
        continue
    fi

    # Strip weak stub main() and any local getenv definition from the bitcode.
    # We strip debug info first so that sed doesn't break DISubprogram
    # metadata entries that reference the deleted functions.
    nomain_bc="${bc_file%.bc}_nomain.bc"
    ${LLVM_PATH}/opt -strip-debug "$bc_file" -o /tmp/_stripped_debug.bc
    ${LLVM_PATH}/llvm-dis /tmp/_stripped_debug.bc -o /tmp/_strip_main.ll
    sed -e '/^define.*@main(/,/^}/d' \
        -e '/^define.*@getenv(/,/^}/c declare ptr @getenv(ptr)' \
        /tmp/_strip_main.ll > /tmp/_strip_main_clean.ll
    ${LLVM_PATH}/llvm-as /tmp/_strip_main_clean.ll -o "$nomain_bc"
    echo "[*] Stripped stub main + getenv from $(basename "$bc_file")"

    # afl-clang-lto accepts .bc input — it will:
    #   1. Run AFL's LTO instrumentation pass on the bitcode
    #   2. Compile to native code with deterministic edge IDs
    #   3. Link everything together
    #
    # The .bc already contains magma + SVF symbols (from get-bc/llvm-link),
    # so do NOT re-link magma.o. Only add system libs not in the bitcode.
    # libxml2 needs liblzma for XZ decompression support
    EXTRA_LIBS=""
    [[ "$PROGRAM" == *libxml2* ]] && EXTRA_LIBS="-llzma"

    $CXX \
        "$nomain_bc" \
        "$FUZZER/repo/libAFLDriver.a" \
        $LDFLAGS \
        -lpthread -lm -lz -lrt -lstdc++ $EXTRA_LIBS \
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

    # Skip non-fuzzer binaries (no LLVMFuzzerTestOneInput)
    if ! grep -q "LLVMFuzzerTestOneInput" "$bc_file"; then
        echo "[*] Skipping $PROGRAM for CmpLog (not a fuzzer harness)"
        continue
    fi

    # Reuse the _nomain.bc from Phase 3 if it exists
    nomain_bc="${bc_file%.bc}_nomain.bc"
    if [ ! -f "$nomain_bc" ]; then
        ${LLVM_PATH}/opt -strip-debug "$bc_file" -o /tmp/_stripped_debug.bc
        ${LLVM_PATH}/llvm-dis /tmp/_stripped_debug.bc -o /tmp/_strip_main.ll
        sed -e '/^define.*@main(/,/^}/d' \
            -e '/^define.*@getenv(/,/^}/c declare ptr @getenv(ptr)' \
            /tmp/_strip_main.ll > /tmp/_strip_main_clean.ll
        ${LLVM_PATH}/llvm-as /tmp/_strip_main_clean.ll -o "$nomain_bc"
    fi

    EXTRA_LIBS=""
    [[ "$PROGRAM" == *libxml2* ]] && EXTRA_LIBS="-llzma"

    $CXX \
        "$nomain_bc" \
        "$FUZZER/repo/libAFLDriver.a" \
        $LDFLAGS \
        -lpthread -lm -lz -lrt -lstdc++ $EXTRA_LIBS \
        -o "$OUT/cmplog/${PROGRAM}"

    echo "[*] CmpLog binary: $OUT/cmplog/${PROGRAM}"
done
unset AFL_LLVM_CMPLOG
