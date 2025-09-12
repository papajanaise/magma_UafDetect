#!/bin/bash
set -e

exec > >(tee -a /home/magma_workdir/log/afl_uaf_detect_libpng_build.log) 2>&1

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env MAGMA: path to Magma support files
# - env OUT: path to directory where artifacts are stored
# - env CFLAGS and CXXFLAGS must be set to link against Magma instrumentation
##

export CC="$FUZZER/repo/afl-clang-fast"
export CXX="$FUZZER/repo/afl-clang-fast++"
export AS="$FUZZER/repo/afl-as"

PASS_SO="$FUZZER/repo/afl-llvm-uaf-pass.so"
export CFLAGS="$CFLAGS -fsanitize=address -Xclang -load -Xclang "$PASS_SO" -Xclang -fpass-plugin="$PASS_SO""
export CXXFLAGS="$CXXFLAGS -fsanitize=address -Xclang -load -Xclang "$PASS_SO" -Xclang -fpass-plugin="$PASS_SO""
export LDFLAGS="$LDFLAGS -fsanitize=address"

export LIBS="$LIBS -l:afl_driver.o -lstdc++"

"$MAGMA/build.sh"
"$TARGET/build.sh"

# NOTE: We pass $OUT directly to the target build.sh script, since the artifact
#       itself is the fuzz target. In the case of Angora, we might need to
#       replace $OUT by $OUT/fast and $OUT/track, for instance.
