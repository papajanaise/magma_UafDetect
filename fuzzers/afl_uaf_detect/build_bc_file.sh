#!/bin/bash
set -euo pipefail

export PATH="$HOME/go/bin:$PATH"

##
## PHASE 1: Build target with gclang to get normal binaries + embedded bitcode
##

# Tell gllvm to use vanilla clang underneath
export LLVM_COMPILER_PATH="/usr/lib/llvm-16/bin"  # must match installed LLVM
export LLVM_CC_NAME="clang"
export LLVM_CXX_NAME="clang++"

# Set compilers to gclang — the target's build.sh will pick these up
export CC="gclang"
export CXX="gclang++"

# Keep Magma's CFLAGS/LDFLAGS (for canary support), but remove
# anything AFL-specific. Magma sets these in the Dockerfile.
# Add -g for debug info if your instrumentation needs it.
export CFLAGS="$CFLAGS -g"
export CXXFLAGS="$CXXFLAGS -g"

# LIBS includes magma.o for canary support — keep that,
# but do NOT link libAFLDriver.a yet (that's Phase 3)
export MAGMA_LIBS="$LIBS"

# Limit parallelism to avoid hitting process limits (EAGAIN/fork) in containers.
# gclang wraps each clang call with extra processes, so high -j values exhaust ulimit -u.
export MAKEFLAGS="-j${MAGMA_JOBS:-4}"

# Build the target (library + harness binaries) into $OUT
"$MAGMA/build.sh"

# OpenSSL's fuzz/driver.c (libFuzzer branch) provides LLVMFuzzerTestOneInput but no main().
# main() is normally supplied by -fsanitize=fuzzer, which we don't use with gclang.
# Use a weak stub so the fuzz binaries link for get-bc extraction, but AFL's strong main
# from libAFLDriver.a will override it at the instrument.sh relinking step (Phase 3).
cat > /tmp/stub_main.c << 'EOF'
__attribute__((weak)) int main(int argc, char **argv) { return 0; }
EOF
"$CC" $CFLAGS -c /tmp/stub_main.c -o "$OUT/stub_main.o"
export LIBS="$LIBS -l:stub_main.o"

"$TARGET/build.sh"

##
## PHASE 2: Extract .bc and run your custom instrumentation
##

# Extract bitcode only for the target's harness programs
prog="$OUT/$PROGRAM"
[ -f "$prog" ] || { echo "[!] Binary not found: $prog"; continue; }

get-bc -o "$OUT/$PROGRAM.bc" "$prog"

echo "[*] Extracted $OUT/$PROGRAM.bc"
