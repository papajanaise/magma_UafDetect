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
# -fsanitize=address: bake ASan IR-level instrumentation into the per-TU
# bitcode captured by gclang. Without this, Phase 3's AFL_USE_ASAN=1 only
# links the runtime — user code stays uninstrumented and UAF/OOB outside
# malloc redzones goes undetected. Phase 2 (free_finder/svf driver) skips
# asan_* intrinsics so they don't pollute the alloc/free analysis.
#
# -fsanitize-address-use-after-return=never: disable SUAR detection (no
# fake-stack allocation). libpng's setjmp/longjmp-based error handling
# (png_safe_execute) triggers false-positive SUAR reports when longjmp
# returns past frames whose fake-stack slots have been popped. magma's
# injected bugs are heap UAFs, not stack UAFs — we don't need SUAR.
# Match what lto_asan/clang-11 had by default.
ASAN_CFLAGS="-fsanitize=address -fsanitize-address-use-after-return=never"
export CFLAGS="$CFLAGS -g $ASAN_CFLAGS"
export CXXFLAGS="$CXXFLAGS -g $ASAN_CFLAGS"
export LDFLAGS="${LDFLAGS:-} -fsanitize=address"

# LIBS includes magma.o for canary support — keep that,
# but do NOT link libAFLDriver.a yet (that's Phase 3)
export MAGMA_LIBS="$LIBS"

# Limit parallelism to avoid hitting process limits (EAGAIN/fork) in containers.
# gclang wraps each clang call with extra processes, so high -j values exhaust ulimit -u.
export MAKEFLAGS="-j${MAGMA_JOBS:-1}"

# Build the target (library + harness binaries) into $OUT
"$MAGMA/build.sh"

# OpenSSL's fuzz/driver.c (libFuzzer branch) provides LLVMFuzzerTestOneInput but no main().
# main() is normally supplied by -fsanitize=fuzzer, which we don't use with gclang.
# Use a weak stub so the fuzz binaries link for get-bc extraction, but AFL's strong main
# from libAFLDriver.a will override it at the instrument.sh relinking step (Phase 3).
# Write the stub source under $OUT (per-target, per-campaign) rather than /tmp.
# Singularity bind-mounts the host /tmp into every container, so parallel target
# builds racing on /tmp/stub_main.c can read a half-written (empty) file and
# produce a stub_main.o with no `main` symbol — causing later fuzzer links to
# fail with "undefined reference to `main'".
cat > "$OUT/stub_main.c" << 'EOF'
__attribute__((weak)) int main(int argc, char **argv) { return 0; }
EOF
"$CC" $CFLAGS -c "$OUT/stub_main.c" -o "$OUT/stub_main.o"
export LIBS="$LIBS -l:stub_main.o"

"$TARGET/build.sh"

##
## PHASE 2: Extract .bc and run your custom instrumentation
##

# Extract bitcode for each program listed in the target's configrc.
source "$TARGET/configrc"

TARGET_DIR="$OUT/targets"
if [ ! -d "$TARGET_DIR" ]; then
    echo "[!] No targets directory found at $TARGET_DIR"
    exit 1
fi

for name in "${PROGRAMS[@]}"; do
    prog="$TARGET_DIR/$name"
    if [ ! -f "$prog" ]; then
        echo "WARNING: binary '$name' not found at $prog, skipping" >&2
        continue
    fi
    get-bc -o "$TARGET_DIR/${name}.bc" "$prog"
    echo "[*] Extracted $TARGET_DIR/${name}.bc"
done
