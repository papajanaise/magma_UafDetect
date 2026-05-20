#!/bin/bash
#SBATCH -J build-svf-driver
#SBATCH --ntasks=1
#SBATCH --mem=16G
#SBATCH --time=01:00:00
#SBATCH --partition=standard
#SBATCH --mail-type=ALL
#SBATCH --mail-user=m.thielebein@tu-berlin.de
#SBATCH --exclude=gpu[001-066],node177

module load singularity
set -euo pipefail

# Picks SINGULARITY_TMPDIR on local-disk scratch with enough free space,
# so FUSE squashfuse-mount works (BeeGFS forbids FUSE → slow extraction).
source /home/users/m/m.thielebein/magma_UafDetect/lib_singularity_tmpdir.sh

# Pick any afl_uaf_detect container (they all have cmake + LLVM)
SIF=$(ls /home/users/m/m.thielebein/magma_containers/magma_afl_uaf_detect_*.sif | grep -v devcontainer | head -1)
if [ -z "$SIF" ]; then
    echo "No container found for afl_uaf_detect"
    exit 1
fi

echo "Building SVF driver using $SIF"

singularity exec \
    -B /home/users/m/m.thielebein/magma_UafDetect/fuzzers/afl_uaf_detect:/magma/fuzzers/afl_uaf_detect \
    -B /home/users/m/m.thielebein/SVF:/SVF \
    "$SIF" \
    bash -c '
        set -euo pipefail
        # Wipe the build dir so a stale CMakeCache.txt from a different
        # source path (e.g. devcontainer at /workspaces/...) cannot make
        # cmake refuse to reconfigure.
        rm -rf /magma/fuzzers/afl_uaf_detect/repo/SVF_drivers/build
        cmake -S /magma/fuzzers/afl_uaf_detect/repo/SVF_drivers \
              -B /magma/fuzzers/afl_uaf_detect/repo/SVF_drivers/build \
              -DSVF_DIR=/SVF
        cmake --build /magma/fuzzers/afl_uaf_detect/repo/SVF_drivers/build --verbose
    '

STAMP_DIR="/home/users/m/m.thielebein/magma_UafDetect/.build_stamps"
mkdir -p "$STAMP_DIR"
touch "$STAMP_DIR/svf_driver.stamp"

echo "SVF driver built successfully."
