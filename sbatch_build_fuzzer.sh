#!/bin/bash
#SBATCH -J build-fuzzer
#SBATCH --ntasks=1
#SBATCH --mem=16G
#SBATCH --time=01:00:00
#SBATCH --partition=standard
#SBATCH --mail-type=ALL
#SBATCH --mail-user=m.thielebein@tu-berlin.de
#SBATCH --exclude=gpu[001-066],node177

module load singularity
set -euo pipefail
ulimit -v unlimited

# Picks SINGULARITY_TMPDIR on local-disk scratch with enough free space,
# so FUSE squashfuse-mount works (BeeGFS forbids FUSE → slow extraction).
source /home/users/m/m.thielebein/magma_UafDetect/lib_singularity_tmpdir.sh

: "${FUZZER_NAME:?Set FUZZER_NAME via --export}"

# Pick any container for this fuzzer (they all share the same base image)
SIF=$(ls /home/users/m/m.thielebein/magma_containers/magma_${FUZZER_NAME}_*.sif | grep -v devcontainer | head -1)
if [ -z "$SIF" ]; then
    echo "No container found for fuzzer $FUZZER_NAME"
    exit 1
fi

echo "Building fuzzer $FUZZER_NAME using $SIF"

export SINGULARITYENV_FUZZER="/magma/fuzzers/${FUZZER_NAME}"
export SINGULARITYENV_OUT="/magma_out"

FUZZER_OUT="/home/users/m/m.thielebein/magma_out/${FUZZER_NAME}/_fuzzer_build"
mkdir -p "$FUZZER_OUT"

singularity exec --writable-tmpfs \
    -B /home/users/m/m.thielebein/magma_UafDetect/fuzzers/$FUZZER_NAME:/magma/fuzzers/$FUZZER_NAME \
    -B "$FUZZER_OUT":/magma_out \
    "$SIF" \
    /magma/fuzzers/${FUZZER_NAME}/build.sh

rm -rf "$FUZZER_OUT"

STAMP_DIR="/home/users/m/m.thielebein/magma_UafDetect/.build_stamps"
mkdir -p "$STAMP_DIR"
touch "$STAMP_DIR/fuzzer_${FUZZER_NAME}.stamp"

echo "Fuzzer $FUZZER_NAME built successfully."
