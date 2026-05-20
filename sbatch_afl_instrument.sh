#!/bin/bash
#SBATCH -o afl_instrument.%j.%N.out
#SBATCH -J afl-instrument
#SBATCH --ntasks=1
#SBATCH --mem=16G
#SBATCH --time=04:00:00
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

: "${TARGET:?Set TARGET via --export}"
: "${ANALYZER:?Set ANALYZER via --export}"

FUZZER="afl_uaf_detect"

echo "=== AFL Instrument ==="
echo "Fuzzer:   $FUZZER"
echo "Target:   $TARGET"
echo "Analyzer: $ANALYZER"
echo "======================"

SHARED_DIR="/home/users/m/m.thielebein/magma_workdir/${FUZZER}/${TARGET}/instrument"
mkdir -p "$SHARED_DIR"

export SINGULARITYENV_SHARED=/magma_shared

singularity exec \
    -B /home/users/m/m.thielebein/magma_UafDetect/fuzzers/${FUZZER}:/magma/fuzzers/${FUZZER} \
    -B /home/users/m/m.thielebein/magma_UafDetect/targets/${TARGET}:/magma/targets/${TARGET} \
    -B /home/users/m/m.thielebein/magma_out/${FUZZER}/${TARGET}/${ANALYZER}:/magma_out \
    -B /home/users/m/m.thielebein/SVF:/SVF \
    -B "${SHARED_DIR}":/magma_shared \
    /home/users/m/m.thielebein/magma_containers/magma_${FUZZER}_${TARGET}.sif \
    /magma/fuzzers/${FUZZER}/afl_instrument.sh

echo "AFL instrumentation finished."
