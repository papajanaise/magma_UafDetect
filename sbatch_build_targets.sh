#!/bin/bash
#SBATCH -o bc_file_build.%j.%N.out
#SBATCH -J bc-file-builder
#SBATCH --ntasks=1
#SBATCH --mem=16G
#SBATCH --time=25:00:00
#SBATCH --partition=standard
#SBATCH --mail-type=ALL
#SBATCH --mail-user=m.thielebein@tu-berlin.de
#SBATCH --exclude=gpu[001-066]

module load singularity
set -euo pipefail
ulimit -v unlimited

# --- These come from: sbatch --export=TARGET=...,PROGRAM=... ---
: "${TARGET:?Set TARGET via --export}"
: "${FUZZER:?Set FUZZER via --export}"
: "${ANALYZER:?Set ANALYZER via --export}"

echo "=== SVF Analyser ==="
echo "Target:  $TARGET"
echo "Analyzer: $ANALYZER"
echo "Program: $FUZZER"
echo "======================"

# --- Environment for the container ---
export SINGULARITYENV_FUZZER="/magma/fuzzers/${FUZZER}"
export SINGULARITYENV_TARGET="/magma/targets/${TARGET}"
export SINGULARITYENV_MAGMA="/magma/magma"
export SINGULARITYENV_OUT="/magma_out"

if [ "$FUZZER" == "afl_uaf_detect" ]; then
    export SINGULARITYENV_ANALYZER="$ANALYZER"
    RUN_SCRIPT="/magma/fuzzers/${FUZZER}/build_bc_files.sh"
else
    export ANALYZER=""
    RUN_SCRIPT="/magma/fuzzers/${FUZZER}/instrument.sh"
fi

# --- Launch ---
singularity exec \
    -B /home/users/m/m.thielebein/magma_UafDetect/fuzzers/${FUZZER}:/magma/fuzzers/${FUZZER} \
    -B /home/users/m/m.thielebein/magma_UafDetect/targets/${TARGET}:/magma/targets/${TARGET} \
    -B /home/users/m/m.thielebein/magma_out/${FUZZER}/${TARGET}/${ANALYZER}:/magma_out  \
    -B /home/users/m/m.thielebein/SVF:/SVF \
    /home/users/m/m.thielebein/magma_containers/magma_${FUZZER}_${TARGET}.sif \
    ${RUN_SCRIPT}

echo "Building BC files finished."