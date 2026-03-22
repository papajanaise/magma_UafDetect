#!/bin/bash
#SBATCH -o svf_analyser.%j.%N.out
#SBATCH -J svf-analyser
#SBATCH --ntasks=1
#SBATCH --mem=16G
#SBATCH --time=25:00:00
#SBATCH --partition=standard
#SBATCH --mail-type=ALL
#SBATCH --mail-user=m.thielebein@tu-berlin.de

module load singularity
set -euo pipefail
ulimit -v unlimited

# --- These come from: sbatch --export=TARGET=...,PROGRAM=... ---
: "${TARGET:?Set TARGET via --export}"
: "${PROGRAM:?Set PROGRAM via --export}"
: "${ANALYZER:?Set ANALYZER via --export}"

echo "=== SVF Analyser ==="
echo "Target:  $TARGET"
echo "Analyzer: $ANALYZER"
echo "Program: $PROGRAM"
echo "======================"

# --- Environment for the container ---
export SINGULARITYENV_PROGRAM="$PROGRAM"
export SINGULARITYENV_POLL=5
export SINGULARITYENV_TIMEOUT=24h
export SINGULARITYENV_AFFINITY=0

# --- Launch ---
singularity exec \
    -B /home/users/m/m.thielebein/magma_UafDetect/fuzzers/afl_uaf_detect/repo/SVF_drivers:/magma/fuzzers/afl_uaf_detect/repo/SVF_drivers \
    -B /home/users/m/m.thielebein/magma_out/${FUZZER_NAME}/${TARGET_NAME}/${ANALYZER}:/magma_out  \
    /home/users/m/m.thielebein/magma_containers/magma_devcontainer_260304.sif \
    /magma/fuzzers/afl_uaf_detect/repo/SVF_drivers/build/${ANALYZER}-driver \
    "/magma_out/"

echo "Analyser finished."