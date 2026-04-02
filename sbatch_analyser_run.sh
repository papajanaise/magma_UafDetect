#!/bin/bash
#SBATCH -o svf_analyser.%j.%N.out
#SBATCH -J svf-analyser
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

mkdir -p /home/users/m/m.thielebein/magma_out/afl_uaf_detect/${TARGET}/${ANALYZER}/analyzer_logs/

# --- Launch ---
singularity exec \
    -B /home/users/m/m.thielebein/magma_UafDetect/fuzzers/afl_uaf_detect/repo/SVF_drivers:/magma/fuzzers/afl_uaf_detect/repo/SVF_drivers \
    -B /home/users/m/m.thielebein/magma_out/afl_uaf_detect/${TARGET}/${ANALYZER}:/magma_out  \
    -B /home/users/m/m.thielebein/SVF:/SVF \
    /home/users/m/m.thielebein/magma_containers/magma_afl_uaf_detect_${TARGET}.sif \
    /magma/fuzzers/afl_uaf_detect/repo/SVF_drivers/build/${ANALYZER}-driver \
    "/magma_out/targets/${PROGRAM}.bc" -o "/magma_out/targets/${PROGRAM}_instr.bc" > "/home/users/m/m.thielebein/magma_out/afl_uaf_detect/${TARGET}/${ANALYZER}/analyzer_logs/${PROGRAM}_analyser.log" 2>&1

echo "Analyser finished."