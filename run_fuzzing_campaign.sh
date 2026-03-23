#!/bin/bash
#SBATCH -o magma_campaign.%j.%N.out
#SBATCH -J magma-fuzz
#SBATCH --ntasks=1
#SBATCH --mem=16G
#SBATCH --time=24:00:00
#SBATCH --partition=standard
#SBATCH --mail-type=ALL
#SBATCH --mail-user=m.thielebein@tu-berlin.de

module load singularity
set -euo pipefail
ulimit -v unlimited

# --- These come from: sbatch --export=FUZZER=...,TARGET=...,PROGRAM=... ---
: "${FUZZER:?Set FUZZER via --export}"
: "${TARGET:?Set TARGET via --export}"
: "${PROGRAM:?Set PROGRAM via --export}"

# --- Paths ---
SIF="/home/users/m/m.thielebein/magma_containers/magma_${FUZZER}_${TARGET}.sif"
BASE="$HOME/magma_results"
if [ "$FUZZER" == "afl_uaf_detect" ]; then
    HOST_OUT="$HOME/magma_out/${FUZZER}/${TARGET}/${ANALYZER}"
else
    HOST_OUT="$HOME/magma_out/${FUZZER}/${TARGET}"
fi


RUN_ID="${SLURM_JOB_ID}"
CAMPAIGN_DIR="${BASE}/${FUZZER}/${TARGET}/${PROGRAM}/${RUN_ID}"
mkdir -p "$CAMPAIGN_DIR"/{findings,monitor,log}

# --- Check what ARGS the target actually expects ---
# Extract from configrc (uses associative array PROGRAM_ARGS)
EXPECTED_ARGS=$(singularity exec "$SIF" bash -c \
    "source /magma/targets/${TARGET}/configrc 2>/dev/null; echo \"\${PROGRAM_ARGS[$PROGRAM]:-}\"" \
) || EXPECTED_ARGS=""

echo "=== Magma Campaign ==="
echo "Fuzzer:  $FUZZER"
echo "Target:  $TARGET"
echo "Program: $PROGRAM"
echo "Args:    '${EXPECTED_ARGS}'"
echo "SIF:     $SIF"
echo "Shared:  $CAMPAIGN_DIR"
echo "Job ID:  $SLURM_JOB_ID"
echo "Out: $HOST_OUT"
echo "======================"

# --- Environment for the container ---
export SINGULARITYENV_FUZZER="/magma/fuzzers/${FUZZER}"
export SINGULARITYENV_TARGET="/magma/targets/${TARGET}"
export SINGULARITYENV_PROGRAM="$PROGRAM"
export SINGULARITYENV_MAGMA="/magma/magma"
export SINGULARITYENV_OUT="/magma_out"
export SINGULARITYENV_SHARED="/magma_shared"
export SINGULARITYENV_ARGS="$EXPECTED_ARGS"
export SINGULARITYENV_POLL=5
export SINGULARITYENV_TIMEOUT=86400 #-> 24h          #3600  #1h

# --- Launch ---
singularity exec \
    --writable-tmpfs \
    --bind "$CAMPAIGN_DIR":/magma_shared \
    --bind "/home/users/m/m.thielebein/magma_UafDetect":"/magma" \
    --bind "$HOST_OUT":"/magma_out" \
    "$SIF" \
    /bin/bash /magma/magma/run.sh

echo "Campaign finished."