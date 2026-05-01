#!/bin/bash
#SBATCH --ntasks=1
#SBATCH --mem=4G
#SBATCH --time=25:00:00
#SBATCH --partition=standard
#SBATCH --exclude=gpu[001-066]

set -euo pipefail

: "${BIN_PATH:?Set BIN_PATH via --export}"
: "${ANALYZER:?Set ANALYZER via --export}"
: "${STAMP:?Set STAMP via --export}"
: "${TIMEOUT:=86400}"

NAME="$(basename "$BIN_PATH")"             # uaf_001_free_finder_instr
TEST_ID="${NAME%_${ANALYZER}_instr}"       # uaf_001

CAMPAIGN_DIR="/home/users/m/m.thielebein/uaf_batch/campaign_results/$STAMP/$ANALYZER/$TEST_ID/${SLURM_JOB_ID}"
SEED_DIR="$CAMPAIGN_DIR/seeds"
AFL_OUT="$CAMPAIGN_DIR/afl"
mkdir -p "$SEED_DIR" "$AFL_OUT"

# Generic seed: UAF\x01 magic + 0xFF cmd/flag bytes + padding.
# Satisfies uaf_001 (first byte 'U') and SCHEMA medium/large cases
# (magic UAF\x01, non-zero cmd & flag, min_input_length).
{ printf 'UAF\x01\xff\xff\xff\xff'; head -c 60 /dev/zero; } > "$SEED_DIR/seed"

AFL_FUZZ="/home/users/m/m.thielebein/magma_UafDetect/fuzzers/afl_uaf_detect/repo/afl-fuzz"

export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_AUTORESUME=1
export AFL_MAP_SIZE=2097152
export AFL_USE_UAF_DETECT=1
export AFL_UAF_SELECT_PROB="${AFL_UAF_SELECT_PROB:-0.70}"
if [ "$ANALYZER" = "free_finder" ]; then
    export AFL_USE_FREE_FINDER=1
fi

echo "=== UAF batch campaign ==="
echo "Binary:   $BIN_PATH"
echo "Analyzer: $ANALYZER"
echo "Test:     $TEST_ID"
echo "Out:      $AFL_OUT"
echo "Job ID:   $SLURM_JOB_ID"
echo "=========================="

"$AFL_FUZZ" -i "$SEED_DIR" -o "$AFL_OUT" -V "$TIMEOUT" -- "$BIN_PATH" @@
echo "Campaign finished."
