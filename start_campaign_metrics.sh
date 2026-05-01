#!/bin/bash
# Usage: start_campaign_metrics.sh <fuzzer> <num_campaigns> [analyzer]
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Usage: $0 <fuzzer> <num_campaigns> [analyzer]" >&2
    exit 1
fi

FUZZER="$1"
NUM_CAMPAIGNS="$2"
ANALYZER="${3:-}"

RESULTS_DIR=/home/users/m/m.thielebein/magma_results
SBATCH_SCRIPT=/home/users/m/m.thielebein/magma_UafDetect/sbatch_campaign_metrics.sh

if [[ ! -d "$RESULTS_DIR/$FUZZER" ]]; then
    echo "ERROR: $RESULTS_DIR/$FUZZER does not exist" >&2
    exit 1
fi
if [[ -n "$ANALYZER" && ! -d "$RESULTS_DIR/$FUZZER/$ANALYZER" ]]; then
    echo "ERROR: $RESULTS_DIR/$FUZZER/$ANALYZER does not exist" >&2
    exit 1
fi

STAMP=$(date +%y%m%d_%H%M)
SUFFIX="${ANALYZER:+_$ANALYZER}"
OUTPUT_DIR="$RESULTS_DIR/analysis_${FUZZER}${SUFFIX}_${STAMP}"

echo "[*] Submitting campaign metrics job"
echo "    fuzzer=$FUZZER analyzer=${ANALYZER:-<all>} n=$NUM_CAMPAIGNS"
echo "    output=$OUTPUT_DIR"

sbatch \
    --export=FUZZER="$FUZZER",NUM_CAMPAIGNS="$NUM_CAMPAIGNS",ANALYZER="$ANALYZER",OUTPUT_DIR="$OUTPUT_DIR",RESULTS_DIR="$RESULTS_DIR" \
    "$SBATCH_SCRIPT"
