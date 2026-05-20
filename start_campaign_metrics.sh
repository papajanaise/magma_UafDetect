#!/bin/bash
# Usage: start_campaign_metrics.sh <fuzzer> <num_campaigns> [analyzer] [--offset N]
set -euo pipefail

usage() {
    echo "Usage: $0 <fuzzer> <num_campaigns> [analyzer] [--offset N]" >&2
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

FUZZER="$1"; shift
NUM_CAMPAIGNS="$1"; shift
ANALYZER=""
OFFSET=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --offset)
            [[ $# -ge 2 ]] || usage
            OFFSET="$2"
            shift 2
            ;;
        --offset=*)
            OFFSET="${1#--offset=}"
            shift
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage
            ;;
        *)
            if [[ -n "$ANALYZER" ]]; then
                echo "Unexpected positional arg: $1" >&2
                usage
            fi
            ANALYZER="$1"
            shift
            ;;
    esac
done

if ! [[ "$OFFSET" =~ ^[0-9]+$ ]]; then
    echo "ERROR: --offset must be a non-negative integer (got: $OFFSET)" >&2
    exit 1
fi

RESULTS_DIR=/home/users/m/m.thielebein/magma_results
TARGETS_DIR=/home/users/m/m.thielebein/magma_UafDetect/targets
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
OFFSUFFIX=""
if [[ "$OFFSET" -gt 0 ]]; then
    OFFSUFFIX="_off${OFFSET}"
fi
OUTPUT_DIR="$RESULTS_DIR/analysis_${FUZZER}${SUFFIX}${OFFSUFFIX}_${STAMP}"

echo "[*] Submitting campaign metrics job"
echo "    fuzzer=$FUZZER analyzer=${ANALYZER:-<all>} n=$NUM_CAMPAIGNS offset=$OFFSET"
echo "    output=$OUTPUT_DIR"

sbatch \
    --export=FUZZER="$FUZZER",NUM_CAMPAIGNS="$NUM_CAMPAIGNS",OFFSET="$OFFSET",ANALYZER="$ANALYZER",OUTPUT_DIR="$OUTPUT_DIR",RESULTS_DIR="$RESULTS_DIR",TARGETS_DIR="$TARGETS_DIR" \
    "$SBATCH_SCRIPT"
