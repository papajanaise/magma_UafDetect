#!/bin/bash
#SBATCH -o /home/users/m/m.thielebein/magma_campaign_logs/campaign_analysis_jobs/campaign_metrics.%j.%N.out
#SBATCH -J campaign-metrics
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=02:00:00
#SBATCH --partition=standard
#SBATCH --mail-type=ALL
#SBATCH --mail-user=m.thielebein@tu-berlin.de

set -euo pipefail

: "${FUZZER:?Set FUZZER via --export}"
: "${NUM_CAMPAIGNS:?Set NUM_CAMPAIGNS via --export}"
: "${OUTPUT_DIR:?Set OUTPUT_DIR via --export}"
: "${ANALYZER:=}"
: "${RESULTS_DIR:=/home/users/m/m.thielebein/magma_results}"

SCRIPT=/home/users/m/m.thielebein/magma_UafDetect/tools/campaign_metrics.py
VENV_PY=/home/users/m/m.thielebein/magma_UafDetect/tools/.venv/bin/python
if [[ ! -x "$VENV_PY" ]]; then
    echo "ERROR: venv python not found at $VENV_PY" >&2
    echo "Create it once with:" >&2
    echo "  python3 -m venv $(dirname $(dirname $VENV_PY)) && $VENV_PY -m pip install numpy pandas" >&2
    exit 1
fi

echo "=== Campaign Metrics ==="
echo "Fuzzer:         $FUZZER"
echo "Analyzer:       ${ANALYZER:-<all>}"
echo "Num campaigns:  $NUM_CAMPAIGNS"
echo "Results dir:    $RESULTS_DIR"
echo "Output dir:     $OUTPUT_DIR"
echo "========================"

mkdir -p "$OUTPUT_DIR"

args=(
    --fuzzer "$FUZZER"
    --num-campaigns "$NUM_CAMPAIGNS"
    --results-dir "$RESULTS_DIR"
    --output-dir "$OUTPUT_DIR"
    -v
)
if [[ -n "$ANALYZER" ]]; then
    args+=(--analyzer "$ANALYZER")
fi

"$VENV_PY" "$SCRIPT" "${args[@]}"

echo "Done."
