#!/bin/bash
set -euo pipefail

###############################################################################
# analyse_comparison.sh
#
# Compare pre-computed campaign results across fuzzers. Reads monitor_analysis.csv
# and crash_replay.csv from each campaign directory (produced by analyse_campaigns.sh),
# merges them, and runs the bug comparison.
#
# Usage:
#   ./analyse_comparison.sh [OPTIONS] --fuzzers SPEC
#
# --fuzzers SPEC
#   Comma-separated list of fuzzers to include. Each entry:
#       <fuzzer>[/<analyzer>][@<offset>]
#   Example:
#     --fuzzers "aflplusplus_lto_asan,afl_uaf_detect/free_finder@1,afl_uaf_detect/svf"
#
# Options:
#   --results-dir DIR    Results directory (default: /home/.../magma_results)
#   --magma-out DIR      Magma output directory (default: /home/.../magma_out)
#   --partition PART     Slurm partition (default: standard)
#   --time HH:MM:SS      Slurm time limit (default: 01:00:00)
#   --local              Run inline instead of submitting slurm jobs
###############################################################################

RESULTS_DIR="/home/users/m/m.thielebein/magma_results"
MAGMA_OUT="/home/users/m/m.thielebein/magma_out"
PARTITION="standard"
TIME_LIMIT="01:00:00"
FUZZER_SPEC=""
LOCAL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fuzzers)     FUZZER_SPEC="$2"; shift 2 ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        --magma-out)   MAGMA_OUT="$2"; shift 2 ;;
        --partition)   PARTITION="$2"; shift 2 ;;
        --time)        TIME_LIMIT="$2"; shift 2 ;;
        --local)       LOCAL=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$FUZZER_SPEC" ]; then
    echo "ERROR: --fuzzers SPEC is required." >&2
    echo "Usage: $0 --fuzzers <fuzzer>[/<analyzer>][@<offset>],..." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOBS_DIR="$SCRIPT_DIR/slurm_jobs"
source "$JOBS_DIR/lib_campaigns.sh"

###############################################################################
# Enumerate campaigns
###############################################################################

DATESTAMP=$(date +%m%d_%H%M)

RUN_DIR="$RESULTS_DIR/comparison_${DATESTAMP}"
LOG_DIR="$RUN_DIR/logs"
CSV_DIR="$RUN_DIR/csv"
mkdir -p "$LOG_DIR" "$CSV_DIR"

CAMPAIGN_LIST="$LOG_DIR/campaigns.list"
: > "$CAMPAIGN_LIST"

parse_fuzzer_spec "$FUZZER_SPEC"
walk_results_dir

echo "Fuzzer filter: $FUZZER_SPEC"
echo "Found $NUM_CAMPAIGNS campaigns."
echo ""

if [ "$NUM_CAMPAIGNS" -eq 0 ]; then
    echo "Nothing to compare."
    exit 0
fi

###############################################################################
# Validate: check all per-campaign CSVs exist
###############################################################################

missing_monitor=()
missing_crash=()

while IFS='|' read -r _f _a _l _t _p _r _d; do
    campaign_dir="$_d$_r"
    if [ ! -f "$campaign_dir/monitor_analysis.csv" ]; then
        missing_monitor+=("$_r")
        echo "  [MISSING] $campaign_dir/monitor_analysis.csv"
    fi
    if [ ! -f "$campaign_dir/crash_replay.csv" ]; then
        missing_crash+=("$_r")
        echo "  [MISSING] $campaign_dir/crash_replay.csv"
    fi
done < "$CAMPAIGN_LIST"

# Combine missing IDs
declare -A missing_ids_map=()
for id in ${missing_monitor[@]+"${missing_monitor[@]}"} ${missing_crash[@]+"${missing_crash[@]}"}; do
    missing_ids_map["$id"]=1
done

if [ "${#missing_ids_map[@]}" -gt 0 ]; then
    missing_csv=$(printf '%s,' "${!missing_ids_map[@]}")
    missing_csv="${missing_csv%,}"
    echo ""
    echo "ERROR: ${#missing_ids_map[@]} campaigns are missing pre-computed results." >&2
    echo "" >&2
    echo "Run analyse_campaigns.sh first:" >&2
    echo "  ./analyse_campaigns.sh --jobs $missing_csv" >&2
    exit 1
fi

echo "All per-campaign results found."
echo ""

###############################################################################
# Output files
###############################################################################

MONITOR_CSV="$CSV_DIR/monitor_analysis.csv"
CRASH_CSV="$CSV_DIR/crash_bug_mapping.csv"
BUG_CSV="$CSV_DIR/bug_comparison.csv"

###############################################################################
# Execute
###############################################################################

if [ "$LOCAL" = "1" ]; then
    echo "Running locally..."
    echo ""

    # Step 1: Collect results
    CAMPAIGN_LIST="$CAMPAIGN_LIST" \
    MONITOR_CSV="$MONITOR_CSV" \
    CRASH_CSV="$CRASH_CSV" \
        bash "$JOBS_DIR/results_collect.sh"

    echo ""

    # Step 2: Bug comparison
    MONITOR_CSV="$MONITOR_CSV" \
    CRASH_CSV="$CRASH_CSV" \
    BUG_CSV="$BUG_CSV" \
        bash "$JOBS_DIR/bug_comparison.sh"
else
    echo "Submitting Slurm jobs..."
    echo "  Partition: $PARTITION"
    echo "  Time limit: $TIME_LIMIT"
    echo ""

    # Job 1: Collect pre-computed results
    JOB_COLLECT=$(sbatch \
        --partition="$PARTITION" \
        --time="00:30:00" \
        --job-name="cmp_collect" \
        --ntasks=1 \
        --cpus-per-task=1 \
        --output="$LOG_DIR/collect_%j.out" \
        --error="$LOG_DIR/collect_%j.err" \
        --export="CAMPAIGN_LIST=$CAMPAIGN_LIST,MONITOR_CSV=$MONITOR_CSV,CRASH_CSV=$CRASH_CSV" \
        --parsable \
        --exclude=node177 \
        "$JOBS_DIR/results_collect.sh")
    echo "Job 1 (Collect results):   $JOB_COLLECT  -> $MONITOR_CSV + $CRASH_CSV"

    # Job 2: Bug comparison (depends on collect)
    JOB_COMPARE=$(sbatch \
        --partition="$PARTITION" \
        --time="$TIME_LIMIT" \
        --job-name="cmp_compare" \
        --ntasks=1 \
        --cpus-per-task=1 \
        --output="$LOG_DIR/compare_%j.out" \
        --error="$LOG_DIR/compare_%j.err" \
        --export="MONITOR_CSV=$MONITOR_CSV,CRASH_CSV=$CRASH_CSV,BUG_CSV=$BUG_CSV" \
        --dependency=afterok:"$JOB_COLLECT" \
        --parsable \
        --exclude=node177 \
        "$JOBS_DIR/bug_comparison.sh")
    echo "Job 2 (Bug comparison):    $JOB_COMPARE  -> $BUG_CSV  (after $JOB_COLLECT)"

    echo ""
    echo "Run directory: $RUN_DIR/"
    echo "  Slurm logs:  $LOG_DIR/"
    echo "  CSV output:  $CSV_DIR/"
    echo ""
    echo "Output files (when complete):"
    echo "  Monitor analysis:  $MONITOR_CSV"
    echo "  Crash bug mapping: $CRASH_CSV"
    echo "  Bug comparison:    $BUG_CSV"
fi
