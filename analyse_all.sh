#!/bin/bash
set -euo pipefail

###############################################################################
# analyse_all.sh
#
# Combined analysis of magma fuzzing results, submitted as Slurm jobs:
#   Job 1a) Monitor analysis (array)  -> one task per campaign
#   Job 1b) Monitor merge             -> monitor_analysis.csv
#   Job 2)  Crash replay              -> crash_bug_mapping.csv
#   Job 3)  Bug comparison            -> bug_comparison.csv
#
# Jobs 1a & 2 run in parallel; 1b runs after 1a; 3 runs after 1b + 2.
#
# Usage:
#   ./analyse_all.sh [--parallel N] [--timeout SECS] [--results-dir DIR]
#                    [--partition PART] [--time HH:MM:SS]
###############################################################################

RESULTS_DIR="/home/users/m/m.thielebein/magma_results"
MAGMA_OUT="/home/users/m/m.thielebein/magma_out"
TIMEOUT=10
PARALLEL=4
PARTITION="standard"
TIME_LIMIT="04:00:00"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --parallel)    PARALLEL="$2"; shift 2 ;;
        --timeout)     TIMEOUT="$2"; shift 2 ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        --partition)   PARTITION="$2"; shift 2 ;;
        --time)        TIME_LIMIT="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

DATESTAMP=$(date +%m%d_%H%M)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOBS_DIR="$SCRIPT_DIR/slurm_jobs"

RUN_DIR="$RESULTS_DIR/analysis_${DATESTAMP}"
LOG_DIR="$RUN_DIR/logs"
CSV_DIR="$RUN_DIR/csv"
mkdir -p "$LOG_DIR" "$CSV_DIR"

MONITOR_CSV="$CSV_DIR/monitor_analysis.csv"
CRASH_CSV="$CSV_DIR/crash_bug_mapping.csv"
BUG_CSV="$CSV_DIR/bug_comparison.csv"

###############################################################################
# Enumerate monitor campaigns
###############################################################################

CAMPAIGN_LIST="$LOG_DIR/campaigns.list"
: > "$CAMPAIGN_LIST"
NUM_CAMPAIGNS=0

for fuzzer_dir in "$RESULTS_DIR"/*/; do
    [ -d "$fuzzer_dir" ] || continue
    fuzzer=$(basename "$fuzzer_dir")
    [ "${fuzzer:0:1}" = "." ] && continue
    [ "$fuzzer" = "tmp" ] && continue
    [[ "$fuzzer" = analysis_* ]] && continue

    for target_dir in "$fuzzer_dir"/*/; do
        [ -d "$target_dir" ] || continue
        target=$(basename "$target_dir")

        for program_dir in "$target_dir"/*/; do
            [ -d "$program_dir" ] || continue
            program=$(basename "$program_dir")

            # Find latest run
            max_run=""
            for _d in "$program_dir"/*/; do
                [ -d "$_d" ] || continue
                _id=$(basename "$_d")
                case "$_id" in *[!0-9]*) continue ;; esac
                if [ -z "$max_run" ] || [ "$_id" -gt "$max_run" ]; then
                    max_run="$_id"
                fi
            done
            [ -z "$max_run" ] && continue

            monitor_dir="$program_dir/$max_run/monitor"
            [ -d "$monitor_dir" ] || continue

            echo "$fuzzer|$target|$program|$max_run|$monitor_dir" >> "$CAMPAIGN_LIST"
            NUM_CAMPAIGNS=$((NUM_CAMPAIGNS + 1))
        done
    done
done

echo "Found $NUM_CAMPAIGNS monitor campaigns to analyse."

###############################################################################
# Submit jobs
###############################################################################

echo "Submitting Slurm jobs..."
echo "  Partition: $PARTITION"
echo "  Time limit: $TIME_LIMIT"
echo ""

EXPORT_COMMON="ALL"

# Job 1a: Monitor analysis array (one task per campaign)
if [ "$NUM_CAMPAIGNS" -gt 0 ]; then
    JOB1_ARRAY_ID=$(sbatch \
        --partition="$PARTITION" \
        --time="02:00:00" \
        --job-name="analyse_mon" \
        --ntasks=1 \
        --cpus-per-task=1 \
        --array="1-${NUM_CAMPAIGNS}" \
        --output="$LOG_DIR/monitor_%A_%a.out" \
        --error="$LOG_DIR/monitor_%A_%a.err" \
        --export="CAMPAIGN_LIST=$CAMPAIGN_LIST,LOG_DIR=$LOG_DIR" \
        --parsable \
        "$JOBS_DIR/monitor_campaign.sh")
    echo "Job 1a (Monitor array):    $JOB1_ARRAY_ID  [$NUM_CAMPAIGNS tasks]"

    # Job 1b: Merge partials (depends on all array tasks)
    JOB1_MERGE_ID=$(sbatch \
        --partition="$PARTITION" \
        --time="00:30:00" \
        --job-name="analyse_merge" \
        --ntasks=1 \
        --cpus-per-task=1 \
        --output="$LOG_DIR/monitor_merge_%j.out" \
        --error="$LOG_DIR/monitor_merge_%j.err" \
        --export="LOG_DIR=$LOG_DIR,MONITOR_CSV=$MONITOR_CSV" \
        --dependency=afterok:"$JOB1_ARRAY_ID" \
        --parsable \
        "$JOBS_DIR/monitor_merge.sh")
    echo "Job 1b (Monitor merge):    $JOB1_MERGE_ID  -> $MONITOR_CSV  (after array $JOB1_ARRAY_ID)"
else
    echo "No monitor campaigns found — skipping Part 1."
    echo "fuzzer,target,program,run,bug,reached_s,triggered_s,free_reached_s" > "$MONITOR_CSV"
    JOB1_MERGE_ID=""
fi

# Job 2: Crash replay (independent)
JOB2_ID=$(sbatch \
    --partition="$PARTITION" \
    --time="$TIME_LIMIT" \
    --job-name="analyse_replay" \
    --ntasks=1 \
    --cpus-per-task="$PARALLEL" \
    --output="$LOG_DIR/replay_%j.out" \
    --error="$LOG_DIR/replay_%j.err" \
    --export="RESULTS_DIR=$RESULTS_DIR,MAGMA_OUT=$MAGMA_OUT,CRASH_CSV=$CRASH_CSV,TIMEOUT=$TIMEOUT,PARALLEL=$PARALLEL" \
    --parsable \
    "$JOBS_DIR/crash_replay.sh")
echo "Job 2 (Crash replay):      $JOB2_ID  -> $CRASH_CSV"

# Job 3: Bug comparison (depends on merge + replay)
DEP_LIST="$JOB2_ID"
if [ -n "${JOB1_MERGE_ID:-}" ]; then
    DEP_LIST="${JOB1_MERGE_ID}:${JOB2_ID}"
fi
JOB3_ID=$(sbatch \
    --partition="$PARTITION" \
    --time="01:00:00" \
    --job-name="analyse_compare" \
    --ntasks=1 \
    --cpus-per-task=1 \
    --output="$LOG_DIR/compare_%j.out" \
    --error="$LOG_DIR/compare_%j.err" \
    --export="MONITOR_CSV=$MONITOR_CSV,CRASH_CSV=$CRASH_CSV,BUG_CSV=$BUG_CSV" \
    --dependency=afterok:"$DEP_LIST" \
    --parsable \
    "$JOBS_DIR/bug_comparison.sh")
echo "Job 3 (Bug comparison):    $JOB3_ID  -> $BUG_CSV  (after jobs $DEP_LIST)"

echo ""
echo "Run directory: $RUN_DIR/"
echo "  Slurm logs:  $LOG_DIR/"
echo "  CSV output:  $CSV_DIR/"
echo ""
echo "Output files (when complete):"
echo "  Monitor analysis:  $MONITOR_CSV"
echo "  Crash bug mapping: $CRASH_CSV"
echo "  Bug comparison:    $BUG_CSV"
