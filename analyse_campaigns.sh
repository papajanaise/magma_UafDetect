#!/bin/bash
set -euo pipefail

###############################################################################
# analyse_campaigns.sh
#
# Per-campaign analysis: process monitor files and replay crashes for each
# fuzzing campaign. Results are stored directly in the campaign directory
# so they can be reused by analyse_comparison.sh without re-processing.
#
# Usage:
#   ./analyse_campaigns.sh [OPTIONS] { --fuzzer <name> [--analyzer <name>] [--offset N]
#                                     | --jobs <id1,id2,...> }
#
# Modes (mutually exclusive):
#   --fuzzer <name>      Find campaigns by fuzzer name in the results directory
#   --analyzer <name>    Analyzer within fuzzer (only for afl_uaf_detect)
#   --offset N           Starting run offset: 0 = latest, 1 = one before, ... (default: 0)
#   --num-runs N         Number of consecutive runs to analyse, starting at --offset
#                        (default: 1). E.g. --num-runs 3 -> offsets 0,1,2.
#   --jobs <ids>         Find campaigns by slurm job ID (comma-separated)
#
# Options:
#   --results-dir DIR    Results directory (default: /home/.../magma_results)
#   --magma-out DIR      Magma output directory (default: /home/.../magma_out)
#   --force              Reprocess even if results already exist
#   --local              Run inline instead of submitting slurm jobs
#   --partition PART     Slurm partition (default: standard)
#   --time HH:MM:SS      Per-task time limit (default: 06:00:00)
#   --timeout SECS       Crash replay timeout (default: 10)
#   --parallel N         Crash replay parallel workers (default: 4)
#   --dry-run            Show campaigns without processing
###############################################################################

RESULTS_DIR="/home/users/m/m.thielebein/magma_results"
MAGMA_OUT="/home/users/m/m.thielebein/magma_out"
FORCE=0
LOCAL=0
DRY_RUN=0
PARTITION="standard"
TIME_LIMIT="06:00:00"
TIMEOUT=10
PARALLEL=4
MAX_CONCURRENT=8

FUZZER_NAME=""
ANALYZER_NAME=""
OFFSET=0
NUM_RUNS=1
JOB_IDS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fuzzer)      FUZZER_NAME="$2"; shift 2 ;;
        --analyzer)    ANALYZER_NAME="$2"; shift 2 ;;
        --offset)      OFFSET="$2"; shift 2 ;;
        --num-runs)    NUM_RUNS="$2"; shift 2 ;;
        --jobs)        JOB_IDS="$2"; shift 2 ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        --magma-out)   MAGMA_OUT="$2"; shift 2 ;;
        --force)       FORCE=1; shift ;;
        --local)       LOCAL=1; shift ;;
        --partition)   PARTITION="$2"; shift 2 ;;
        --time)        TIME_LIMIT="$2"; shift 2 ;;
        --timeout)     TIMEOUT="$2"; shift 2 ;;
        --parallel)    PARALLEL="$2"; shift 2 ;;
        --dry-run)     DRY_RUN=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Validate mode
if [ -n "$FUZZER_NAME" ] && [ -n "$JOB_IDS" ]; then
    echo "ERROR: --fuzzer and --jobs are mutually exclusive." >&2
    exit 1
fi
if [ -z "$FUZZER_NAME" ] && [ -z "$JOB_IDS" ]; then
    echo "ERROR: Must specify either --fuzzer or --jobs." >&2
    echo "Usage: $0 { --fuzzer <name> [--analyzer <name>] [--offset N] | --jobs <id1,id2,...> }" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/slurm_jobs/lib_campaigns.sh"

###############################################################################
# Enumerate campaigns
###############################################################################

DATESTAMP=$(date +%m%d_%H%M)
CAMPAIGN_LIST=$(mktemp /tmp/campaigns.XXXXXX)
trap 'rm -f "$CAMPAIGN_LIST"' EXIT

if [ -n "$FUZZER_NAME" ]; then
    case "$NUM_RUNS" in *[!0-9]*|"") echo "ERROR: --num-runs must be a positive integer (got: $NUM_RUNS)" >&2; exit 1 ;; esac
    if [ "$NUM_RUNS" -lt 1 ]; then
        echo "ERROR: --num-runs must be >= 1 (got: $NUM_RUNS)" >&2
        exit 1
    fi
    # Build a SPEC string from --fuzzer/--analyzer/--offset/--num-runs.
    # When NUM_RUNS > 1, expand to multiple comma-separated entries with offsets
    # OFFSET, OFFSET+1, ..., OFFSET+NUM_RUNS-1.
    base="$FUZZER_NAME"
    [ -n "$ANALYZER_NAME" ] && base="$base/$ANALYZER_NAME"
    spec=""
    for i in $(seq 0 $((NUM_RUNS - 1))); do
        off=$((OFFSET + i))
        entry="${base}@${off}"
        spec="${spec:+$spec,}$entry"
    done
    parse_fuzzer_spec "$spec"
    walk_results_dir
    echo "Fuzzer filter: $spec"
else
    enumerate_by_job_ids "$JOB_IDS"
    echo "Job ID filter: $JOB_IDS"
fi

echo "Found $NUM_CAMPAIGNS campaigns."
echo ""

if [ "$NUM_CAMPAIGNS" -eq 0 ]; then
    echo "Nothing to do."
    exit 0
fi

###############################################################################
# Filter already-processed campaigns (unless --force)
###############################################################################

if [ "$FORCE" != "1" ]; then
    FILTERED_LIST=$(mktemp /tmp/campaigns_filtered.XXXXXX)
    trap 'rm -f "$CAMPAIGN_LIST" "$FILTERED_LIST"' EXIT
    skipped=0
    while IFS='|' read -r _f _a _l _t _p _r _d; do
        campaign_dir="$_d$_r"
        if [ -f "$campaign_dir/monitor_analysis.csv" ] && [ -f "$campaign_dir/crash_replay.csv" ]; then
            echo "  [SKIP] $_f${_a:+/$_a} $_t/$_p run $_r (already analysed)"
            skipped=$((skipped + 1))
        else
            echo "$_f|$_a|$_l|$_t|$_p|$_r|$_d" >> "$FILTERED_LIST"
        fi
    done < "$CAMPAIGN_LIST"

    if [ "$skipped" -gt 0 ]; then
        echo ""
        echo "Skipped $skipped already-analysed campaigns. Use --force to reprocess."
    fi

    mv "$FILTERED_LIST" "$CAMPAIGN_LIST"
    NUM_CAMPAIGNS=$(wc -l < "$CAMPAIGN_LIST")

    if [ "$NUM_CAMPAIGNS" -eq 0 ]; then
        echo "All campaigns already analysed. Nothing to do."
        exit 0
    fi

    echo "$NUM_CAMPAIGNS campaigns to process."
    echo ""
fi

###############################################################################
# Dry-run: just show the list
###############################################################################

if [ "$DRY_RUN" = "1" ]; then
    echo "Campaigns to analyse (dry-run):"
    while IFS='|' read -r _f _a _l _t _p _r _d; do
        echo "  $_f${_a:+/$_a} $_t/$_p run $_r  ($_d$_r)"
    done < "$CAMPAIGN_LIST"
    exit 0
fi

###############################################################################
# Execute
###############################################################################

if [ "$LOCAL" = "1" ]; then
    echo "Running locally..."
    echo ""
    task=0
    while IFS= read -r line; do
        task=$((task + 1))
        export TASK_ID="$task"
        export CAMPAIGN_LIST
        export MAGMA_OUT
        export TIMEOUT
        export PARALLEL
        export FORCE
        # Write a single-line campaign list for this task
        TASK_CAMPAIGN_LIST=$(mktemp /tmp/task_campaign.XXXXXX)
        echo "$line" > "$TASK_CAMPAIGN_LIST"
        TASK_ID=1 CAMPAIGN_LIST="$TASK_CAMPAIGN_LIST" \
            bash "$SCRIPT_DIR/slurm_jobs/campaign_analyse.sh"
        rm -f "$TASK_CAMPAIGN_LIST"
        echo ""
    done < "$CAMPAIGN_LIST"
    echo "All campaigns processed locally."
else
    LOG_DIR="$RESULTS_DIR/.campaign_analysis_logs_${DATESTAMP}"
    mkdir -p "$LOG_DIR"

    # Copy campaign list to a stable location for slurm
    STABLE_LIST="$LOG_DIR/campaigns.list"
    cp "$CAMPAIGN_LIST" "$STABLE_LIST"

    # Self-maintaining bad-node exclude list. campaign_analyse.sh appends to
    # this file when its threshold-error guard fires (all replayed crashes
    # returned no canary firings — broken container/node). Picked up on the
    # next run so we don't keep losing tasks to known-bad nodes.
    BAD_NODES_FILE="${MAGMA_BAD_NODES_FILE:-$HOME/.magma_bad_nodes}"
    EXTRA_EXCLUDE=""
    if [ -s "$BAD_NODES_FILE" ]; then
        EXTRA_EXCLUDE=$(sort -u "$BAD_NODES_FILE" | grep -v '^$' | paste -sd,)
        if [ -n "$EXTRA_EXCLUDE" ]; then
            echo "  Bad nodes:  $EXTRA_EXCLUDE  (from $BAD_NODES_FILE)"
        fi
    fi
    EXCLUDE_SPEC="gpu[001-066],node177${EXTRA_EXCLUDE:+,$EXTRA_EXCLUDE}"

    JOB_ID=$(sbatch \
        --partition="$PARTITION" \
        --time="$TIME_LIMIT" \
        --job-name="camp_analyse" \
        --ntasks=1 \
        --cpus-per-task="$PARALLEL" \
        --array="1-${NUM_CAMPAIGNS}%${MAX_CONCURRENT}" \
        --output="$LOG_DIR/campaign_%A_%a.out" \
        --error="$LOG_DIR/campaign_%A_%a.err" \
        --export="CAMPAIGN_LIST=$STABLE_LIST,MAGMA_OUT=$MAGMA_OUT,TIMEOUT=$TIMEOUT,PARALLEL=$PARALLEL,FORCE=$FORCE,MAGMA_BAD_NODES_FILE=$BAD_NODES_FILE" \
        --parsable \
        --exclude="$EXCLUDE_SPEC" \
        "$SCRIPT_DIR/slurm_jobs/campaign_analyse.sh")

    echo "Submitted slurm array job: $JOB_ID  [$NUM_CAMPAIGNS tasks]"
    echo "  Partition:  $PARTITION"
    echo "  Time limit: $TIME_LIMIT"
    echo "  Logs:       $LOG_DIR/"
fi
