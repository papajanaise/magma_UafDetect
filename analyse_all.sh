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
#                    [--fuzzers SPEC]
#
# --fuzzers SPEC
#   Comma-separated list of fuzzers to include. Each entry:
#       <fuzzer>[/<analyzer>][@<offset>]
#   <analyzer> is only meaningful for afl_uaf_detect. <offset> selects which
#   run to use: 0 = latest, 1 = one before, 2 = two before, ... (default 0).
#   Omitting --fuzzers analyses every fuzzer at its latest run (offset 0).
#   Example:
#     --fuzzers "aflplusplus_lto_asan,afl_uaf_detect/free_finder@1,afl_uaf_detect/svf"
###############################################################################

RESULTS_DIR="/home/users/m/m.thielebein/magma_results"
MAGMA_OUT="/home/users/m/m.thielebein/magma_out"
TIMEOUT=10
PARALLEL=4
PARTITION="standard"
TIME_LIMIT="04:00:00"
FUZZER_SPEC=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --parallel)    PARALLEL="$2"; shift 2 ;;
        --timeout)     TIMEOUT="$2"; shift 2 ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        --partition)   PARTITION="$2"; shift 2 ;;
        --time)        TIME_LIMIT="$2"; shift 2 ;;
        --fuzzers)     FUZZER_SPEC="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Parse --fuzzers SPEC into three parallel arrays.
declare -a FILTER_FUZZERS=() FILTER_ANALYZERS=() FILTER_OFFSETS=()
if [ -n "$FUZZER_SPEC" ]; then
    IFS=',' read -ra _spec_items <<< "$FUZZER_SPEC"
    for _item in "${_spec_items[@]}"; do
        [ -z "$_item" ] && continue
        _offset=0
        if [[ "$_item" == *"@"* ]]; then
            _offset="${_item##*@}"
            _item="${_item%@*}"
        fi
        case "$_offset" in *[!0-9]*|"") echo "Invalid offset in --fuzzers entry: $_item@$_offset"; exit 1 ;; esac
        if [[ "$_item" == *"/"* ]]; then
            _f="${_item%%/*}"
            _a="${_item#*/}"
        else
            _f="$_item"
            _a=""
        fi
        FILTER_FUZZERS+=("$_f")
        FILTER_ANALYZERS+=("$_a")
        FILTER_OFFSETS+=("$_offset")
    done
fi

# Echoes every matching offset (one per line) for the given (fuzzer, analyzer),
# so that the caller can emit a campaign per offset when the user requested the
# same (fuzzer, analyzer) with multiple offsets. Returns non-zero if this pair
# should be skipped entirely. With no --fuzzers, the default is offset 0.
# A filter entry with empty analyzer matches any analyzer under that fuzzer.
filter_offsets() {
    local _fuzzer="$1" _analyzer="$2" _i _found=0
    if [ "${#FILTER_FUZZERS[@]}" -eq 0 ]; then
        echo 0
        return 0
    fi
    for _i in "${!FILTER_FUZZERS[@]}"; do
        if [ "${FILTER_FUZZERS[$_i]}" = "$_fuzzer" ]; then
            if [ -z "${FILTER_ANALYZERS[$_i]}" ] || [ "${FILTER_ANALYZERS[$_i]}" = "$_analyzer" ]; then
                echo "${FILTER_OFFSETS[$_i]}"
                _found=1
            fi
        fi
    done
    [ "$_found" -eq 1 ] && return 0
    return 1
}

# Build the analyzer-like label that identifies a campaign in the CSVs.
# When the same (fuzzer, analyzer) is requested with multiple offsets we need
# each variant to land in its own column in bug_comparison.sh, so we suffix the
# offset. Otherwise we keep the plain analyzer name.
# Args: analyzer offset num_offsets_for_this_pair
make_label() {
    local _analyzer="$1" _offset="$2" _dup="$3"
    if [ "$_dup" -gt 1 ]; then
        if [ -n "$_analyzer" ]; then
            echo "${_analyzer}@${_offset}"
        else
            echo "@${_offset}"
        fi
    else
        echo "$_analyzer"
    fi
}

# Pick the Nth-from-latest numeric run subdir under $1 (0 = latest).
# Echoes the chosen run id, or nothing if no such run exists.
nth_run() {
    local _program_dir="$1" _offset="$2"
    local _runs=() _d _id
    for _d in "$_program_dir"*/; do
        [ -d "$_d" ] || continue
        _id=$(basename "$_d")
        case "$_id" in *[!0-9]*) continue ;; esac
        _runs+=("$_id")
    done
    [ "${#_runs[@]}" -eq 0 ] && return 0
    printf '%s\n' "${_runs[@]}" | sort -n -r | sed -n "$((_offset + 1))p"
}

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
CRASH_CAMPAIGN_LIST="$LOG_DIR/crash_campaigns.list"
: > "$CAMPAIGN_LIST"
: > "$CRASH_CAMPAIGN_LIST"
NUM_CAMPAIGNS=0
NUM_CRASH_CAMPAIGNS=0

# Layout reminder (see sbatch_fuzzing_campaign.sh):
#   afl_uaf_detect:        <fuzzer>/<analyzer>/<target>/<program>/<run>/monitor
#   other fuzzers:         <fuzzer>/<target>/<program>/<run>/monitor
# Known analyzer subdirs for the prefixed layout:
KNOWN_ANALYZERS=(free_finder svf)
is_analyzer_name() {
    local n="$1"
    local a
    for a in "${KNOWN_ANALYZERS[@]}"; do
        [ "$n" = "$a" ] && return 0
    done
    return 1
}

# Walk a single <target>/ directory and emit one campaign line per program,
# picking the run at the given offset (0 = latest, 1 = one before, ...).
# Always appends to CRASH_CAMPAIGN_LIST; only appends to CAMPAIGN_LIST when a
# monitor directory exists for the selected run.
#
# The `label` field is what downstream CSVs use in place of analyzer so that
# multiple run offsets for the same (fuzzer, analyzer) get their own column in
# bug_comparison.sh. `analyzer` remains the raw name used for path lookups.
# Args: fuzzer analyzer label target target_dir offset
emit_target_campaigns() {
    local _fuzzer="$1" _analyzer="$2" _label="$3" _target="$4" _target_dir="$5" _offset="$6"
    local _program_dir _program _chosen_run _monitor_dir
    for _program_dir in "$_target_dir"*/; do
        [ -d "$_program_dir" ] || continue
        _program=$(basename "$_program_dir")
        _chosen_run=$(nth_run "$_program_dir" "$_offset")
        if [ -z "$_chosen_run" ]; then
            echo "  [SKIP] $_fuzzer${_analyzer:+/$_analyzer}@$_offset $_target/$_program: no run at that offset"
            continue
        fi
        echo "$_fuzzer|$_analyzer|$_label|$_target|$_program|$_chosen_run|$_program_dir" >> "$CRASH_CAMPAIGN_LIST"
        NUM_CRASH_CAMPAIGNS=$((NUM_CRASH_CAMPAIGNS + 1))
        _monitor_dir="$_program_dir$_chosen_run/monitor"
        [ -d "$_monitor_dir" ] || continue
        echo "$_fuzzer|$_analyzer|$_label|$_target|$_program|$_chosen_run|$_monitor_dir" >> "$CAMPAIGN_LIST"
        NUM_CAMPAIGNS=$((NUM_CAMPAIGNS + 1))
    done
}

for fuzzer_dir in "$RESULTS_DIR"/*/; do
    [ -d "$fuzzer_dir" ] || continue
    fuzzer=$(basename "$fuzzer_dir")
    [ "${fuzzer:0:1}" = "." ] && continue
    [ "$fuzzer" = "tmp" ] && continue
    [[ "$fuzzer" = analysis_* ]] && continue

    for sub_dir in "$fuzzer_dir"/*/; do
        [ -d "$sub_dir" ] || continue
        sub=$(basename "$sub_dir")
        if [ "$fuzzer" = "afl_uaf_detect" ] && is_analyzer_name "$sub"; then
            # Analyzer-prefixed layout: descend one extra level.
            if ! offsets_raw=$(filter_offsets "$fuzzer" "$sub"); then
                continue
            fi
            readarray -t offsets_arr <<< "$offsets_raw"
            for target_dir in "$sub_dir"/*/; do
                [ -d "$target_dir" ] || continue
                target=$(basename "$target_dir")
                for off in "${offsets_arr[@]}"; do
                    label=$(make_label "$sub" "$off" "${#offsets_arr[@]}")
                    emit_target_campaigns "$fuzzer" "$sub" "$label" "$target" "$target_dir" "$off"
                done
            done
        elif [ "$fuzzer" = "afl_uaf_detect" ]; then
            # Legacy layout (no analyzer prefix) for a fuzzer that requires
            # an analyzer subdir in MAGMA_OUT. Attribute to whichever
            # analyzer's build artifacts exist for this target, defaulting
            # to free_finder if neither is present.
            legacy_analyzer="free_finder"
            for a in "${KNOWN_ANALYZERS[@]}"; do
                if [ -d "$MAGMA_OUT/$fuzzer/$sub/$a" ]; then
                    legacy_analyzer="$a"
                    break
                fi
            done
            if ! offsets_raw=$(filter_offsets "$fuzzer" "$legacy_analyzer"); then
                continue
            fi
            readarray -t offsets_arr <<< "$offsets_raw"
            for off in "${offsets_arr[@]}"; do
                label=$(make_label "$legacy_analyzer" "$off" "${#offsets_arr[@]}")
                emit_target_campaigns "$fuzzer" "$legacy_analyzer" "$label" "$sub" "$sub_dir" "$off"
            done
        else
            # Legacy / no-analyzer layout for fuzzers without an analyzer dim.
            if ! offsets_raw=$(filter_offsets "$fuzzer" ""); then
                continue
            fi
            readarray -t offsets_arr <<< "$offsets_raw"
            for off in "${offsets_arr[@]}"; do
                label=$(make_label "" "$off" "${#offsets_arr[@]}")
                emit_target_campaigns "$fuzzer" "" "$label" "$sub" "$sub_dir" "$off"
            done
        fi
    done
done

echo "Found $NUM_CAMPAIGNS monitor campaigns and $NUM_CRASH_CAMPAIGNS crash campaigns to analyse."
if [ -n "$FUZZER_SPEC" ]; then
    echo "  Fuzzer filter: $FUZZER_SPEC"
fi

###############################################################################
# Submit jobs
###############################################################################

echo "Submitting Slurm jobs..."
echo "  Partition: $PARTITION"
echo "  Time limit: $TIME_LIMIT"
echo ""

EXPORT_COMMON="ALL"

# Job 1a: Monitor analysis array (one task per campaign)
# Submitted in held state so tasks cannot start before we record the
# downstream job IDs they need in order to cancel on failure.
if [ "$NUM_CAMPAIGNS" -gt 0 ]; then
    JOB1_ARRAY_ID=$(sbatch \
        --partition="$PARTITION" \
        --time="02:00:00" \
        --job-name="analyse_mon" \
        --ntasks=1 \
        --cpus-per-task=1 \
        --array="1-${NUM_CAMPAIGNS}" \
        --hold \
        --output="$LOG_DIR/monitor_%A_%a.out" \
        --error="$LOG_DIR/monitor_%A_%a.err" \
        --export="CAMPAIGN_LIST=$CAMPAIGN_LIST,LOG_DIR=$LOG_DIR" \
        --parsable \
        --exclude=gpu[001-066] \
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
    echo "fuzzer,analyzer,target,program,run,bug,reached_s,triggered_s,free_reached_s" > "$MONITOR_CSV"
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
    --export="RESULTS_DIR=$RESULTS_DIR,MAGMA_OUT=$MAGMA_OUT,CRASH_CSV=$CRASH_CSV,TIMEOUT=$TIMEOUT,PARALLEL=$PARALLEL,CRASH_CAMPAIGN_LIST=$CRASH_CAMPAIGN_LIST" \
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

# Record downstream job IDs so that monitor_campaign tasks can cancel them
# on failure (otherwise they hang forever in DependencyNeverSatisfied state).
DOWNSTREAM_JOBS_FILE="$LOG_DIR/downstream_jobs.txt"
: > "$DOWNSTREAM_JOBS_FILE"
[ -n "${JOB1_MERGE_ID:-}" ] && echo "$JOB1_MERGE_ID" >> "$DOWNSTREAM_JOBS_FILE"
echo "$JOB3_ID" >> "$DOWNSTREAM_JOBS_FILE"

# Release the held monitor array now that the downstream file is in place.
if [ "$NUM_CAMPAIGNS" -gt 0 ]; then
    scontrol release "$JOB1_ARRAY_ID"
fi

echo ""
echo "Run directory: $RUN_DIR/"
echo "  Slurm logs:  $LOG_DIR/"
echo "  CSV output:  $CSV_DIR/"
echo ""
echo "Output files (when complete):"
echo "  Monitor analysis:  $MONITOR_CSV"
echo "  Crash bug mapping: $CRASH_CSV"
echo "  Bug comparison:    $BUG_CSV"
