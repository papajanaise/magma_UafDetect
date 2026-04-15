#!/bin/bash
# campaign_analyse.sh — Per-campaign analysis: monitor + crash replay.
#
# Processes a single fuzzing campaign and writes results directly into the
# campaign directory so they can be reused by later comparisons.
#
# Output files (in <program_dir>/<run_id>/):
#   monitor_analysis.csv  — first reached/triggered/free timestamps per bug
#   crash_replay.csv      — per-crash bug mapping from replay
#
# Expected environment variables (via sbatch --export):
#   CAMPAIGN_LIST  — path to campaign list file
#   MAGMA_OUT      — path to magma output directory (compiled binaries)
#   TIMEOUT        — timeout per crash replay in seconds (default: 10)
#   PARALLEL       — number of parallel replay workers (default: 4)
#   FORCE          — set to 1 to reprocess even if results exist (default: 0)
#
# Uses SLURM_ARRAY_TASK_ID (or TASK_ID for local mode) to pick the campaign.
set -euo pipefail

TASK_ID="${SLURM_ARRAY_TASK_ID:-${TASK_ID:-}}"
if [ -z "$TASK_ID" ]; then
    echo "ERROR: Neither SLURM_ARRAY_TASK_ID nor TASK_ID is set." >&2
    exit 1
fi

TIMEOUT="${TIMEOUT:-10}"
PARALLEL="${PARALLEL:-4}"
FORCE="${FORCE:-0}"

on_error() {
    local rc=$?
    echo "ERROR: campaign_analyse task $TASK_ID failed (exit $rc)." >&2
    exit "$rc"
}
trap on_error ERR

LINE=$(sed -n "${TASK_ID}p" "$CAMPAIGN_LIST")
if [ -z "$LINE" ]; then
    echo "No campaign for task $TASK_ID"
    exit 0
fi

IFS='|' read -r fuzzer analyzer label target program run_id program_dir <<< "$LINE"
CAMPAIGN_DIR="$program_dir$run_id"

echo "========================================================================"
echo "Campaign: $fuzzer${analyzer:+/$analyzer} / $target / $program (run $run_id)"
echo "Dir:      $CAMPAIGN_DIR"
echo "========================================================================"
echo ""

###############################################################################
# Part A: Monitor analysis
###############################################################################

MONITOR_OUT="$CAMPAIGN_DIR/monitor_analysis.csv"
monitor_dir="$CAMPAIGN_DIR/monitor"

if [ -f "$MONITOR_OUT" ] && [ "$FORCE" != "1" ]; then
    echo "[SKIP] monitor_analysis.csv already exists (use FORCE=1 to reprocess)"
elif [ ! -d "$monitor_dir" ]; then
    echo "[SKIP] No monitor directory found at $monitor_dir"
else
    echo "--- Monitor analysis ---"

    FILE_LIST=$(mktemp)
    trap 'rm -f "$FILE_LIST"; on_error' ERR
    trap 'rm -f "$FILE_LIST"' EXIT

    for f in "$monitor_dir"/*; do
        [ -f "$f" ] || continue
        ts=$(basename "$f")
        case "$ts" in tmp) continue ;; *[!0-9]*) continue ;; esac
        echo "$ts"
    done | sort -n > "$FILE_LIST"

    num_files=$(wc -l < "$FILE_LIST")
    if [ "$num_files" -eq 0 ]; then
        echo "No monitor snapshots found."
        echo "fuzzer,analyzer,target,program,run,bug,reached_s,triggered_s,free_reached_s" \
            > "$CAMPAIGN_DIR/.monitor_analysis.csv.tmp"
        mv "$CAMPAIGN_DIR/.monitor_analysis.csv.tmp" "$MONITOR_OUT"
    else
        echo "Processing $num_files monitor snapshots..."

        awk -v dir="$monitor_dir" \
            -v prefix="$fuzzer,$analyzer,$target,$program,$run_id" \
            '
BEGIN {
    file_list = ARGV[1]

    while ((getline ts < file_list) > 0) {
        fpath = dir "/" ts
        header = ""
        data = ""
        if ((getline header < fpath) > 0) {
            getline data < fpath
        }
        close(fpath)

        if (header == "" || data == "") continue

        n = split(header, cols, ",")
        split(data, vals, ",")

        for (i = 1; i <= n; i++) {
            col = cols[i]
            val = vals[i] + 0

            if (col ~ /[^A-Za-z0-9_.\-]/) continue

            if (match(col, /_R$/)) {
                bug = substr(col, 1, length(col) - 2)
                if (bug == "") continue
                seen[bug] = 1
                if (val > 0 && !(bug in first_reached))
                    first_reached[bug] = ts
            } else if (match(col, /_T$/)) {
                bug = substr(col, 1, length(col) - 2)
                if (bug == "") continue
                seen[bug] = 1
                if (val > 0 && !(bug in first_triggered))
                    first_triggered[bug] = ts
            } else if (match(col, /_F$/)) {
                bug = substr(col, 1, length(col) - 2)
                if (bug == "") continue
                seen[bug] = 1
                if (val > 0 && !(bug in first_free))
                    first_free[bug] = ts
            }
        }
    }
    close(file_list)

    # Header
    print "fuzzer,analyzer,target,program,run,bug,reached_s,triggered_s,free_reached_s"

    n_bugs = 0
    for (bug in seen) bugs[++n_bugs] = bug

    if (n_bugs == 0) {
        print prefix ",(no data),-,-,-"
    } else {
        for (i = 2; i <= n_bugs; i++) {
            key = bugs[i]; j = i - 1
            while (j > 0 && bugs[j] > key) { bugs[j+1] = bugs[j]; j-- }
            bugs[j+1] = key
        }
        for (i = 1; i <= n_bugs; i++) {
            bug = bugs[i]
            r = (bug in first_reached)   ? first_reached[bug]   : "-"
            t = (bug in first_triggered) ? first_triggered[bug] : "-"
            f = (bug in first_free)      ? first_free[bug]      : "-"
            print prefix "," bug "," r "," t "," f
        }
    }
}
' "$FILE_LIST" > "$CAMPAIGN_DIR/.monitor_analysis.csv.tmp"

        mv "$CAMPAIGN_DIR/.monitor_analysis.csv.tmp" "$MONITOR_OUT"
        rows=$(( $(wc -l < "$MONITOR_OUT") - 1 ))
        echo "Monitor analysis done. Wrote $rows bug rows to $MONITOR_OUT"
    fi

    rm -f "$FILE_LIST"
    # Reset traps after cleanup
    trap on_error ERR
    trap - EXIT
fi

echo ""

###############################################################################
# Part B: Crash replay
###############################################################################

CRASH_OUT="$CAMPAIGN_DIR/crash_replay.csv"

if [ -f "$CRASH_OUT" ] && [ "$FORCE" != "1" ]; then
    echo "[SKIP] crash_replay.csv already exists (use FORCE=1 to reprocess)"
    echo ""
    echo "Done."
    exit 0
fi

echo "--- Crash replay ---"

# MAGMA_OUT layout:
#   aflplusplus_lto_asan: <fuzzer>/<target>/afl/targets/<program>
#                         <fuzzer>/<target>/monitor
#   afl_uaf_detect:       <fuzzer>/<target>/<analyzer>/afl/<program>
#                         <fuzzer>/<target>/<analyzer>/monitor
get_exe_path() {
    local _fuzzer="$1" _target="$2" _analyzer="$3" _program="$4"
    case "$_fuzzer" in
        aflplusplus_lto_asan)
            echo "$MAGMA_OUT/$_fuzzer/$_target/afl/targets/$_program" ;;
        afl_uaf_detect)
            echo "$MAGMA_OUT/$_fuzzer/$_target/$_analyzer/afl/$_program" ;;
        *) echo "" ;;
    esac
}

get_monitor_path() {
    local _fuzzer="$1" _target="$2" _analyzer="$3"
    case "$_fuzzer" in
        aflplusplus_lto_asan)
            echo "$MAGMA_OUT/$_fuzzer/$_target/monitor" ;;
        afl_uaf_detect)
            echo "$MAGMA_OUT/$_fuzzer/$_target/$_analyzer/monitor" ;;
        *) echo "" ;;
    esac
}

get_findings_subdir() {
    local _fuzzer="$1"
    case "$_fuzzer" in
        aflplusplus_lto_asan) echo "main" ;;
        afl_uaf_detect)       echo "default" ;;
        *)                    echo "main" ;;
    esac
}

replay_one_crash() {
    local _monitor="$1" _target_bin="$2" _crash_file="$3" _out_file="$4"
    ASAN_OPTIONS="use_sigaltstack=0:detect_leaks=0:abort_on_error=1:allocator_may_return_null=1" \
        timeout "$TIMEOUT" \
        "$_monitor" --dump human --fetch watch "$_target_bin" "$_crash_file" \
        > "$_out_file" 2>/dev/null
    return $?
}

parse_canary_output() {
    local _file="$1"
    local reached="" triggered="" free_reached=""
    while IFS=' ' read -r bugid _ r_count _ t_count _ f_count; do
        [[ -z "$bugid" ]] && continue
        case "$bugid" in *[!A-Za-z0-9_.-]*) continue ;; esac
        : "${r_count:=0}" "${t_count:=0}" "${f_count:=0}"
        if [ "$r_count" -gt 0 ] 2>/dev/null; then
            reached="${reached:+$reached;}$bugid($r_count)"
        fi
        if [ "$t_count" -gt 0 ] 2>/dev/null; then
            triggered="${triggered:+$triggered;}$bugid($t_count)"
        fi
        if [ "$f_count" -gt 0 ] 2>/dev/null; then
            free_reached="${free_reached:+$free_reached;}$bugid($f_count)"
        fi
    done < "$_file"
    echo "${reached:-none},${triggered:-none},${free_reached:-none}"
}

parse_crash_filename() {
    local _fname="$1"
    local crash_id="" sig="" time_ms=""
    IFS=',' read -ra parts <<< "$_fname"
    for part in "${parts[@]}"; do
        IFS=':' read -r key val <<< "$part"
        case "$key" in
            id)   crash_id="$val" ;;
            sig)  sig="$val" ;;
            time) time_ms="$val" ;;
        esac
    done
    echo "$crash_id,$sig,$time_ms"
}

is_supported_fuzzer() {
    case "$1" in
        aflplusplus_lto_asan|afl_uaf_detect) return 0 ;;
        *) return 1 ;;
    esac
}

# Check if this fuzzer is supported for replay
if ! is_supported_fuzzer "$fuzzer"; then
    echo "[SKIP] Unsupported fuzzer for replay: $fuzzer"
    echo "fuzzer,analyzer,target,program,run_id,crash_id,signal,time_ms,replay_exit_code,bugs_reached,bugs_triggered,bugs_free_reached" \
        > "$CAMPAIGN_DIR/.crash_replay.csv.tmp"
    mv "$CAMPAIGN_DIR/.crash_replay.csv.tmp" "$CRASH_OUT"
    echo ""
    echo "Done."
    exit 0
fi

monitor_bin=$(get_monitor_path "$fuzzer" "$target" "$analyzer")
if [[ ! -x "$monitor_bin" ]]; then
    echo "[SKIP] No monitor binary at $monitor_bin"
    echo "fuzzer,analyzer,target,program,run_id,crash_id,signal,time_ms,replay_exit_code,bugs_reached,bugs_triggered,bugs_free_reached" \
        > "$CAMPAIGN_DIR/.crash_replay.csv.tmp"
    mv "$CAMPAIGN_DIR/.crash_replay.csv.tmp" "$CRASH_OUT"
    echo ""
    echo "Done."
    exit 0
fi

target_bin=$(get_exe_path "$fuzzer" "$target" "$analyzer" "$program")
if [[ ! -x "$target_bin" ]]; then
    echo "[SKIP] No executable at $target_bin"
    echo "fuzzer,analyzer,target,program,run_id,crash_id,signal,time_ms,replay_exit_code,bugs_reached,bugs_triggered,bugs_free_reached" \
        > "$CAMPAIGN_DIR/.crash_replay.csv.tmp"
    mv "$CAMPAIGN_DIR/.crash_replay.csv.tmp" "$CRASH_OUT"
    echo ""
    echo "Done."
    exit 0
fi

subdir=$(get_findings_subdir "$fuzzer")
crash_dir="$CAMPAIGN_DIR/findings/$subdir/crashes"

crash_files=()
if [ -d "$crash_dir" ]; then
    while IFS= read -r -d '' f; do
        crash_files+=("$f")
    done < <(find "$crash_dir" -maxdepth 1 -name 'id:*' -print0 | sort -z)
fi

TMPDIR_REPLAY=$(mktemp -d /tmp/replay_crashes.XXXXXX)
trap 'rm -rf "$TMPDIR_REPLAY"' EXIT

echo "fuzzer,analyzer,target,program,run_id,crash_id,signal,time_ms,replay_exit_code,bugs_reached,bugs_triggered,bugs_free_reached" \
    > "$CAMPAIGN_DIR/.crash_replay.csv.tmp"

if [ ${#crash_files[@]} -eq 0 ]; then
    echo "No crash files found in $crash_dir"
else
    echo "Replaying ${#crash_files[@]} crashes (parallel=$PARALLEL, timeout=${TIMEOUT}s)..."

    active_jobs=0
    for crash_file in "${crash_files[@]}"; do
        crash_fname=$(basename "$crash_file")
        result_file="$TMPDIR_REPLAY/$crash_fname.result"
        exit_file="$TMPDIR_REPLAY/$crash_fname.exit"

        (
            replay_one_crash "$monitor_bin" "$target_bin" "$crash_file" "$result_file"
            echo $? > "$exit_file"
        ) &

        active_jobs=$((active_jobs + 1))
        if [[ $active_jobs -ge $PARALLEL ]]; then
            wait -n 2>/dev/null || true
            active_jobs=$((active_jobs - 1))
        fi
    done

    wait

    processed=0
    for crash_file in "${crash_files[@]}"; do
        crash_fname=$(basename "$crash_file")
        crash_meta=$(parse_crash_filename "$crash_fname")
        result_file="$TMPDIR_REPLAY/$crash_fname.result"
        exit_file="$TMPDIR_REPLAY/$crash_fname.exit"

        exit_code=0
        if [[ -f "$exit_file" ]]; then
            exit_code=$(cat "$exit_file")
        fi

        if [[ -f "$result_file" && -s "$result_file" ]]; then
            canary_data=$(parse_canary_output "$result_file")
        else
            canary_data="none,none,none"
        fi

        echo "$fuzzer,$analyzer,$target,$program,$run_id,$crash_meta,$exit_code,$canary_data" \
            >> "$CAMPAIGN_DIR/.crash_replay.csv.tmp"

        processed=$((processed + 1))
    done

    echo "Replayed $processed crashes."
fi

mv "$CAMPAIGN_DIR/.crash_replay.csv.tmp" "$CRASH_OUT"
rm -rf "$TMPDIR_REPLAY"

rows=$(( $(wc -l < "$CRASH_OUT") - 1 ))
echo "Crash replay done. Wrote $rows rows to $CRASH_OUT"
echo ""
echo "Done."
