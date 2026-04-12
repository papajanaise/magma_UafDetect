#!/bin/bash
# crash_replay.sh — Replay crash inputs through monitor binary
#
# Expected environment variables (via sbatch --export):
#   RESULTS_DIR           — magma results directory
#   MAGMA_OUT             — magma output directory (compiled binaries)
#   CRASH_CSV             — output path for crash bug mapping CSV
#   TIMEOUT               — timeout per crash replay (seconds)
#   PARALLEL              — number of parallel replay workers
#   CRASH_CAMPAIGN_LIST   — file listing campaigns to replay, one per line:
#                               fuzzer|analyzer|label|target|program|run_id|program_dir
#                           (built by analyse_all.sh, honours --fuzzers filter)
#                           analyzer is used for MAGMA_OUT path lookup, label
#                           is the identifier written to the CSV so that
#                           multiple run offsets get distinct columns.
set -euo pipefail

# MAGMA_OUT layout (note: analyzer is a child of TARGET here, opposite to
# RESULTS_DIR where analyzer is a child of FUZZER):
#   aflplusplus_lto_asan: <fuzzer>/<target>/afl/targets/<program>
#                         <fuzzer>/<target>/monitor
#   afl_uaf_detect:       <fuzzer>/<target>/<analyzer>/afl/<program>
#                         <fuzzer>/<target>/<analyzer>/monitor
get_exe_path() {
    local fuzzer="$1" target="$2" analyzer="$3" program="$4"
    case "$fuzzer" in
        aflplusplus_lto_asan)
            echo "$MAGMA_OUT/$fuzzer/$target/afl/targets/$program" ;;
        afl_uaf_detect)
            echo "$MAGMA_OUT/$fuzzer/$target/$analyzer/afl/$program" ;;
        *) echo "" ;;
    esac
}

get_monitor_path() {
    local fuzzer="$1" target="$2" analyzer="$3"
    case "$fuzzer" in
        aflplusplus_lto_asan)
            echo "$MAGMA_OUT/$fuzzer/$target/monitor" ;;
        afl_uaf_detect)
            echo "$MAGMA_OUT/$fuzzer/$target/$analyzer/monitor" ;;
        *) echo "" ;;
    esac
}

get_findings_subdir() {
    local fuzzer="$1"
    case "$fuzzer" in
        aflplusplus_lto_asan) echo "main" ;;
        afl_uaf_detect)       echo "default" ;;
        *)                    echo "main" ;;
    esac
}

replay_one_crash() {
    local monitor="$1" target_bin="$2" crash_file="$3" out_file="$4"
    ASAN_OPTIONS="use_sigaltstack=0:detect_leaks=0:abort_on_error=1:allocator_may_return_null=1" \
        timeout "$TIMEOUT" \
        "$monitor" --dump human --fetch watch "$target_bin" "$crash_file" \
        > "$out_file" 2>/dev/null
    return $?
}

parse_canary_output() {
    local file="$1"
    local reached="" triggered="" free_reached=""
    while IFS=' ' read -r bugid _ r_count _ t_count _ f_count; do
        [[ -z "$bugid" ]] && continue
        # Drop corrupted bug IDs (see monitor_campaign.sh for details).
        case "$bugid" in *[!A-Za-z0-9_.-]*) continue ;; esac
        # Use single-bracket `[` (the `test` builtin) instead of `[[ ]]`:
        # `[[ -gt ]]` runs bash arithmetic, which under `set -u` tries to
        # dereference any non-numeric token as a variable name and dies on
        # malformed monitor lines (e.g. "SQLUAF04: unbound variable"). The
        # `2>/dev/null` swallows test's "integer expression expected" message.
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
    done < "$file"
    echo "${reached:-none},${triggered:-none},${free_reached:-none}"
}

parse_crash_filename() {
    local fname="$1"
    local crash_id="" sig="" time_ms=""
    IFS=',' read -ra parts <<< "$fname"
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

echo "========================================================================"
echo "Part 2: Crash replay (replaying crash inputs through monitor)"
echo "========================================================================"
echo ""

TMPDIR_REPLAY=$(mktemp -d /tmp/replay_crashes.XXXXXX)
trap 'rm -rf "$TMPDIR_REPLAY"' EXIT

echo "fuzzer,analyzer,target,program,run_id,crash_id,signal,time_ms,replay_exit_code,bugs_reached,bugs_triggered,bugs_free_reached" \
    > "$CRASH_CSV"

total_crashes=0
processed=0
skipped=0

if [[ -z "${CRASH_CAMPAIGN_LIST:-}" || ! -f "$CRASH_CAMPAIGN_LIST" ]]; then
    echo "ERROR: CRASH_CAMPAIGN_LIST not set or missing: ${CRASH_CAMPAIGN_LIST:-}" >&2
    exit 1
fi

# Only process fuzzers that have a monitor/binary layout we know about.
is_supported_fuzzer() {
    case "$1" in
        aflplusplus_lto_asan|afl_uaf_detect) return 0 ;;
        *) return 1 ;;
    esac
}

# Count crashes
while IFS='|' read -r fuzzer analyzer label target program run_id program_dir; do
    [[ -z "$fuzzer" ]] && continue
    is_supported_fuzzer "$fuzzer" || continue
    subdir=$(get_findings_subdir "$fuzzer")
    crash_dir="$program_dir$run_id/findings/$subdir/crashes"
    [[ -d "$crash_dir" ]] || continue
    n=$(ls -1 "$crash_dir" 2>/dev/null | grep -c '^id:' || true)
    total_crashes=$((total_crashes + n))
done < "$CRASH_CAMPAIGN_LIST"

echo "Total crashes to replay: $total_crashes"
echo "Parallel workers: $PARALLEL, Timeout per crash: ${TIMEOUT}s"
echo ""

# Replay crashes
while IFS='|' read -r fuzzer analyzer label target program run_id program_dir; do
    [[ -z "$fuzzer" ]] && continue
    if ! is_supported_fuzzer "$fuzzer"; then
        echo "  [SKIP] Unsupported fuzzer for replay: $fuzzer"
        continue
    fi

    monitor=$(get_monitor_path "$fuzzer" "$target" "$analyzer")
    if [[ ! -x "$monitor" ]]; then
        echo "  [SKIP] No monitor binary for $fuzzer${analyzer:+/$analyzer}/$target ($monitor)"
        continue
    fi

    target_bin=$(get_exe_path "$fuzzer" "$target" "$analyzer" "$program")
    if [[ ! -x "$target_bin" ]]; then
        echo "  [SKIP] No executable for $fuzzer${analyzer:+/$analyzer}/$target/$program at $target_bin"
        skipped=$((skipped + 1))
        continue
    fi

    subdir=$(get_findings_subdir "$fuzzer")
    crash_dir="$program_dir$run_id/findings/$subdir/crashes"
    [[ -d "$crash_dir" ]] || continue

    crash_files=()
    while IFS= read -r -d '' f; do
        crash_files+=("$f")
    done < <(find "$crash_dir" -maxdepth 1 -name 'id:*' -print0 | sort -z)

    [[ ${#crash_files[@]} -eq 0 ]] && continue

    echo "  [$fuzzer${label:+/$label}] $target/$program (run $run_id): ${#crash_files[@]} crashes"

    batch_results_dir="$TMPDIR_REPLAY/$fuzzer/${label:-_}/$target/$program/$run_id"
    mkdir -p "$batch_results_dir"

    active_jobs=0
    for crash_file in "${crash_files[@]}"; do
        crash_fname=$(basename "$crash_file")
        result_file="$batch_results_dir/$crash_fname.result"
        exit_file="$batch_results_dir/$crash_fname.exit"

        (
            replay_one_crash "$monitor" "$target_bin" "$crash_file" "$result_file"
            echo $? > "$exit_file"
        ) &

        active_jobs=$((active_jobs + 1))
        if [[ $active_jobs -ge $PARALLEL ]]; then
            wait -n 2>/dev/null || true
            active_jobs=$((active_jobs - 1))
        fi
    done

    wait

    for crash_file in "${crash_files[@]}"; do
        crash_fname=$(basename "$crash_file")
        crash_meta=$(parse_crash_filename "$crash_fname")
        result_file="$batch_results_dir/$crash_fname.result"
        exit_file="$batch_results_dir/$crash_fname.exit"

        exit_code=0
        if [[ -f "$exit_file" ]]; then
            exit_code=$(cat "$exit_file")
        fi

        if [[ -f "$result_file" && -s "$result_file" ]]; then
            canary_data=$(parse_canary_output "$result_file")
        else
            canary_data="none,none,none"
        fi

        echo "$fuzzer,$label,$target,$program,$run_id,$crash_meta,$exit_code,$canary_data" \
            >> "$CRASH_CSV"

        processed=$((processed + 1))
    done

    rm -rf "$batch_results_dir"
done < "$CRASH_CAMPAIGN_LIST"

echo ""
echo "Crash replay done. Processed $processed crashes, skipped $skipped programs."
echo "Crash CSV written to: $CRASH_CSV"
echo ""
echo "Part 2 (Crash replay) complete."
