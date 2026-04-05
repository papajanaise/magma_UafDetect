#!/bin/bash
# crash_replay.sh — Replay crash inputs through monitor binary
#
# Expected environment variables (via sbatch --export):
#   RESULTS_DIR  — magma results directory
#   MAGMA_OUT    — magma output directory (compiled binaries)
#   CRASH_CSV    — output path for crash bug mapping CSV
#   TIMEOUT      — timeout per crash replay (seconds)
#   PARALLEL     — number of parallel replay workers
set -euo pipefail

get_exe_path() {
    local fuzzer="$1" target="$2" program="$3"
    case "$fuzzer" in
        aflplusplus_lto_asan)
            echo "$MAGMA_OUT/$fuzzer/$target/afl/targets/$program" ;;
        afl_uaf_detect)
            echo "$MAGMA_OUT/$fuzzer/$target/free_finder/afl/$program" ;;
        *) echo "" ;;
    esac
}

get_monitor_path() {
    local fuzzer="$1" target="$2"
    case "$fuzzer" in
        aflplusplus_lto_asan)
            echo "$MAGMA_OUT/$fuzzer/$target/monitor" ;;
        afl_uaf_detect)
            echo "$MAGMA_OUT/$fuzzer/$target/free_finder/monitor" ;;
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

get_last_run() {
    local program_path="$1"
    ls -1 "$program_path" 2>/dev/null | grep '^[0-9]*$' | sort -n | tail -1
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
        if [[ "$r_count" -gt 0 ]]; then
            reached="${reached:+$reached;}$bugid($r_count)"
        fi
        if [[ "$t_count" -gt 0 ]]; then
            triggered="${triggered:+$triggered;}$bugid($t_count)"
        fi
        if [[ "$f_count" -gt 0 ]]; then
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

echo "fuzzer,target,program,run_id,crash_id,signal,time_ms,replay_exit_code,bugs_reached,bugs_triggered,bugs_free_reached" \
    > "$CRASH_CSV"

total_crashes=0
processed=0
skipped=0

# Count crashes
for fuzzer_dir in "$RESULTS_DIR"/*/; do
    fuzzer=$(basename "$fuzzer_dir")
    [[ -d "$fuzzer_dir" ]] || continue
    [[ "$fuzzer" =~ ^(aflplusplus_lto_asan|afl_uaf_detect)$ ]] || continue

    for target_dir in "$fuzzer_dir"/*/; do
        target=$(basename "$target_dir")
        [[ -d "$target_dir" ]] || continue
        for program_dir in "$target_dir"/*/; do
            program=$(basename "$program_dir")
            [[ -d "$program_dir" ]] || continue
            last_run=$(get_last_run "$program_dir")
            [[ -z "$last_run" ]] && continue
            subdir=$(get_findings_subdir "$fuzzer")
            crash_dir="$program_dir/$last_run/findings/$subdir/crashes"
            [[ -d "$crash_dir" ]] || continue
            n=$(ls -1 "$crash_dir" 2>/dev/null | grep -c '^id:' || true)
            total_crashes=$((total_crashes + n))
        done
    done
done

echo "Total crashes to replay: $total_crashes"
echo "Parallel workers: $PARALLEL, Timeout per crash: ${TIMEOUT}s"
echo ""

# Replay crashes
for fuzzer_dir in "$RESULTS_DIR"/*/; do
    fuzzer=$(basename "$fuzzer_dir")
    [[ -d "$fuzzer_dir" ]] || continue
    [[ "$fuzzer" =~ ^(aflplusplus_lto_asan|afl_uaf_detect)$ ]] || continue

    for target_dir in "$fuzzer_dir"/*/; do
        target=$(basename "$target_dir")
        [[ -d "$target_dir" ]] || continue

        monitor=$(get_monitor_path "$fuzzer" "$target")
        if [[ ! -x "$monitor" ]]; then
            echo "  [SKIP] No monitor binary for $fuzzer/$target"
            continue
        fi

        for program_dir in "$target_dir"/*/; do
            program=$(basename "$program_dir")
            [[ -d "$program_dir" ]] || continue

            last_run=$(get_last_run "$program_dir")
            [[ -z "$last_run" ]] && continue

            target_bin=$(get_exe_path "$fuzzer" "$target" "$program")
            if [[ ! -x "$target_bin" ]]; then
                echo "  [SKIP] No executable for $fuzzer/$target/$program at $target_bin"
                skipped=$((skipped + 1))
                continue
            fi

            subdir=$(get_findings_subdir "$fuzzer")
            crash_dir="$program_dir/$last_run/findings/$subdir/crashes"
            [[ -d "$crash_dir" ]] || continue

            crash_files=()
            while IFS= read -r -d '' f; do
                crash_files+=("$f")
            done < <(find "$crash_dir" -maxdepth 1 -name 'id:*' -print0 | sort -z)

            [[ ${#crash_files[@]} -eq 0 ]] && continue

            echo "  [$fuzzer] $target/$program (run $last_run): ${#crash_files[@]} crashes"

            batch_results_dir="$TMPDIR_REPLAY/$fuzzer/$target/$program"
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

                echo "$fuzzer,$target,$program,$last_run,$crash_meta,$exit_code,$canary_data" \
                    >> "$CRASH_CSV"

                processed=$((processed + 1))
            done

            rm -rf "$batch_results_dir"
        done
    done
done

echo ""
echo "Crash replay done. Processed $processed crashes, skipped $skipped programs."
echo "Crash CSV written to: $CRASH_CSV"
echo ""
echo "Part 2 (Crash replay) complete."
