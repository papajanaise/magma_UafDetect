#!/bin/bash
set -euo pipefail

###############################################################################
# analyse_all.sh
#
# Combined analysis of magma fuzzing results:
#   1) Monitor analysis  -> monitor_analysis.csv   (from canary timestamps)
#   2) Crash replay       -> crash_bug_mapping.csv  (replay each crash input)
#   3) Bug comparison     -> bug_comparison.csv     (per-bug first times by fuzzer)
#
# Usage:
#   ./analyse_all.sh [--parallel N] [--timeout SECS] [--results-dir DIR]
###############################################################################

RESULTS_DIR="/home/users/m/m.thielebein/magma_results"
MAGMA_OUT="/home/users/m/m.thielebein/magma_out"
TIMEOUT=10
PARALLEL=4

DATESTAMP=$(date +%m%d_%H%M)
MONITOR_CSV=""
CRASH_CSV=""
BUG_CSV=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --parallel)    PARALLEL="$2"; shift 2 ;;
        --timeout)     TIMEOUT="$2"; shift 2 ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

MONITOR_CSV="$RESULTS_DIR/monitor_analysis_${DATESTAMP}.csv"
CRASH_CSV="$RESULTS_DIR/crash_bug_mapping_${DATESTAMP}.csv"
BUG_CSV="$RESULTS_DIR/bug_comparison_${DATESTAMP}.csv"

###############################################################################
# Helper functions
###############################################################################

format_time() {
    local secs="$1"
    if [ -z "$secs" ] || [ "$secs" = "-" ]; then
        echo "-"
        return
    fi
    local h=$((secs / 3600))
    local m=$(( (secs % 3600) / 60 ))
    local s=$((secs % 60))
    printf "%d:%02d:%02d" "$h" "$m" "$s"
}

format_time_ms() {
    local ms="$1"
    if [ -z "$ms" ] || [ "$ms" = "-" ]; then
        echo "-"
        return
    fi
    local secs=$((ms / 1000))
    format_time "$secs"
}

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

###############################################################################
# Part 1: Monitor analysis
###############################################################################

echo "========================================================================"
echo "Part 1: Monitor analysis (canary timestamps)"
echo "========================================================================"
echo ""

echo "fuzzer,target,program,run,bug,reached_s,triggered_s,free_reached_s" > "$MONITOR_CSV"

for fuzzer_dir in "$RESULTS_DIR"/*/; do
    [ -d "$fuzzer_dir" ] || continue
    fuzzer=$(basename "$fuzzer_dir")
    [ "${fuzzer:0:1}" = "." ] && continue
    [ "$fuzzer" = "tmp" ] && continue

    for target_dir in "$fuzzer_dir"/*/; do
        [ -d "$target_dir" ] || continue
        target=$(basename "$target_dir")

        for program_dir in "$target_dir"/*/; do
            [ -d "$program_dir" ] || continue
            program=$(basename "$program_dir")

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
            run_id="$max_run"
            run_dir="$program_dir/$run_id/"

            monitor_dir="$run_dir/monitor"
            [ -d "$monitor_dir" ] || continue

            declare -A first_reached first_triggered first_free seen_bugs
            bug_count=0

            timestamps=()
            for f in "$monitor_dir"/*; do
                [ -f "$f" ] || continue
                ts=$(basename "$f")
                case "$ts" in tmp) continue ;; *[!0-9]*) continue ;; esac
                timestamps+=("$ts")
            done

            if [ ${#timestamps[@]} -eq 0 ]; then
                unset first_reached first_triggered first_free seen_bugs
                bug_count=0
                continue
            fi
            IFS=$'\n' sorted_ts=($(printf '%s\n' "${timestamps[@]}" | sort -n)); unset IFS

            for ts in "${sorted_ts[@]}"; do
                fpath="$monitor_dir/$ts"
                [ -s "$fpath" ] || continue

                header="" data=""
                { IFS= read -r header; IFS= read -r data; } < "$fpath"
                [ -z "$header" ] && continue
                [ -z "$data" ] && continue

                IFS=',' read -ra cols <<< "$header"
                IFS=',' read -ra vals <<< "$data"

                for i in "${!cols[@]}"; do
                    col="${cols[$i]}"
                    val="${vals[$i]:-0}"

                    if [[ "$col" == *_R ]]; then
                        bug="${col%_R}"
                        if [ -z "${seen_bugs[$bug]+x}" ]; then seen_bugs["$bug"]=1; bug_count=$((bug_count+1)); fi
                        if [ "$val" -gt 0 ] 2>/dev/null && [ -z "${first_reached[$bug]+x}" ]; then
                            first_reached["$bug"]="$ts"
                        fi
                    elif [[ "$col" == *_T ]]; then
                        bug="${col%_T}"
                        if [ -z "${seen_bugs[$bug]+x}" ]; then seen_bugs["$bug"]=1; bug_count=$((bug_count+1)); fi
                        if [ "$val" -gt 0 ] 2>/dev/null && [ -z "${first_triggered[$bug]+x}" ]; then
                            first_triggered["$bug"]="$ts"
                        fi
                    elif [[ "$col" == *_F ]]; then
                        bug="${col%_F}"
                        if [ -z "${seen_bugs[$bug]+x}" ]; then seen_bugs["$bug"]=1; bug_count=$((bug_count+1)); fi
                        if [ "$val" -gt 0 ] 2>/dev/null && [ -z "${first_free[$bug]+x}" ]; then
                            first_free["$bug"]="$ts"
                        fi
                    fi
                done
            done

            if [ "$bug_count" -eq 0 ]; then
                echo "$fuzzer,$target,$program,$run_id,(no data),-,-,-" >> "$MONITOR_CSV"
            else
                for bug in $(printf '%s\n' "${!seen_bugs[@]}" | sort); do
                    r="${first_reached[$bug]:--}"
                    t="${first_triggered[$bug]:--}"
                    f="${first_free[$bug]:--}"
                    echo "$fuzzer,$target,$program,$run_id,$bug,$r,$t,$f" >> "$MONITOR_CSV"
                done
            fi

            unset first_reached first_triggered first_free seen_bugs
            bug_count=0
        done
    done
done

echo "Monitor CSV written to: $MONITOR_CSV"

# Print formatted table
{
    printf "%-25s %-15s %-35s %-10s %-12s %10s %10s %12s\n" \
        "FUZZER" "TARGET" "PROGRAM" "RUN" "BUG" "REACHED" "TRIGGERED" "FREE_REACHED"
    printf '%0.s-' {1..135}
    echo

    tail -n +2 "$MONITOR_CSV" | sort -t, -k1,1 -k2,2 -k3,3 -k5,5 -k4,4 | while IFS=',' read -r fuzzer target program run bug reached triggered free_reached; do
        r_fmt=$(format_time "$reached")
        t_fmt=$(format_time "$triggered")
        f_fmt=$(format_time "$free_reached")
        printf "%-25s %-15s %-35s %-10s %-12s %10s %10s %12s\n" \
            "$fuzzer" "$target" "$program" "$run" "$bug" "$r_fmt" "$t_fmt" "$f_fmt"
    done
}

echo ""

###############################################################################
# Part 2: Crash replay
###############################################################################

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

###############################################################################
# Part 3: Bug comparison across fuzzers
#
# For each bug detected via crashes, show per-fuzzer:
#   - first crash time (from crash CSV, time_ms field)
#   - first free_reached (from crash CSV, bugs_free_reached field)
#   - first reached / use-reached (from crash CSV, bugs_reached field)
#   - first triggered (from crash CSV, bugs_triggered field)
###############################################################################

echo "========================================================================"
echo "Part 3: Bug comparison across fuzzers"
echo "========================================================================"
echo ""

awk -F',' '
NR == 1 { next }

{
    fuzzer = $1
    target = $2
    time_ms = $7 + 0
    bug_key_prefix = target
}

# Process reached bugs
$9 != "none" {
    split($9, bugs, ";")
    for (i in bugs) {
        bug = bugs[i]
        gsub(/\([0-9]+\)/, "", bug)
        key = bug SUBSEP fuzzer
        if (!(key in first_reached) || time_ms < first_reached[key]) {
            first_reached[key] = time_ms
        }
        all_bugs[bug] = target
        all_fuzzers[fuzzer] = 1
    }
}

# Process triggered bugs
$10 != "none" {
    split($10, bugs, ";")
    for (i in bugs) {
        bug = bugs[i]
        gsub(/\([0-9]+\)/, "", bug)
        key = bug SUBSEP fuzzer
        if (!(key in first_triggered) || time_ms < first_triggered[key]) {
            first_triggered[key] = time_ms
        }
        all_bugs[bug] = target
        all_fuzzers[fuzzer] = 1
    }
}

# Process free_reached bugs
$11 != "none" {
    split($11, bugs, ";")
    for (i in bugs) {
        bug = bugs[i]
        gsub(/\([0-9]+\)/, "", bug)
        key = bug SUBSEP fuzzer
        if (!(key in first_free) || time_ms < first_free[key]) {
            first_free[key] = time_ms
        }
        all_bugs[bug] = target
        all_fuzzers[fuzzer] = 1
    }
}

# Track first crash time per bug per fuzzer (any crash that mentions this bug)
$9 != "none" || $10 != "none" || $11 != "none" {
    # Collect all bug IDs mentioned in this row
    delete row_bugs
    if ($9 != "none") { split($9, _b, ";"); for (i in _b) { gsub(/\([0-9]+\)/, "", _b[i]); row_bugs[_b[i]] = 1 } }
    if ($10 != "none") { split($10, _b, ";"); for (i in _b) { gsub(/\([0-9]+\)/, "", _b[i]); row_bugs[_b[i]] = 1 } }
    if ($11 != "none") { split($11, _b, ";"); for (i in _b) { gsub(/\([0-9]+\)/, "", _b[i]); row_bugs[_b[i]] = 1 } }

    for (bug in row_bugs) {
        key = bug SUBSEP fuzzer
        if (!(key in first_crash) || time_ms < first_crash[key]) {
            first_crash[key] = time_ms
        }
    }
}

function fmt_time(ms) {
    if (ms == "" || ms + 0 == 0 && !(ms in first_crash)) return "-"
    s = int(ms / 1000)
    h = int(s / 3600)
    m = int((s % 3600) / 60)
    sec = s % 60
    return sprintf("%d:%02d:%02d", h, m, sec)
}

function fmt_ms(ms) {
    if (ms == "") return "-"
    return fmt_time(ms)
}

END {
    # Sort fuzzers
    nf = asorti(all_fuzzers, sorted_fuzzers)

    # CSV output
    printf "bug,target"
    for (fi = 1; fi <= nf; fi++) {
        f = sorted_fuzzers[fi]
        printf ",%s_first_crash_s,%s_reached_s,%s_triggered_s,%s_free_reached_s", f, f, f, f
    }
    printf "\n"

    nb = asorti(all_bugs, sorted_bugs)
    for (bi = 1; bi <= nb; bi++) {
        bug = sorted_bugs[bi]
        target = all_bugs[bug]
        printf "%s,%s", bug, target
        for (fi = 1; fi <= nf; fi++) {
            f = sorted_fuzzers[fi]
            key = bug SUBSEP f

            fc = (key in first_crash)    ? first_crash[key]    : ""
            fr = (key in first_reached)  ? first_reached[key]  : ""
            ft = (key in first_triggered)? first_triggered[key] : ""
            ff = (key in first_free)     ? first_free[key]     : ""

            # Output raw milliseconds for CSV
            printf ",%s,%s,%s,%s", \
                (fc != "" ? fc : "-"), \
                (fr != "" ? fr : "-"), \
                (ft != "" ? ft : "-"), \
                (ff != "" ? ff : "-")
        }
        printf "\n"
    }
}
' "$CRASH_CSV" > "$BUG_CSV"

echo "Bug comparison CSV written to: $BUG_CSV"
echo ""

# Print formatted table
awk -F',' '
function fmt(val) {
    if (val == "-" || val == "") return "-"
    ms = val + 0
    s = int(ms / 1000)
    h = int(s / 3600)
    m = int((s % 3600) / 60)
    sec = s % 60
    return sprintf("%d:%02d:%02d", h, m, sec)
}
NR == 1 {
    # Parse header to find fuzzers
    for (i = 3; i <= NF; i += 4) {
        split($i, parts, "_first_crash")
        fuzzers[++nf] = parts[1]
    }

    printf "%-12s %-10s", "BUG", "TARGET"
    for (fi = 1; fi <= nf; fi++) {
        printf " | %-12s %-12s %-12s %-12s", \
            fuzzers[fi] "_crash", fuzzers[fi] "_reach", fuzzers[fi] "_trig", fuzzers[fi] "_free"
    }
    printf "\n"
    for (i = 0; i < 24 + nf * 56; i++) printf "-"
    printf "\n"
    next
}
{
    printf "%-12s %-10s", $1, $2
    col = 3
    for (fi = 1; fi <= nf; fi++) {
        printf " | %-12s %-12s %-12s %-12s", \
            fmt($col), fmt($(col+1)), fmt($(col+2)), fmt($(col+3))
        col += 4
    }
    printf "\n"
}
' "$BUG_CSV"

echo ""
echo "========================================================================"
echo "Output files:"
echo "  Monitor analysis:  $MONITOR_CSV"
echo "  Crash bug mapping: $CRASH_CSV"
echo "  Bug comparison:    $BUG_CSV"
echo "========================================================================"
