#!/bin/bash
#
# Show status of all expected fuzzing campaigns.
# Compares elapsed time against expected timeout to detect early failures.
#
# Usage:
#   ./check_fuzzing_jobs.sh                  # uses default timeout of 86400s (24h)
#   ./check_fuzzing_jobs.sh --timeout 7200   # check against 2h timeout
#

FUZZERS=("afl_uaf_detect" "aflplusplus_lto_asan")
TARGETS=("expat" "libjpeg-turbo" "libpng" "libxml2" "sqlite3")
ANALYZERS=("free_finder" "svf")  # analyzers appended as suffix for afl_uaf_detect jobs
TIMEOUT=86400  # default: 24 hours (must match what was passed to start_fuzzing_target.sh)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *)         echo "Usage: $0 [--timeout seconds]"; exit 1 ;;
    esac
done

# Convert HH:MM:SS or D-HH:MM:SS to total seconds
elapsed_to_seconds() {
    local e="$1"
    local days=0 h m s
    if [[ "$e" == *-* ]]; then
        days="${e%%-*}"
        e="${e#*-}"
    fi
    IFS=: read -r h m s <<< "$e"
    echo $(( days*86400 + 10#$h*3600 + 10#$m*60 + 10#$s ))
}

# Build list of expected job names
declare -a EXPECTED=()
for f in "${FUZZERS[@]}"; do
    for t in "${TARGETS[@]}"; do
        source /home/users/m/m.thielebein/magma_UafDetect/targets/"$t"/configrc
        for p in "${PROGRAMS[@]}"; do
            if [[ "$f" == "afl_uaf_detect" ]]; then
                for a in "${ANALYZERS[@]}"; do
                    EXPECTED+=("${f}_${t}_${p}_${a}")
                done
            else
                EXPECTED+=("${f}_${t}_${p}")
            fi
        done
    done
done

# Collect most recent sacct entry per job name (last line wins)
declare -A JOB_STATE JOB_ELAPSED JOB_END JOB_ID
while IFS='|' read -r jobid name state elapsed end; do
    # Trim whitespace
    jobid="${jobid#"${jobid%%[![:space:]]*}"}"
    jobid="${jobid%"${jobid##*[![:space:]]}"}"
    name="${name#"${name%%[![:space:]]*}"}"
    name="${name%"${name##*[![:space:]]}"}"
    state="${state#"${state%%[![:space:]]*}"}"
    state="${state%"${state##*[![:space:]]}"}"
    elapsed="${elapsed#"${elapsed%%[![:space:]]*}"}"
    elapsed="${elapsed%"${elapsed##*[![:space:]]}"}"
    end="${end#"${end%%[![:space:]]*}"}"
    end="${end%"${end##*[![:space:]]}"}"
    JOB_ID["$name"]="$jobid"
    JOB_STATE["$name"]="$state"
    JOB_ELAPSED["$name"]="$elapsed"
    JOB_END["$name"]="$end"
done < <(sacct -u "$USER" --format=JobID,JobName%80,State%12,Elapsed,End -n -X --parsable2 2>/dev/null)

# Allow 10% tolerance for timeout comparison
MIN_OK_SECONDS=$(( TIMEOUT * 90 / 100 ))

# Format seconds to human-readable
fmt_duration() {
    local s="$1"
    printf "%dh%02dm%02ds" $((s/3600)) $(((s%3600)/60)) $((s%60))
}

# Categorize and display
running=()
finished=()
failed=()
missing=()

for job in "${EXPECTED[@]}"; do
    state="${JOB_STATE[$job]:-}"
    elapsed="${JOB_ELAPSED[$job]:-}"
    end="${JOB_END[$job]:-}"

    if [[ -z "$state" ]]; then
        missing+=("$job")
        continue
    fi

    if [[ "$state" == "RUNNING" || "$state" == "PENDING" ]]; then
        running+=("$(printf "  %-70s  %-9s  elapsed %s" "$job" "$state" "$elapsed")")
        continue
    fi

    # Job is no longer running — check elapsed vs expected timeout
    elapsed_sec=$(elapsed_to_seconds "$elapsed")

    if [[ "$state" != "COMPLETED" ]]; then
        # SLURM itself reported failure
        failed+=("$(printf "  %-70s  %-9s  ended %s  ran %s (expected %s)" "$job" "$state" "$end" "$(fmt_duration $elapsed_sec)" "$(fmt_duration $TIMEOUT)")")
    elif [[ $elapsed_sec -ge $MIN_OK_SECONDS ]]; then
        finished+=("$(printf "  %-70s  %-9s  ended %s  ran %s" "$job" "OK" "$end" "$(fmt_duration $elapsed_sec)")")
    else
        failed+=("$(printf "  %-70s  %-9s  ended %s  ran %s (expected %s)" "$job" "EARLY" "$end" "$(fmt_duration $elapsed_sec)" "$(fmt_duration $TIMEOUT)")")
    fi
done

total=${#EXPECTED[@]}
echo "=== Fuzzing Campaign Status (${total} expected, timeout=$(fmt_duration $TIMEOUT)) ==="
echo ""

if [[ ${#running[@]} -gt 0 ]]; then
    echo "RUNNING (${#running[@]}):"
    printf '%s\n' "${running[@]}"
    echo ""
fi

if [[ ${#finished[@]} -gt 0 ]]; then
    echo "FINISHED (${#finished[@]}):"
    printf '%s\n' "${finished[@]}"
    echo ""
fi

if [[ ${#failed[@]} -gt 0 ]]; then
    echo "FAILED (${#failed[@]}):"
    printf '%s\n' "${failed[@]}"
    echo ""
fi

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "MISSING — no job found (${#missing[@]}):"
    for job in "${missing[@]}"; do
        echo "  $job"
    done
    echo ""
fi

echo "Summary: ${#running[@]} running, ${#finished[@]} finished, ${#failed[@]} failed, ${#missing[@]} missing"
