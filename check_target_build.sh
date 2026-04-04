#!/bin/bash

# Find the most recent build log directory
LOG_BASE="/home/users/m/m.thielebein/magma_campaign_logs/build_jobs"
LAST_DIR=$(ls -1d "$LOG_BASE"/*/ 2>/dev/null | sort | tail -1)

if [ -z "$LAST_DIR" ]; then
    echo "No build logs found in $LOG_BASE"
    exit 1
fi

echo "Build run: $(basename "$LAST_DIR")"
echo ""

# Extract job IDs from log filenames and query sacct
declare -A RESULTS
while IFS= read -r file; do
    base=$(basename "$file")
    # Extract job name and ID from filename: build_<fuzzer>_<target>.<jobid>.out
    jobid=$(echo "$base" | grep -oP '\.\K\d+(?=\.out)')
    name=$(echo "$base" | sed "s/\.$jobid\.out//")
    if [ -n "$jobid" ]; then
        state=$(sacct -j "$jobid" --format=State --noheader --parsable2 2>/dev/null | head -1 | tr -d ' ')
        RESULTS["$name"]="$jobid $state"
    fi
done < <(ls "$LAST_DIR"/*.out 2>/dev/null)

# Also check for pending/queued jobs that have no log file yet
PIPELINE_FILE="/home/users/m/m.thielebein/magma_UafDetect/.pipeline_jobs"
if [ -f "$PIPELINE_FILE" ]; then
    while read -r jobid jobtype jobname; do
        key="${jobtype}_$(echo "$jobname" | tr '/' '_')"
        if [ -z "${RESULTS[$key]}" ]; then
            state=$(sacct -j "$jobid" --format=State --noheader --parsable2 2>/dev/null | head -1 | tr -d ' ')
            RESULTS["$key"]="$jobid ${state:-UNKNOWN}"
        fi
    done < "$PIPELINE_FILE"
fi

# Print grouped by status — fuzzer builds first, then target builds
for status in COMPLETED RUNNING PENDING FAILED; do
    fuzzer_entries=()
    target_entries=()
    for name in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
        read -r jobid state <<< "${RESULTS[$name]}"
        if [ "$state" = "$status" ]; then
            # Fuzzer build jobs: build_fuzzer_<name>
            if [[ "$name" == build_fuzzer_* ]]; then
                fuzzer_name="${name#build_fuzzer_}"
                artifact_info=""
                if [ "$status" = "COMPLETED" ]; then
                    afl_cc="/home/users/m/m.thielebein/magma_UafDetect/fuzzers/$fuzzer_name/repo/afl-cc"
                    if [ -x "$afl_cc" ]; then
                        built=$(stat -c '%y' "$afl_cc" 2>/dev/null | cut -d. -f1)
                        artifact_info=" — afl-cc built $built"
                    else
                        artifact_info=" — afl-cc missing!"
                    fi
                fi
                fuzzer_entries+=("  [fuzzer] $fuzzer_name ($jobid)$artifact_info")
                continue
            fi
            # Target build jobs: strip "build_" prefix, show as fuzzer/target
            stripped=$(echo "$name" | sed 's/^build_//')
            # Match known fuzzer prefixes to split correctly
            if [[ "$stripped" == afl_uaf_detect_* ]]; then
                label="afl_uaf_detect/$(echo "$stripped" | sed 's/^afl_uaf_detect_//')"
            elif [[ "$stripped" == aflplusplus_lto_asan_* ]]; then
                label="aflplusplus_lto_asan/$(echo "$stripped" | sed 's/^aflplusplus_lto_asan_//')"
            else
                label="$stripped"
            fi
            # For completed jobs, show timestamp of built artifacts
            artifact_info=""
            if [ "$status" = "COMPLETED" ]; then
                fuzzer=$(echo "$label" | cut -d/ -f1)
                target=$(echo "$label" | cut -d/ -f2)
                if [ "$fuzzer" = "afl_uaf_detect" ]; then
                    artifact_dir="/home/users/m/m.thielebein/magma_out/afl_uaf_detect/$target/free_finder/afl"
                elif [ "$fuzzer" = "aflplusplus_lto_asan" ]; then
                    artifact_dir="/home/users/m/m.thielebein/magma_out/aflplusplus_lto_asan/$target/afl/targets"
                fi
                if [ -d "$artifact_dir" ]; then
                    newest=$(find "$artifact_dir" -maxdepth 1 -type f -executable -printf '%T@ %Tc\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
                    if [ -n "$newest" ]; then
                        artifact_info=" — built $newest"
                    else
                        artifact_info=" — no executables found"
                    fi
                else
                    artifact_info=" — no artifacts dir"
                fi
            fi
            target_entries+=("  $label ($jobid)$artifact_info")
        fi
    done
    if [ ${#fuzzer_entries[@]} -gt 0 ] || [ ${#target_entries[@]} -gt 0 ]; then
        total=$(( ${#fuzzer_entries[@]} + ${#target_entries[@]} ))
        echo "$status ($total):"
        printf '%s\n' "${fuzzer_entries[@]}"
        printf '%s\n' "${target_entries[@]}"
        echo ""
    fi
done
