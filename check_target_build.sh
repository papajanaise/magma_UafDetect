#!/bin/bash

# Report build status by querying Slurm directly (no log-dir parsing).
# For every fuzzer+target+analyzer combination that is NOT currently being
# built, print the timestamp of the newest built executable.

FUZZERS="${FUZZERS:-aflplusplus_lto_asan afl_uaf_detect}"
TARGETS="${TARGETS:-expat libjpeg-turbo libpng libxml2 sqlite3}"
# Default to showing both analyzer variants; override with ANALYZER env.
ANALYZERS="${ANALYZER:-svf free_finder}"

MAGMA_OUT="/home/users/m/m.thielebein/magma_out"
FUZZER_REPO_BASE="/home/users/m/m.thielebein/magma_UafDetect/fuzzers"
SVF_DRIVER_DIR="/home/users/m/m.thielebein/magma_UafDetect/fuzzers/afl_uaf_detect/repo/SVF_drivers/build"

# Snapshot of the current user's pending/running jobs: "jobid|state|jobname".
ACTIVE_JOBS=$(squeue --me -h -o '%i|%T|%j' 2>/dev/null)

# If a job whose name matches $1 exactly is active, print "JOBID STATE".
job_by_name() {
    local name="$1"
    awk -F'|' -v n="$name" '$3 == n {print $1, $2; exit}' <<< "$ACTIVE_JOBS"
}

# Print "built <human date>" for the newest executable in $1, or a marker.
probe_artifact_dir() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        echo "no artifacts dir ($dir)"
        return
    fi
    local newest
    newest=$(find "$dir" -maxdepth 1 -type f -executable -printf '%T@ %Tc\n' 2>/dev/null \
             | sort -rn | head -1 | cut -d' ' -f2-)
    if [ -n "$newest" ]; then
        echo "built $newest"
    else
        echo "no executables found"
    fi
}

# Print "built <human date>" for a single executable file.
probe_file() {
    local f="$1"
    if [ -x "$f" ]; then
        echo "built $(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)"
    else
        echo "missing ($f)"
    fi
}

# Artifact directory for a given (fuzzer, target, analyzer).
artifact_dir_for() {
    local fuzzer="$1" target="$2" analyzer="$3"
    case "$fuzzer" in
        aflplusplus_lto_asan)
            echo "$MAGMA_OUT/aflplusplus_lto_asan/$target/afl/targets" ;;
        afl_uaf_detect)
            case "$analyzer" in
                free_finder) echo "$MAGMA_OUT/afl_uaf_detect/$target/free_finder/afl" ;;
                svf)         echo "$MAGMA_OUT/afl_uaf_detect/$target/svf/targets" ;;
            esac
            ;;
    esac
}

echo "== Fuzzers =="
for fuzzer in $FUZZERS; do
    active=$(job_by_name "build_fuzzer_${fuzzer}")
    if [ -n "$active" ]; then
        read -r jid state <<< "$active"
        echo "  [building: $state] $fuzzer ($jid)"
    else
        echo "  $fuzzer — $(probe_file "$FUZZER_REPO_BASE/$fuzzer/repo/afl-cc")"
    fi
done
echo ""

echo "== Analyzer (SVF driver) =="
active=$(job_by_name "build_svf_driver")
if [ -n "$active" ]; then
    read -r jid state <<< "$active"
    echo "  [building: $state] svf_driver ($jid)"
else
    echo "  svf-driver         — $(probe_file "$SVF_DRIVER_DIR/svf-driver")"
    echo "  free_finder-driver — $(probe_file "$SVF_DRIVER_DIR/free_finder-driver")"
fi
echo ""

echo "== Target builds =="
for fuzzer in $FUZZERS; do
    if [[ "$fuzzer" == "afl_uaf_detect" ]]; then
        analyzers_iter=($ANALYZERS)
    else
        analyzers_iter=("")
    fi
    for target in $TARGETS; do
        for analyzer in "${analyzers_iter[@]}"; do
            suffix="${analyzer:+_${analyzer}}"
            job_name="build_${fuzzer}_${target}${suffix}"
            label="${fuzzer}/${target}${analyzer:+ [$analyzer]}"
            active=$(job_by_name "$job_name")
            if [ -n "$active" ]; then
                read -r jid state <<< "$active"
                echo "  [building: $state] $label ($jid)"
            else
                dir=$(artifact_dir_for "$fuzzer" "$target" "$analyzer")
                echo "  $label — $(probe_artifact_dir "$dir")"
            fi
        done
    done
done
