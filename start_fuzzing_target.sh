#!/bin/bash
#
# Usage:
#   ./start_fuzzing_target.sh                          # all fuzzers x all targets
#   ./start_fuzzing_target.sh -f afl_uaf_detect        # one fuzzer, all targets
#   ./start_fuzzing_target.sh -t expat -t libpng       # all fuzzers, two targets
#   ./start_fuzzing_target.sh -f aflplusplus_lto_asan -t sqlite3   # one combo
#   ./start_fuzzing_target.sh --timeout 86400           # override campaign timeout (seconds)
#

ALL_FUZZERS=("afl_uaf_detect")
ALL_TARGETS=("expat" "libjpeg-turbo" "libpng" "libxml2" "sqlite3")
ALL_ANALYZERS=("free_finder")

FUZZERS=()
TARGETS=()
TIMEOUT=86400  # default: 24 hours (in seconds)

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--fuzzer)   FUZZERS+=("$2"); shift 2 ;;
        -t|--target)   TARGETS+=("$2"); shift 2 ;;
        --timeout)     TIMEOUT="$2"; shift 2 ;;
        *)             echo "Unknown option: $1"; echo "Usage: $0 [-f fuzzer]... [-t target]... [--timeout seconds]"; exit 1 ;;
    esac
done

# Default to all if none specified
if [[ ${#FUZZERS[@]} -eq 0 ]]; then
    FUZZERS=("${ALL_FUZZERS[@]}")
fi
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=("${ALL_TARGETS[@]}")
fi

LOG_DIR="/home/users/m/m.thielebein/magma_campaign_logs/fuzzing_campaigns/$(date '+%Y%m%d_%H%M%S')"
mkdir -p "$LOG_DIR"

for fuzzer in "${FUZZERS[@]}"; do
    export FUZZER="$fuzzer"
    for target in "${TARGETS[@]}"; do
        export TARGET="$target"

        CONFIGRC="/home/users/m/m.thielebein/magma_UafDetect/targets/${TARGET}/configrc"
        source "$CONFIGRC"

        for PROGRAM in "${PROGRAMS[@]}"; do
            if [ "$FUZZER" == "afl_uaf_detect" ]; then
                ANALYZERS=("${ALL_ANALYZERS[@]}")
            else
                ANALYZERS=("")
            fi
            for ANALYZER in "${ANALYZERS[@]}"; do
                export ANALYZER
                JOB_SUFFIX="${ANALYZER:+_${ANALYZER}}"
                sbatch --export=FUZZER="${FUZZER}",TARGET="${TARGET}",PROGRAM="${PROGRAM}",ANALYZER="${ANALYZER}",TIMEOUT="${TIMEOUT}" \
                    --job-name="${FUZZER}_${TARGET}_${PROGRAM}${JOB_SUFFIX}" \
                    -o "${LOG_DIR}/magma_campaign_${FUZZER}_${TARGET}_${PROGRAM}${JOB_SUFFIX}.%j.out" \
                    /home/users/m/m.thielebein/magma_UafDetect/sbatch_fuzzing_campaign.sh
            done
        done
    done
done
