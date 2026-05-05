#!/bin/bash
set -e

for var in $(env | grep -o '^AFL_[^=]*'); do
    unset "$var"
done

T0=$(date +%s.%N)

# Run a build phase, emit a [TIMING] line, propagate the phase's exit code so
# that under set -e a failure still aborts the script after the line is printed.
run_phase() {
    local phase="$1"; shift
    local s ts_s e ts_e rc=0 elapsed
    s=$(date +%s.%N); ts_s=$(date '+%F %T')
    "$@" || rc=$?
    e=$(date +%s.%N); ts_e=$(date '+%F %T')
    elapsed=$(awk "BEGIN{printf \"%.1f\", $e-$s}")
    printf '[TIMING] phase=%-25s elapsed=%ss    (start=%s, end=%s)\n' \
           "$phase" "$elapsed" "$ts_s" "$ts_e"
    return $rc
}

run_phase prebuild /magma/magma/prebuild.sh

if [ "$FUZZER_NAME" == "afl_uaf_detect" ]; then
    run_phase build_bc_files             ${FUZZER}/build_bc_files.sh
    run_phase static_analysis_instrument ${FUZZER}/static_analysis_instrument.sh
    run_phase afl_instrument             ${FUZZER}/afl_instrument.sh
else
    run_phase instrument ${FUZZER}/instrument.sh
fi

TFINAL=$(date +%s.%N)
TOTAL=$(awk "BEGIN{printf \"%.1f\", $TFINAL-$T0}")
printf '[TIMING] phase=%-25s elapsed=%ss    fuzzer=%s target=%s analyzer=%s\n' \
       'TOTAL' "$TOTAL" "$FUZZER_NAME" "$TARGET_NAME" "${ANALYZER:-none}"
