#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
# - env FUZZARGS: extra arguments to pass to the fuzzer
##
echo "Using local aflplusplus_lto_asan run.sh123"


mkdir -p "$SHARED/findings"

flag_cmplog=(-c "$OUT/cmplog/$PROGRAM")

export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
#export AFL_NO_UI=1
export AFL_DRIVER_DONT_DEFER=1
export ASAN_OPTIONS="use_sigaltstack=0:allocator_may_return_null=1:abort_on_error=1:symbolize=0"

echo "PROGRAM=$PROGRAM"
echo "ARGS=$ARGS"
echo "FUZZARGS=$FUZZARGS"

if [ "$TARGET_NAME" == "libpng" ]; then
    export FUZZARGS="$FUZZARGS -x $FUZZER/repo/dictionaries/png.dict"
fi

if [ "$TARGET_NAME" == "expat" ]; then
    export FUZZARGS="$FUZZARGS -x $FUZZER/repo/dictionaries/xml.dict"
fi

"$FUZZER/repo/afl-fuzz" -m none -i "$TARGET/corpus/$PROGRAM" -o "$SHARED/findings" \
    "${flag_cmplog[@]}" \
    $FUZZARGS -- "$OUT/afl/$PROGRAM" $ARGS 2>&1 | tee $SHARED/log/afl_output.log
