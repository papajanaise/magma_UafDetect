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
echo "Using afl_uaf_detect run.sh"

mkdir -p "$SHARED/findings"

export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
export AFL_MAP_SIZE=2097152
export AFL_USE_UAF_DETECT=1
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:malloc_context_size=0:symbolize=0:allocator_may_return_null=1:use_sigaltstack=0"

# Derive TARGET_NAME from $TARGET path
TARGET_NAME="$(basename "$TARGET")"

echo "PROGRAM=$PROGRAM"
echo "ARGS=$ARGS"
echo "FUZZARGS=$FUZZARGS"
echo "TARGET_NAME=$TARGET_NAME"

# Persistent mode detection: libFuzzer-style harnesses have a weak main
# symbol from aflpp_driver — must feed via stdin ("-")
if nm "$OUT/afl/$PROGRAM" 2>/dev/null | grep -qE '^[0-9a-f]+\s+W\s+main$'; then
    echo "Persistent mode detected (weak main), setting ARGS=-"
    ARGS="-"
fi

# Target-specific dictionaries
if [ "$TARGET_NAME" == "libpng" ]; then
    export FUZZARGS="$FUZZARGS -x $FUZZER/repo/dictionaries/png.dict"
fi

if [ "$TARGET_NAME" == "expat" ] || [ "$TARGET_NAME" == "libxml2" ]; then
    export FUZZARGS="$FUZZARGS -x $FUZZER/repo/dictionaries/xml.dict"
fi

if [ "$TARGET_NAME" == "libjpeg-turbo" ]; then
    export FUZZARGS="$FUZZARGS -x $FUZZER/repo/dictionaries/jpeg.dict"
fi

if [ "$TARGET_NAME" == "sqlite3" ]; then
    export FUZZARGS="$FUZZARGS -x $FUZZER/repo/dictionaries/sql.dict"
fi

# CmpLog — verify the path exists before enabling
flag_cmplog=()
cmplog_binary=""
for candidate in \
    "$OUT/cmplog/$PROGRAM" \
    "$OUT/cmplog/targets/$PROGRAM"; do
    if [ -f "$candidate" ]; then
        cmplog_binary="$candidate"
        break
    fi
done

if [ -n "$cmplog_binary" ]; then
    flag_cmplog=(-c "$cmplog_binary")
    echo "CmpLog enabled: $cmplog_binary"
else
    echo "WARNING: No CmpLog binary found, comparison solving disabled"
fi

# Verify corpus
corpus_dir="$TARGET/corpus/$PROGRAM"
if [ ! -d "$corpus_dir" ] || [ -z "$(ls -A "$corpus_dir" 2>/dev/null)" ]; then
    echo "WARNING: Corpus dir empty or missing: $corpus_dir"
fi

"$FUZZER/repo/afl-fuzz" -m none -i "$TARGET/corpus/$PROGRAM" -o "$SHARED/findings" \
    "${flag_cmplog[@]}" $FUZZARGS -- "$OUT/afl/$PROGRAM" $ARGS 2>&1
