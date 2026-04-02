#!/bin/bash

LOG_DIR="/home/users/m/m.thielebein/magma_campaign_logs/fuzzing_campaigns/$(date '+%Y%m%d_%H%M%S')"
mkdir -p "$LOG_DIR"

for fuzzer in "afl_uaf_detect" "aflplusplus_lto_asan"; do
    export FUZZER="$fuzzer"
    for target in "expat" "libjpeg-turbo" "libpng" "libxml2" "sqlite3"; do
        export TARGET="$target"

        CONFIGRC="/home/users/m/m.thielebein/magma_UafDetect/targets/${TARGET}/configrc"
        source "$CONFIGRC"

        for PROGRAM in "${PROGRAMS[@]}"; do
            if [ "$FUZZER" == "afl_uaf_detect" ]; then
                for analyzer in "free_finder"; do
                    export ANALYZER="$analyzer"
                done
            else
                export ANALYZER=""
            fi
            sbatch --export=FUZZER="${FUZZER}",TARGET="${TARGET}",PROGRAM="${PROGRAM}",ANALYZER="${ANALYZER}" \
                --job-name="${FUZZER}_${TARGET}_${PROGRAM}" \
                -o "${LOG_DIR}/magma_campaign_${FUZZER}_${TARGET}_${PROGRAM}.%j.out" \
                /home/users/m/m.thielebein/magma_UafDetect/sbatch_fuzzing_campaign.sh
        done
    done
done