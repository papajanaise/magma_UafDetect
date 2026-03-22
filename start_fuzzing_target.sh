#!/bin/bash

export FUZZER="aflplusplus_lto_asan"
export TARGET="expat"
export ANALYZER="free_finder"    #free_finder or svf Analysis

CONFIGRC="/home/users/m/m.thielebein/magma_UafDetect/targets/${TARGET}/configrc"
source "$CONFIGRC"

for PROGRAM in "${PROGRAMS[@]}"; do
    export PROGRAM=$PROGRAM #xml_parsebuffer_fuzzer_UTF-16LE
    sbatch /home/users/m/m.thielebein/magma_UafDetect/run_fuzzing_campaign.sh
done
