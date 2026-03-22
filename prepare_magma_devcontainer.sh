#!/bin/bash
set -e

for var in $(env | grep -o '^AFL_[^=]*'); do
    unset "$var"
done

/magma/magma/prebuild.sh
#${FUZZER}/fetch.sh 
${FUZZER}/build.sh  #only once per fuzzer
/magma/magma/apply_patches.sh #only once per target
${FUZZER}/build_bc_files.sh  #only for afl_uaf_detect!
${FUZZER}/static_analysis_instrument.sh #only for afl_uaf_detect!
${FUZZER}/afl_instrument.sh
/magma/magma/run.sh