#!/bin/bash
set -e

for var in $(env | grep -o '^AFL_[^=]*'); do
    unset "$var"
done

/magma/magma/prebuild.sh

if [ "$FUZZER_NAME" == "afl_uaf_detect" ]; then
    ${FUZZER}/build_bc_files.sh  
    ${FUZZER}/static_analysis_instrument.sh
    ${FUZZER}/afl_instrument.sh
else
    ${FUZZER}/instrument.sh
fi