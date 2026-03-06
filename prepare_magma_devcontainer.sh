#!/bin/bash
set -e

for var in $(env | grep -o '^AFL_[^=]*'); do
    unset "$var"
done

/magma/magma/prebuild.sh
#${FUZZER}/fetch.sh 
${FUZZER}/build.sh  #only once per fuzzer
/magma/magma/apply_patches.sh
${FUZZER}/build_bc_file.sh
${FUZZER}/svf_instrumentation.sh
${FUZZER}/instrument.sh
/magma/magma/run.sh