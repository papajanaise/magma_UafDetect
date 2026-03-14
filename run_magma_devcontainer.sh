#!/bin/bash
set -e

export FUZZER_NAME=afl_uaf_detect
export TARGET_NAME=expat

export SINGULARITYENV_FUZZER_NAME=$FUZZER_NAME
export SINGULARITYENV_TARGET_NAME=$TARGET_NAME
export SINGULARITYENV_FUZZER=/magma/fuzzers/$FUZZER_NAME
export SINGULARITYENV_TARGET=/magma/targets/$TARGET_NAME
export SINGULARITYENV_SVF_DIR=/SVF

mkdir -p /home/users/m/m.thielebein/magma_out/${FUZZER_NAME}/${TARGET_NAME}
mkdir -p /home/users/m/m.thielebein/magma_workdir/${FUZZER_NAME}/${TARGET_NAME}

singularity shell \
    --userns \
    --contain \
    --bind /home/users/m/m.thielebein/magma_UafDetect:/magma \
    --bind /home/users/m/m.thielebein/magma_out/${FUZZER_NAME}/${TARGET_NAME}:/magma_out \
    --bind /home/users/m/m.thielebein/magma_workdir/${FUZZER_NAME}/${TARGET_NAME}:/magma_shared \
    --bind /home/users/m/m.thielebein/SVF:/SVF\
    magma_${FUZZER_NAME}_${TARGET_NAME}.sif