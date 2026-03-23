#!/bin/bash

export FUZZER_NAME="aflplusplus_lto_asan" 
export TARGET_NAME="sqlite3" 
export ANALYZER="free_finder"    #free_finder or svf Analysis
export PROGRAM_NAME="sqlite3_fuzz"  #xml_parse_fuzzer_UTF-8, libjpeg_turbo_fuzzer, libpng_read_fuzzer, libxml2_xml_read_memory_fuzzer, sqlite3_fuzz

export SINGULARITYENV_FUZZER_NAME=${FUZZER_NAME}
export SINGULARITYENV_TARGET_NAME=${TARGET_NAME}
export SINGULARITYENV_FUZZER=/magma/fuzzers/$FUZZER_NAME
export SINGULARITYENV_TARGET=/magma/targets/$TARGET_NAME
export SINGULARITYENV_PROGRAM=${PROGRAM_NAME}
export SINGULARITYENV_ARGS=""
export SINGULARITYENV_POLL=5
export SINGULARITYENV_TIMEOUT=86400     # campaign duration in seconds (e.g. 24h)
export SINGULARITYENV_MAGMA=/magma/magma
export SINGULARITYENV_OUT=/magma_out
export SINGULARITYENV_SHARED=/magma_shared

CAMPAIGN_DIR="/home/users/m/m.thielebein/magma_workdir/${FUZZER_NAME}/${TARGET_NAME}/$(date '+%Y%m%d_%H%M%S')"
mkdir -p "$CAMPAIGN_DIR"
echo "Campaign directory: $CAMPAIGN_DIR"

if [ "$FUZZER_NAME" == "afl_uaf_detect" ]; then
    OUT_DIR="/home/users/m/m.thielebein/magma_out/${FUZZER_NAME}/${TARGET_NAME}/${ANALYZER}"
else
    OUT_DIR="/home/users/m/m.thielebein/magma_out/${FUZZER_NAME}/${TARGET_NAME}"
fi
echo "Output directory: $OUT_DIR"
mkdir -p "$OUT_DIR"

module load singularity
singularity shell --writable-tmpfs \
    -B /home/users/m/m.thielebein/magma_UafDetect/magma:/magma/magma \
    -B /home/users/m/m.thielebein/magma_UafDetect/tools:/magma/tools \
    -B /home/users/m/m.thielebein/magma_UafDetect/fuzzers/$FUZZER_NAME:/magma/fuzzers/$FUZZER_NAME \
    -B /home/users/m/m.thielebein/magma_UafDetect/targets/$TARGET_NAME:/magma/targets/$TARGET_NAME \
    -B "$CAMPAIGN_DIR":/magma_shared \
    -B /home/users/m/m.thielebein/SVF:/SVF \
    -B "$OUT_DIR":/magma_out \
    /home/users/m/m.thielebein/magma_containers/magma_${FUZZER_NAME}_${TARGET_NAME}.sif