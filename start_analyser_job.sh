#!/bin/bash

TARGETS=("libpng" "sqlite3" "libjpeg-turbo" "libxml2" "expat")
export ANALYZER="free_finder"    #free_finder or svf Analysis

if [ ! -f "/home/users/m/m.thielebein/magma_UafDetect/fuzzers/afl_uaf_detect/repo/SVF_drivers/build/${ANALYZER}-driver" ]; then
    echo "ERROR: ${ANALYZER}-driver not found at /home/users/m/m.thielebein/magma_UafDetect/fuzzers/afl_uaf_detect/repo/SVF_drivers/build/${ANALYZER}-driver"
    exit 1
fi

for TARGET in "${TARGETS[@]}"; do
    export TARGET
    TARGET_DIR="/home/users/m/m.thielebein/magma_out/afl_uaf_detect/${TARGET}/${ANALYZER}/targets"
    if [ ! -d "$TARGET_DIR" ]; then
        echo "WARNING: targets directory not found at $TARGET_DIR, skipping ${TARGET}"
        continue
    fi

    for bc_file in "$TARGET_DIR"/*.bc; do
        [ -f "$bc_file" ] || continue
        [[ "$(basename "$bc_file")" == *_instr* ]] && continue
        name="$(basename "${bc_file%.bc}")"
        echo "[*] Running ${ANALYZER}-driver on ${TARGET}/${name}.bc"
        sbatch --export=TARGET="${TARGET}",PROGRAM="${name}",ANALYZER="${ANALYZER}" \
            /home/users/m/m.thielebein/magma_UafDetect/svf_uaf_detect_analyser_run.sh
    done
done