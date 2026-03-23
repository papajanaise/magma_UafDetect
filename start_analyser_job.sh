#!/bin/bash

export TARGET="expat"
export ANALYZER="free_finder"    #free_finder or svf Analysis

if [ ! -f "/home/users/m/m.thielebein/magma_UafDetect/fuzzers/afl_uaf_detect/repo/SVF_drivers/build/${ANALYZER}-driver" ]; then
    echo "ERROR: ${ANALYZER}-driver not found at /home/users/m/m.thielebein/magma_UafDetect/fuzzers/afl_uaf_detect/repo/SVF_drivers/build/${ANALYZER}-driver"
    exit 1
fi

TARGET_DIR="/home/users/m/m.thielebein/magma_out/afl_uaf_detect/${TARGET}/${ANALYZER}/targets"
if [ ! -d "$TARGET_DIR" ]; then
    echo "ERROR: targets directory not found at $TARGET_DIR"
    exit 1
fi

for bc_file in "$TARGET_DIR"/*.bc; do
    #bc_file="$TARGET_DIR/$PROGRAM.bc"
    [ -f "$bc_file" ] || continue
    [[ "$(basename "$bc_file")" == *_instr* ]] && continue
    name="$(basename "${bc_file%.bc}")"
    echo "[*] Running free-finder-driver on $name.bc"
    sbatch --export=TARGET="${TARGET}",PROGRAM="${name}",ANALYZER="${ANALYZER}" \
        /home/users/m/m.thielebein/magma_UafDetect/svf_uaf_detect_analyser_run.sh
done