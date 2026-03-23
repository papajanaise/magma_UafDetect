#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env OUT: path to directory where artifacts are stored
# - env ANALYZER: which analyzer to use (free_finder or svf)

if [ ! -f "$FUZZER/repo/SVF_drivers/build/${ANALYZER}-driver" ]; then
    echo "ERROR: ${ANALYZER}-driver not found at $FUZZER/repo/SVF_drivers/build/${ANALYZER}-driver"
    exit 1
fi

TARGET_DIR="$OUT/targets"
if [ ! -d "$TARGET_DIR" ]; then
    echo "ERROR: targets directory not found at $TARGET_DIR"
    exit 1
fi

for bc_file in "$TARGET_DIR"/*.bc; do
    #bc_file="$TARGET_DIR/$PROGRAM.bc"
    [ -f "$bc_file" ] || continue
    [[ "$(basename "$bc_file")" == *_instr* ]] && continue
    name="$(basename "${bc_file%.bc}")"
    echo "[*] Running $ANALYZER-driver on $name.bc"
    "$FUZZER/repo/SVF_drivers/build/$ANALYZER-driver" "$bc_file" -o "$TARGET_DIR/${name}_instr.bc" -w -p -i
done
