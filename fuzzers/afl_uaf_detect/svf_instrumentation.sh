#!/bin/bash

if [ ! -f "$FUZZER/repo/SVF_drivers/build/svf-icfg-driver" ]; then
    echo "ERROR: svf-icfg-driver not found at $FUZZER/repo/SVF_drivers/build/svf-icfg-driver"
    exit 1
fi

TARGET_DIR="$OUT/targets"
if [ ! -d "$TARGET_DIR" ]; then
    echo "ERROR: targets directory not found at $TARGET_DIR"
    exit 1
fi

#for bc_file in "$TARGET_DIR"/*.bc; do
    bc_file="$TARGET_DIR/$PROGRAM.bc"
    [ -f "$bc_file" ] || continue
    name="$(basename "${bc_file%.bc}")"
    echo "[*] Running svf-icfg-driver on $name.bc"
    "$FUZZER/repo/SVF_drivers/build/svf-icfg-driver" "$bc_file" -o "$TARGET_DIR/${name}_instr.bc" -w -p -i
#done
