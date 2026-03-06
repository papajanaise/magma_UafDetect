#!/bin/bash

if [ ! -f "$FUZZER/repo/SVF_drivers/build/svf-icfg-driver" ]; then
    echo "ERROR: svf_icfg-driver not found at $FUZZER/repo/SVF_drivers/build/svf_icfg-driver"
    exit 1
fi
if [ ! -f "$OUT/$PROGRAM.bc" ]; then
    echo "ERROR: bitcode file not found at $OUT/$PROGRAM.bc"
    exit 1
fi

$FUZZER/repo/SVF_drivers/build/svf-icfg-driver $OUT/$PROGRAM.bc -o "$OUT/${PROGRAM}_instr.bc" -w -p -i
