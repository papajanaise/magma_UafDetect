#!/bin/bash
set -euo pipefail

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

# Delete any stale *_instr.bc artifacts from previous runs. Without this, a
# driver failure on this run would silently leave the old _instr.bc in place,
# and the downstream afl_instrument.sh stage would happily build a binary from
# the stale bitcode while the campaign log reports an error.
find "$TARGET_DIR" -maxdepth 1 -type f -name '*_instr*.bc' -delete
# Also drop any stale .timings sidecars from previous runs so aggregation only
# sums results from this run.
find "$TARGET_DIR" -maxdepth 1 -type f -name '*_instr.bc.timings' -delete

processed=0
for bc_file in "$TARGET_DIR"/*.bc; do
    [ -f "$bc_file" ] || continue
    [[ "$(basename "$bc_file")" == *_instr* ]] && continue
    name="$(basename "${bc_file%.bc}")"
    out_bc="$TARGET_DIR/${name}_instr.bc"
    echo "[*] Running $ANALYZER-driver on $name.bc"
    if ! "$FUZZER/repo/SVF_drivers/build/$ANALYZER-driver" "$bc_file" -o "$out_bc" -w -p -i; then
        echo "ERROR: $ANALYZER-driver failed on $name.bc" >&2
        exit 1
    fi
    if [ ! -f "$out_bc" ]; then
        echo "ERROR: $ANALYZER-driver reported success but did not produce $out_bc" >&2
        exit 1
    fi
    processed=$((processed + 1))
done

if [ "$processed" -eq 0 ]; then
    echo "ERROR: no input .bc files were processed in $TARGET_DIR" >&2
    exit 1
fi

# Aggregate per-bc timing sidecars dropped by the analyzer driver.  Each
# sidecar holds key=value lines (static_analysis, instrumentation in seconds).
# Emit one [TIMING] line per phase summed across all bc files, with a
# per-bc breakdown for visibility.
shopt -s nullglob
timing_files=("$TARGET_DIR"/*_instr.bc.timings)
shopt -u nullglob
if [ ${#timing_files[@]} -gt 0 ]; then
    awk '
        FNR == 1 {
            n = split(FILENAME, parts, "/")
            bc = parts[n]
            sub(/_instr\.bc\.timings$/, "", bc)
        }
        /^static_analysis=/ { sa[bc] = substr($0, index($0,"=")+1); sa_total += sa[bc] + 0 }
        /^instrumentation=/ { ins[bc] = substr($0, index($0,"=")+1); ins_total += ins[bc] + 0 }
        END {
            sa_detail = ""; ins_detail = ""
            for (k in sa) {
                sa_detail = sa_detail (sa_detail ? ", " : "") k "=" sprintf("%.1f", sa[k]) "s"
            }
            for (k in ins) {
                ins_detail = ins_detail (ins_detail ? ", " : "") k "=" sprintf("%.1f", ins[k]) "s"
            }
            printf "[TIMING] phase=%-25s elapsed=%.1fs    (per-bc: %s)\n", "static_analysis", sa_total, sa_detail
            printf "[TIMING] phase=%-25s elapsed=%.1fs    (per-bc: %s)\n", "instrumentation", ins_total, ins_detail
        }
    ' "${timing_files[@]}"
fi
