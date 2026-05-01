#!/bin/bash
#
# Submit one slurm job per (test case x analyzer) for the uaf_batch suite.
# Discovers /home/users/m/m.thielebein/uaf_batch/uaf_*_free_finder_instr
# and uaf_*_svf_instr executables; ANALYZER is derived from the suffix.
#
# Usage:
#   ./start_fuzzing_uaf_batch.sh                # all binaries, 24h timeout
#   ./start_fuzzing_uaf_batch.sh --timeout 3600 # override per-campaign timeout

set -euo pipefail

BATCH_DIR="/home/users/m/m.thielebein/uaf_batch"
TIMEOUT=7200  #default 2h -> 7200s

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "Usage: $0 [--timeout seconds]" >&2; exit 1 ;;
    esac
done

STAMP="$(date '+%Y%m%d_%H%M%S')"
LOG_DIR="/home/users/m/m.thielebein/uaf_batch/campaign_logs/$STAMP"
mkdir -p "$LOG_DIR"

shopt -s nullglob
for bin in "$BATCH_DIR"/uaf_*_free_finder_instr "$BATCH_DIR"/uaf_*_svf_instr; do
    [ -x "$bin" ] || { echo "skip (not executable): $bin" >&2; continue; }
    name="$(basename "$bin")"
    case "$name" in
        *_free_finder_instr) ANALYZER="free_finder" ;;
        *_svf_instr)         ANALYZER="svf" ;;
    esac
    sbatch \
        --export=BIN_PATH="$bin",ANALYZER="$ANALYZER",STAMP="$STAMP",TIMEOUT="$TIMEOUT" \
        --job-name="uaf_${name}" \
        -o "$LOG_DIR/${name}.%j.out" \
        /home/users/m/m.thielebein/magma_UafDetect/sbatch_fuzz_uaf_case.sh
done
