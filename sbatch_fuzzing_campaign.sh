#!/bin/bash
#SBATCH --ntasks=1
#SBATCH --mem=16G
#SBATCH --time=25:00:00
#SBATCH --partition=standard
#SBATCH --mail-type=ALL
#SBATCH --mail-user=m.thielebein@tu-berlin.de
#SBATCH --exclude=gpu[001-066]

module load singularity
set -euo pipefail
ulimit -v unlimited

# --- These come from: sbatch --export=FUZZER=...,TARGET=...,PROGRAM=... ---
: "${FUZZER:?Set FUZZER via --export}"
: "${TARGET:?Set TARGET via --export}"
: "${PROGRAM:?Set PROGRAM via --export}"
: "${TIMEOUT:=7200}"  # default 2h if not passed

# --- Paths ---
SIF="/home/users/m/m.thielebein/magma_containers/magma_${FUZZER}_${TARGET}.sif"
BASE="$HOME/magma_results"
if [ "$FUZZER" == "afl_uaf_detect" ]; then
    HOST_OUT="$HOME/magma_out/${FUZZER}/${TARGET}/${ANALYZER}"
else
    HOST_OUT="$HOME/magma_out/${FUZZER}/${TARGET}"
fi


RUN_ID="${SLURM_JOB_ID}"
CAMPAIGN_DIR="${BASE}/${FUZZER}/${ANALYZER}/${TARGET}/${PROGRAM}/${RUN_ID}"
mkdir -p "$CAMPAIGN_DIR"/{findings,monitor,log}

# --- Stage a private copy of the build artifacts ---
# We snapshot only the files run.sh actually reads from $OUT (the monitor
# binary, the AFL fuzz target, and the optional CmpLog binary) into a
# campaign-local staging dir, then bind-mount that read-only into the
# container as /magma_out. This decouples the running campaign from
# $HOST_OUT, so a concurrent rebuild on the host cannot clobber the
# binaries this campaign is using.
STAGE_OUT="${CAMPAIGN_DIR}/magma_out"
mkdir -p "${STAGE_OUT}"

# Required: monitor binary (same location for every fuzzer layout).
if [ ! -x "${HOST_OUT}/monitor" ]; then
    echo "ERROR: missing monitor binary at ${HOST_OUT}/monitor" >&2
    exit 1
fi
cp -a "${HOST_OUT}/monitor" "${STAGE_OUT}/monitor"

# Required: AFL fuzz target. afl_uaf_detect places it at $OUT/afl/$PROGRAM,
# while aflplusplus_lto_asan (and friends) place it at $OUT/afl/targets/$PROGRAM.
# Stage whichever one exists, preserving the relative path the fuzzer's
# run.sh expects.
afl_target=""
for rel in "afl/${PROGRAM}" "afl/targets/${PROGRAM}"; do
    if [ -f "${HOST_OUT}/${rel}" ]; then
        afl_target="${rel}"
        break
    fi
done
if [ -z "$afl_target" ]; then
    echo "ERROR: missing fuzz target; tried ${HOST_OUT}/afl/${PROGRAM} and ${HOST_OUT}/afl/targets/${PROGRAM}" >&2
    exit 1
fi
mkdir -p "${STAGE_OUT}/$(dirname "$afl_target")"
cp -a "${HOST_OUT}/${afl_target}" "${STAGE_OUT}/${afl_target}"

# Optional: CmpLog binary, same two possible layouts.
for rel in "cmplog/${PROGRAM}" "cmplog/targets/${PROGRAM}"; do
    if [ -f "${HOST_OUT}/${rel}" ]; then
        mkdir -p "${STAGE_OUT}/$(dirname "$rel")"
        cp -a "${HOST_OUT}/${rel}" "${STAGE_OUT}/${rel}"
        break
    fi
done

echo "Staged build artifacts into ${STAGE_OUT} ($(du -sh "${STAGE_OUT}" | cut -f1))"

# --- Stage the fuzzer-repo binaries needed at runtime ---
# Without this, the campaign still runs $FUZZER/repo/afl-fuzz directly out
# of the live /magma bind, so a concurrent fuzzer rebuild on the host can
# clobber the binary mid-exec (race produces ENOENT). We snapshot the
# small set of files actually invoked at fuzz time and bind them in
# read-only on top of the corresponding paths inside the container.
HOST_FUZZER_REPO="/home/users/m/m.thielebein/magma_UafDetect/fuzzers/${FUZZER}/repo"
STAGE_FUZZER_REPO="${CAMPAIGN_DIR}/fuzzer_repo"
mkdir -p "${STAGE_FUZZER_REPO}"

if [ ! -x "${HOST_FUZZER_REPO}/afl-fuzz" ]; then
    echo "ERROR: missing afl-fuzz at ${HOST_FUZZER_REPO}/afl-fuzz" >&2
    exit 1
fi
cp -a "${HOST_FUZZER_REPO}/afl-fuzz" "${STAGE_FUZZER_REPO}/afl-fuzz"

# afl-fuzz internally exec()s a few helpers (afl-showmap is the common one);
# stage them when present so a fuzzer rebuild can't disturb them either.
for helper in afl-showmap afl-tmin afl-analyze afl-gotcpu; do
    if [ -x "${HOST_FUZZER_REPO}/${helper}" ]; then
        cp -a "${HOST_FUZZER_REPO}/${helper}" "${STAGE_FUZZER_REPO}/${helper}"
    fi
done

# Dictionaries are read by afl-fuzz via -x at startup; stage the whole dir.
if [ -d "${HOST_FUZZER_REPO}/dictionaries" ]; then
    cp -a "${HOST_FUZZER_REPO}/dictionaries" "${STAGE_FUZZER_REPO}/dictionaries"
fi

echo "Staged fuzzer repo into ${STAGE_FUZZER_REPO} ($(du -sh "${STAGE_FUZZER_REPO}" | cut -f1))"

# --- Check what ARGS the target actually expects ---
# Extract from configrc (uses associative array PROGRAM_ARGS)
EXPECTED_ARGS=$(singularity exec "$SIF" bash -c \
    "source /magma/targets/${TARGET}/configrc 2>/dev/null; echo \"\${PROGRAM_ARGS[$PROGRAM]:-}\"" \
) || EXPECTED_ARGS=""

echo "=== Magma Campaign ==="
echo "Fuzzer:  $FUZZER"
echo "Target:  $TARGET"
echo "Program: $PROGRAM"
echo "Args:    '${EXPECTED_ARGS}'"
echo "SIF:     $SIF"
echo "Shared:  $CAMPAIGN_DIR"
echo "Job ID:  $SLURM_JOB_ID"
echo "Out (host source): $HOST_OUT"
echo "Out (staged):      $STAGE_OUT"
echo "======================"

# --- Environment for the container ---
export SINGULARITYENV_FUZZER="/magma/fuzzers/${FUZZER}"
export SINGULARITYENV_TARGET="/magma/targets/${TARGET}"
export SINGULARITYENV_PROGRAM="$PROGRAM"
export SINGULARITYENV_MAGMA="/magma/magma"
export SINGULARITYENV_OUT="/magma_out"
export SINGULARITYENV_SHARED="/magma_shared"
export SINGULARITYENV_ARGS="$EXPECTED_ARGS"
export SINGULARITYENV_POLL=5
export SINGULARITYENV_TIMEOUT="$TIMEOUT"
export SINGULARITYENV_ANALYZER="${ANALYZER:-}"

# --- Launch ---
# Build per-file binds that overlay the staged fuzzer-repo files on top of
# the live /magma mount. We bind individual files (rather than the whole
# /magma/fuzzers/$FUZZER/repo dir) so that everything else under repo/
# (sources, build artifacts, sub-tools we don't stage) keeps coming from
# the live mount, while the runtime-critical binaries are frozen for the
# duration of this campaign.
fuzzer_binds=()
for f in afl-fuzz afl-showmap afl-tmin afl-analyze afl-gotcpu; do
    if [ -f "${STAGE_FUZZER_REPO}/${f}" ]; then
        fuzzer_binds+=(--bind "${STAGE_FUZZER_REPO}/${f}:/magma/fuzzers/${FUZZER}/repo/${f}:ro")
    fi
done
if [ -d "${STAGE_FUZZER_REPO}/dictionaries" ]; then
    fuzzer_binds+=(--bind "${STAGE_FUZZER_REPO}/dictionaries:/magma/fuzzers/${FUZZER}/repo/dictionaries:ro")
fi

singularity exec \
    --writable-tmpfs \
    --bind "$CAMPAIGN_DIR":/magma_shared \
    --bind "/home/users/m/m.thielebein/magma_UafDetect":"/magma" \
    --bind "$STAGE_OUT":"/magma_out":ro \
    "${fuzzer_binds[@]}" \
    "$SIF" \
    /bin/bash /magma/magma/run.sh

echo "Campaign finished."