#!/bin/bash

export ANALYZER="free_finder"
export TARGETS="expat libjpeg-turbo libpng libxml2 sqlite3"

LOG_DIR="/home/users/m/m.thielebein/magma_campaign_logs/build_jobs/$(date '+%Y%m%d_%H%M%S')"
mkdir -p "$LOG_DIR"

PIPELINE_FILE="/home/users/m/m.thielebein/magma_UafDetect/.pipeline_jobs"
> "$PIPELINE_FILE"

TARGETS_DIR="/home/users/m/m.thielebein/magma_UafDetect/targets"

# Clean all target repos on the host before submitting any jobs.
# This prevents stale build artifacts from interfering with fresh builds.
for target in $TARGETS; do
    echo "Cleaning $target repo..."
    git -C "$TARGETS_DIR/$target/repo" clean -fdx
    git -C "$TARGETS_DIR/$target/repo" checkout -- .
done
rm -rf "$TARGETS_DIR/sqlite3/work" "$TARGETS_DIR/expat/install"

# Apply Magma bug patches to each target repo (after clean, before build)
for target in $TARGETS; do
    echo "Applying patches to $target..."
    TARGET="$TARGETS_DIR/$target" /home/users/m/m.thielebein/magma_UafDetect/magma/apply_patches.sh
done

# Build each fuzzer first in a separate job
declare -A FUZZER_BUILD_JOB

for fuzzer in "afl_uaf_detect" "aflplusplus_lto_asan"; do
    FUZZER_JOB=$(sbatch --parsable \
        --export=FUZZER_NAME="${fuzzer}" \
        --job-name="build_fuzzer_${fuzzer}" \
        -o "${LOG_DIR}/build_fuzzer_${fuzzer}.%j.out" \
        /home/users/m/m.thielebein/magma_UafDetect/sbatch_build_fuzzer.sh)
    echo "Submitted fuzzer build job $FUZZER_JOB for ${fuzzer}"
    echo "$FUZZER_JOB build_fuzzer ${fuzzer}" >> "$PIPELINE_FILE"
    FUZZER_BUILD_JOB[$fuzzer]="$FUZZER_JOB"
done

# Use associative array to track the last job per target, so that
# builds for the same target (different fuzzers) run sequentially.
# This prevents concurrent writes to the same bind-mounted source repo.
declare -A LAST_JOB_FOR_TARGET

for fuzzer in "afl_uaf_detect" "aflplusplus_lto_asan"; do
    export FUZZER_NAME="$fuzzer"
    for target in $TARGETS; do
        export TARGET_NAME="$target"

        # Depend on the fuzzer build job, and on the previous target build
        # for the same target (to avoid concurrent writes to the source repo)
        DEPS="${FUZZER_BUILD_JOB[$fuzzer]}"
        if [[ -n "${LAST_JOB_FOR_TARGET[$target]:-}" ]]; then
            DEPS="${DEPS}:${LAST_JOB_FOR_TARGET[$target]}"
        fi

        # Submit the build job and capture its ID
        BUILD_JOB=$(sbatch --parsable \
            --dependency=afterok:${DEPS} \
            --export=FUZZER_NAME="${FUZZER_NAME}",TARGET_NAME="${TARGET_NAME}",ANALYZER="${ANALYZER}" \
            --job-name="build_${FUZZER_NAME}_${TARGET_NAME}" \
            -o "${LOG_DIR}/build_${FUZZER_NAME}_${TARGET_NAME}.%j.out" \
            /home/users/m/m.thielebein/magma_UafDetect/sbatch_full_build_pipeline.sh)
        echo "Submitted build job $BUILD_JOB for ${FUZZER_NAME}/${TARGET_NAME} (after fuzzer:${FUZZER_BUILD_JOB[$fuzzer]})"
        echo "$BUILD_JOB build ${FUZZER_NAME}/${TARGET_NAME}" >> "$PIPELINE_FILE"

        LAST_JOB_FOR_TARGET[$target]="$BUILD_JOB"
    done
done
