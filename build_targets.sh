#!/bin/bash

export ANALYZER="free_finder svf "    #free_finder or svf Analysis
export TARGETS="expat libjpeg-turbo libpng libxml2 sqlite3" #targets to build
export FUZZERS="afl_uaf_detect" #aflplusplus first because the fuzzer is usally done building first and targets can already be built

LOG_DIR="/home/users/m/m.thielebein/magma_campaign_logs/build_jobs/$(date '+%Y%m%d_%H%M%S')"
mkdir -p "$LOG_DIR"

PIPELINE_FILE="/home/users/m/m.thielebein/magma_UafDetect/.pipeline_jobs"
> "$PIPELINE_FILE"

# IDs of all dependent build jobs we submit — the dependency watcher below
# uses this list to detect dead dependency chains.
SUBMITTED_BUILD_JOBS=()

TARGETS_DIR="/home/users/m/m.thielebein/magma_UafDetect/targets"

# Emit "<jobid>|<jobname>" for every live BUILD job belonging to the current
# user. Excludes:
#   * zombies whose dependency will never be satisfied (watcher will cancel
#     them — chaining new work behind them would kill the new work too),
#   * any job whose name doesn't start with "build_" (e.g. fuzzing campaign
#     jobs that merely consume the fuzzer/target — they don't modify the
#     fuzzer binary or source tree, so they are not actually blocking).
_live_jobs() {
    squeue --me -h -o '%i|%T|%R|%j' 2>/dev/null | \
        awk -F'|' '$3 !~ /DependencyNeverSatisfied/ && $4 ~ /^build_/ {print $1 "|" $4}'
}

# Return newline-separated IDs of live jobs whose name contains the given
# substring (bash substring match, no regex).
active_job_ids_matching() {
    local needle="$1"
    local jid jname
    while IFS='|' read -r jid jname; do
        [[ -z "$jid" ]] && continue
        if [[ "$jname" == *"$needle"* ]]; then
            printf '%s\n' "$jid"
        fi
    done < <(_live_jobs)
}

# Return IDs of live jobs whose name matches $1 exactly.
active_job_ids_exact() {
    local name="$1"
    local jid jname
    while IFS='|' read -r jid jname; do
        [[ -z "$jid" ]] && continue
        if [[ "$jname" == "$name" ]]; then
            printf '%s\n' "$jid"
        fi
    done < <(_live_jobs)
}

# Highest (newest) job ID among live jobs whose name contains the substring.
# Useful for target serialization: prior runs chain target jobs via
# LAST_JOB_FOR_TARGET, so waiting on the tail of the chain transitively
# waits on every earlier job in it.
active_newest_job_id_matching() {
    local needle="$1"
    active_job_ids_matching "$needle" | sort -n | tail -1
}

# Detect in-progress jobs so we don't clobber builds that are already running.
#   * fuzzers / analyzers: if any active job uses one, skip its rebuild and
#     treat the existing active jobs as additional deps for downstream builds.
#   * targets: don't skip — instead submit the new build but chain it behind
#     any active jobs for the same target, and skip the local clean/patch
#     (which would corrupt the in-use source tree).
declare -A SKIP_FUZZER_BUILD
declare -A SKIP_ANALYZER_BUILD
declare -A FUZZER_EXTRA_DEPS
declare -A ANALYZER_EXTRA_DEPS
declare -A TARGET_EXTRA_DEPS

for fuzzer in $FUZZERS; do
    # Broad "in use" check: any active job referencing the fuzzer means its
    # binary is currently needed by something and we must not rebuild it.
    using_ids=$(active_job_ids_matching "$fuzzer" | paste -sd, -)
    if [[ -n "$using_ids" ]]; then
        echo "WARNING: fuzzer '${fuzzer}' is in use by active job(s) [${using_ids}] — NOT rebuilding fuzzer." >&2
        SKIP_FUZZER_BUILD[$fuzzer]=1
    fi
    # But only chain new builds behind an actual fuzzer-build job — consumers
    # of the fuzzer (target builds) don't modify the binary, so they needn't
    # block downstream work.
    build_ids=$(active_job_ids_exact "build_fuzzer_${fuzzer}" | paste -sd: -)
    if [[ -n "$build_ids" ]]; then
        FUZZER_EXTRA_DEPS[$fuzzer]="$build_ids"
    fi
done

for analyzer in $ANALYZER; do
    using_ids=$(active_job_ids_matching "$analyzer" | paste -sd, -)
    if [[ -n "$using_ids" ]]; then
        echo "WARNING: analyzer '${analyzer}' is in use by active job(s) [${using_ids}] — NOT rebuilding analyzer." >&2
        SKIP_ANALYZER_BUILD[$analyzer]=1
    fi
    # Only an actual driver build job is a real dependency for new builds.
    if [[ "$analyzer" == "svf" ]]; then
        build_ids=$(active_job_ids_exact "build_svf_driver" | paste -sd: -)
        if [[ -n "$build_ids" ]]; then
            ANALYZER_EXTRA_DEPS[$analyzer]="$build_ids"
        fi
    fi
done

for target in $TARGETS; do
    newest=$(active_newest_job_id_matching "$target")
    if [[ -n "$newest" ]]; then
        echo "WARNING: target '${target}' has active job(s); chaining new builds behind newest ($newest) — skipping local clean/patch." >&2
        TARGET_EXTRA_DEPS[$target]="$newest"
    fi
done

# Clean all target repos on the host before submitting any jobs, so the
# patches always apply against exactly the source revision fetch.sh declares.
#
# Re-fetch (rm -rf + run fetch.sh) when:
#   * the repo doesn't exist yet,
#   * the target uses a tarball (no .git — `git checkout --` isn't available,
#     so re-extracting is the only way to undo patches),
#   * fetch.sh has changed since the last fetch (e.g. the user bumped the
#     pinned tag/commit),
#   * the repo's HEAD has drifted from what fetch.sh produced.
# Otherwise just `git clean -fdx` + `git checkout -- .`.
#
# Pin state lives at $TARGETS_DIR/$target/.repo_pin — one line:
#     "<sha256 of fetch.sh> <git HEAD sha or empty>"

_fetch_sh_hash() {
    sha256sum "$1" | awk '{print $1}'
}

_record_pin() {
    local target="$1"
    local repo="$TARGETS_DIR/$target/repo"
    local fetch="$TARGETS_DIR/$target/fetch.sh"
    local pin="$TARGETS_DIR/$target/.repo_pin"
    local head=""
    [[ -d "$repo/.git" ]] && head=$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)
    printf '%s %s\n' "$(_fetch_sh_hash "$fetch")" "$head" > "$pin"
}

_needs_refetch() {
    local target="$1"
    local repo="$TARGETS_DIR/$target/repo"
    local fetch="$TARGETS_DIR/$target/fetch.sh"
    local pin="$TARGETS_DIR/$target/.repo_pin"

    if [[ ! -d "$repo" ]] || [[ -z "$(ls -A "$repo" 2>/dev/null)" ]]; then
        return 0
    fi
    # Tarball-style targets have no working-tree-revert option — fetch.sh
    # is the only producer of a clean state.
    if [[ ! -d "$repo/.git" ]]; then
        return 0
    fi
    # First run after introducing pin tracking: trust the existing checkout
    # so we don't gratuitously nuke a healthy repo.
    if [[ ! -f "$pin" ]]; then
        _record_pin "$target"
        return 1
    fi

    local pinned_hash pinned_head current_hash current_head
    read -r pinned_hash pinned_head < "$pin" || true
    current_hash=$(_fetch_sh_hash "$fetch")
    current_head=$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)

    if [[ "$current_hash" != "$pinned_hash" ]]; then
        echo "  $target: fetch.sh changed since last fetch — re-fetching."
        return 0
    fi
    if [[ -n "$pinned_head" && "$current_head" != "$pinned_head" ]]; then
        echo "  $target: HEAD ($current_head) drifted from pinned ($pinned_head) — re-fetching."
        return 0
    fi
    return 1
}

for target in $TARGETS; do
    if [[ -n "${TARGET_EXTRA_DEPS[$target]:-}" ]]; then
        echo "Skipping clean of $target repo (active job in progress)."
        continue
    fi
    repo="$TARGETS_DIR/$target/repo"
    if _needs_refetch "$target"; then
        echo "Fetching $target source..."
        rm -rf "$repo"
        mkdir -p "$repo"
        TARGET="$TARGETS_DIR/$target" OUT="$TARGETS_DIR/$target" \
            bash "$TARGETS_DIR/$target/fetch.sh"
        _record_pin "$target"
    else
        echo "Cleaning $target repo..."
        git -C "$repo" clean -fdx
        git -C "$repo" checkout -- .
    fi
done
if [[ -z "${TARGET_EXTRA_DEPS[sqlite3]:-}" ]]; then
    rm -rf "$TARGETS_DIR/sqlite3/work"
fi
if [[ -z "${TARGET_EXTRA_DEPS[expat]:-}" ]]; then
    rm -rf "$TARGETS_DIR/expat/install"
fi

# Apply Magma bug patches to each target repo (after clean, before build)
for target in $TARGETS; do
    if [[ -n "${TARGET_EXTRA_DEPS[$target]:-}" ]]; then
        echo "Skipping patches for $target (active job in progress)."
        continue
    fi
    echo "Applying patches to $target..."
    TARGET="$TARGETS_DIR/$target" /home/users/m/m.thielebein/magma_UafDetect/magma/apply_patches.sh
done

FUZZERS_DIR="/home/users/m/m.thielebein/magma_UafDetect/fuzzers"

# Fetch fuzzer sources on the host if missing. Skip when a build of the
# same fuzzer is already in flight, to avoid corrupting an in-use tree.
for fuzzer in $FUZZERS; do
    if [[ -n "${SKIP_FUZZER_BUILD[$fuzzer]:-}" ]]; then
        continue
    fi
    fuzzer_repo="$FUZZERS_DIR/$fuzzer/repo"
    if [[ ! -d "$fuzzer_repo/.git" ]]; then
        echo "Fetching $fuzzer source..."
        rm -rf "$fuzzer_repo"
        mkdir -p "$fuzzer_repo"
        FUZZER="$FUZZERS_DIR/$fuzzer" \
            bash "$FUZZERS_DIR/$fuzzer/fetch.sh"
    fi
done

# Build each fuzzer first in a separate job
declare -A FUZZER_BUILD_JOB

for fuzzer in $FUZZERS; do
    if [[ -n "${SKIP_FUZZER_BUILD[$fuzzer]:-}" ]]; then
        echo "Skipping fuzzer build submission for ${fuzzer} (already in use)."
        continue
    fi
    FUZZER_JOB=$(sbatch --parsable \
        --export=FUZZER_NAME="${fuzzer}" \
        --job-name="build_fuzzer_${fuzzer}" \
        -o "${LOG_DIR}/build_fuzzer_${fuzzer}.%j.out" \
        /home/users/m/m.thielebein/magma_UafDetect/sbatch_build_fuzzer.sh)
    echo "Submitted fuzzer build job $FUZZER_JOB for ${fuzzer}"
    echo "$FUZZER_JOB build_fuzzer ${fuzzer}" >> "$PIPELINE_FILE"
    FUZZER_BUILD_JOB[$fuzzer]="$FUZZER_JOB"
done

# Build SVF driver in parallel with fuzzer builds (unless an svf build is
# already in flight — in which case downstream jobs will depend on it instead).
SVF_DRIVER_JOB=""
if [[ -z "${SKIP_ANALYZER_BUILD[svf]:-}" ]]; then
    SVF_DRIVER_JOB=$(sbatch --parsable \
        --job-name="build_svf_driver" \
        -o "${LOG_DIR}/build_svf_driver.%j.out" \
        /home/users/m/m.thielebein/magma_UafDetect/sbatch_build_svf_driver.sh)
    echo "Submitted SVF driver build job $SVF_DRIVER_JOB"
    echo "$SVF_DRIVER_JOB build svf_driver" >> "$PIPELINE_FILE"
else
    echo "Skipping SVF driver build submission (already in use)."
fi

# Use associative array to track the last job per target, so that
# builds for the same target (different fuzzers) run sequentially.
# This prevents concurrent writes to the same bind-mounted source repo.
declare -A LAST_JOB_FOR_TARGET

for fuzzer in $FUZZERS; do
    export FUZZER_NAME="$fuzzer"

    # Which analyzer variants to build for this fuzzer.
    # afl_uaf_detect has two (free_finder, svf) — submit one Slurm job per
    # variant so each gets its own log file and independent failure mode.
    # Other fuzzers don't use ANALYZER; represent that as a single empty entry
    # so the loop below runs exactly once.
    if [[ "$fuzzer" == "afl_uaf_detect" ]]; then
        analyzers_iter=($ANALYZER)
    else
        analyzers_iter=("")
    fi

    for target in $TARGETS; do
        export TARGET_NAME="$target"

        for analyzer in "${analyzers_iter[@]}"; do
            # Depend on the fuzzer build job, the SVF driver build (for afl_uaf_detect),
            # and on the previous target build for the same target (to avoid concurrent
            # writes to the source repo — true across analyzer variants too, since both
            # variants patch/build under /magma/targets/$target). Also chain onto any
            # already-in-flight jobs we detected for this fuzzer/analyzer/target so
            # we don't race builds that were running before this script started.
            # afterok: artifact producers we consume (fuzzer binary, svf driver).
            # afterany: serialization-only deps (prior target build sharing the
            # same source tree) — we need them *finished*, not successful, so
            # a failed sibling variant doesn't cascade-cancel the next one.
            DEPS_OK=""
            DEPS_ANY=""
            _add_ok() {
                local d="$1"; [[ -z "$d" ]] && return
                DEPS_OK="${DEPS_OK:+${DEPS_OK}:}${d}"
            }
            _add_any() {
                local d="$1"; [[ -z "$d" ]] && return
                DEPS_ANY="${DEPS_ANY:+${DEPS_ANY}:}${d}"
            }
            _add_ok "${FUZZER_BUILD_JOB[$fuzzer]:-}"
            _add_ok "${FUZZER_EXTRA_DEPS[$fuzzer]:-}"
            if [[ "$fuzzer" == "afl_uaf_detect" ]]; then
                _add_ok "${SVF_DRIVER_JOB:-}"
                _add_ok "${ANALYZER_EXTRA_DEPS[$analyzer]:-}"
            fi
            _add_any "${LAST_JOB_FOR_TARGET[$target]:-}"
            _add_any "${TARGET_EXTRA_DEPS[$target]:-}"

            # Per-variant job name / log file. For fuzzers without analyzer
            # variants we omit the suffix so existing tooling keeps working.
            job_suffix="${analyzer:+_${analyzer}}"
            JOB_NAME="build_${FUZZER_NAME}_${TARGET_NAME}${job_suffix}"

            # Submit the build job and capture its ID
            dep_parts=()
            dep_spec=""
            [[ -n "$DEPS_OK"  ]] && dep_parts+=("afterok:${DEPS_OK}")
            [[ -n "$DEPS_ANY" ]] && dep_parts+=("afterany:${DEPS_ANY}")
            dep_args=()
            if [ ${#dep_parts[@]} -gt 0 ]; then
                dep_spec=$(IFS=,; echo "${dep_parts[*]}")
                dep_args+=(--dependency="$dep_spec")
            fi
            BUILD_JOB=$(sbatch --parsable \
                "${dep_args[@]}" \
                --export=FUZZER_NAME="${FUZZER_NAME}",TARGET_NAME="${TARGET_NAME}",ANALYZER="${analyzer}" \
                --job-name="${JOB_NAME}" \
                -o "${LOG_DIR}/${JOB_NAME}.%j.out" \
                /home/users/m/m.thielebein/magma_UafDetect/sbatch_full_build_pipeline.sh)
            echo "Submitted build job $BUILD_JOB for ${FUZZER_NAME}/${TARGET_NAME}${analyzer:+/${analyzer}} (deps: ${dep_spec:-none})"
            echo "$BUILD_JOB build ${FUZZER_NAME}/${TARGET_NAME}${analyzer:+/${analyzer}}" >> "$PIPELINE_FILE"

            LAST_JOB_FOR_TARGET[$target]="$BUILD_JOB"
            SUBMITTED_BUILD_JOBS+=("$BUILD_JOB")
        done
    done
done

###############################################################################
# Dependency watcher: poll Slurm and cancel any of the build jobs we submitted
# whose dependency can never be satisfied (e.g. the parent build ran OOM or
# failed), printing a clear error message so these never sit in the queue in
# DependencyNeverSatisfied state indefinitely.
###############################################################################

WATCHER_LOG="${LOG_DIR}/dependency_watcher.log"
WATCHER_PIDFILE="${LOG_DIR}/dependency_watcher.pid"

if [ ${#SUBMITTED_BUILD_JOBS[@]} -gt 0 ]; then
    (
        set +e
        trap 'exit 0' TERM INT
        remaining=("${SUBMITTED_BUILD_JOBS[@]}")
        echo "[$(date '+%F %T')] Watching ${#remaining[@]} build jobs: ${remaining[*]}"
        while [ ${#remaining[@]} -gt 0 ]; do
            sleep 30
            still=()
            for jid in "${remaining[@]}"; do
                # Read state + reason for this job from squeue (only shows
                # jobs still queued/running). Missing = finished, drop it.
                line=$(squeue -h -j "$jid" -o '%T|%R' 2>/dev/null || true)
                if [ -z "$line" ]; then
                    continue
                fi
                state="${line%%|*}"
                reason="${line#*|}"
                if [ "$state" = "PENDING" ] && [[ "$reason" == *DependencyNeverSatisfied* ]]; then
                    echo "[$(date '+%F %T')] ERROR: job $jid dependency can not be satisfied — cancelling." >&2
                    scancel "$jid" 2>/dev/null || true
                    continue
                fi
                still+=("$jid")
            done
            remaining=("${still[@]}")
        done
        echo "[$(date '+%F %T')] Dependency watcher done."
    ) >> "$WATCHER_LOG" 2>&1 &
    echo $! > "$WATCHER_PIDFILE"
    disown 2>/dev/null || true
    echo ""
    echo "Dependency watcher started (pid $(cat "$WATCHER_PIDFILE"))."
    echo "  Log:     $WATCHER_LOG"
    echo "  Pidfile: $WATCHER_PIDFILE"
fi
