#!/bin/bash
# campaign_analyse.sh — Per-campaign analysis: monitor + crash replay.
#
# Processes a single fuzzing campaign and writes results directly into the
# campaign directory so they can be reused by later comparisons.
#
# Output files (in <program_dir>/<run_id>/):
#   monitor_analysis.csv  — first reached/triggered/free_reached/free_triggered timestamps per bug
#   crash_replay.csv      — per-crash bug mapping from replay
#
# Expected environment variables (via sbatch --export):
#   CAMPAIGN_LIST  — path to campaign list file
#   MAGMA_OUT      — path to magma output directory (compiled binaries)
#   TIMEOUT        — timeout per crash replay in seconds (default: 10)
#   PARALLEL       — number of parallel replay workers (default: 4)
#   FORCE          — set to 1 to reprocess even if results exist (default: 0)
#
# Uses SLURM_ARRAY_TASK_ID (or TASK_ID for local mode) to pick the campaign.
set -euo pipefail

# Crash replay execs the per-target container — singularity is provided by the
# module system on the compute nodes (same as all sbatch_*.sh in this repo).
# Tolerate the "command not found" case so --local mode on a node without the
# module still loads cleanly; the later `command -v singularity` guard skips
# the replay with a clear message in that case.
if ! command -v singularity >/dev/null 2>&1 && command -v module >/dev/null 2>&1; then
    module load singularity 2>/dev/null || true
fi

TASK_ID="${SLURM_ARRAY_TASK_ID:-${TASK_ID:-}}"
if [ -z "$TASK_ID" ]; then
    echo "ERROR: Neither SLURM_ARRAY_TASK_ID nor TASK_ID is set." >&2
    exit 1
fi

TIMEOUT="${TIMEOUT:-10}"
PARALLEL="${PARALLEL:-4}"
FORCE="${FORCE:-0}"

# Per-task scratch must be on local disk, NOT BeeGFS.
#
# Crash-replay redirects `singularity exec … > $result_file 2>/dev/null` to
# capture the monitor's stdout. When $result_file lives on BeeGFS, the
# short-lived singularity process exits before its buffered writes hit the
# meta server — the file stays 0 bytes and parse_canary_output sees nothing
# but "none,none,none,none". Confirmed empirically: same command writes the
# expected 374-byte canary report to /tmp, but 0 bytes to $HOME/.cache.
# So prefer SLURM_TMPDIR, then /tmp (local on every compute node), and only
# fall back to $HOME/.cache when CAMPAIGN_TMPDIR_BASE explicitly forces it.
TMPDIR_BASE="${CAMPAIGN_TMPDIR_BASE:-${SLURM_TMPDIR:-/tmp}}"
mkdir -p "$TMPDIR_BASE"

# Self-heal: reap our own task_* leftovers from runs that were SIGKILLed
# (OOM, walltime, scancel -9) and so couldn't fire the cleanup() trap below.
# Slurm here has JobContainerType=(null) and no Epilog, so /tmp persists
# across jobs — anything we leak stays until something like this reaps it.
# uid filter + 1h age guarantees we never touch anyone else's files or a
# concurrent job of our own. chmod first because abandoned dirs may contain
# mode-0555 gllvm Go-module-cache that rm can't recurse without it.
find "$TMPDIR_BASE" -mindepth 1 -maxdepth 1 -user "${USER:-$(id -un)}" -mmin +60 \
    -name 'task_*' -exec chmod -R u+w {} + 2>/dev/null || true
find "$TMPDIR_BASE" -mindepth 1 -maxdepth 1 -user "${USER:-$(id -un)}" -mmin +60 \
    -name 'task_*' -exec rm -rf {} + 2>/dev/null || true

TMPDIR=$(mktemp -d "$TMPDIR_BASE/task_${SLURM_ARRAY_JOB_ID:-${SLURM_JOB_ID:-local}}_${TASK_ID}.XXXXXX")
export TMPDIR

# Keep singularity's image-staging area OUT of $TMPDIR. When singularity
# stages the SIF here, the extracted rootfs contains Go-module-cache dirs at
# mode 0555 (gllvm in the magma containers) which the cleanup-trap rm(1)
# can't recurse into without chmod first. Prefer the job-local SLURM tmpdir
# or /tmp on the compute node — these are job-scoped and OS-cleaned.
export SINGULARITY_TMPDIR="${SINGULARITY_TMPDIR:-${SLURM_TMPDIR:-/tmp}}"

cleanup() {
    if [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ]; then
        # Any singularity-staged rootfs leftovers may include mode-0555 dirs
        # (read-only Go module cache). chmod first so rm can recurse; silence
        # both since cleanup failure is non-fatal and shouldn't spam the log.
        chmod -R u+w "$TMPDIR" 2>/dev/null || true
        rm -rf "$TMPDIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT

on_error() {
    local rc=$?
    echo "ERROR: campaign_analyse task $TASK_ID failed (exit $rc)." >&2
    exit "$rc"
}
trap on_error ERR

LINE=$(sed -n "${TASK_ID}p" "$CAMPAIGN_LIST")
if [ -z "$LINE" ]; then
    echo "No campaign for task $TASK_ID"
    exit 0
fi

IFS='|' read -r fuzzer analyzer label target program run_id program_dir <<< "$LINE"
CAMPAIGN_DIR="$program_dir$run_id"

echo "========================================================================"
echo "Campaign: $fuzzer${analyzer:+/$analyzer} / $target / $program (run $run_id)"
echo "Dir:      $CAMPAIGN_DIR"
echo "========================================================================"
echo ""

###############################################################################
# Part A: Monitor analysis
###############################################################################

MONITOR_OUT="$CAMPAIGN_DIR/monitor_analysis.csv"
monitor_dir="$CAMPAIGN_DIR/monitor"

if [ -f "$MONITOR_OUT" ] && [ "$FORCE" != "1" ]; then
    echo "[SKIP] monitor_analysis.csv already exists (use FORCE=1 to reprocess)"
elif [ ! -d "$monitor_dir" ]; then
    echo "[SKIP] No monitor directory found at $monitor_dir"
else
    echo "--- Monitor analysis ---"

    FILE_LIST=$(mktemp)
    trap 'rm -f "$FILE_LIST"; on_error' ERR
    trap 'rm -f "$FILE_LIST"; cleanup' EXIT

    for f in "$monitor_dir"/*; do
        ts="${f##*/}"
        case "$ts" in tmp) continue ;; *[!0-9]*) continue ;; esac
        echo "$ts"
    done | sort -n > "$FILE_LIST"

    num_files=$(wc -l < "$FILE_LIST")
    if [ "$num_files" -eq 0 ]; then
        echo "No monitor snapshots found."
        echo "fuzzer,analyzer,target,program,run,bug,reached_s,triggered_s,free_reached_s,free_triggered_s" \
            > "$CAMPAIGN_DIR/.monitor_analysis.csv.tmp"
        mv "$CAMPAIGN_DIR/.monitor_analysis.csv.tmp" "$MONITOR_OUT"
    else
        echo "Processing $num_files monitor snapshots..."

        awk -v dir="$monitor_dir" \
            -v prefix="$fuzzer,$analyzer,$target,$program,$run_id" \
            '
BEGIN {
    file_list = ARGV[1]
    n_processed = 0

    while ((getline ts < file_list) > 0) {
        fpath = dir "/" ts
        header = ""
        data = ""
        if ((getline header < fpath) > 0) {
            getline data < fpath
        }
        close(fpath)

        n_processed++
        if (n_processed % 1000 == 0)
            printf("  ... %d files processed\n", n_processed) > "/dev/stderr"

        if (header == "" || data == "") continue

        n = split(header, cols, ",")
        split(data, vals, ",")

        for (i = 1; i <= n; i++) {
            col = cols[i]
            val = vals[i] + 0

            if (col ~ /[^A-Za-z0-9_.\-]/) continue

            # Check _FT before _T because BUG_FT also ends in _T.
            if (match(col, /_FT$/)) {
                bug = substr(col, 1, length(col) - 3)
                if (bug == "") continue
                seen[bug] = 1
                if (val > 0 && !(bug in first_free_triggered))
                    first_free_triggered[bug] = ts
            } else if (match(col, /_F$/)) {
                bug = substr(col, 1, length(col) - 2)
                if (bug == "") continue
                seen[bug] = 1
                if (val > 0 && !(bug in first_free_reached))
                    first_free_reached[bug] = ts
            } else if (match(col, /_R$/)) {
                bug = substr(col, 1, length(col) - 2)
                if (bug == "") continue
                seen[bug] = 1
                if (val > 0 && !(bug in first_reached))
                    first_reached[bug] = ts
            } else if (match(col, /_T$/)) {
                bug = substr(col, 1, length(col) - 2)
                if (bug == "") continue
                seen[bug] = 1
                if (val > 0 && !(bug in first_triggered))
                    first_triggered[bug] = ts
            }
        }
    }
    close(file_list)

    # Header
    print "fuzzer,analyzer,target,program,run,bug,reached_s,triggered_s,free_reached_s,free_triggered_s"

    n_bugs = 0
    for (bug in seen) bugs[++n_bugs] = bug

    if (n_bugs == 0) {
        print prefix ",(no data),-,-,-,-"
    } else {
        for (i = 2; i <= n_bugs; i++) {
            key = bugs[i]; j = i - 1
            while (j > 0 && bugs[j] > key) { bugs[j+1] = bugs[j]; j-- }
            bugs[j+1] = key
        }
        for (i = 1; i <= n_bugs; i++) {
            bug = bugs[i]
            r  = (bug in first_reached)         ? first_reached[bug]         : "-"
            t  = (bug in first_triggered)       ? first_triggered[bug]       : "-"
            fr = (bug in first_free_reached)    ? first_free_reached[bug]    : "-"
            ft = (bug in first_free_triggered)  ? first_free_triggered[bug]  : "-"
            print prefix "," bug "," r "," t "," fr "," ft
        }
    }
}
' "$FILE_LIST" > "$CAMPAIGN_DIR/.monitor_analysis.csv.tmp"

        mv "$CAMPAIGN_DIR/.monitor_analysis.csv.tmp" "$MONITOR_OUT"
        rows=$(( $(wc -l < "$MONITOR_OUT") - 1 ))
        echo "Monitor analysis done. Wrote $rows bug rows to $MONITOR_OUT"
    fi

    rm -f "$FILE_LIST"
    # Reset traps after cleanup
    trap on_error ERR
    trap cleanup EXIT
fi

echo ""

###############################################################################
# Replay setup
###############################################################################

CRASH_OUT="$CAMPAIGN_DIR/crash_replay.csv"

CRASH_HEADER="fuzzer,analyzer,target,program,run_id,crash_id,signal,time_ms,replay_exit_code,bugs_reached,bugs_triggered,bugs_free_reached,bugs_free_triggered,replay_crashed,asan_type"

# ASan options for the crash-replay pass.
CRASH_ASAN_OPTIONS="use_sigaltstack=0:detect_leaks=0:abort_on_error=1:allocator_may_return_null=1"

# MAGMA_OUT layout:
#   aflplusplus_lto_asan: <fuzzer>/<target>/afl/targets/<program>
#                         <fuzzer>/<target>/monitor
#   afl_uaf_detect:       <fuzzer>/<target>/<analyzer>/afl/<program>
#                         <fuzzer>/<target>/<analyzer>/monitor
get_exe_path() {
    local _fuzzer="$1" _target="$2" _analyzer="$3" _program="$4"
    case "$_fuzzer" in
        aflplusplus_lto_asan)
            echo "$MAGMA_OUT/$_fuzzer/$_target/afl/targets/$_program" ;;
        afl_uaf_detect)
            echo "$MAGMA_OUT/$_fuzzer/$_target/$_analyzer/afl/$_program" ;;
        *) echo "" ;;
    esac
}

# Replay binaries are gcc+ASan-only builds with magma canaries — no AFL or
# free_finder/SVF instrumentation. Produced by replay_build/build_replay_*.sh.
# They are fuzzer- and analyzer-agnostic, so both fuzzers reuse the single
# set built under afl_uaf_detect/<target>/free_finder/replay/.
get_replay_exe_path() {
    local _fuzzer="$1" _target="$2" _analyzer="$3" _program="$4"
    echo "$MAGMA_OUT/afl_uaf_detect/$_target/free_finder/replay/$_target/targets/$_program"
}

# Per-(fuzzer,target) Singularity container with the matching glibc / libstdc++
# / libasan ABI. Replay binaries dynamically link against the toolchain in
# their build container, so the same container must wrap execution.
CONTAINERS_DIR="${CONTAINERS_DIR:-/home/users/m/m.thielebein/magma_containers}"
get_container_path() {
    local _fuzzer="$1" _target="$2"
    echo "$CONTAINERS_DIR/magma_${_fuzzer}_${_target}.sif"
}

get_monitor_path() {
    local _fuzzer="$1" _target="$2" _analyzer="$3"
    case "$_fuzzer" in
        aflplusplus_lto_asan)
            echo "$MAGMA_OUT/$_fuzzer/$_target/monitor" ;;
        afl_uaf_detect)
            echo "$MAGMA_OUT/$_fuzzer/$_target/$_analyzer/monitor" ;;
        *) echo "" ;;
    esac
}

get_findings_subdir() {
    local _fuzzer="$1" _campaign_dir="$2"
    # AFL names the queue/crashes/hangs dir after the fuzzer instance: "-M
    # default" → findings/default, "-M main" → findings/main, no -M →
    # findings/default. afl_uaf_detect campaigns flip-flopped between the
    # two across the recent run.sh changes — probe what was actually
    # written for this campaign and only fall back to the fuzzer-specific
    # default when neither subdir exists yet.
    if [ -n "$_campaign_dir" ]; then
        for cand in default main; do
            if [ -d "$_campaign_dir/findings/$cand" ]; then
                echo "$cand"
                return
            fi
        done
    fi
    case "$_fuzzer" in
        aflplusplus_lto_asan) echo "main" ;;
        afl_uaf_detect)       echo "default" ;;
        *)                    echo "main" ;;
    esac
}

replay_one_input() {
    local _container="$1" _monitor="$2" _target_bin="$3" _input_file="$4" _out_file="$5" _asan_prefix="$6" _asan_options="$7"
    # The monitor's --fetch watch creates a `monitor_XXXXXX` mkstemp file in cwd
    # and only unlinks it on a clean exit. When `timeout` SIGKILLs us the file
    # is leaked; --pwd into TMPDIR_REPLAY so the caller's trap reaps them.
    #
    # Bind mounts:
    #   MAGMA_OUT      → covers the monitor binary and the replay target binary
    #   CAMPAIGN_DIR   → covers the input file (crash or queue entry)
    #   TMPDIR_REPLAY  → cwd for the monitor temp file and the result file
    # SINGULARITYENV_ASAN_OPTIONS propagates the env var into the container.
    # log_path is needed because monitor.c's fetch_watch dup2's the child's
    # stderr to /dev/null, so ASAN's diagnostic would be lost otherwise. With
    # log_path set, libasan writes the report to "<prefix>.<pid>" regardless.
    SINGULARITYENV_ASAN_OPTIONS="${_asan_options}:log_path=$_asan_prefix" \
        timeout "$TIMEOUT" \
        singularity exec \
            --bind "$MAGMA_OUT":"$MAGMA_OUT" \
            --bind "$CAMPAIGN_DIR":"$CAMPAIGN_DIR" \
            --bind "$TMPDIR_REPLAY":"$TMPDIR_REPLAY" \
            --pwd "$TMPDIR_REPLAY" \
            "$_container" \
            "$_monitor" --dump human --fetch watch "$_target_bin" "$_input_file" \
            > "$_out_file" 2>/dev/null
    return $?
}

parse_canary_output() {
    local _file="$1"
    local reached="" triggered="" free_reached="" free_triggered=""
    while IFS=' ' read -r bugid _ r_count _ t_count _ fr_count _ ft_count; do
        [[ -z "$bugid" ]] && continue
        case "$bugid" in *[!A-Za-z0-9_.-]*) continue ;; esac
        : "${r_count:=0}" "${t_count:=0}" "${fr_count:=0}" "${ft_count:=0}"
        if [ "$r_count" -gt 0 ] 2>/dev/null; then
            reached="${reached:+$reached;}$bugid($r_count)"
        fi
        if [ "$t_count" -gt 0 ] 2>/dev/null; then
            triggered="${triggered:+$triggered;}$bugid($t_count)"
        fi
        if [ "$fr_count" -gt 0 ] 2>/dev/null; then
            free_reached="${free_reached:+$free_reached;}$bugid($fr_count)"
        fi
        if [ "$ft_count" -gt 0 ] 2>/dev/null; then
            free_triggered="${free_triggered:+$free_triggered;}$bugid($ft_count)"
        fi
    done < "$_file"
    echo "${reached:-none},${triggered:-none},${free_reached:-none},${free_triggered:-none}"
}

# Inspect ASAN reports (written via log_path=<prefix>; ASAN appends .<pid>).
# Emits "<replay_crashed>,<asan_type>" where:
#   replay_crashed: "yes" if at least one ASAN report or non-zero monitor exit
#                   indicating crash; "timeout" if exit=124; "no" otherwise.
#   asan_type:      the AddressSanitizer error class extracted from the report
#                   (e.g. "heap-use-after-free", "heap-buffer-overflow",
#                   "double-free", "stack-buffer-overflow", ...), empty if no
#                   ASAN report was produced.
parse_asan_report() {
    local _prefix="$1" _exit_code="$2"
    local _crashed="no" _type=""
    local _logs=( "$_prefix".* )
    if [ -f "${_logs[0]}" ]; then
        for _log in "${_logs[@]}"; do
            [ -s "$_log" ] || continue
            # `|| true` so a partial log without the ERROR line doesn't
            # crash this function under `set -euo pipefail`.
            _type=$(grep -aoE 'AddressSanitizer: [A-Za-z0-9_-]+' "$_log" 2>/dev/null \
                    | head -n1 \
                    | sed 's/^AddressSanitizer: //' || true)
            [ -n "$_type" ] && break
        done
        _crashed="yes"
    fi
    if [ "$_exit_code" = "124" ]; then
        _crashed="timeout"
    elif [ "$_crashed" = "no" ] && [ "$_exit_code" != "0" ]; then
        # Monitor wrapper itself exited non-zero (e.g. target died from a
        # signal ASAN didn't intercept). Surface this as a crash even with
        # no ASAN report.
        _crashed="yes"
    fi
    echo "$_crashed,$_type"
}

parse_crash_filename() {
    local _fname="$1"
    local crash_id="" sig="" time_ms=""
    IFS=',' read -ra parts <<< "$_fname"
    for part in "${parts[@]}"; do
        IFS=':' read -r key val <<< "$part"
        case "$key" in
            id)   crash_id="$val" ;;
            sig)  sig="$val" ;;
            time) time_ms="$val" ;;
        esac
    done
    echo "$crash_id,$sig,$time_ms"
}

is_supported_fuzzer() {
    case "$1" in
        aflplusplus_lto_asan|afl_uaf_detect) return 0 ;;
        *) return 1 ;;
    esac
}

# Precondition checks. Failure here means we can't run Part B — write a
# stub CSV (so downstream consumers don't crash on missing files) and exit
# cleanly.
write_stub_csv() {
    local _path="$1" _header="$2"
    # Don't clobber a real result if it's already present.
    if [ -f "$_path" ]; then
        return
    fi
    echo "$_header" > "${_path}.tmp"
    mv "${_path}.tmp" "$_path"
}

REPLAY_OK=1
REPLAY_SKIP_REASON=""

if ! is_supported_fuzzer "$fuzzer"; then
    REPLAY_OK=0
    REPLAY_SKIP_REASON="Unsupported fuzzer for replay: $fuzzer"
fi

monitor_bin=$(get_monitor_path "$fuzzer" "$target" "$analyzer")
target_bin=$(get_replay_exe_path "$fuzzer" "$target" "$analyzer" "$program")
container=$(get_container_path "$fuzzer" "$target")

if [ "$REPLAY_OK" = "1" ] && [[ ! -x "$monitor_bin" ]]; then
    REPLAY_OK=0
    REPLAY_SKIP_REASON="No monitor binary at $monitor_bin"
fi
if [ "$REPLAY_OK" = "1" ] && [[ ! -x "$target_bin" ]]; then
    REPLAY_OK=0
    REPLAY_SKIP_REASON="No replay executable at $target_bin (build with replay_build/build_replay_${target}.sh)"
fi
if [ "$REPLAY_OK" = "1" ] && [[ ! -f "$container" ]]; then
    REPLAY_OK=0
    REPLAY_SKIP_REASON="No container at $container"
fi
if [ "$REPLAY_OK" = "1" ] && ! command -v singularity >/dev/null 2>&1; then
    REPLAY_OK=0
    REPLAY_SKIP_REASON="singularity not in PATH on this node"
fi

if [ "$REPLAY_OK" != "1" ]; then
    echo "[SKIP] $REPLAY_SKIP_REASON"
    write_stub_csv "$CRASH_OUT" "$CRASH_HEADER"
    echo ""
    echo "Done."
    exit 0
fi

subdir=$(get_findings_subdir "$fuzzer" "$CAMPAIGN_DIR")

TMPDIR_REPLAY=$(mktemp -d "$TMPDIR/replay.XXXXXX")
trap 'rm -rf "$TMPDIR_REPLAY"; cleanup' EXIT

###############################################################################
# Part B: Crash replay
###############################################################################

if [ -f "$CRASH_OUT" ] && [ "$FORCE" != "1" ]; then
    echo "[SKIP] crash_replay.csv already exists (use FORCE=1 to reprocess)"
else
    echo "--- Crash replay ---"

    crash_dir="$CAMPAIGN_DIR/findings/$subdir/crashes"
    crash_files=()
    if [ -d "$crash_dir" ]; then
        while IFS= read -r -d '' f; do
            crash_files+=("$f")
        done < <(find "$crash_dir" -maxdepth 1 -name 'id:*' -print0 | sort -z)
    fi

    # Persist per-crash ASAN reports alongside crash_replay.csv. Wipe first so a
    # re-run (FORCE=1) doesn't leave stale logs from a previous crash set.
    CRASH_LOG_DIR="$CAMPAIGN_DIR/crash_replay_logs"
    rm -rf "$CRASH_LOG_DIR"
    mkdir -p "$CRASH_LOG_DIR"

    echo "$CRASH_HEADER" > "$CAMPAIGN_DIR/.crash_replay.csv.tmp"

    crash_processed=0
    crash_all_none=0
    if [ ${#crash_files[@]} -eq 0 ]; then
        echo "No crash files found in $crash_dir"
    else
        echo "Replaying ${#crash_files[@]} crashes (parallel=$PARALLEL, timeout=${TIMEOUT}s)..."

        active_jobs=0
        for crash_file in "${crash_files[@]}"; do
            crash_fname=$(basename "$crash_file")
            result_file="$TMPDIR_REPLAY/crash_$crash_fname.result"
            exit_file="$TMPDIR_REPLAY/crash_$crash_fname.exit"
            # ASAN_OPTIONS is COLON-separated key=value pairs, so log_path
            # cannot contain ':'. AFL filenames embed colons in every field
            # (id:000000,sig:06,…). Sanitize ':' and ',' to '_' so libasan
            # parses the option string correctly.
            asan_prefix="$TMPDIR_REPLAY/crash_$(printf %s "$crash_fname" | tr ':,' '__').asan"

            (
                replay_one_input "$container" "$monitor_bin" "$target_bin" "$crash_file" "$result_file" "$asan_prefix" "$CRASH_ASAN_OPTIONS"
                echo $? > "$exit_file"
            ) &

            active_jobs=$((active_jobs + 1))
            if [[ $active_jobs -ge $PARALLEL ]]; then
                wait -n 2>/dev/null || true
                active_jobs=$((active_jobs - 1))
            fi
        done

        wait

        for crash_file in "${crash_files[@]}"; do
            crash_fname=$(basename "$crash_file")
            crash_meta=$(parse_crash_filename "$crash_fname")
            result_file="$TMPDIR_REPLAY/crash_$crash_fname.result"
            exit_file="$TMPDIR_REPLAY/crash_$crash_fname.exit"
            asan_prefix="$TMPDIR_REPLAY/crash_$(printf %s "$crash_fname" | tr ':,' '__').asan"

            exit_code=0
            [[ -f "$exit_file" ]] && exit_code=$(cat "$exit_file")

            if [[ -f "$result_file" && -s "$result_file" ]]; then
                canary_data=$(parse_canary_output "$result_file")
            else
                canary_data="none,none,none,none"
            fi
            asan_data=$(parse_asan_report "$asan_prefix" "$exit_code")

            # libasan writes one "<prefix>.<pid>" per process; concatenate any
            # that exist so the persisted log captures forked-child reports.
            crash_log="$CRASH_LOG_DIR/$crash_fname.asan.log"
            asan_logs=( "$asan_prefix".* )
            if [ -f "${asan_logs[0]}" ]; then
                cat "${asan_logs[@]}" > "$crash_log" 2>/dev/null || true
            else
                : > "$crash_log"
            fi

            echo "$fuzzer,$analyzer,$target,$program,$run_id,$crash_meta,$exit_code,$canary_data,$asan_data" \
                >> "$CAMPAIGN_DIR/.crash_replay.csv.tmp"

            [ "$canary_data" = "none,none,none,none" ] && crash_all_none=$((crash_all_none + 1))
            crash_processed=$((crash_processed + 1))
        done

        echo "Replayed $crash_processed crashes."
    fi

    # Guard against silent replay-pipeline failures. The monitor's
    # `--fetch watch` always reports counters (zeroed when the target writes
    # nothing to the storage file), so a bad container/node combination
    # produces exit_code=0 + all-none rows for every crash with no other
    # signal. Detect this BEFORE committing the .tmp to crash_replay.csv so
    # the next FORCE=0 re-run naturally reprocesses this campaign. Also
    # append the bad node to the shared exclude list so the dispatcher skips
    # it next time. Threshold avoids false alarms on small samples (single
    # non-bug crashes legitimately produce all-none rows).
    if [ "$crash_processed" -ge 5 ] && [ "$crash_all_none" -eq "$crash_processed" ]; then
        _bad_node="${SLURMD_NODENAME:-$(hostname)}"
        echo "ERROR: all $crash_processed replayed crashes returned no canary firings." >&2
        echo "       This usually indicates a broken container/node — node=$_bad_node." >&2

        # Don't commit the bad CSV — discard the .tmp and remove the partial
        # ASAN log dir so a re-run starts clean without needing FORCE=1.
        rm -f "$CAMPAIGN_DIR/.crash_replay.csv.tmp"
        rm -rf "$CRASH_LOG_DIR"

        # Append to the bad-nodes file (read by analyse_campaigns.sh on the
        # next run). Concurrent appends from sibling array tasks are fine —
        # the dispatcher dedupes on read.
        _bad_nodes_file="${MAGMA_BAD_NODES_FILE:-$HOME/.magma_bad_nodes}"
        if mkdir -p "$(dirname "$_bad_nodes_file")" 2>/dev/null \
           && printf '%s\n' "$_bad_node" >> "$_bad_nodes_file" 2>/dev/null; then
            echo "       Appended '$_bad_node' to $_bad_nodes_file." >&2
        else
            echo "       (could not append to $_bad_nodes_file — add manually)" >&2
        fi
        echo "       Re-run analyse_campaigns.sh; the dispatcher will exclude this node automatically." >&2
        exit 1
    fi

    mv "$CAMPAIGN_DIR/.crash_replay.csv.tmp" "$CRASH_OUT"
    rows=$(( $(wc -l < "$CRASH_OUT") - 1 ))
    echo "Crash replay done. Wrote $rows rows to $CRASH_OUT"
fi

rm -rf "$TMPDIR_REPLAY"

echo ""
echo "Done."
