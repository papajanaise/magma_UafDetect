#!/bin/bash
# monitor_campaign.sh — Process one fuzzing campaign's monitor data
#
# Expected environment variables (via sbatch --export):
#   CAMPAIGN_LIST  — path to campaign list file
#   LOG_DIR        — directory for partial CSV output
#
# Uses SLURM_ARRAY_TASK_ID to pick the campaign line.
set -euo pipefail

# On any failure, cancel the downstream jobs that depend on this array with
# afterok, so they don't hang forever in DependencyNeverSatisfied state.
on_error() {
    local rc=$?
    echo "ERROR: monitor_campaign task ${SLURM_ARRAY_TASK_ID} failed (exit $rc)." >&2
    if [ -n "${LOG_DIR:-}" ] && [ -f "$LOG_DIR/downstream_jobs.txt" ]; then
        local dep_jobs
        dep_jobs=$(tr '\n' ' ' < "$LOG_DIR/downstream_jobs.txt")
        if [ -n "$dep_jobs" ]; then
            echo "dependency can not be satisfied — cancelling downstream jobs: $dep_jobs" >&2
            scancel $dep_jobs 2>/dev/null || true
        fi
    fi
    exit "$rc"
}
trap on_error ERR

LINE=$(sed -n "${SLURM_ARRAY_TASK_ID}p" "$CAMPAIGN_LIST")
if [ -z "$LINE" ]; then
    echo "No campaign for task $SLURM_ARRAY_TASK_ID"
    exit 0
fi

IFS='|' read -r fuzzer analyzer label target program run_id monitor_dir <<< "$LINE"
echo "Processing: $fuzzer${analyzer:+/$analyzer} / $target / $program (run $run_id, label=$label)"

PARTIAL_CSV="$LOG_DIR/monitor_partial_${SLURM_ARRAY_TASK_ID}.csv"

# Build a sorted list of numeric timestamp filenames.
FILE_LIST=$(mktemp)
trap 'rm -f "$FILE_LIST"; on_error' ERR
trap 'rm -f "$FILE_LIST"' EXIT

for f in "$monitor_dir"/*; do
    [ -f "$f" ] || continue
    ts=$(basename "$f")
    case "$ts" in tmp) continue ;; *[!0-9]*) continue ;; esac
    echo "$ts"
done | sort -n > "$FILE_LIST"

num_files=$(wc -l < "$FILE_LIST")
if [ "$num_files" -eq 0 ]; then
    echo "No timestamps found."
    : > "$PARTIAL_CSV"
    exit 0
fi

echo "Processing $num_files monitor snapshots with awk..."

# Process all monitor files in bulk with awk — reads each file via getline,
# avoiding per-file bash string parsing which is the main bottleneck.
awk -v dir="$monitor_dir" \
    -v prefix="$fuzzer,$label,$target,$program,$run_id" \
    '
BEGIN {
    file_list = ARGV[1]
    bug_count = 0

    while ((getline ts < file_list) > 0) {
        fpath = dir "/" ts
        header = ""
        data = ""
        if ((getline header < fpath) > 0) {
            getline data < fpath
        }
        close(fpath)

        if (header == "" || data == "") continue

        n = split(header, cols, ",")
        split(data, vals, ",")

        for (i = 1; i <= n; i++) {
            col = cols[i]
            val = vals[i] + 0

            # Skip columns with non bug-id characters (corrupted IDs).
            if (col ~ /[^A-Za-z0-9_.\-]/) continue

            if (match(col, /_R$/)) {
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
            } else if (match(col, /_F$/)) {
                bug = substr(col, 1, length(col) - 2)
                if (bug == "") continue
                seen[bug] = 1
                if (val > 0 && !(bug in first_free))
                    first_free[bug] = ts
            }
        }
    }
    close(file_list)

    # Collect and sort bug names.
    n_bugs = 0
    for (bug in seen) {
        bugs[++n_bugs] = bug
    }

    if (n_bugs == 0) {
        print prefix ",(no data),-,-,-"
    } else {
        # Simple insertion sort (bug count is small).
        for (i = 2; i <= n_bugs; i++) {
            key = bugs[i]
            j = i - 1
            while (j > 0 && bugs[j] > key) {
                bugs[j + 1] = bugs[j]
                j--
            }
            bugs[j + 1] = key
        }
        for (i = 1; i <= n_bugs; i++) {
            bug = bugs[i]
            r = (bug in first_reached)   ? first_reached[bug]   : "-"
            t = (bug in first_triggered) ? first_triggered[bug] : "-"
            f = (bug in first_free)      ? first_free[bug]      : "-"
            print prefix "," bug "," r "," t "," f
        }
    }
}
' "$FILE_LIST" > "$PARTIAL_CSV"

echo "Done. Wrote $(wc -l < "$PARTIAL_CSV") rows."
