#!/bin/bash
#
# Report UAF-batch campaign status by querying Slurm directly.
# For every (uaf_NNN x analyzer) pair derivable from binaries in
# $BATCH_DIR, show whether a campaign is currently running (with
# elapsed time) or missing.

BATCH_DIR="${BATCH_DIR:-/home/users/m/m.thielebein/uaf_batch}"

# squeue snapshot: "jobid|state|jobname|elapsed"
ACTIVE_JOBS=$(squeue --me -h -o '%i|%T|%j|%M' 2>/dev/null)

# If a job whose name matches $1 exactly is active, print "JOBID STATE ELAPSED".
job_by_name() {
    local name="$1"
    awk -F'|' -v n="$name" '$3 == n {print $1, $2, $4; exit}' <<< "$ACTIVE_JOBS"
}

shopt -s nullglob
binaries=("$BATCH_DIR"/uaf_*_free_finder_instr "$BATCH_DIR"/uaf_*_svf_instr)
if [ ${#binaries[@]} -eq 0 ]; then
    echo "No uaf_*_{free_finder,svf}_instr binaries in $BATCH_DIR" >&2
    exit 1
fi

# Sort by basename for stable output.
mapfile -t binaries < <(printf '%s\n' "${binaries[@]}" | sort)

running=0
pending=0
missing=0
no_binary=0

echo "== UAF batch campaigns =="
for bin in "${binaries[@]}"; do
    name="$(basename "$bin")"
    case "$name" in
        *_free_finder_instr) analyzer="free_finder"; test_id="${name%_free_finder_instr}" ;;
        *_svf_instr)         analyzer="svf";         test_id="${name%_svf_instr}" ;;
    esac
    label=$(printf '  %-10s [%-11s]' "$test_id" "$analyzer")

    if [ ! -x "$bin" ]; then
        echo "$label  no binary"
        ((no_binary++))
        continue
    fi

    active=$(job_by_name "uaf_${name}")
    if [ -n "$active" ]; then
        read -r jid state elapsed <<< "$active"
        case "$state" in
            RUNNING) ((running++)) ;;
            *)       ((pending++)) ;;
        esac
        printf '%s  %-8s %-10s (job %s)\n' "$label" "$state" "$elapsed" "$jid"
    else
        echo "$label  missing"
        ((missing++))
    fi
done

total=${#binaries[@]}
echo ""
echo "Summary: $running running, $pending pending, $missing missing, $no_binary no-binary (out of $total)"
