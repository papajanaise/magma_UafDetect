#!/bin/bash
# monitor_campaign.sh — Process one fuzzing campaign's monitor data
#
# Expected environment variables (via sbatch --export):
#   CAMPAIGN_LIST  — path to campaign list file
#   LOG_DIR        — directory for partial CSV output
#
# Uses SLURM_ARRAY_TASK_ID to pick the campaign line.
set -euo pipefail

LINE=$(sed -n "${SLURM_ARRAY_TASK_ID}p" "$CAMPAIGN_LIST")
if [ -z "$LINE" ]; then
    echo "No campaign for task $SLURM_ARRAY_TASK_ID"
    exit 0
fi

IFS='|' read -r fuzzer target program run_id monitor_dir <<< "$LINE"
echo "Processing: $fuzzer / $target / $program (run $run_id)"

PARTIAL_CSV="$LOG_DIR/monitor_partial_${SLURM_ARRAY_TASK_ID}.csv"
: > "$PARTIAL_CSV"

declare -A first_reached first_triggered first_free seen_bugs
bug_count=0

timestamps=()
for f in "$monitor_dir"/*; do
    [ -f "$f" ] || continue
    ts=$(basename "$f")
    case "$ts" in tmp) continue ;; *[!0-9]*) continue ;; esac
    timestamps+=("$ts")
done

if [ ${#timestamps[@]} -eq 0 ]; then
    echo "No timestamps found."
    exit 0
fi
IFS=$'\n' sorted_ts=($(printf '%s\n' "${timestamps[@]}" | sort -n)); unset IFS

for ts in "${sorted_ts[@]}"; do
    fpath="$monitor_dir/$ts"
    [ -s "$fpath" ] || continue

    header="" data=""
    { IFS= read -r header; IFS= read -r data; } < "$fpath"
    [ -z "$header" ] && continue
    [ -z "$data" ] && continue

    IFS=',' read -ra cols <<< "$header"
    IFS=',' read -ra vals <<< "$data"

    for i in "${!cols[@]}"; do
        col="${cols[$i]}"
        val="${vals[$i]:-0}"

        if [[ "$col" == *_R ]]; then
            bug="${col%_R}"
            if [ -z "${seen_bugs[$bug]+x}" ]; then seen_bugs["$bug"]=1; bug_count=$((bug_count+1)); fi
            if [ "$val" -gt 0 ] 2>/dev/null && [ -z "${first_reached[$bug]+x}" ]; then
                first_reached["$bug"]="$ts"
            fi
        elif [[ "$col" == *_T ]]; then
            bug="${col%_T}"
            if [ -z "${seen_bugs[$bug]+x}" ]; then seen_bugs["$bug"]=1; bug_count=$((bug_count+1)); fi
            if [ "$val" -gt 0 ] 2>/dev/null && [ -z "${first_triggered[$bug]+x}" ]; then
                first_triggered["$bug"]="$ts"
            fi
        elif [[ "$col" == *_F ]]; then
            bug="${col%_F}"
            if [ -z "${seen_bugs[$bug]+x}" ]; then seen_bugs["$bug"]=1; bug_count=$((bug_count+1)); fi
            if [ "$val" -gt 0 ] 2>/dev/null && [ -z "${first_free[$bug]+x}" ]; then
                first_free["$bug"]="$ts"
            fi
        fi
    done
done

if [ "$bug_count" -eq 0 ]; then
    echo "$fuzzer,$target,$program,$run_id,(no data),-,-,-" >> "$PARTIAL_CSV"
else
    for bug in $(printf '%s\n' "${!seen_bugs[@]}" | sort); do
        r="${first_reached[$bug]:--}"
        t="${first_triggered[$bug]:--}"
        f="${first_free[$bug]:--}"
        echo "$fuzzer,$target,$program,$run_id,$bug,$r,$t,$f" >> "$PARTIAL_CSV"
    done
fi

echo "Done. Wrote $(wc -l < "$PARTIAL_CSV") rows."
