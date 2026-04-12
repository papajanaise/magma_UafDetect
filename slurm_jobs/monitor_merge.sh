#!/bin/bash
# monitor_merge.sh — Merge partial monitor CSVs into final MONITOR_CSV
#
# Expected environment variables (via sbatch --export):
#   LOG_DIR      — directory containing monitor_partial_*.csv files
#   MONITOR_CSV  — output path for merged CSV
set -euo pipefail

format_time() {
    local secs="$1"
    if [ -z "$secs" ] || [ "$secs" = "-" ]; then
        echo "-"
        return
    fi
    local h=$((secs / 3600))
    local m=$(( (secs % 3600) / 60 ))
    local s=$((secs % 60))
    printf "%d:%02d:%02d" "$h" "$m" "$s"
}

echo "========================================================================"
echo "Part 1: Monitor analysis — merging partial results"
echo "========================================================================"
echo ""

echo "fuzzer,analyzer,target,program,run,bug,reached_s,triggered_s,free_reached_s" > "$MONITOR_CSV"

for partial in "$LOG_DIR"/monitor_partial_*.csv; do
    [ -f "$partial" ] || continue
    cat "$partial" >> "$MONITOR_CSV"
done

total=$(( $(wc -l < "$MONITOR_CSV") - 1 ))
echo "Merged $total rows into $MONITOR_CSV"
echo ""

# Print formatted table
{
    printf "%-25s %-12s %-15s %-35s %-10s %-12s %10s %10s %12s\n" \
        "FUZZER" "ANALYZER" "TARGET" "PROGRAM" "RUN" "BUG" "REACHED" "TRIGGERED" "FREE_REACHED"
    printf '%0.s-' {1..148}
    echo

    tail -n +2 "$MONITOR_CSV" | sort -t, -k1,1 -k2,2 -k3,3 -k4,4 -k6,6 -k5,5 | while IFS=',' read -r fuzzer analyzer target program run bug reached triggered free_reached; do
        r_fmt=$(format_time "$reached")
        t_fmt=$(format_time "$triggered")
        f_fmt=$(format_time "$free_reached")
        printf "%-25s %-12s %-15s %-35s %-10s %-12s %10s %10s %12s\n" \
            "$fuzzer" "${analyzer:--}" "$target" "$program" "$run" "$bug" "$r_fmt" "$t_fmt" "$f_fmt"
    done
}

echo ""
echo "Part 1 (Monitor analysis) complete."
