#!/bin/bash
# results_collect.sh — Collect pre-computed per-campaign CSVs into merged files.
#
# Reads monitor_analysis.csv and crash_replay.csv from each campaign directory,
# applies label substitution, and concatenates into the merged output files.
#
# Expected environment variables (via sbatch --export):
#   CAMPAIGN_LIST  — path to campaign list file
#   MONITOR_CSV    — output path for merged monitor analysis CSV
#   CRASH_CSV      — output path for merged crash bug mapping CSV
set -euo pipefail

echo "========================================================================"
echo "Collecting pre-computed campaign results"
echo "========================================================================"
echo ""

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

###############################################################################
# Collect monitor analysis
###############################################################################

echo "--- Monitor analysis ---"
echo "fuzzer,analyzer,target,program,run,bug,reached_s,triggered_s,free_reached_s" > "$MONITOR_CSV"

monitor_errors=0
monitor_rows=0

while IFS='|' read -r fuzzer analyzer label target program run_id program_dir; do
    campaign_dir="$program_dir$run_id"
    csv="$campaign_dir/monitor_analysis.csv"

    if [ ! -f "$csv" ]; then
        echo "  [ERROR] Missing: $csv" >&2
        monitor_errors=$((monitor_errors + 1))
        continue
    fi

    # Strip header, replace column 2 (analyzer) with label
    tail -n +2 "$csv" | awk -F',' -v lbl="$label" 'OFS="," { $2 = lbl; print }' >> "$MONITOR_CSV"
    n=$(( $(wc -l < "$csv") - 1 ))
    monitor_rows=$((monitor_rows + n))
done < "$CAMPAIGN_LIST"

echo "Merged $monitor_rows monitor rows into $MONITOR_CSV"

if [ "$monitor_errors" -gt 0 ]; then
    echo "WARNING: $monitor_errors campaigns had missing monitor_analysis.csv" >&2
fi

echo ""

###############################################################################
# Collect crash replay
###############################################################################

echo "--- Crash replay ---"
echo "fuzzer,analyzer,target,program,run_id,crash_id,signal,time_ms,replay_exit_code,bugs_reached,bugs_triggered,bugs_free_reached" > "$CRASH_CSV"

crash_errors=0
crash_rows=0

while IFS='|' read -r fuzzer analyzer label target program run_id program_dir; do
    campaign_dir="$program_dir$run_id"
    csv="$campaign_dir/crash_replay.csv"

    if [ ! -f "$csv" ]; then
        echo "  [ERROR] Missing: $csv" >&2
        crash_errors=$((crash_errors + 1))
        continue
    fi

    # Strip header, replace column 2 (analyzer) with label
    tail -n +2 "$csv" | awk -F',' -v lbl="$label" 'OFS="," { $2 = lbl; print }' >> "$CRASH_CSV"
    n=$(( $(wc -l < "$csv") - 1 ))
    crash_rows=$((crash_rows + n))
done < "$CAMPAIGN_LIST"

echo "Merged $crash_rows crash rows into $CRASH_CSV"

if [ "$crash_errors" -gt 0 ]; then
    echo "WARNING: $crash_errors campaigns had missing crash_replay.csv" >&2
fi

echo ""

###############################################################################
# Print formatted monitor summary table
###############################################################################

{
    printf "%-25s %-12s %-15s %-35s %-10s %-12s %10s %10s %12s\n" \
        "FUZZER" "ANALYZER" "TARGET" "PROGRAM" "RUN" "BUG" "REACHED" "TRIGGERED" "FREE_REACHED"
    printf '%0.s-' {1..148}
    echo

    tail -n +2 "$MONITOR_CSV" | sort -t, -k1,1 -k2,2 -k3,3 -k4,4 -k6,6 -k5,5 | \
    while IFS=',' read -r fuzzer analyzer target program run bug reached triggered free_reached; do
        r_fmt=$(format_time "$reached")
        t_fmt=$(format_time "$triggered")
        f_fmt=$(format_time "$free_reached")
        printf "%-25s %-12s %-15s %-35s %-10s %-12s %10s %10s %12s\n" \
            "$fuzzer" "${analyzer:--}" "$target" "$program" "$run" "$bug" "$r_fmt" "$t_fmt" "$f_fmt"
    done
}

echo ""

total_errors=$((monitor_errors + crash_errors))
if [ "$total_errors" -gt 0 ]; then
    echo "ERROR: $total_errors campaigns had missing results. Run analyse_campaigns.sh first." >&2
    exit 1
fi

echo "Collection complete."
