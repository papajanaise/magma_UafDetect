#!/bin/bash
# bug_comparison.sh — Compare bug detection across fuzzers
#
# Expected environment variables (via sbatch --export):
#   MONITOR_CSV  — monitor analysis CSV (from Part 1)
#   CRASH_CSV    — crash bug mapping CSV (from Part 2)
#   BUG_CSV      — output path for bug comparison CSV
set -euo pipefail

echo "========================================================================"
echo "Part 3: Bug comparison across fuzzers"
echo "========================================================================"
echo ""

# Two-file awk: MONITOR_CSV (file 1) then CRASH_CSV (file 2)
# Monitor CSV: fuzzer,target,program,run,bug,reached_s,triggered_s,free_reached_s
# Crash CSV:   fuzzer,target,program,run_id,crash_id,signal,time_ms,replay_exit_code,bugs_reached,bugs_triggered,bugs_free_reached
awk -F',' '

function isort(arr, n,    i, j, tmp) {
    for (i = 2; i <= n; i++) {
        tmp = arr[i]
        j = i - 1
        while (j >= 1 && arr[j] > tmp) {
            arr[j+1] = arr[j]
            j--
        }
        arr[j+1] = tmp
    }
}

# File 1: Monitor CSV — reached/triggered/free_reached (seconds)
# Take minimum time across programs for each bug+fuzzer
FILENAME == ARGV[1] && FNR > 1 {
    fuzzer = $1; target = $2; bug = $5
    reached_s = $6; triggered_s = $7; free_s = $8

    if (bug == "(no data)") next

    all_bugs[bug] = target
    all_fuzzers[fuzzer] = 1
    key = bug SUBSEP fuzzer

    if (reached_s != "-" && reached_s + 0 > 0) {
        if (!(key in mon_reached) || reached_s + 0 < mon_reached[key] + 0)
            mon_reached[key] = reached_s + 0
    }
    if (triggered_s != "-" && triggered_s + 0 > 0) {
        if (!(key in mon_triggered) || triggered_s + 0 < mon_triggered[key] + 0)
            mon_triggered[key] = triggered_s + 0
    }
    if (free_s != "-" && free_s + 0 > 0) {
        if (!(key in mon_free) || free_s + 0 < mon_free[key] + 0)
            mon_free[key] = free_s + 0
    }
    next
}

# File 2: Crash CSV — first crash time and crash count per bug+fuzzer
FILENAME == ARGV[2] && FNR > 1 {
    fuzzer = $1; target = $2; time_ms = $7 + 0

    # Collect all bug IDs mentioned in this crash (from replay columns)
    delete row_bugs
    if ($9 != "none")  { split($9,  _b, ";"); for (i in _b) { gsub(/\([0-9]+\)/, "", _b[i]); row_bugs[_b[i]] = 1 } }
    if ($10 != "none") { split($10, _b, ";"); for (i in _b) { gsub(/\([0-9]+\)/, "", _b[i]); row_bugs[_b[i]] = 1 } }
    if ($11 != "none") { split($11, _b, ";"); for (i in _b) { gsub(/\([0-9]+\)/, "", _b[i]); row_bugs[_b[i]] = 1 } }

    for (bug in row_bugs) {
        all_bugs[bug] = target
        all_fuzzers[fuzzer] = 1
        key = bug SUBSEP fuzzer

        # First crash time (ms)
        if (!(key in first_crash) || time_ms < first_crash[key])
            first_crash[key] = time_ms

        # Crash count
        crash_count[key]++
    }
    next
}

END {
    nf = 0
    for (k in all_fuzzers) sorted_fuzzers[++nf] = k
    isort(sorted_fuzzers, nf)

    # CSV header
    printf "bug,target"
    for (fi = 1; fi <= nf; fi++) {
        f = sorted_fuzzers[fi]
        printf ",%s_first_crash_s,%s_num_crashes,%s_reached_s,%s_triggered_s,%s_free_reached_s", f, f, f, f, f
    }
    printf "\n"

    nb = 0
    for (k in all_bugs) sorted_bugs[++nb] = k
    isort(sorted_bugs, nb)

    for (bi = 1; bi <= nb; bi++) {
        bug = sorted_bugs[bi]
        target = all_bugs[bug]
        printf "%s,%s", bug, target
        for (fi = 1; fi <= nf; fi++) {
            f = sorted_fuzzers[fi]
            key = bug SUBSEP f

            # First crash time: convert ms -> s
            if (key in first_crash) {
                fc = int(first_crash[key] / 1000)
            } else {
                fc = "-"
            }
            nc = (key in crash_count) ? crash_count[key] : 0
            mr = (key in mon_reached)   ? mon_reached[key]   : "-"
            mt = (key in mon_triggered) ? mon_triggered[key] : "-"
            mf = (key in mon_free)      ? mon_free[key]      : "-"

            printf ",%s,%s,%s,%s,%s", fc, nc, mr, mt, mf
        }
        printf "\n"
    }
}
' "$MONITOR_CSV" "$CRASH_CSV" > "$BUG_CSV"

echo "Bug comparison CSV written to: $BUG_CSV"
echo ""

# Print formatted table
awk -F',' '
function fmt_s(val) {
    if (val == "-" || val == "") return "-"
    s = val + 0
    h = int(s / 3600)
    m = int((s % 3600) / 60)
    sec = s % 60
    return sprintf("%d:%02d:%02d", h, m, sec)
}
NR == 1 {
    # Parse fuzzers from header (every 5 columns starting at col 3)
    for (i = 3; i <= NF; i += 5) {
        split($i, parts, "_first_crash")
        fuzzers[++nf] = parts[1]
    }

    printf "%-12s %-10s", "BUG", "TARGET"
    for (fi = 1; fi <= nf; fi++) {
        printf " | %-10s %-8s %-10s %-10s %-10s", \
            fuzzers[fi] "_crash", "n_crash", fuzzers[fi] "_reach", fuzzers[fi] "_trig", fuzzers[fi] "_free"
    }
    printf "\n"
    for (i = 0; i < 24 + nf * 56; i++) printf "-"
    printf "\n"
    next
}
{
    printf "%-12s %-10s", $1, $2
    col = 3
    for (fi = 1; fi <= nf; fi++) {
        printf " | %-10s %-8s %-10s %-10s %-10s", \
            fmt_s($col), $(col+1), fmt_s($(col+2)), fmt_s($(col+3)), fmt_s($(col+4))
        col += 5
    }
    printf "\n"
}
' "$BUG_CSV"

echo ""
echo "========================================================================"
echo "Output files:"
echo "  Monitor analysis:  $MONITOR_CSV"
echo "  Crash bug mapping: $CRASH_CSV"
echo "  Bug comparison:    $BUG_CSV"
echo "========================================================================"
echo ""
echo "Part 3 (Bug comparison) complete."
