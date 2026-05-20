#!/usr/bin/env bash
# generate_afl_log_plot_data.sh — Erzeugt Plot-ready CSVs aus den Event-CSVs
#
# Eingabe (in IN_DIR, default: aktuelles Verzeichnis):
#   bitmask_progress.csv, free_found.csv, use_free_found.csv, alias_ratio.csv
#
# Ausgabe (in OUT_DIR):
#   Pro Target (z.B. expat, sqlite3) je eine CSV pro Plot.
#
# Schemata:
#   plot1_bitmask_<target>.csv       campaign,queue_entry,cumulative_events
#   plot2_free_<target>.csv          campaign,queue_entry,cumulative_free
#   plot2_usefree_<target>.csv       campaign,queue_entry,cumulative_usefree
#   plot4_alias_<target>.csv         campaign,total,ratio
#
#   campaigns_per_target.txt         Liste der Campaign-IDs pro Target

set -euo pipefail

IN_DIR="${IN_DIR:-.}"
OUT_DIR="${OUT_DIR:-.}"
mkdir -p "$OUT_DIR"

cumulate_per_campaign() {
    # Liest stdin (campaign,queue_entry-Paare), sortiert, kumuliert pro Campaign
    sort -t, -k1,1 -k2,2n | \
        awk -F, 'BEGIN {OFS=","}
            {
                if ($1 != prev) { prev = $1; cum = 0 }
                cum++
                print $1, $2, cum
            }'
}

targets=$(tail -n +2 "$IN_DIR/bitmask_progress.csv" | cut -d, -f1 | sort -u)
if [ -z "$targets" ]; then
    echo "ERROR: no targets in $IN_DIR/bitmask_progress.csv" >&2
    exit 1
fi

echo "discovered targets:" >&2
echo "$targets" | sed 's/^/  /' >&2

# Campaign-IDs-Liste schreiben
: > "$OUT_DIR/campaigns_per_target.txt"

for target in $targets; do
    safe_target=$(echo "$target" | tr '/ ' '__')

    # Plot 1
    {
        echo "campaign,queue_entry,cumulative_events"
        awk -F, -v t="$target" '$1==t {print $2","$4}' \
            "$IN_DIR/bitmask_progress.csv" | cumulate_per_campaign
    } > "$OUT_DIR/plot1_bitmask_${safe_target}.csv"

    # Plot 2a (Free)
    {
        echo "campaign,queue_entry,cumulative_free"
        awk -F, -v t="$target" '$1==t {print $2","$4}' \
            "$IN_DIR/free_found.csv" | cumulate_per_campaign
    } > "$OUT_DIR/plot2_free_${safe_target}.csv"

    # Plot 2b (Use+Free)
    {
        echo "campaign,queue_entry,cumulative_usefree"
        awk -F, -v t="$target" '$1==t {print $2","$4}' \
            "$IN_DIR/use_free_found.csv" | cumulate_per_campaign
    } > "$OUT_DIR/plot2_usefree_${safe_target}.csv"

    # Plot 4 (Alias)
    {
        echo "campaign,total,ratio"
        awk -F, -v t="$target" '$1==t {print $2","$5","$6}' \
            "$IN_DIR/alias_ratio.csv" | sort -t, -k1,1 -k2,2n
    } > "$OUT_DIR/plot4_alias_${safe_target}.csv"

    # Campaign-IDs als komma-getrennte Liste (für \foreach)
    cids=$(awk -F, -v t="$target" '$1==t {print $2}' "$IN_DIR/bitmask_progress.csv" \
           | sort -u | paste -sd ',' -)
    echo "$target: $cids" >> "$OUT_DIR/campaigns_per_target.txt"
done

echo "" >&2
echo "wrote per-target CSVs to: $OUT_DIR/" >&2
echo "campaign IDs in: $OUT_DIR/campaigns_per_target.txt" >&2
cat "$OUT_DIR/campaigns_per_target.txt" >&2