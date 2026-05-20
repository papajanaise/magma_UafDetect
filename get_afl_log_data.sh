#!/usr/bin/env bash
# get_afl_log_data.sh — Auto-discover die letzten N Kampagnen pro Harness und
# extrahiere alle UAF-Events aus afl_coverage_log.txt in CSVs.
#
# Usage:
#   ./get_afl_log_data.sh HARNESS_DIR [HARNESS_DIR ...]
#
# Beispiel:
#   ./get_afl_log_data.sh \
#     magma_results/afl_uaf_detect/free_finder/expat/xml_parsebuffer_fuzzer_UTF-8 \
#     magma_results/afl_uaf_detect/free_finder/sqlite3/sqlite3_fuzz
#
# Verhalten:
#   - target  = Basename des Parent-Dir von HARNESS_DIR
#               (z.B. "expat", "sqlite3")
#   - In jedem HARNESS_DIR werden numerische Subdirs gesucht;
#     die N höchsten IDs werden verwendet (default N=10).
#   - Pro Campaign: <ID>/findings/default/afl_coverage_log.txt
#
# Environment-Variablen:
#   OUT_DIR         = Ausgabeverzeichnis (default: .)
#   NUM_CAMPAIGNS   = wie viele Kampagnen pro Harness (default: 10)
#   LOG_RELPATH     = relativer Pfad zum Logfile (default: findings/default/afl_coverage_log.txt)

set -euo pipefail

OUT_DIR="${OUT_DIR:-.}"
NUM_CAMPAIGNS="${NUM_CAMPAIGNS:-10}"
LOG_RELPATH="${LOG_RELPATH:-findings/default/afl_coverage_log.txt}"
mkdir -p "$OUT_DIR"

# CSV-Header
echo "target,campaign_id,counter,queue_entry,bitmask"           > "$OUT_DIR/bitmask_progress.csv"
echo "target,campaign_id,counter,queue_entry,hit_count"         > "$OUT_DIR/hit_count_progress.csv"
echo "target,campaign_id,counter,queue_entry,initial_bitmask"   > "$OUT_DIR/free_found.csv"
echo "target,campaign_id,counter,queue_entry"                   > "$OUT_DIR/use_free_found.csv"
echo "target,campaign_id,counter,queue_entry"                   > "$OUT_DIR/use_no_free.csv"
echo "target,campaign_id,rebuild_seq,with_weight,total,ratio"   > "$OUT_DIR/alias_ratio.csv"

for harness_dir in "$@"; do
    if [ ! -d "$harness_dir" ]; then
        echo "WARN: not a directory: $harness_dir" >&2
        continue
    fi
    harness_dir="${harness_dir%/}"
    target=$(basename "$(dirname "$harness_dir")")

    # Numerische Subdirs identifizieren, absteigend nach Zahlenwert sortieren,
    # die ersten NUM_CAMPAIGNS nehmen
    campaign_ids=$(
        for d in "$harness_dir"/*/; do
            [ -d "$d" ] || continue
            base=$(basename "$d")
            [[ "$base" =~ ^[0-9]+$ ]] && echo "$base"
        done | sort -nr | head -n "$NUM_CAMPAIGNS"
    )

    if [ -z "$campaign_ids" ]; then
        echo "WARN: no numeric campaign subdirs in $harness_dir" >&2
        continue
    fi

    n_found=$(echo "$campaign_ids" | wc -l)
    echo "=== target=$target  harness=$(basename "$harness_dir")  campaigns=$n_found ===" >&2

    for cid in $campaign_ids; do
        log_file="$harness_dir/$cid/$LOG_RELPATH"
        if [ ! -f "$log_file" ]; then
            echo "  WARN: missing $log_file" >&2
            continue
        fi
        echo "  [$target] processing campaign $cid" >&2

        awk -v T="$target" -v C="$cid" -v OUT="$OUT_DIR" '
            # --- "Higher UafPathVisitBitmask for Counter X found: M by Queue Entry Q" ---
            /\[UAF DETECT\] Higher UafPathVisitBitmask for Counter/ {
                c=""; m=""; e=""
                for (i=1; i<=NF; i++) {
                    if ($i == "Counter") { c = $(i+1); gsub(/:/, "", c) }
                    if ($i == "found:")  { m = $(i+1) }
                    if ($i == "Entry")   { e = $(i+1) }
                }
                if (c != "" && m != "" && e != "")
                    print T "," C "," c "," e "," m >> OUT "/bitmask_progress.csv"
                next
            }

            # --- "Higher UafPathBlockHitCount for Counter X found: H by Queue Entry Q" ---
            /\[UAF DETECT\] Higher UafPathBlockHitCount for Counter/ {
                c=""; h=""; e=""
                for (i=1; i<=NF; i++) {
                    if ($i == "Counter") { c = $(i+1); gsub(/:/, "", c) }
                    if ($i == "found:")  { h = $(i+1) }
                    if ($i == "Entry")   { e = $(i+1) }
                }
                if (c != "" && h != "" && e != "")
                    print T "," C "," c "," e "," h >> OUT "/hit_count_progress.csv"
                next
            }

            # --- "Free found for Counter X: visit bitmask = M by Queue Entry Q" ---
            # (dedupliziert pro Counter; die parallele "block hit count"-Zeile
            # wird ignoriert, da redundant)
            /\[UAF DETECT\] Free found for Counter [0-9]+: visit bitmask/ {
                c=""; m=""; e=""
                for (i=1; i<=NF; i++) {
                    if ($i == "Counter") { c = $(i+1); gsub(/:/, "", c) }
                    if ($i == "bitmask") { m = $(i+2) }   # +2 überspringt "="
                    if ($i == "Entry")   { e = $(i+1) }
                }
                if (c != "" && !(c in free_seen)) {
                    free_seen[c] = 1
                    print T "," C "," c "," e "," m >> OUT "/free_found.csv"
                }
                next
            }

            # --- "Use+Free found for Counter X by Queue Entry Q" ---
            /\[UAF DETECT\] Use\+Free found for Counter/ {
                c=""; e=""
                for (i=1; i<=NF; i++) {
                    if ($i == "Counter") { c = $(i+1); gsub(/:/, "", c) }
                    if ($i == "Entry")   { e = $(i+1) }
                }
                if (c != "" && !(c in usefree_seen)) {
                    usefree_seen[c] = 1
                    print T "," C "," c "," e >> OUT "/use_free_found.csv"
                }
                next
            }

            # --- "Use found WITHOUT free for Counter X by Queue Entry Q (low priority)" ---
            /\[UAF DETECT\] Use found WITHOUT free for Counter/ {
                c=""; e=""
                for (i=1; i<=NF; i++) {
                    if ($i == "Counter") { c = $(i+1); gsub(/:/, "", c) }
                    if ($i == "Entry")   { e = $(i+1) }
                }
                if (c != "" && !(c in usenofree_seen)) {
                    usenofree_seen[c] = 1
                    print T "," C "," c "," e >> OUT "/use_no_free.csv"
                }
                next
            }

            # --- "[UAF ALIAS] N entries with UAF weight out of M total" ---
            # Feste Feldpositionen: $3 = N, $10 = M
            /\[UAF ALIAS\] [0-9]+ entries with UAF weight out of [0-9]+ total/ {
                w = $3 + 0
                t = $10 + 0
                if (t > 0) {
                    rebuild_seq++
                    printf "%s,%s,%d,%d,%d,%.6f\n", T, C, rebuild_seq, w, t, w/t \
                        >> OUT "/alias_ratio.csv"
                }
                next
            }
        ' "$log_file"
    done
done

echo "" >&2
echo "wrote CSVs to: $OUT_DIR/" >&2
wc -l "$OUT_DIR"/*.csv >&2