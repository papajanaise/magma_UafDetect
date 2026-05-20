#!/usr/bin/env bash
# aggregate_table.sh — Extrahiert die vier Tabellenspalten aus free_finder-Logs
#
# Spalten:
#   1. num_counters                 = Wert von "FreeSiteCount value:"
#   2. avg_deallocs_per_counter     = arith. Mittel von "deallocs=" über alle
#                                     [FREE-CHAIN-INNER]-Zeilen
#   3. avg_outer_chain_bbs          = arith. Mittel von (preOuterInter +
#                                     preOuterIntra) über alle [FREE-CHAIN]-Zeilen
#   4. avg_inner_chain_bbs_per_dealloc
#                                   = arith. Mittel der Per-Counter-Quoten
#                                     (chainBBs / deallocs) über alle
#                                     [FREE-CHAIN-INNER]-Zeilen mit deallocs > 0
#
# Usage:
#   ./aggregate_table.sh path/to/logs/*.log > table.csv

set -euo pipefail

echo "program,num_counters,avg_deallocs_per_counter,avg_outer_chain_bbs,avg_outer_inter_pct,avg_inner_chain_bbs_per_dealloc"

for f in "$@"; do
  [ -f "$f" ] || continue

  # Programmname = Logfile-Basename ohne Endung
  prog=$(basename "$f")
  prog="${prog%.log}"
  prog="${prog%.bc}"

  awk -v PROG="$prog" '
    BEGIN {
      counters = 0
      sumD = 0; nD = 0                 # für Spalte 2
      sumOuter = 0; nOuter = 0         # für Spalte 3
      sumInter = 0                     # für Spalte 3 (Inter-Anteil)
      sumInnerRatio = 0; nInnerRatio = 0   # für Spalte 4
    }

    # --- Spalte 1: Counter-Anzahl ---
    /^FreeSiteCount value:/ {
      counters = $NF
      next
    }

    # --- Spalte 3: Outer-Chain (preOuterInter + preOuterIntra) ---
    /\[FREE-CHAIN\] counter=/ {
      pi = 0; pa = 0
      for (i=1; i<=NF; i++) {
        if ($i ~ /^preOuterInter=/) { split($i, a, "="); pi = a[2] + 0 }
        if ($i ~ /^preOuterIntra=/) { split($i, a, "="); pa = a[2] + 0 }
      }
      sumOuter += (pi + pa)
      sumInter += pi
      nOuter++
      next
    }

    # --- Spalte 2 + Spalte 4: Inner-Chain ---
    /\[FREE-CHAIN-INNER\] counter=/ {
      d = 0; cbb = 0
      for (i=1; i<=NF; i++) {
        if ($i ~ /^deallocs=/) { split($i, a, "="); d = a[2] + 0 }
        if ($i ~ /^chainBBs=/) { split($i, a, "="); cbb = a[2] + 0 }
      }
      # Spalte 2: durchschnittliche Deallocs pro Wrapper-Counter
      sumD += d
      nD++
      # Spalte 4: Per-Counter-Quote (BBs pro einzelnem Inner-Pfad)
      if (d > 0) {
        sumInnerRatio += cbb / d
        nInnerRatio++
      }
      next
    }

    END {
      avgD     = (nD          ? sumD / nD                     : 0)
      avgOuter = (nOuter      ? sumOuter / nOuter             : 0)
      avgInter = (nOuter      ? sumInter / nOuter             : 0)
      interPct = (avgOuter > 0 ? (avgInter / avgOuter) * 100   : 0)
      avgInner = (nInnerRatio ? sumInnerRatio / nInnerRatio   : 0)
      printf "%s,%d,%.2f,%.2f,%.2f,%.2f\n",
             PROG, counters, avgD, avgOuter, interPct, avgInner
    }
  ' "$f"
done