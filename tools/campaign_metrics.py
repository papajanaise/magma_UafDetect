#!/usr/bin/env python3
"""Per-campaign metrics tables per (fuzzer[, analyzer], target, program).

Reads per-campaign outputs of analyse_campaigns.sh (monitor_analysis.csv,
crash_replay.csv) plus raw AFL plot_data / fuzzer_stats / queue. Outputs:

* metrics_<group>.csv (wide, bugs x runs)
    Two-row header: run_id repeated across 3 sub-columns, then
    crashes,ttfc_s,etfc. Scalar rows (branch_coverage, unique_crashes,
    execs_per_sec, total_executions, corpus_size) use the crashes sub-column.

* general_stats/general_stats_<group>.csv
    One row per campaign, columns:
    run_id,branch_coverage,unique_crashes,execs_per_sec,total_executions,corpus_size

* per_bug/bug_<BUGID>_<group>.csv (one file per bug encountered in any of N runs)
    One row per campaign, columns:
    run_id,first_crash_s,num_crashes,etfc,reached_s,triggered_s,free_reached_s

* coverage_over_time/coverage_edges_<group>.csv and coverage_pct_<group>.csv
    Wide: campaigns as rows, integer-minute columns 1..M where
    M = ceil(max(relative_time)/60) over the group. Cells use a
    step-function lookup against the campaign's plot_data; trailing minutes
    past a campaign's runtime are empty. The earlier per-campaign
    coverage_over_time/<target>_<program>_<run_id>.csv files are no longer
    written.

The findings/ subdirectory is autodetected (main or default) so both
aflplusplus and afl_uaf_detect campaign layouts are supported.
"""

import argparse
import csv
import logging
import math
import os
import re
import sys

import pandas as pd

KNOWN_TARGETS = {"expat", "libjpeg-turbo", "libpng", "libxml2", "sqlite3"}
SCALAR_ROWS = [
    "branch_coverage",
    "unique_crashes",
    "execs_per_sec",
    "total_executions",
    "corpus_size",
]
SUBCOLS = ("crashes", "ttfc_s", "etfc")
BUG_TOKEN_RE = re.compile(r"([A-Za-z0-9_.\-]+)\s*\(")

FINDINGS_SUBDIRS = ("main", "default")
GENERAL_STATS_FIELDS = [
    "branch_coverage", "unique_crashes", "execs_per_sec",
    "total_executions", "corpus_size",
]
PER_BUG_FIELDS = [
    "first_crash_s", "num_crashes", "etfc",
    "reached_s", "triggered_s", "free_reached_s",
]


def _findings_subdir(campaign_dir):
    base = os.path.join(campaign_dir, "findings")
    for name in FINDINGS_SUBDIRS:
        cand = os.path.join(base, name)
        if os.path.isdir(cand):
            return cand
    return None


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--fuzzer", required=True)
    p.add_argument("--num-campaigns", type=int, required=True)
    p.add_argument("--analyzer", default=None)
    p.add_argument("--results-dir", default="/home/users/m/m.thielebein/magma_results")
    p.add_argument("--output-dir", required=True)
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p.parse_args()


def detect_layout(fuzzer_root):
    """Return list of (analyzer_or_None, analyzer_root_path)."""
    entries = sorted(
        d for d in os.listdir(fuzzer_root)
        if os.path.isdir(os.path.join(fuzzer_root, d))
    )
    if not entries:
        return []
    first = os.path.join(fuzzer_root, entries[0])
    first_children = set(os.listdir(first)) if os.path.isdir(first) else set()
    if first_children & KNOWN_TARGETS:
        return [(e, os.path.join(fuzzer_root, e)) for e in entries]
    return [(None, fuzzer_root)]


def discover_campaigns(analyzer_root, n):
    """Return dict {(target, program): [campaign_dirs_newest_first]} capped at n."""
    groups = {}
    for target in sorted(os.listdir(analyzer_root)):
        tdir = os.path.join(analyzer_root, target)
        if not os.path.isdir(tdir):
            continue
        for program in sorted(os.listdir(tdir)):
            pdir = os.path.join(tdir, program)
            if not os.path.isdir(pdir):
                continue
            campaigns = [
                os.path.join(pdir, c) for c in os.listdir(pdir)
                if os.path.isdir(os.path.join(pdir, c))
            ]
            campaigns.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            if len(campaigns) < n:
                logging.warning(
                    "skipping %s/%s: only %d campaign(s), needed %d",
                    target, program, len(campaigns), n,
                )
                continue
            groups[(target, program)] = campaigns[:n]
    return groups


def parse_fuzzer_stats(path):
    stats = {}
    with open(path) as f:
        for line in f:
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            stats[k.strip()] = v.strip()
    return stats


def parse_plot_data(path):
    df = pd.read_csv(path, skipinitialspace=True)
    df.columns = [c.lstrip("# ").strip() for c in df.columns]
    if "map_size" in df.columns and not pd.api.types.is_numeric_dtype(df["map_size"]):
        df["map_size"] = df["map_size"].astype(str).str.rstrip("%").astype(float)
    return df


def parse_monitor_analysis(campaign_dir):
    """Return {bug: {reached_s, triggered_s, free_reached_s}} from monitor_analysis.csv.

    Each value is int or None ("" and "-" map to None). Returns None if the
    file is missing.
    """
    path = os.path.join(campaign_dir, "monitor_analysis.csv")
    if not os.path.isfile(path):
        return None

    def _to_int(v):
        v = (v or "").strip()
        if not v or v == "-":
            return None
        try:
            return int(v)
        except ValueError:
            return None

    out = {}
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            bug = (row.get("bug") or "").strip()
            if not bug or bug == "(no data)":
                continue
            out[bug] = {
                "reached_s":      _to_int(row.get("reached_s")),
                "triggered_s":    _to_int(row.get("triggered_s")),
                "free_reached_s": _to_int(row.get("free_reached_s")),
            }
    return out


def parse_crash_replay(campaign_dir):
    """Return {bug: {count, first_crash_s}} from crash_replay.csv.

    Each crash row contributes 1 per distinct bug id in bugs_triggered
    (multiplicity (N) ignored). first_crash_s = min(time_ms)/1000.0 over
    rows whose bugs_triggered contains the bug; rows with missing or
    non-int time_ms are skipped for the min. Returns None if the file is
    missing.
    """
    path = os.path.join(campaign_dir, "crash_replay.csv")
    if not os.path.isfile(path):
        return None
    counts = {}
    first_ms = {}
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            triggered = (row.get("bugs_triggered") or "").strip()
            if not triggered or triggered == "none":
                continue
            try:
                t_ms = int((row.get("time_ms") or "").strip())
            except ValueError:
                t_ms = None
            bugs_here = set()
            for entry in triggered.split(";"):
                m = BUG_TOKEN_RE.match(entry.strip())
                if m:
                    bugs_here.add(m.group(1))
            for bug in bugs_here:
                counts[bug] = counts.get(bug, 0) + 1
                if t_ms is not None:
                    prev = first_ms.get(bug)
                    if prev is None or t_ms < prev:
                        first_ms[bug] = t_ms
    return {
        bug: {
            "count": counts[bug],
            "first_crash_s": (first_ms[bug] / 1000.0) if bug in first_ms else None,
        }
        for bug in counts
    }


def execs_at_time(plot_df, t):
    if plot_df.empty or "total_execs" not in plot_df.columns:
        return float("nan")
    le = plot_df[plot_df["relative_time"] <= t]
    if le.empty:
        return float(plot_df["total_execs"].iloc[0])
    return float(le["total_execs"].iloc[-1])


def campaign_metrics(campaign_dir):
    fdir = _findings_subdir(campaign_dir)
    if fdir is None:
        logging.warning(
            "%s: no findings/{%s} subdir — treating fuzzer_stats/plot_data/queue as missing",
            campaign_dir, ",".join(FINDINGS_SUBDIRS),
        )
        stats_path = plot_path = queue_path = ""
    else:
        stats_path = os.path.join(fdir, "fuzzer_stats")
        plot_path = os.path.join(fdir, "plot_data")
        queue_path = os.path.join(fdir, "queue")

    fs = parse_fuzzer_stats(stats_path) if os.path.isfile(stats_path) else {}
    plot_df = parse_plot_data(plot_path) if os.path.isfile(plot_path) else pd.DataFrame()

    triggers = parse_monitor_analysis(campaign_dir)
    if triggers is None:
        logging.warning(
            "%s: missing monitor_analysis.csv — run analyse_campaigns.sh first; "
            "treating as no bug triggers",
            campaign_dir,
        )
        triggers = {}

    crash_counts = parse_crash_replay(campaign_dir)
    if crash_counts is None:
        logging.warning(
            "%s: missing crash_replay.csv — run analyse_campaigns.sh first; "
            "treating as zero crashes",
            campaign_dir,
        )
        crash_counts = {}

    def as_float(k, default=float("nan")):
        v = fs.get(k, "")
        try:
            return float(v.rstrip("%"))
        except (ValueError, AttributeError):
            return default

    def as_float_first(keys, default=float("nan")):
        for k in keys:
            v = as_float(k, default=None)
            if v is not None:
                return v
        return default

    corpus_size = 0
    if queue_path and os.path.isdir(queue_path):
        corpus_size = sum(
            1 for e in os.listdir(queue_path)
            if not e.startswith(".") and e != "README.txt"
        )

    per_bug = {}
    for bug in set(triggers) | set(crash_counts):
        t_info = triggers.get(bug) or {}
        triggered_s = t_info.get("triggered_s")
        c_info = crash_counts.get(bug) or {}
        count = int(c_info.get("count", 0))
        per_bug[bug] = {
            # Aliases used by the existing wide-table writer:
            "crashes": count,
            "ttfc_s": float(triggered_s) if triggered_s is not None else None,
            "etfc": execs_at_time(plot_df, triggered_s) if triggered_s is not None else None,
            # Fields used by the new per-bug long-format CSV:
            "num_crashes": count,
            "first_crash_s": c_info.get("first_crash_s"),
            "reached_s": t_info.get("reached_s"),
            "triggered_s": triggered_s,
            "free_reached_s": t_info.get("free_reached_s"),
        }

    if not plot_df.empty and "relative_time" in plot_df.columns:
        keep = ["relative_time"]
        for c in ("edges_found", "map_size"):
            if c in plot_df.columns:
                keep.append(c)
        coverage_series_full = plot_df[keep].copy()
    else:
        coverage_series_full = None

    return {
        "run_id": os.path.basename(campaign_dir.rstrip("/")),
        "scalars": {
            "branch_coverage": as_float("bitmap_cvg"),
            "unique_crashes": as_float_first(("unique_crashes", "saved_crashes")),
            "execs_per_sec": as_float("execs_per_sec"),
            "total_executions": as_float("execs_done"),
            "corpus_size": float(corpus_size),
        },
        "per_bug": per_bug,
        "coverage_series_full": coverage_series_full,
    }


def build_wide_table(per_campaign):
    """Build a MultiIndex-column DataFrame with the wide layout."""
    run_ids = [c["run_id"] for c in per_campaign]
    bugs = sorted({bug for c in per_campaign for bug in c["per_bug"]})
    row_index = bugs + SCALAR_ROWS
    columns = pd.MultiIndex.from_product([run_ids, SUBCOLS])

    df = pd.DataFrame("", index=row_index, columns=columns, dtype=object)

    for c in per_campaign:
        rid = c["run_id"]
        for bug, vals in c["per_bug"].items():
            df.loc[bug, (rid, "crashes")] = vals["crashes"]
            df.loc[bug, (rid, "ttfc_s")] = "" if vals["ttfc_s"] is None else vals["ttfc_s"]
            df.loc[bug, (rid, "etfc")] = "" if vals["etfc"] is None else vals["etfc"]
        for bug in bugs:
            if bug not in c["per_bug"]:
                df.loc[bug, (rid, "crashes")] = 0
        for name in SCALAR_ROWS:
            df.loc[name, (rid, "crashes")] = c["scalars"][name]
    return df


def group_filename(target, program, analyzer):
    parts = ["metrics", target, program]
    if analyzer:
        parts.append(analyzer)
    return "_".join(parts) + ".csv"


def general_stats_filename(target, program, analyzer):
    parts = ["general_stats", target, program]
    if analyzer:
        parts.append(analyzer)
    return "_".join(parts) + ".csv"


def bug_filename(target, program, analyzer, bug):
    parts = ["bug", bug, target, program]
    if analyzer:
        parts.append(analyzer)
    return "_".join(parts) + ".csv"


def coverage_filename(target, program, analyzer, kind):
    parts = [f"coverage_{kind}", target, program]
    if analyzer:
        parts.append(analyzer)
    return "_".join(parts) + ".csv"


def _fmt_cell(v):
    if v is None:
        return ""
    if isinstance(v, float) and pd.isna(v):
        return ""
    return v


def write_general_stats_csv(per_campaign, out_path):
    """One row per campaign; first column run_id then GENERAL_STATS_FIELDS."""
    with open(out_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["run_id"] + GENERAL_STATS_FIELDS)
        for c in per_campaign:
            row = [c["run_id"]]
            for k in GENERAL_STATS_FIELDS:
                row.append(_fmt_cell(c["scalars"].get(k)))
            w.writerow(row)


def coverage_at_minute(plot_df, t_min, col):
    """Step-function lookup: last plot_data row with relative_time <= t_min*60."""
    if plot_df is None or plot_df.empty or col not in plot_df.columns:
        return None
    le = plot_df[plot_df["relative_time"] <= t_min * 60]
    if le.empty:
        return None
    return le[col].iloc[-1]


def write_coverage_wide_csv(per_campaign, out_path, col):
    """Wide CSV: campaigns as rows, minutes 1..M as columns. Returns True if written.

    M = ceil(max(relative_time)/60) over all campaigns in the group. Cells past
    a campaign's own runtime, or before its first plot_data sample, are empty.
    """
    max_t = 0.0
    for c in per_campaign:
        df = c.get("coverage_series_full")
        if df is not None and not df.empty:
            max_t = max(max_t, float(df["relative_time"].max()))
    M = int(math.ceil(max_t / 60.0))
    if M == 0:
        return False
    with open(out_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["run_id"] + list(range(1, M + 1)))
        for c in per_campaign:
            df = c.get("coverage_series_full")
            row = [c["run_id"]]
            for t_min in range(1, M + 1):
                row.append(_fmt_cell(coverage_at_minute(df, t_min, col)))
            w.writerow(row)
    return True


def write_per_bug_csvs(per_campaign, out_dir, target, program, analyzer):
    """One CSV per bug. Row per campaign; first col run_id then PER_BUG_FIELDS.

    Bugs absent from a campaign get a row with num_crashes=0 and empty time
    fields (so every campaign is represented in every per-bug file).
    """
    bugs = sorted({bug for c in per_campaign for bug in c["per_bug"]})
    written = []
    for bug in bugs:
        path = os.path.join(out_dir, bug_filename(target, program, analyzer, bug))
        with open(path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["run_id"] + PER_BUG_FIELDS)
            for c in per_campaign:
                vals = c["per_bug"].get(bug)
                row = [c["run_id"]]
                if vals is None:
                    row.extend(["", 0, "", "", "", ""])
                else:
                    for k in PER_BUG_FIELDS:
                        if k == "num_crashes":
                            row.append(int(vals.get("num_crashes", 0)))
                        else:
                            row.append(_fmt_cell(vals.get(k)))
                w.writerow(row)
        written.append(path)
    return written


def main():
    args = parse_args()
    logging.basicConfig(
        level=[logging.WARNING, logging.INFO, logging.DEBUG][min(args.verbose, 2)],
        format="%(levelname)s: %(message)s",
    )

    fuzzer_root = os.path.join(args.results_dir, args.fuzzer)
    if not os.path.isdir(fuzzer_root):
        sys.exit(f"not a directory: {fuzzer_root}")

    layout = detect_layout(fuzzer_root)
    if args.analyzer is not None:
        layout = [(a, p) for a, p in layout if a == args.analyzer]
        if not layout:
            sys.exit(f"analyzer {args.analyzer} not found under {fuzzer_root}")

    os.makedirs(args.output_dir, exist_ok=True)
    gs_dir = os.path.join(args.output_dir, "general_stats")
    bug_dir = os.path.join(args.output_dir, "per_bug")
    cov_dir = os.path.join(args.output_dir, "coverage_over_time")

    metrics_written = 0
    general_stats_written = 0
    per_bug_written = 0
    cov_edges_written = 0
    cov_pct_written = 0

    for analyzer, aroot in layout:
        groups = discover_campaigns(aroot, args.num_campaigns)
        logging.info("analyzer=%s groups=%d", analyzer, len(groups))
        for (target, program), campaigns in groups.items():
            logging.info("%s/%s/%s: %d campaigns",
                         analyzer, target, program, len(campaigns))
            per = [campaign_metrics(c) for c in campaigns]

            df = build_wide_table(per)
            out_path = os.path.join(args.output_dir,
                                    group_filename(target, program, analyzer))
            df.to_csv(out_path)
            metrics_written += 1

            os.makedirs(gs_dir, exist_ok=True)
            write_general_stats_csv(
                per,
                os.path.join(gs_dir, general_stats_filename(target, program, analyzer)),
            )
            general_stats_written += 1

            os.makedirs(bug_dir, exist_ok=True)
            per_bug_written += len(
                write_per_bug_csvs(per, bug_dir, target, program, analyzer)
            )

            os.makedirs(cov_dir, exist_ok=True)
            if write_coverage_wide_csv(
                per,
                os.path.join(cov_dir, coverage_filename(target, program, analyzer, "edges")),
                "edges_found",
            ):
                cov_edges_written += 1
            if write_coverage_wide_csv(
                per,
                os.path.join(cov_dir, coverage_filename(target, program, analyzer, "pct")),
                "map_size",
            ):
                cov_pct_written += 1

    print(f"wrote {metrics_written} metrics file(s) to {args.output_dir}")
    print(f"wrote {general_stats_written} general_stats file(s) to {gs_dir}")
    print(f"wrote {per_bug_written} per-bug file(s) to {bug_dir}")
    print(f"wrote {cov_edges_written} coverage_edges and {cov_pct_written} coverage_pct file(s) to {cov_dir}")


if __name__ == "__main__":
    main()
