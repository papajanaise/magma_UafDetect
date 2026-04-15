#!/usr/bin/env python3
"""Aggregate metrics over N fuzzing campaigns per (fuzzer[, analyzer], target, program)."""

import argparse
import csv
import json
import logging
import os
import sys
from collections import defaultdict

import numpy as np
import pandas as pd

KNOWN_TARGETS = {"expat", "libjpeg-turbo", "libpng", "libxml2", "sqlite3"}
STATS = ["mean", "median", "stddev", "min", "max"]


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
        # fuzzer+analyzer layout
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
    # bitmap cvg may be "x%" string
    if "map_size" in df.columns and df["map_size"].dtype == object:
        df["map_size"] = df["map_size"].str.rstrip("%").astype(float)
    return df


def parse_monitor_dir(monitor_dir):
    rows = []
    files = [f for f in os.listdir(monitor_dir) if f.isdigit()]
    files.sort(key=int)
    for ts in files:
        try:
            with open(os.path.join(monitor_dir, ts), newline="") as fh:
                reader = csv.DictReader(fh)
                row = next(reader, None)
                if row is None:
                    continue
                row["TIME"] = int(ts)
                rows.append(row)
        except Exception as ex:
            logging.debug("monitor parse skip %s: %s", ts, ex)
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows).set_index("TIME").fillna(0).astype(int)
    return df


def first_trigger_times(monitor_df):
    """Return {bug: relative_time_seconds} for first time _T > 0."""
    result = {}
    if monitor_df.empty:
        return result
    bugs = {c[:-2] for c in monitor_df.columns if c.endswith("_T")}
    for bug in bugs:
        col = f"{bug}_T"
        if col not in monitor_df.columns:
            continue
        hits = monitor_df[monitor_df[col] > 0]
        if not hits.empty:
            result[bug] = int(hits.index[0])
    return result


def execs_at_time(plot_df, t):
    if plot_df.empty or "total_execs" not in plot_df.columns:
        return float("nan")
    le = plot_df[plot_df["relative_time"] <= t]
    if le.empty:
        return float(plot_df["total_execs"].iloc[0])
    return float(le["total_execs"].iloc[-1])


def campaign_metrics(campaign_dir):
    stats_path = os.path.join(campaign_dir, "findings", "main", "fuzzer_stats")
    plot_path = os.path.join(campaign_dir, "findings", "main", "plot_data")
    queue_path = os.path.join(campaign_dir, "findings", "main", "queue")
    monitor_path = os.path.join(campaign_dir, "monitor")

    fs = parse_fuzzer_stats(stats_path) if os.path.isfile(stats_path) else {}
    plot_df = parse_plot_data(plot_path) if os.path.isfile(plot_path) else pd.DataFrame()
    mon_df = parse_monitor_dir(monitor_path) if os.path.isdir(monitor_path) else pd.DataFrame()

    def as_float(k, default=float("nan")):
        v = fs.get(k, "")
        try:
            return float(v.rstrip("%"))
        except (ValueError, AttributeError):
            return default

    corpus_size = 0
    if os.path.isdir(queue_path):
        corpus_size = sum(
            1 for e in os.listdir(queue_path)
            if not e.startswith(".") and e != "README.txt"
        )

    triggers = first_trigger_times(mon_df)
    ttfc = {bug: float(t) for bug, t in triggers.items()}
    etfc = {bug: execs_at_time(plot_df, t) for bug, t in triggers.items()}

    return {
        "scalars": {
            "branch_coverage": as_float("bitmap_cvg"),
            "unique_crashes": as_float("unique_crashes"),
            "unique_hangs": as_float("unique_hangs"),
            "execs_per_sec": as_float("execs_per_sec"),
            "total_executions": as_float("execs_done"),
            "corpus_size": float(corpus_size),
        },
        "time_to_first_crash": ttfc,
        "execs_to_first_crash": etfc,
        "coverage_series": plot_df[["relative_time", "edges_found"]].copy()
            if not plot_df.empty and "edges_found" in plot_df.columns else pd.DataFrame(),
        "run_time": as_float("run_time", 0.0),
    }


def summarize(values):
    arr = np.array([v for v in values if not (isinstance(v, float) and np.isnan(v))],
                   dtype=float)
    if arr.size == 0:
        return {s: float("nan") for s in STATS}
    return {
        "mean": float(np.mean(arr)),
        "median": float(np.median(arr)),
        "stddev": float(np.std(arr, ddof=1)) if arr.size > 1 else 0.0,
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
    }


def aggregate_group(per_campaign):
    scalar_keys = per_campaign[0]["scalars"].keys()
    agg = {k: summarize([c["scalars"][k] for c in per_campaign]) for k in scalar_keys}

    bugs = set()
    for c in per_campaign:
        bugs |= set(c["time_to_first_crash"].keys())
    per_bug = {}
    for bug in sorted(bugs):
        times = [c["time_to_first_crash"].get(bug, float("nan")) for c in per_campaign]
        execs = [c["execs_to_first_crash"].get(bug, float("nan")) for c in per_campaign]
        per_bug[bug] = {
            "time_to_first_crash": summarize(times),
            "execs_to_first_crash": summarize(execs),
            "n_campaigns_triggered": int(sum(
                1 for t in times if not (isinstance(t, float) and np.isnan(t))
            )),
        }
    return agg, per_bug


def aggregate_coverage_over_time(per_campaign, step=60):
    series = [c["coverage_series"] for c in per_campaign if not c["coverage_series"].empty]
    if not series:
        return pd.DataFrame()
    max_t = int(min(s["relative_time"].max() for s in series))
    if max_t <= 0:
        return pd.DataFrame()
    grid = np.arange(0, max_t + 1, step)
    resampled = []
    for s in series:
        s_sorted = s.sort_values("relative_time")
        vals = np.interp(grid, s_sorted["relative_time"], s_sorted["edges_found"])
        resampled.append(vals)
    m = np.vstack(resampled)
    out = pd.DataFrame({
        "relative_time": grid,
        "mean": m.mean(axis=0),
        "median": np.median(m, axis=0),
        "stddev": m.std(axis=0, ddof=1) if m.shape[0] > 1 else np.zeros(m.shape[1]),
        "min": m.min(axis=0),
        "max": m.max(axis=0),
    })
    return out


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

    rows = []
    json_out = []
    cov_frames = []

    for analyzer, aroot in layout:
        groups = discover_campaigns(aroot, args.num_campaigns)
        logging.info("analyzer=%s groups=%d", analyzer, len(groups))
        for (target, program), campaigns in groups.items():
            logging.info("%s/%s/%s: %d campaigns", analyzer, target, program, len(campaigns))
            per = [campaign_metrics(c) for c in campaigns]
            scalars, per_bug = aggregate_group(per)
            cov = aggregate_coverage_over_time(per)
            if not cov.empty:
                cov.insert(0, "program", program)
                cov.insert(0, "target", target)
                cov.insert(0, "analyzer", analyzer or "")
                cov.insert(0, "fuzzer", args.fuzzer)
                cov_frames.append(cov)

            base = {
                "fuzzer": args.fuzzer,
                "analyzer": analyzer or "",
                "target": target,
                "program": program,
                "n_campaigns": len(campaigns),
            }
            for metric, stat_dict in scalars.items():
                row = dict(base)
                row["metric"] = metric
                row["scope"] = "scalar"
                row["bug"] = ""
                row.update(stat_dict)
                rows.append(row)
            for bug, metrics in per_bug.items():
                for metric, stat_dict in metrics.items():
                    if metric == "n_campaigns_triggered":
                        continue
                    row = dict(base)
                    row["metric"] = metric
                    row["scope"] = "per_bug"
                    row["bug"] = bug
                    row.update(stat_dict)
                    row["n_campaigns_triggered"] = metrics["n_campaigns_triggered"]
                    rows.append(row)

            json_out.append({
                **base,
                "campaigns": [os.path.basename(c) for c in campaigns],
                "scalars": scalars,
                "per_bug": per_bug,
            })

    metrics_csv = os.path.join(args.output_dir, "metrics.csv")
    metrics_json = os.path.join(args.output_dir, "metrics.json")
    cov_csv = os.path.join(args.output_dir, "coverage_over_time.csv")

    if rows:
        fieldnames = ["fuzzer", "analyzer", "target", "program", "scope", "bug",
                      "metric", "n_campaigns", "n_campaigns_triggered",
                      "mean", "median", "stddev", "min", "max"]
        with open(metrics_csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)
    with open(metrics_json, "w") as f:
        json.dump({"fuzzer": args.fuzzer, "num_campaigns": args.num_campaigns,
                   "groups": json_out}, f, indent=2)
    if cov_frames:
        pd.concat(cov_frames, ignore_index=True).to_csv(cov_csv, index=False)

    print(f"wrote {metrics_csv}")
    print(f"wrote {metrics_json}")
    if cov_frames:
        print(f"wrote {cov_csv}")


if __name__ == "__main__":
    main()
