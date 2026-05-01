#!/usr/bin/env python3
"""Summarise a UAF-batch fuzzing campaign.

Usage:
    analyze_uaf_batch_campaign.py <STAMP>

Reads /home/users/m/m.thielebein/uaf_batch/campaign_results/<STAMP>/<analyzer>/<test_id>/<jobid>/afl/default/
and writes <STAMP>/summary.csv (per-campaign overview) and <STAMP>/bug_metrics.csv
(per-(test, bug) detail with free_finder vs svf columns side-by-side).

Bug attribution: each crash is replayed against an ASan-instrumented twin
binary at <asan-bin-dir>/<test_id>_<analyzer>_instr_asan; the freed-here
line and access-site line from ASan's report are matched against the test
case's uaf_NNN.json. The twin binaries must be pre-built (host has no
LLVM-16); the script prints the build recipe when twins are missing.

The static bug catalog at /home/users/m/m.thielebein/uaf_batch/bugs.csv
is write-once; the script keeps the existing file and only creates it
when missing.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

BATCH_DIR = Path("/home/users/m/m.thielebein/uaf_batch")
RESULTS_ROOT = BATCH_DIR / "campaign_results"
DEFAULT_ASAN_DIR = BATCH_DIR / "asan_replay"
BUGS_CSV_PATH = BATCH_DIR / "bugs.csv"  # canonical, written once; bugs don't change per campaign

CRASH_NAME_RE = re.compile(r"id:(?P<id>\d+),sig:(?P<sig>\d+).*?,time:(?P<time>\d+),execs:(?P<execs>\d+)")

ASAN_BUILD_RECIPE = """\
    LLVM16=/usr/lib/llvm-16/bin
    OUT=/home/users/m/m.thielebein/uaf_batch/asan_replay
    mkdir -p "$OUT"

    cat > /tmp/uaf_runtime_stub.c <<'EOF'
    #include <stdint.h>
    static unsigned char dummy_area[1u << 20];
    unsigned char *__uaf_area_ptr = dummy_area;
    __thread uint32_t __uaf_current_counter;
    EOF
    "$LLVM16/clang" -O0 -g -c /tmp/uaf_runtime_stub.c -o /tmp/uaf_runtime_stub.o

    cd /home/users/m/m.thielebein/uaf_batch
    for bc in uaf_*_free_finder_instr.bc uaf_*_svf_instr.bc; do
        out="$OUT/${bc%.bc}_asan"
        "$LLVM16/clang" -O0 -g -fsanitize=address -fno-omit-frame-pointer \\
            "$bc" /tmp/uaf_runtime_stub.o -o "$out"
    done"""

ASAN_HEADER_RE = re.compile(r"==\d+==ERROR: AddressSanitizer:\s+(?P<kind>[\w\-]+)")
ASAN_RW_RE = re.compile(r"^(READ|WRITE) of size", re.MULTILINE)
# Symbolised frame: "    #0 0x... in func file.c:42"
ASAN_FRAME_SYM_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-f]+\s+in\s+(?P<func>\S+)\s+(?P<file>[^\s:]+):(?P<line>\d+)",
    re.MULTILINE,
)
# Unsymbolised frame: "    #0 0x... (/path/to/binary+0xOFFSET)" — host without llvm-symbolizer.
ASAN_FRAME_OFF_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-f]+\s+\((?P<bin>[^)]+?)\+(?P<off>0x[0-9a-f]+)\)",
    re.MULTILINE,
)
# `addr2line -p -s -f` output: "func at file.c:42"
ADDR2LINE_RE = re.compile(r"^(?P<func>\S+)\s+at\s+(?P<file>[^\s:]+):(?P<line>\d+)")


@dataclass
class Campaign:
    analyzer: str
    test_id: str
    jobid: str
    afl_dir: Path  # .../afl/default

    @property
    def crashes_dir(self) -> Path:
        return self.afl_dir / "crashes"

    @property
    def fuzzer_stats(self) -> Path:
        return self.afl_dir / "fuzzer_stats"


@dataclass
class CrashAttribution:
    test_id: str
    analyzer: str
    crash_id: str
    sig: str
    time_ms: int
    execs: int
    bug_id: str
    kind: str
    use_line: Optional[int]
    free_line: Optional[int]
    note: str = ""


def discover_campaigns(root: Path) -> list[Campaign]:
    out: list[Campaign] = []
    for analyzer_dir in sorted(root.iterdir()):
        if not analyzer_dir.is_dir() or analyzer_dir.name not in ("free_finder", "svf"):
            continue
        for test_dir in sorted(analyzer_dir.iterdir()):
            if not test_dir.is_dir() or not test_dir.name.startswith("uaf_"):
                continue
            for job_dir in sorted(test_dir.iterdir()):
                if not job_dir.is_dir() or not job_dir.name.isdigit():
                    continue
                afl_default = job_dir / "afl" / "default"
                if (afl_default / "fuzzer_stats").is_file():
                    out.append(Campaign(
                        analyzer=analyzer_dir.name,
                        test_id=test_dir.name,
                        jobid=job_dir.name,
                        afl_dir=afl_default,
                    ))
    return out


def parse_fuzzer_stats(path: Path) -> dict[str, str]:
    stats = {}
    for line in path.read_text().splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        stats[k.strip()] = v.strip()
    return stats


def collect_summary(c: Campaign) -> dict:
    s = parse_fuzzer_stats(c.fuzzer_stats)
    start = int(s.get("start_time", 0) or 0)
    last_update = int(s.get("last_update", 0) or 0)
    edges_found = int(s.get("edges_found", 0) or 0)
    total_edges = int(s.get("total_edges", 0) or 0)
    cvg = (100.0 * edges_found / total_edges) if total_edges else 0.0

    last_edge = int(s.get("last_find", 0) or 0)
    last_find_s = (last_edge - start) if (last_edge and start) else 0

    return {
        "test_id": c.test_id,
        "analyzer": c.analyzer,
        "jobid": c.jobid,
        "duration_s": last_update - start if last_update and start else int(s.get("run_time", 0) or 0),
        "total_execs": int(s.get("execs_done", 0) or 0),
        "execs_per_sec": float(s.get("execs_per_sec", 0) or 0),
        "corpus_count": int(s.get("corpus_count", 0) or 0),
        "edges_found": edges_found,
        "total_edges": total_edges,
        "branch_coverage_pct": round(cvg, 2),
        "unique_crashes": int(s.get("saved_crashes", 0) or 0),
        "unique_hangs": int(s.get("saved_hangs", 0) or 0),
        "cycles_done": int(s.get("cycles_done", 0) or 0),
        "stability": s.get("stability", ""),
        "last_find_s": last_find_s,
    }


def write_summary_csv(path: Path, rows: list[dict]) -> None:
    fields = [
        "test_id", "analyzer", "jobid", "duration_s",
        "total_execs", "execs_per_sec", "corpus_count",
        "edges_found", "total_edges", "branch_coverage_pct",
        "unique_crashes", "unique_hangs", "cycles_done",
        "stability", "last_find_s",
    ]
    rows = sorted(rows, key=lambda r: (r["test_id"], r["analyzer"]))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


# --------------------------------------------------------------------------
# ASan twin lookup + crash replay + bug attribution
# --------------------------------------------------------------------------

def asan_twin_path(asan_dir: Path, test_id: str, analyzer: str) -> Path:
    return asan_dir / f"{test_id}_{analyzer}_instr_asan"


def lookup_asan_twin(asan_dir: Path, test_id: str, analyzer: str) -> Optional[Path]:
    """Return the path to a pre-built ASan twin, or None if missing.

    The host doesn't have LLVM-16; the twins are built inside a Singularity
    container. See the build recipe printed by the script when twins are
    missing."""
    twin = asan_twin_path(asan_dir, test_id, analyzer)
    return twin if twin.is_file() else None


def parse_crash_filename(name: str) -> Optional[dict]:
    m = CRASH_NAME_RE.match(name)
    if not m:
        return None
    return {"id": m["id"], "sig": m["sig"], "time": int(m["time"]), "execs": int(m["execs"])}


def resolve_offsets(binary: Path, offsets: list[str]) -> dict[str, tuple[str, int]]:
    """Run addr2line once on a batch of offsets. Returns {offset: (file, line)}
    for offsets that resolved to a real source location. Without -i, addr2line
    emits one line per offset (the outermost frame), in input order."""
    if not offsets:
        return {}
    proc = subprocess.run(
        ["addr2line", "-e", str(binary), "-f", "-p", "-s", *offsets],
        capture_output=True, text=True, check=False,
    )
    out: dict[str, tuple[str, int]] = {}
    lines = proc.stdout.splitlines()
    for off, raw in zip(offsets, lines):
        m = ADDR2LINE_RE.match(raw.strip())
        if m and m.group("file") != "??":
            out[off] = (m.group("file"), int(m.group("line")))
    return out


def parse_asan_output(stderr: str, source_basename: str,
                      asan_bin: Path) -> dict:
    """Extract kind + freed-here line + access-site line from ASan stderr.

    `source_basename` is e.g. "uaf_006.c" — only frames in this file count
    as the user-code site. When ASan emits unsymbolised frames (host has
    no llvm-symbolizer), offsets are post-resolved with addr2line.
    """
    out = {"kind": "", "use_line": None, "free_line": None, "note": ""}
    if "AddressSanitizer:" not in stderr:
        out["note"] = "no-asan-report"
        return out

    rw = ASAN_RW_RE.search(stderr)
    if rw:
        out["kind"] = rw.group(1).lower()

    # Split into sections at "freed by thread", "previously allocated by", etc.
    chunks = re.split(r"(freed by thread .*? here:|previously allocated by thread .*? here:)",
                      stderr)
    access_chunk = chunks[0] if chunks else stderr
    freed_idx = next((i for i, c in enumerate(chunks) if c.startswith("freed by thread")), -1)
    freed_chunk = chunks[freed_idx + 1] if 0 <= freed_idx < len(chunks) - 1 else ""

    # Collect all offsets across both chunks so we resolve in one addr2line call.
    def collect_offsets(text: str) -> list[str]:
        return [m.group("off") for m in ASAN_FRAME_OFF_RE.finditer(text)]

    all_offsets = collect_offsets(access_chunk) + collect_offsets(freed_chunk)
    resolved = resolve_offsets(asan_bin, all_offsets) if all_offsets else {}

    def topmost_user_line(text: str) -> Optional[int]:
        for line in text.splitlines():
            sym = ASAN_FRAME_SYM_RE.match(line)
            if sym and sym.group("file").endswith(source_basename):
                return int(sym.group("line"))
            off = ASAN_FRAME_OFF_RE.match(line)
            if off:
                hit = resolved.get(off.group("off"))
                if hit and hit[0].endswith(source_basename):
                    return hit[1]
        return None

    out["use_line"] = topmost_user_line(access_chunk)
    out["free_line"] = topmost_user_line(freed_chunk)
    return out


def attribute_to_bug(json_data: dict, asan: dict) -> tuple[str, str]:
    """Return (bug_id, note). Bug id is "1" for tiny cases, the JSON's
    `id` for medium/large, or "unknown"/"ambiguous" with a note."""
    if asan.get("note") == "no-asan-report":
        return ("unknown", "non-uaf crash")

    use_line = asan.get("use_line")
    free_line = asan.get("free_line")
    kind = asan.get("kind", "")

    uafs = json_data.get("uafs")
    if not uafs:
        # Tiny schema: single bug, top-level free_line/use_line.
        j_free = json_data.get("free_line")
        j_use = json_data.get("use_line")
        if free_line == j_free and use_line == j_use:
            return ("1", "")
        return ("1", f"line mismatch (asan free={free_line} use={use_line}, json free={j_free} use={j_use})")

    # Medium/large: filter on free_line, then kind, then closest use_line.
    candidates = [u for u in uafs if u.get("free_line") == free_line]
    if not candidates:
        return ("unknown", f"no uaf with free_line={free_line}")
    if kind:
        narrowed = [u for u in candidates if u.get("kind") == kind]
        if narrowed:
            candidates = narrowed
    if len(candidates) == 1:
        return (str(candidates[0]["id"]), "")
    if use_line is not None:
        candidates = sorted(candidates, key=lambda u: abs((u.get("use_line") or 0) - use_line))
        return (str(candidates[0]["id"]), "tie-broken by closest use_line")
    return (str(candidates[0]["id"]), "ambiguous, picked first")


def replay_one(args_tuple) -> CrashAttribution:
    asan_bin, crash_path, test_id, analyzer, json_data, source_basename, timeout = args_tuple
    name = crash_path.name
    parsed = parse_crash_filename(name)
    if not parsed:
        return CrashAttribution(test_id, analyzer, name, "", 0, 0, "unknown",
                                "", None, None, "unparseable filename")
    try:
        proc = subprocess.run(
            [str(asan_bin), str(crash_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env={
                **os.environ,
                "ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0:symbolize=1:allocator_may_return_null=1",
            },
        )
        stderr = proc.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return CrashAttribution(test_id, analyzer, parsed["id"], parsed["sig"],
                                parsed["time"], parsed["execs"], "unknown",
                                "", None, None, "replay timeout")

    asan = parse_asan_output(stderr, source_basename, asan_bin)
    bug_id, note = attribute_to_bug(json_data, asan)
    return CrashAttribution(
        test_id=test_id,
        analyzer=analyzer,
        crash_id=parsed["id"],
        sig=parsed["sig"],
        time_ms=parsed["time"],
        execs=parsed["execs"],
        bug_id=bug_id,
        kind=asan.get("kind", ""),
        use_line=asan.get("use_line"),
        free_line=asan.get("free_line"),
        note=note or asan.get("note", ""),
    )


def attribute_all(campaigns: list[Campaign], asan_dir: Path,
                  jobs: int, replay_timeout: int) -> list[CrashAttribution]:
    tasks = []
    json_cache: dict[str, dict] = {}
    twin_cache: dict[tuple[str, str], Optional[Path]] = {}
    missing_twins: list[tuple[str, str]] = []

    for c in campaigns:
        if c.test_id not in json_cache:
            jp = BATCH_DIR / f"{c.test_id}.json"
            json_cache[c.test_id] = json.loads(jp.read_text()) if jp.is_file() else {}
        key = (c.test_id, c.analyzer)
        if key not in twin_cache:
            twin_cache[key] = lookup_asan_twin(asan_dir, c.test_id, c.analyzer)
            if twin_cache[key] is None:
                missing_twins.append(key)
        twin = twin_cache[key]
        if twin is None or not c.crashes_dir.is_dir():
            continue
        source_basename = f"{c.test_id}.c"
        json_data = json_cache[c.test_id]
        for crash in sorted(c.crashes_dir.iterdir()):
            if not crash.name.startswith("id:"):
                continue
            tasks.append((twin, crash, c.test_id, c.analyzer, json_data,
                          source_basename, replay_timeout))

    if missing_twins:
        print(f"[warn] {len(missing_twins)} ASan twin(s) missing under {asan_dir}; "
              f"those crashes will be skipped:", file=sys.stderr)
        for tid, ana in missing_twins:
            print(f"        - {asan_twin_path(asan_dir, tid, ana).name}", file=sys.stderr)
        print("\n  ASan twin build recipe (run inside the container with LLVM 16):",
              file=sys.stderr)
        print(ASAN_BUILD_RECIPE, file=sys.stderr)

    if not tasks:
        return []

    results: list[CrashAttribution] = []
    with ProcessPoolExecutor(max_workers=max(1, jobs)) as ex:
        for r in ex.map(replay_one, tasks):
            results.append(r)
    return results


def write_crash_attribution_csv(path: Path, rows: list[CrashAttribution]) -> None:
    fields = ["test_id", "analyzer", "crash_id", "sig", "time_ms", "execs",
              "bug_id", "kind", "use_line", "free_line", "note"]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: getattr(r, k) for k in fields})


# --------------------------------------------------------------------------
# Per-bug catalog + per-campaign metrics
# --------------------------------------------------------------------------

def expected_bugs(test_id: str) -> list[dict]:
    """Return [{bug_id, kind, description}, ...] from the JSON, including
    bugs no campaign found yet (so the table reflects coverage gaps)."""
    jp = BATCH_DIR / f"{test_id}.json"
    if not jp.is_file():
        return []
    j = json.loads(jp.read_text())
    if not j.get("uafs"):
        return [{"bug_id": "1", "kind": "", "description": j.get("description", "")}]
    return [
        {"bug_id": str(u["id"]), "kind": u.get("kind", ""),
         "description": f'{u.get("pointer","")} via {u.get("mechanism","?")}'}
        for u in j["uafs"]
    ]


def write_bugs_catalog_if_missing(path: Path, test_ids: list[str]) -> bool:
    """Write the static bug catalog at `path` if it doesn't exist yet.
    Returns True if the file was created, False if it already existed."""
    if path.exists():
        return False
    rows = []
    for tid in test_ids:
        for bug in expected_bugs(tid):
            rows.append({
                "test_id": tid,
                "bug_id": bug["bug_id"],
                "kind": bug["kind"],
                "description": bug["description"],
            })
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["test_id", "bug_id", "kind", "description"])
        w.writeheader()
        w.writerows(rows)
    return True


def build_bug_metrics(crash_rows: list[CrashAttribution],
                      test_ids: list[str]) -> list[dict]:
    """Per-campaign per-bug metrics, joined by (test_id, bug_id) with
    /uaf_batch/bugs.csv. Bugs that no campaign reached still get a row
    (zero crashes) so the table mirrors the catalog's shape."""
    grouped: dict[tuple[str, str, str], list[tuple[int, int]]] = {}
    for r in crash_rows:
        if r.bug_id in ("unknown", "ambiguous"):
            continue
        grouped.setdefault((r.test_id, r.bug_id, r.analyzer), []).append((r.time_ms, r.execs))

    out: list[dict] = []
    for tid in test_ids:
        for bug in expected_bugs(tid):
            row = {"test_id": tid, "bug_id": bug["bug_id"]}
            for analyzer, prefix in (("free_finder", "ff"), ("svf", "svf")):
                events = grouped.get((tid, bug["bug_id"], analyzer), [])
                if events:
                    events.sort()
                    row[f"{prefix}_crashes"] = len(events)
                    row[f"{prefix}_ttfc_s"] = round(events[0][0] / 1000.0, 3)
                    row[f"{prefix}_etfc"] = events[0][1]
                    row[f"{prefix}_last_s"] = round(events[-1][0] / 1000.0, 3)
                else:
                    row[f"{prefix}_crashes"] = 0
                    row[f"{prefix}_ttfc_s"] = ""
                    row[f"{prefix}_etfc"] = ""
                    row[f"{prefix}_last_s"] = ""
            out.append(row)
    return out


def write_bug_metrics_csv(path: Path, rows: list[dict]) -> None:
    fields = [
        "test_id", "bug_id",
        "ff_crashes", "ff_ttfc_s", "ff_etfc", "ff_last_s",
        "svf_crashes", "svf_ttfc_s", "svf_etfc", "svf_last_s",
    ]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stamp", help="Campaign timestamp directory under campaign_results/")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4,
                    help="Parallel workers for crash replay")
    ap.add_argument("--asan-bin-dir", type=Path, default=DEFAULT_ASAN_DIR,
                    help="Directory holding pre-built ASan twin binaries "
                         "(<test_id>_<analyzer>_instr_asan); host has no LLVM-16 "
                         "so build them inside a container, see recipe in "
                         "the warning when twins are missing")
    ap.add_argument("--skip-replay", action="store_true",
                    help="Skip crash replay; only emit summary.csv")
    ap.add_argument("--replay-timeout", type=int, default=10,
                    help="Per-crash timeout in seconds")
    args = ap.parse_args()

    campaign_root = RESULTS_ROOT / args.stamp
    if not campaign_root.is_dir():
        print(f"campaign root not found: {campaign_root}", file=sys.stderr)
        return 1

    campaigns = discover_campaigns(campaign_root)
    if not campaigns:
        print(f"no campaigns under {campaign_root}", file=sys.stderr)
        return 1

    print(f"found {len(campaigns)} campaigns under {campaign_root}")
    summary_rows = [collect_summary(c) for c in campaigns]
    summary_path = campaign_root / "summary.csv"
    write_summary_csv(summary_path, summary_rows)
    print(f"  wrote {summary_path} ({len(summary_rows)} rows)")

    if args.skip_replay:
        return 0

    crash_rows = attribute_all(
        campaigns, args.asan_bin_dir,
        jobs=args.jobs,
        replay_timeout=args.replay_timeout,
    )
    crash_csv = campaign_root / "crash_attribution.csv"
    write_crash_attribution_csv(crash_csv, crash_rows)
    print(f"  wrote {crash_csv} ({len(crash_rows)} crashes)")

    test_ids = sorted({c.test_id for c in campaigns})

    if write_bugs_catalog_if_missing(BUGS_CSV_PATH, test_ids):
        print(f"  wrote {BUGS_CSV_PATH} (static bug catalog)")
    else:
        print(f"  kept existing {BUGS_CSV_PATH} (static bug catalog)")

    bug_rows = build_bug_metrics(crash_rows, test_ids)
    bug_metrics_csv = campaign_root / "bug_metrics.csv"
    write_bug_metrics_csv(bug_metrics_csv, bug_rows)
    print(f"  wrote {bug_metrics_csv} ({len(bug_rows)} (test, bug) rows)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
