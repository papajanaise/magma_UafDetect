#!/usr/bin/env python3
"""
Extract free_finder analyzer summaries + dealloc info from patches and emit
a per-bug coverage verdict table.

Usage:
    free_finder_extract.py <job_id>
        # job_id is the directory name under
        # /home/users/m/m.thielebein/magma_campaign_logs/build_jobs/
        # e.g. 20260407_142106

    free_finder_extract.py --log-dir /path/to/build_jobs/20260407_142106

Outputs (under /home/users/m/m.thielebein/magma_results/):
    free_finder_summary_<job_id>.txt   raw extraction (logs + patches)
    free_finder_table_<job_id>.txt     per-bug verdict table

If you want to add or remove targets, edit TARGETS below.
"""
import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

BUILD_JOBS_ROOT = "/home/users/m/m.thielebein/magma_campaign_logs/build_jobs"
TARGETS_DIR     = "/home/users/m/m.thielebein/magma_UafDetect/targets"
RESULTS_DIR     = "/home/users/m/m.thielebein/magma_results"
# Root of per-target instrumented bitcodes produced by the drivers.
INSTR_OUT_ROOT  = "/home/users/m/m.thielebein/magma_out/afl_uaf_detect"

TARGETS = ["expat", "libjpeg-turbo", "libpng", "libxml2", "sqlite3"]
ANALYZERS = ["free_finder", "svf"]

# Per-target heuristics for the verdict pass.
#
# `direct_aliases`: extra C symbols that we treat as known direct deallocs
#                   for this target (in addition to libc free/realloc).
#                   When the patch calls one of these and Phase 1 reported
#                   >= 2 known deallocs, we count it as a direct hit.
#
# `wrapper_alias`: when a patch calls foo, the actual symbol in the .bc may
#                  be MAGMA_foo because of magma's canary instrumentation.
#                  We try both names against the wrapper set.
#
# `notes`: free-form notes that get printed in the verdict table for this
#          target only.
# `fptr_aliases`: name -> resolved function. Used when a patch references a
# global function-pointer name (e.g. xmlFree) that the analyzer never sees as
# a function symbol; we look up the resolved target in wrapperFuns instead.
TARGET_HINTS = {
    "expat": {
        "fptr_aliases": {},
        "notes": "EXPUAF03/06 use pool->mem->free_fcn (struct fptr). "
                 "Default expat allocator suite is statically initialised "
                 "to libc free, so Andersen typically resolves these to "
                 "direct free() sites.",
    },
    "libjpeg-turbo": {
        "fptr_aliases": {},
        "notes": "JPGUAF05 calls jpeg_destroy_decompress -> jpeg_destroy "
                 "-> *self_destruct -> free_pool -> free. With "
                 "MAX_WRAPPER_LEVEL=2 the cascade stops at free_pool / "
                 "self_destruct; jpeg_destroy_decompress is not promoted.",
    },
    "libpng": {
        "fptr_aliases": {},
        "notes": "All libpng_uaf_* patches call png_free which becomes "
                 "MAGMA_png_free at the IR level. CVE-2019-7317 (PNG002) "
                 "uses the png_image_free_function chain (3+ levels deep) "
                 "and is not detected at MAX_WRAPPER_LEVEL=2.",
    },
    "libxml2": {
        "fptr_aliases": {
            "xmlFree":    "xmlMemFree",
            "xmlMalloc":  "xmlMemMalloc",
            "xmlRealloc": "xmlMemRealloc",
        },
        "notes": "All libxml2 UAF patches call xmlFree, a global function "
                 "pointer initialised to xmlMemFree. xmlMemFree is in "
                 "wrapperFuns, so the indirect calls are tagged via Pass A.",
    },
    "sqlite3": {
        "fptr_aliases": {},
        "notes": "Patches use sqlite3DbFree / sqlite3DbFreeNN. Their dealloc "
                 "chain dispatches via sqlite3GlobalConfig.m.xFree (struct "
                 "fptr) which Andersen cannot resolve, so callsAnyEligible "
                 "fails before the name whitelist runs and these wrappers "
                 "are NOT promoted.",
    },
}

# ---------------------------------------------------------------------------
# patch parsing
# ---------------------------------------------------------------------------

FREE_CALL_RE = re.compile(
    r'\b([a-zA-Z_][a-zA-Z0-9_]*'
    r'(?:[Ff]ree|FREE|[Dd]estroy|DESTROY|[Dd]elete|DELETE|'
    r'[Dd]ealloc|DEALLOC|[Rr]elease|RELEASE)'
    r'[a-zA-Z0-9_]*)\s*\('
)
INDIRECT_RE = re.compile(
    r'(\([\*]?\s*[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*'
    r'[a-zA-Z_][a-zA-Z0-9_]*\s*\))\s*\('
)
FPTR_RE = re.compile(
    r'\b([a-zA-Z_][a-zA-Z0-9_]*_fcn|'
    r'[a-zA-Z_][a-zA-Z0-9_]*_fn|'
    r'[a-zA-Z_][a-zA-Z0-9_]*Func)\s*\('
)
REALLOC_RE = re.compile(
    r'\b([a-zA-Z_][a-zA-Z0-9_]*[Rr]ealloc[a-zA-Z0-9_]*)\s*\('
)
MAGMA_FREE_LOG_RE = re.compile(
    r'MAGMA_FREE_LOG\s*\(\s*"([^"]+)"\s*\)'
)

# Names we ignore when scanning patches (magma framework noise).
PATCH_IGNORE = set()


def _scan_body_for_dealloc(body, found, canary_ids, source_tag=""):
    """Scan one line body and append matches to `found`. `source_tag` is
    appended to wrapper names so the verdict can tell context-only matches
    apart from added-line matches.  `canary_ids` collects MAGMA_FREE_LOG
    bug-id strings.

    Returns True if at least one dealloc-like match was appended in this
    call, False otherwise.  Canaries alone do not count as a match."""
    suffix = source_tag
    matched = False
    # Extract canary bug IDs — these are evidence of an injected free site.
    for m in MAGMA_FREE_LOG_RE.finditer(body):
        canary_ids.add(m.group(1))
    for _ in re.finditer(r'\bfree\s*\(', body):
        found.append(('direct_free' + suffix, body.strip()))
        matched = True
    for m in FREE_CALL_RE.finditer(body):
        name = m.group(1)
        if name.lower() == 'free':
            continue
        if name == 'MAGMA_FREE_LOG':
            continue  # handled above as canary, not a real dealloc wrapper
        if name in PATCH_IGNORE:
            continue
        found.append(('wrapper:' + name + suffix, body.strip()))
        matched = True
    for _ in INDIRECT_RE.finditer(body):
        found.append(('indirect_fptr' + suffix, body.strip()))
        matched = True
    for m in FPTR_RE.finditer(body):
        found.append(('fptr_named:' + m.group(1) + suffix, body.strip()))
        matched = True
    for m in REALLOC_RE.finditer(body):
        found.append(('realloc:' + m.group(1) + suffix, body.strip()))
        matched = True
    return matched


_HUNK_HEADER_RE = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@')
_PLUSPLUS_RE    = re.compile(r'^\+\+\+\s+(?:b/)?(\S+)')


def extract_dealloc_from_patch(path):
    """Return (items, context_hunks, canary_ids, free_sites) from a patch.

    items: list of (kind, snippet) tuples.
    context_hunks: list of @@ hunk headers.
    canary_ids: set of MAGMA_FREE_LOG bug-id strings found in added lines.
    free_sites: list of (file_path, line_number) tuples for each added
                '+' line that contained a dealloc-like call.  Used to
                match the patch's physical free sites against the
                counters instrumented in the bitcode.  Pulled from:
                  * '+++ b/<path>' header (most recent before the hunk)
                  * '@@ -a,b +c,d @@' target-side start line `c`
                  * count `+`/' ' lines within the hunk to advance.

    First pass: only added (+) lines. If that finds nothing dealloc-like
    (common for canary-only patches that just add MAGMA_FREE_LOG markers
    around an *existing* free), fall back to scanning context lines (no
    +/- prefix) — those are unchanged source lines that the patch hunks
    surround. Context-line matches are tagged with '@ctx' so the verdict
    pass can recognise them.

    kind is one of:
        direct_free[@ctx], wrapper:<name>[@ctx], indirect_fptr[@ctx],
        fptr_named:<name>[@ctx], realloc:<name>[@ctx]
    """
    added = []
    ctx_lines = []           # list of (file, line, body) — untouched context lines
    context_hunks = []
    canary_ids = set()
    free_sites = []          # [(file, line), ...] added-line matches
    current_file = None
    new_cursor = None        # line number on the new-file side
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                mpp = _PLUSPLUS_RE.match(line)
                if mpp:
                    current_file = mpp.group(1)
                    new_cursor = None
                    continue
                mhh = _HUNK_HEADER_RE.match(line)
                if mhh:
                    new_cursor = int(mhh.group(1))
                    context_hunks.append(line.rstrip())
                    continue
                if new_cursor is None:
                    continue
                if line.startswith('+') and not line.startswith('+++'):
                    before_len = len(added)
                    matched = _scan_body_for_dealloc(
                        line[1:], added, canary_ids)
                    if matched and current_file is not None:
                        free_sites.append((current_file, new_cursor))
                    new_cursor += 1
                elif line.startswith('-') and not line.startswith('---'):
                    pass  # deletions don't advance new-file cursor
                else:
                    # context line — keep for fallback scan
                    body = line.rstrip("\n")
                    if body.startswith(' '):
                        body = body[1:]
                    ctx_lines.append((current_file, new_cursor, body))
                    new_cursor += 1
    except Exception as e:
        return [('error', str(e))], context_hunks, canary_ids, []

    if not added:
        # Scan context lines as a fallback — also record their locations.
        for cfile, cline, body in ctx_lines:
            before_len = len(added)
            matched = _scan_body_for_dealloc(body, added, canary_ids,
                                             source_tag="@ctx")
            if matched and cfile is not None and cline is not None:
                free_sites.append((cfile, cline))

    seen = set()
    uniq = []
    for k, v in added:
        key = (k, v[:80])
        if key in seen:
            continue
        seen.add(key)
        uniq.append((k, v))
    # Dedup free_sites.
    seen_fs = set()
    uniq_fs = []
    for fs in free_sites:
        if fs in seen_fs: continue
        seen_fs.add(fs)
        uniq_fs.append(fs)
    return uniq, context_hunks, canary_ids, uniq_fs


# ---------------------------------------------------------------------------
# bitcode manifest extraction
# ---------------------------------------------------------------------------

_LLVM_DIS_CACHE = [None]  # sentinel: None = not yet searched; "" = not found


def _find_llvm_dis(min_version=16):
    """Locate an llvm-dis binary of at least `min_version`.

    The drivers write bitcode with LLVM 16 (opaque pointers), which the
    default /usr/bin/llvm-dis (LLVM 14 in the magma target containers)
    cannot read.  Prefer newer toolchains explicitly; fall back to
    lower versions only if nothing newer is available.

    Resolution order (highest version first):
      1. Versioned binaries `llvm-dis-<N>` for N=18..14 on PATH.
      2. Same, under common prefixes
         (/usr/bin, /usr/local/bin, /usr/lib/llvm-<N>/bin,
          /opt/homebrew/bin, /opt/llvm*/bin, /SVF/llvm-*.obj/bin,
          $LLVM_DIR/bin, $LLVM_HOME/bin).
      3. Unversioned `llvm-dis` on PATH (may be older, so tried last).
      4. Empty string → not found.
    """
    if _LLVM_DIS_CACHE[0] is not None:
        return _LLVM_DIS_CACHE[0]

    def _version_of(path):
        try:
            out = subprocess.check_output(
                [path, "--version"],
                stderr=subprocess.DEVNULL, text=True, errors="replace",
                timeout=5)
        except Exception:
            return None
        m = re.search(r'LLVM version\s+(\d+)\.(\d+)', out)
        return int(m.group(1)) if m else None

    # Candidate binary names, newest version first.
    named = [f"llvm-dis-{v}" for v in range(18, 13, -1)]
    # Directories worth probing.  Include env-var hints, SVF bundled
    # toolchain (on host or bind-mounted inside the container), and the
    # standard apt-installed `/usr/lib/llvm-<N>/bin`.
    prefixes = ["/usr/bin/", "/usr/local/bin/", "/opt/homebrew/bin/"]
    for v in range(18, 13, -1):
        prefixes.append(f"/usr/lib/llvm-{v}/bin/")
    prefixes += sorted(glob.glob("/opt/llvm*/bin/"))
    prefixes += sorted(glob.glob("/SVF/llvm-*.obj/bin/"))
    for env in ("LLVM_DIR", "LLVM_HOME"):
        val = os.environ.get(env)
        if val:
            prefixes.append(val.rstrip("/") + "/bin/")

    # Try named-and-versioned binaries first.
    for name in named:
        # PATH lookup.
        p = shutil.which(name)
        if p:
            _LLVM_DIS_CACHE[0] = p
            return p
        # Prefix lookup.
        for pref in prefixes:
            cand = pref + name
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                _LLVM_DIS_CACHE[0] = cand
                return cand

    # Try unversioned `llvm-dis` — but verify it's new enough.
    for loc in [shutil.which("llvm-dis")] + [pref + "llvm-dis" for pref in prefixes]:
        if not loc: continue
        if not (os.path.isfile(loc) and os.access(loc, os.X_OK)): continue
        v = _version_of(loc)
        if v is not None and v >= min_version:
            _LLVM_DIS_CACHE[0] = loc
            return loc

    # Last resort — accept any llvm-dis on PATH so the user sees a clear
    # version-mismatch error instead of silent "not found".
    p = shutil.which("llvm-dis")
    if p:
        _LLVM_DIS_CACHE[0] = p
        return p
    _LLVM_DIS_CACHE[0] = ""
    return ""


# --- regex patterns for IR parsing ---
# SSA names in textual IR: %<name> where name is [0-9]+ or [A-Za-z_][\w.]*
_SSA = r'%[-A-Za-z0-9_.]+'
# `@__uaf_area_ptr` shared-memory load, e.g.
#   %123 = load volatile ptr, ptr @__uaf_area_ptr, align 8
_SHMEM_LOAD_RE = re.compile(
    rf'^\s*({_SSA})\s*=\s*load\s+volatile\s+ptr,\s*ptr\s+@__uaf_area_ptr\b'
)
# `%geptr = getelementptr i8, ptr %shmemload, i64 OFFSET` (or inbounds).
_GEP_RE = re.compile(
    rf'^\s*({_SSA})\s*=\s*getelementptr\s+(?:inbounds\s+)?i8,\s*'
    rf'ptr\s+({_SSA}),\s*i64\s+(-?\d+)'
)
# `%set = or i8 %reg, CONST`
_OR_RE = re.compile(
    rf'^\s*({_SSA})\s*=\s*or\s+i8\s+({_SSA}),\s*(-?\d+)\b'
)
# `store volatile i8 %set, ptr %geptr, align 1, !dbg !N`
_STORE_RE = re.compile(
    rf'^\s*store\s+volatile\s+i8\s+({_SSA}),\s*ptr\s+({_SSA})'
    rf'[^!]*(?:,\s*!dbg\s+!(\d+))?\s*$'
)
# Function boundaries — reset local SSA state on new function.
_FUNC_BEGIN_RE = re.compile(r'^define\b')
_FUNC_END_RE   = re.compile(r'^\s*\}\s*$')
# Metadata lines:
#   !7 = !DILocation(line: 42, column: 5, scope: !8, inlinedAt: !9)
# `inlinedAt:` links to the DILocation of the call site that inlined this
# instruction.  Walking the chain gives every source location the emitted
# instruction originated from — we need this so a counter placed inside
# an inlined wrapper (e.g. png_free's body) can still be matched against
# the caller's patched source line.
_DILOC_RE = re.compile(
    r'^\s*!(\d+)\s*=\s*!DILocation\(\s*line:\s*(\d+)'
    r'(?:\s*,\s*column:\s*(\d+))?\s*,\s*scope:\s*!(\d+)'
)
_INLINED_AT_RE = re.compile(r'inlinedAt:\s*!(\d+)')
#   !8 = distinct !DISubprogram(name: "...", ..., file: !9, ...)
#   !9 = !DILexicalBlock(..., file: !9, ...)
#   !10 = !DINamespace(..., scope: !11, ...)
_SCOPE_LINE_RE = re.compile(
    r'^\s*!(\d+)\s*=\s*(?:distinct\s+)?!(\w+)\s*\((.*)\)\s*$'
)
#   !11 = !DIFile(filename: "xmlparse.c", directory: "...")
_DIFILE_RE = re.compile(
    r'^\s*!(\d+)\s*=\s*!DIFile\(filename:\s*"([^"]*)",'
    r'\s*directory:\s*"([^"]*)"'
)


def _extract_scope_file(text, key):
    """From a scope's body text, extract the `file: !N` reference."""
    m = re.search(r'file:\s*!(\d+)', text)
    return int(m.group(1)) if m else None


def _extract_scope_parent(text):
    """From a scope's body text, extract the `scope: !N` reference (if any)."""
    m = re.search(r'scope:\s*!(\d+)', text)
    return int(m.group(1)) if m else None


def _resolve_file(md_idx, scopes, diloc_cache, difile_cache):
    """Walk scope chain until a node with a `file: !N` field is found,
    then resolve that !N via difile_cache to (filename, directory)."""
    seen = set()
    cur = md_idx
    while cur is not None and cur not in seen:
        seen.add(cur)
        info = scopes.get(cur)
        if info is None:
            return None
        file_ref, parent_ref = info
        if file_ref is not None and file_ref in difile_cache:
            return difile_cache[file_ref]
        cur = parent_ref
    return None


def extract_manifest_from_bc(bc_path):
    """Return `{"tool": "free_finder"|"svf", "counters": [...], "source": bc_path}`
    or None if llvm-dis is unavailable or the file can't be parsed."""
    llvm_dis = _find_llvm_dis()
    if not llvm_dis:
        return None
    try:
        proc = subprocess.run(
            [llvm_dis, bc_path, "-o", "-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            errors="replace")
    except FileNotFoundError as e:
        print(f"extract_manifest_from_bc({bc_path}): "
              f"llvm-dis not found at runtime: {e}",
              file=sys.stderr)
        return None
    if proc.returncode != 0 or not proc.stdout:
        tail = (proc.stderr or "").strip().splitlines()[-3:]
        print(f"extract_manifest_from_bc({bc_path}): "
              f"llvm-dis exit={proc.returncode}, stderr tail:",
              file=sys.stderr)
        for line in tail:
            print(f"    {line}", file=sys.stderr)
        return None
    ir = proc.stdout

    # Pass 1: collect metadata nodes (DILocations, scope chains, DIFiles).
    diloc     = {}    # idx -> (line, col, scope_idx, inlined_at_idx_or_None)
    scopes    = {}    # idx -> (file_idx_or_None, parent_scope_idx_or_None)
    difile    = {}    # idx -> (filename, directory)

    for line in ir.splitlines():
        m = _DIFILE_RE.match(line)
        if m:
            difile[int(m.group(1))] = (m.group(2), m.group(3))
            continue
        m = _DILOC_RE.match(line)
        if m:
            idx   = int(m.group(1))
            ln    = int(m.group(2))
            col   = int(m.group(3)) if m.group(3) else 0
            scope = int(m.group(4))
            mia   = _INLINED_AT_RE.search(line)
            inlined_at = int(mia.group(1)) if mia else None
            diloc[idx] = (ln, col, scope, inlined_at)
            continue
        m = _SCOPE_LINE_RE.match(line)
        if m:
            idx  = int(m.group(1))
            body = m.group(3)
            # We don't care which DI kind it is — just whether it has
            # `file:` or `scope:` fields.
            file_ref   = _extract_scope_file(body, idx)
            parent_ref = _extract_scope_parent(body)
            scopes[idx] = (file_ref, parent_ref)

    # Pass 2: walk functions.  Per-function state: set of SSA names
    # that are loads of @__uaf_area_ptr, a map from GEP names to their
    # i64 OFFSET + parent shmem-load name, and a map from OR-result
    # names to the (const, source-reg) pair.
    counters = {}   # idx -> {"free": {...}, "use": {...}} (locations)
    saw_use_constant = False

    def set_loc(idx, kind, loc, chain=None):
        if idx not in counters:
            counters[idx] = {"idx": idx}
        if kind not in counters[idx]:
            counters[idx][kind] = loc
            if chain:
                counters[idx][kind + "_chain"] = chain

    def resolve_one(md_idx):
        """Resolve a single DILocation idx to {file, line, col}.  Does NOT
        walk the inlinedAt chain."""
        if md_idx not in diloc: return None
        ln, col, scope, _ = diloc[md_idx]
        fd = _resolve_file(scope, scopes, diloc, difile)
        if fd is None:
            return {"file": "?", "line": ln, "col": col}
        fname, directory = fd
        return {"file": fname, "line": ln, "col": col}

    def resolve_dbg_chain(md_idx):
        """Walk the inlinedAt chain from the leaf DILocation upward,
        returning the full list of (file, line) a counter was originated
        from.  First element is the leaf (innermost, where the store
        instruction actually sits); last element is the outermost caller.
        A counter is considered to cover ALL locations in this chain."""
        chain = []
        seen = set()
        cur = md_idx
        while cur is not None and cur not in seen:
            seen.add(cur)
            loc = resolve_one(cur)
            if loc is not None:
                chain.append(loc)
            tup = diloc.get(cur)
            if tup is None:
                break
            cur = tup[3]  # inlinedAt
        return chain

    shmem_loads = set()  # SSA names of @__uaf_area_ptr loads
    gep_offset  = {}     # gepname -> OFFSET (counter-based byte offset)
    or_const    = {}     # orname  -> CONST (1 or 2)

    in_func = False
    for line in ir.splitlines():
        if _FUNC_BEGIN_RE.match(line):
            in_func = True
            shmem_loads.clear()
            gep_offset.clear()
            or_const.clear()
            continue
        if in_func and _FUNC_END_RE.match(line):
            in_func = False
            continue
        if not in_func:
            continue

        m = _SHMEM_LOAD_RE.match(line)
        if m:
            shmem_loads.add(m.group(1))
            continue

        m = _GEP_RE.match(line)
        if m:
            dst, src, off = m.group(1), m.group(2), int(m.group(3))
            if src in shmem_loads:
                # Counter flag byte is at base+1 where base = (idx+1)*8.
                if off >= 9 and (off - 1) % 8 == 0:
                    gep_offset[dst] = off
            continue

        m = _OR_RE.match(line)
        if m:
            dst, src, const = m.group(1), m.group(2), int(m.group(3))
            if const in (1, 2):
                or_const[dst] = const
                if const == 2:
                    saw_use_constant = True
            continue

        m = _STORE_RE.match(line)
        if m:
            val, ptr, md = m.group(1), m.group(2), m.group(3)
            if ptr not in gep_offset or val not in or_const:
                continue
            off  = gep_offset[ptr]
            cnst = or_const[val]
            idx  = off // 8 - 1
            chain = resolve_dbg_chain(int(md)) if md else []
            loc = chain[0] if chain else None
            kind = "free" if cnst == 1 else "use"
            if loc is not None:
                set_loc(idx, kind, loc, chain)
            continue

    tool = "svf" if saw_use_constant else "free_finder"
    return {
        "tool": tool,
        "counters": [counters[i] for i in sorted(counters.keys())],
        "source": bc_path,
    }


def find_instr_bcs(target, analyzer):
    """Return list of '*_instr.bc' paths for the given target/analyzer."""
    pat = os.path.join(INSTR_OUT_ROOT, target, analyzer, "targets",
                       "*_instr.bc")
    return sorted(glob.glob(pat))


def merge_manifests(manifests):
    """Combine multiple per-fuzzer manifests into one.  Counter indices
    are local to each bitcode, so we re-key by (source, idx)."""
    if not manifests: return None
    tools = {m["tool"] for m in manifests}
    tool = "svf" if "svf" in tools else "free_finder"
    entries = []
    for m in manifests:
        for c in m["counters"]:
            entry = dict(c)
            entry["source"] = os.path.basename(m["source"])
            entries.append(entry)
    return {"tool": tool, "counters": entries}


# ---------------------------------------------------------------------------
# log parsing
# ---------------------------------------------------------------------------

# Legacy format: [FREE finder] Phase 1/2/3 ...
WRAPPER_NAME_RE = re.compile(
    r'\[FREE finder\]\s+Phase 2 \(level (\d+)\):\s+'
    r'Wrapper (?:accepted by name|detected):\s*([^\s(]+)'
)
PHASE1_RE = re.compile(
    r'\[FREE finder\] Phase 1: Identified (\d+) known dealloc'
)
PHASE2_RE = re.compile(
    r'\[FREE finder\] Phase 2: Found (\d+) thin dealloc wrapper'
)
PHASE3_RE = re.compile(
    r'\[FREE finder\] Phase 3: Found (\d+) free/realloc site\(s\)\s*'
    r'\((\d+) direct,\s*(\d+) via wrappers,\s*(\d+) via indirect calls\)'
)
FILTER_RE = re.compile(
    r'\[FREE finder\] Filter (\S+)\s*: rejected (\d+) wrapper'
)

# New SVFG-based format:
#   [FREE finder SVFG] Phase 1: Identified N known dealloc/realloc function(s)
#   [FREE finder SVFG] Phase 2: Found N wrapper function(s) via SVFG analysis
#     Dealloc: free -> X wrapper(s): name1 name2 ...
#     Dealloc: realloc -> Y wrapper(s): name1 name2 ...
#   [FREE finder driver] Collected N instrumentation site(s)
PHASE1_SVFG_RE = re.compile(
    r'\[FREE finder SVFG\] Phase 1: Identified (\d+) known dealloc'
)
PHASE2_SVFG_RE = re.compile(
    r'\[FREE finder SVFG\] Phase 2: Found (\d+) wrapper function'
)
DRIVER_SITES_RE = re.compile(
    r'\[FREE finder driver\] Collected (\d+) instrumentation site'
)
DEALLOC_WRAPPER_LINE_RE = re.compile(
    r'^\s*Dealloc:\s*(\S+)\s*->\s*(\d+)\s+wrapper\(s\):\s*(.*)$'
)


def parse_log(path):
    """Return (raw_summary_text, parsed_dict) for one free_finder log.

    Handles two log formats:
      * Legacy: '[FREE finder] Phase 1/2/3 ...' with Phase 3 direct/
        wrapper/indirect breakdown and per-level wrapper accept lines.
      * New SVFG: '[FREE finder SVFG] Phase 1/2 ...' followed by
        '  Dealloc: X -> N wrapper(s): name1 name2 ...' lines, and
        '[FREE finder driver] Collected N instrumentation site(s)'
        instead of a Phase 3 breakdown.
    """
    parsed = {
        "wrappers": set(),
        "phase1_known": None,
        "phase2_count": None,
        "phase3_total": None,
        "phase3_direct": None,
        "phase3_wrapper": None,
        "phase3_indirect": None,
        "filters": {},      # name -> rejected count
        "dealloc_groups": {},  # new format: dealloc name -> set of wrappers
        "format": None,     # 'legacy' | 'svfg' | None (unknown)
    }
    out_lines = []
    in_dealloc_block = False  # tracks whether next indented lines may be
                              # Dealloc group listings (new SVFG format)
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                stripped = line.rstrip()

                if 'Running free_finder-driver' in line:
                    out_lines.append(stripped)
                    in_dealloc_block = False
                    continue

                # Continuation of a new-format Phase 2 block: indented
                # '  Dealloc: X -> N wrapper(s): name1 name2 ...' lines.
                if in_dealloc_block:
                    md = DEALLOC_WRAPPER_LINE_RE.match(line)
                    if md:
                        dname = md.group(1)
                        names = md.group(3).split()
                        parsed["dealloc_groups"].setdefault(
                            dname, set()).update(names)
                        parsed["wrappers"].update(names)
                        # Echo a truncated form into the summary so the
                        # raw file is still useful but not thousands of
                        # lines.
                        preview = " ".join(names[:10])
                        more = ("" if len(names) <= 10
                                else f" ... (+{len(names) - 10} more)")
                        out_lines.append(
                            f"  Dealloc: {dname} -> {len(names)} "
                            f"wrapper(s): {preview}{more}")
                        continue
                    # Any non-dealloc line closes the block.
                    in_dealloc_block = False

                if '[FREE finder' not in line:
                    continue

                # Legacy per-wrapper accept lines — capture silently.
                m = WRAPPER_NAME_RE.search(line)
                if m:
                    parsed["wrappers"].add(m.group(2))
                    continue

                out_lines.append(stripped)

                # --- new SVFG format ---
                m = PHASE1_SVFG_RE.search(line)
                if m:
                    parsed["phase1_known"] = int(m.group(1))
                    parsed["format"] = "svfg"
                    continue
                m = PHASE2_SVFG_RE.search(line)
                if m:
                    parsed["phase2_count"] = int(m.group(1))
                    parsed["format"] = "svfg"
                    in_dealloc_block = True  # expect Dealloc: ... follow-ups
                    continue
                m = DRIVER_SITES_RE.search(line)
                if m:
                    parsed["phase3_total"] = int(m.group(1))
                    if parsed["format"] is None:
                        parsed["format"] = "svfg"
                    continue

                # --- legacy format ---
                m = PHASE1_RE.search(line)
                if m:
                    parsed["phase1_known"] = int(m.group(1))
                    parsed["format"] = "legacy"
                    continue
                m = PHASE2_RE.search(line)
                if m:
                    parsed["phase2_count"] = int(m.group(1))
                    parsed["format"] = "legacy"
                    continue
                m = PHASE3_RE.search(line)
                if m:
                    parsed["phase3_total"]    = int(m.group(1))
                    parsed["phase3_direct"]   = int(m.group(2))
                    parsed["phase3_wrapper"]  = int(m.group(3))
                    parsed["phase3_indirect"] = int(m.group(4))
                    parsed["format"] = "legacy"
                    continue
                m = FILTER_RE.search(line)
                if m:
                    parsed["filters"][m.group(1)] = int(m.group(2))
                    continue
    except Exception as e:
        return f"ERROR reading log: {e}", parsed

    return ("\n".join(out_lines)
            if out_lines else "(no free_finder phase output found)",
            parsed)


# ---------------------------------------------------------------------------
# verdict logic
# ---------------------------------------------------------------------------

def name_in_wrapper_set(name, wrappers, fptr_aliases=None):
    """Match a patch's referenced symbol against the analyzer's wrapper set.

    Match priority:
      1. exact (`name` ∈ wrappers)
      2. MAGMA-prefixed (magma canary instrumentation rewrites the symbol)
      3. static suffix (LLVM disambiguates static symbols as `name.NNN`)
      4. fptr alias (target-specific: e.g. libxml2 xmlFree -> xmlMemFree)

    No substring fallback — that produced false matches like
    xmlFree -> xmlFreeValidCtxt.
    """
    if name in wrappers:
        return name
    magma = "MAGMA_" + name
    if magma in wrappers:
        return magma
    for w in wrappers:
        if w.startswith(name + ".") or w.startswith(magma + "."):
            return w
    if fptr_aliases:
        target = fptr_aliases.get(name)
        if target:
            # Recurse on the resolved target (covers MAGMA_xmlMemFree etc.).
            sub = name_in_wrapper_set(target, wrappers, None)
            if sub:
                return f"{sub} (via fptr alias {name}->{target})"
    return None


def verdict_for_patch(target, patch_basename, items, free_sites,
                      manifest, canary_ids=None):
    """Return (status, reasoning) for one patch.

    Verdict is driven by the instrumented bitcode's counter manifest.
    We match each (file, line) recorded from the patch's added dealloc
    calls against the manifest's free-site locations (allow ±2-line
    slack for whitespace drift).  For svf manifests we also require
    the matched counter to have a `use` location (== a same-counter
    use-flag store was emitted after all filtering).

    status is one of: 'found', 'likely', 'missed', 'no-dealloc',
                       'canary-only', 'no-bc'.
    """
    if manifest is None:
        return ("no-bc",
                "no instrumented .bc manifest available (llvm-dis missing, "
                "build failed, or .bc not produced)")

    if not items:
        if canary_ids:
            ids_str = ", ".join(sorted(canary_ids))
            return ("canary-only",
                    f"MAGMA_FREE_LOG present ({ids_str}) — patch has an "
                    f"injected free canary but the dealloc mechanism is not "
                    f"identifiable by name (e.g. implicit realloc/GROW)")
        return ("no-dealloc",
                "patch added no dealloc-like calls and no MAGMA_FREE_LOG "
                "canary — likely a UAF on the use side, not a free site")

    tool = manifest.get("tool", "free_finder")
    # Build (basename, line) -> idx map from manifest free entries.
    # A counter can match on ANY location in its inlinedAt chain, not just
    # the leaf — otherwise counters placed inside an inlined wrapper (e.g.
    # a store emitted in png_free's body but for a call at pngset.c:644)
    # would be reported as missed.  We key by (basename, line) and include
    # every link of every counter's chain.  First-come-first-served: if
    # two chains hit the same (file, line), the lower-idx counter wins.
    free_by_loc = {}
    for c in manifest["counters"]:
        if "free" not in c:
            continue
        chain = c.get("free_chain") or [c["free"]]
        for loc in chain:
            key = (os.path.basename(loc["file"]), loc["line"])
            if key not in free_by_loc:
                free_by_loc[key] = c["idx"]

    # Locate the first counter whose free location (leaf OR any inlined-at
    # caller) matches any of the patch's dealloc lines (with ±2-line slack).
    for (pf, pl) in free_sites:
        base = os.path.basename(pf)
        for dl in (0, -1, 1, -2, 2):
            idx = free_by_loc.get((base, pl + dl))
            if idx is None:
                continue
            # Found a matching counter.
            if tool == "svf":
                use_loc = None
                for c in manifest["counters"]:
                    if c["idx"] == idx and "use" in c:
                        use_loc = c["use"]
                        break
                if use_loc is not None:
                    return ("found",
                            f"counter {idx}: free {base}:{pl} -> use "
                            f"{os.path.basename(use_loc['file'])}:"
                            f"{use_loc['line']}")
                return ("likely",
                        f"counter {idx}: free {base}:{pl} matched but "
                        f"no paired use — likely filtered (reachability, "
                        f"per-free cap, or hard cap)")
            return ("found", f"counter {idx}: free {base}:{pl}")

    # No match.  Build a helpful reason.
    if not free_sites:
        # Patch mentions dealloc-like calls but we couldn't pin down
        # a (file, line) pair — e.g. all matches came from lines
        # without an associated hunk cursor.
        return ("missed",
                "patch has dealloc-like calls but no file:line was "
                "extractable — check patch format")
    loc_list = ", ".join(f"{os.path.basename(f)}:{l}"
                         for f, l in free_sites[:3])
    more = "" if len(free_sites) <= 3 else f" (+{len(free_sites)-3} more)"
    return ("missed",
            f"no free-site counter in the instrumented .bc for patch "
            f"lines {loc_list}{more}")


# ---------------------------------------------------------------------------
# top-level driver
# ---------------------------------------------------------------------------

def find_log(log_dir, target, analyzer):
    """Locate the SLURM log for (target, analyzer) inside `log_dir`."""
    pat = os.path.join(log_dir,
                       f"build_afl_uaf_detect_{target}_{analyzer}.*.out")
    matches = sorted(glob.glob(pat))
    return matches[0] if matches else None


def collect_target(log_dir, target, analyzer):
    """Return (log_path, raw_log, parsed_log, patch_data, manifest).

    manifest: merged-across-fuzzer-entry-points counter manifest from the
    instrumented bitcode under
        /home/users/m/m.thielebein/magma_out/afl_uaf_detect/<target>/<analyzer>/
    Returns None if no bitcode or llvm-dis was found.
    """
    log_path = find_log(log_dir, target, analyzer)
    raw, parsed = ("(no log)", {})
    if log_path is not None:
        raw, parsed = parse_log(log_path)

    # Per-bitcode manifests, merged.
    bc_paths = find_instr_bcs(target, analyzer)
    per_bc_manifests = []
    for bc in bc_paths:
        m = extract_manifest_from_bc(bc)
        if m is not None:
            per_bc_manifests.append(m)
    manifest = merge_manifests(per_bc_manifests)

    patches_dir = os.path.join(TARGETS_DIR, target, "patches", "bugs")
    patches = sorted(glob.glob(os.path.join(patches_dir, "*.patch")))
    patch_data = []
    for p in patches:
        name = os.path.basename(p)
        items, ctx, canary_ids, free_sites = extract_dealloc_from_patch(p)
        patch_data.append((name, items, ctx, canary_ids, free_sites))

    return log_path, raw, parsed, patch_data, manifest, bc_paths


def write_summary(out_path, log_dir, analyzer, results):
    """Raw summary file (logs + patches + bitcode manifests)."""
    with open(out_path, 'w') as out:
        out.write(f"{analyzer} extraction\n")
        out.write(f"log_dir: {log_dir}\n")
        out.write("=" * 80 + "\n")
        for target, data in results.items():
            log_path, raw, parsed, patch_data, manifest, bc_paths = data
            out.write(f"\n{'=' * 80}\nTARGET: {target}\n{'=' * 80}\n")
            out.write(f"--- LOG ({log_path}) ---\n")
            if not raw or raw == "(no log)":
                out.write("(no log found)\n")
            else:
                out.write(raw + "\n")
            if parsed and parsed.get("wrappers"):
                out.write(
                    f"\nWrappers in log ({len(parsed['wrappers'])}):\n")
                for w in sorted(parsed["wrappers"]):
                    out.write(f"  - {w}\n")
            out.write("\n--- INSTRUMENTED BITCODE ---\n")
            for bc in bc_paths:
                out.write(f"  bc: {bc}\n")
            if manifest is None:
                out.write(
                    "  (no manifest — bc missing or llvm-dis not found)\n")
            else:
                cnt = len(manifest["counters"])
                with_use = sum(1 for c in manifest["counters"] if "use" in c)
                out.write(
                    f"  tool: {manifest['tool']}\n"
                    f"  counters: {cnt}"
                    + (f" ({with_use} with paired use)"
                       if manifest["tool"] == "svf" else "")
                    + "\n")
            for name, items, ctx, canary_ids, free_sites in patch_data:
                out.write(f"\n--- PATCH {name} ---\n")
                if canary_ids:
                    out.write("  CANARY IDs: "
                              + ", ".join(sorted(canary_ids)) + "\n")
                for h in ctx[:6]:
                    out.write("  HUNK: " + h + "\n")
                if free_sites:
                    for fs in free_sites[:6]:
                        out.write(f"  FREE LINE: {fs[0]}:{fs[1]}\n")
                if not items:
                    out.write("  (no dealloc-like calls in added lines)\n")
                for k, v in items[:15]:
                    out.write(f"  [{k}] {v[:140]}\n")


def write_table(out_path, log_dir, analyzer, results):
    """Compact per-bug verdict table driven by instrumented-bitcode manifest."""
    status_glyph = {
        "found":       "FOUND     ",
        "likely":      "LIKELY    ",
        "missed":      "MISSED    ",
        "canary-only": "CANARY    ",
        "no-dealloc":  "N/A       ",
        "no-bc":       "NO-BC     ",
    }
    all_statuses = list(status_glyph.keys())

    with open(out_path, 'w') as out:
        out.write(f"{analyzer} coverage table (bitcode-verified)\n")
        out.write(f"log_dir: {log_dir}\n")
        out.write("=" * 100 + "\n\n")

        grand = {s: 0 for s in all_statuses}

        for target, data in results.items():
            log_path, raw, parsed, patch_data, manifest, bc_paths = data
            out.write(f"\n{'=' * 100}\nTARGET: {target}\n{'=' * 100}\n")

            # Context from log (informational only — verdict uses manifest).
            if parsed:
                out.write(
                    f"  Log format             : "
                    f"{parsed.get('format') or 'unknown'}\n")
                if parsed.get("phase1_known") is not None:
                    out.write(
                        f"  Phase 1 known deallocs : "
                        f"{parsed['phase1_known']}\n")
                if parsed.get("phase2_count") is not None:
                    out.write(
                        f"  Phase 2 wrappers       : "
                        f"{parsed['phase2_count']}"
                        f"  ({len(parsed['wrappers'])} from log)\n")
                if parsed.get("phase3_total") is not None:
                    out.write(
                        f"  Sites (driver)         : "
                        f"{parsed['phase3_total']}\n")

            # Manifest summary (authoritative).
            if manifest is None:
                out.write(
                    f"  Bitcode manifest       : NONE"
                    f"  ({'no .bc found' if not bc_paths else 'llvm-dis failed'})\n")
            else:
                cnt = len(manifest["counters"])
                with_use = sum(1 for c in manifest["counters"] if "use" in c)
                out.write(
                    f"  Bitcode manifest       : tool={manifest['tool']}, "
                    f"counters={cnt}"
                    + (f", paired-use={with_use}"
                       if manifest["tool"] == "svf" else "")
                    + "\n")
                for bc in bc_paths:
                    out.write(f"    from: {bc}\n")

            hints = TARGET_HINTS.get(target, {})
            if hints.get("notes"):
                out.write(f"  Notes                  : {hints['notes']}\n")
            out.write("\n")

            out.write(
                f"  {'Bug':<48} {'Status':<10} {'Dealloc / Reasoning'}\n")
            out.write("  " + "-" * 96 + "\n")

            t_count = {s: 0 for s in all_statuses}

            for name, items, ctx, canary_ids, free_sites in patch_data:
                status, reasoning = verdict_for_patch(
                    target, name, items, free_sites, manifest, canary_ids)
                t_count[status] += 1
                grand[status] += 1

                dealloc_kinds = []
                for k, _ in items:
                    is_ctx = k.endswith("@ctx")
                    bare = k[:-len("@ctx")] if is_ctx else k
                    suffix = " (ctx)" if is_ctx else ""
                    if bare == "direct_free":
                        dealloc_kinds.append("direct free" + suffix)
                    elif bare.startswith("wrapper:"):
                        dealloc_kinds.append(bare[len("wrapper:"):] + suffix)
                    elif bare.startswith("fptr_named:"):
                        dealloc_kinds.append(
                            "fptr:" + bare[len("fptr_named:"):] + suffix)
                    elif bare == "indirect_fptr":
                        dealloc_kinds.append("indirect_fptr" + suffix)
                    elif bare.startswith("realloc:"):
                        dealloc_kinds.append(bare[len("realloc:"):] + suffix)
                dealloc_str = ", ".join(sorted(set(dealloc_kinds))) or "(none)"

                canary_str = ""
                if canary_ids:
                    canary_str = ("  [canary: "
                                  + ", ".join(sorted(canary_ids)) + "]")

                out.write(
                    f"  {name:<48} {status_glyph[status]} "
                    f"{dealloc_str}{canary_str}\n")
                if reasoning:
                    out.write(f"  {'':<48} {'':<10} -> {reasoning}\n")

            out.write(
                f"\n  Subtotal: "
                f"{t_count['found']} found, "
                f"{t_count['likely']} likely, "
                f"{t_count['missed']} missed, "
                f"{t_count['canary-only']} canary-only, "
                f"{t_count['no-dealloc']} N/A, "
                f"{t_count['no-bc']} no-bc\n")

        out.write("\n" + "=" * 100 + "\n")
        out.write(
            f"GRAND TOTAL: "
            f"{grand['found']} found, "
            f"{grand['likely']} likely, "
            f"{grand['missed']} missed, "
            f"{grand['canary-only']} canary-only, "
            f"{grand['no-dealloc']} N/A, "
            f"{grand['no-bc']} no-bc\n")


def parse_args():
    ap = argparse.ArgumentParser(
        description="Bitcode-verified coverage table for a build job.")
    ap.add_argument("job_id", nargs="?",
                    help="build job directory name "
                         "(e.g. 20260407_142106). "
                         "Looked up under " + BUILD_JOBS_ROOT)
    ap.add_argument("--log-dir",
                    help="absolute path to a build_jobs/<id> directory; "
                         "overrides job_id")
    ap.add_argument("--analyzer",
                    choices=ANALYZERS + ["both"],
                    default="both",
                    help="which analyzer(s) to process "
                         "(default: both free_finder and svf)")
    ap.add_argument("--out-summary", help="override summary output path")
    ap.add_argument("--out-table",   help="override table output path")
    return ap.parse_args()


def main():
    args = parse_args()
    if args.log_dir:
        log_dir = args.log_dir
        tag = os.path.basename(log_dir.rstrip("/"))
    elif args.job_id:
        log_dir = os.path.join(BUILD_JOBS_ROOT, args.job_id)
        tag = args.job_id
    else:
        print("error: provide a job_id or --log-dir", file=sys.stderr)
        sys.exit(2)

    if not os.path.isdir(log_dir):
        print(f"error: log_dir does not exist: {log_dir}", file=sys.stderr)
        sys.exit(2)

    os.makedirs(RESULTS_DIR, exist_ok=True)

    llvm_dis = _find_llvm_dis()
    if not llvm_dis:
        print(
            "WARNING: no llvm-dis found on PATH or common prefixes.\n"
            "         Per-bug verdicts will be 'no-bc' for every target.\n"
            "         Install with e.g. `apt install llvm-18-tools`\n"
            "         or point PATH at an existing LLVM toolchain.",
            file=sys.stderr)
    else:
        print(f"using llvm-dis: {llvm_dis}")

    analyzers = ANALYZERS if args.analyzer == "both" else [args.analyzer]

    for analyzer in analyzers:
        summary_path = (args.out_summary
                        or os.path.join(RESULTS_DIR,
                                        f"{analyzer}_summary_{tag}.txt"))
        table_path = (args.out_table
                      or os.path.join(RESULTS_DIR,
                                      f"{analyzer}_table_{tag}.txt"))

        results = {}
        for t in TARGETS:
            results[t] = collect_target(log_dir, t, analyzer)

        write_summary(summary_path, log_dir, analyzer, results)
        write_table(table_path,   log_dir, analyzer, results)

        print(f"[{analyzer}] WROTE {summary_path}")
        print(f"[{analyzer}] WROTE {table_path}")


if __name__ == "__main__":
    main()
