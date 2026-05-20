#!/bin/bash
#
# Remove old job/run directories, keeping the N most recent
# (default N=10) for each fuzzer/target/program in magma_results
# and the most recent one for each fuzzer/target in magma_workdir.
#
# Usage:
#   ./clean_old_results.sh                        # dry-run, keep 10 results, 1 workdir
#   ./clean_old_results.sh --delete               # actually delete
#   ./clean_old_results.sh --results-only --delete
#   KEEP=20 ./clean_old_results.sh --delete       # override results keep count
#

RESULTS_DIR="/home/users/m/m.thielebein/magma_results"
WORKDIR="/home/users/m/m.thielebein/magma_workdir"
DRY_RUN=true
RESULTS_ONLY=false
KEEP_RESULTS="${KEEP:-10}"
KEEP_WORKDIR=1

for arg in "$@"; do
    case "$arg" in
        --delete)        DRY_RUN=false ;;
        --results-only)  RESULTS_ONLY=true ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

total_removed=0
total_kept=0

# Helper: given a parent dir and a name pattern regex, keep only the latest
# (sorted descending), delete the rest.
clean_subdirs() {
    local parent="$1"
    local pattern="$2"
    local keep="${3:-1}"

    mapfile -t dirs < <(
        for d in "$parent"/*/; do
            [[ -d "$d" ]] || continue
            name=$(basename "$d")
            [[ "$name" =~ $pattern ]] && echo "$name"
        done | sort -rn
    )

    if [[ ${#dirs[@]} -le $keep ]]; then
        ((total_kept += ${#dirs[@]}))
        return
    fi

    ((total_kept += keep))

    for old in "${dirs[@]:$keep}"; do
        old_path="${parent}/${old}"
        if $DRY_RUN; then
            echo "[dry-run] rm -rf $old_path"
        else
            rm -rf "$old_path"
            echo "removed $old_path"
        fi
        ((total_removed++))
    done
}

# --- magma_results: <fuzzer>/<target>/<program>/<job_id> ---
echo "=== magma_results (keep newest $KEEP_RESULTS) ==="
for fuzzer_dir in "$RESULTS_DIR"/*/; do
    [[ -d "$fuzzer_dir" ]] || continue
    for target_dir in "$fuzzer_dir"/*/; do
        [[ -d "$target_dir" ]] || continue
        for program_dir in "$target_dir"/*/; do
            [[ -d "$program_dir" ]] || continue
            clean_subdirs "$program_dir" '^[0-9]+$' "$KEEP_RESULTS"
        done
    done
done

if $RESULTS_ONLY; then
    echo "--- skipping magma_workdir (--results-only) ---"
else
# --- magma_workdir: <fuzzer>/<target>/<analyzer>/<timestamp> ---
# Some targets have timestamps directly, others nest under an analyzer dir.
echo "=== magma_workdir (keep newest $KEEP_WORKDIR) ==="
for fuzzer_dir in "$WORKDIR"/afl_uaf_detect/ "$WORKDIR"/aflplusplus_lto_asan/; do
    [[ -d "$fuzzer_dir" ]] || continue
    echo "--- $(basename "$fuzzer_dir") ---"
    for target_dir in "$fuzzer_dir"/*/; do
        [[ -d "$target_dir" ]] || continue
        for sub_dir in "$target_dir"/*/; do
            [[ -d "$sub_dir" ]] || continue
            name=$(basename "$sub_dir")
            if [[ "$name" =~ ^[0-9]{8}_[0-9]{6}$ ]]; then
                # Timestamps directly under target — clean at target level
                clean_subdirs "$target_dir" '^[0-9]{8}_[0-9]{6}$' "$KEEP_WORKDIR"
                break
            else
                # Analyzer subdir — clean timestamps inside it
                clean_subdirs "$sub_dir" '^[0-9]{8}_[0-9]{6}$' "$KEEP_WORKDIR"
            fi
        done
    done
done
fi

echo ""
if $DRY_RUN; then
    echo "Dry run: would remove $total_removed directories (keeping $total_kept latest)."
    echo "Re-run with --delete to actually remove them."
else
    echo "Removed $total_removed directories (kept $total_kept latest)."
fi
