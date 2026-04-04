#!/bin/bash
#
# Remove old job/run directories, keeping only the most recent one,
# for each fuzzer/target/program in magma_results and each
# fuzzer/target in magma_workdir.
#
# Usage:
#   ./clean_old_results.sh          # dry-run (shows what would be deleted)
#   ./clean_old_results.sh --delete # actually delete
#

RESULTS_DIR="/home/users/m/m.thielebein/magma_results"
WORKDIR="/home/users/m/m.thielebein/magma_workdir"
DRY_RUN=true

if [[ "${1:-}" == "--delete" ]]; then
    DRY_RUN=false
fi

total_removed=0
total_kept=0

# Helper: given a parent dir and a name pattern regex, keep only the latest
# (sorted descending), delete the rest.
clean_subdirs() {
    local parent="$1"
    local pattern="$2"

    mapfile -t dirs < <(
        for d in "$parent"/*/; do
            [[ -d "$d" ]] || continue
            name=$(basename "$d")
            [[ "$name" =~ $pattern ]] && echo "$name"
        done | sort -rn
    )

    if [[ ${#dirs[@]} -le 1 ]]; then
        return
    fi

    ((total_kept++))

    for old in "${dirs[@]:1}"; do
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
echo "=== magma_results ==="
for fuzzer_dir in "$RESULTS_DIR"/*/; do
    [[ -d "$fuzzer_dir" ]] || continue
    for target_dir in "$fuzzer_dir"/*/; do
        [[ -d "$target_dir" ]] || continue
        for program_dir in "$target_dir"/*/; do
            [[ -d "$program_dir" ]] || continue
            clean_subdirs "$program_dir" '^[0-9]+$'
        done
    done
done

# --- magma_workdir: <fuzzer>/<target>/<timestamp> ---
echo "=== magma_workdir ==="
for fuzzer_dir in "$WORKDIR"/*/; do
    [[ -d "$fuzzer_dir" ]] || continue
    for target_dir in "$fuzzer_dir"/*/; do
        [[ -d "$target_dir" ]] || continue
        clean_subdirs "$target_dir" '^[0-9]{8}_[0-9]{6}$'
    done
done

echo ""
if $DRY_RUN; then
    echo "Dry run: would remove $total_removed directories (keeping $total_kept latest)."
    echo "Re-run with --delete to actually remove them."
else
    echo "Removed $total_removed directories (kept $total_kept latest)."
fi
