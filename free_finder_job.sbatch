#!/bin/bash
#SBATCH --job-name=ff_extract
#SBATCH --output=/home/users/m/m.thielebein/magma_results/ff_extract.%A_%a.out
#SBATCH --error=/home/users/m/m.thielebein/magma_results/ff_extract.%A_%a.err
#SBATCH --time=00:20:00
#SBATCH --mem=4G
#SBATCH --cpus-per-task=1
#SBATCH --partition=standard
#SBATCH --array=0-1

# Job array: task 0 = free_finder, task 1 = svf.
# Both tasks run the same extract script in parallel, each over one
# analyzer's instrumented bitcodes.
#
# Usage:
#   sbatch free_finder_job.sbatch <build_job_id>
#
# To run only one analyzer, override the array range at submit time:
#   sbatch --array=0 free_finder_job.sbatch <build_job_id>   # free_finder
#   sbatch --array=1 free_finder_job.sbatch <build_job_id>   # svf
#
# Writes (one pair per analyzer task):
#   /home/users/m/m.thielebein/magma_results/free_finder_summary_<id>.txt
#   /home/users/m/m.thielebein/magma_results/free_finder_table_<id>.txt
#   /home/users/m/m.thielebein/magma_results/svf_summary_<id>.txt
#   /home/users/m/m.thielebein/magma_results/svf_table_<id>.txt
#
# Mechanism:
#   The sbatch script loads Singularity and `singularity exec`s into a
#   magma afl_uaf_detect container (they have LLVM 16's `llvm-dis-16`,
#   which is needed to parse the opaque-pointer bitcode produced by the
#   SVF drivers).  The Python extract script's `_find_llvm_dis()` will
#   pick up `llvm-dis-16` from PATH inside the container automatically.

set -euo pipefail

module load singularity

JOB_ID="${1:-}"
if [[ -z "$JOB_ID" ]]; then
    echo "usage: sbatch $0 <build_job_id>" >&2
    exit 2
fi

ANALYZERS=(free_finder svf)
TASK_ID="${SLURM_ARRAY_TASK_ID:-0}"
ANALYZER="${ANALYZERS[$TASK_ID]:-}"
if [[ -z "$ANALYZER" ]]; then
    echo "ERROR: array task $TASK_ID has no analyzer mapping" >&2
    exit 2
fi

# Pick any non-devcontainer afl_uaf_detect .sif — they all ship llvm-dis-16.
SIF=$(ls /home/users/m/m.thielebein/magma_containers/magma_afl_uaf_detect_*.sif \
        | grep -v devcontainer | head -1)
if [[ -z "$SIF" ]]; then
    echo "ERROR: no afl_uaf_detect .sif found" >&2
    exit 1
fi

echo "[$ANALYZER] container : $SIF"
echo "[$ANALYZER] build job : $JOB_ID"

singularity exec "$SIF" \
    python3 /home/users/m/m.thielebein/magma_results/free_finder_extract.py \
    "$JOB_ID" --analyzer "$ANALYZER"

echo "[$ANALYZER] DONE"
