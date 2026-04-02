#!/bin/bash
#SBATCH -J bc-file-builder
#SBATCH --ntasks=1
#SBATCH --mem=16G
#SBATCH --time=25:00:00
#SBATCH --partition=standard
#SBATCH --mail-type=ALL
#SBATCH --mail-user=m.thielebein@tu-berlin.de
#SBATCH --exclude=gpu[001-066]

module load singularity
set -euo pipefail
ulimit -v unlimited

export SINGULARITYENV_FUZZER_NAME=${FUZZER_NAME}
export SINGULARITYENV_TARGET_NAME=${TARGET_NAME}
export SINGULARITYENV_FUZZER=/magma/fuzzers/$FUZZER_NAME
export SINGULARITYENV_TARGET=/magma/targets/$TARGET_NAME
export SINGULARITYENV_ANALYZER=${ANALYZER}
export SINGULARITYENV_MAGMA=/magma/magma
export SINGULARITYENV_OUT=/magma_out
export SINGULARITYENV_SHARED=/magma_shared

CAMPAIGN_DIR="/home/users/m/m.thielebein/magma_workdir/${FUZZER_NAME}/${TARGET_NAME}/$(date '+%Y%m%d_%H%M%S')"
mkdir -p "$CAMPAIGN_DIR"
echo "Campaign directory: $CAMPAIGN_DIR"

if [ "$FUZZER_NAME" == "afl_uaf_detect" ]; then
    OUT_DIR="/home/users/m/m.thielebein/magma_out/${FUZZER_NAME}/${TARGET_NAME}/${ANALYZER}"
else
    OUT_DIR="/home/users/m/m.thielebein/magma_out/${FUZZER_NAME}/${TARGET_NAME}"
fi
echo "Output directory: $OUT_DIR"
mkdir -p "$OUT_DIR"

module load singularity
singularity exec --writable-tmpfs \
    -B /home/users/m/m.thielebein/magma_UafDetect/magma:/magma/magma \
    -B /home/users/m/m.thielebein/magma_UafDetect/tools:/magma/tools \
    -B /home/users/m/m.thielebein/magma_UafDetect/fuzzers/$FUZZER_NAME:/magma/fuzzers/$FUZZER_NAME \
    -B /home/users/m/m.thielebein/magma_UafDetect/targets/$TARGET_NAME:/magma/targets/$TARGET_NAME \
    -B "$CAMPAIGN_DIR":/magma_shared \
    -B /home/users/m/m.thielebein/SVF:/SVF \
    -B "$OUT_DIR":/magma_out \
    -B /home/users/m/m.thielebein/magma_UafDetect/prepare_magma_devcontainer.sh:/prepare_magma_devcontainer.sh \
    /home/users/m/m.thielebein/magma_containers/magma_${FUZZER_NAME}_${TARGET_NAME}.sif \
    /prepare_magma_devcontainer.sh
    