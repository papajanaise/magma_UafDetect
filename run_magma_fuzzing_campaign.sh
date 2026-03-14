#!/bin/bash

#SBATCH -o campaign.%j.%N.out   # Output-File
#SBATCH -J campaign_%j_%N 		# Job Name
#SBATCH --ntasks=1 		# Anzahl Prozesse (CPU-Cores)
#SBATCH --mem=500M              # 500MiB resident memory pro node

##Max Walltime vorgeben:
#SBATCH --time=24:00:00 # Erwartete Laufzeit

#Auf Standard-Knoten rechnen:
#SBATCH --partition=standard

export SINGULARITYENV_FUZZER_NAME=$FUZZER_NAME
export SINGULARITYENV_TARGET_NAME=$TARGET_NAME
export SINGULARITYENV_FUZZER=/magma/fuzzers/$FUZZER_NAME
export SINGULARITYENV_TARGET=/magma/targets/$TARGET_NAME
export SINGULARITYENV_MAGMA=/magma/magma
export SINGULARITYENV_OUT=/magma_out
export SINGULARITYENV_SHARED=/magma_shared
export SINGULARITYENV_PROGRAM=$PROGRAM_NAME
export SINGULARITYENV_POLL=${POLL:-5}
export SINGULARITYENV_TIMEOUT=${TIMEOUT:-86400}

mkdir -p /home/users/m/m.thielebein/magma_out/${FUZZER_NAME}/${TARGET_NAME}
mkdir -p /home/users/m/m.thielebein/magma_result/${FUZZER_NAME}/${TARGET_NAME}

module load singularity

singularity exec magma_${FUZZER_NAME}_${TARGET_NAME}.sif -c \
    --bind /home/users/m/m.thielebein/magma_UafDetect:/magma \
    --bind /home/users/m/m.thielebein/magma_out/${FUZZER_NAME}/${TARGET_NAME}:/magma_out \
    --bind /home/users/m/m.thielebein/magma_result/${FUZZER_NAME}/${TARGET_NAME}:/magma_shared \
    /magma/magma/run.sh