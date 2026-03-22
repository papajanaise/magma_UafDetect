#!/bin/bash
set -eu

FUZZER="${FUZZER:-aflplusplus_lto_asan}"
TARGETS="${TARGETS:-sqlite3}"

TEMPLATE="magma_containers/magma_devcontainer.def"
GENERATED="/tmp/magma_devcontainer_generated.def"
OUTPUT="magma_containers/magma_${FUZZER}_${TARGETS// /_}.sif"

# Substitute placeholders into a temporary def file
sed -e "s|@@FUZZER@@|${FUZZER}|g" \
    -e "s|@@TARGETS@@|${TARGETS}|g" \
    "${TEMPLATE}" > "${GENERATED}"

echo "Building with FUZZER=${FUZZER} TARGETS=${TARGETS}"
echo "  def file: ${GENERATED}"
echo "  output:   ${OUTPUT}"

module load singularity
singularity build --remote "${OUTPUT}" "${GENERATED}"
