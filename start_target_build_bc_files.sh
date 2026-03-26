#!/bin/bash

export FUZZER="aflplusplus_lto_asan"
export TARGET="libjpeg-turbo"
export ANALYZER="free_finder"    #free_finder or svf Analysis


sbatch --export=FUZZER="${FUZZER}",TARGET="${TARGET}",ANALYZER="${ANALYZER}" \
        /home/users/m/m.thielebein/magma_UafDetect/run_target_build_bc_files.sh

