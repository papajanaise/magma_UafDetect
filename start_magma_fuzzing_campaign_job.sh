#!/bin/bash
set -e

export FUZZER_NAME=aflplusplus_lto_asan
export TARGET_NAME=expat
export PROGRAM_NAME=xml_parse_fuzzer_UTF-8

sbatch run_magma_fuzzing_campaign.sh