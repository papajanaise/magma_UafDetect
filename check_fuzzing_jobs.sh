#!/bin/bash

# List all expected jobs vs actual running jobs
comm -23 \
  <(for f in afl_uaf_detect aflplusplus_lto_asan; do
      for t in expat libjpeg-turbo libpng libxml2 sqlite3; do
        source /home/users/m/m.thielebein/magma_UafDetect/targets/$t/configrc
        for p in "${PROGRAMS[@]}"; do echo "${f}_${t}_${p}"; done
      done
    done | sort) \
  <(squeue -u $USER -h -o "%j" | sort) 
