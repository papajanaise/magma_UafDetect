#!/bin/bash
# Fetch libexpat at tag R_2_5_0
#
# Version strategy:
#   R_2_5_0 is the first tag that contains fixes for BOTH injected CVEs:
#     - CVE-2022-40674 (fixed in R_2_4_9, PR #629 commit 4a32da8)
#     - CVE-2022-43680 (fixed in R_2_5_0, PR #650 commit 5290462)
#
#   The Magma injection patches (in patches/) will reverse both fixes,
#   re-introducing the original UAF conditions in a clean, buildable tree.
set -e

git clone \
    --depth 1 \
    --branch R_2_5_0 \
    https://github.com/libexpat/libexpat.git \
    "$TARGET/repo"
