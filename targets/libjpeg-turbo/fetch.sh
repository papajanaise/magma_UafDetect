#!/bin/bash

# SPDX-License-Identifier: Apache-2.0

##
# Fetch the libjpeg-turbo source code.
# Pinned to version 2.1.3 for reproducibility.
# Source is stored in $TARGET/repo as required by Magma.
##

git clone --branch 2.1.3 --depth 1 \
    https://github.com/libjpeg-turbo/libjpeg-turbo \
    "$TARGET/repo"
