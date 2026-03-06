#!/bin/bash

# SPDX-License-Identifier: Apache-2.0

##
# Pre-install dependencies for libjpeg-turbo target.
# Runs as root inside the Docker container.
##

apt-get update && apt-get install -y \
    cmake \
    nasm \
    make \
    git \
    autoconf \
    libtool \
    pkg-config
