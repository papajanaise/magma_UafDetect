#!/bin/bash
# Preinstall system dependencies for libexpat Magma target
set -e

apt-get update -qq
apt-get install -y --no-install-recommends \
    git \
    cmake \
    make \
    automake \
    autoconf \
    libtool \
    pkg-config \
    docbook2x \
    ca-certificates \
    gsutil
