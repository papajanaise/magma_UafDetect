#!/bin/bash

# SPDX-License-Identifier: Apache-2.0

##
# Download seed corpus for libjpeg_turbo_fuzzer from the OSS-Fuzz public
# corpus bucket. Run this script once from the repo root before building:
#
#   bash targets/libjpeg_turbo/corpus/libjpeg_turbo_fuzzer/get_seeds.sh
#
# Requirements: gsutil (Google Cloud SDK) or curl/wget with public access.
# The OSS-Fuzz corpus bucket is publicly readable without authentication.
##

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---- Option 1: gsutil (preferred, fastest) --------------------------------
if command -v gsutil &>/dev/null; then
    echo "[*] Downloading seeds via gsutil..."
    gsutil -m cp "gs://oss-fuzz-corpus/libjpeg-turbo/libjpeg_turbo_fuzzer_seed_corpus.zip" .
    unzip -o libjpeg_turbo_fuzzer_seed_corpus.zip
    rm -f libjpeg_turbo_fuzzer_seed_corpus.zip
    echo "[+] Done. $(ls -1 *.jpg *.jpeg 2>/dev/null | wc -l) seed files downloaded."
    exit 0
fi

# ---- Option 2: curl (fallback) --------------------------------------------
if command -v curl &>/dev/null; then
    echo "[*] Downloading seeds via curl..."
    curl -L -o libjpeg_turbo_fuzzer_seed_corpus.zip \
        "https://storage.googleapis.com/oss-fuzz-corpus/libjpeg-turbo/libjpeg_turbo_fuzzer_seed_corpus.zip"
    unzip -o libjpeg_turbo_fuzzer_seed_corpus.zip
    rm -f libjpeg_turbo_fuzzer_seed_corpus.zip
    echo "[+] Done."
    exit 0
fi

echo "[!] Neither gsutil nor curl found. Please install one and re-run, or"
echo "    manually place JPEG files in this directory."
exit 1
