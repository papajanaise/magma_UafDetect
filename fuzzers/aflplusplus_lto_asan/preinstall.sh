#!/bin/bash
set -e

apt-get update && \
    apt-get install -y make build-essential git wget libexpat1-dev

apt-get install -y apt-utils apt-transport-https ca-certificates gnupg

echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-16 main" >> /etc/apt/sources.list
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

apt-get update && \
    apt-get install -y clang-16 clangd-16 clang-tools-16 libc++1-16 libc++-16-dev \
      libc++abi1-16 libc++abi-16-dev libclang1-16 libclang-16-dev libclang-common-16-dev \
      libclang-cpp11 libclang-cpp11-dev liblld-16 liblld-16-dev liblldb-16 \
      liblldb-16-dev libllvm11 libomp-16-dev libomp5-16 lld-16 lldb-16 \
      llvm-16 llvm-16-dev llvm-16-runtime llvm-16-tools

update-alternatives \
  --install /usr/lib/llvm              llvm             /usr/lib/llvm-16  20 \
  --slave   /usr/bin/llvm-config       llvm-config      /usr/bin/llvm-config-16  \
    --slave   /usr/bin/llvm-ar           llvm-ar          /usr/bin/llvm-ar-16 \
    --slave   /usr/bin/llvm-as           llvm-as          /usr/bin/llvm-as-16 \
    --slave   /usr/bin/llvm-bcanalyzer   llvm-bcanalyzer  /usr/bin/llvm-bcanalyzer-16 \
    --slave   /usr/bin/llvm-c-test       llvm-c-test      /usr/bin/llvm-c-test-16 \
    --slave   /usr/bin/llvm-cov          llvm-cov         /usr/bin/llvm-cov-16 \
    --slave   /usr/bin/llvm-diff         llvm-diff        /usr/bin/llvm-diff-16 \
    --slave   /usr/bin/llvm-dis          llvm-dis         /usr/bin/llvm-dis-16 \
    --slave   /usr/bin/llvm-dwarfdump    llvm-dwarfdump   /usr/bin/llvm-dwarfdump-16 \
    --slave   /usr/bin/llvm-extract      llvm-extract     /usr/bin/llvm-extract-16 \
    --slave   /usr/bin/llvm-link         llvm-link        /usr/bin/llvm-link-16 \
    --slave   /usr/bin/llvm-mc           llvm-mc          /usr/bin/llvm-mc-16 \
    --slave   /usr/bin/llvm-nm           llvm-nm          /usr/bin/llvm-nm-16 \
    --slave   /usr/bin/llvm-objdump      llvm-objdump     /usr/bin/llvm-objdump-16 \
    --slave   /usr/bin/llvm-ranlib       llvm-ranlib      /usr/bin/llvm-ranlib-16 \
    --slave   /usr/bin/llvm-readobj      llvm-readobj     /usr/bin/llvm-readobj-16 \
    --slave   /usr/bin/llvm-rtdyld       llvm-rtdyld      /usr/bin/llvm-rtdyld-16 \
    --slave   /usr/bin/llvm-size         llvm-size        /usr/bin/llvm-size-16 \
    --slave   /usr/bin/llvm-stress       llvm-stress      /usr/bin/llvm-stress-16 \
    --slave   /usr/bin/llvm-symbolizer   llvm-symbolizer  /usr/bin/llvm-symbolizer-16 \
    --slave   /usr/bin/llvm-tblgen       llvm-tblgen      /usr/bin/llvm-tblgen-16

update-alternatives \
  --install /usr/bin/clang                 clang                  /usr/bin/clang-16     20 \
  --slave   /usr/bin/clang++               clang++                /usr/bin/clang++-16 \
  --slave   /usr/bin/clang-cpp             clang-cpp              /usr/bin/clang-cpp-16
