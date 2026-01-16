#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update && \
    apt-get install -y make build-essential git wget lsb-release gnupg software-properties-common \
    cmake ninja-build python3 \
    zlib1g-dev libz3-dev z3 \
    libtinfo5 

wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
./llvm.sh 13   # installs clang-13, lld-13, lldb-13, etc.

apt-get install -y clang-13 && rm -rf /var/lib/apt/lists/*

update-alternatives \
  --install /usr/lib/llvm              llvm             /usr/lib/llvm-13  20 \
  --slave   /usr/bin/llvm-config       llvm-config      /usr/bin/llvm-config-13  \
    --slave   /usr/bin/llvm-ar           llvm-ar          /usr/bin/llvm-ar-13 \
    --slave   /usr/bin/llvm-as           llvm-as          /usr/bin/llvm-as-13 \
    --slave   /usr/bin/llvm-bcanalyzer   llvm-bcanalyzer  /usr/bin/llvm-bcanalyzer-13 \
    --slave   /usr/bin/llvm-c-test       llvm-c-test      /usr/bin/llvm-c-test-13 \
    --slave   /usr/bin/llvm-cov          llvm-cov         /usr/bin/llvm-cov-13 \
    --slave   /usr/bin/llvm-diff         llvm-diff        /usr/bin/llvm-diff-13 \
    --slave   /usr/bin/llvm-dis          llvm-dis         /usr/bin/llvm-dis-13 \
    --slave   /usr/bin/llvm-dwarfdump    llvm-dwarfdump   /usr/bin/llvm-dwarfdump-13 \
    --slave   /usr/bin/llvm-extract      llvm-extract     /usr/bin/llvm-extract-13 \
    --slave   /usr/bin/llvm-link         llvm-link        /usr/bin/llvm-link-13 \
    --slave   /usr/bin/llvm-mc           llvm-mc          /usr/bin/llvm-mc-13 \
    --slave   /usr/bin/llvm-nm           llvm-nm          /usr/bin/llvm-nm-13 \
    --slave   /usr/bin/llvm-objdump      llvm-objdump     /usr/bin/llvm-objdump-13 \
    --slave   /usr/bin/llvm-ranlib       llvm-ranlib      /usr/bin/llvm-ranlib-13 \
    --slave   /usr/bin/llvm-readobj      llvm-readobj     /usr/bin/llvm-readobj-13 \
    --slave   /usr/bin/llvm-rtdyld       llvm-rtdyld      /usr/bin/llvm-rtdyld-13 \
    --slave   /usr/bin/llvm-size         llvm-size        /usr/bin/llvm-size-13 \
    --slave   /usr/bin/llvm-stress       llvm-stress      /usr/bin/llvm-stress-13 \
    --slave   /usr/bin/llvm-symbolizer   llvm-symbolizer  /usr/bin/llvm-symbolizer-13 \
    --slave   /usr/bin/llvm-tblgen       llvm-tblgen      /usr/bin/llvm-tblgen-13

update-alternatives \
  --install /usr/bin/clang                 clang                  /usr/bin/clang-13     20 \
  --slave   /usr/bin/clang++               clang++                /usr/bin/clang++-13 \
  --slave   /usr/bin/clang-cpp             clang-cpp              /usr/bin/clang-cpp-13
# -----------------------------
# Install + build SVF
# -----------------------------
export LLVM_DIR=/usr/lib/llvm-13
export PATH=/usr/lib/llvm-13/bin:$PATH
export BUILD_TYPE='Release'
export BUILD_DIR="./build"
export SVFHOME="/SVF"

git clone https://github.com/SVF-tools/SVF.git
cd $SVFHOME
git checkout SVF-2.6
rm -rf "${BUILD_DIR}"
mkdir "${BUILD_DIR}"
cmake -D CMAKE_BUILD_TYPE:STRING="${BUILD_TYPE}" \
  -DSVF_ENABLE_ASSERTIONS:BOOL=true            \
  -DSVF_SANITIZE="OFF"            \
  -S "${SVFHOME}" -B "${BUILD_DIR}"
cmake --build "${BUILD_DIR}"

# Make SVF available to later steps (build.sh)
echo "export PATH=${SVF_PREFIX}/bin:\$PATH" >> /etc/profile.d/svf.sh
echo "export LD_LIBRARY_PATH=${SVF_PREFIX}/lib:\$LD_LIBRARY_PATH" >> /etc/profile.d/svf.sh
