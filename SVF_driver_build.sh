cmake -S /magma/fuzzers/afl_uaf_detect/repo/SVF_drivers -B /magma/fuzzers/afl_uaf_detect/repo/SVF_drivers/build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DSVF_DIR=/home/users/m/m.thielebein/SVF
cmake --build /magma/fuzzers/afl_uaf_detect/repo/SVF_drivers/build --verbose
