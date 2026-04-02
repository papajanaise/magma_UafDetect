export ANALYZER="free_finder"
for target in "expat" "libjpeg-turbo" "libpng" "libxml2" "sqlite3"; do
    export TARGET="$target"
    sbatch --export=TARGET="${TARGET}",PROGRAM="${name}",ANALYZER="${ANALYZER}" \
        /home/users/m/m.thielebein/magma_UafDetect/sbatch_afl_instrument.sh
done