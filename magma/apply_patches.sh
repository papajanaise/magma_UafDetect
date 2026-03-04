#!/bin/bash
set -e

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

# TODO filter patches by target config.yaml
dirs=()
[ -d "$TARGET/patches/setup" ] && dirs+=("$TARGET/patches/setup")
[ -d "$TARGET/patches/bugs" ]  && dirs+=("$TARGET/patches/bugs")

if [ ${#dirs[@]} -eq 0 ]; then
    echo "No patch directories found for $TARGET"
    exit 0
fi

if [ "${TARGET:-}" = "libxml2" ]; then
    patchdir="$TARGET"
else
    patchdir="$TARGET/repo"
fi

find "${dirs[@]}" -name "*.patch" | sort | while read patch; do
    name=${patch##*/}
    name=${name%.patch}
    if sed "s/%MAGMA_BUG%/$name/g" "$patch" | patch -R --dry-run -F4 -p1 -d "$patchdir" > /dev/null 2>&1; then
        echo "Skipping $patch (already applied)"
    else
        echo "Applying $patch"
        sed "s/%MAGMA_BUG%/$name/g" "$patch" | patch -F4 -p1 -d "$patchdir"
    fi
done