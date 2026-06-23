#!/bin/bash
# Test one csmith-generated C file through perf-gcov and AutoFDO.

CC=${CC:-gcc}
PERF=${PERF:-perf}

set -x
set -e

failed() {
        echo FAILED
}
trap failed ERR

if [ $# -ne 1 ] ; then
    echo "Usage: $0 FILE.c" >&2
    exit 2
fi

src=$1
base=${src%.c}
if [ "$base" = "$src" ] ; then
    src="${base}.c"
fi

if [ ! -f "$src" ] ; then
    echo "missing input file: $src" >&2
    exit 2
fi

$CC -w -g -O2 -I/usr/include/csmith -o "$base" "$src"
timeout 30 $PERF record -b -o "${base}.data" -c 10001 -e branches:ppu "./${base}" || true
$PERF script -i "${base}.data" gcov.py "${base}.gcov" --verbose --binary "$base"
./dump.py --max-count 1000000 "${base}.gcov" > "${base}.dump"
if [ -n "$(type -p dump_gcov)" ] ; then
    echo "autofdo dump"
    dump_gcov "${base}.gcov"
    create_gcov -gcov_version 2 --binary "$base" --gcov "${base}.gcov2" --profile "${base}.data"
    ./dump.py "${base}.gcov2" > "${base}.dump2"
    echo "autofdo reference dump"
    dump_gcov "${base}.gcov2"
    echo "diff gcov.py vs create_gcov"
    if ! diff -u "${base}.dump" "${base}.dump2" ; then
        echo "non-identical dump accepted; checking non-zero offsets"
    fi
    awk '/^[[:space:]]+[0-9]+(\.[0-9]+)?:/ && $2 != 0 { sub(/^[[:space:]]+/, ""); sub(/:.*/, ""); sub(/\..*/, ""); print }' "${base}.dump" | sort -u > "${base}.offsets"
    awk '/^[[:space:]]+[0-9]+(\.[0-9]+)?:/ && $2 != 0 { sub(/^[[:space:]]+/, ""); sub(/:.*/, ""); sub(/\..*/, ""); print }' "${base}.dump2" | sort -u > "${base}.offsets2"
    comm -23 "${base}.offsets" "${base}.offsets2" > "${base}.offsets.missing"
    if [ -s "${base}.offsets.missing" ] ; then
        echo "source line offsets missing from create_gcov reference"
        cat "${base}.offsets.missing"
        false
    fi
fi
$CC -w -g -O2 -fauto-profile="${base}.gcov" "$src" -o "${base}.opt"
"./${base}.opt"

trap "" ERR
