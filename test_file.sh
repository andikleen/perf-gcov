#!/bin/bash
# Test one csmith-generated C file through perf-gcov and create_gcov.

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
$PERF script -i "${base}.data" gcov.py "${base}.gcov" --binary "$base"
./dump.py --max-count 1000000 "${base}.gcov" > "${base}.dump"

if [ -n "$(type -p create_gcov)" ] ; then
    create_gcov -gcov_version 2 --binary "$base" --gcov "${base}.gcov2" --profile "${base}.data" 2>&1 | grep -v "WARNING:" || true
    ./dump.py "${base}.gcov2" > "${base}.dump2"
    
    echo "=== Comparing dumps ==="
    if diff -u "${base}.dump" "${base}.dump2" ; then
        echo "PASS: Dumps are identical"
    else
        echo "FAIL: Dumps differ"
        echo "Diff saved to ${base}.diff"
        diff -u "${base}.dump" "${base}.dump2" > "${base}.diff" || true
        exit 1
    fi
fi

$CC -w -g -O2 -fauto-profile="${base}.gcov" "$src" -o "${base}.opt"
"./${base}.opt"

trap "" ERR
