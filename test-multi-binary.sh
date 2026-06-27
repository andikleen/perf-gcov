#!/bin/bash
# Test multi-binary auto-discovery and filtering in gcov.py
# SPDX-License-Identifier: GPL-3.0-or-later

CC=${CC:-gcc}
PERF=${PERF:-perf}

set -x
set -e

failed() {
	echo "FAILED"
}
trap failed ERR 0

cleanup_multibin() {
	rm -f ${cleanup_files}
	rm -rf ${cleanup_dirs}
}
trap cleanup_multibin EXIT

cleanup_files=""
cleanup_dirs=""

# Build three standalone test binaries
$CC -g -O2 -o tmulti1 tmulti1.c
cleanup_files="tmulti1"
$CC -g -O2 -o tmulti2 tmulti2.c
cleanup_files="${cleanup_files} tmulti2"
$CC -g -O2 -o tmulti3 tmulti3.c
cleanup_files="${cleanup_files} tmulti3"

# Build wrapper script
cp run-multi-wrap.sh run-tests-wrapper.sh
cleanup_files="${cleanup_files} run-tests-wrapper.sh"

# Verify each runs correctly
echo "Verifying test binaries..."
./tmulti1 >/dev/null && echo "tmulti1 OK"
./tmulti2 >/dev/null && echo "tmulti2 OK"
./tmulti3 >/dev/null && echo "tmulti3 OK"

# Record profile running all three via wrapper
if ! $PERF record -b -o multibin.data -c 100 -e branches:ppu ./run-tests-wrapper.sh >/dev/null 2>&1; then
	echo "perf record failed" >&2
	exit 1
fi
cleanup_files="${cleanup_files} multibin.data"

echo "=== AUTO-DISCOVERY (3 binaries) ==="
rm -f tmulti1.gcov tmulti2.gcov tmulti3.gcov
$PERF script -i multibin.data ./gcov.py --gcov-version 3 2>&1
test -f tmulti1.gcov || { echo "missing tmulti1.gcov"; exit 1; }
test -f tmulti2.gcov || { echo "missing tmulti2.gcov"; exit 1; }
test -f tmulti3.gcov || { echo "missing tmulti3.gcov"; exit 1; }
echo "AUTO-DISCOVERY: OK"

echo "=== --binary FILTER (tmulti1 only) ==="
rm -f tmulti1-filtered.gcov tmulti2.gcov tmulti3.gcov
$PERF script -i multibin.data ./gcov.py tmulti1-filtered.gcov --gcov-version 3 --binary tmulti1 2>&1 | tail -5
test -f tmulti1-filtered.gcov || { echo "missing tmulti1-filtered.gcov"; exit 1; }
test ! -f tmulti2.gcov || { echo "tmulti2.gcov should be filtered out"; exit 1; }
cleanup_files="${cleanup_files} tmulti1-filtered.gcov"
echo "BINARY FILTER: OK"

echo "=== --binary FNMATCH (tmulti[13]) ==="
rm -f tmulti1.gcov tmulti2.gcov tmulti3.gcov
$PERF script -i multibin.data ./gcov.py --gcov-version 3 --binary 'tmulti[13]' 2>&1 | tail -10
test -f tmulti1.gcov || { echo "missing tmulti1.gcov from fnmatch"; exit 1; }
test -f tmulti3.gcov || { echo "missing tmulti3.gcov from fnmatch"; exit 1; }
test ! -f tmulti2.gcov || { echo "tmulti2.gcov should be filtered out by fnmatch"; exit 1; }
echo "FNMATCH FILTER: OK"

echo "=== --output-dir ==="
rm -rf multibin_out
$PERF script -i multibin.data ./gcov.py --gcov-version 3 --output-dir multibin_out 2>&1 | tail -10
test -f multibin_out/tmulti1.gcov || { echo "missing multibin_out/tmulti1.gcov"; exit 1; }
test -f multibin_out/tmulti2.gcov || { echo "missing multibin_out/tmulti2.gcov"; exit 1; }
test -f multibin_out/tmulti3.gcov || { echo "missing multibin_out/tmulti3.gcov"; exit 1; }
cleanup_dirs="multibin_out"
echo "OUTPUT-DIR: OK"

echo "=== --min-samples FILTER ==="
rm -f tmulti1.gcov tmulti2.gcov tmulti3.gcov
$PERF script -i multibin.data ./gcov.py --gcov-version 3 --min-samples 1000000 2>&1 | tail -5
test ! -f tmulti1.gcov || { echo "tmulti1.gcov should be filtered by --min-samples"; exit 1; }
echo "MIN-SAMPLES: OK"

echo "=== RUN 3 TIMES -> STABLE ==="
for run in 1 2 3; do
    rm -f tmulti1.gcov tmulti2.gcov tmulti3.gcov
    $PERF record -b -o multibin.data -c 100 -e branches:ppu ./run-tests-wrapper.sh >/dev/null 2>&1
    $PERF script -i multibin.data ./gcov.py --gcov-version 3 --quiet 2>&1
    test -f tmulti1.gcov || { echo "run $run: missing tmulti1.gcov"; exit 1; }
    test -f tmulti2.gcov || { echo "run $run: missing tmulti2.gcov"; exit 1; }
    test -f tmulti3.gcov || { echo "run $run: missing tmulti3.gcov"; exit 1; }
    echo "  run $run: OK"
done
echo "STABLE: OK"

# Final cleanup via trap
trap - EXIT
cleanup_multibin
echo "ALL MULTI-BINARY TESTS PASSED"
