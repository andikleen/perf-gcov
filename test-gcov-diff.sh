#!/bin/bash
# Test gcov-diff.py — diff two gcov profiles from a two-path program

set -x
set -e

DIFF=./gcov-diff.py
CC=${CC:-gcc}
PERF=${PERF:-perf}
PROG=tdiff

failed() {
    echo FAILED
}
trap failed ERR 0

cleanup_files=""

echo "=== BUILD ==="
$CC -g -O2 -o ${PROG} ${PROG}.c
cleanup_files="${cleanup_files} ${PROG}"

echo "=== PERF RECORD (default path) ==="
$PERF record -b -o ${PROG}.default.data -c 50001 -e branches:ppu ./${PROG} 2>&1 | tail -1
cleanup_files="${cleanup_files} ${PROG}.default.data"

echo "=== PERF RECORD (fast path) ==="
$PERF record -b -o ${PROG}.fast.data -c 50001 -e branches:ppu ./${PROG} fast 2>&1 | tail -1
cleanup_files="${cleanup_files} ${PROG}.fast.data"

echo "=== GENERATE GCOV (default) ==="
$PERF script -i ${PROG}.default.data gcov.py ${PROG}.default.gcov \
    --verbose --min-samples 1 --binary ${PROG} --gcov-version 2 2>&1 | tail -5
cleanup_files="${cleanup_files} ${PROG}.default.gcov"

echo "=== GENERATE GCOV (fast) ==="
$PERF script -i ${PROG}.fast.data gcov.py ${PROG}.fast.gcov \
    --verbose --min-samples 1 --binary ${PROG} --gcov-version 2 2>&1 | tail -5
cleanup_files="${cleanup_files} ${PROG}.fast.gcov"

# 1. Self-diff: same file against itself → no differences
echo "=== SELF-DIFF (detailed) ==="
${DIFF} --mode detailed ${PROG}.default.gcov ${PROG}.default.gcov 2>&1 | grep -q "Lines newly covered: 0"
echo "SELF-DIFF DETAILED: OK"

echo "=== SELF-DIFF (summary) ==="
${DIFF} --mode summary ${PROG}.default.gcov ${PROG}.default.gcov 2>&1 | grep -q "Lines newly covered: 0"
echo "SELF-DIFF SUMMARY: OK"

echo "=== SELF-DIFF (lines) ==="
${DIFF} --mode lines ${PROG}.default.gcov ${PROG}.default.gcov 2>&1 > /dev/null
echo "SELF-DIFF LINES: OK"

# 2. Cross-diff: different profiles → non-empty diff
echo "=== CROSS-DIFF (summary) ==="
${DIFF} --mode summary ${PROG}.default.gcov ${PROG}.fast.gcov 2>&1 | grep -q "Lines uncovered: [1-9]"
echo "CROSS-DIFF SUMMARY: OK"

echo "=== CROSS-DIFF (detailed) ==="
${DIFF} --mode detailed ${PROG}.default.gcov ${PROG}.fast.gcov 2>&1 > /dev/null
echo "CROSS-DIFF DETAILED: OK"

echo "=== CROSS-DIFF (lines) ==="
${DIFF} --mode lines ${PROG}.default.gcov ${PROG}.fast.gcov 2>&1 > /dev/null
echo "CROSS-DIFF LINES: OK"
# 3. Error: missing file
echo "=== MISSING FILE ==="
if ${DIFF} nonexistent.gcov ${PROG}.default.gcov 2>&1; then
    echo "expected error for missing file"
    false
fi
echo "MISSING FILE: OK"

# 4. Error: bad magic
echo "=== BAD MAGIC ==="
echo "garbage bytes" > ${PROG}.bad
cleanup_files="${cleanup_files} ${PROG}.bad"
if ${DIFF} ${PROG}.bad ${PROG}.default.gcov 2>&1; then
    echo "expected error for bad magic"
    false
fi
echo "BAD MAGIC: OK"

# 5. --threshold filter
echo "=== THRESHOLD ==="
${DIFF} --mode summary --threshold 1000000 ${PROG}.default.gcov ${PROG}.fast.gcov 2>&1 > /dev/null
echo "THRESHOLD: OK"

# 6. --no-zeros
echo "=== NO-ZEROS ==="
${DIFF} --mode summary --no-zeros ${PROG}.default.gcov ${PROG}.fast.gcov 2>&1 > /dev/null
echo "NO-ZEROS: OK"

# 7. --relative mode
echo "=== RELATIVE ==="
${DIFF} --mode detailed --relative ${PROG}.default.gcov ${PROG}.fast.gcov 2>&1 > /dev/null
echo "RELATIVE: OK"

# 8. --quiet
echo "=== QUIET ==="
${DIFF} --mode detailed --quiet ${PROG}.default.gcov ${PROG}.fast.gcov 2>&1 | grep -v "=== gcov-diff detailed ===" | grep -q "Common functions"
echo "QUIET: OK"

trap - EXIT
rm -f ${cleanup_files}
echo "ALL GCOV-DIFF TESTS PASSED"
