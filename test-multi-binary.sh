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

# Build multi-file non-LTO test binary (non-unique static symbols)
$CC -g -O2 -o tnonunique tnonunique1.c tnonunique2.c
cleanup_files="${cleanup_files} tnonunique"

# Verify non-unique symbols (no .lto_priv suffixes without LTO)
nonunique=$(nm tnonunique | awk '$2 == "t" || $2 == "T" {print $3}' | sort | uniq -d)
if [ -z "$nonunique" ]; then
	echo "tnonunique should have non-unique symbols but none found" >&2
	exit 1
fi
for sym in $nonunique; do
	echo "  Non-unique symbol: $sym"
done

# Build wrapper script
cp run-multi-wrap.sh run-tests-wrapper.sh
cleanup_files="${cleanup_files} run-tests-wrapper.sh"

# Verify each runs correctly
echo "Verifying test binaries..."
./tmulti1 >/dev/null && echo "tmulti1 OK"
./tmulti2 >/dev/null && echo "tmulti2 OK"
./tmulti3 >/dev/null && echo "tmulti3 OK"
./tnonunique >/dev/null && echo "tnonunique OK"

# Record profile running all three via wrapper
if ! $PERF record -b -o multibin.data -c 10003 -e branches:ppu ./run-tests-wrapper.sh >/dev/null 2>&1; then
	echo "perf record failed" >&2
	exit 1
fi
cleanup_files="${cleanup_files} multibin.data"

echo "=== AUTO-DISCOVERY (4 binaries) ==="
rm -f tmulti1.gcov tmulti2.gcov tmulti3.gcov tnonunique.gcov
$PERF script -i multibin.data ./gcov.py --gcov-version 3 2>&1
test -f tmulti1.gcov || { echo "missing tmulti1.gcov"; exit 1; }
test -f tmulti2.gcov || { echo "missing tmulti2.gcov"; exit 1; }
test -f tmulti3.gcov || { echo "missing tmulti3.gcov"; exit 1; }
test -f tnonunique.gcov || { echo "missing tnonunique.gcov"; exit 1; }
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
test -f multibin_out/tnonunique.gcov || { echo "missing multibin_out/tnonunique.gcov"; exit 1; }
cleanup_dirs="multibin_out"
echo "OUTPUT-DIR: OK"

echo "=== --min-samples FILTER ==="
rm -f tmulti1.gcov tmulti2.gcov tmulti3.gcov tnonunique.gcov
$PERF script -i multibin.data ./gcov.py --gcov-version 3 --min-samples 1000000 2>&1 | tail -5
test ! -f tmulti1.gcov || { echo "tmulti1.gcov should be filtered by --min-samples"; exit 1; }
echo "MIN-SAMPLES: OK"

echo "=== RUN 3 TIMES -> STABLE ==="
for run in 1 2 3; do
    rm -f tmulti1.gcov tmulti2.gcov tmulti3.gcov tnonunique.gcov
    $PERF record -b -o multibin.data -c 10003 -e branches:ppu ./run-tests-wrapper.sh >/dev/null 2>&1
    $PERF script -i multibin.data ./gcov.py --gcov-version 3 --quiet 2>&1
    test -f tmulti1.gcov || { echo "run $run: missing tmulti1.gcov"; exit 1; }
    test -f tmulti2.gcov || { echo "run $run: missing tmulti2.gcov"; exit 1; }
    test -f tmulti3.gcov || { echo "run $run: missing tmulti3.gcov"; exit 1; }
    test -f tnonunique.gcov || { echo "run $run: missing tnonunique.gcov"; exit 1; }
    echo "  run $run: OK"
done
echo "STABLE: OK"

echo "=== NON-UNIQUE SYMBOLS (no LTO) ==="
rm -f tnonunique.gcov tnonunique.dump tnonunique-perf.data
# Record tnonunique separately (smaller data, avoids scanning 4-binary file)
$PERF record -b -o tnonunique-perf.data -c 10003 -e branches:ppu ./tnonunique >/dev/null 2>&1
cleanup_files="${cleanup_files} tnonunique-perf.data"
$PERF script -i tnonunique-perf.data ./gcov.py tnonunique.gcov --gcov-version 3 2>&1
# Verify gcov contains both static functions (compute and helper each appear)
./gcov-dump.py tnonunique.gcov > tnonunique.dump
echo "GCOV dump for tnonunique (non-unique symbols):"
cat tnonunique.dump
# Check that dump contains expected top-level function names (format: funcname:sourcefile)
grep -q "^compute:" tnonunique.dump || { echo "missing function 'compute' in tnonunique.gcov"; exit 1; }
grep -q "^helper:" tnonunique.dump || { echo "missing function 'helper' in tnonunique.gcov"; exit 1; }
grep -q "^entry_b:" tnonunique.dump || { echo "missing function 'entry_b' in tnonunique.gcov"; exit 1; }
grep -q "^main:" tnonunique.dump || { echo "missing function 'main' in tnonunique.gcov"; exit 1; }
# entry_a is only inlined under main, not a top-level function — check it appears anywhere
grep -q "entry_a" tnonunique.dump || { echo "missing inline 'entry_a' in tnonunique.gcov"; exit 1; }
# Verify separate entries per translation unit (non-unique symbol fix)
count_compute=$(grep -c "^compute:" tnonunique.dump)
if [ "$count_compute" -lt 2 ]; then
	echo "expected 2 separate 'compute' entries (one per file), got $count_compute" >&2
	exit 1
fi
count_helper=$(grep -c "^helper:" tnonunique.dump)
if [ "$count_helper" -lt 2 ]; then
	echo "expected 2 separate 'helper' entries (one per file), got $count_helper" >&2
	exit 1
fi
echo "  Verified $count_compute compute + $count_helper helper top-level entries (was 1 before fix)"
# Check for .lto_priv absence (these are non-LTO, should NOT have .lto_priv)
if grep -q "lto_priv" tnonunique.dump; then
	echo "tnonunique should NOT have .lto_priv suffixes (no LTO)" >&2
	exit 1
fi
cleanup_files="${cleanup_files} tnonunique.dump"
echo "NON-UNIQUE SYMBOLS: OK"

# Final cleanup via trap
trap - EXIT
cleanup_multibin
echo "ALL MULTI-BINARY TESTS PASSED"
