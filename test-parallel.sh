#!/bin/bash
# Test gcov-parallel.sh — verify parallel processing matches sequential gcov.py
#
# Builds a test binary, perf records it, then compares sequential gcov.py
# output against parallel gcov-parallel.sh output at various job counts.
#
# SPDX-License-Identifier: GPL-3.0-or-later

CC=${CC:-gcc}
PERF=${PERF:-perf}
PARALLEL=./gcov-parallel.sh
DUMPER=./gcov-dump.py

set -x
set -e


failed() {
  echo "FAILED"
}
trap failed ERR 0

cleanup_parallel() {
  rm -f ${cleanup_files}
}
trap cleanup_parallel EXIT

# Check GCC version for v3 support
check_gcc_v3_support() {
  local version=$($CC -dumpversion | cut -d. -f1)
  if [ "$version" -ge 16 ]; then
    return 0
  else
    return 1
  fi
}

# Build test binary
i=tcall
echo "=== BUILD ==="
$CC -g -O2 -o ${i} ${i}.c

echo "=== PERF RECORD ==="
$PERF record -b -o perf.data -c 10001 -e branches:ppu ./${i} 2>&1 | tail -1
cleanup_files="perf.data"

# Generate reference gcov (single-threaded)
echo "=== REFERENCE gcov v2 ==="
$PERF script -i perf.data gcov.py ref.gcov --verbose --binary ${i} --gcov-version 2 2>&1 | tail -5
cleanup_files="${cleanup_files} ref.gcov"

echo "=== REFERENCE gcov v3 ==="
$PERF script -i perf.data gcov.py ref3.gcov --verbose --binary ${i} --gcov-version 3 2>&1 | tail -5
cleanup_files="${cleanup_files} ref3.gcov"

# Cap max jobs to 4 — larger N creates time slices too granular for a small
# perf.data, which can cause perf to reject the time string on empty ranges.
MAX_JOBS=$(nproc 2>/dev/null || echo 4)
if [[ $MAX_JOBS -gt 4 ]]; then MAX_JOBS=4; fi

# Test gcov-parallel.sh with various job counts for v2
for jobs in 1 2 ${MAX_JOBS}; do
  echo "=== PARALLEL jobs=${jobs} gcov v2 ==="
  ${PARALLEL} -j ${jobs} -i perf.data --binary ${i} --gcov par.${jobs}.v2.gcov --gcov-version 2
  cleanup_files="${cleanup_files} par.${jobs}.v2.gcov"

  echo "=== COMPARE v2 jobs=${jobs} ==="
  diff <(${DUMPER} ref.gcov 2>&1) <(${DUMPER} par.${jobs}.v2.gcov 2>&1)
  echo "MATCH v2 jobs=${jobs}: OK"
done

# Test gcov-parallel.sh with various job counts for v3
if check_gcc_v3_support; then
  for jobs in 1 2 ${MAX_JOBS}; do
    echo "=== PARALLEL jobs=${jobs} gcov v3 ==="
    ${PARALLEL} -j ${jobs} -i perf.data --binary ${i} --gcov par.${jobs}.v3.gcov --gcov-version 3
    cleanup_files="${cleanup_files} par.${jobs}.v3.gcov"

    echo "=== COMPARE v3 jobs=${jobs} ==="
    diff <(${DUMPER} ref3.gcov 2>&1) <(${DUMPER} par.${jobs}.v3.gcov 2>&1)
    echo "MATCH v3 jobs=${jobs}: OK"
  done
else
  echo "=== v3: SKIP (GCC < 16) ==="
fi
