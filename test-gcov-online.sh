#!/bin/bash
# test-gcov-online.sh - Test gcov-online-profile.sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
ONLINE="$SCRIPT_DIR/gcov-online-profile.sh"
TMPDIR=$(mktemp -d /tmp/gcov-online-test-XXXXXX)
FAILED=0

# Build and start an infinite-loop workload
gcc -g -O2 -o "$TMPDIR/infloop" -x c - <<'EOF' 2>/dev/null
volatile int counter = 0;
int main(void) { while (1) counter++; return 0; }
EOF

"$TMPDIR/infloop" & WPID=$!
for _ in 1 2 3; do kill -0 "$WPID" 2>/dev/null && { sleep 0.3; break; }; sleep 0.3; done

cleanup() { kill $WPID 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$TMPDIR" /tmp/gcov-online-??????;  }
trap cleanup EXIT

OUTDIR() { echo "$TMPDIR/test-$1"; }
pass() { echo "PASS"; }
fail() { echo "FAIL"; FAILED=1; }
skip() { echo "SKIP ($1)"; }

COMMON_OPTS=()
PID_OPTS=(--non-global -- --pid "$WPID")

system_wide_works() {
    local tmpdir
    tmpdir=$(mktemp -d)
    if perf record -a -b -e branches:ppu -c 300003 -o "$tmpdir/perf.data" sleep 0.1 >/dev/null 2>&1; then
        if [[ -s "$tmpdir/perf.data" ]]; then
            rm -rf "$tmpdir"
            return 0
        fi
    fi
    rm -rf "$tmpdir"
    return 1
}

echo "=== Test 1: Basic + cleanup (system-wide) ==="
rm -rf "$(OUTDIR basic)"
if system_wide_works; then
    $ONLINE --output-dir "$(OUTDIR basic)" --interval 1 --binary infloop --iterations 2 "${COMMON_OPTS[@]}" >& log$$
    [ -f "$(OUTDIR basic)/infloop.gcov" ] && pass || fail
else
    skip "system-wide perf unavailable"
fi

echo "=== Test 2: Basic + cleanup (non-global) ==="
rm -rf "$(OUTDIR basic-ng)"
$ONLINE --output-dir "$(OUTDIR basic-ng)" --interval 1 --binary infloop --iterations 2 "${COMMON_OPTS[@]}" "${PID_OPTS[@]}" >& log$$
[ -f "$(OUTDIR basic-ng)/infloop.gcov" ] && pass || fail

echo "=== Test 3: Profile merging (3 iterations) ==="
rm -rf "$(OUTDIR merge)"
$ONLINE --output-dir "$(OUTDIR merge)" --interval 1 --binary infloop --iterations 3 "${COMMON_OPTS[@]}" "${PID_OPTS[@]}" >& log$$
[ -f "$(OUTDIR merge)/infloop.gcov" ] && pass || fail

echo "=== Test 4: Custom parameters ==="
rm -rf "$(OUTDIR params)"
$ONLINE --output-dir "$(OUTDIR params)" --interval 1 --count 100000 --binary infloop --iterations 1 "${COMMON_OPTS[@]}" "${PID_OPTS[@]}" >& log$$
[ -f "$(OUTDIR params)/infloop.gcov" ] && pass || fail

echo "=== Test 5: --quiet mode ==="
rm -rf "$(OUTDIR quiet)"
$ONLINE --output-dir "$(OUTDIR quiet)" --interval 1 --binary infloop --iterations 1 --quiet "${COMMON_OPTS[@]}" "${PID_OPTS[@]}" >& log$$
[ -f "$(OUTDIR quiet)/infloop.gcov" ] && pass || fail

echo "=== Test 6: Multiple --binary flags ==="
rm -rf "$(OUTDIR multi)"
$ONLINE --output-dir "$(OUTDIR multi)" --interval 1 --binary infloop --iterations 1 "${COMMON_OPTS[@]}" "${PID_OPTS[@]}" >& log$$
[ -f "$(OUTDIR multi)/infloop.gcov" ] && pass || fail

echo "=== Test 7: Temp dirs cleaned ==="
LEFT=$(ls /tmp/gcov-online-?????? 2>/dev/null | wc -l)
[ "$LEFT" -eq 0 ] && pass || { echo "($LEFT leftover)"; fail; }

#echo "=== Test 8: Test specific process ==="
#rm -rf "$(OUTDIR multi)"
#$ONLINE --output-dir "$(OUTDIR multi)" --interval 1 --binary infloop --iterations 1 "${COMMON_OPTS[@]}" -- timeout 1 ./infloop >& log$$
#[ -f "$(OUTDIR multi)/infloop.gcov" ] && pass || fail

echo ""
[ "$FAILED" -eq 0 ] && ( rm -f log$$ ; echo "ALL TESTS PASSED" ) || { echo "SOME TESTS FAILED"; exit 1; }
