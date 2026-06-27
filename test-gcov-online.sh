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

cleanup() { kill $WPID 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$TMPDIR" /tmp/gcov-online-??????; }
trap cleanup EXIT

OUTDIR() { echo "$TMPDIR/test-$1"; }
pass() { echo "PASS"; }
fail() { echo "FAIL"; FAILED=1; }

echo "=== Test 1: Basic + cleanup ==="
rm -rf "$(OUTDIR basic)"
$ONLINE --output-dir "$(OUTDIR basic)" --interval 1 --binary infloop --iterations 2 >/dev/null 2>&1
[ -f "$(OUTDIR basic)/infloop.gcov" ] && pass || fail

echo "=== Test 2: Profile merging (3 iterations) ==="
rm -rf "$(OUTDIR merge)"
$ONLINE --output-dir "$(OUTDIR merge)" --interval 1 --binary infloop --iterations 3 >/dev/null 2>&1
[ -f "$(OUTDIR merge)/infloop.gcov" ] && pass || fail

echo "=== Test 3: Custom parameters ==="
rm -rf "$(OUTDIR params)"
$ONLINE --output-dir "$(OUTDIR params)" --interval 1 --count 100000 --binary infloop --iterations 1 >/dev/null 2>&1
[ -f "$(OUTDIR params)/infloop.gcov" ] && pass || fail

echo "=== Test 4: --quiet mode ==="
rm -rf "$(OUTDIR quiet)"
$ONLINE --output-dir "$(OUTDIR quiet)" --interval 1 --binary infloop --iterations 1 --quiet >/dev/null 2>&1
[ -f "$(OUTDIR quiet)/infloop.gcov" ] && pass || fail

echo "=== Test 5: Multiple --binary flags ==="
rm -rf "$(OUTDIR multi)"
$ONLINE --output-dir "$(OUTDIR multi)" --interval 1 --binary infloop --binary infloop --iterations 1 >/dev/null 2>&1
[ -f "$(OUTDIR multi)/infloop.gcov" ] && pass || fail

echo "=== Test 6: Temp dirs cleaned ==="
LEFT=$(ls /tmp/gcov-online-?????? 2>/dev/null | wc -l)
[ "$LEFT" -eq 0 ] && pass || { echo "($LEFT leftover)"; fail; }

echo ""
[ "$FAILED" -eq 0 ] && echo "ALL TESTS PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
