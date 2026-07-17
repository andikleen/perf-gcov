#!/bin/bash
# Test profile-merger.py

CC=${CC:-gcc}
PERF=${PERF:-perf}
MERGER=./profile-merger.py
DUMPER=./gcov-dump.py

# Find a GCC 16+ capable compiler for v3 format tests.
# Set CC_V3 environment variable to override auto-detection.
if [ -n "$CC_V3" ]; then
	:  # user-provided
elif command -v gcc-16 >/dev/null 2>&1; then
	CC_V3=gcc-16
else
	CC_V3=$CC
fi

set -x
set -e
set -o pipefail

failed() {
	echo "FAILED"
}
trap failed ERR 0
check_gcc_v3_support() {
	local version=$($CC_V3 -dumpversion | cut -d. -f1)
	if [ "$version" -ge 16 ]; then
		return 0
	else
		return 1
	fi
}

i=tcall

echo "=== BUILD ==="
$CC -g -O2 -o ${i} ${i}.c

echo "=== PERF RECORD ==="
$PERF record -b -o ${i}.d1 -c 10001 -e branches:ppu ./${i} 2>&1 | tail -1
$PERF record -b -o ${i}.d2 -c 10001 -e branches:ppu ./${i} 2>&1 | tail -1
cleanup_files="${i}.d1 ${i}.d2"

# Generate gcov v2 from both
$PERF script -i ${i}.d1 gcov.py ${i}.1.2 --verbose --min-samples 1 --binary ${i} --gcov-version 2 2>&1 | tail -5
$PERF script -i ${i}.d2 gcov.py ${i}.2.2 --verbose --min-samples 1 --binary ${i} --gcov-version 2 2>&1 | tail -5
cleanup_files="${cleanup_files} ${i}.1.2 ${i}.2.2"

# Generate gcov v3 from both
$PERF script -i ${i}.d1 gcov.py ${i}.1.3 --verbose --min-samples 1 --binary ${i} --gcov-version 3 2>&1 | tail -5
$PERF script -i ${i}.d2 gcov.py ${i}.2.3 --verbose --min-samples 1 --binary ${i} --gcov-version 3 2>&1 | tail -5
cleanup_files="${cleanup_files} ${i}.1.3 ${i}.2.3"

# 1. Identity: single-file merge produces identical dump
echo "=== IDENTITY v2 ==="
${MERGER} -o ${i}.id.2 --gcov-version 2 ${i}.1.2
diff <(${DUMPER} ${i}.1.2 2>&1) <(${DUMPER} ${i}.id.2 2>&1)
echo "IDENTITY v2: OK"

echo "=== IDENTITY v3 ==="
${MERGER} -o ${i}.id.3 --gcov-version 3 ${i}.1.3
diff <(${DUMPER} ${i}.1.3 2>&1) <(${DUMPER} ${i}.id.3 2>&1)
echo "IDENTITY v3: OK"
cleanup_files="${cleanup_files} ${i}.id.2 ${i}.id.3"

# 2. Self-merge: merging file with itself doubles all counts
echo "=== COPY 2x ==="
${MERGER} -o ${i}.copy.2 --gcov-version 2 ${i}.1.2 ${i}.1.2
python3 -c "
import re, subprocess, sys
orig = subprocess.check_output(['${DUMPER}', '${i}.1.2'], stderr=subprocess.STDOUT).decode()
copy = subprocess.check_output(['${DUMPER}', '${i}.copy.2'], stderr=subprocess.STDOUT).decode()
olines = [l for l in orig.splitlines() if re.match(r'^\s+\d+', l)]
clines = [l for l in copy.splitlines() if re.match(r'^\s+\d+', l)]
for o, c in zip(olines, clines):
    oval = int(o.split()[1].rstrip(':'))
    cval = int(c.split()[1].rstrip(':'))
    if oval > 0 and cval != oval * 2:
        print(f'MISMATCH: orig={oval} merged={cval}')
        sys.exit(1)
print('COPY 2x: OK')
"
cleanup_files="${cleanup_files} ${i}.copy.2"

# 3. Two-file merge (v2 and v3)
echo "=== TWO FILES v2 ==="
${MERGER} -o ${i}.two.2 --gcov-version 2 ${i}.1.2 ${i}.2.2
test -s ${i}.two.2 && echo "TWO V2: OK"

echo "=== TWO FILES v3 ==="
${MERGER} -o ${i}.two.3 --gcov-version 3 ${i}.1.3 ${i}.2.3
test -s ${i}.two.3 && echo "TWO V3: OK"
cleanup_files="${cleanup_files} ${i}.two.2 ${i}.two.3"

# 4. Mixed version input should be rejected
echo "=== MIXED v2+v3 REJECTED ==="
if ${MERGER} -o ${i}.mix --gcov-version 3 ${i}.1.2 ${i}.1.3 >${i}.mix.log 2>&1; then
  echo "MIXED REJECT: FAIL - merger accepted mixed versions"
  exit 1
elif grep -q "cannot merge mixed" ${i}.mix.log; then
  echo "MIXED REJECT: OK"
else
  echo "MIXED REJECT: FAIL - expected error on mixed versions"
  cat ${i}.mix.log
  exit 1
fi
cleanup_files="${cleanup_files} ${i}.mix.log"

# 5. Threshold filtering
echo "=== THRESHOLD ==="
${MERGER} -o ${i}.thr --gcov-version 2 --threshold 50000 ${i}.1.2 ${i}.2.2
python3 -c "
import re, subprocess, sys
out = subprocess.check_output(['${DUMPER}', '${i}.thr'], stderr=subprocess.STDOUT).decode()
counts = [int(l.split()[1].rstrip(':')) for l in out.splitlines() if re.match(r'^\s+\d+', l)]
hot = [c for c in counts if c >= 50000]
cold = [c for c in counts if 0 < c < 50000]
print(f'THRESHOLD: hot={len(hot)}, cold={len(cold)}')
assert len(hot) > 0, 'no hot positions above threshold'
assert len(cold) == 0, f'{len(cold)} cold positions below threshold remain'
print('THRESHOLD: OK')
"
cleanup_files="${cleanup_files} ${i}.thr"

# 6. Targets summed correctly
echo "=== TARGETS SUM ==="
python3 -c "
import re, subprocess, sys
single = subprocess.check_output(['${DUMPER}', '${i}.1.2'], stderr=subprocess.STDOUT).decode()
double = subprocess.check_output(['${DUMPER}', '${i}.copy.2'], stderr=subprocess.STDOUT).decode()
stargets = re.findall(r'^\s{4}\S+:\s+(\d+)', single, re.MULTILINE)
dtargets = re.findall(r'^\s{4}\S+:\s+(\d+)', double, re.MULTILINE)
for s, d in zip(stargets, dtargets):
    sval, dval = int(s), int(d)
    if dval != sval * 2:
        print(f'TARGET MISMATCH: single={sval} double={dval}')
        sys.exit(1)
print(f'TARGETS SUM: OK ({len(stargets)} targets, all 2x)')
"

# 7. Inline tree preserved
echo "=== INLINE STRUCTURE ==="
python3 -c "
import re, subprocess, sys
single = subprocess.check_output(['${DUMPER}', '${i}.1.2'], stderr=subprocess.STDOUT).decode()
double = subprocess.check_output(['${DUMPER}', '${i}.copy.2'], stderr=subprocess.STDOUT).decode()
sdepth = max((l.count(' ') for l in single.splitlines() if 'num_call' in l), default=0)
ddepth = max((l.count(' ') for l in double.splitlines() if 'num_call' in l), default=0)
scallsites = len([l for l in single.splitlines() if 'num_call' in l])
dcallsites = len([l for l in double.splitlines() if 'num_call' in l])
if sdepth != ddepth:
    print(f'DEPTH MISMATCH: single={sdepth} double={ddepth}')
    sys.exit(1)
if scallsites != dcallsites:
    print(f'CALLSITES MISMATCH: single={scallsites} double={dcallsites}')
    sys.exit(1)
print(f'INLINE STRUCTURE: OK (depth={sdepth}, {scallsites} callsites)')
"

# 8. End-to-end: compile with merged profile
echo "=== E2E v2 ==="
$CC -g -O2 -fauto-profile=${i}.two.2 ${i}.c -o ${i}.two.opt
./${i}.two.opt
echo "E2E V2: OK"
cleanup_files="${cleanup_files} ${i}.two.opt"

if check_gcc_v3_support ; then
	echo "=== E2E v3 ==="
	$CC_V3 -g -O2 -fauto-profile=${i}.two.3 ${i}.c -o ${i}.two.opt3
	./${i}.two.opt3
	echo "E2E V3: OK"
	cleanup_files="${cleanup_files} ${i}.two.opt3"
fi

# 9. Error handling: bad file
echo "=== BAD FILE ==="
echo "garbage" > ${i}.bad
cleanup_files="${cleanup_files} ${i}.bad"
${MERGER} ${i}.bad >${i}.bad.log 2>&1 && {
  echo "BAD FILE: FAIL - merger accepted invalid input"
  exit 1
}
grep -q "bad magic" ${i}.bad.log || {
  echo "BAD FILE: FAIL - unexpected error"
  cat ${i}.bad.log
  exit 1
}
cleanup_files="${cleanup_files} ${i}.bad.log"
echo "BAD FILE: OK"
echo "=== EMPTY OUTPUT v3 ==="
MERGE_OUT_EMPTY3="${i}.empty.3"
cleanup_files="${cleanup_files} ${MERGE_OUT_EMPTY3}"
${MERGER} --output_file ${MERGE_OUT_EMPTY3} --gcov-version 3
test -s ${MERGE_OUT_EMPTY3}
${DUMPER} ${MERGE_OUT_EMPTY3} 2>&1 | grep -q "num functions 0"
echo "EMPTY OUTPUT V3: OK"

echo "=== EMPTY OUTPUT v2 ==="
MERGE_OUT_EMPTY2="${i}.empty.2"
cleanup_files="${cleanup_files} ${MERGE_OUT_EMPTY2}"
${MERGER} --output_file ${MERGE_OUT_EMPTY2} --gcov-version 2
test -s ${MERGE_OUT_EMPTY2}
${DUMPER} ${MERGE_OUT_EMPTY2} 2>&1 | grep -q "num functions 0"
echo "EMPTY OUTPUT V2: OK"

# Final cleanup via trap
trap - EXIT
rm -f ${cleanup_files}
echo "ALL MERGE TESTS PASSED"
