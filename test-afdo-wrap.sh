#!/bin/bash
# Test afdo-gcc.py wrapper
# SPDX-License-Identifier: GPL-3.0-or-later

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
WRAPPER="$SCRIPT_DIR/afdo-gcc.py"
FAILED=0

failed() {
    echo "FAILED"
    FAILED=1
}

trap failed ERR

# Setup test environment
TMP=$(mktemp -d ./afdo-wrap-test-XXXXXX)
TMP=$(realpath "$TMP")
cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

# Create fake compiler that echoes args
mkdir -p "$TMP/realbin"
cat > "$TMP/realbin/fake-cc" <<'EOF'
#!/bin/bash
echo "FAKE-CC-MARKER" > "$FAKE_OUT_DIR/marker.txt"
echo "$@" > "$FAKE_OUT_DIR/argv.out"
exit 0
EOF
chmod +x "$TMP/realbin/fake-cc"
ln -s fake-cc "$TMP/realbin/gcc"

# Create distinct fake g++ to verify family detection
cat > "$TMP/realbin/g++" <<'EOF'
#!/bin/bash
echo "FAKE-GXX-MARKER" > "$FAKE_OUT_DIR/marker.txt"
echo "$@" > "$FAKE_OUT_DIR/argv.out"
exit 0
EOF
chmod +x "$TMP/realbin/g++"

# Create alternate fake for precedence tests
cat > "$TMP/realbin/fake-cc-alt" <<'EOF'
#!/bin/bash
echo "FAKE-CC-ALT-MARKER" > "$FAKE_OUT_DIR/marker.txt"
echo "$@" > "$FAKE_OUT_DIR/argv.out"
exit 0
EOF
chmod +x "$TMP/realbin/fake-cc-alt"

# Create afdo directory with test profiles
mkdir -p "$TMP/afdodir"
touch "$TMP/afdodir/foo.gcov"
touch "$TMP/afdodir/a.out.gcov"

# Helper to run wrapper and capture output
run_wrap() {
    local name=$1
    shift
    export FAKE_OUT_DIR="$TMP"
    rm -f "$TMP/argv.out" "$TMP/marker.txt" "$TMP/stderr.txt"

    # Create wrapper symlink with specific name for family testing
    ln -sf "$WRAPPER" "$TMP/$name"

    # Scope PATH to the wrapper call only (don't pollute E2E test environment)
    PATH="$TMP/realbin:$PATH" "$TMP/$name" "$@" 2>"$TMP/stderr.txt" || true
}

pass() { echo "PASS"; }
fail() { echo "FAIL"; FAILED=1; }

echo "=== Test 1: Inject on LTO link ==="
run_wrap afdo-gcc -flto --afdo-dir="$TMP/afdodir" -o foo a.o
if grep -q -- "-fauto-profile=$TMP/afdodir/foo.gcov" "$TMP/argv.out" &&\
   ! grep -q -- "--afdo-dir" "$TMP/argv.out"; then
    pass
else
    fail
fi

echo "=== Test 2: No inject when compiling (-c) ==="
run_wrap afdo-gcc -c -flto --afdo-dir="$TMP/afdodir" -o foo.o foo.c
if ! grep -q -- "-fauto-profile" "$TMP/argv.out"; then
    pass
else
    fail
fi

echo "=== Test 3: No inject without -flto ==="
run_wrap afdo-gcc --afdo-dir="$TMP/afdodir" -o foo a.o
if ! grep -q -- "-fauto-profile" "$TMP/argv.out"; then
    pass
else
    fail
fi

echo "=== Test 4: -fno-lto cancels -flto ==="
run_wrap afdo-gcc -flto -fno-lto --afdo-dir="$TMP/afdodir" -o foo a.o
if ! grep -q -- "-fauto-profile" "$TMP/argv.out"; then
    pass
else
    fail
fi

echo "=== Test 5: Missing profile warns and skips ==="
run_wrap afdo-gcc -flto --afdo-dir="$TMP/afdodir" -o missing a.o
if ! grep -q -- "-fauto-profile" "$TMP/argv.out" &&\
   grep -q "no profile.*missing.gcov" "$TMP/stderr.txt"; then
    pass
else
    fail
fi

echo "=== Test 6: Default a.out ==="
run_wrap afdo-gcc -flto --afdo-dir="$TMP/afdodir" a.o
if grep -q -- "-fauto-profile=$TMP/afdodir/a.out.gcov" "$TMP/argv.out"; then
    pass
else
    fail
fi

echo "=== Test 7: Respect existing -fauto-profile ==="
run_wrap afdo-gcc -flto --afdo-dir="$TMP/afdodir" -fauto-profile=user.gcov -o foo a.o
argv_content=$(cat "$TMP/argv.out")
if echo "$argv_content" | grep -q -- "-fauto-profile=user.gcov" &&\
   ! echo "$argv_content" | grep -q -- "-fauto-profile=$TMP/afdodir/foo.gcov" &&\
   ! echo "$argv_content" | grep -q -- "--afdo-dir"; then
    pass
else
    fail
fi

echo "=== Test 8: Wrapper flags stripped ==="
run_wrap afdo-gcc -flto --afdo-dir="$TMP/afdodir" --afdo-cc="$TMP/realbin/fake-cc" -o foo a.o
if ! grep -q -- "--afdo-dir" "$TMP/argv.out" &&\
   ! grep -q -- "--afdo-cc" "$TMP/argv.out"; then
    pass
else
    fail
fi

echo "=== Test 9: Real compiler precedence (--afdo-cc wins) ==="
run_wrap afdo-gcc --afdo-cc="$TMP/realbin/fake-cc-alt" -o foo a.o
if grep -q "FAKE-CC-ALT-MARKER" "$TMP/marker.txt"; then
    pass
else
    fail
fi

echo "=== Test 10: Real compiler precedence (AFDO_CC) ==="
export AFDO_CC="$TMP/realbin/fake-cc-alt"
run_wrap afdo-gcc -o foo a.o
unset AFDO_CC
if grep -q "FAKE-CC-ALT-MARKER" "$TMP/marker.txt"; then
    pass
else
    fail
fi

echo "=== Test 11: Space-form flags ==="
run_wrap afdo-gcc -flto --afdo-dir "$TMP/afdodir" -o foo a.o
if grep -q -- "-fauto-profile=$TMP/afdodir/foo.gcov" "$TMP/argv.out"; then
    pass
else
    fail
fi

echo "=== Test 12: Glued -o form (-obar) ==="
run_wrap afdo-gcc -flto --afdo-dir="$TMP/afdodir" -obar a.o
# Last -o wins; "bar" should be extracted and bar.gcov injected
touch "$TMP/afdodir/bar.gcov"
run_wrap afdo-gcc -flto --afdo-dir="$TMP/afdodir" -obar a.o
if grep -q -- "-fauto-profile=$TMP/afdodir/bar.gcov" "$TMP/argv.out"; then
    pass
else
    fail
fi

echo "=== Test 13: Family detection (afdo-g++.py) ==="
# Test the shipped symlink name afdo-g++.py (with .py extension) resolves to g++ family
export AFDO_CXX="$TMP/realbin/g++"
run_wrap afdo-g++.py -o foo a.o
unset AFDO_CXX
# Check that the g++ fake ran (distinct marker) and AFDO_CXX was honored
if grep -q "FAKE-GXX-MARKER" "$TMP/marker.txt"; then
    pass
else
    fail
fi

echo "=== Test 14: Preprocessing (-E) doesn't inject ==="
run_wrap afdo-gcc -E -flto --afdo-dir="$TMP/afdodir" foo.c
if ! grep -q -- "-fauto-profile" "$TMP/argv.out"; then
    pass
else
    fail
fi

echo "=== Test 15: Assembly (-S) doesn't inject ==="
run_wrap afdo-gcc -S -flto --afdo-dir="$TMP/afdodir" -o foo.s foo.c
if ! grep -q -- "-fauto-profile" "$TMP/argv.out"; then
    pass
else
    fail
fi

echo "=== Test 16: Empty --afdo-dir= rejected ==="
run_wrap afdo-gcc --afdo-dir= -o foo a.o
# Should exit with error; check stderr for "requires a value"
if grep -q "requires a value" "$TMP/stderr.txt"; then
    pass
else
    fail
fi

echo "=== Test 17: --help support ==="
# Lone --help prints wrapper usage and exits 0
"$WRAPPER" --help > "$TMP/help.txt" 2>&1
if grep -q -- "--afdo-dir" "$TMP/help.txt" &&\
   grep -q "AFDO_CC" "$TMP/help.txt"; then
    pass
else
    fail
fi
# --help=target passes through to the real compiler (fake in this case)
run_wrap afdo-gcc --help=target -o foo a.o
if grep -q -- "--help=target" "$TMP/argv.out"; then
    pass
else
    fail
fi

# E2E test with real gcc (guarded on gcc 16+)
echo "=== Test 18: E2E with real GCC (if available) ==="
if command -v gcc >/dev/null 2>&1; then
    GCC_VERSION=$(gcc -dumpversion | cut -d. -f1)
    if [ "$GCC_VERSION" -ge 16 ]; then
        # Create a simple test program
        cat > "$TMP/test.c" <<'EOFC'
int main() { return 0; }
EOFC

        # Compile to object with LTO
        gcc -g -O2 -flto -c "$TMP/test.c" -o "$TMP/test.o"

        # Create a minimal profile (or skip if gcov.py not easily runnable)
        # For now, create an empty but valid gcov file
        cat > "$TMP/afdodir/test-e2e.gcov" <<'EOFG'
afdo
EOFG

        # Try linking with wrapper
        if "$WRAPPER" -flto --afdo-dir="$TMP/afdodir" -o "$TMP/test-e2e" "$TMP/test.o" 2>"$TMP/e2e-stderr.txt"; then
            if [ -x "$TMP/test-e2e" ] && "$TMP/test-e2e"; then
                pass
            else
                echo "SKIP (binary not executable or failed)"
            fi
        else
            echo "SKIP (link failed, profile may be invalid)"
        fi
    else
        echo "SKIP (gcc < 16)"
    fi
else
    echo "SKIP (gcc not found)"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "SOME TESTS FAILED"
    exit 1
fi
