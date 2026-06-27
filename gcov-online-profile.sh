#!/bin/bash
# gcov-online-profile.sh - Continuous system-wide profiling with merging
#
# Profiles the system in a loop using perf record -a, generates gcov profiles
# via the streaming pipeline, and merges results into an output directory.
# Runs until Ctrl+C.
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
GCOV_PY="$SCRIPT_DIR/gcov.py"
MERGER="$SCRIPT_DIR/profile-merger.py"

# Defaults
OUTPUT_DIR="."
INTERVAL=5
ITERATIONS=0
BINARIES=()
EVENT="branches:ppu"
COUNT=300003
PERF_RECORD_OPTS=""
QUIET=false
VERBOSE=false
FORWARD_OPTS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") --output-dir DIR [options] [-- <gcov-opts>]

Generate gcov profiles in a continuous loop, merging into an output directory.
Runs until Ctrl+C.

Script options:
  --output-dir DIR  Output directory for merged profiles (default: current dir)
  --interval N      Sleep duration per iteration (default: 5)
  --iterations N    Run N iterations then exit (default: infinite)
  --event EVENT     Perf event (default: branches:ppu)
  --count N         Sample period (default: 300003)
  --cpu CPU         Limit profiling to specific CPUs (e.g., 0, 0-3)
  --cgroup CGROUP   Limit profiling to specific cgroup
  --uid UID         Limit profiling to specific user ID
  --binary NAME     Binary to profile (fnmatch pattern, repeatable).
                    If omitted, all binaries are profiled.
  --quiet           Suppress all output except config summary
  --verbose         Show detailed per-iteration output

All other --options are forwarded to gcov.py. Common gcov.py options:
  --gcov-version N  GCOV version (default: 3)
  --threshold N     Min samples threshold (default: 10)
  --help            Show this message and exit

Examples:
  ./gcov-online-profile.sh --output-dir /tmp/profiles
  ./gcov-online-profile.sh --output-dir /tmp/profiles --binary bash --interval 10
  ./gcov-online-profile.sh --output-dir /tmp/profiles --gcov-version 2 --verbose
EOF
    exit 1
}

# Helper: validate a positive integer argument
require_int_arg() {
    local flag=$1 val=$2
    if [[ -z $val || $val == -* ]]; then
        echo "error: $flag requires a value" >&2
        exit 1
    fi
    if ! [[ $val =~ ^[0-9]+$ ]] || [[ $val -le 0 ]]; then
        echo "error: $flag must be a positive integer" >&2
        exit 1
    fi
}

# Helper: validate a non-empty string argument
require_arg() {
    local flag=$1 val=$2
    if [[ -z $val || $val == -* ]]; then
        echo "error: $flag requires a value" >&2
        exit 1
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --output-dir)
            require_arg "$1" "${2-}"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --interval)
            require_int_arg "$1" "${2-}"
            INTERVAL="$2"
            shift 2
            ;;
        --iterations|--limit)
            require_int_arg "$1" "${2-}"
            ITERATIONS="$2"
            shift 2
            ;;
        --event)
            require_arg "$1" "${2-}"
            EVENT="$2"
            shift 2
            ;;
        --count)
            require_int_arg "$1" "${2-}"
            COUNT="$2"
            shift 2
            ;;
        --cpu)
            require_arg "$1" "${2-}"
            PERF_RECORD_OPTS="$PERF_RECORD_OPTS --cpu $2"
            shift 2
            ;;
        --cgroup)
            require_arg "$1" "${2-}"
            PERF_RECORD_OPTS="$PERF_RECORD_OPTS --cgroup $2"
            shift 2
            ;;
        --uid)
            require_arg "$1" "${2-}"
            PERF_RECORD_OPTS="$PERF_RECORD_OPTS --uid $2"
            shift 2
            ;;
        --binary)
            require_arg "$1" "${2-}"
            BINARIES+=("$2")
            shift 2
            ;;
        --quiet)
            QUIET=true
            FORWARD_OPTS+=("--quiet")
            shift
            ;;
        --verbose)
            VERBOSE=true
            FORWARD_OPTS+=("--verbose")
            shift
            ;;
        --help|-h)
            usage
            ;;
        --)
            shift
            FORWARD_OPTS+=("$@")
            break
            ;;
        *)
            FORWARD_OPTS+=("$1")
            shift
            ;;
    esac
done

# Validate
if [[ $ITERATIONS -gt 0 && ! $ITERATIONS =~ ^[0-9]+$ ]]; then
    echo "error: --iterations must be a non-negative integer" >&2
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Validate dependencies
for dep in "$GCOV_PY" "$MERGER"; do
    if [[ ! -f "$dep" ]]; then
        echo "error: $dep not found" >&2
        exit 1
    fi
done

# Extract gcov-version and threshold from FORWARD_OPTS for profile-merger.py
MERGE_GCOV_VERSION=3
MERGE_THRESHOLD=10
_i=0
while [[ $_i -lt ${#FORWARD_OPTS[@]} ]]; do
    opt="${FORWARD_OPTS[$_i]}"
    _i=$((_i + 1))
    if [[ $opt == "--gcov-version" || $opt == "--gcov_version" ]]; then
        MERGE_GCOV_VERSION="${FORWARD_OPTS[$_i]:-}"
    elif [[ $opt == "--threshold" || $opt == "--threshold"* ]]; then
        MERGE_THRESHOLD="${FORWARD_OPTS[$_i]:-}"
    fi
done

# Signal handling
# Single Ctrl+C: finish current iteration (perf script + merge), then exit.
# Double Ctrl+C: force immediate exit (restored default SIGINT handler).
STOP_AFTER_ITERATION=false
cleanup() {
    if $STOP_AFTER_ITERATION; then
        # Second Ctrl+C — force exit immediately
        echo "" >&2
        echo "Force exit..." >&2
        rm -rf "$CURRENT_TMPDIR"
        exit 1
    fi
    echo "" >&2
    echo "Finishing current iteration..." >&2
    STOP_AFTER_ITERATION=true
    trap - SIGINT SIGTERM  # Second Ctrl+C hits default handler (terminate)
}
trap cleanup SIGINT SIGTERM

# Configuration summary (always shown, even with --quiet)
echo "=== Continuous System Profiling ===" >&2
echo "Output directory: $OUTPUT_DIR" >&2
echo "Interval: $INTERVAL seconds" >&2
echo "Event: $EVENT" >&2
echo "Sample period: $COUNT" >&2
if [[ ${#BINARIES[@]} -gt 0 ]]; then
    echo "Binaries: ${BINARIES[*]}" >&2
else
    echo "Binaries: all (auto-discover)" >&2
fi
echo "Press Ctrl+C to stop (double Ctrl+C to force exit)" >&2
echo "" >&2

TOTAL_MERGES=0
merge_profiles() {
    local src_dir=$1 dest_dir=$2
    local merged=0 bins=()

    for src_file in "$src_dir"/*.gcov; do
        [[ -f "$src_file" ]] || continue

        local base dest_file
        base=$(basename "$src_file")
        dest_file="$dest_dir/$base"

        if [[ -f "$dest_file" ]]; then
            local tmp
            tmp=$(mktemp -p "$dest_dir" .gcov-merge-XXXXXX)
            err="$tmp.err"
            if "$MERGER" "$dest_file" "$src_file" \
                --output "$tmp" \
                --gcov-version "$MERGE_GCOV_VERSION" \
                --threshold "$MERGE_THRESHOLD" 2>"$err"; then
                rm -f "$err"
                mv "$tmp" "$dest_file"
                TOTAL_MERGES=$((TOTAL_MERGES + 1))
            else
                echo "warning: merge failed for $base: $(cat "$err" 2>/dev/null)" >&2
                rm -f "$tmp" "$err"
            fi
        else
            cp "$src_file" "$dest_file"
        fi
        merged=$((merged + 1))
        bins+=("$base")
    done

    if $VERBOSE && [[ $merged -gt 0 ]]; then
        echo "Profiled $merged binaries:" >&2
        for b in "${bins[@]}"; do
            echo "  $OUTPUT_DIR/$b" >&2
        done
    fi

    if [[ $merged -gt 0 ]]; then
        $QUIET || echo "Merged $merged profiles into $OUTPUT_DIR" >&2
    fi
}

# Main loop
ITER=0
while true; do
    ITER=$((ITER + 1))
    if [[ $ITERATIONS -gt 0 && $ITER -gt $ITERATIONS ]]; then
        break
    fi
    CURRENT_TMPDIR=$(mktemp -d /tmp/gcov-online-XXXXXX)

    # Profile system-wide for N seconds
    if ! perf record -a -b -e "$EVENT" -c "$COUNT" $PERF_RECORD_OPTS \
        -o "$CURRENT_TMPDIR/perf.data" sleep "$INTERVAL" >/dev/null 2>"$CURRENT_TMPDIR/perf-err.txt"; then
        if [[ ! -s "$CURRENT_TMPDIR/perf.data" ]]; then
            echo "warning: perf record produced no data (iteration $ITER)" >&2
        fi
        # perf record may fail due to Ctrl+C killing sleep; continue
    fi

    # If temp dir was removed by force-exit cleanup, stop
    [[ -d "$CURRENT_TMPDIR" ]] || break

    # Build gcov.py command as array (handles spaces in arguments)
    GCOV_CMD=("$GCOV_PY" "--output-dir" "$CURRENT_TMPDIR")
    for bin in "${BINARIES[@]}"; do
        GCOV_CMD+=("--binary" "$bin")
    done
    for opt in "${FORWARD_OPTS[@]}"; do
        GCOV_CMD+=("$opt")
    done

    # Generate gcov profiles
    $VERBOSE && $QUIET && false  # mutually exclusive; quiet wins
    if $VERBOSE; then
        perf script -i "$CURRENT_TMPDIR/perf.data" "${GCOV_CMD[@]}" 2>&1 || true
    elif $QUIET; then
        perf script -i "$CURRENT_TMPDIR/perf.data" "${GCOV_CMD[@]}" >/dev/null 2>&1 || true
    else
        perf script -i "$CURRENT_TMPDIR/perf.data" "${GCOV_CMD[@]}" 2>/dev/null || true
    fi

    # Merge profiles into output directory
    merge_profiles "$CURRENT_TMPDIR" "$OUTPUT_DIR"

    # Cleanup temp directory
    rm -rf "$CURRENT_TMPDIR"
    CURRENT_TMPDIR=""

    # If Ctrl+C was pressed, exit after finishing this iteration
    $STOP_AFTER_ITERATION && break
done

# Print final summary
if [[ $ITER -gt 1 ]] && ! $QUIET; then
    echo "Completed $((ITER - 1)) iterations. $TOTAL_MERGES merges. Output directory: $OUTPUT_DIR" >&2
fi
exit 0
