#!/bin/bash
# gcov-parallel.sh - Process perf.data in parallel using time-sliced perf script
#
# Splits perf.data into N time-slices, processes each slice concurrently with
# gcov.py, then merges the results into a single gcov file.
#
# When --jobs is not specified, the number of workers is auto-detected from
# nproc and capped so each slice gets at least --min-mb-per-job MB of data.
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
GCOV_PY="$SCRIPT_DIR/gcov.py"
MERGER="$SCRIPT_DIR/profile-merger.py"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] -- <profile-opts>

Process perf.data in parallel using time-sliced perf script, then merge results.

Wrapper options:
  -j, --jobs <N>         Number of parallel workers (default: nproc). Must be >= 1.
  -i, --profile <file>   Input perf data file (default: perf.data)
  --gcov <file>          Output gcov file (default: auto-detected from binary name)
  --min-mb-per-job <N>   Minimum MB per job when auto-detecting job count.
                         Lower = more parallel jobs (default: 10).
                         Ignored when --jobs is explicitly set.

All other --options are forwarded to gcov.py. Common options:
  --binary <pattern>   Binary to profile (fnmatch pattern, repeatable)
  --threshold <N>      Min samples threshold (default: 10)
  --gcov-version <2|3> Format version (default: 3)
  --verbose            Enable verbose output

See gcov.py --help for complete list of options.

Examples:
  # Basic usage
  gcov-parallel.sh -i perf.data --binary ./app --gcov app.gcov

  # Use 4 parallel workers
  gcov-parallel.sh -j 4 -i perf.data --binary ./app --gcov app.gcov

  # With verbose output and custom threshold
  gcov-parallel.sh -i perf.data --binary ./app --gcov app.gcov --verbose --threshold 20

Pipeline:
  perf script -i <profile> --time <slice>/<N> gcov.py ...
  profile-merger.py -o <output> <slice-files...>
EOF
  exit 1
}

# Helper: validate a positive integer argument
require_int_arg() {
  if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
    echo "error: $1 requires a positive integer argument" >&2
    exit 1
  fi
}

# Helper: validate a non-empty string argument
require_arg() {
  if [[ -z "${2:-}" || "$2" =~ ^- ]]; then
    echo "error: $1 requires a non-empty argument" >&2
    exit 1
  fi
}

# Defaults
JOBS=""
JOBS_EXPLICIT=false
MIN_MB_PER_JOB=10
PROFILE=""
GCOV=""
FORWARD_OPTS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --jobs|-j)
      require_int_arg "$@"
      JOBS="$2"
      JOBS_EXPLICIT=true
      shift 2
      ;;
    --min-mb-per-job)
      require_int_arg "$@"
      MIN_MB_PER_JOB="$2"
      shift 2
      ;;
    --profile|-i)
      require_arg "$@"
      PROFILE="$2"
      shift 2
      ;;
    --gcov)
      require_arg "$@"
      GCOV="$2"
      shift 2
      ;;
    --help|-h)
      usage
      break
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

# Validation
if [[ -z "$PROFILE" ]]; then
  if [[ -f "perf.data" ]]; then
    PROFILE="perf.data"
  else
    echo "error: no profile specified and perf.data not found" >&2
    exit 1
  fi
fi

if [[ ! -f "$PROFILE" ]]; then
  echo "error: profile not found: $PROFILE" >&2
  exit 1
fi

if [[ ! -f "$MERGER" ]]; then
  echo "error: profile-merger.py not found at $MERGER" >&2
  exit 1
fi

if [[ ! -f "$GCOV_PY" ]]; then
  echo "error: gcov.py not found at $GCOV_PY" >&2
  exit 1
fi

# Resolve number of parallel jobs
if [[ -z "$JOBS" ]]; then
  JOBS=$(nproc 2>/dev/null || echo 1)
  # Auto-limit based on file size: avoid slices smaller than MIN_MB_PER_JOB
  if [[ -f "$PROFILE" ]]; then
    FILE_BYTES=$(stat -c%s "$PROFILE" 2>/dev/null || echo 0)
    if [[ "$FILE_BYTES" -gt 0 ]]; then
      FILE_MB=$((FILE_BYTES / 1048576))
      if [[ "$FILE_MB" -lt 1 ]]; then
        FILE_MB=1
      fi
      MAX_BY_SIZE=$((FILE_MB / MIN_MB_PER_JOB))
      if [[ "$MAX_BY_SIZE" -lt 1 ]]; then
        MAX_BY_SIZE=1
      fi
      if [[ "$JOBS" -gt "$MAX_BY_SIZE" ]]; then
        JOBS=$MAX_BY_SIZE
      fi
    fi
  fi
fi

# Resolve output path
if [[ -z "$GCOV" ]]; then
  binary=""
  for opt in "${FORWARD_OPTS[@]}"; do
    if [[ "$opt" == "--binary" || "$opt" == "-binary" ]]; then
      binary=""
    elif [[ -z "$binary" && ! "$opt" =~ ^- ]]; then
      binary="$opt"
    fi
  done
  if [[ -n "$binary" ]]; then
    GCOV="$(basename "$binary").gcov"
  else
    GCOV="file.gcov"
  fi
fi

# Extract gcov-version and threshold from FORWARD_OPTS for profile-merger.py
MERGE_GCOV_VERSION=3
MERGE_THRESHOLD=10
_i=0
while [[ $_i -lt ${#FORWARD_OPTS[@]} ]]; do
  opt="${FORWARD_OPTS[$_i]}"
  _i=$((_i + 1))
  if [[ $opt == "--gcov-version" || $opt == "--gcov_version" ]]; then
    MERGE_GCOV_VERSION="${FORWARD_OPTS[$_i]:-}"
    _i=$((_i + 1))
  elif [[ $opt == "--threshold" || $opt == "--threshold"* ]]; then
    MERGE_THRESHOLD="${FORWARD_OPTS[$_i]:-}"
    _i=$((_i + 1))
  fi
done

# Setup temp file paths (hidden files in output directory)
OUTPUT_DIR="$(dirname "$GCOV")"
if [[ "$OUTPUT_DIR" == "." ]]; then
  OUTPUT_DIR=""
else
  OUTPUT_DIR="${OUTPUT_DIR}/"
fi
OUTPUT_BASE="$(basename "$GCOV")"
TEMP_PREFIX="${OUTPUT_DIR}.${OUTPUT_BASE}.par."

# Compute time slice percentages
PCT=$((100 / JOBS))
REM=$((100 % JOBS))

# Launch parallel subprocesses
PIDS=()
for ((i = 1; i <= JOBS; i++)); do
  if [[ $i -eq $JOBS && $REM -gt 0 ]]; then
    # Last slice with remainder — use explicit range syntax
    # a%/n doesn't work when this slice's size differs from the others
    START_PCT=$(( (i - 1) * PCT ))
    TIME_SPEC="${START_PCT}%-100%"
  else
    TIME_SPEC="${PCT}%/$i"
  fi
  TEMP_FILE="${TEMP_PREFIX}$((i - 1)).gcov.tmp"
  perf script -i "$PROFILE" --time "$TIME_SPEC" \
    "$GCOV_PY" --gcov "$TEMP_FILE" "${FORWARD_OPTS[@]}" &
  PIDS+=($!)
done

# Signal handler — kill subprocesses and clean up temp files
cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -f "${TEMP_PREFIX}"*.gcov.tmp
  exit 1
}
trap cleanup SIGINT SIGTERM

# Wait for all subprocesses
FAILED=false
for pid in "${PIDS[@]}"; do
  wait "$pid" || FAILED=true
done

# Merge or fail
if [[ "$FAILED" == true ]]; then
  echo "error: one or more parallel subprocesses failed" >&2
  rm -f "${TEMP_PREFIX}"*.gcov.tmp
  exit 1
fi

if [[ $JOBS -eq 1 ]]; then
  # Single slice — just rename
  mv "${TEMP_PREFIX}0.gcov.tmp" "$GCOV"
else
  # Merge slices
  "$MERGER" -o "$GCOV" \
    --gcov-version "$MERGE_GCOV_VERSION" \
    --threshold "$MERGE_THRESHOLD" \
    "${TEMP_PREFIX}"*.gcov.tmp
  rm -f "${TEMP_PREFIX}"*.gcov.tmp
fi
