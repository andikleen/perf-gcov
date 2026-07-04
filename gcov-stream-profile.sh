#!/bin/bash
# gcov-stream-profile.sh - Generate gcov profiles without saving perf.data to disk
#
# Uses a streaming pipeline:
#   perf record -o - | perf script -i - | gcov.py
#
# This avoids writing the intermediate perf.data file to disk, saving 2-240MB
# of disk I/O per profiling run.
#
# Open: Add support for gcc-auto-profile to auto-detect optimal CPU-specific
#       events. Currently gcc-auto-profile does not support stdout output (-o -),
#       it hardcodes writing to perf.data.

set -e          # Exit on error
set -o pipefail # Catch errors in pipelines

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] -- <workload> [workload-args]

Generate gcov profile without saving perf.data to disk using a streaming pipeline.

Options:
  --binary <path>       Path to the profiled binary (default: workload executable)
  --gcov <path>         Output .gcov file path (default: <binary-name>.gcov)

Wrapper options (handled by this script):
  --event <event>       Perf event specification (default: br_inst_retired.near_taken:upp)
			Use branches:ppu if perf errors out
  --count <N>           Sample period (default: auto)

All other --options are forwarded to gcov.py. Common options:
  --threshold <N>       Min samples threshold (default: 10)
  --gcov-version <2|3>  Format version (default: 3)
  --verbose             Enable verbose output
  --top <N>             Print top N samples

See gcov.py --help for complete list of options.

Examples:
  # Simplest usage (auto-detects binary and output name)
  gcov-stream-profile.sh -- ./app

  # Works with commands in PATH
  gcov-stream-profile.sh -- ls /tmp

  # Basic usage with explicit paths
  gcov-stream-profile.sh --binary ./app --gcov app.gcov -- ./app

  # User-space branches with custom threshold
  gcov-stream-profile.sh --binary ./app --gcov app.gcov --event branches:u --threshold 20 -- ./app

  # With verbose output (auto-detect binary/gcov)
  gcov-stream-profile.sh --verbose -- ./app

  # Workload with arguments
  gcov-stream-profile.sh -- ./server --port 8080

Pipeline: perf record -e <event> -o - | perf script -i - gcov.py [options]

EOF
  exit 1
}

# Defaults
EVENT="br_inst_retired.near_taken:ppu"
COUNT=""
BINARY=""
GCOV=""
GCOV_OPTS=()
WORKLOAD=()

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --binary|-binary)
      BINARY="$2"
      shift 2
      ;;
    --gcov|-gcov)
      GCOV="$2"
      shift 2
      ;;
    --event|-event)
      EVENT="$2"
      shift 2
      ;;
    --count|-count)
      COUNT="$2"
      shift 2
      ;;
    --)
      shift
      WORKLOAD=("$@")
      break
      ;;
    --*)
      # Forward unknown options to gcov.py
      GCOV_OPTS+=("$1")
      # Check if this option takes a value (next arg doesn't start with -- or --)
      if [[ $# -gt 1 && $2 != --* && $2 != -- ]]; then
        GCOV_OPTS+=("$2")
        shift 2
      else
        shift
      fi
      ;;
    *)
      echo "Error: Unknown argument: $1" >&2
      usage
      ;;
  esac
done

# Validation
if [[ ${#WORKLOAD[@]} -eq 0 ]]; then
  echo "Error: workload command is required after --" >&2
  usage
fi

# Auto-detect binary and gcov from workload if not specified
if [[ -z "$BINARY" ]]; then
  BINARY="${WORKLOAD[0]}"
  echo "Auto-detected binary: $BINARY" >&2
fi

if [[ -z "$GCOV" ]]; then
  # Generate gcov filename from binary basename
  BINARY_BASENAME="$(basename "$BINARY")"
  GCOV="${BINARY_BASENAME}.gcov"
  echo "Auto-detected gcov output: $GCOV" >&2
fi

# Check if binary exists, if not try to find it in PATH
if [[ ! -e "$BINARY" ]]; then
  BINARY_IN_PATH="$(type -p "$BINARY" 2>/dev/null || true)"
  if [[ -n "$BINARY_IN_PATH" ]]; then
    echo "Binary not found, using PATH: $BINARY_IN_PATH" >&2
    BINARY="$BINARY_IN_PATH"
  else
    echo "Error: binary not found: $BINARY" >&2
    exit 1
  fi
elif [[ -d "$BINARY" ]]; then
  echo "Error: $BINARY is a directory, not a binary" >&2
  exit 1
elif [[ ! -f "$BINARY" ]]; then
  echo "Error: $BINARY is not a regular file" >&2
  exit 1
fi

# Find gcov.py in same directory as this script
SCRIPT_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
GCOV_PY="$SCRIPT_DIR/gcov.py"

if [[ ! -f "$GCOV_PY" ]]; then
  echo "Error: gcov.py not found at: $GCOV_PY" >&2
  exit 1
fi

if [[ ! -x "$GCOV_PY" ]]; then
  echo "Error: gcov.py is not executable: $GCOV_PY" >&2
  exit 1
fi

# Build perf record command
PERF_CMD="perf record -b -c 100003 -e $EVENT"
if [[ -n "$COUNT" ]]; then
  PERF_CMD="$PERF_CMD -c $COUNT"
fi
PERF_CMD="$PERF_CMD -o - ${WORKLOAD[*]}"

# Build perf script command
SCRIPT_CMD="perf script -i - $GCOV_PY --binary $BINARY --gcov $GCOV"
if [[ ${#GCOV_OPTS[@]} -gt 0 ]]; then
  SCRIPT_CMD="$SCRIPT_CMD ${GCOV_OPTS[*]}"
fi

# Execute pipeline
eval "$PERF_CMD | $SCRIPT_CMD"
