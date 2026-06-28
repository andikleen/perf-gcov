#!/usr/bin/env python3
import sys
import argparse
from format import *

ap = argparse.ArgumentParser()
ap.add_argument('gcovfile', type=argparse.FileType('rb'))
ap.add_argument('--max-count', type=int, help="Error out if any count is larger than N")
args = ap.parse_args()

f = args.gcovfile

def dump_pos(num_pos: int, callsites: int) -> None:
    for p in range(num_pos):
        offset = r32(f)
        num_targets = r32(f)
        counter = rcounter(f)
        print("  %s: %d" % (fmt_offset(offset), counter))
        check_counter(counter, args.max_count)
        for t in range(num_targets):
            expect("topn hist type", r32(f), HIST_TYPE_INDIR_CALL_TOPN)
            target = str_table[rcounter(f)]
            count = rcounter(f)
            print("    %s: %d" % (target, count))
            check_counter(count, args.max_count)
    for i in range(callsites):
        offset = r32(f)
        name = str_table[r32(f)]
        num_pos = r32(f)
        num_call = r32(f)
        print("%s%s %s num_pos %d num_call %d" %
              (" " * (i+3)*2, name, fmt_offset(offset), num_pos, num_call))
        dump_pos(num_pos, num_call)

expect("magic", r32(f), GCOV_DATA_MAGIC)
version = r32(f)
if version not in [2, 3]:
    sys.exit(f"Unsupported GCOV version {version}. Expected version 2 or 3, but file contains version {version}. The file may be corrupted or from an incompatible version.")
print(f"GCOV version: {version}")
r32(f)

# Read summary section (v3 only)
if version == 3:
    tag = r32(f)
    if tag == GCOV_TAG_AFDO_SUMMARY:
        print("=" * 50)
        print("PROFILE SUMMARY")
        print("=" * 50)
        total_count = rcounter(f)
        max_count = rcounter(f)
        max_function_count = rcounter(f)
        num_counts = rcounter(f)
        num_functions = rcounter(f)
        num_detailed = rcounter(f)

        print(f"Total count:          {total_count:,}")
        print(f"Max count:            {max_count:,}")
        print(f"Max function count:   {max_function_count:,}")
        print(f"Number of counts:     {num_counts:,}")
        print(f"Number of functions:  {num_functions:,}")
        print(f"\nDetailed summaries ({num_detailed}):")
        print(f"{'Percentile':>12} {'Min Count':>15} {'Num Counts':>15}")
        print("-" * 50)

        for i in range(num_detailed):
            cutoff = r32(f)
            min_count = rcounter(f)
            num = rcounter(f)
            percentile = cutoff / 10000.0
            print(f"{percentile:>11.4f}% {min_count:>15,} {num:>15,}")

        print("=" * 50)
        print()

        # Read next tag (should be FILE_NAMES)
        tag = r32(f)

    # Check we got FILE_NAMES tag
    expect("string table magic", tag, GCOV_TAG_AFDO_FILE_NAMES)
else:
    # v2: next tag should be FILE_NAMES
    expect("string table magic", r32(f), GCOV_TAG_AFDO_FILE_NAMES)
r32(f)  # length

file_table = []
str_table = {}

if version == 2:
    # v2: just function names
    num = r32(f)
    for i in range(num):
        str_table[i] = rstring(f)

elif version == 3:
    # v3: file names, then functions with file indices
    num_files = r32(f)
    for i in range(num_files):
        file_table.append(rstring(f))

    num_funcs = r32(f)
    for i in range(num_funcs):
        func_name = rstring(f)
        file_idx = r32(f)

        # Format as "function:file" (AutoFDO style)
        if file_idx < len(file_table):
            str_table[i] = f"{func_name}:{file_table[file_idx]}"
        elif file_idx == 0xFFFFFFFF:  # -1 as unsigned
            str_table[i] = func_name  # No file info
        else:
            # Invalid index - file may be corrupted
            print(f"Warning: function '{func_name}' has invalid file index {file_idx} (max valid: {len(file_table)-1})", file=sys.stderr)
            str_table[i] = f"{func_name}:<?>"

expect("function magic", r32(f), GCOV_TAG_AFDO_FUNCTION)
r32(f)  # len
num_funcs = r32(f)
print("num functions %d" % num_funcs)
for i in range(num_funcs):
    head = rcounter(f)
    ts = 0
    if version >= 3:
        ts = rcounter(f)  # timestamp (v3 only)
    fname = str_table[r32(f)]
    if version >= 3 and ts:
        print("%s: %d  (timestamp %d)" % (fname, head, ts))
    else:
        print("%s: %d" % (fname, head))
    check_counter(head, args.max_count)
    num_pos = r32(f)
    callsites = r32(f)
    dump_pos(num_pos, callsites)
