#!/usr/bin/python
import struct
import sys
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('gcovfile', type=argparse.FileType('rb'))
ap.add_argument('--max-count', type=int, help="Error out if any count is larger than N")
args = ap.parse_args()

GCOV_TAG_AFDO_FILE_NAMES = 0xaa000000
GCOV_TAG_AFDO_FUNCTION = 0xac000000
GCOV_TAG_AFDO_MODULE_GROUPING = 0xae000000
GCOV_TAG_AFDO_WORKING_SET = 0xaf000000
GCOV_DATA_MAGIC = 0x67636461 # 'gcda'
GCOV_VERSION = 2
HIST_TYPE_INDIR_CALL_TOPN = 7

def r32(f):
    return struct.unpack("I", f.read(4))[0]

def rstring(f):
    l = r32(f)
    s = f.read(l)
    return struct.unpack("%ds" % l, s)[0].decode('utf-8')[:-1]

def rcounter(f):
    a = r32(f)
    b = r32(f)
    return a | (b << 32)

def expect(what, val, exp):
    if val != exp:
        sys.exit("for %s expect %x got val %x" % (what, exp, val))

def warn_expect(what, val, exp):
    if val != exp:
        print("for %s expect %x got val %x" % (what, exp, val))

def check_counter(count):
    if args.max_count and count > args.max_count:
        sys.exit("count value %d larger than %d" % (count, args.max_count))

def fmt_offset(offset):
    if offset & 0xffff:
        return "%d.%d" % (offset >> 16, offset & 0xffff)
    return "%d" % (offset >> 16)

f = args.gcovfile

def dump_pos(num_pos, callsites):
    for p in range(num_pos):
        offset = r32(f)
        num_targets = r32(f)
        counter = rcounter(f)
        print("  %s: %d" % (fmt_offset(offset), counter))
        check_counter(counter)
        for t in range(num_targets):
            expect("topn hist type", r32(f), HIST_TYPE_INDIR_CALL_TOPN)
            target = str_table[rcounter(f)]
            count = rcounter(f)
            print("    %s: %d" % (target, count))
            check_counter(count)
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
r32(f) # len
num_funcs = r32(f)
print("num functions %d" % num_funcs)
for i in range(num_funcs):
    head = rcounter(f)
    fname = str_table[r32(f)]
    print("%s: %d" % (fname, head))
    check_counter(head)
    num_pos = r32(f)
    callsites = r32(f)
    dump_pos(num_pos, callsites)


