#!/usr/bin/python
import struct
import sys

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

def fmt_offset(offset):
    if offset & 0xffff:
        return "%d.%d" % (offset >> 16, offset & 0xffff)
    return "%d" % (offset >> 16)

f = open(sys.argv[1], "rb")

expect("magic", r32(f), GCOV_DATA_MAGIC)
expect("version", r32(f), GCOV_VERSION)
r32(f)

expect("string table magic", r32(f), GCOV_TAG_AFDO_FILE_NAMES)
r32(f) # len
num = r32(f)
str_table = dict()
for i in range(num):
    str_table[i] = rstring(f)

expect("function magic", r32(f), GCOV_TAG_AFDO_FUNCTION)
r32(f) # len
num_funcs = r32(f)
for i in range(num_funcs):
    head = rcounter(f)
    fname = str_table[r32(f)]
    print("%s: %d" % (fname, head))
    num_pos = r32(f)
    callsites = r32(f)
    for p in range(num_pos):
        offset = r32(f)
        num_targets = r32(f)
        counter = rcounter(f)
        print("  %s: %d" % (fmt_offset(offset), counter))
        for t in range(num_targets):
            expect("topn hist type", r32(f), HIST_TYPE_INDIR_CALL_TOPN)
            target = str_table[rcounter(f)]
            count = rcounter(f)
            print("    %s: %d" % (target, count))
    # XXX recursion
