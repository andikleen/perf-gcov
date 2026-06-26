#!/usr/bin/env python3
# Shared GCOV format constants and I/O helpers for perf-gcov tools
# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import struct
import sys
from typing import BinaryIO

GCOV_TAG_AFDO_SUMMARY = 0xa8000000
GCOV_TAG_AFDO_FILE_NAMES = 0xaa000000
GCOV_TAG_AFDO_FUNCTION = 0xac000000
GCOV_TAG_AFDO_MODULE_GROUPING = 0xae000000
GCOV_TAG_AFDO_WORKING_SET = 0xaf000000
GCOV_DATA_MAGIC = 0x67636461  # 'gcda'
HIST_TYPE_INDIR_CALL_TOPN = 7
DEFAULT_CUTOFFS = [
    10000, 100000, 200000, 300000, 400000, 500000, 600000, 700000,
    800000, 900000, 950000, 990000, 999000, 999900, 999990, 999999,
]


def w32(f: BinaryIO, v: int) -> None:
    try:
        f.write(struct.pack("I", v))
    except struct.error:
        sys.exit("bad value for w32 %x" % v)


def wstring(f: BinaryIO, s: str) -> None:
    s += "\0"
    w32(f, len(s))
    f.write(struct.pack("%ds" % len(s), s.encode('utf-8')))


def wcounter(f: BinaryIO, v: int) -> None:
    w32(f, (v       ) & 0xffffffff)
    w32(f, (v >> 32 ) & 0xffffffff)


def gen_offset(line: int, disc: int) -> int:
    """Generate 32-bit offset from line number and discriminator.

    Format: bits [31:16] = line, bits [15:0] = discriminator.
    Discriminator is masked to 16 bits (matching autofdo).
    """
    line = line & 0xFFFF if line < 0 else min(line, 0xFFFF)
    return (line << 16) | (disc & 0xFFFF)


def r32(f: BinaryIO) -> int:
    return struct.unpack("I", f.read(4))[0]


def rstring(f: BinaryIO) -> str:
    l = r32(f)
    s = f.read(l)
    return struct.unpack("%ds" % l, s)[0].decode('utf-8')[:-1]


def rcounter(f: BinaryIO) -> int:
    a = r32(f)
    b = r32(f)
    return a | (b << 32)


def expect(what: str, val: int, exp: int) -> None:
    if val != exp:
        sys.exit("for %s expect %x got val %x" % (what, exp, val))


def warn_expect(what: str, val: int, exp: int) -> None:
    if val != exp:
        print("for %s expect %x got val %x" % (what, exp, val))


def check_counter(count: int, max_count: int | None = None) -> None:
    if max_count and count > max_count:
        sys.exit("count value %d larger than %d" % (count, max_count))


def fmt_offset(offset: int) -> str:
    if offset & 0xffff:
        return "%d.%d" % (offset >> 16, offset & 0xffff)
    return "%d" % (offset >> 16)


def merge_nodes(dest, src) -> None:
    """Merge src node's positions, targets, and children into dest.

    Handles the common subset shared by all FuncNode-like trees:
    positions (Counter), targets (dict[int, Counter[str]]), children.
    """
    for off, count in src.positions.items():
        dest.positions[off] += count
    for off, src_targets in src.targets.items():
        for tgt, tgt_count in src_targets.items():
            dest.targets[off][tgt] += tgt_count
    for key, src_child in src.children.items():
        dest_child = dest.children.get(key)
        if dest_child is None:
            dest.children[key] = copy.deepcopy(src_child)
        else:
            merge_nodes(dest_child, src_child)


def write_gcov_tail(f: BinaryIO) -> None:
    w32(f, GCOV_TAG_AFDO_MODULE_GROUPING)
    w32(f, 4)
    w32(f, 0)

    w32(f, GCOV_TAG_AFDO_WORKING_SET)
    w32(f, 4)
    w32(f, 0)
