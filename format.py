#!/usr/bin/env python3
# Shared GCOV format constants and I/O helpers for perf-gcov tools
# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import struct
import sys
from collections import Counter
from typing import Any, BinaryIO, Protocol

FuncKey = tuple[str, str | None]

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
    w32(f, (v) & 0xffffffff)
    w32(f, (v >> 32) & 0xffffffff)


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
    length = r32(f)
    s = f.read(length)
    return struct.unpack("%ds" % length, s)[0].decode('utf-8')[:-1]


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


class _V2Node(Protocol):
    """Minimal interface for FuncNode-like objects in v2 tree operations."""
    targets: dict[int, Counter]
    children: dict


class _MergeableNode(_V2Node, Protocol):
    """Interface for nodes that can be merged via merge_nodes."""
    positions: Counter[int]


def merge_nodes(dest: _MergeableNode, src: _MergeableNode) -> None:
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


def make_v2_merged_tree(tree: dict[FuncKey, Any]) -> dict[str, Any]:
    """Merge a composite-key (name, source_file) tree into a name-keyed tree for v2.

    Strips the source_file dimension from keys and recursively merges
    targets from Counter[tuple] to Counter[str].
    """
    merged: dict[str, Any] = {}
    for key, node in tree.items():
        name = key[0]
        if name in merged:
            merge_nodes(merged[name], node)
        else:
            merged[name] = copy.deepcopy(node)
    _merge_v2_node_targets(merged)
    return merged


def _merge_v2_node_targets(tree: dict[str, _V2Node]) -> None:
    for node in tree.values():
        for off in list(node.targets):
            merged: Counter[str] = Counter()
            for tkey, tcount in node.targets[off].items():
                merged[tkey[0] if isinstance(tkey, tuple) else tkey] += tcount
            node.targets[off] = merged
        _merge_v2_child_targets(node)


def _merge_v2_child_targets(node: _V2Node) -> None:
    for child in node.children.values():
        for off in list(child.targets):
            merged: Counter[str] = Counter()
            for tkey, tcount in child.targets[off].items():
                merged[tkey[0] if isinstance(tkey, tuple) else tkey] += tcount
            child.targets[off] = merged
        _merge_v2_child_targets(child)


def write_v2_function_instance(f: BinaryIO, node: Any, offset: int,
                               string_index: dict[str, int],
                               threshold: int) -> None:
    """Write one function instance in v2 format."""
    if offset == 0:
        head = node.head_count() if callable(node.head_count) else node.head_count
        wcounter(f, head)
        w32(f, string_index[node.name])
    else:
        w32(f, offset)
        w32(f, string_index[node.name])

    positions: list[tuple[int, int, Counter[str]]] = []
    for off in sorted(node.positions):
        count = node.positions[off]
        targets: Counter[str] = Counter()
        for name, c in node.targets.get(off, Counter()).items():
            if c >= threshold:
                targets[name] += c
        has_output = count >= threshold or (count == 0 and targets)
        if not has_output:
            zeros = node.structural_zeros if hasattr(node, 'structural_zeros') else set()
            if off not in zeros:
                continue
        positions.append((off, count, targets))

    children: list[tuple[int, str, Any]] = []
    for (coff, cname, csrc), child in sorted(node.children.items()):
        try:
            has_output = child.has_output(threshold)
        except TypeError:
            has_output = child.has_output()
        if has_output:
            children.append((coff, cname, child))

    w32(f, len(positions))
    w32(f, len(children))

    for off, count, targets in positions:
        w32(f, off)
        w32(f, len(targets))
        wcounter(f, count)
        for tname, tcount in targets.most_common():
            w32(f, HIST_TYPE_INDIR_CALL_TOPN)
            wcounter(f, string_index[tname])
            wcounter(f, tcount)

    for coff, _, child in children:
        write_v2_function_instance(f, child, coff, string_index, threshold)


def write_v2_function_section(f: BinaryIO, tree: dict[str, Any],
                              string_index: dict[str, int],
                              threshold: int) -> None:
    """Write GCOV_TAG_AFDO_FUNCTION section for v2 format."""
    w32(f, GCOV_TAG_AFDO_FUNCTION)
    lenoff = f.tell()
    w32(f, 0)
    w32(f, len(tree))
    for name in sorted(tree):
        write_v2_function_instance(f, tree[name], 0, string_index, threshold)
    endoff = f.tell()
    f.seek(lenoff)
    w32(f, endoff - lenoff)
    f.seek(endoff)
