#!/usr/bin/env python3
"""Diff two gcov profile files, focusing on coverage changes.

Usage:
  ./gcov-diff.py before.gcov after.gcov              # detailed mode
  ./gcov-diff.py --mode summary before.gcov after.gcov
  ./gcov-diff.py --mode lines before.gcov after.gcov
"""
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import sys
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import BinaryIO
from format import *

# ---- Data model ----


@dataclass(slots=True)
class FuncNode:
    """Node in a parsed gcov profile tree for diff comparison."""

    name: str
    source_file: str | None = None
    head_count: int = 0
    timestamp: int = 0
    positions: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    targets: dict[int, dict[tuple[str, str | None], int]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    _children: dict[tuple[int, str, str | None], "FuncNode"] = field(
        default_factory=dict, init=False, repr=False)

    def child(self, offset: int, name: str,
              source_file: str | None = None) -> "FuncNode":
        key = (offset, name, source_file)
        node = self._children.get(key)
        if node is None:
            node = FuncNode(name, source_file)
            self._children[key] = node
        return node

    @property
    def children(self) -> list["FuncNode"]:
        return list(self._children.values())

    def total_count(self) -> int:
        return sum(self.positions.values())


@dataclass
class FunctionDiff:
    """Diff of a matched pair of function instances."""
    name: str
    source_file: str | None
    head_count_a: int
    head_count_b: int
    timestamp_a: int
    timestamp_b: int
    at_offset: int = 0
    positions: dict[int, tuple[int | None, int | None]] = field(default_factory=dict)
    children: list["FunctionDiff"] = field(default_factory=list)


@dataclass
class DiffSummary:
    total_count_a: int = 0
    total_count_b: int = 0
    functions_in_a: int = 0
    functions_in_b: int = 0
    functions_common: int = 0
    functions_only_a: int = 0
    functions_only_b: int = 0
    newly_covered_positions: int = 0
    uncovered_positions: int = 0


@dataclass
class DiffResult:
    functions_only_a: list[FunctionDiff] = field(default_factory=list)
    functions_only_b: list[FunctionDiff] = field(default_factory=list)
    functions_common: list[FunctionDiff] = field(default_factory=list)
    summary: DiffSummary = field(default_factory=DiffSummary)


# ---- Error helpers ----


def _expect_tag(f: BinaryIO, path: str, expected: int, label: str) -> None:
    got = r32(f)
    if got != expected:
        sys.exit(f"error: {path}: expected {label} 0x{expected:08x}, got 0x{got:08x}")


def _skip_section(f: BinaryIO) -> None:
    length = r32(f)
    if length > 0:
        f.read(length)


# ---- Profile reading ----


def read_profile(path: str) -> tuple[dict[FuncKey, FuncNode], int, bytes]:
    """Read a gcov file and return (tree, version, raw_summary_bytes)."""
    try:
        f: BinaryIO = open(path, "rb")
    except FileNotFoundError:
        sys.exit(f"error: file not found: {path}")
    except OSError as e:
        sys.exit(f"error: cannot open {path}: {e}")

    summary_bytes = b""
    try:
        magic = r32(f)
        if magic != GCOV_DATA_MAGIC:
            sys.exit(f"error: {path}: bad magic 0x{magic:08x}, not a gcov file")
        version = r32(f)
        if version not in (2, 3):
            sys.exit(f"error: {path}: unsupported gcov version {version}")
        r32(f)  # reserved

        if version >= 3:
            summary_bytes = _read_summary(f, path)

        names, file_table = _read_name_table(f, version, path)
        tree = _read_function_section(f, names, file_table, version, path)
        _read_module_grouping(f, path)
        _read_working_set(f, path)
    except struct.error:
        sys.exit(f"error: {path}: truncated or corrupt gcov file")
    finally:
        f.close()

    return tree, version, summary_bytes


def _read_summary(f: BinaryIO, path: str) -> bytes:
    _expect_tag(f, path, GCOV_TAG_AFDO_SUMMARY, "AFDO summary tag")
    return read_summary_raw(f)


def _read_name_table(f: BinaryIO, version: int, path: str
                     ) -> tuple[list[tuple[str, int]], list[str]]:
    _expect_tag(f, path, GCOV_TAG_AFDO_FILE_NAMES, "file names tag")
    r32(f)  # length, skip

    file_table: list[str] = []
    if version >= 3:
        num_files = r32(f)
        for _ in range(num_files):
            file_table.append(rstring(f))

    names: list[tuple[str, int]] = []
    num_names = r32(f)
    for _ in range(num_names):
        name = rstring(f)
        file_index = r32(f) if version >= 3 else -1
        names.append((name, file_index))

    return names, file_table


def _read_function_section(
    f: BinaryIO, names: list[tuple[str, int]], file_table: list[str],
    version: int, path: str,
) -> dict[FuncKey, FuncNode]:
    _expect_tag(f, path, GCOV_TAG_AFDO_FUNCTION, "AFDO function tag")
    r32(f)  # length
    num_functions = r32(f)
    tree: dict[FuncKey, FuncNode] = {}
    for _ in range(num_functions):
        _read_function_instance(f, tree, names, file_table, version, path)
    return tree


def _read_function_instance(
    f: BinaryIO, tree: dict[FuncKey, FuncNode], names: list[tuple[str, int]],
    file_table: list[str], version: int, path: str,
    parent: FuncNode | None = None, callsite_offset: int = 0,
) -> None:
    is_toplevel = parent is None

    if is_toplevel:
        head_count = rcounter(f)
        timestamp = rcounter(f) if version >= 3 else 0
    else:
        head_count = 0
        timestamp = 0

    name_index = r32(f)
    if name_index < 0 or name_index >= len(names):
        sys.exit(f"error: {path}: invalid name index {name_index}")
    name = names[name_index][0]
    file_idx = names[name_index][1]
    source_file: str | None = None
    if 0 <= file_idx < len(file_table):
        source_file = file_table[file_idx]

    num_pos = r32(f)
    num_callsites = r32(f)

    if is_toplevel:
        key = (name, source_file)
        node = tree.get(key)
        if node is None:
            node = FuncNode(name, source_file, head_count, timestamp)
            tree[key] = node
        else:
            node.head_count += head_count
            if timestamp:
                node.timestamp = timestamp
    else:
        assert parent is not None
        node = parent.child(callsite_offset, name, source_file)

    for _ in range(num_pos):
        offset = r32(f)
        num_targets = r32(f)
        count = rcounter(f)
        node.positions[offset] += count
        for _ in range(num_targets):
            t = r32(f)
            if t != HIST_TYPE_INDIR_CALL_TOPN:
                sys.exit(f"error: {path}: expected HIST_TYPE_INDIR_CALL_TOPN, got {t}")
            target_idx = rcounter(f)
            target_name = names[target_idx][0]
            target_file_idx = names[target_idx][1]
            target_src: str | None = None
            if 0 <= target_file_idx < len(file_table):
                target_src = file_table[target_file_idx]
            target_count = rcounter(f)
            node.targets[offset][(target_name, target_src)] += target_count

    for _ in range(num_callsites):
        cs_offset = r32(f)
        _read_function_instance(f, tree, names, file_table, version, path,
                                parent=node, callsite_offset=cs_offset)


def _read_module_grouping(f: BinaryIO, path: str) -> None:
    tag = r32(f)
    if tag == GCOV_TAG_AFDO_MODULE_GROUPING:
        _skip_section(f)
    elif tag != 0:
        print(f"warning: {path}: unexpected tag 0x{tag:08x} where module grouping expected",
              file=sys.stderr)


def _read_working_set(f: BinaryIO, path: str) -> None:
    tag = r32(f)
    if tag == GCOV_TAG_AFDO_WORKING_SET:
        _skip_section(f)
    elif tag != 0:
        print(f"warning: {path}: unexpected tag 0x{tag:08x} where working set expected",
              file=sys.stderr)


# ---- Diff logic ----




def _sum_only_counts(node: FuncNode) -> int:
    """Sum counts in a function, including children."""
    total = node.total_count()
    for c in node.children:
        total += _sum_only_counts(c)
    return total


def _diff_positions(
    pos_a: dict[int, int], pos_b: dict[int, int],
) -> dict[int, tuple[int | None, int | None]]:
    """Diff two position dicts. Returns offset -> (count_a, count_b)."""
    all_offsets = set(pos_a) | set(pos_b)
    result: dict[int, tuple[int | None, int | None]] = {}
    for off in sorted(all_offsets):
        va = pos_a.get(off)
        vb = pos_b.get(off)
        result[off] = (va, vb)
    return result


def _diff_child_pairs(
    children_a: dict, children_b: dict,
    threshold: int, no_zeros: bool,
) -> tuple[list[FuncNode], list[FunctionDiff], list[FuncNode]]:
    """Diff two child dicts. Returns (only_a, common, only_b).

    Children are matched by (offset, name, source_file) key.
    """
    a_keys = set(children_a)
    b_keys = set(children_b)

    only_a = [children_a[k] for k in sorted(a_keys - b_keys, key=_child_key_sort)]
    only_b = [children_b[k] for k in sorted(b_keys - a_keys, key=_child_key_sort)]

    common: list[FunctionDiff] = []
    for key in sorted(a_keys & b_keys, key=_child_key_sort):
        ca = children_a[key]
        cb = children_b[key]
        common.append(_diff_nodes(ca, cb, threshold, no_zeros, at_offset=key[0]))

    return only_a, common, only_b


def _child_key_sort(key: tuple) -> tuple:
    """Sort key for child dict entries: (offset, name, source_file)."""
    return (key[0], key[1], key[2] or "")


def _diff_nodes(
    node_a: FuncNode, node_b: FuncNode,
    threshold: int, no_zeros: bool,
    at_offset: int = 0,
) -> FunctionDiff:
    """Diff two matched FuncNodes into a FunctionDiff."""
    fd = FunctionDiff(
        name=node_a.name,
        source_file=node_a.source_file,
        head_count_a=node_a.head_count,
        head_count_b=node_b.head_count,
        timestamp_a=node_a.timestamp,
        timestamp_b=node_b.timestamp,
        at_offset=at_offset,
        positions=_diff_positions(node_a.positions, node_b.positions),
    )

    # Diff children
    only_a_kids, common_kids, only_b_kids = _diff_child_pairs(
        node_a._children, node_b._children,
        threshold, no_zeros,
    )

    # Attach children from only_a/only_b as "pseudo-diffs" for unified display
    for ca in only_a_kids:
        fd.children.append(_funcnode_only_a(ca, threshold, no_zeros))
    fd.children.extend(common_kids)
    for cb in only_b_kids:
        fd.children.append(_funcnode_only_b(cb, threshold, no_zeros))

    # Apply filters
    fd.positions = {
        off: (va, vb)
        for off, (va, vb) in fd.positions.items()
        if _include_position(va, vb, threshold, no_zeros)
    }

    return fd


def _funcnode_only_a(node: FuncNode, threshold: int, no_zeros: bool,
                     at_offset: int = 0) -> FunctionDiff:
    """Wrap a FuncNode only present in A as a FunctionDiff for display."""
    positions: dict[int, tuple[int | None, int | None]] = {}
    for off, count in node.positions.items():
        if _include_position(count, None, threshold, no_zeros):
            positions[off] = (count, None)
    fd = FunctionDiff(
        name=node.name,
        source_file=node.source_file,
        head_count_a=node.head_count,
        head_count_b=0,
        timestamp_a=node.timestamp,
        timestamp_b=0,
        at_offset=at_offset,
        positions=positions,
    )
    for key, child in sorted(node._children.items(), key=lambda kv: _child_key_sort(kv[0])):
        fd.children.append(_funcnode_only_a(child, threshold, no_zeros, at_offset=key[0]))
    return fd


def _funcnode_only_b(node: FuncNode, threshold: int, no_zeros: bool,
                     at_offset: int = 0) -> FunctionDiff:
    """Wrap a FuncNode only present in B as a FunctionDiff for display."""
    positions: dict[int, tuple[int | None, int | None]] = {}
    for off, count in node.positions.items():
        if _include_position(None, count, threshold, no_zeros):
            positions[off] = (None, count)
    fd = FunctionDiff(
        name=node.name,
        source_file=node.source_file,
        head_count_a=0,
        head_count_b=node.head_count,
        timestamp_a=0,
        timestamp_b=node.timestamp,
        at_offset=at_offset,
        positions=positions,
    )
    for key, child in sorted(node._children.items(), key=lambda kv: _child_key_sort(kv[0])):
        fd.children.append(_funcnode_only_b(child, threshold, no_zeros, at_offset=key[0]))
    return fd


def _include_position(
    va: int | None, vb: int | None,
    threshold: int, no_zeros: bool,
) -> bool:
    """Determine whether a position should appear in diff output."""
    if va is None and vb is None:
        return False
    if no_zeros and (va is None or va == 0) and (vb is None or vb == 0):
        return False
    if va is None or vb is None:
        # New or lost coverage — always show (unless suppressed by no_zeros above)
        return True
    if abs(vb - va) <= threshold:
        return False
    return True


def diff_trees(tree_a: dict[FuncKey, FuncNode],
               tree_b: dict[FuncKey, FuncNode],
               threshold: int = 0, no_zeros: bool = False) -> DiffResult:
    """Diff two parsed gcov trees. Returns a DiffResult."""
    keys_a = set(tree_a)
    keys_b = set(tree_b)

    result = DiffResult()

    # Functions only in A — wrap through filter to apply threshold/no_zeros
    for key in sorted(keys_a - keys_b, key=_key_sort):
        fd = _funcnode_only_a(tree_a[key], threshold, no_zeros)
        result.functions_only_a.append(fd)

    # Functions only in B
    for key in sorted(keys_b - keys_a, key=_key_sort):
        fd = _funcnode_only_b(tree_b[key], threshold, no_zeros)
        result.functions_only_b.append(fd)

    # Common functions
    for key in sorted(keys_a & keys_b, key=_key_sort):
        fd = _diff_nodes(tree_a[key], tree_b[key], threshold, no_zeros)
        result.functions_common.append(fd)

    # Compute summary
    result.summary = _compute_summary(tree_a, tree_b, result)
    return result


def _key_sort(key: FuncKey) -> tuple:
    return (key[0], key[1] or "")


def _compute_summary(
    tree_a: dict[FuncKey, FuncNode],
    tree_b: dict[FuncKey, FuncNode],
    result: DiffResult,
) -> DiffSummary:
    s = DiffSummary()
    s.functions_in_a = len(tree_a)
    s.functions_in_b = len(tree_b)
    s.functions_common = len(result.functions_common)
    s.functions_only_a = len(result.functions_only_a)
    s.functions_only_b = len(result.functions_only_b)

    s.total_count_a = sum(_sum_only_counts(n) for n in tree_a.values())
    s.total_count_b = sum(_sum_only_counts(n) for n in tree_b.values())

    # Count newly covered / uncovered across all common function positions
    _count_coverage_changes(result.functions_common, s)

    return s


def _count_coverage_changes(common: list[FunctionDiff], s: DiffSummary) -> None:
    """Tally newly-covered and uncovered positions recursively."""
    for fd in common:
        for va, vb in fd.positions.values():
            if (va is None or va == 0) and (vb is not None and vb > 0):
                s.newly_covered_positions += 1
            elif (va is not None and va > 0) and (vb is None or vb == 0):
                s.uncovered_positions += 1
        _count_coverage_changes(fd.children, s)


# ---- Rendering ----


def _pct_str(delta: int, base: int) -> str:
    """Format a percentage string from delta and base."""
    if base == 0:
        if delta > 0:
            return "+inf%"
        elif delta < 0:
            return "-inf%"
        else:
            return "0.0%"
    return f"{delta / base * 100:+.1f}%"


def _fmt_count_delta(va: int | None, vb: int | None,
                     show_pct: bool, show_abs: bool) -> str:
    """Format a count delta for one position."""
    if va is None:
        return f"+{vb}  (new)"
    if vb is None:
        return f"{va} -> 0  (lost)"

    delta = vb - va
    parts = []
    if show_abs:
        parts.append(f"{delta:+d}")
    if show_pct:
        parts.append(_pct_str(delta, va))
    if len(parts) == 2:
        suffix = f" ({parts[0]}, {parts[1]})"
    elif parts:
        suffix = f" ({parts[0]})"
    else:
        suffix = ""
    return f"{va} -> {vb}{suffix}"




def _render_summary_header(result: DiffResult, file_a: str, file_b: str,
                           ver_a: int, ver_b: int) -> None:
    s = result.summary
    print(f"File A: {file_a} (v{ver_a}, {s.functions_in_a} functions, total {s.total_count_a} counts)")
    print(f"File B: {file_b} (v{ver_b}, {s.functions_in_b} functions, total {s.total_count_b} counts)")
    print(f"Functions: {s.functions_common} common, {s.functions_only_a} only in A, {s.functions_only_b} only in B")
    if s.total_count_a > 0:
        delta = s.total_count_b - s.total_count_a
        print(f"Coverage delta: {delta:+d} counts ({_pct_str(delta, s.total_count_a)})")
    else:
        print(f"Coverage delta: {s.total_count_b} counts (new)")
    print(f"Lines newly covered: {s.newly_covered_positions}")
    print(f"Lines uncovered: {s.uncovered_positions}")


def _render_detailed(
    result: DiffResult, file_a: str, file_b: str,
    ver_a: int, ver_b: int, show_pct: bool, show_abs: bool,
    quiet: bool,
) -> None:
    print("=== gcov-diff detailed ===")
    if not quiet:
        _render_summary_header(result, file_a, file_b, ver_a, ver_b)
        print()

    # Functions only in A
    print("Functions only in A:")
    if not result.functions_only_a:
        print("  (none)")
    else:
        for node in result.functions_only_a:
            _render_only_function(node, show_pct, show_abs, side="A")
    print()

    # Functions only in B
    print("Functions only in B:")
    if not result.functions_only_b:
        print("  (none)")
    else:
        for node in result.functions_only_b:
            _render_only_function(node, show_pct, show_abs, side="B")
    print()

    # Common functions
    print("Common functions:")
    if not result.functions_common:
        print("  (none)")
    else:
        for fd in result.functions_common:
            _render_common_function(fd, show_pct, show_abs, indent="")


def _render_only_function(fd: FunctionDiff, show_pct: bool, show_abs: bool,
                          side: str) -> None:
    """Render a function present only in one side."""
    label = f"{fd.name}:{fd.source_file or '?'}"
    parts = [f"head={fd.head_count_a if side == 'A' else fd.head_count_b}"]
    ts = fd.timestamp_a if side == 'A' else fd.timestamp_b
    if ts:
        parts.append(f"ts={ts}")
    print(f"  {label}: {', '.join(parts)}")
    for off in sorted(fd.positions):
        va, vb = fd.positions[off]
        print(f"    {fmt_offset(off)}: {_fmt_count_delta(va, vb, show_pct, show_abs)}")
    for child in fd.children:
        _render_common_function(child, show_pct, show_abs, indent="  ", prefix="inlined ")


def _render_common_function(fd: FunctionDiff, show_pct: bool, show_abs: bool,
                            indent: str = "", prefix: str = "") -> None:
    """Render a common (matched) function diff."""
    label = f"{fd.name}:{fd.source_file or '?'}"
    head_str = _fmt_count_delta(fd.head_count_a, fd.head_count_b, show_pct, show_abs)
    if fd.at_offset and prefix:
        print(f"{indent}{prefix}{label} at offset {fd.at_offset}:")
    elif prefix:
        print(f"{indent}{prefix}{label}:")
    else:
        print(f"{indent}{label}")
        print(f"{indent}  head: {head_str}")

    for off in sorted(fd.positions):
        va, vb = fd.positions[off]
        line = _fmt_count_delta(va, vb, show_pct, show_abs)
        print(f"{indent}  {fmt_offset(off)}: {line}")

    for child in fd.children:
        _render_common_function(child, show_pct, show_abs, indent + "  ", prefix="inlined ")


def _render_lines(result: DiffResult, show_pct: bool, show_abs: bool) -> None:
    """Machine-parseable lines output."""
    for fd in result.functions_common:
        _render_lines_function(fd, show_pct, show_abs, prefix="+")


def _render_lines_function(fd: FunctionDiff, show_pct: bool, show_abs: bool,
                           prefix: str = "+") -> None:
    label = f"{fd.name}:{fd.source_file or '?'}"
    for off in sorted(fd.positions):
        va, vb = fd.positions[off]
        va_str = str(va) if va is not None else ""
        vb_str = str(vb) if vb is not None else ""
        print(f"+ {label} {fmt_offset(off)} {va_str} {vb_str}")
    for child in fd.children:
        _render_lines_function(child, show_pct, show_abs, prefix=prefix)


# ---- CLI ----


def main() -> None:
    ap = argparse.ArgumentParser(description="Diff two gcov profile files.")
    ap.add_argument('file_a', help="First gcov file (baseline)")
    ap.add_argument('file_b', help="Second gcov file (comparison)")
    ap.add_argument('--mode', choices=['summary', 'detailed', 'lines'],
                    default='detailed')
    ap.add_argument('--threshold', type=int, default=0,
                    help="Ignore changes with count diff <= N (default 0)")
    ap.add_argument('--no-zeros', action='store_true',
                    help="Suppress zero-count positions (scaffolding)")
    ap.add_argument('--relative', action='store_true',
                    help="Show only percentage changes (default: absolute + relative)")
    ap.add_argument('--quiet', action='store_true',
                    help="Suppress summary header in detailed mode")
    args = ap.parse_args()

    show_pct = True
    show_abs = not args.relative
    if args.relative:
        show_abs = False

    tree_a, ver_a, _ = read_profile(args.file_a)
    tree_b, ver_b, _ = read_profile(args.file_b)

    if ver_a != ver_b:
        print(f"warning: file versions differ ({ver_a} vs {ver_b})",
              file=sys.stderr)

    result = diff_trees(tree_a, tree_b,
                        threshold=args.threshold,
                        no_zeros=args.no_zeros)

    if args.mode == 'summary':
        _render_summary_header(result, args.file_a, args.file_b, ver_a, ver_b)
    elif args.mode == 'detailed':
        _render_detailed(result, args.file_a, args.file_b, ver_a, ver_b,
                         show_pct, show_abs, args.quiet)
    elif args.mode == 'lines':
        _render_lines(result, show_pct, show_abs)


if __name__ == '__main__':
    main()
