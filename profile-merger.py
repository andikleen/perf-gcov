#!/usr/bin/env python3
# Merge multiple gcov profile files by summing counts
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import copy
import argparse
from collections import Counter, defaultdict
from typing import BinaryIO
from format import *
import suffix

class FuncNode:
    """A node in the profile tree, matching GCOV_TAG_AFDO_FUNCTION layout."""

    __slots__ = ("name", "source_file", "positions", "targets",
                 "children", "head_count", "total_count", "timestamp")

    def __init__(self, name: str, source_file: str | None = None,
                 head_count: int = 0, timestamp: int = 0):
        self.name = name
        self.source_file = source_file
        self.positions: Counter[int] = Counter()
        self.targets: dict[int, Counter[str]] = defaultdict(Counter)
        self.children: dict[tuple[int, str], "FuncNode"] = {}
        self.head_count = head_count
        self.total_count = 0
        self.timestamp = timestamp

    def child(self, offset: int, name: str,
              source_file: str | None = None) -> "FuncNode":
        key = (offset, name)
        node = self.children.get(key)
        if node is None:
            node = FuncNode(name, source_file)
            self.children[key] = node
        elif source_file and not node.source_file:
            node.source_file = source_file
        return node

    def has_output(self, threshold: int) -> bool:
        if filtered_positions(self, threshold):
            return True
        return any(c.has_output(threshold) for c in self.children.values())

def _expect_tag(f: BinaryIO, path: str, expected: int, label: str) -> None:
    got = r32(f)
    if got != expected:
        sys.exit(f"error: {path}: expected {label} 0x{expected:08x}, got 0x{got:08x}")


def _skip_section(f: BinaryIO) -> None:
    length = r32(f)
    if length > 0:
        f.read(length)

def read_profile(path: str) -> tuple[dict[str, FuncNode], int]:
    """Read a gcov file and return (tree, version)."""
    try:
        f: BinaryIO = open(path, "rb")
    except FileNotFoundError:
        sys.exit(f"error: file not found: {path}")
    except OSError as e:
        sys.exit(f"error: cannot open {path}: {e}")

    try:
        magic = r32(f)
        if magic != GCOV_DATA_MAGIC:
            sys.exit(f"error: {path}: bad magic 0x{magic:08x}, not a gcov file")
        version = r32(f)
        if version not in (2, 3):
            sys.exit(f"error: {path}: unsupported gcov version {version}")
        r32(f)  # reserved

        if version >= 3:
            _read_summary(f, path)

        names, file_table = _read_name_table(f, version, path)
        tree = _read_function_section(f, names, file_table, version, path)
        _read_module_grouping(f, path)
        _read_working_set(f, path)
    finally:
        f.close()

    return tree, version

def _read_summary(f: BinaryIO, path: str) -> None:
    _expect_tag(f, path, GCOV_TAG_AFDO_SUMMARY, "AFDO summary tag")
    rcounter(f)  # total_count
    rcounter(f)  # max_count
    rcounter(f)  # max_function_count
    rcounter(f)  # num_counts
    rcounter(f)  # num_functions
    num = rcounter(f)
    for _ in range(num):
        r32(f)      # cutoff
        rcounter(f)  # min_count
        rcounter(f)  # num_counts

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

def _read_function_section(f: BinaryIO, names, file_table, version, path):
    _expect_tag(f, path, GCOV_TAG_AFDO_FUNCTION, "AFDO function tag")
    r32(f)  # length
    num_functions = r32(f)
    tree: dict[str, FuncNode] = {}
    for _ in range(num_functions):
        _read_function_instance(f, tree, names, file_table, version, path)
    return tree

def _read_function_instance(f: BinaryIO, tree, names, file_table, version, path,
                            parent=None, callsite_offset=0):
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
    source_file = file_table[file_idx] if 0 <= file_idx < len(file_table) else None

    num_pos = r32(f)
    num_callsites = r32(f)

    if is_toplevel:
        node = tree.get(name)
        if node is None:
            node = FuncNode(name, source_file, head_count, timestamp)
            tree[name] = node
        else:
            node.head_count += head_count
            if timestamp:
                node.timestamp = timestamp
            if source_file and not node.source_file:
                node.source_file = source_file
    else:
        node = parent.child(callsite_offset, name, source_file)

    for _ in range(num_pos):
        offset = r32(f)
        num_targets = r32(f)
        count = rcounter(f)
        node.positions[offset] += count
        node.total_count += count
        for _ in range(num_targets):
            t = r32(f)
            if t != HIST_TYPE_INDIR_CALL_TOPN:
                sys.exit(f"error: {path}: expected HIST_TYPE_INDIR_CALL_TOPN, got {t}")
            target_name = names[rcounter(f)][0]
            target_count = rcounter(f)
            node.targets[offset][target_name] += target_count

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

def merge_profiles(dest: dict[str, FuncNode],
                   src: dict[str, FuncNode]) -> None:
    """Merge src tree into dest tree. Sums counts (AFDO merge semantics)."""
    for name, src_node in src.items():
        dest_node = dest.get(name)
        if dest_node is None:
            dest[name] = copy.deepcopy(src_node)
        else:
            _merge_node(dest_node, src_node)

def _merge_node(dest: FuncNode, src: FuncNode) -> None:
    dest.head_count += src.head_count
    dest.total_count += src.total_count
    if src.source_file and not dest.source_file:
        dest.source_file = src.source_file
    merge_nodes(dest, src)

def filtered_positions(node: FuncNode,
                        threshold: int) -> list[tuple[int, int, Counter[str]]]:
    result = []
    for off in sorted(node.positions):
        count = node.positions[off]
        targets = Counter({name: c for name, c
                           in node.targets.get(off, Counter()).items()
                           if c >= threshold})
        if count > 0 and count < threshold:
            continue
        result.append((off, count, targets))
    return result

def emitted_children(node: FuncNode, threshold: int
                      ) -> list[tuple[int, str, FuncNode]]:
    return [(coff, cname, child)
            for (coff, cname), child in sorted(node.children.items())
            if child.has_output(threshold)]


def collect_strings(node: FuncNode, out: set[str], threshold: int) -> None:
    out.add(node.name)
    for _, _, targets in filtered_positions(node, threshold):
        out.update(targets.keys())
    for _, _, child in emitted_children(node, threshold):
        collect_strings(child, out, threshold)

def collect_strings_v3(node: FuncNode, func_names: set[str],
                        files: set[str],
                        func_to_file: dict[str, str | None],
                        tree: dict[str, FuncNode], threshold: int) -> None:
    func_names.add(node.name)
    if node.source_file:
        files.add(node.source_file)
        if node.name not in func_to_file:
            func_to_file[node.name] = node.source_file

    for _, _, targets in filtered_positions(node, threshold):
        func_names.update(targets.keys())
        for target_name in targets.keys():
            if target_name not in func_to_file:
                tgt_node = tree.get(target_name)
                if tgt_node and tgt_node.source_file:
                    func_to_file[target_name] = tgt_node.source_file
                else:
                    func_to_file[target_name] = None

    for _, _, child in emitted_children(node, threshold):
        collect_strings_v3(child, func_names, files, func_to_file, tree,
                           threshold)

def wfunc_node(f: BinaryIO, node: FuncNode, offset: int,
               string_index: dict[str, int], toplevel: bool,
               gcov_version: int, threshold: int) -> None:
    if toplevel:
        wcounter(f, node.head_count)
        if gcov_version >= 3:
            wcounter(f, node.timestamp)
        w32(f, string_index[node.name])
    else:
        w32(f, offset)
        w32(f, string_index[node.name])

    positions = filtered_positions(node, threshold)
    children = emitted_children(node, threshold)

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
        wfunc_node(f, child, coff, string_index, False,
                   gcov_version, threshold)

def gen_strtable(tree: dict[str, FuncNode],
                 threshold: int) -> tuple[list[str], dict[str, int]]:
    strings: set[str] = set()
    for node in tree.values():
        collect_strings(node, strings, threshold)
    string_table = [""] + sorted(strings)
    string_index = {name: i for i, name in enumerate(string_table)}
    return string_table, string_index


def gen_strtable_v3(tree: dict[str, FuncNode], threshold: int):
    source_files: set[str] = set()
    function_names: set[str] = set()
    func_to_file: dict[str, str | None] = {}

    for name, node in tree.items():
        if node.source_file:
            source_files.add(node.source_file)
            func_to_file[name] = node.source_file
        collect_strings_v3(node, function_names, source_files,
                           func_to_file, tree, threshold)

    file_table = sorted(source_files)
    file_index = {fname: i for i, fname in enumerate(file_table)}

    func_file_map: dict[str, int] = {}
    for func_name, src_file in func_to_file.items():
        if src_file and src_file in file_index:
            func_file_map[func_name] = file_index[src_file]
        else:
            func_file_map[func_name] = -1

    string_table = [""] + sorted(function_names)
    string_index = {name: i for i, name in enumerate(string_table)}

    return file_table, file_index, func_file_map, string_table, string_index

def compute_summary(tree: dict[str, FuncNode]) -> dict:
    total_count = 0
    max_count = 0
    max_function_count = 0
    num_counts = 0
    num_functions = len(tree)
    count_frequencies: dict[int, int] = {}

    def traverse_node(node: FuncNode, is_root: bool = False) -> None:
        nonlocal total_count, max_count, max_function_count, num_counts

        if is_root and 0 in node.positions:
            func_head_count = node.positions[0]
            max_function_count = max(max_function_count, func_head_count)

        for offset, count in node.positions.items():
            if count > 0:
                total_count += count
                max_count = max(max_count, count)
                num_counts += 1
                count_frequencies[count] = count_frequencies.get(count, 0) + 1

        for (call_offset, callee_name), child in node.children.items():
            traverse_node(child, is_root=False)

    for func_node in tree.values():
        traverse_node(func_node, is_root=True)

    detailed_summaries = []
    if total_count > 0 and count_frequencies:
        sorted_counts = sorted(count_frequencies.items(),
                                key=lambda x: x[0], reverse=True)
        cumulative_sum = 0
        cumulative_samples = 0
        idx = 0

        for cutoff in DEFAULT_CUTOFFS:
            threshold = (total_count * cutoff) // 1_000_000
            last_count = 0

            while cumulative_sum < threshold and idx < len(sorted_counts):
                count_val, freq = sorted_counts[idx]
                cumulative_sum += count_val * freq
                cumulative_samples += freq
                last_count = count_val
                idx += 1

            detailed_summaries.append({
                'cutoff': cutoff,
                'min_count': last_count,
                'num_counts': cumulative_samples,
            })
    else:
        detailed_summaries = [
            {'cutoff': cutoff, 'min_count': 0, 'num_counts': 0}
            for cutoff in DEFAULT_CUTOFFS
        ]

    return {
        'total_count': total_count,
        'max_count': max_count,
        'max_function_count': max_function_count,
        'num_counts': num_counts,
        'num_functions': num_functions,
        'detailed_summaries': detailed_summaries,
    }

def write_summary(f: BinaryIO, summary: dict) -> None:
    w32(f, GCOV_TAG_AFDO_SUMMARY)
    wcounter(f, summary['total_count'])
    wcounter(f, summary['max_count'])
    wcounter(f, summary['max_function_count'])
    wcounter(f, summary['num_counts'])
    wcounter(f, summary['num_functions'])
    wcounter(f, len(summary['detailed_summaries']))

    for ds in summary['detailed_summaries']:
        w32(f, ds['cutoff'])
        wcounter(f, ds['min_count'])
        wcounter(f, ds['num_counts'])

def write_profile(path: str, tree: dict[str, FuncNode],
                  gcov_version: int, threshold: int) -> None:
    if not tree:
        sys.exit(f"error: no functions to write (empty tree)")

    with open(path, "wb") as f:
        w32(f, GCOV_DATA_MAGIC)
        w32(f, gcov_version)
        w32(f, 0)

        if gcov_version >= 3:
            summary = compute_summary(tree)
            write_summary(f, summary)

        w32(f, GCOV_TAG_AFDO_FILE_NAMES)

        if gcov_version == 2:
            string_table, string_index = gen_strtable(tree, threshold)
            length = 4 + sum(len(s) + 5 for s in string_table)
            w32(f, length)
            w32(f, len(string_table))
            for fn in string_table:
                wstring(f, fn)
        else:
            ft, fi, fmap, st, string_index = gen_strtable_v3(tree, threshold)
            length = 4
            length += sum(len(fname) + 5 for fname in ft)
            length += 4
            length += sum(len(func) + 5 + 4 for func in st)
            w32(f, length)

            w32(f, len(ft))
            for fname in ft:
                wstring(f, fname)

            w32(f, len(st))
            for func_name in st:
                wstring(f, func_name)
                file_idx = fmap.get(func_name, -1)
                w32(f, file_idx if file_idx >= 0 else 0xFFFFFFFF)

        w32(f, GCOV_TAG_AFDO_FUNCTION)
        lenoff = f.tell()
        w32(f, 0)
        w32(f, len(tree))
        for name in sorted(tree):
            wfunc_node(f, tree[name], 0, string_index, True,
                       gcov_version, threshold)
        endoff = f.tell()
        f.seek(lenoff)
        w32(f, endoff - lenoff)
        f.seek(endoff)

        write_gcov_tail(f)

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Merge multiple gcov profile files")
    ap.add_argument('input_files', nargs='+',
                    help="Input gcov profile files")
    ap.add_argument('--output', '-o', default='merged.gcov',
                    help="Output gcov file (default: merged.gcov)")
    ap.add_argument('--gcov-version', '--gcov_version',
                    type=int, choices=[2, 3], default=3,
                    help="Output gcov version (default: 3)")
    ap.add_argument('--threshold', type=int, default=10,
                    help="Min samples for a position to be emitted (default: 10)")
    ap.add_argument('--suffix-elision', choices=suffix.ELIDE_POLICIES,
                    default='all',
                    help="Suffix elision policy (default: %(default)s)")
    args = ap.parse_args()

    if len(args.input_files) < 1:
        sys.exit("error: need at least one input file")

    versions = set()
    trees: list[tuple[str, dict[str, FuncNode]]] = []
    for path in args.input_files:
        tree, ver = read_profile(path)
        versions.add(ver)
        trees.append((path, tree))

    if len(versions) > 1:
        print(f"warning: mixed input versions {sorted(versions)}", file=sys.stderr)

    dest = trees[0][1]
    for src_path, src_tree in trees[1:]:
        merge_profiles(dest, src_tree)

    suffix.elide_tree_suffixes(dest, args.suffix_elision)
    write_profile(args.output, dest, args.gcov_version, args.threshold)
    print(f"Merged {len(trees)} profiles, {len(dest)} functions -> {args.output}")


if __name__ == '__main__':
    main()
