#!/usr/bin/env python3
# Generate gcc gcov profile files from perf record -b
# gcc -O2 -o workload ...
# perf record -b -c 100003 -e branches:upp workload
# gcov.py --binary workload file.gcov
# gcc -fauto-profile=file.gcov -o workload.opt -O2 ...
#
# SPDX-License-Identifier: GPL-3.0-or-later

# the code is written in typed python using mypy,
# please run make typecheck to verify after changes

# open:
# handle non unique symbols using dwarf (same file)
# check buildid
# output multiple gcovs
# support online mode
# implement suffix elision policy for .

import os
import sys
from collections import Counter, defaultdict
import struct
from typing import BinaryIO, NamedTuple, Final, Any
import argparse
import itertools
import os.path
import subprocess
import pathlib
import backtrace

ppath = os.getenv('PERF_EXEC_PATH')
if ppath is None:
    perf = os.getenv('PERF')
    if perf is None:
        perf = "perf"
    if len(sys.argv) == 1:
        sys.exit("Usage: gcov.py --gcov gcovfile --profile perf.data --binary elfbinary")
    data = "perf.data"
    if "--profile" in sys.argv:
        i = sys.argv.index("--profile")
        if i + 1 < len(sys.argv):
            del sys.argv[i]
            data = sys.argv[i]
            del sys.argv[i]
    pargs = [perf, "script", "-i", data, sys.argv[0]] + sys.argv[1:]
    sys.exit(subprocess.run(pargs).returncode)

sys.path.append(ppath + '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

try:
    from perf_trace_context import perf_script_context # type: ignore
except ImportError:
    sys.exit("Cannot find perf python modules")

ap = argparse.ArgumentParser()
ap.add_argument('output', default="file.gcov", nargs='?', help="Output gcov file. Default file.gcov")
ap.add_argument('--binary', help="Generate gcov file for binary", required=True)
ap.add_argument('--profile', '-i', help="Profile data. Default perf.data") # handled by perf
ap.add_argument('--gcov', help="gcov output file")
ap.add_argument('--profiler', help="set profiler type", choices=["perf"]) # for create_gcov compatibility. nop.
ap.add_argument('--threshold', default=10, type=int, help="Min number of samples for location to output")
ap.add_argument('--verbose', action='store_true', help="Print every sample")
ap.add_argument('--top', default=0, type=int, help="Print N top samples")
ap.add_argument('--dump-dwarf', action='store_true', help="Dump dwarf symbol table")
ap.add_argument('--gcov-version', '--gcov_version', type=int, choices=[2, 3], default=3,
                help="GCOV version: 2 (function names only) or 3 (with source files, default)")
ap.add_argument('--strip-dup-backedge-stride-limit', type=int, default=4096,
                help="Skip duplicate top LBR entry if from-to stride exceeds this. Default 4096")
ap.add_argument('--insn-range-max', type=int, default=1<<20, help="Max range between branches to probe")
args = ap.parse_args()

if args.binary is None:
    sys.exit("Need --binary")

btstate = backtrace.createstate(args.binary)
# XXX which exception to catch?

def trace_begin():
    pass

GCOV_TAG_AFDO_SUMMARY = 0xa8000000
GCOV_TAG_AFDO_FILE_NAMES = 0xaa000000
GCOV_TAG_AFDO_FUNCTION = 0xac000000
GCOV_TAG_AFDO_MODULE_GROUPING = 0xae000000
GCOV_TAG_AFDO_WORKING_SET = 0xaf000000
GCOV_DATA_MAGIC = 0x67636461 # 'gcda'
GCOV_VERSION = 2
HIST_TYPE_INDIR_CALL_TOPN = 7

# One frame of an inline stack as returned by libbacktrace pcinfo.
Frame = NamedTuple('Frame', [('file', str | None),
                             ('line', int),
                             ('disc', int),
                             ('sym', str | None),
                             ('declline', int)])

class Stats:
    def __init__(self):
        self.ignored = 0
        self.errored = 0
        self.crossed = 0
        self.total = 0
        self.raw_ignored_branches = 0
        self.raw_total_branches = 0
        self.output_total_positions = 0
        self.output_ignored_positions = 0
        self.output_branches = 0
        # outermost function name -> profile tree root
        self.tree : dict[str, "FuncNode"] = dict()
        # Range-based profile data (LBR-derived ranges)
        # (begin_addr, end_addr) -> count
        self.range_counts: Counter[tuple[int, int]] = Counter()
        # (from_addr, to_addr) -> count
        self.branch_counts: Counter[tuple[int, int]] = Counter()

        # Error/skip counters for diagnostics
        self.dwarf_lookup_failures = 0  # Addresses with no DWARF info
        self.missing_symbols = 0         # Frames with no symbol name
        self.incomplete_stacks = 0       # Incomplete inline stacks

    def root(self, name: str, source_file: str | None = None) -> "FuncNode":
        node = self.tree.get(name)
        if node is None:
            node = FuncNode(name, source_file)
            self.tree[name] = node
        elif source_file and not node.source_file:
            node.source_file = source_file
        return node

stats = Stats()

# Frame cache: addr -> frames | None
# Amortizes cost of repeated getframes() calls during range expansion
_frame_cache: dict[int, list[Frame] | None] = {}

def getframes_cached(ip: int) -> list[Frame] | None:
    """Cached version of getframes for efficient range expansion."""
    if ip not in _frame_cache:
        _frame_cache[ip] = getframes(ip)
    return _frame_cache[ip]

def clear_frame_cache():
    """Clear the frame cache.

    Call this if:
    - Processing multiple binaries in one run
    - Binary file changes during execution
    - Need to free memory after processing large profile
    """
    global _frame_cache
    _frame_cache.clear()

def get_frame_cache_stats() -> dict[str, int]:
    """Get frame cache statistics.

    Returns:
        dict with 'size' (number of entries) and 'memory' (estimated bytes)
    """
    return {
        'size': len(_frame_cache),
        # Rough estimate: each Frame ~48 bytes, plus overhead
        'memory': sum(len(frames) * 48 if frames else 0
                     for frames in _frame_cache.values())
    }

def w32(f: BinaryIO, v: int):
    try:
        f.write(struct.pack("I", v))
    except struct.error:
        sys.exit("bad value for w32 %x" % v)

def wstring(f: BinaryIO, s: str):
    s += "\0"
    w32(f, len(s))
    f.write(struct.pack("%ds" % len(s), s.encode('utf-8')))

def wcounter(f: BinaryIO, v: int):
    w32(f, (v       ) & 0xffffffff)
    w32(f, (v >> 32 ) & 0xffffffff)

def gen_offset(line: int, disc: int) -> int:
    """Generate 64-bit offset from line number and discriminator.

    Format: bits [63:16] = line, bits [15:0] = discriminator

    Args:
        line: Relative line number (0-65535)
        disc: Discriminator value (0-65535)

    Returns:
        32-bit offset value (line << 16 | disc)

    Raises:
        ValueError: If line or disc out of valid range
    """
    if not (0 <= line <= 0xFFFF):
        raise ValueError(f"Line {line} out of range [0, 65535]")
    if not (0 <= disc <= 0xFFFF):
        raise ValueError(f"Discriminator {disc} out of range [0, 65535]")
    return (line << 16) | disc

class FuncNode:
    """A node in the profile tree.

    Each node corresponds to one (possibly inlined) function instance.
    Inlined callees are stored as child nodes keyed by the call offset in
    this function and the callee name, mirroring gcc's nested
    GCOV_TAG_AFDO_FUNCTION layout"""
    __slots__ = ("name", "source_file", "positions", "targets", "children", "structural_zeros")

    def __init__(self, name: str, source_file: str | None = None):
        self.name = name
        self.source_file = source_file  # basename from DWARF
        # offset -> sample count for positions directly in this instance
        self.positions: Counter[int] = Counter()
        # offset -> {callee name -> count} for resolved call targets
        self.targets: dict[int, Counter[str]] = defaultdict(Counter)
        # (offset, callee name) -> child node for inlined callees
        self.children: dict[tuple[int, str], FuncNode] = dict()
        # Offsets that must be emitted even with count=0 and no targets.
        # These mark scaffolding positions (function entry/exit boundaries).
        # NOTE: This is runtime-only state used during tree construction;
        # it is not directly persisted to the GCOV file format.
        self.structural_zeros: set[int] = set()

    def child(self, offset: int, name: str, source_file: str | None = None) -> "FuncNode":
        key = (offset, name)
        node = self.children.get(key)
        if node is None:
            node = FuncNode(name, source_file)
            self.children[key] = node
        elif source_file and not node.source_file:
            node.source_file = source_file
        return node

    def head_count(self) -> int:
        # Emit 0 for head count; GCC computes effective entry count from max(positions)
        return 0

    def has_output(self) -> bool:
        if filtered_positions(self):
            return True
        return any(child.has_output() for child in self.children.values())

def add_path(root: FuncNode, path: list[tuple[str, int]], offset: int,
             count: int, target: str | None, inline_source_files: list[str | None] | None = None) -> None:
    """Accumulate COUNT into the tree.

    PATH is the inline call chain from the outermost real function down to
    (but excluding) the innermost frame, as (function name, call offset)
    pairs. OFFSET is the position offset within the innermost frame and
    TARGET, if set, is a call target recorded at that position.
    inline_source_files are the source files for each inline frame in path."""
    node = root
    for i, (name, off) in enumerate(path):
        src_file = inline_source_files[i] if inline_source_files and i < len(inline_source_files) else None
        node = node.child(off, name, src_file)
    node.positions[offset] += count
    if target is not None:
        node.targets[offset][target] += count

def filtered_positions(node: FuncNode) -> list[tuple[int, int, Counter[str]]]:
    positions = []
    for off in sorted(node.positions):
        count = node.positions[off]
        targets = Counter({name: target_count
                           for name, target_count in node.targets.get(off, Counter()).items()
                           if target_count >= args.threshold})

        if count == 0:
            # Emit zero-count positions if they are structural or have targets
            if off not in node.structural_zeros and not targets:
                continue
        elif count < args.threshold:
            continue

        positions.append((off, count, targets))
    return positions

def emitted_children(node: FuncNode) -> list[tuple[int, str, FuncNode]]:
    return [(coff, cname, child)
            for (coff, cname), child in sorted(node.children.items())
            if child.has_output()]

def collect_strings(node: FuncNode, out: set[str]) -> None:
    out.add(node.name)
    for _, _, targets in filtered_positions(node):
        out.update(targets.keys())
    for _, _, child in emitted_children(node):
        collect_strings(child, out)

def wfunc_node(f: BinaryIO, node: FuncNode, offset: int,
               string_index: dict[str, int], toplevel: bool) -> None:
    if toplevel:
        wcounter(f, node.head_count())
        w32(f, string_index[node.name])
    else:
        w32(f, offset)
        w32(f, string_index[node.name])
    positions = filtered_positions(node)
    children = emitted_children(node)

    # number of positions and number of inlined callees
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
        wfunc_node(f, child, coff, string_index, False)

def gen_strtable(stats: Stats):
    strings: set[str] = set()
    for node in stats.tree.values():
        collect_strings(node, strings)
    string_table = sorted(strings)
    string_index = { name: i for i, name in enumerate(string_table) }
    return string_table, string_index

def gen_strtable_v3(stats: Stats):
    """Generate string table for GCOV v3 format with file names.

    Returns:
        file_table: list[str] - sorted unique source filenames
        file_index: dict[str, int] - filename → index mapping
        func_file_map: dict[str, int] - function name → file index mapping
        string_table: list[str] - sorted unique function/target names
        string_index: dict[str, int] - string → index mapping
    """
    source_files: set[str] = set()
    function_names: set[str] = set()
    func_to_file: dict[str, str | None] = {}

    # Collect from tree roots
    for name, node in stats.tree.items():
        if node.source_file:
            source_files.add(node.source_file)
            func_to_file[name] = node.source_file
        collect_strings_v3(node, function_names, source_files, func_to_file)

    # Build file table and index
    file_table = sorted(source_files)
    file_index = {fname: i for i, fname in enumerate(file_table)}

    # Build function → file_index mapping
    func_file_map = {}
    for func_name, src_file in func_to_file.items():
        if src_file and src_file in file_index:
            func_file_map[func_name] = file_index[src_file]
        else:
            func_file_map[func_name] = -1  # No file info

    # Build string table
    string_table = sorted(function_names)
    string_index = {name: i for i, name in enumerate(string_table)}

    return file_table, file_index, func_file_map, string_table, string_index

def compute_summary(stats: Stats) -> dict:
    """Compute profile summary statistics for GCOV_TAG_AFDO_SUMMARY.

    Traverses the profile tree and computes aggregate statistics and
    percentile-based histogram (detailed summaries) showing how execution
    counts are distributed.

    - Recursively traverse all nodes (including inlined children)
    - Count only top-level functions in num_functions
    - Use cumulative percentile histogram (persistent state across cutoffs)
    """
    # Default percentile cutoffs (from AutoFDO)
    # These are in parts per million: 10000 = 1%, 100000 = 10%, etc.
    DEFAULT_CUTOFFS = [
        10000, 100000, 200000, 300000, 400000, 500000, 600000, 700000,
        800000, 900000, 950000, 990000, 999000, 999900, 999990, 999999
    ]

    total_count = 0
    max_count = 0
    max_function_count = 0
    num_counts = 0
    num_functions = len(stats.tree)  # Count only top-level functions (matches AutoFDO)
    count_frequencies: dict[int, int] = {}  # {count: frequency}

    def traverse_node(node: FuncNode, is_root: bool = False) -> None:
        """Recursively traverse a node and its inlined children.
        """
        nonlocal total_count, max_count, max_function_count, num_counts

        # For root nodes, track function entry count (offset 0)
        # This matches AutoFDO's VisitTopSymbol which tracks node->head_count
        if is_root and 0 in node.positions:
            func_head_count = node.positions[0]
            max_function_count = max(max_function_count, func_head_count)

        # Collect all position counts from this node
        # Filter out zero counts (structural positions with no execution)
        for offset, count in node.positions.items():
            if count > 0:
                total_count += count
                max_count = max(max_count, count)
                num_counts += 1
                count_frequencies[count] = count_frequencies.get(count, 0) + 1

        # Recursively traverse inlined children (callsites)
        # This matches AutoFDO's Traverse which iterates node->callsites
        for (call_offset, callee_name), child in node.children.items():
            traverse_node(child, is_root=False)

    # Traverse all top-level functions
    for func_name, func_node in stats.tree.items():
        traverse_node(func_node, is_root=True)

    # Compute detailed summaries (percentile histogram)
    # This follows AutoFDO's ComputeDetailedSummary algorithm:
    # - Sort counts descending (hottest first)
    # - Iterate cutoffs ascending (1%, 10%, 20%, ...)
    # - Use PERSISTENT state (cumulative histogram)
    detailed_summaries = []
    if total_count > 0 and count_frequencies:
        # Sort counts in descending order (hottest first)
        sorted_counts = sorted(count_frequencies.items(), key=lambda x: x[0], reverse=True)
        cumulative_sum = 0
        cumulative_samples = 0
        idx = 0

        for cutoff in DEFAULT_CUTOFFS:
            # Calculate threshold: what cumulative count represents this percentile?
            # AutoFDO uses uint128_t to avoid overflow, but Python handles arbitrary precision
            # Note: cutoff is in parts per million (10000 = 1%, 1000000 = 100%)
            threshold = (total_count * cutoff) // 1_000_000
            last_count = 0

            # Accumulate counts until we reach the threshold
            # State persists across iterations (cumulative)
            while cumulative_sum < threshold and idx < len(sorted_counts):
                count, freq = sorted_counts[idx]
                cumulative_sum += count * freq
                cumulative_samples += freq
                last_count = count
                idx += 1

            # Store cumulative result: "Top N positions accounting for X% of execution"
            detailed_summaries.append({
                'cutoff': cutoff,
                'min_count': last_count,
                'num_counts': cumulative_samples
            })

    return {
        'total_count': total_count,
        'max_count': max_count,
        'max_function_count': max_function_count,
        'num_counts': num_counts,
        'num_functions': num_functions,
        'detailed_summaries': detailed_summaries
    }

def write_summary(f: BinaryIO, summary: dict) -> None:
    """Write GCOV_TAG_AFDO_SUMMARY section.

    Writes the profile summary statistics in GCOV v3 format.
    Note: Unlike other sections, SUMMARY has no length field - the tag is
    followed directly by the data fields.
    """
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


def collect_strings_v3(node: FuncNode, func_names: set[str], files: set[str],
                       func_to_file: dict[str, str | None]) -> None:
    """Recursively collect function names and source files for v3 format.

    Traverses the function tree and collects:
    - All function names (including inline children and call targets)
    - All source filenames referenced by functions
    - Mapping from function names to their source files

    For call targets, attempts to resolve source files via stats.tree lookup.
    If not found, marks as None (external function).
    """
    func_names.add(node.name)
    if node.source_file:
        files.add(node.source_file)
        if node.name not in func_to_file:
            func_to_file[node.name] = node.source_file

    # Collect from call targets
    for _, _, targets in filtered_positions(node):
        func_names.update(targets.keys())
        # For targets, try to look up source file from tree if not already mapped
        for target_name in targets.keys():
            if target_name not in func_to_file:
                # Try to find this function in the tree
                if target_name in stats.tree and stats.tree[target_name].source_file:
                    func_to_file[target_name] = stats.tree[target_name].source_file
                else:
                    func_to_file[target_name] = None  # No file info

    # Recurse into inline children
    for _, _, child in emitted_children(node):
        collect_strings_v3(child, func_names, files, func_to_file)


def expand_ranges() -> None:
    """Expand range_counts into position counts in the profile tree.

    1. For each range, add range count to EVERY valid address in the range
    2. Multiple addresses may map to the same source position (different discriminators)
    3. For each source position, take the MAXIMUM count from all addresses that map to it."""

    print(f"Expanding {len(stats.range_counts)} ranges into source positions...")

    if args.verbose:
        print("\nRange counts:")
        for (begin, end), count in sorted(stats.range_counts.items()):
            print(f"  [{begin:x}-{end:x}]: count={count}")

    # Count of valid address probes (addresses that yielded DWARF info)
    # Note: this is total probes, not unique addresses (an address can be probed by multiple ranges)
    valid_address_probes = 0
    skipped_ranges = 0

    # First, build address_count_map by iterating all ranges
    # Multiple ranges can contribute to the same address (they accumulate)
    address_counts: dict[int, int] = defaultdict(int)

    for (begin, end), range_count in stats.range_counts.items():
        range_has_data = False
        for addr in range(begin, end):
            frames = getframes_cached(addr)
            if frames is None:
                continue

            range_has_data = True
            valid_address_probes += 1

            # Add range count to this address
            address_counts[addr] += range_count

        if not range_has_data:
            skipped_ranges += 1

    # Now process each address and map to source positions
    # For each unique (root, path, offset), take MAX count from all addresses mapping to it
    # Also track source files for root and inline frames
    position_max_counts: dict[tuple[str, tuple[tuple[str, int], ...], int], int] = {}
    position_source_files: dict[tuple[str, tuple[tuple[str, int], ...], int], tuple[str | None, list[str | None]]] = {}

    for addr, addr_count in address_counts.items():
        frames = getframes_cached(addr)
        if frames is None:
            stats.dwarf_lookup_failures += 1
            continue

        # Build inline call path
        root_frame = frames[0]
        if not root_frame.sym:
            stats.missing_symbols += 1
            continue

        root_name = root_frame.sym
        root_source_file = os.path.basename(root_frame.file) if root_frame.file else None

        names: list[str] = [root_name]
        source_files: list[str | None] = [root_source_file]
        for fr in frames[1:]:
            if not fr.sym:
                break
            names.append(fr.sym)
            source_files.append(os.path.basename(fr.file) if fr.file else None)

        if len(names) != len(frames):
            stats.incomplete_stacks += 1
            continue

        path: list[tuple[str, int]] = []
        for i in range(1, len(frames)):
            path.append((names[i], frame_offset(frames[i - 1])))

        leaf_off = frame_offset(frames[-1])
        path_tuple = tuple(path)
        pos_key = (root_name, path_tuple, leaf_off)

        # Take MAX count for this position (not sum!)
        if pos_key not in position_max_counts or addr_count > position_max_counts[pos_key]:
            position_max_counts[pos_key] = addr_count
            # Store source files: (root_source, [inline source files])
            position_source_files[pos_key] = (root_source_file, source_files[1:])

    # Add positions to profile tree
    for pos_key, count in position_max_counts.items():
        root_name, path_tuple, leaf_off = pos_key
        path = list(path_tuple)
        root_source_file, inline_source_files = position_source_files[pos_key]
        root = stats.root(root_name, root_source_file)
        add_path(root, path, leaf_off, count, None, inline_source_files)

    #print(f"Probed {valid_address_probes} addresses from {len(stats.range_counts) - skipped_ranges} ranges")
    #print(f"Skipped {skipped_ranges} ranges with no debug info")
    #print(f"Frame cache size: {len(_frame_cache)}")

    # Report diagnostics if any errors occurred
    if stats.dwarf_lookup_failures > 0:
        print(f"Note: {stats.dwarf_lookup_failures} addresses had no DWARF info")
    if stats.missing_symbols > 0:
        print(f"Note: {stats.missing_symbols} frames had no symbol names")
    if stats.incomplete_stacks > 0:
        print(f"Note: {stats.incomplete_stacks} inline stacks were incomplete")


def add_branch_targets() -> None:
    """Add call targets from branch_counts to the profile tree.

    For each branch (from, to), resolve both addresses and add the target
    at the source position if it's a call."""

    print(f"Adding call targets from {len(stats.branch_counts)} branches...")
    added_targets = 0

    for (from_addr, to_addr), count in stats.branch_counts.items():
        sframes = getframes_cached(from_addr)
        dframes = getframes_cached(to_addr)

        if sframes is None or dframes is None:
            continue

        # Determine if this is a call (different root functions)
        # Compare root (outermost) frames, not innermost frames.
        # Innermost frames differ for any inline context change, but that's not a call.
        sroot = sframes[0]
        droot = dframes[0]
        is_call = sroot.sym != droot.sym

        if not is_call:
            continue  # Not a call, skip

        # Get root names
        sroot_name = sroot.sym
        droot_name = droot.sym

        if not sroot_name or not droot_name:
            continue

        # Extract source files
        sroot_source_file = os.path.basename(sroot.file) if sroot.file else None

        # Build source inline path with source files
        root = stats.root(sroot_name, sroot_source_file)
        names: list[str] = [sroot_name]
        source_files: list[str | None] = []
        for fr in sframes[1:]:
            if not fr.sym:
                break
            names.append(fr.sym)
            source_files.append(os.path.basename(fr.file) if fr.file else None)

        if len(names) != len(sframes):
            continue

        path: list[tuple[str, int]] = []
        for i in range(1, len(sframes)):
            path.append((names[i], frame_offset(sframes[i - 1])))

        # Determine target name
        # Use innermost destination frame if available, otherwise root
        dinner = dframes[-1]
        target = dinner.sym if dinner.sym else droot_name
        if not target:
            continue

        # Add target at source position. Materialize a zero-count position only
        # when it is needed to carry a qualifying target histogram.
        leaf_off = frame_offset(sframes[-1])
        node = root
        for i, (name, off) in enumerate(path):
            src_file = source_files[i] if i < len(source_files) else None
            node = node.child(off, name, src_file)
        node.positions.setdefault(leaf_off, 0)
        node.targets[leaf_off][target] += count
        added_targets += 1

    print(f"Added {added_targets} call targets")

def add_dwarf_zero_scaffolding():
    """Add zero-count positions at function boundaries based on DWARF observations.

    Add function epilogue (line after max observed line)."""

    added_zeros = 0

    for name, node in stats.tree.items():
        if not node.positions:
            continue

        # Add entry scaffolding at line 1
        entry_offset = 1 << 16  # Line 1, discriminator 0
        has_entry = any((off >> 16) == 1 for off in node.positions.keys())
        if not has_entry:
            node.positions[entry_offset] = 0
            node.structural_zeros.add(entry_offset)
            added_zeros += 1

        # Find line number range from actual positions
        lines = {(off >> 16) for off in node.positions.keys()}
        if not lines:
            continue

        max_line = max(lines)

        # Add epilogue zero at a line beyond max observed
        # The +3 offset is an empirical heuristic that approximates where AutoFDO
        # places epilogue scaffolding. AutoFDO derives this from DWARF line table
        # end_sequence markers, which compilers typically place 2-4 lines past the
        # last executable statement in a function (accounting for closing braces,
        # return statements, and compiler-generated epilogue code).
        #
        # Note: This is a cosmetic heuristic. GCC's -fauto-profile only cares about
        # execution counts, not exact scaffolding placement. A proper implementation
        # would require parsing DWARF line table end_sequence markers or querying
        # DW_AT_high_pc from function DIEs.
        epilogue_line = max_line + 3
        epilogue_offset = epilogue_line << 16

        # Check if this line already has data (any discriminator)
        has_epilogue = any((off >> 16) == epilogue_line for off in node.positions.keys())
        if not has_epilogue:
            node.positions[epilogue_offset] = 0
            node.structural_zeros.add(epilogue_offset)
            added_zeros += 1

    print(f"Added {added_zeros} DWARF-informed zero scaffolding positions")

def trace_end():
    print("%d raw branches, %d filtered, %d errored, %d crossed" %
          (stats.raw_total_branches, stats.raw_ignored_branches, stats.errored, stats.crossed))
    print(f"Collected {len(stats.range_counts)} ranges and {len(stats.branch_counts)} branches")

    # Expand ranges into position counts (main attribution step)
    expand_ranges()

    # Add call targets from branch data
    add_branch_targets()

    # Add DWARF-informed zero scaffolding for function boundaries
    add_dwarf_zero_scaffolding()

    if args.top > 0:
        entries: list[tuple[str, int]] = []
        for name, node in stats.tree.items():
            collect_top(entries, name, node)
        for path, count in sorted(entries, key=lambda x: x[1], reverse=True)[:args.top]:
            print(path, "\t", count, "%.2f" % (float(count) / stats.raw_total_branches * 100. if stats.raw_total_branches else 0.0))

    # XXX multiple output files
    update_branch_counts(stats)

    with open(args.gcov if args.gcov else args.output, "wb") as f:
        w32(f, GCOV_DATA_MAGIC)
        w32(f, args.gcov_version)  # Write actual version from args
        w32(f, 0)

        # Write summary section (v3 only)
        if args.gcov_version == 3:
            summary = compute_summary(stats)
            write_summary(f, summary)
            print(f"Summary: {summary['num_functions']} functions, {summary['num_counts']} counts, total={summary['total_count']}")

        # Write string table (version-specific)
        w32(f, GCOV_TAG_AFDO_FILE_NAMES)

        if args.gcov_version == 2:
            # Version 2: simple string list
            string_table, string_index = gen_strtable(stats)
            length = 4 + sum((len(s) + 5) for s in string_table)
            w32(f, length)
            w32(f, len(string_table))
            for fn in string_table:
                wstring(f, fn)

        elif args.gcov_version == 3:
            # Version 3: files + functions with indices
            file_table, file_index, func_file_map, string_table, string_index = gen_strtable_v3(stats)

            # Calculate length
            length = 4  # num_filenames
            length += sum(len(fname) + 5 for fname in file_table)
            length += 4  # num_functions
            length += sum(len(func) + 5 + 4 for func in string_table)

            w32(f, length)

            # Write file names
            w32(f, len(file_table))
            for fname in file_table:
                wstring(f, fname)

            # Write function names with file indices
            w32(f, len(string_table))
            for func_name in string_table:
                wstring(f, func_name)
                file_idx = func_file_map.get(func_name, -1)
                w32(f, file_idx if file_idx >= 0 else 0xFFFFFFFF)  # -1 as unsigned

        else:
            sys.exit(f"Unsupported GCOV version: {args.gcov_version}. Only versions 2 and 3 are supported. Use --gcov-version 2 or --gcov-version 3.")

        # write function profile
        w32(f, GCOV_TAG_AFDO_FUNCTION)
        lenoff = f.tell()
        w32(f, 0) # length. ignored by gcc
        print("Writing %d functions" % len(stats.tree))
        w32(f, len(stats.tree))
        for name in sorted(stats.tree):
            wfunc_node(f, stats.tree[name], 0, string_index, True)

        if not pathlib.Path(f.name).is_fifo():
            endoff = f.tell()
            f.seek(lenoff, 0)
            print("Data length %d" % (endoff - lenoff))
            w32(f, endoff - lenoff)
            f.seek(endoff, 0)

        # not used by gcc
        w32(f, GCOV_TAG_AFDO_MODULE_GROUPING)
        w32(f, 4)
        w32(f, 0)

        w32(f, GCOV_TAG_AFDO_WORKING_SET)
        w32(f, 4)
        w32(f, 0)

    print("%d processed branches, %d output branches, %.2f%% ignored" %
          (stats.output_total_positions,
           stats.output_branches,
           (float(stats.output_ignored_positions) / stats.output_total_positions * 100.
            if stats.output_total_positions else 0.0)))

def collect_top(entries: list[tuple[str, int]], prefix: str, node: FuncNode) -> None:
    for off, count in node.positions.items():
        entries.append(("%s:%d" % (prefix, off), count))
    for (coff, cname), child in node.children.items():
        collect_top(entries, "%s/%s@%d" % (prefix, cname, coff), child)

def update_branch_counts(stats: Stats) -> None:
    stats.output_total_positions = 0
    stats.output_ignored_positions = 0
    stats.output_branches = 0
    for node in stats.tree.values():
        update_node_branch_counts(node)

def update_node_branch_counts(node: FuncNode) -> None:
    for count in node.positions.values():
        stats.output_total_positions += count
        if count < args.threshold:
            stats.output_ignored_positions += count
        else:
            stats.output_branches += count
    for child in node.children.values():
        update_node_branch_counts(child)

# Return the inline/frame stack for IP as a list of Frame, ordered from the
# outermost (real, symbol-table) function down to the innermost inlined
# frame. Returns None if the address cannot be resolved.
def getframes(ip:int) -> list[Frame] | None:
    p = backtrace.pcinfo(btstate, ip)
    #print("pcinfo %x" % ip, p)
    if p is None or len(p) == 0:
        return None
    op = p[0]
    # pcinfo entry layout: (PC, filename, lineno, function, disc, decl_line)
    # entries sharing op's PC form the inline stack, innermost first.
    frames = [Frame(x[1], x[2], x[4], x[3], x[5])
              for x in itertools.takewhile(lambda x: x[0] == op[0], p)]
    if frames[0].file is None:
        return None
    frames.reverse()
    return frames

def frame_offset(fr: Frame) -> int:
    """Calculate offset of a frame relative to its function declaration line.

    Args:
        fr: Frame with line, declline, and discriminator info

    Returns:
        Encoded offset (line << 16 | discriminator)
    """
    # Offset of a frame relative to its function declaration line
    base = fr.declline if fr.declline else fr.line
    line = fr.line - base
    if line < 0:
        # Negative offsets indicate DWARF inconsistency (line before declaration)
        # This can happen with inlined code or compiler-generated code
        if args.verbose:
            import sys
            print(f"WARNING: Negative line offset clamped to 0: "
                  f"function={fr.sym}, line={fr.line}, base={base}",
                  file=sys.stderr)
        line = 0
    return gen_offset(line, fr.disc)

def sym_name(bsym: str, frame_sym: str | None) -> str:
    # prefer the symbol-table name from perf; fall back to the frame's
    # function name from debug info.
    if bsym and "+" in bsym:
        return bsym.split("+")[0]
    if bsym:
        return bsym
    return frame_sym if frame_sym else ""

def process_event(param_dict):
    """Process LBR branch stack to build range_counts and branch_counts.

    Implements LBR range reconstruction: for adjacent LBR entries,
    range [entry[i].to, entry[i-1].from) represents executed code."""

    brstack = param_dict["brstack"]
    brstacksym = param_dict["brstacksym"]

    if len(brstack) == 0:
        return

    # Filter to branches within our target binary
    focused_branches = []
    for br, bsym in zip(brstack, brstacksym):
        stats.total += 1
        stats.raw_total_branches += 1
        if br["from_dsoname"] != br["to_dsoname"]:
            stats.crossed += 1
            stats.raw_ignored_branches += 1
            continue
        if os.path.basename(br["from_dsoname"]) != os.path.basename(args.binary):
            stats.ignored += 1
            stats.raw_ignored_branches += 1
            continue
        focused_branches.append((br, bsym))

    # Implement duplicate-top-entry filtering (backedge detection heuristic)
    if (len(focused_branches) >= 2 and
        focused_branches[0][0]["from"] == focused_branches[1][0]["from"] and
        focused_branches[0][0]["to"] == focused_branches[1][0]["to"]):
        # Entries 0 and 1 are duplicates
        br0_from = focused_branches[0][0]["from"]
        br0_to = focused_branches[0][0]["to"]
        stride = abs(br0_from - br0_to)
        if stride > args.strip_dup_backedge_stride_limit:
            # Skip the duplicate top entry
            focused_branches = focused_branches[1:]

    if len(focused_branches) == 0:
        return

    for br, _ in focused_branches:
        stats.branch_counts[(br["from"], br["to"])] += 1

    if len(focused_branches) < 2:
        # Need at least 2 entries to form a range, but still keep branch samples.
        return

    # Build range_counts and branch_counts from adjacent LBR entries
    # LBR ordering: entries are from most recent (index 0) to oldest
    # Range construction: current.to → previous.from represents execution

    for i in range(1, len(focused_branches)):
        br, _ = focused_branches[i]
        prev_br, _ = focused_branches[i - 1]

        begin = br["to"]
        end = prev_br["from"]

        # Validate range
        if end < begin:
            continue
        if end - begin > args.insn_range_max:
            continue

        stats.range_counts[(begin, end)] += 1
