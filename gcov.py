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

import os
import sys
from collections import Counter, defaultdict
from functools import cache
from typing import NamedTuple, Any, BinaryIO
import argparse
import fnmatch
import itertools
import os.path
import subprocess
import pathlib
import backtrace
import suffix
from format import *

# Define argparse early so --help works without perf re-execution
ap = argparse.ArgumentParser()
ap.add_argument('output', default="file.gcov", nargs='?', help="Output gcov file. Default file.gcov")
ap.add_argument('--binary', action='append', default=[],
                help="Binary to profile (fnmatch pattern, repeatable). "
                     "If omitted, auto-discover all binaries.")
ap.add_argument('--profile', '-i', help="Profile data. Default perf.data")
ap.add_argument('--gcov', help="gcov output file")
ap.add_argument('--profiler', help="set profiler type (nop)", choices=["perf"])
ap.add_argument('--threshold', default=10, type=int, help="Min number of samples for location to output")
ap.add_argument('--verbose', action='store_true', help="Be more verbose")
ap.add_argument('--gcov-version', '--gcov_version', type=int, choices=[2, 3], default=3,
                help="GCOV version: 2 (upto gcc 15) or 3 (gcc 16+, default)")
ap.add_argument('--strip-dup-backedge-stride-limit', type=int, default=4096,
                help="Skip duplicate top LBR entry if from-to stride exceeds this. Default 4096")
ap.add_argument('--insn-range-max', type=int, default=1<<20, help="Max range between branches to probe")
ap.add_argument('--suffix-elision', choices=suffix.ELIDE_POLICIES, default='all',
                help="Symbol suffix elision policy (default: %(default)s)")
ap.add_argument('--min-samples', type=int, default=100,
                help="Skip binaries with fewer samples (default: 100)")
ap.add_argument('--output-dir', help="Output directory for multi-binary mode")
ap.add_argument('--write-empty', action='store_true',
                help="Write empty profile files for binaries with no data")
ap.add_argument('--quiet', action='store_true',
                help="Suppress statistics output")

if '--help' in sys.argv or '-h' in sys.argv:
    ap.print_help()
    sys.exit(0)

if os.getenv('PERF_EXEC_PATH') is None:
    perf = os.getenv('PERF')
    if perf is None:
        perf = "perf"
    data = "perf.data"
    for arg in sys.argv[1:]:
        if arg.startswith("--profile="):
            data = arg.split("=", 1)[1]
            sys.argv.remove(arg)
            break
        if arg == "--profile" or arg == "-i":
            i = sys.argv.index(arg)
            if i + 1 < len(sys.argv):
                del sys.argv[i]
                data = sys.argv[i]
                del sys.argv[i]
                break
    pargs = [perf, "script", "-i", data, sys.argv[0]] + sys.argv[1:]
    sys.exit(subprocess.run(pargs).returncode)

perf_exec_path = os.getenv('PERF_EXEC_PATH')
assert perf_exec_path is not None  # Only reached under perf script
sys.path.append(perf_exec_path + '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

try:
    from perf_trace_context import perf_script_context # type: ignore
except ImportError:
    sys.exit("Cannot find perf python modules")

args = ap.parse_args()

def vprint(*vals, **kwargs):
    """Print only if not in quiet mode."""
    if not args.quiet:
        print(*vals, **kwargs)

def trace_begin():
    pass

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

        # Error/skip counters for diagnostics
        self.dwarf_lookup_failures = 0  # Addresses with no DWARF info
        self.missing_symbols = 0         # Frames with no symbol name
        self.incomplete_stacks = 0       # Incomplete inline stacks

stats = Stats()

class BinaryContext:
    """Per-binary profiling context."""
    def __init__(self, dsoname: str):
        self.dsoname = dsoname
        self.btstate: Any = None
        # Load offset for shared library relocation (runtime_addr - file_addr)
        self.load_offset: int = 0
        # outermost function name -> profile tree root
        self.tree: dict[str, FuncNode] = {}
        # Range-based profile data (LBR-derived ranges)
        self.range_counts: Counter[tuple[tuple[int, int], str | None]] = Counter()
        # ((from_addr, to_addr), from_sym, to_sym) -> count
        self.branch_counts: Counter[tuple[tuple[int, int], str | None, str | None]] = Counter()
        # Timestamp tracking: first sample time per function
        self.first_address_time: dict[int, int] = {}
        # Root function name -> first sample timestamp
        self.func_timestamp: dict[str, int] = {}
        # Frame cache: addr -> frames | None
        self.frame_cache: dict[int, list[Frame] | None] = {}
        # Sample count for --min-samples filtering
        self.sample_count = 0

    def root(self, name: str, source_file: str | None = None) -> "FuncNode":
        node = self.tree.get(name)
        if node is None:
            node = FuncNode(name, source_file)
            self.tree[name] = node
        elif source_file and not node.source_file:
            node.source_file = source_file
        return node

# dsoname -> BinaryContext
binaries: dict[str, BinaryContext] = {}

def is_file_dso(dsoname: str) -> bool:
    """Check if DSO is a real file (not kernel, vdso, etc.)."""
    return not dsoname.startswith('[') and '/' in dsoname

@cache
def is_position_independent(dsoname: str) -> bool:
    """Return True if the ELF file is ET_DYN (PIE or shared library).
    Results are cached per dsoname."""
    try:
        with open(dsoname, "rb") as f:
            ident = f.read(20)
    except OSError:
        return False
    if len(ident) < 20 or ident[:4] != b'\x7fELF':
        return False
    ei_data = ident[5]
    if ei_data == 1:  # ELFDATA2LSB
        e_type = ident[16] | (ident[17] << 8)
    elif ei_data == 2:  # ELFDATA2MSB
        e_type = (ident[16] << 8) | ident[17]
    else:
        return False
    return e_type == 3  # ET_DYN

def should_process_binary(dsoname: str) -> bool:
    """Check if binary matches --binary patterns."""
    if not args.binary:
        return True
    basename = os.path.basename(dsoname)
    return any(fnmatch.fnmatch(dsoname, pat) or fnmatch.fnmatch(basename, pat)
               for pat in args.binary)

def get_or_create_binary(dsoname: str, dso_map_start: int = 0, map_pgoff: int = 0) -> BinaryContext | None:
    """Get or create BinaryContext for a DSO."""
    if dsoname in binaries:
        return binaries[dsoname]

    if not is_file_dso(dsoname):
        return None

    if not should_process_binary(dsoname):
        return None

    try:
        btstate = backtrace.createstate(dsoname)
    except Exception as e:
        print(f"warning: cannot create backtrace state for {dsoname}: {e}", file=sys.stderr)
        return None

    ctx = BinaryContext(dsoname)
    ctx.btstate = btstate
    # Only ET_DYN files (PIE/shared library) need load offset subtraction.
    if dso_map_start and map_pgoff and is_position_independent(dsoname):
        ctx.load_offset = dso_map_start - map_pgoff
        vprint(f"  {os.path.basename(dsoname)}: load_offset=0x{ctx.load_offset:x}")

    binaries[dsoname] = ctx
    return ctx

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
               string_index: dict[str, int], toplevel: bool, ctx: BinaryContext) -> None:
    if toplevel:
        wcounter(f, node.head_count())
        if args.gcov_version >= 3:
            ts = ctx.func_timestamp.get(node.name, 0)
            wcounter(f, ts)  # first sample timestamp (nanoseconds)
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
        wfunc_node(f, child, coff, string_index, False, ctx)

def gen_strtable(ctx: BinaryContext):
    strings: set[str] = set()
    for node in ctx.tree.values():
        collect_strings(node, strings)
    # Index 0 must be empty (reserved by GCC)
    string_table = [""] + sorted(strings)
    string_index = { name: i for i, name in enumerate(string_table) }
    return string_table, string_index

def gen_strtable_v3(ctx: BinaryContext):
    """Generate string table for GCOV v3 format with file names."""
    source_files: set[str] = set()
    function_names: set[str] = set()
    func_to_file: dict[str, str | None] = {}

    # Collect from tree roots
    for name, node in ctx.tree.items():
        if node.source_file:
            source_files.add(node.source_file)
            func_to_file[name] = node.source_file
        collect_strings_v3(ctx, node, function_names, source_files, func_to_file)

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

    # Build string table (index 0 must be empty, reserved by GCC)
    string_table = [""] + sorted(function_names)
    string_index = {name: i for i, name in enumerate(string_table)}

    return file_table, file_index, func_file_map, string_table, string_index

def compute_summary(ctx: BinaryContext) -> dict:
    """Compute profile summary statistics for GCOV_TAG_AFDO_SUMMARY."""
    total_count = 0
    max_count = 0
    max_function_count = 0
    num_counts = 0
    num_functions = len(ctx.tree)  # Count only top-level functions
    count_frequencies: dict[int, int] = {}  # {count: frequency}

    def traverse_node(node: FuncNode, is_root: bool = False) -> None:
        nonlocal total_count, max_count, max_function_count, num_counts

        # For root nodes, track function entry count (offset 0)
        if is_root and 0 in node.positions:
            func_head_count = node.positions[0]
            max_function_count = max(max_function_count, func_head_count)

        # Collect all position counts from this node
        for offset, count in node.positions.items():
            if count > 0:
                total_count += count
                max_count = max(max_count, count)
                num_counts += 1
                count_frequencies[count] = count_frequencies.get(count, 0) + 1

        # Recursively traverse inlined children (callsites)
        for (call_offset, callee_name), child in node.children.items():
            traverse_node(child, is_root=False)

    # Traverse all top-level functions
    for func_name, func_node in ctx.tree.items():
        traverse_node(func_node, is_root=True)

    # Compute detailed summaries (percentile histogram)
    detailed_summaries = []
    if total_count > 0 and count_frequencies:
        # Sort counts in descending order (hottest first)
        sorted_counts = sorted(count_frequencies.items(), key=lambda x: x[0], reverse=True)
        cumulative_sum = 0
        cumulative_samples = 0
        idx = 0

        for cutoff in DEFAULT_CUTOFFS:
            # Calculate threshold: what cumulative count represents this percentile?
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
    else:
        # Empty or zero-count profile: write 16 zero entries
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

def collect_strings_v3(ctx: BinaryContext, node: FuncNode, func_names: set[str], files: set[str],
                       func_to_file: dict[str, str | None]) -> None:
    """Recursively collect function names and source files for v3 format."""
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
                if target_name in ctx.tree and ctx.tree[target_name].source_file:
                    func_to_file[target_name] = ctx.tree[target_name].source_file
                else:
                    func_to_file[target_name] = None  # No file info

    # Recurse into inline children
    for _, _, child in emitted_children(node):
        collect_strings_v3(ctx, child, func_names, files, func_to_file)


def expand_ranges(ctx: BinaryContext) -> None:
    """Expand range_counts into position counts in the profile tree for one binary.

    1. For each range, add range count to EVERY valid address in the range
    2. Multiple addresses may map to the same source position (different discriminators)
    3. For each source position, take the MAXIMUM count from all addresses that map to it."""

    vprint(f"Expanding {len(ctx.range_counts)} ranges for {os.path.basename(ctx.dsoname)}...")

    if args.verbose:
        print("\nRange counts:")
        for (begin, end), sym in ctx.range_counts.keys():
            count = ctx.range_counts[((begin, end), sym)]
            print(f"  [{begin:x}-{end:x}] ({sym}): count={count}")

    valid_address_probes = 0
    skipped_ranges = 0
    dwarf_failures = 0
    missing_syms = 0
    incomplete = 0

    address_counts: dict[int, int] = defaultdict(int)
    address_symbols: dict[int, str | None] = {}

    for ((begin, end), range_sym), range_count in ctx.range_counts.items():
        range_has_data = False
        for addr in range(begin, end + 1):
            frames = getframes(ctx, addr)
            if frames is None:
                continue

            range_has_data = True
            valid_address_probes += 1

            address_counts[addr] += range_count
            if addr not in address_symbols:
                address_symbols[addr] = range_sym

        if not range_has_data:
            skipped_ranges += 1

    position_max_counts: dict[tuple[str, tuple[tuple[str, int], ...], int], int] = {}
    position_source_files: dict[tuple[str, tuple[tuple[str, int], ...], int], tuple[str | None, list[str | None]]] = {}

    for addr, addr_count in address_counts.items():
        frames = getframes(ctx, addr)
        if frames is None:
            dwarf_failures += 1
            continue

        root_frame = frames[0]
        if not root_frame.sym:
            missing_syms += 1
            continue

        perf_sym = address_symbols.get(addr)
        if perf_sym and root_frame.sym in perf_sym:
            root_name = perf_sym
        else:
            root_name = root_frame.sym
        root_source_file = os.path.basename(root_frame.file) if root_frame.file else None

        addr_time = ctx.first_address_time.get(addr)
        if addr_time and root_name not in ctx.func_timestamp:
            ctx.func_timestamp[root_name] = addr_time

        names: list[str] = [root_name]
        source_files: list[str | None] = [root_source_file]
        for fr in frames[1:]:
            if not fr.sym:
                break
            names.append(fr.sym)
            source_files.append(os.path.basename(fr.file) if fr.file else None)

        if len(names) != len(frames):
            incomplete += 1
            continue

        path: list[tuple[str, int]] = []
        for i in range(1, len(frames)):
            path.append((names[i], frame_offset(frames[i - 1])))

        leaf_off = frame_offset(frames[-1])
        path_tuple = tuple(path)
        pos_key = (root_name, path_tuple, leaf_off)

        if pos_key not in position_max_counts or addr_count > position_max_counts[pos_key]:
            position_max_counts[pos_key] = addr_count
            position_source_files[pos_key] = (root_source_file, source_files[1:])

    for pos_key, count in position_max_counts.items():
        root_name, path_tuple, leaf_off = pos_key
        path = list(path_tuple)
        root_source_file, inline_source_files = position_source_files[pos_key]
        root = ctx.root(root_name, root_source_file)

        if len(path) > 0:
            root_call_offset = path[0][1]
            if root_call_offset in root.positions:
                root.positions[root_call_offset] = max(
                    root.positions[root_call_offset], count
                )
            else:
                root.positions[root_call_offset] = count

        add_path(root, path, leaf_off, count, None, inline_source_files)

    stats.dwarf_lookup_failures += dwarf_failures
    stats.missing_symbols += missing_syms
    stats.incomplete_stacks += incomplete

def add_branch_targets(ctx: BinaryContext) -> None:
    """Add call targets from branch_counts to the profile tree for one binary."""

    vprint(f"Adding call targets from {len(ctx.branch_counts)} branches for {os.path.basename(ctx.dsoname)}...")
    added_targets = 0

    for ((from_addr, to_addr), from_sym, to_sym), count in ctx.branch_counts.items():
        sframes = getframes(ctx, from_addr)
        dframes = getframes(ctx, to_addr)

        if sframes is None or dframes is None:
            continue

        sroot = sframes[0]
        droot = dframes[0]
        is_call = sroot.sym != droot.sym

        if not is_call:
            continue

        if from_sym and sroot.sym and sroot.sym in from_sym:
            sroot_name: str = from_sym
        elif sroot.sym:
            sroot_name = sroot.sym
        else:
            continue

        if to_sym and droot.sym and droot.sym in to_sym:
            droot_name = to_sym
        elif droot.sym:
            droot_name = droot.sym
        else:
            continue

        sroot_source_file = os.path.basename(sroot.file) if sroot.file else None

        root = ctx.root(sroot_name, sroot_source_file)
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

        if droot_name and droot_name not in ctx.func_timestamp:
            branch_time = ctx.first_address_time.get(from_addr)
            if branch_time:
                ctx.func_timestamp[droot_name] = branch_time

        if not droot_name:
            continue
        target = droot_name

        leaf_off = frame_offset(sframes[-1])
        node = root
        for i, (name, off) in enumerate(path):
            src_file = source_files[i] if i < len(source_files) else None
            node = node.child(off, name, src_file)
        node.positions.setdefault(leaf_off, 0)
        node.targets[leaf_off][target] += count
        added_targets += 1

    vprint(f"Added {added_targets} call targets")

def add_dwarf_zero_scaffolding(ctx: BinaryContext) -> None:
    """Add zero-count positions at function boundaries for one binary."""

    added_zeros = 0

    for name, node in ctx.tree.items():
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

    vprint(f"Added {added_zeros} DWARF-informed zero scaffolding positions")

def write_gcov_file(ctx: BinaryContext, output_path: str) -> bool:
    """Write gcov profile file for a specific binary. Returns True if written."""

    if not ctx.tree:
        if args.write_empty:
            print(f"Warning: writing empty file to {output_path}")
        else:
            print(f"Skipping {output_path} (no profile data)")
            return False

    update_branch_counts(ctx)

    with open(output_path, "wb") as f:
        w32(f, GCOV_DATA_MAGIC)
        w32(f, args.gcov_version)
        w32(f, 0)

        if args.gcov_version == 3:
            summary = compute_summary(ctx)
            write_summary(f, summary)
            vprint(f"Summary: {summary['num_functions']} functions, {summary['num_counts']} counts, total={summary['total_count']}")

        w32(f, GCOV_TAG_AFDO_FILE_NAMES)

        if args.gcov_version == 2:
            string_table, string_index = gen_strtable(ctx)
            length = 4 + sum((len(s) + 5) for s in string_table)
            w32(f, length)
            w32(f, len(string_table))
            for fn in string_table:
                wstring(f, fn)

        elif args.gcov_version == 3:
            file_table, file_index, func_file_map, string_table, string_index = gen_strtable_v3(ctx)

            length = 4
            length += sum(len(fname) + 5 for fname in file_table)
            length += 4
            length += sum(len(func) + 5 + 4 for func in string_table)

            w32(f, length)

            w32(f, len(file_table))
            for fname in file_table:
                wstring(f, fname)

            w32(f, len(string_table))
            for func_name in string_table:
                wstring(f, func_name)
                file_idx = func_file_map.get(func_name, -1)
                w32(f, file_idx if file_idx >= 0 else 0xFFFFFFFF)

        w32(f, GCOV_TAG_AFDO_FUNCTION)
        lenoff = f.tell()
        w32(f, 0)
        vprint("Writing %d functions to %s" % (len(ctx.tree), output_path))
        w32(f, len(ctx.tree))
        for name in sorted(ctx.tree):
            wfunc_node(f, ctx.tree[name], 0, string_index, True, ctx)

        if not pathlib.Path(f.name).is_fifo():
            endoff = f.tell()
            f.seek(lenoff, 0)
            vprint("Data length %d" % (endoff - lenoff))
            w32(f, endoff - lenoff)
            f.seek(endoff, 0)

        write_gcov_tail(f)

    print(f"Wrote {output_path}")
    return True

def trace_end():
    vprint("%d raw branches, %d filtered, %d errored, %d crossed" %
          (stats.raw_total_branches, stats.raw_ignored_branches, stats.errored, stats.crossed))

    # Filter binaries by --min-samples
    active_binaries = {dsoname: ctx for dsoname, ctx in binaries.items()
                       if ctx.sample_count >= args.min_samples}

    if len(active_binaries) == 0:
        print("No binaries with sufficient samples", file=sys.stderr)
        return

    # Process each binary
    for dsoname, ctx in active_binaries.items():
        basename = os.path.basename(dsoname)
        vprint(f"\nProcessing {basename} ({ctx.sample_count} samples)...")

        expand_ranges(ctx)
        add_branch_targets(ctx)
        add_dwarf_zero_scaffolding(ctx)
        suffix.elide_tree_suffixes(ctx.tree, args.suffix_elision)

    # Determine output filenames
    output_paths: dict[str, str] = {}
    if len(active_binaries) == 1:
        dsoname = list(active_binaries.keys())[0]
        output_paths[dsoname] = args.gcov if args.gcov else args.output
    else:
        if args.gcov:
            print("warning: --gcov ignored in multi-binary mode", file=sys.stderr)
        used_paths: set[str] = set()
        for dsoname in active_binaries:
            basename = os.path.basename(dsoname)
            if args.output_dir:
                os.makedirs(args.output_dir, exist_ok=True)
                path = os.path.join(args.output_dir, f"{basename}.gcov")
            else:
                path = f"{basename}.gcov"

            if path in used_paths:
                print(f"warning: output conflict for {dsoname}, skipping", file=sys.stderr)
                # TODO: use buildid for conflict resolution
                continue

            used_paths.add(path)
            output_paths[dsoname] = path

    # Write output files
    written: list[str] = []
    for dsoname, ctx in active_binaries.items():
        if dsoname not in output_paths:
            continue
        if write_gcov_file(ctx, output_paths[dsoname]):
            written.append(dsoname)

    # Print final summary
    vprint(f"\nWrote {len(written)} profile files:")
    for dsoname in written:
        vprint(f"  {os.path.basename(dsoname)}")

    if stats.dwarf_lookup_failures > 0:
        vprint(f"Note: {stats.dwarf_lookup_failures} addresses had no DWARF info")
    if stats.missing_symbols > 0:
        vprint(f"Note: {stats.missing_symbols} frames had no symbol names")
    if stats.incomplete_stacks > 0:
        vprint(f"Note: {stats.incomplete_stacks} inline stacks were incomplete")

    vprint("%d processed branches, %d output branches, %.2f%% ignored" %
           (stats.output_total_positions,
            stats.output_branches,
            (float(stats.output_ignored_positions) / stats.output_total_positions * 100.
             if stats.output_total_positions else 0.0)))

def update_branch_counts(ctx: BinaryContext) -> None:
    for node in ctx.tree.values():
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
def getframes(ctx: BinaryContext, ip: int) -> list[Frame] | None:
    """Cached lookup of inline call stack for address in a specific binary."""
    if ip in ctx.frame_cache:
        return ctx.frame_cache[ip]

    p = backtrace.pcinfo(ctx.btstate, ip)
    if p is None or len(p) == 0:
        ctx.frame_cache[ip] = None
        return None
    op = p[0]
    # pcinfo entry layout: (PC, filename, lineno, function, disc, decl_line)
    # entries sharing op's PC form the inline stack, innermost first.
    frames = [Frame(x[1], x[2], x[4], x[3], x[5])
              for x in itertools.takewhile(lambda x: x[0] == op[0], p)]
    if frames[0].file is None:
        ctx.frame_cache[ip] = None
        return None
    frames.reverse()
    ctx.frame_cache[ip] = frames
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
        if not args.quiet:
            print(f"WARNING: Negative line offset clamped to 0: "
                  f"function={fr.sym}, line={fr.line}, base={base}",
                  file=sys.stderr)
        line = 0
    return gen_offset(line, fr.disc)



def process_event(param_dict):
    """Process LBR branch stack to build range_counts and branch_counts.

    Routes branches to the correct per-binary context. Cross-binary
    branches are filtered out."""

    brstack = param_dict["brstack"]
    brstacksym = param_dict["brstacksym"]

    if len(brstack) == 0:
        return

    # Pass mmap info to get_or_create_binary so it can compute
    # the load offset once per DSO (only for ET_DYN).
    dso_map_start = param_dict.get("dso_map_start", 0)
    map_pgoff = param_dict.get("map_pgoff", 0)

    # Route each branch to its binary context
    focused_by_binary: dict[str, list[tuple[BinaryContext, dict, dict]]] = {}
    for br, bsym in zip(brstack, brstacksym):
        stats.total += 1
        stats.raw_total_branches += 1
        if br["from_dsoname"] != br["to_dsoname"]:
            stats.crossed += 1
            stats.raw_ignored_branches += 1
            continue

        ctx = get_or_create_binary(br["from_dsoname"], dso_map_start, map_pgoff)
        if ctx is None:
            stats.ignored += 1
            stats.raw_ignored_branches += 1
            continue

        ctx.sample_count += 1
        focused_by_binary.setdefault(ctx.dsoname, []).append((ctx, br, bsym))

    sample_time = param_dict.get("sample", {}).get("time", 0)

    for dsoname, branches in focused_by_binary.items():
        ctx = binaries[dsoname]

        # Duplicate-top-entry filtering per binary
        if (len(branches) >= 2 and
            branches[0][1]["from"] == branches[1][1]["from"] and
            branches[0][1]["to"] == branches[1][1]["to"]):
            br0_from = branches[0][1]["from"]
            br0_to = branches[0][1]["to"]
            if abs(br0_from - br0_to) > args.strip_dup_backedge_stride_limit:
                branches = branches[1:]

        if len(branches) == 0:
            continue

        if sample_time:
            for _, br, _ in branches:
                # Subtract load offset to get file-relative addresses
                from_addr = br["from"] - ctx.load_offset
                to_addr = br["to"] - ctx.load_offset
                ctx.first_address_time.setdefault(from_addr, sample_time)
                ctx.first_address_time.setdefault(to_addr, sample_time)

        for _, br, bsym in branches:
            from_sym = bsym.get("from", "").split("+")[0] if "+" in bsym.get("from", "") else None
            to_sym = bsym.get("to", "").split("+")[0] if "+" in bsym.get("to", "") else None
            # Subtract load offset to get file-relative addresses
            from_addr = br["from"] - ctx.load_offset
            to_addr = br["to"] - ctx.load_offset
            ctx.branch_counts[((from_addr, to_addr), from_sym, to_sym)] += 1

        if len(branches) < 2:
            continue

        for i in range(1, len(branches)):
            _, br, bsym = branches[i]
            _, prev_br, _ = branches[i - 1]

            # Subtract load offset to get file-relative addresses
            begin = br["to"] - ctx.load_offset
            end = prev_br["from"] - ctx.load_offset

            if end < begin:
                continue
            if end - begin > args.insn_range_max:
                continue

            to_sym = bsym.get("to", "").split("+")[0] if "+" in bsym.get("to", "") else None
            ctx.range_counts[((begin, end), to_sym)] += 1
