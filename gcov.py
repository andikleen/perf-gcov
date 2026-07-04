#!/usr/bin/env python3
# Generate gcc gcov profile files from perf record -b
# gcc -O2 -o workload ...
# perf record -b -c 100003 -e br_inst_retired.near_taken:upp workload
# gcov.py --binary workload file.gcov
# gcc -fauto-profile=file.gcov -o workload.opt -O2 ...
#
# SPDX-License-Identifier: GPL-3.0-or-later

# the code is written in typed python using mypy,
# please run make typecheck to verify after changes

# open:
# check buildid?
# better way to handle PIE binaries. fix libbacktrace?
# better algorithm for range probing.
# fallback mode using normal samples to handle no LBR support

import os
import sys
from collections import Counter, defaultdict
from functools import lru_cache
from typing import NamedTuple, Any, BinaryIO
from types import ModuleType
import argparse
import fnmatch
import itertools
import subprocess
import pathlib

FRAME_CACHE_MAXSIZE = 65536

# Add script directory to PYTHONPATH to find backtrace module when run from elsewhere
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

backtrace: ModuleType | None
try:
    import backtrace  # type: ignore[import-not-found]
except ModuleNotFoundError:
    backtrace = None
import suffix
from format import *  # noqa: F403

# Define argparse early so --help works without perf re-execution
ap = argparse.ArgumentParser()
ap.add_argument('output', default="file.gcov", nargs='?', help="Output gcov file. Default file.gcov")
ap.add_argument('--binary', '-binary', action='append', default=[],
                help="Binary to profile (fnmatch pattern, repeatable). "
                     "If omitted, auto-discover all binaries.")
ap.add_argument('--profile', '-i', '-profile',
                help="Profile data. Default perf.data")
ap.add_argument('--gcov', '-gcov', help="gcov output file")
ap.add_argument('--profiler', '-profiler',
                help="set profiler type (nop)", choices=["perf"])
ap.add_argument('--threshold', default=10, type=int, help="Min number of samples for location to output")
ap.add_argument('--verbose', action='store_true', help="Be more verbose")
ap.add_argument('--gcov-version', '-gcov_version', type=int, choices=[2, 3], default=3,
                help="GCOV version: 2 (upto gcc 15) or 3 (gcc 16+, default)")
ap.add_argument('--strip-dup-backedge-stride-limit', type=int, default=4096,
                help="Skip duplicate top LBR entry if from-to stride exceeds this. Default 4096")
ap.add_argument('--insn-range-max', type=int, default=1 << 20, help="Max range between branches to probe")
ap.add_argument('--insn-range-stride', type=int, default=0, help="Stride to probe for (0=auto based on profile size)")
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
        if arg.startswith("-profile="):
            data = arg.split("=", 1)[1]
            sys.argv.remove(arg)
            break
        if arg == "--profile" or arg == "-profile" or arg == "-i":
            i = sys.argv.index(arg)
            if i + 1 < len(sys.argv):
                del sys.argv[i]
                data = sys.argv[i]
                del sys.argv[i]
                break
    pargs = [perf, "script", "-i", data, sys.argv[0]] + sys.argv[1:]
    sys.exit(subprocess.run(pargs).returncode)

if backtrace is None:
    sys.exit("backtrace module not found or not matching python perf is built with")

perf_exec_path = os.getenv('PERF_EXEC_PATH')
assert perf_exec_path is not None  # Only reached under perf script
sys.path.append(perf_exec_path + '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

try:
    from perf_trace_context import perf_script_context  # type: ignore[import]
except ImportError:
    sys.exit("Cannot find perf python modules")

args = ap.parse_args()

def vprint(*vals: Any, **kwargs: Any) -> None:
    """Print only if not in quiet mode."""
    if not args.quiet:
        print(*vals, **kwargs)

def trace_begin() -> None:
    pass

# One frame of an inline stack as returned by libbacktrace pcinfo.
Frame = NamedTuple('Frame', [('file', str | None),
                             ('line', int),
                             ('disc', int),
                             ('sym', str | None),
                             ('declline', int)])

class Stats:
    def __init__(self) -> None:
        self.crossed = 0
        self.raw_ignored_branches = 0
        self.raw_total_branches = 0
        self.output_total_positions = 0
        self.output_ignored_positions = 0
        self.output_branches = 0

        # Error/skip counters for diagnostics
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
        self.tree: dict[FuncKey, FuncNode] = {}
        # Range-based profile data (LBR-derived ranges)
        self.range_counts: Counter[tuple[tuple[int, int], str | None]] = Counter()
        # ((from_addr, to_addr), from_sym, to_sym, from_off, to_off) -> count
        self.branch_counts: Counter[tuple[tuple[int, int], str | None, str | None, int | None, int | None]] = Counter()
        # Timestamp tracking: first sample time per function
        self.first_address_time: dict[int, int] = {}
        # Root function name -> first sample timestamp
        self.func_timestamp: dict[FuncKey, int] = {}
        # Sample count for --min-samples filtering
        self.sample_count = 0
        # Whether we have printed per-binary warnings (to avoid spamming)
        self.warned_no_debug: bool = False
        self.warned_neg_line: int = 0

    def root(self, name: str, source_file: str | None = None) -> "FuncNode":
        key = (name, source_file)
        node = self.tree.get(key)
        if node is None:
            node = FuncNode(name, source_file)
            self.tree[key] = node
        return node

# dsoname -> BinaryContext
binaries: dict[str, BinaryContext] = {}

def is_file_dso(dsoname: str) -> bool:
    """Check if DSO is a real file (not kernel, vdso, etc.)."""
    return not dsoname.startswith('[') and '/' in dsoname

@lru_cache(maxsize=None)
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
    """Check if binary matches --binary patterns.

    Matches the DSO against user-provided patterns using three strategies
    (any match suffices):
      1. fnmatch full DSO path against the raw pattern
      2. fnmatch DSO basename against the raw pattern
      3. fnmatch DSO basename against the pattern's basename

    Strategy 3 handles the case where the binary was built in a different
    directory than where it was deployed/perf'd. This mirrors autofdo's
    approach of extracting the basename and matching against DSO basenames.

    """
    if not args.binary:
        return True
    dso_basename = os.path.basename(dsoname)
    for pat in args.binary:
        # Strategy 1: full path match
        if fnmatch.fnmatch(dsoname, pat):
            return True
        # Strategy 2: DSO basename against full pattern
        if fnmatch.fnmatch(dso_basename, pat):
            return True
        # Strategy 3: DSO basename against pattern's basename (autofdo-style)
        pat_basename = os.path.basename(pat)
        if pat_basename and fnmatch.fnmatch(dso_basename, pat_basename):
            return True
    return False

def get_or_create_binary(dsoname: str, dso_map_start: int = 0, map_pgoff: int = 0) -> BinaryContext | None:
    """Get or create BinaryContext for a DSO."""
    if dsoname in binaries:
        return binaries[dsoname]

    if not is_file_dso(dsoname):
        return None

    if not should_process_binary(dsoname):
        return None

    try:
        btstate = backtrace.createstate(dsoname)  # type: ignore[union-attr]
    except Exception as e:
        print(f"warning: cannot create backtrace state for {dsoname}: {e}", file=sys.stderr)
        return None

    ctx = BinaryContext(dsoname)
    ctx.btstate = btstate
    # Only ET_DYN files (PIE/shared library) need load offset subtraction.
    if is_position_independent(dsoname):
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
    __slots__ = ("name", "source_file", "positions", "targets", "children", "structural_zeros", "head_count_value")

    def __init__(self, name: str, source_file: str | None = None):
        self.name = name
        self.source_file = source_file  # basename from DWARF
        # offset -> sample count for positions directly in this instance
        self.positions: Counter[int] = Counter()
        # offset -> {callee name -> count} for resolved call targets
        self.targets: dict[int, Counter[FuncKey]] = defaultdict(Counter)
        # (offset, callee name) -> child node for inlined callees
        self.children: dict[tuple[int, str, str | None], FuncNode] = dict()
        # Offsets that must be emitted even with count=0 and no targets.
        # These mark scaffolding positions (function entry/exit boundaries).
        # NOTE: This is runtime-only state used during tree construction;
        # it is not directly persisted to the GCOV file format.
        self.structural_zeros: set[int] = set()
        self.head_count_value: int = 0

    def child(self, offset: int, name: str, source_file: str | None = None) -> "FuncNode":
        key = (offset, name, source_file)
        node = self.children.get(key)
        if node is None:
            node = FuncNode(name, source_file)
            self.children[key] = node
        return node

    def head_count(self) -> int:
        return self.head_count_value

    def has_output(self) -> bool:
        if filtered_positions(self):
            return True
        return any(child.has_output() for child in self.children.values())

def add_path(root: FuncNode, path: list[tuple[str, int]], offset: int,
             count: int, target: FuncKey | None,
             inline_source_files: list[str | None] | None = None) -> None:
    node = root
    for i, (name, off) in enumerate(path):
        src_file = inline_source_files[i] if inline_source_files and i < len(inline_source_files) else None
        node = node.child(off, name, src_file)
    node.positions[offset] += count
    if target is not None:
        node.targets[offset][target] += count

def filtered_positions(node: FuncNode) -> list[tuple[int, int, Counter[FuncKey]]]:
    positions = []
    child_offsets = {coff for (coff, _, _) in emitted_children(node)}
    for off in sorted(node.positions):
        if off in child_offsets:
            continue
        count = node.positions[off]
        targets = Counter({key: target_count
                           for key, target_count in node.targets.get(off, Counter()).items()
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
            for (coff, cname, csrc), child in sorted(node.children.items())
            if child.has_output()]

def wfunc_node(f: BinaryIO, node: FuncNode, offset: int,
               entry_index: dict[FuncKey, int],
               toplevel: bool, ctx: BinaryContext) -> None:
    node_key = (node.name, node.source_file)
    if toplevel:
        wcounter(f, node.head_count())
        if args.gcov_version >= 3:
            ts = ctx.func_timestamp.get(node_key, 0)
            wcounter(f, ts)  # first sample timestamp (nanoseconds)
        w32(f, entry_index[node_key])
    else:
        w32(f, offset)
        w32(f, entry_index[node_key])
    positions = filtered_positions(node)
    children = emitted_children(node)

    # number of positions and number of inlined callees
    w32(f, len(positions))
    w32(f, len(children))

    for off, count, targets in positions:
        w32(f, off)
        w32(f, len(targets))
        wcounter(f, count)
        for tkey, tcount in targets.most_common():
            w32(f, HIST_TYPE_INDIR_CALL_TOPN)
            wcounter(f, entry_index[tkey])
            wcounter(f, tcount)

    for coff, _, child in children:
        wfunc_node(f, child, coff, entry_index, False, ctx)

def gen_strtable(tree: dict[str, FuncNode]) -> tuple[list[str], dict[str, int]]:
    strings: set[str] = set()
    for node in tree.values():
        _collect_strings_v2(node, strings)
    # Index 0 must be empty (reserved by GCC)
    string_table = [""] + sorted(strings)
    string_index = {name: i for i, name in enumerate(string_table)}
    return string_table, string_index


def _collect_strings_v2(node: FuncNode, out: set[str]) -> None:
    out.add(node.name)
    # Collect target function names so string_index entries exist for
    # indirect call targets whose names aren't in the profile tree.
    for targets in node.targets.values():
        for tkey in targets:
            out.add(tkey[0] if isinstance(tkey, tuple) else tkey)
    for _, _, child in emitted_children(node):
        _collect_strings_v2(child, out)

def gen_strtable_v3(
    ctx: BinaryContext,
) -> tuple[list[str], dict[str, int], list[tuple[str, int]], dict[FuncKey, int]]:
    """Generate file table and function entry list for GCOV v3 format.

    Returns:
        file_table: sorted list of source file names
        file_index: source_file → index mapping
        entries: list of (function_name, file_index) pairs (allows duplicate names)
        entry_index: (name, source_file) → position in entries list
    """
    source_files: set[str] = set()
    func_to_file: dict[FuncKey, str | None] = {}

    # Collect from tree roots
    for (name, src_file), node in ctx.tree.items():
        if src_file:
            source_files.add(src_file)
        func_to_file[(name, src_file)] = src_file
        collect_strings_v3(ctx, node, source_files, func_to_file)

    # Build file table and index
    file_table = sorted(source_files)
    file_index = {fname: i for i, fname in enumerate(file_table)}

    # Build ordered entry list (allows duplicate names with different files)
    entries: list[tuple[str, int]] = []
    entry_index: dict[FuncKey, int] = {}
    for key in sorted(ctx.tree, key=lambda k: (k[0], k[1] or "")):
        name, src_file = key
        file_idx = file_index.get(src_file, -1) if src_file else -1
        entry_index[key] = len(entries)
        entries.append((name, file_idx))

    # Add entries for target functions not in the tree
    for key in func_to_file:
        if key not in entry_index:
            name, src_file = key
            file_idx = file_index.get(src_file, -1) if src_file else -1
            entry_index[key] = len(entries)
            entries.append((name, file_idx))

    return file_table, file_index, entries, entry_index

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
            # Exclude scaffolding zeros (gcov.py injects them; autofdo doesn't)
            if count > 0:
                total_count += count
                max_count = max(max_count, count)
                num_counts += 1
                count_frequencies[count] = count_frequencies.get(count, 0) + 1

        # Recursively traverse inlined children (callsites)
        for (call_offset, callee_name, callee_src), child in node.children.items():
            traverse_node(child, is_root=False)

    # Traverse all top-level functions
    for key, func_node in ctx.tree.items():
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

def collect_strings_v3(ctx: BinaryContext, node: FuncNode, files: set[str],
                       func_to_file: dict[FuncKey, str | None]) -> None:
    """Recursively collect source files and func_to_file mappings for v3 format."""
    key = (node.name, node.source_file)
    if node.source_file:
        files.add(node.source_file)
    if key not in func_to_file:
        func_to_file[key] = node.source_file

    # Collect from call targets
    for _, _, targets in filtered_positions(node):
        for tkey in targets.keys():
            _, tsrc = tkey
            if tsrc:
                files.add(tsrc)
            if tkey not in func_to_file:
                func_to_file[tkey] = tsrc

    # Recurse into inline children
    for _, _, child in emitted_children(node):
        collect_strings_v3(ctx, child, files, func_to_file)

def expand_ranges(ctx: BinaryContext) -> None:
    """Expand range_counts into position counts in the profile tree for one binary.

    Overlapping ranges SUM per address, then addresses mapping to the same
    source (line,disc) take MAX. Matches autofdo: profile.cc:173 (SUM),
    symbol_map.cc:572-573 (MAX)."""

    vprint(f"Expanding {len(ctx.range_counts)} ranges for {os.path.basename(ctx.dsoname)}...")

    if args.verbose:
        print("\nRange counts:")
        for (begin, end), sym in ctx.range_counts.keys():
            count = ctx.range_counts[((begin, end), sym)]
            print(f"  [{begin:x}-{end:x}] ({sym}): count={count}")


    address_count: dict[int, int] = defaultdict(int)
    address_sym: dict[int, str | None] = {}

    for ((begin, end), range_sym), range_count in ctx.range_counts.items():
        for addr in range(begin, end + 1, args.insn_range_stride):
            frames = getframes(ctx, addr)
            if frames is None:
                continue

            address_count[addr] += range_count
            if addr not in address_sym:
                address_sym[addr] = range_sym


    position_max_counts: dict[tuple[str, str | None, tuple[tuple[str, int], ...], int], int] = {}
    position_source_files: dict[tuple[str, str | None, tuple[tuple[str, int], ...], int], tuple[str | None, list[str | None]]] = {}

    for addr, addr_count in address_count.items():
        frames = getframes(ctx, addr)
        if frames is None:
            continue

        root_frame = frames[0]
        if not root_frame.sym:
            stats.missing_symbols += 1
            continue

        perf_sym = address_sym.get(addr)
        if perf_sym and root_frame.sym in perf_sym:
            root_name = perf_sym
        else:
            root_name = root_frame.sym
        root_source_file = root_frame.file if root_frame.file else None


        names: list[str] = [root_name]
        source_files: list[str | None] = [root_source_file]
        for fr in frames[1:]:
            if not fr.sym:
                break
            names.append(fr.sym)
            source_files.append(fr.file if fr.file else None)

        if len(names) != len(frames):
            stats.incomplete_stacks += 1
            continue

        path: list[tuple[str, int]] = []
        for i in range(1, len(frames)):
            path.append((names[i], frame_offset(frames[i - 1], ctx)))

        leaf_off = frame_offset(frames[-1], ctx)
        path_tuple = tuple(path)
        pos_key = (root_name, root_source_file, path_tuple, leaf_off)

        if pos_key not in position_max_counts or addr_count > position_max_counts[pos_key]:
            position_max_counts[pos_key] = addr_count
            position_source_files[pos_key] = (root_source_file, source_files[1:])

    for pos_key, count in position_max_counts.items():
        root_name, root_source_file, path_tuple, leaf_off = pos_key
        path = list(path_tuple)
        _, inline_source_files = position_source_files[pos_key]
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

def add_branch_targets(ctx: BinaryContext) -> None:
    """Add call targets from branch_counts to the profile tree for one binary."""

    vprint(f"Adding call targets from {len(ctx.branch_counts)} branches for {os.path.basename(ctx.dsoname)}...")
    added_targets = 0

    for ((from_addr, to_addr), from_sym, to_sym, from_off, to_off), count in ctx.branch_counts.items():
        sframes = getframes(ctx, from_addr)
        dframes = getframes(ctx, to_addr)

        if sframes is None or dframes is None:
            continue

        sroot = sframes[0]
        droot = dframes[0]
        is_call = sroot.sym != droot.sym

        if not is_call:
            continue

        # Distinguish CALL from RET: use perf's symbol offset.
        # A CALL lands at the function entry (offset 0 or no offset);
        # a RET lands at a return site inside the caller (non-zero offset).
        if to_off is not None and to_off > 0:
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

        sroot_source_file = sroot.file if sroot.file else None
        droot_source_file = droot.file if droot.file else None

        root = ctx.root(sroot_name, sroot_source_file)
        names: list[str] = [sroot_name]
        source_files: list[str | None] = []
        for fr in sframes[1:]:
            if not fr.sym:
                break
            names.append(fr.sym)
            source_files.append(fr.file if fr.file else None)

        if len(names) != len(sframes):
            continue

        path: list[tuple[str, int]] = []
        for i in range(1, len(sframes)):
            path.append((names[i], frame_offset(sframes[i - 1], ctx)))

        if droot_name and (droot_name, droot_source_file) not in ctx.func_timestamp:
            branch_time = ctx.first_address_time.get(from_addr)
            if branch_time:
                ctx.func_timestamp[(droot_name, droot_source_file)] = branch_time

        if not droot_name:
            continue
        target = (droot_name, droot_source_file)

        leaf_off = frame_offset(sframes[-1], ctx)
        node = root
        for i, (name, off) in enumerate(path):
            src_file = source_files[i] if i < len(source_files) else None
            node = node.child(off, name, src_file)
        node.positions.setdefault(leaf_off, 0)
        node.targets[leaf_off][target] += count
        added_targets += 1

    vprint(f"Added {added_targets} call targets")

def propagate_head_counts(tree: dict[FuncKey, FuncNode]) -> None:
    """Sum incoming call targets per callee and store as head_count_value."""
    incoming: Counter[FuncKey] = Counter()

    def walk(node: FuncNode) -> None:
        for targets in node.targets.values():
            for callee_key, count in targets.items():
                incoming[callee_key] += count
        for child in node.children.values():
            walk(child)

    for root in tree.values():
        walk(root)

    for callee_key, count in incoming.items():
        node = tree.get(callee_key)
        if node is not None:
            node.head_count_value = count

def propagate_timestamps(ctx: BinaryContext) -> None:
    """Resolve unique LBR FROM addresses to per-function timestamps.

    Iterates first_address_time (unique FROM addresses from LBR entries),
    resolves each to a function via getframes (cache-hot after expand_ranges),
    and records the minimum sample time per function.
    """
    for addr, sample_time in ctx.first_address_time.items():
        frames = getframes(ctx, addr)
        if frames is None:
            continue
        root = frames[0]
        if not root.sym:
            continue
        root_name = root.sym
        root_source_file = root.file if root.file else None
        root_key = (root_name, root_source_file)
        old = ctx.func_timestamp.get(root_key)
        if old is None or sample_time < old:
            ctx.func_timestamp[root_key] = sample_time
def add_dwarf_zero_scaffolding(ctx: BinaryContext) -> None:
    """Add zero-count positions at function boundaries for one binary."""

    added_zeros = 0

    for key, node in ctx.tree.items():
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
    # Write to a temp file first, then atomically rename to output_path.
    # This prevents partial/corrupt files if the process is interrupted.
    tmp_path = output_path + ".tmp"
    try:
        with open(tmp_path, "wb") as f:
            w32(f, GCOV_DATA_MAGIC)
            w32(f, args.gcov_version)
            w32(f, 0)

            if args.gcov_version == 3:
                summary = compute_summary(ctx)
                write_summary(f, summary)
                vprint(f"Summary: {summary['num_functions']} functions, {summary['num_counts']} counts, total={summary['total_count']}")

            w32(f, GCOV_TAG_AFDO_FILE_NAMES)

            entry_index: dict[FuncKey, int] = {}
            if args.gcov_version == 2:
                v2_tree = make_v2_merged_tree(ctx.tree)
                string_table, string_index = gen_strtable(v2_tree)
                length = 4 + sum((4 + wstring_nbytes(s)) for s in string_table)
                w32(f, length)
                w32(f, len(string_table))
                for fn in string_table:
                    wstring(f, fn)

                vprint("Writing %d functions to %s" % (len(v2_tree), output_path))
                write_v2_function_section(f, v2_tree, string_index, args.threshold)
                write_gcov_tail(f)

            elif args.gcov_version == 3:
                file_table, file_index, entries, entry_index = gen_strtable_v3(ctx)

                length = 4
                length += sum(4 + wstring_nbytes(fname) for fname in file_table)
                length += 4
                length += sum(4 + wstring_nbytes(name) + 4 for name, _ in entries)

                w32(f, length)

                w32(f, len(file_table))
                for fname in file_table:
                    wstring(f, fname)

                w32(f, len(entries))
                for func_name, file_idx in entries:
                    wstring(f, func_name)
                    w32(f, file_idx if file_idx >= 0 else 0xFFFFFFFF)

                w32(f, GCOV_TAG_AFDO_FUNCTION)
                lenoff = f.tell()
                w32(f, 0)

                vprint("Writing %d functions to %s" % (len(ctx.tree), output_path))
                w32(f, len(ctx.tree))
                for key in sorted(ctx.tree, key=lambda k: (k[0], k[1] or "")):
                    wfunc_node(f, ctx.tree[key], 0, entry_index, True, ctx)

                if not pathlib.Path(f.name).is_fifo():
                    endoff = f.tell()
                    f.seek(lenoff, 0)
                    vprint("Data length %d" % (endoff - lenoff))
                    w32(f, endoff - lenoff)
                    f.seek(endoff, 0)

                write_gcov_tail(f)

        os.rename(tmp_path, output_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    print(f"Wrote {output_path}")
    return True

def trace_end() -> None:
    vprint("%d raw branches, %d filtered, %d crossed" %
           (stats.raw_total_branches, stats.raw_ignored_branches,
            stats.crossed))

    # Filter binaries by --min-samples
    active_binaries = {dsoname: ctx for dsoname, ctx in binaries.items()
                       if ctx.sample_count >= args.min_samples}

    if len(active_binaries) == 0:
        print("No binaries with sufficient samples", file=sys.stderr)
        return

    # Process each binary
    for dsoname, ctx in active_binaries.items():
        basename = os.path.basename(dsoname)

        # Auto-tune insn-range-stride: if not user-specified, scale stride
        # to keep the number of probed addresses manageable (~100K max).
        if args.insn_range_stride == 0:
            total_span = sum(end - begin + 1 for ((begin, end), _), _ in ctx.range_counts.items())
            # Target ~100K address lookups max; scale stride to match
            auto_stride = max(1, total_span // 100000)
            # Round up to next power of 2 for nice stride values
            if auto_stride > 1:
                auto_stride = 1 << auto_stride.bit_length()
            auto_stride = min(auto_stride, 256)
            if auto_stride != 1:
                vprint(f"  {basename}: auto stride={auto_stride} (total_span={total_span})")
        else:
            auto_stride = args.insn_range_stride
        args.insn_range_stride = auto_stride

        vprint(f"\nProcessing {basename} ({ctx.sample_count} samples, stride={auto_stride})...")
        expand_ranges(ctx)
        add_branch_targets(ctx)
        propagate_head_counts(ctx.tree)
        propagate_timestamps(ctx)
        add_dwarf_zero_scaffolding(ctx)
        suffix.elide_tree_suffixes(ctx.tree, args.suffix_elision)

    # Determine output filenames.
    # Priority: --output-dir > --gcov (single binary) > default.
    if args.gcov and len(active_binaries) > 1:
        print("warning: --gcov ignored in multi-binary mode", file=sys.stderr)
    output_paths: dict[str, str] = {}
    used_paths: set[str] = set()
    for dsoname in active_binaries:
        basename = os.path.basename(dsoname)
        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            path = os.path.join(args.output_dir, f"{basename}.gcov")
        elif args.gcov and len(active_binaries) == 1:
            path = args.gcov
        elif len(active_binaries) == 1:
            path = args.output
        else:
            path = f"{basename}.gcov"
        if path in used_paths:
            print(f"warning: output conflict for {dsoname}, skipping", file=sys.stderr)
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

    if stats.missing_symbols > 0:
        vprint(f"Note: {stats.missing_symbols} frames had no symbol names")
    if stats.incomplete_stacks > 0:
        vprint(f"Note: {stats.incomplete_stacks} inline stacks were incomplete")

    # Warn about binaries with samples but no debug info
    for dsoname, ctx in active_binaries.items():
        if ctx.sample_count > 0 and not ctx.tree and not ctx.warned_no_debug:
            basename = os.path.basename(dsoname)
            vprint(f"{basename} has {ctx.sample_count} samples but no debug info "
                   f"({dsoname})")
            ctx.warned_no_debug = True

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
@lru_cache(maxsize=FRAME_CACHE_MAXSIZE)
def getframes(ctx: BinaryContext, ip: int) -> list[Frame] | None:
    """Cached lookup of inline call stack for address in a specific binary."""
    p = backtrace.pcinfo(ctx.btstate, ip)  # type: ignore[union-attr]
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

def frame_offset(fr: Frame, ctx: BinaryContext) -> int:
    """Calculate offset of a frame relative to its function declaration line.

    Args:
        fr: Frame with line, declline, and discriminator info
        ctx: Binary context (for per-binary warning throttling)

    Returns:
        Encoded offset (line << 16 | discriminator)
    """
    # Offset of a frame relative to its function declaration line
    base = fr.declline if fr.declline else fr.line
    line = fr.line - base
    if line < 0:
        # Negative offsets indicate DWARF inconsistency (line before declaration)
        # This can happen with inlined code or compiler-generated code
        if args.verbose and ctx.warned_neg_line < 10:
            print(f"WARNING: Negative line offset clamped to 0: "
                  f"function={fr.sym}, line={fr.line}, base={base}",
                  file=sys.stderr)
            ctx.warned_neg_line += 1
            if ctx.warned_neg_line == 10:
                print("WARNING: (further negative offsets suppressed)",
                      file=sys.stderr)
        elif not ctx.warned_neg_line and not args.quiet:
            print("WARNING: Negative line offset clamped to 0 (use --verbose for details)",
                  file=sys.stderr)
            ctx.warned_neg_line = 1
        line = 0
    return gen_offset(line, fr.disc)


def process_event(param_dict: dict[str, Any]) -> None:
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
    sample_time = param_dict.get("sample", {}).get("time", 0)
    sample_ip = param_dict.get("sample", {}).get("ip", 0)

    # Track the most-recently-seen branch per binary for
    # duplicate-backedge filtering and range computation.
    last_branch: dict[str, dict] = {}

    for br, bsym in zip(brstack, brstacksym):
        stats.raw_total_branches += 1
        if br["from_dsoname"] != br["to_dsoname"]:
            stats.crossed += 1
            stats.raw_ignored_branches += 1
            continue
        # Cheap pre-filter: skip non-file DSOs
        if not is_file_dso(br["from_dsoname"]):
            stats.raw_ignored_branches += 1
            continue

        dsoname = br["from_dsoname"]
        ctx = get_or_create_binary(dsoname, dso_map_start, map_pgoff)
        if ctx is None:
            stats.raw_ignored_branches += 1
            continue

        ctx.sample_count += 1

        # Duplicate-backedge filter: skip if this branch matches the
        # most-recently-seen branch from the same binary
        prev = last_branch.get(dsoname)
        if prev is not None and prev["from"] == br["from"] and prev["to"] == br["to"]:
            if abs(br["from"] - br["to"]) > args.strip_dup_backedge_stride_limit:
                continue

        last_branch[dsoname] = br

        bs_from = bsym.get("from", "")
        bs_to = bsym.get("to", "")
        from_parts = bs_from.rsplit("+", 1)
        to_parts = bs_to.rsplit("+", 1)
        from_sym = from_parts[0] if from_parts[0] else None
        to_sym = to_parts[0] if to_parts[0] else None
        try:
            from_off = int(from_parts[1], 16) if len(from_parts) > 1 else None
            to_off = int(to_parts[1], 16) if len(to_parts) > 1 else None
        except ValueError:
            print("parse error", bs_from, bs_to)
            return
        # Subtract load offset to get file-relative addresses
        from_addr = br["from"] - ctx.load_offset
        to_addr = br["to"] - ctx.load_offset
        ctx.branch_counts[((from_addr, to_addr), from_sym, to_sym, from_off, to_off)] += 1
        if sample_time and sample_ip:
            ctx.first_address_time.setdefault(sample_ip - ctx.load_offset, sample_time)
        # Range between this branch's target and the previous same-binary branch's source
        if prev is not None:
            end = prev["from"] - ctx.load_offset
            if end >= to_addr and end - to_addr <= args.insn_range_max:
                ctx.range_counts[((to_addr, end), to_sym)] += 1
