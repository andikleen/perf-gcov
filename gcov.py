#!/usr/bin/env python3
# generate gcc gcov autofdo files from perf record -b
# gcc -O2 -o workload ...
# perf record -b -c 100003 -e branches:upp workload
# gcov.py --binary workload file.gcov
# gcc -fauto-profile=file.gcov -o workload.opt -O2 ...

# the code is written in typed python using mypy,
# please run make typecheck to verify after changes

# open:
# handle non unique symbols using dwarf (same file)
# check buildid
# output multiple gcovs
# support online mode
# implement suffix elision policy for .
# unit tests

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
ap.add_argument('--binary', help="Generate gcov file for binary")
ap.add_argument('--profile', '-i', help="Profile data. Default perf.data") # handled by perf
ap.add_argument('--gcov', help="gcov output file")
ap.add_argument('--threshold', default=10, type=int, help="Min number of samples for location to output")
ap.add_argument('--verbose', action='store_true', help="Print every sample")
ap.add_argument('--top', default=0, type=int, help="Print N top samples")
ap.add_argument('--dump-dwarf', action='store_true', help="Dump dwarf symbol table")
ap.add_argument('--gcov_version', type=int, help="gcov version. Only 2 supported", default=2)
args = ap.parse_args()

if args.gcov_version != 2:
    sys.exit("Only gcov version 2 is supported")
if args.binary is None:
    sys.exit("Need --binary")

btstate = backtrace.createstate(args.binary)
# XXX which exception to catch?

def trace_begin():
    pass

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
        self.ignored_branches = 0
        self.total_branches = 0
        self.output_branches = 0
        # outermost function name -> profile tree root
        self.tree : dict[str, "FuncNode"] = dict()

    def root(self, name: str) -> "FuncNode":
        node = self.tree.get(name)
        if node is None:
            node = FuncNode(name)
            self.tree[name] = node
        return node

stats = Stats()

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
    assert line >= 0, "line %d" % line
    return (line << 16) | disc

class FuncNode:
    """A node in the profile tree.

    Each node corresponds to one (possibly inlined) function instance.
    Inlined callees are stored as child nodes keyed by the call offset in
    this function and the callee name, mirroring gcc's nested
    GCOV_TAG_AFDO_FUNCTION layout"""
    __slots__ = ("name", "positions", "targets", "children")

    def __init__(self, name: str):
        self.name = name
        # offset -> sample count for positions directly in this instance
        self.positions: Counter[int] = Counter()
        # offset -> {callee name -> count} for resolved call targets
        self.targets: dict[int, Counter[str]] = defaultdict(Counter)
        # (offset, callee name) -> child node for inlined callees
        self.children: dict[tuple[int, str], FuncNode] = dict()

    def child(self, offset: int, name: str) -> "FuncNode":
        key = (offset, name)
        node = self.children.get(key)
        if node is None:
            node = FuncNode(name)
            self.children[key] = node
        return node

    def head_count(self) -> int:
        # Entry/head count of a function instance is the maximum sample
        # count seen, matching how an entry block dominates the body.
        c = max((count for count in self.positions.values()
                 if count >= args.threshold), default=0)
        for child in self.children.values():
            c = max(c, child.head_count())
        return c

def add_path(root: FuncNode, path: list[tuple[str, int]], offset: int,
             count: int, target: str | None) -> None:
    """Accumulate COUNT into the tree.

    PATH is the inline call chain from the outermost real function down to
    (but excluding) the innermost frame, as (function name, call offset)
    pairs. OFFSET is the position offset within the innermost frame and
    TARGET, if set, is a call target recorded at that position."""
    node = root
    for name, off in path:
        node = node.child(off, name)
    node.positions[offset] += count
    if target is not None:
        node.targets[offset][target] += count

def filtered_positions(node: FuncNode) -> list[tuple[int, int, Counter[str]]]:
    positions = []
    for off in sorted(node.positions):
        count = node.positions[off]
        if count < args.threshold:
            continue
        targets = Counter({name: target_count
                           for name, target_count in node.targets.get(off, Counter()).items()
                           if target_count >= args.threshold})
        positions.append((off, count, targets))
    return positions

def emitted_children(node: FuncNode) -> list[tuple[int, str, FuncNode]]:
    return [(coff, cname, child)
            for (coff, cname), child in sorted(node.children.items())
            if child.head_count() > 0]

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

def trace_end():
    print("%d total, %d ignored, %d errored, %d crossed" %
          (stats.total, stats.ignored, stats.errored, stats.crossed))

    if args.top > 0:
        entries: list[tuple[str, int]] = []
        for name, node in stats.tree.items():
            collect_top(entries, name, node)
        for path, count in sorted(entries, key=lambda x: x[1], reverse=True)[:args.top]:
            print(path, "\t", count, "%.2f" % (float(count) / stats.total * 100. if stats.total else 0.0))

    # XXX multiple output files
    string_table, string_index = gen_strtable(stats)
    update_branch_counts(stats)

    with open(args.gcov if args.gcov else args.output, "wb") as f:
        w32(f, GCOV_DATA_MAGIC)
        w32(f, GCOV_VERSION)
        w32(f, 0)

        # write string table
        w32(f, GCOV_TAG_AFDO_FILE_NAMES)
        w32(f, sum((len(s) + 5 for s in string_table)) + 4)
        w32(f, len(string_table))
        for fn in string_table:
            wstring(f, fn)

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
          (stats.total_branches,
           stats.output_branches,
           (float(stats.ignored_branches) / stats.total_branches * 100. if stats.total_branches else 0.0)))

def collect_top(entries: list[tuple[str, int]], prefix: str, node: FuncNode) -> None:
    for off, count in node.positions.items():
        entries.append(("%s:%d" % (prefix, off), count))
    for (coff, cname), child in node.children.items():
        collect_top(entries, "%s/%s@%d" % (prefix, cname, coff), child)

def update_branch_counts(stats: Stats) -> None:
    stats.total_branches = 0
    stats.ignored_branches = 0
    stats.output_branches = 0
    for node in stats.tree.values():
        update_node_branch_counts(node)

def update_node_branch_counts(node: FuncNode) -> None:
    for count in node.positions.values():
        stats.total_branches += count
        if count < args.threshold:
            stats.ignored_branches += count
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
    # offset of a frame relative to its function declaration line
    base = fr.declline if fr.declline else fr.line
    line = fr.line - base
    if line < 0:
        # XXX print warning
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
    for br, bsym in zip(param_dict["brstack"], param_dict["brstacksym"]):
        stats.total += 1
        if br["from_dsoname"] != br["to_dsoname"]:
            stats.crossed += 1
            continue
        if os.path.basename(br["from_dsoname"]) != os.path.basename(args.binary):
            stats.ignored += 1
            continue
        sframes = getframes(br["from"])
        dframes = getframes(br["to"])
        if sframes is None or dframes is None:
            stats.ignored += 1
            continue

        # The outermost frame is the real (symbol table) function; perf
        # gives us its name in bsym. Inner frames are inlined callees.
        sroot_name = sym_name(bsym["from"], sframes[0].sym)
        droot_name = sym_name(bsym["to"], dframes[0].sym)
        if not sroot_name:
            continue

        # innermost frames decide whether this branch is a call leaving the
        # current (possibly inlined) function.
        sinner = sframes[-1]
        dinner = dframes[-1]
        is_call = sinner.sym != dinner.sym

        # Walk the source inline stack from outermost to innermost. The
        # outermost frame is the root function; each deeper frame is an
        # inlined callee reached at the *caller* frame's call offset. The
        # innermost frame holds the branch position.
        names: list[str] = [sroot_name]
        for fr in sframes[1:]:
            if not fr.sym:
                break
            names.append(fr.sym)
        if len(names) != len(sframes):
            # an inlined frame had no resolvable name; skip this branch
            continue
        # callsite path: (callee name, call offset in caller) pairs
        path: list[tuple[str, int]] = []
        for i in range(1, len(sframes)):
            # frame i is reached from frame i-1 at frame i-1's offset
            path.append((names[i], frame_offset(sframes[i - 1])))
        leaf_off = frame_offset(sframes[-1])
        target = None
        if is_call:
            target = droot_name if len(dframes) == 1 else (dinner.sym if dinner.sym else droot_name)
            if not target:
                target = None
        add_path(stats.root(sroot_name), path, leaf_off, 1, target)
