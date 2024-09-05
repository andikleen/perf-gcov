# generate gcc gcov autofdo files from perf record -b
# gcc -O2 -o workload ...
# perf record -b -c 100003 -e branches:upp workload
# perf script gcov.py --binary workload file.gcov
# gcc -fauto-profile=file.gcov -o workload.opt -O2 ...

# open:
# callers inline stack
# handle non unique symbols
# lookup based on buildid
# output multiple gcovs
# unit tests

import os
import sys
import pprint
from collections import Counter, defaultdict, namedtuple
from itertools import groupby
from struct import pack
import struct
from typing import BinaryIO, NamedTuple
import argparse
import os.path
import subprocess

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
	'/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import perf_script_context, perf_brstack_srcline, perf_resolve_ip

ap = argparse.ArgumentParser()
ap.add_argument('output', default="file.gcov", nargs='?', help="Output gcov file. Default file.gcov")
ap.add_argument('--threshold', default=10, help="Min number of samples for location to output")
ap.add_argument('--verbose', action='store_true', help="Print every sample")
ap.add_argument('--top', default=0, help="Print N top samples")
ap.add_argument('--binary', action='append', help="Only use samples for binary specified as basename. Can be used multiple times.", default=[])
args = ap.parse_args()

def trace_begin():
    pass

GCOV_TAG_AFDO_FILE_NAMES = 0xaa000000
GCOV_TAG_AFDO_FUNCTION = 0xac000000
GCOV_TAG_AFDO_MODULE_GROUPING = 0xae000000
GCOV_TAG_AFDO_WORKING_SET = 0xaf000000
GCOV_DATA_MAGIC = 0x67636461 # 'gcda'
GCOV_VERSION = 2
HIST_TYPE_INDIR_CALL_TOPN = 7

Location = NamedTuple('Location', [('sym', str),
                                   ('srcid', int),
                                   ('offset', int),
                                   ('exeid', int)])
Key = NamedTuple('Key', [('src', Location),
                         ('dst', Location)])
Branch = NamedTuple('Branch', [('src', Location),
                               ('dst', Location),
                               ('count', int)])
Inline = NamedTuple('Inline', [('fileid', int),
                               ('name', str),
                               ('offset', int)])

class Stats:
    def __init__(self):
        self.ignored = 0
        self.errored = 0
        self.crossed = 0
        self.total = 0
        self.branches : Counter[Key] = Counter()
        # XXX need file id to handle non unique
        self.functions : set[str] = set()
        self.filenames : dict[str,int] = dict()
        self.exenames : dict[str, int] = dict()
        self.inlinestacks : dict[tuple[int, int], list[Inline]] = dict()
        self.next_id = 0

stats = Stats()

# to generate inline relative offsets need the abstract origin of the inlines
# this requires reading the .debug_info because perf doesn't know it because the
# libraries/programs it uses don't supply
# XXX doesn't handle functions with non unique names correctly
def read_sym_lines(exe: str) -> dict[str, int] :
    with subprocess.Popen(["objdump", "-e", exe, "-Wi"], stdout=subprocess.PIPE, universal_newlines=True) as p:
        d = {}
        seen = 0
        name = ""
        line = 0
        assert p.stdout is not None
        for l in p.stdout:
            n = l.split()
            if len(n) < 4:
                continue
            if n[1] == "Abbrev":
                seen = 0
                if len(n) >= 5 and n[4] == "(DW_TAG_subprogram)":
                    seen = 1
            if n[1] == "DW_AT_name" and seen == 1:
                name = n[3]
                if name == "(indirect":
                    name = n[7]
                seen += 1
            if n[1] == "DW_AT_decl_line" and seen == 2:
                line = int(n[3])
                seen += 1
            if n[1] == "DW_AT_inline" and n[3] == "1" and seen == 3:
                d[name] = line
                seen = 0
        return d

sym_lines : dict[str, dict[str, int]] = {}
warned : set[str] = set()

def find_sym_line(exe: str, sym: str) -> int:
    if exe not in sym_lines:
        sym_lines[exe] = read_sym_lines(exe)
    if sym in sym_lines[exe]:
        return sym_lines[exe][sym]
    if sym not in warned:
        print("cannot find symbol %s in %s" % (sym, exe))
        warned.add(sym)
    return 0

def w32(f: BinaryIO, v: int):
    try:
        f.write(pack("I", v))
    except struct.error:
        sys.exit("bad value for w32 %x" % v)

def wstring(f: BinaryIO, s: str):
    s += "\0"
    w32(f, len(s))
    f.write(pack("%ds" % len(s), s.encode('utf-8')))

def wcounter(f: BinaryIO, v: int):
    w32(f, (v       ) & 0xffffffff)
    w32(f, (v >> 32 ) & 0xffffffff)

def gen_offset(line: int, disc: int) -> int:
    assert line >= 0, "line %d" % line
    return (line << 16) | disc

def wfunc_instance(f: BinaryIO,
                   all_branches: list[Branch],
                   string_index: dict[str, int],
                   func: str) -> None:
    sbranches = sorted(all_branches, key=lambda x: x.src)
    wcounter(f, sum((x.count for x in all_branches)))
    w32(f, string_index[func])
    num = 0
    for src, branchit in groupby(sbranches, lambda x: x.src):
        if sum((b.count for b in branchit)) < args.threshold:
            continue
        num += 1
    w32(f, num)
    w32(f, 0) # call sites XXX

    for src, branchit in groupby(sbranches, lambda x: x.src):
        branches = list(branchit)
        count = sum((b.count for b in branches))
        if count < args.threshold:
            continue
        # file contains only source offset
        # target is implicitly known by the compiler
        w32(f, branches[0].src.offset)
        num_calls = sum((1 if b.src.sym != b.dst.sym and b.count >= args.threshold else 0 for b in branches))
        w32(f, num_calls)
        wcounter(f, count)

        if args.verbose:
            print(branches[0], len(branches), "count", count, "num_calls", num_calls)
        # also dump call targets to other functions
        if num_calls > 0:
            for b in branches:
                # should check branch type to see if it could be recursion
                # otherwise cannot distinguish from an ordinary branch
                # however this wouldn't work for recursive tail calls?
                if b.dst.sym == b.src.sym:
                    continue
                if b.count < args.threshold:
                    continue
                w32(f, HIST_TYPE_INDIR_CALL_TOPN)
                wcounter(f, string_index[b.dst.sym])
                wcounter(f, b.count)
                
    # dump inline stack

def gen_strtable(stats: Stats):
    string_table = sorted(stats.functions)
    string_index = { name: i for i, name in enumerate(string_table) }
    return string_table, string_index

def gen_func_table(stats: Stats) -> defaultdict[str, list[Branch]]:
    func_table: defaultdict[str, list[Branch]] = defaultdict(list)
    # XXX handle non unique symbols. file match?
    for k, count in stats.branches.items():
        func_table[k.src.sym].append(Branch(k.src, k.dst, count))
    return func_table

def trace_end():
    print("%d total, %d ignored, %d errored, %d crossed" %
          (stats.total, stats.ignored, stats.errored, stats.crossed), file=sys.stderr)

    if args.top > 0:
        for a, b in stats.branches.most_common(args.top):
            print(a, "\t", b, "%.2f" % (float(b)/stats.total*100.), file=sys.stderr)

    string_table, string_index = gen_strtable(stats)
    func_table = gen_func_table(stats)

    with open(args.output, "wb") as f:
        w32(f, GCOV_DATA_MAGIC)
        w32(f, GCOV_VERSION)
        w32(f, 0)

        # write string table
        w32(f, GCOV_TAG_AFDO_FILE_NAMES)
        w32(f, sum((len(s) + 1 for s in string_table)))
        w32(f, len(string_table))
        for fn in string_table:
            wstring(f, fn)

        # write function profile
        w32(f, GCOV_TAG_AFDO_FUNCTION)
        w32(f, 0) # length. ignored by gcc. XXX fill in
        w32(f, len(stats.functions))
        for func in stats.functions:
            wfunc_instance(f, func_table[func], string_index, func)

        # not used by gcc
        w32(f, GCOV_TAG_AFDO_MODULE_GROUPING)
        w32(f, 0)
        w32(f, 0)

        w32(f, GCOV_TAG_AFDO_WORKING_SET)
        w32(f, 0)
        w32(f, 0)
        
def get_id(d: dict[str,int], fn:str) -> int:
    if fn in d:
        fid = d[fn]
    else:
        fid = stats.next_id
        stats.next_id += 1
        d[fn] = fid
    return fid

def get_fid(fn:str) -> int:
    return get_id(stats.filenames, fn)

def get_eid(fn:str) -> int:
    return get_id(stats.exenames, fn)

def fmtres(x):
    return "%s at %s:%d:%d" % (x[3], x[0], x[1], x[2])

# XXX cache
# XXX add file id
def gen_inline(exe: str, il: tuple[tuple[str,int,int,str], ...]) -> list[Inline]:
    def inline_tuple(x : tuple[str,int,int,str]) -> Inline:
        sl = find_sym_line(exe, x[3])
        if sl == 0 or sl > x[2]:
            if args.verbose:
                print("Cannot resolve inline %s" % (fmtres(x)))
            return Inline(0, "", 0)
        return Inline(get_fid(x[0]), x[3], gen_offset(x[1] - sl, x[2]))
    return [inline_tuple(x) for x in il]

def process_event(param_dict):
    for br, bsym in zip(param_dict["brstack"], param_dict["brstacksym"]):
        #pprint.pp(br)
        stats.total += 1
        if br["from_dsoname"] != br["to_dsoname"]:
            stats.crossed += 1
            continue
        res = perf_brstack_srcline(perf_script_context, br)
        if res[0] is None or res[1] is None:
            stats.ignored += 1
            continue

        def resolve(res:tuple[str, int, int, str, str, tuple[tuple[str,int,int,str], ...]],
                    s:str,
                    ip:int) -> Location:
            if args.binary and os.path.basename(res[3]) not in args.binary:
                return Location("", 0, 0, 0)
            if "+" in s:
                sym, ipoff = s.split("+")
                stats.functions.add(sym)
                symip = ip - int(ipoff, 16)
                symres = perf_resolve_ip(perf_script_context, symip)
                if symres:
                    if symres[0] == res[0]:
                        fid = get_fid(res[0])
                        if res[1] < symres[1]:
                            if args.verbose:
                                print("symbol %s %s sample %s has negative line offset" % (
                                    sym, fmtres(symres), fmtres(res)))
                            return Location("", 0, 0, 0)
                        return Location(sym, fid, gen_offset(res[1] - symres[1], res[2]), get_eid(res[3]))
            return Location("", 0, 0, 0)
        key = Key(resolve(res[0], bsym["from"], br["from"]), resolve(res[1], bsym["to"], br["to"]))
        if not key.src.sym or not key.dst.sym:
            stats.errored += 1
            continue
        stats.branches[key] += 1
        if res[0][5]:
            ikey = (get_eid(res[0][3]), br["from"])
            if ikey not in stats.inlinestacks:
                stats.inlinestacks[ikey] = gen_inline(res[0][3], res[0][5])
