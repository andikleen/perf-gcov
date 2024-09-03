# generate gcc gcov autofdo files from perf record -b
# gcc -O2 -o workload ...
# perf record -b workload
# perf script gcov.py > file.gcov
# gcc -fauto-profile=file.gcov -o workload.opt -O2 ...

# open:
# threshold
# callers inline stack (need perf change)
# focus binary
# call sites
# handle non unique symbols
# output multiple gcovs based on buildid
# unit tests

import os
import sys
import pprint
from collections import Counter, defaultdict, namedtuple
from itertools import groupby
from struct import pack
from typing import BinaryIO, NamedTuple

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
	'/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import perf_script_context, perf_brstack_srcline, perf_resolve_ip

def trace_begin():
    pass

GCOV_TAG_AFDO_FILE_NAMES = 0xaa000000
GCOV_TAG_AFDO_FUNCTION = 0xac000000
GCOV_TAG_AFDO_MODULE_GROUPING = 0xae000000
GCOV_TAG_AFDO_WORKING_SET = 0xaf000000
GCOV_DATA_MAGIC = 0x67636461 # 'gcda'
GCOV_VERSION = 2
HIST_TYPE_INDIR_CALL_TOPN = 7

Location = NamedTuple('Location', [('sym', str), ('fileid', int), ('offset', int)])
Key = NamedTuple('Key', [('src', Location), ('dst', Location)])
Callsite = NamedTuple('Callsite', [('callersym', str), ('offset', int),
				   ('callers', list[Location]), ('count', int)])
Branch = NamedTuple('Branch', [('src', Location), ('dst', Location),
                                ('count', int)])

class Stats:
    def __init__(self):
        self.ignored = 0;
        self.total = 0
        self.branches : Counter[Key] = Counter()
        self.functions : set[str] = set()
        self.filenames : dict[str,int] = dict()
        self.symlines : dict[tuple[str,int], int] = dict()
        self.next_fid = 0

stats = Stats()

def w32(f: BinaryIO, v: int):
    f.write(pack("I", v))

def wstring(f: BinaryIO, s: str):
    s += "\0"
    w32(f, len(s))
    f.write(pack("%ds" % len(s), s.encode('utf-8')))

def wcounter(f: BinaryIO, v: int):
    w32(f, (v       ) & 0xffffffff)
    w32(f, (v >> 32 ) & 0xffffffff)

def gen_offset(line: int, disc: int) -> int:
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
        num += 1
    w32(f, num)
    w32(f, 0) # call sites XXX

    for src, branchit in groupby(sbranches, lambda x: x.src):
        branches = list(branchit)
        # file contains only source offset
        # target is implicitly known by the compiler
        # XXX how does this handle switch/computed goto?
        w32(f, branches[0].src.offset)
        num_calls = sum((1 if b.src.sym != b.dst.sym else 0 for b in branches))
        w32(f, num_calls)
        count = sum((b.count for b in branches))
        wcounter(f, count)

        print(branches[0], len(branches), "count", count, "num_calls", num_calls)
        # also dump call targets to other functions
        if num_calls > 0:
            for b in branches:
                # should check branch type to see if it could be recursion
                # otherwise cannot distinguish from an ordinary branch
                # however this wouldn't work for recursive tail calls?
                if b.dst.sym == b.src.sym:
                    continue
                w32(f, HIST_TYPE_INDIR_CALL_TOPN)
                wcounter(f, string_index[b.dst.sym])
                wcounter(f, b.count)
        # XXX dump inline stack

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
    print("%d total, %d ignored" % (stats.total, stats.ignored), file=sys.stderr)
    for a, b in stats.branches.most_common(10):
        print(a, "\t", b, "%.2f" % (float(b)/stats.total*100.), file=sys.stderr)

    string_table, string_index = gen_strtable(stats)
    func_table = gen_func_table(stats)

    with open("file.gcov", "wb") as f:
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
        
def get_fid(fn:str) -> int:
    if fn in stats.filenames:
        fid = stats.filenames[fn]
    else:
        fid = stats.next_fid
        stats.next_fid += 1
        stats.filenames[fn] = fid
    return fid

def process_event(param_dict):
    for br, bsym in zip(param_dict["brstack"], param_dict["brstacksym"]):
        #pprint.pp(br)
        stats.total += 1
        if br["from_dsoname"] != br["to_dsoname"]:
            stats.ignored += 1
            continue
        res = perf_brstack_srcline(perf_script_context, br)
        if res[0] is None or res[1] is None:
            stats.ignored += 1
            continue

        def resolve(res:tuple[str, int, int], s:str, ip:int) -> Location:
            if "+" in s:
                sym, ipoff = s.split("+")
                stats.functions.add(sym)
                symip = ip - int(ipoff, 16)
                symres = perf_resolve_ip(perf_script_context, symip)
                if symres:
                    if symres[0] == res[0]:
                        fid = get_fid(res[0])
			# XXX handle inline
                        return Location(sym, fid, gen_offset(res[1] - symres[1], res[2]))
                    # XXX check inline stack
            return Location("", 0, 0)
        key = Key(resolve(res[0], bsym["from"], br["from"]), resolve(res[1], bsym["to"], br["to"]))
        if key.src.sym is None or key.dst.sym is None:
            stats.ignored += 1
            continue
        stats.branches[key] += 1
