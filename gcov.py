# generate gcc gcov autofdo files from perf record -b
# gcc -O2 -o workload ...
# perf record -b workload
# perf script gcov.py > file.gcov
# gcc -fauto-profile=file.gcov -o workload.opt -O2 ...

# open:
# threshold
# head count
# callers inline stack (need perf change)
# offset relative to function
# call sites
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
GCOV_TAG_MODULE_GROUPING = 0xae000000
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
    def __init__(self: Stats):
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
    w32(f, len(s)+1)
    if len(s) > 0:
        f.write(pack("%ds" % len(s), s.encode('utf-8')))

def wcounter(f: BinaryIO, v: int):
    w32(f, (v       ) & 0xffffffff)
    w32(f, (v >> 32 ) & 0xffffffff)

def gen_offset(line: int, disc: int) -> int:
    return (line << 16) | disc

def wfunc_instance(f: BinaryIO,
                   func_ind: int,
                   all_branches: list[Branch],
                   all_call_sites: list[Callsite],
                   string_table : dict[str, int]) -> None:
    w32(f, func_ind)
    w32(f, len(all_branches))
    #w32(f, len(all_call_sites))
    w32(f, 0)

    for src, branchit in groupby(sorted(all_branches, key=lambda x: x.src)):
        branches = list(branchit)
        w32(f, branches[0].src.offset)
        w32(f, len(branches))
        wcounter(f, sum((b.count for b in branches)))
        for b in branches:
            w32(f, HIST_TYPE_INDIR_CALL_TOPN)
            wcounter(f, b.dst.offset)
            wcounter(f, b.count)
	# for inlines
    #for c in call_sites:
    #    w32(f, c.offset)
    #    wfunc_instance(f, string_index[c.callersym], c.branches, [], string_table)

def gen_strtable(stats: Stats):
    string_table = sorted(stats.functions)
    string_index = { name: i for i, name in enumerate(string_table) }
    slen4 = sum((len(s) + 4 / 4 for s in string_table))
    return string_table, string_index, slen4

def gen_tables(stats: Stats) -> tuple[defaultdict[str, list[Branch]], defaultdict[str, list[Callsite]]]:
    func_table: defaultdict[str, list[Branch]] = defaultdict(list)
    call_sites: defaultdict[str, list[Callsite]] = defaultdict(list)
    # XXX handle non unique symbols. file match?
    for k, count in stats.branches.items():
        # TBD
        #if k.src.sym != k.dst.sym:
        #    call_sites[k.dst.sym].append(Callsite(k.src.sym, k.src.offset, ..., count))
        if k.src.sym != k.dst.sym: # for now
            continue
        func_table[k.src.sym].append(Branch(k.src, k.dst, count))
    return func_table, call_sites

def trace_end():
    print("%d total, %d ignored" % (stats.total, stats.ignored), file=sys.stderr)
    for a, b in stats.branches.most_common(10):
        print(a, "\t", b, "%.2f" % (float(b)/stats.total*100.), file=sys.stderr)

    string_table, string_index, slen4 = gen_strtable(stats)
    func_table, call_sites = gen_tables(stats)

    with open("file.gcov", "wb") as f:
        w32(f, GCOV_DATA_MAGIC)
        w32(f, GCOV_VERSION)
        w32(f, 0)

        # write string table
        w32(f, GCOV_TAG_AFDO_FILE_NAMES)
        w32(f, slen4)
        w32(f, len(string_table))
        for fn in string_table:
            wstring(f, fn)

        # write function profile
        w32(f, GCOV_TAG_AFDO_FUNCTION)
        w32(f, 0) # length. ignored by gcc. XXX fill in
        w32(f, len(stats.functions))
        for func in stats.functions:
            wfunc_instance(f,
                           string_index[func],
                           func_table[func],
                           call_sites[func],
                           sum((x.count for x in call_sites[func])))  # XXX

        # not used by gcc
        w32(f, GCOV_TAG_MODULE_GROUPING)
        w32(f, 0)
        w32(f, 0)
        # working set is not used

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

        def resolve(res:tuple[str, int, int], s) -> Location:
            if "+" in s:
                sym, ipoff = s.split("+")[0]
                stats.functions.add(sym)
                symres = perf_resolve_ip(res[1] - int(ipoff, 16))
                if symres:
                    if symres[0] == res[0]:
                        fid = get_fid(res[0])
			# XXX handle inline
                        return Location(sym, fid, gen_offset(res[1] - symres[1], res[2]))
                    # XXX check inline stack
            return Location("", 0, 0)
        key = Key(resolve(res[0], bsym["from"]), resolve(res[1], bsym["to"]))
        if key.src.sym is None or key.dst.sym is None:
            stats.ignored += 1
            continue
        stats.branches[key] += 1
