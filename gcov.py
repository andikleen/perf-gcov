# generate gcc gcov autofdo files from perf record -b 
# perf record -b workload
# perf script gcov.py > file.gcov

# open: 
# focus binary
# filter for minimal branches

from __future__ import print_function

import os
import sys
import pprint
from collections import Counter, defaultdict, namedtuple
from itertools import chain
from struct import pack

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
	'/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *

def trace_begin():
    pass

GCOV_TAG_AFDO_FILE_NAMES = 0xaa000000
GCOV_TAG_AFDO_FUNCTION = 0xac000000
GCOV_TAG_AFDO_MODULE_GROUPING = 0xae000000
GCOV_DATA_MAGIC = 0x67636461 # 'gcda'
GCOV_VERSION = 0x3430372a # XXX
HIST_TYPE_INDIR_CALL_TOPN = 7

class Stats:
    def __init__(self):
        self.ignored = 0;
        self.total = 0
        self.branches = Counter()
        self.filenames = set()
        self.functions = set()

Key = namedtuple('Key', ['sym', 'filename', 'line', 'disc'])
Target = namedtuple('Target', ['src', 'dst', 'count'])
Callsite = namedtuple('Callsite', ['callersym', 'offset', 'branches', 'count'])

stats = Stats()

def w32(f, v):
    f.write(pack("I", v))

def wstring(f, s):
    w32(f, len(fn)+1)
    if len:
        f.write(pack("%ds" % len(s), s.encode('utf-8'))) 

def wcounter(f, v):
    w32(f, (v       ) & 0xffffffff)
    w32(f, (v >> 32 ) & 0xffffffff)

def gen_offset(t):
    return (t.line << 16) | t.disc

def wfunc_instance(f, func_ind, branches, call_sites, string_table):
    w32(f, func_ind)
    w32(f, len(stats.functions))
    #w32(f, 0) # XXX len(call_sites))
    # XXX how to handle non unique symbols?
    for func, branches in groupby(sorted(branches, key=lambda x: x.src.sym),
                                  lambda x: x.src.sym):
        targets = list(branches)
        w32(f, gen_offset(targets[0].src))
        w32(f, len(targets))
        wcounter(f, sum((x[2] for x in targets)))
        for t in targets:
            w32(f, HIST_TYPE_INDIR_CALL_TOPN)
            wcounter(f, string_index[t.dst.sym])
            wcounter(f, t.count)
    #for c in call_sites:
    #    w32(f, c.offset)
    #    wfunc_instance(f, string_index[c.callersym], c.branches, [], string_table)

def gen_strtable(stats):
    string_table = sorted(chain(stats.filenames, stats.functions))
    string_index = { name: i for i, name in enumerate(string_table) }
    # uses same algorithm as autofdo, can round up too much
    slen4 = sum((len(s) + 4 / 4 for s in string_table))
    return string_table, string_index, slen4

def gen_tables(stats):
    func_table = defaultdict([])
    call_sites = defaultdict([])
    head_count = Counter()
    for k, v in stats.branches.items(): 
        if k.src.sym != k.dst.sym:
            call_sites[k.dst.sym].append(Callsite(k.src.sym, gen_offset(k.src), v))
        func_table[k[0].sym].append(Target(k[0], k[1], v))
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

        # write string table with file names and symbols
        w32(f, GCOV_TAG_AFDO_FILE_NAMES)
        w32(f, slen4)
        w32(len(string_table))
        for fn in string_table:
            wstring(fn)

        # write function profile
        w32(GCOV_TAG_AFDO_FUNCTION)
        w32(0) # length. ignored by gcc. XXX fill in
        w32(len(stats.functions))
        for func in stats.functions:
            wfunc_instance(f, string_index[func], func_table[func], call_sites[func],
                           sum((x.count for x in call_sites[func]))) # XXX include branches inside function?

        # not used by gcc
        w32(GCOV_TAG_MODULE_GROUPING)
        w32(0)
        w32(0)
        # working set is not used

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

        def resolve(res, s):
            sym = None
            if "+" in s:
                sym = s.split("+")[0]
                stats.functions.add(sym)
            stats.filenames.add(res[0])
            return Key(sym, res[0], res[1], res[2])

        key = resolve(res[0], bsym["from"]), resolve(res[1], bsym["to"])
        if key[0].sym is None or key[1].sym is None:
            stats.ignored += 1
            continue
        stats.branches[key] += 1
