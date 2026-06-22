#!/usr/bin/env python3
# generate gcc gcov autofdo files from perf record -b
# gcc -O2 -o workload ...
# perf record -b -c 100003 -e branches:upp workload
# perf script gcov.py --binary workload file.gcov
# gcc -fauto-profile=file.gcov -o workload.opt -O2 ...

# the code is written in typed python using mypy,
# please run make typecheck to verify after changes

# open:
# fix nesting
# handle non unique symbols using dwarf (same file)
# check buildid
# output multiple gcovs
# support online mode
# implement suffix elision policy for .
# unit tests

import os
import sys
from collections import Counter, defaultdict, namedtuple
from itertools import groupby, chain
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
ap.add_argument('--threshold', default=10, help="Min number of samples for location to output")
ap.add_argument('--verbose', action='store_true', help="Print every sample")
ap.add_argument('--top', default=0, help="Print N top samples")
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

Location = NamedTuple('Location', [('sym', str),
                                   ('srcid', int),
                                   ('exeid', int),
                                   ('offset', int)])
EmptyLocation = Location("", 0, 0, 0)
Key = NamedTuple('Key', [('src', Location),
                         ('dst', Location)])
Function = NamedTuple('Function', [('eid', int),
                                   ('fid', int),
                                   ('name', str)])
Branch = NamedTuple('Branch', [('src', Location),
                               ('dst', Location),
                               ('count', int)])
Inline = NamedTuple('Inline', [('fileid', int),
                               ('name', str),
                               ('offset', int)])

PerfInline = NamedTuple('PerfInline', [('file', str),
                                       ('line', int),
                                       ('disc', int),
                                       ('sym', str),
                                       ('declline', int)])

class Stats:
    def __init__(self):
        self.ignored = 0
        self.errored = 0
        self.crossed = 0
        self.total = 0
        self.ignored_branches = 0
        self.total_branches = 0
        self.branches : Counter[Key] = Counter()
        # XXX need file id to handle non unique
        self.functions : set[Function] = set()
        self.srcnames : dict[str, int] = dict()
        self.exenames : dict[str, int] = dict()
        self.inlinestacks : dict[Location, tuple[Inline, ...]] = dict()
        self.inlinestrings : set[str] = set()
        self.next_id = 1

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

def valid_call(b: Branch, func: str) -> bool:
    return b.count >= args.threshold and b.src.sym != b.dst.sym and b.src.sym == func
def wfunc_instance(f: BinaryIO,
                   all_branches: list[Branch],
                   string_index: dict[str, int],
                   func: str,
                   visited_inlines: set) -> None:
    sbranches = sorted(all_branches, key=lambda x: x.src)
    num = 0
    hcount = 0
    inlines = set()
    for src, branchit in groupby(sbranches, lambda x: x.src):
        branches = list(branchit)
        new_inlines = set()
        if branches[0].src in stats.inlinestacks:
            new_inlines.add(stats.inlinestacks[branches[0].src])
        if branches[0].src.sym != func:
            stats.ignored_branches += 1
            continue
        count = 0
        for b in branches:
            count += b.count
            if b.dst in stats.inlinestacks:
                new_inlines.add(stats.inlinestacks[b.dst])
        if count < args.threshold:
            stats.ignored_branches += count
            continue
        inlines.update(new_inlines)
        stats.total_branches += count
        hcount += count
        num += 1
    wcounter(f, hcount)
    w32(f, string_index[func])
    w32(f, num)
    #
    # Number of records for inlined functions.
    #
    w32(f, len(inlines))

    for src, branchit in groupby(sbranches, lambda x: x.src):
        branches = list(branchit)
        count = sum((b.count for b in branches))
        if count < args.threshold:
            continue
        if branches[0].src.sym != func:
            continue
        # contains only source offset
        # target is implicitly known by the compiler
        w32(f, branches[0].src.offset)
        num_calls = sum((1 if valid_call(b, func) else 0 for b in branches))
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
                if not valid_call(b, func):
                    continue
                w32(f, HIST_TYPE_INDIR_CALL_TOPN)
                wcounter(f, string_index[b.dst.sym])
                wcounter(f, b.count)

    # dump inline stack
    if inlines:
        for inl in inlines:
            if inl in visited_inlines:
                continue
            # It is a call, not an inline. This can happen if the compiler
            # decides not to inline a function.
            if not inl:
                continue
            visited_inlines.add(inl)
            wfunc_instance(f, all_branches, string_index, inl[0].name, visited_inlines)


def gen_strtable(stats: Stats):
    string_table = sorted(chain((x.name for x in stats.functions), stats.inlinestrings))
    string_index = { name: i for i, name in enumerate(string_table) }
    return string_table, string_index

def gen_func_table(stats: Stats) -> defaultdict[Function, list[Branch]]:
    func_table: defaultdict[Function, list[Branch]] = defaultdict(list)
    for k, count in stats.branches.items():
        func_table[Function(k.src.exeid, k.src.srcid, k.src.sym)].append(Branch(k.src, k.dst, count))
        if k.src.sym != k.dst.sym:
            func_table[Function(k.dst.exeid, k.dst.srcid, k.dst.sym)].append(Branch(k.src, k.dst, count))
    return func_table

def trace_end():
    print("%d total, %d ignored, %d errored, %d crossed" %
          (stats.total, stats.ignored, stats.errored, stats.crossed))

    if args.top > 0:
        for a, b in stats.branches.most_common(args.top):
            print(a, "\t", b, "%.2f" % (float(b)/stats.total*100.))

    # XXX multiple output files
    string_table, string_index = gen_strtable(stats)
    func_table = gen_func_table(stats)

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
        print("Writing %d functions" % len(stats.functions))
        w32(f, len(stats.functions))
        for k in sorted(stats.functions, key=lambda x: x.name):
            wfunc_instance(f, func_table[k], string_index, k.name, set())

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

    print("%d processed branches, %.2f%% ignored" %
          (stats.total_branches,
           (float(stats.ignored_branches) / stats.total_branches * 100. if stats.total_branches else 0.0)))

def get_id(d: dict[str,int], fn:str) -> int:
    if fn in d:
        return d[fn]
    fid = stats.next_id
    stats.next_id += 1
    d[fn] = fid
    return fid

def get_fid(fn:str) -> int:
    return get_id(stats.srcnames, fn)

def get_eid(fn:str) -> int:
    return get_id(stats.exenames, fn)

SFILE: Final[int] = 0
SLINE: Final[int] = 1
SDISC: Final[int] = 2
SEXE: Final[int] = 3
SBUILDID: Final[int] = 4
SINLINE: Final[int] = 5
SDECLLINE: Final[int] = 6

# indices into an inline-stack entry: (filename, lineno, discriminator,
# function, decl_line)
IFILENAME: Final[int] = 0
ILINENO: Final[int] = 1
IDISC: Final[int] = 2
IFUNCTION: Final[int] = 3
IDECLLINE: Final[int] = 4

def ifmtres(x:PerfInline):
    print(x)
    return "%s at %s:%d[%d]:%d" % (x.sym, x.file, x.line, x.declline if isinstance(x.declline, int) else 0, x.disc)

def ifmtrest(x:tuple[Any, ...]):
    # format a getbt() tuple (file, line, disc, exe, buildid, inline, decl_line)
    return ifmtres(PerfInline(x[SFILE], x[SLINE], x[SDISC], "", x[SDECLLINE]))

def gen_inline(exe: Any, il: Any) -> list[Inline]:
    def inline_tuple(x : PerfInline) -> Inline:
        stats.inlinestrings.add(x.sym)
        return Inline(get_fid(x.file), x.sym, gen_offset(x.line - x.declline, x.disc))
    return [inline_tuple(PerfInline(x[IFILENAME], x[ILINENO], x[IDISC], x[IFUNCTION], x[IDECLLINE]))
            for x in il]

# convert to original perf tuple format
# pcinfo returns tuples of (PC, filename, lineno, function, discriminator, decl_line)
# The returned tuple is indexed by the SFILE..SDECLLINE constants below.
def getbt(ip:int) -> tuple[str, int, int, Any, Any, Any, int] | None:
    p = backtrace.pcinfo(btstate, ip)
    #print("pcinfo %x" % ip, p)
    if p is None:
        return None
    op = p[0]
    # inline stack entries keep the full pcinfo layout
    # (filename, lineno, discriminator, function, decl_line)
    istack = tuple(((x[1], x[2], x[4], x[3], x[5]) for x in itertools.takewhile(lambda x: x[0] == op[0], p[1:])))
    return (op[1], op[2], op[4], None, None, istack, op[5])

i2warned = set()

def process_event(param_dict):
    for br, bsym in zip(param_dict["brstack"], param_dict["brstacksym"]):
        stats.total += 1
        if br["from_dsoname"] != br["to_dsoname"]:
            stats.crossed += 1
            continue
        if os.path.basename(br["from_dsoname"]) != os.path.basename(args.binary):
            stats.ignored += 1
            continue
        res = (getbt(br["from"]), getbt(br["to"]))
        if res[0] is None or res[1] is None:
            print("Ignored fail")
            stats.ignored += 1
            continue

        # source_file_name, line_number, discriminator, executable, build-id, inline-stack, decl_line for each entry of a brstack from the sample. Inline stack is a list of inlines with filename, line number, discriminator, symbolname, decl_line for each entry.
        def resolve(res:tuple[Any, ...],
                    s:str,
                    exe:str,
                    ip:int) -> Location:
            if "+" in s:
                sym, ipoff = s.split("+")
                symip = ip - int(ipoff, 16)
                symres = getbt(symip)
                if symres:
                    #print("symres",symres, "res", res, "ip %x" % ip, "symip %x" % symip)
                    eid = get_eid(exe)
                    fid = get_fid(symres[0])
                    key = Function(eid, fid, sym)
                    stats.functions.add(key)
                    if symres[SFILE] == res[SFILE]:
                        # offsets are relative to the function declaration
                        # line (DW_AT_decl_line), matching gcc/autofdo. Fall
                        # back to the symbol's first line if unavailable.
                        baseline = symres[SDECLLINE] if symres[SDECLLINE] else symres[SLINE]
                        if res[SLINE] < baseline:
                            if args.verbose and (symres, res) not in i2warned:
                                print(res)
                                print("symbol %s %s sample %s has negative line offset" % (
                                    sym,
                                    ifmtrest(symres),
                                     ifmtrest(res)))
                                i2warned.add((symres, res))
                            return EmptyLocation
                        lineoff = res[SLINE] - baseline
                        return Location(sym, fid, eid, gen_offset(lineoff, res[SDISC]))
            if args.verbose:
                print("Cannot resolve", res)
            stats.errored += 1
            return EmptyLocation

        key = Key(resolve(res[0],
                          bsym["from"],
                          br["from_dsoname"],
                          br["from"]),
                  resolve(res[1],
                          bsym["to"],
                          br["to_dsoname"],
                          br["to"]))
        if not key.src.sym or not key.dst.sym:
            continue
        stats.branches[key] += 1
        # handle src too?
        if res[1][SINLINE]:
            ikey = key.dst
            if ikey not in stats.inlinestacks:
                if args.verbose:
                    print("inline", ikey, res[1][SINLINE])
                istack = gen_inline(res[1][SEXE], res[1][SINLINE])
                if istack != EmptyLocation:
                    stats.inlinestacks[ikey] = tuple(istack)
