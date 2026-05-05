import subprocess

# to generate inline relative offsets need the abstract origin of the inlines
# this requires reading the .debug_info because perf doesn't know it because the
# libraries/programs it uses don't supply
# XXX doesn't handle functions with non unique names correctly 
def read_sym_lines(exe: str) -> dict[str, int] :
    with subprocess.Popen(["objdump", "-e", exe, "-Wi"], stdout=subprocess.PIPE, universal_newlines=True) as p:
        d = {}
        seen = 0
        for l in p.stdout:
            n = l.split()
            if len(n) < 4:
                continue
            if n[1] == "Abbrev":
                if len(n) >= 5 and n[4] == "(DW_TAG_subprogram)":
                    seen += 1
                else:
                    seen = 0
            if n[1] == "DW_AT_name" and seen == 1:
                if name == "(indirect":
                    name = n[7]
                seen += 1
            if n[1] == "DW_AT_decl_line" and seen == 2:
                line = int(n[3])
                seen += 1
            if n[1] == "DW_AT_inline" and n[3] == "1":
                d[name] = line
                seen = 0
        return d

sym_lines = {}
warned = set()

def find_sym_line(exe: str, sym: str) -> int:
    if exe not in sym_lines:
        sym_lines[exe] = read_sym_lines(exe)
    if sym in sym_lines[exe]:
        return sym_lines[exe]
    if sym not in warned:
        print("cannot find symbol %s in %s" % (sym, exe))
        warned.add(sym)
    return 0

find_sym_line("tinlines2", "f2")
