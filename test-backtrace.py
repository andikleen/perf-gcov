import backtrace
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('elffile', type=str)
ap.add_argument('ip', type=str)
ap.add_argument('--repeat', default=1, type=int)
args = ap.parse_args()

for i in range(args.repeat):
    state = backtrace.createstate(args.elffile)
    for j in backtrace.pcinfo(state, int(args.ip, 0)):
        print("%x %s:%d %s %d" % j)

