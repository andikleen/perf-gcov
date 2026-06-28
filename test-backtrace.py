import sys
import backtrace
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('elffile', type=str)
ap.add_argument('ip', type=str)
ap.add_argument('--repeat', default=1, type=int)
args = ap.parse_args()

for i in range(args.repeat):
    state = backtrace.createstate(args.elffile)
    if state is None:
        print(f"Failed to create backtrace state for {args.elffile}", file=sys.stderr)
        continue
    frames = backtrace.pcinfo(state, int(args.ip, 0))
    if frames is None:
        print(f"No backtrace info for {args.elffile} IP {args.ip}", file=sys.stderr)
        continue
    for j in frames:
        print("%x %s:%d %s %d" % j)

