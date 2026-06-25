perf based replacement for autofdo to generate profile feedback data for gcc's -fauto-profile option.

It reads LBR data from perf.data files collected with perf record -b and generates
a autofdo gcov file for gcc.

This is implemented in python, but using the python interpreter linked into
the Linux perf tool.

Eventual goal is to support an online modus that supports contiguous profiling of the system
and then rebuilding pieces with profile feedback.

Requires gcc with the libbacktrace patches in
https://github.com/andikleen/gcc/tree/libbacktrace-disc-7
applied. Then copy the <gccbuilddir>/libbacktrace/.libs/libbacktrace.a
and <gccsrcdir>/libbacktrace/backtrace.h files to this directory.

Also depending on your python version (what perf was built with, check with ldd if needed)
may need to change the python-config in the Makefile.

Synopsis:

```
gcc -O2 -o workload ...
perf record -b -c 100003 -e branches:upp workload
gcov.py --binary workload file.gcov
gcc -fauto-profile=file.gcov -o workload.opt -O2 ...
```

or alternatively:

```
gcc -O2 -o workload ...
gcov-stream-profile.sh workload
gcc -fauto-profile=workload.gcov -o workload.opt -O2 ...

```

Differences to autofdo:

Much less testing.

Some differences in output due to differences in dwarf parsing.
