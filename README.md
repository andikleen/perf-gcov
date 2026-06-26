# perf-gcov

perf based replacement for autofdo to generate profile feedback data for gcc's -fauto-profile option.

It reads LBR data from perf.data files collected with perf record -b and generates
a autofdo gcov file for gcc.

This is implemented in python as a perf script using the python interpreter linked into
the Linux perf tool.

Eventual goal is to support an online modus that supports contiguous profiling of the system
and then rebuilding pieces with profile feedback. Right now it is just simpler to build
than autofdo and uses a lot less memory and disk space (if used in streaming mode)

# Setup

Build a gcc with the patch in https://github.com/andikleen/gcc/tree/libbacktrace-disc-8

Then copy the <gccbuilddir>/libbacktrace/.libs/libbacktrace.a
and <gccsrcdir>/libbacktrace/backtrace.h files to this directory.
(or point the makefile to the gcc directories)

Make sure you have the python-devel package for the python
that your perf is built with installed. The Makefile finds
the right python setup from the perf binary. You can override
the perf binary used at build time with PERF=...

Build the backtrace python module

```
make
```

Then gcov.py or gcov-stream-profile.sh can be executed without installation.


# Synopsis

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

The streaming variant does not write the temporary sample data to disk.

The default output is gcov_version 3 for gcc 16+. If you use gcc 15 or older add --gcov-version 2

The gcov.py script is (mostly) argument compatible to autofdo's create_gcov, so can be used as a replacement.
For example to build gcc profiled with perf-gcov use

```
configure ...
make autoprofiledbootstrap CREATE_GCOV=/path/to/gcov.py
```

## Differences to autofdo

* Simpler to build.
* Much less testing.
* Some differences in output due to differences in dwarf parsing.
* Much less memory use for large dumps.
* Supports streaming mode to not save individual samples to disk.
* Integrated into perf so no compatibility issues.
* Orders of magnitude simpler (but only focussed on the gcc job)

