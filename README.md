# perf-gcov

perf based replacement for autofdo to generate profile feedback data for gcc's -fauto-profile option.

It reads LBR data from perf.data files collected with perf record -b and generates
a autofdo gcov file for gcc.

This is implemented in python as a perf script using the python interpreter linked into
the Linux perf tool.

## Setup

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


## Synopsis

```
gcc -O2 -o workload ...
perf record -b -c 100003 -e branches:upp workload
gcov.py --binary workload file.gcov
gcc -fauto-profile=file.gcov -o workload.opt -O2 ...
```

or

```
gcc -O2 -o workload ...
gcov-stream-profile.sh workload
gcc -fauto-profile=workload.gcov -o workload.opt -O2 ...
```

The streaming variant does not write the temporary sample data to disk.

or 
```
gcov-online-profile.sh --output-dir gcovdir
```

The default output is gcov-version 3 for gcc 16+. If you use gcc 15 or older add --gcov-version 2

The gcov.py script is (mostly) argument compatible to autofdo's create\_gcov, so can be used as a replacement.

## Tools

- gcov.py - convert perf.data to autofdo gcov files
- profile-merger.py - merge multiple gcov files together
- dump-gcov.py - dump a autofdo gcov file
- gcov-stream-profile.sh - script to profile and generate gcov without temporary files
- gcov-online-profile.sh - background gcov generation for all running binaris with debuginfo.

## Differences to autofdo

- Simpler to build.
- Less mature.
- Much less memory use for large dumps.
- Supports streaming mode to not save individual samples to disk.
- Supports online mode for background profiling
- Much simpler (but only focussed on the gcc job)
- Some differences in output due to differences in dwarf parsing.

