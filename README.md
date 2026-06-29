# perf-gcov

perf based replacement for autofdo to generate profile feedback data for gcc's
[-fauto-profile](https://gcc.gnu.org/onlinedocs/gcc-16.1.0/gcc/Optimize-Options.html#index-fauto-profile) option.
This often allows improving the performance of compiled code using profiling
data taken from production binaries.

It reads LBR (Last Branch Record) data from perf.data files collected with perf record -b and
generates a autofdo gcov file for gcc.

This is implemented in python as a perf script using the python interpreter
linked into the Linux perf tool.

The goals are to be simpler, use less resources and support new usage models
like online profiling.

## Setup

Get patched libbacktrace (temporary, until these changes are upstreamed)

```
git clone --depth 10 -b libbacktrace-disc-8 https://github.com/andikleen/gcc gcc
cd gcc/libbacktrace
./configure
make
cp backtrace.h .libs/libbacktrace.a ../../perf-gcov
```

Make sure you have the python-devel package for the python
that your perf is built with installed. The Makefile finds
the right python setup from the perf binary. You can override
the perf binary used at build time with PERF=...

```
DEVEL=$(ldd $(which perf) | grep -o python.... | head -1)-config
apt/dnf/zypper install $DEVEL
```

Build the backtrace python module

```
make
```

Then gcov.py or gcov-stream-profile.sh can be executed from this directory 
without installation.

## Synopsis

Profiling currently requires an Intel system with LBR support. This usually
(but not always) means a non virtualized system, unless the hypervisor
is set up to pass through LBR.  If running an old kernel
kernel with a newer CPU it may also require updating the kernel.

Check if LBRs are available:
```
grep . /sys/devices/cpu*/caps/branch_counter_nr
```

The program must be compiled with -O2+ and debug information (-g).

```
gcc -g -O2 -o workload ...
# can also use gcc-auto-profile if installed
perf record -b -c 100003 -e branches:upp workload
gcov.py --binary workload file.gcov
gcc -fauto-profile=file.gcov -o workload.opt -O2 ...
```

Or to avoid temporary files:

```
gcc -O2 -o workload ...
gcov-stream-profile.sh workload
gcc -fauto-profile=workload.gcov -o workload.opt -O2 ...
```

or to do online profiling of all running programs

```
gcov-online-profile.sh --output-dir gcovdir
```

The default output is gcov-version 3 for gcc 16+. If you use gcc 15 or older add --gcov-version 2

## Tools

- gcov.py - convert perf.data to autofdo gcov files
- profile-merger.py - merge multiple gcov files together
- dump-gcov.py - dump a autofdo gcov file
- gcov-stream-profile.sh - script to profile and generate gcov without temporary files
- gcov-online-profile.sh - background gcov generation for all running binaries with debuginfo.

## Compatibility

gcov.py is (mostly) compatible to create\_gcov, and profile-merger.py mostly compatible to profile-merger. They can be used as a replacement in build systems.

## Differences to autofdo

- Much less mature.
- Not a nightmare to build (I hope)
- Much simpler (but only focussed on the gcc job)
- Much less memory use for large input files because they are not completely
loaded into memory.
- Supports streaming mode to not save individual samples to disk.
- Supports online mode for automatic background profiling
- Some differences in output due to differences in dwarf processing
- Currently only supports Intel+LBR, other environments TBD.

## Credits

Andi Kleen with some AI help. Original concept and some algorithms
inspired by [autofdo](https://github.com/google/autofdo). The dwarf
parsing is relying on Ian Lance Taylor's
[libbacktrace](https://github.com/ianlancetaylor/libbacktrace).

## License

GPLv3-or-later
