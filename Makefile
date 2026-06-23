# makefile for backtrace python extension module
# could use the python build system instead
# use the python version that perf is built with
CONFIG := python3.14-config
# can be gccbuilddir/libbacktrace
# otherwise copy libbacktrace.a here first
BACKTRACESRC := .
# if pointing to gcc builddir use .libs/libbacktrace.a
BACKTRACELIB := libbacktrace.a

target := backtrace$(shell $(CONFIG) --extension-suffix)

all: ${target}

${target}: backtracemodule.o 
	gcc -shared -L. -o ${target} backtracemodule.o ${BACKTRACELIB} libbacktrace.a $(shell ${CONFIG} --ldflags --embed)

backtracemodule.o: backtracemodule.c
	gcc -Wall -I.  -fPIC $(shell ${CONFIG} --includes --cflags) -I ${BACKTRACESRC} -c backtracemodule.c

TESTS = tgoto tswitch tdisc tinlines tinlines2 tcall

clean:
	rm -f backtracemodule.o ${target} \
		$(addsuffix .data,$(TESTS)) \
		$(addsuffix .data.old,$(TESTS)) \
		$(addsuffix .gcov,$(TESTS)) \
		$(addsuffix .gcov2,$(TESTS)) \
		$(addsuffix .opt,$(TESTS)) \
		$(addsuffix .offsets,$(TESTS)) \
		$(addsuffix .offsets2,$(TESTS)) \
		$(TESTS)

typecheck:
	mypy gcov.py dump.py --check-untyped-defs

test:
	./tester
