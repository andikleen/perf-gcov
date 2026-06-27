# makefile for backtrace python extension module
# could use the python build system instead
PERF = perf
# use the python version that perf is built with
CONFIG := $(shell ldd `which ${PERF}` |grep -o 'libpython....'|sed -e s/lib// -e 1q)-config
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

TESTS = tgoto tswitch tdisc tinlines tinlines2 tcall test-lto tnonunique1 tnonunique2

MULTI_TESTS = tlibmain tlibmain-only tmulti1 tmulti2 tmulti3
DIRS = multibin_out

clean:
	rm -f backtracemodule.o ${target} \
		$(addsuffix .data,$(TESTS) $(MULTI_TESTS)) multibin.data \
		$(addsuffix .data.old,$(TESTS)) \
		$(addsuffix .gcov,$(TESTS) $(MULTI_TESTS) libtlib.so ld-linux-x86-64.so.2 libc.so.6) \
		$(addsuffix .gcov2,$(TESTS)) \
		$(addsuffix .opt,$(TESTS)) \
		$(addsuffix .offsets,$(TESTS)) \
		$(addsuffix .offsets2,$(TESTS)) \
		$(addsuffix .dump,$(TESTS)) \
		$(addsuffix .dump2,$(TESTS)) \
		$(addsuffix .diff,$(TESTS)) \
		$(TESTS) $(MULTI_TESTS) \
		libtlib.so run-tests-wrapper.sh \
		tcall.d1 tcall.d2 tcall.1.* tcall.2.* tcall.id.* tcall.two.* \
		tcall.copy.* tcall.mix tcall.thr tcall.bad tcall.two.opt perf.data
	rm -rf $(DIRS)

PSRC := gcov.py gcov-dump.py format.py profile-merger.py suffix.py \
	test-suffix.py
typecheck:
	mypy ${PSRC} --check-untyped-defs --disallow-untyped-defs

lint:
	flake8 ${PSRC}

test:
	./tester
	./test-gcov-online.sh
	./test-multi-binary.sh
	./test-merger.sh
