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

target = backtrace$(shell $(CONFIG) --extension-suffix)

all: ${target}

${target}: backtracemodule.o 
	gcc -shared -L. -o ${target} backtracemodule.o ${BACKTRACELIB} libbacktrace.a $(shell ${CONFIG} --ldflags)

backtracemodule.o: backtracemodule.c
	gcc -Wall -I.  -fPIC $(shell ${CONFIG} --includes --cflags) -I ${BACKTRACESRC} -c backtracemodule.c

TESTS = tgoto tswitch tdisc tinlines tinlines2 tcall test-lto tnonunique1 tnonunique2 tindirect

MULTI_TESTS = tlibmain tlibmain-only tmulti1 tmulti2 tmulti3
DIRS = multibin_out

clean:
	rm -f backtracemodule.o ${target} \
		$(addsuffix .data,$(TESTS) $(MULTI_TESTS)) multibin.data \
		$(addsuffix .data.old,$(TESTS)) \
		$(addsuffix .gcov,$(TESTS) $(MULTI_TESTS) libtlib.so ld-linux-x86-64.so.2 libc.so.6) \
		$(addsuffix .gcov2,$(TESTS)) \
		$(addsuffix .gcov3,$(TESTS) $(MULTI_TESTS) libtlib.so ld-linux-x86-64.so.2 libc.so.6) \
		$(addsuffix .opt,$(TESTS) $(MULTI_TESTS)) \
		$(addsuffix .opt3,$(TESTS) $(MULTI_TESTS)) \
		$(addsuffix .optafdo,$(TESTS) $(MULTI_TESTS)) \
		$(addsuffix .offsets,$(TESTS)) \
		$(addsuffix .offsets2,$(TESTS)) \
		$(addsuffix .dump,$(TESTS) $(MULTI_TESTS) libtlib.so) \
		$(addsuffix .dump2,$(TESTS)) \
		$(addsuffix .dump3,$(TESTS) $(MULTI_TESTS) libtlib.so) \
		$(addsuffix .diff,$(TESTS)) \
		$(TESTS) $(MULTI_TESTS) \
		libtlib.so run-tests-wrapper.sh \
		tcall.d1 tcall.d2 tcall.1.* tcall.2.* tcall.id.* tcall.two.* \
		tcall.copy.* tcall.mix tcall.thr tcall.bad tcall.two.opt *ref-*.afdo *new-*.afdo perf.data
	rm -rf $(DIRS)

PSRC := gcov.py gcov-dump.py format.py profile-merger.py suffix.py \
	test-suffix.py afdo-gcc.py strip-types.py gcov-diff.py
typecheck:
	PYRIGHT_PYTHON_FORCE_VERSION=latest pyright ${PSRC}

lint:
	flake8 ${PSRC}

test: all
	./tester
	./test-gcov-online.sh
	./test-multi-binary.sh
	./test-merger.sh
	./test-afdo-wrap.sh
	./test-parallel.sh
	./test-gcov-diff.sh

prefix := ${HOME}

INSTALL := gcov.py profile-merger.py suffix.py format.py gcov-dump.py gcov-diff.py ${target}

install: all
	# or create some lib directory for the libraries?
	# drop more .py suffixes?
	cp ${INSTALL} ${prefix}/bin
	cp afdo-gcc.py ${prefix}/bin/afdo-gcc
	ln -s ${prefix}/bin/afdo-gcc ${prefix}/bin/afdo-g++
