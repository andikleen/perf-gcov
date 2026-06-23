# could use the python build system instead
CONFIG := python3.13-config
BACKTRACESRC := ~/gcc/git/gcc/libbacktrace
BACKTRACELIB := ~/gcc/git/obj-quick/libbacktrace/.libs/libbacktrace.a

target := backtrace$(shell $(CONFIG) --extension-suffix)

all: ${target}

${target}: backtracemodule.o 
	gcc -shared -L. -o ${target} backtracemodule.o ${BACKTRACELIB} libbacktrace.a $(shell ${CONFIG} --ldflags --embed)

backtracemodule.o: backtracemodule.c
	gcc -Wall -I.  -fPIC $(shell ${CONFIG} --includes --cflags) -I ${BACKTRACESRC} -c backtracemodule.c

clean:
	rm -f backtracemodule.o ${target}

typecheck:
	mypy gcov.py dump.py --check-untyped-defs

