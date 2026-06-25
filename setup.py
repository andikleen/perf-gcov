from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import sys
import os
import platform

class BuildExtWithBacktrace(build_ext):
    """Custom build_ext that verifies libbacktrace.a compatibility"""

    def run(self):
        # Check for libbacktrace.a
        if not os.path.exists('libbacktrace.a'):
            print("\nERROR: libbacktrace.a not found!", file=sys.stderr)
            print("This should be bundled with the package.", file=sys.stderr)
            sys.exit(1)

        # Warn about architecture compatibility
        arch = platform.machine()
        if arch != 'x86_64':
            print(f"\nWARNING: This package includes libbacktrace.a built for x86_64.", file=sys.stderr)
            print(f"Your architecture is: {arch}", file=sys.stderr)
            print(f"The build may fail or produce incompatible binaries.", file=sys.stderr)
            print(f"You may need to rebuild libbacktrace.a for your architecture.\n", file=sys.stderr)

        super().run()

backtrace_ext = Extension(
    'backtrace',
    sources=['backtracemodule.c'],
    include_dirs=['.'],
    extra_objects=['libbacktrace.a'],  # Bundled static library
)

setup(
    ext_modules=[backtrace_ext],
    cmdclass={'build_ext': BuildExtWithBacktrace},
    scripts=[
        'gcov-dump.py',
        'gcov-stream-profile.sh',
    ],
)
