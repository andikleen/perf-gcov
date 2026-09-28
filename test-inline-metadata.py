#!/usr/bin/env python3
"""Regression test for libbacktrace inline declaration metadata."""

import importlib.util
import os
import sys
import types
from pathlib import Path


class FakeBacktrace:
    def pcinfo(self, state: object, ip: int) -> list[tuple[object, ...]]:
        del state, ip
        # libbacktrace reports the declaration line one frame late while
        # walking this inline chain.  The correct declarations are 1000,
        # 1492, and 264 in outer-to-inner order.
        return [
            (0x100, "inline.h", 268, "safe_as_a", 0, 1000),
            (0x100, "rtl.h", 1495, "NEXT_INSN", 0, 264),
            (0x100, "cfgrtl.cc", 1010, "force_nonfallthru_and_redirect", 0, 1492),
        ]


def load_gcov():
    fake_perf_trace = types.ModuleType("perf_trace_context")
    setattr(fake_perf_trace, "perf_script_context", {})
    fake_backtrace = types.ModuleType("backtrace")
    setattr(fake_backtrace, "pcinfo", FakeBacktrace().pcinfo)
    sys.modules["backtrace"] = fake_backtrace
    sys.modules["perf_trace_context"] = fake_perf_trace
    os.environ["PERF_EXEC_PATH"] = "/tmp"
    sys.argv = ["gcov.py"]

    path = Path(os.environ.get("GCOV_TEST_SOURCE",
                               str(Path(__file__).with_name("gcov.py"))))
    spec = importlib.util.spec_from_file_location("gcov_under_test", path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load gcov.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    gcov = load_gcov()
    ctx = gcov.BinaryContext("fake")
    ctx.btstate = object()
    frames = gcov.getframes(ctx, 0x100)

    assert frames is not None
    assert [frame.sym for frame in frames] == [
        "force_nonfallthru_and_redirect", "NEXT_INSN", "safe_as_a"
    ]
    assert [frame.declline for frame in frames] == [1000, 1492, 264]
    assert [gcov.frame_offset(frame, ctx) >> 16 for frame in frames] == [10, 3, 4]
    print("INLINE DECLARATION METADATA: OK")

    gcov.args = types.SimpleNamespace(binary=[], binary_exact=[])
    gcov.args.binary_exact = ["/build/prev-gcc/cc1plus"]
    gcov._should_process_cache.clear()
    assert gcov.should_process_binary("/build/prev-gcc/cc1plus")
    assert not gcov.should_process_binary("/build/gcc/cc1plus")


if __name__ == "__main__":
    main()
