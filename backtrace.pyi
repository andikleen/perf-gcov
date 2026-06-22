# Type stub for the backtrace C extension (backtracemodule.c).
#
# The module exposes libbacktrace's pcinfo for an external ELF binary.
from typing import Any

# Opaque PyCapsule returned by createstate and consumed by pcinfo.
BacktraceState = Any

# One resolved frame: (pc, filename, lineno, function, discriminator, decl_line).
# filename and function are None when libbacktrace cannot determine them.
Frame = tuple[int, str | None, int, str | None, int, int]

def createstate(filename: str) -> BacktraceState:
    """Initialize state for the ELF file FILENAME."""
    ...

def pcinfo(state: BacktraceState, ip: int) -> list[Frame]:
    """Return the inline stack for IP as a list of frame tuples (innermost first)."""
    ...
