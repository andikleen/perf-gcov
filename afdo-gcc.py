#!/usr/bin/env python3
# AFDO LTO compiler wrapper - injects -fauto-profile for LTO link steps
#
# Options:
#   --afdo-dir=DIR   directory of <binary>.gcov profiles (enables injection)
#   --afdo-cc=PATH   explicit real compiler (highest precedence)
# Env: AFDO_CC / AFDO_CXX  real C / C++ compiler if --afdo-cc unset
#
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import sys
import subprocess

def detect_family(argv0: str) -> str:
    """Determine compiler family (gcc vs g++) from invocation name.

    Strips a trailing extension (e.g. .py) so both afdo-g++ and
    afdo-g++.py resolve to the g++ family.
    """
    base, _ = os.path.splitext(os.path.basename(argv0))
    if base.endswith(("g++", "c++")):
        return "g++"
    return "gcc"

def parse_wrapper_args(argv: list[str]) -> tuple[str | None, str | None, list[str]]:
    """Parse wrapper-specific args, return (afdo_dir, afdo_cc, compiler_args).

    Strips --afdo-dir and --afdo-cc from the argument list.
    """
    afdo_dir: str | None = None
    afdo_cc: str | None = None
    compiler_args: list[str] = []

    i = 0
    while i < len(argv):
        arg = argv[i]

        # --afdo-dir=VALUE
        if arg.startswith("--afdo-dir="):
            afdo_dir = arg.split("=", 1)[1]
            if not afdo_dir:
                sys.exit("afdo-gcc: --afdo-dir requires a value")
            i += 1
        # --afdo-dir VALUE
        elif arg == "--afdo-dir":
            if i + 1 >= len(argv):
                sys.exit("afdo-gcc: --afdo-dir requires a value")
            afdo_dir = argv[i + 1]
            i += 2
        # --afdo-cc=VALUE
        elif arg.startswith("--afdo-cc="):
            afdo_cc = arg.split("=", 1)[1]
            if not afdo_cc:
                sys.exit("afdo-gcc: --afdo-cc requires a value")
            i += 1
        # --afdo-cc VALUE
        elif arg == "--afdo-cc":
            if i + 1 >= len(argv):
                sys.exit("afdo-gcc: --afdo-cc requires a value")
            afdo_cc = argv[i + 1]
            i += 2
        else:
            compiler_args.append(arg)
            i += 1

    return afdo_dir, afdo_cc, compiler_args

def find_real_compiler(family: str, override: str | None) -> str:
    """Find the real compiler, respecting precedence and skipping self."""
    # Check recursion depth
    depth = int(os.environ.get("AFDO_WRAP_DEPTH", "0"))
    if depth > 5:
        sys.exit("afdo-gcc: recursion depth exceeded (possible self-loop)")

    # Precedence 1: explicit override
    if override:
        if not os.path.isfile(override):
            sys.exit(f"afdo-gcc: --afdo-cc={override} not found")
        return override

    # Precedence 2: environment variable
    env_var = "AFDO_CXX" if family == "g++" else "AFDO_CC"
    env_compiler = os.environ.get(env_var)
    if env_compiler:
        if not os.path.isfile(env_compiler):
            sys.exit(f"afdo-gcc: {env_var}={env_compiler} not found")
        return env_compiler

    # Precedence 3: PATH search, skipping self
    self_real = os.path.realpath(sys.argv[0])
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)

    for path_dir in path_dirs:
        if not path_dir:
            continue
        candidate = os.path.join(path_dir, family)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            candidate_real = os.path.realpath(candidate)
            if candidate_real != self_real:
                return candidate

    sys.exit(f"afdo-gcc: cannot find real {family} compiler")

def is_link_step(args: list[str]) -> bool:
    """Return True if this is a link step (no -c, -S, or -E)."""
    return "-c" not in args and "-S" not in args and "-E" not in args

def has_lto(args: list[str]) -> bool:
    """Return True if LTO is enabled (-flto present, no -fno-lto)."""
    has_flto = any(arg == "-flto" or arg.startswith("-flto=") for arg in args)
    has_fno_lto = "-fno-lto" in args
    return has_flto and not has_fno_lto

def has_profile_flag(args: list[str]) -> bool:
    """Return True if user already specified a profile flag."""
    return any(
        arg.startswith(("-fauto-profile", "-fprofile-use"))
        for arg in args
    )

def output_basename(args: list[str]) -> str:
    """Extract output basename from -o flag, default to a.out."""
    output = None
    i = 0
    while i < len(args):
        arg = args[i]
        # -o <file> (space-separated)
        if arg == "-o" and i + 1 < len(args):
            output = args[i + 1]
            i += 2
        # -o<file> (glued form)
        elif arg.startswith("-o") and len(arg) > 2:
            output = arg[2:]
            i += 1
        else:
            i += 1
    return os.path.basename(output) if output else "a.out"

def print_help() -> None:
    """Print wrapper usage and exit."""
    print("""afdo-gcc / afdo-g++ — AFDO LTO compiler wrapper

Wrapper options:
  --afdo-dir DIR        Directory of <binary>.gcov profiles (enables injection)
  --afdo-cc PATH        Explicit real compiler path (highest precedence)
  --help                Show this help message

Environment variables:
  AFDO_CC               Real C compiler when --afdo-cc unset
  AFDO_CXX              Real C++ compiler when --afdo-cc unset

Behavior:
  Injects -fauto-profile=DIR/<output>.gcov for -flto link steps when the
  profile exists. Warns to stderr and continues if the profile is missing.
  All other invocations pass through to the real compiler unchanged.

All other options are passed through to the real compiler.
Use 'gcc --help' or 'g++ --help' for compiler options.""")
    sys.exit(0)

def main() -> None:
    """Main entry point."""
    if len(sys.argv) < 2:
        sys.exit("afdo-gcc: no arguments provided")

    # Check for help request (before parsing, so --help works without a real compiler)
    # Conservative trigger: a lone --help or -h (no other args)
    # Mixed forms like --help=target or compiler flags with --help pass through
    if sys.argv[1:] == ["--help"] or sys.argv[1:] == ["-h"]:
        print_help()

    # Detect compiler family
    family = detect_family(sys.argv[0])

    # Parse wrapper args
    afdo_dir, afdo_cc, compiler_args = parse_wrapper_args(sys.argv[1:])

    # Find real compiler
    real_compiler = find_real_compiler(family, afdo_cc)

    # Decide whether to inject -fauto-profile
    should_inject = (
        afdo_dir is not None
        and is_link_step(compiler_args)
        and has_lto(compiler_args)
        and not has_profile_flag(compiler_args)
    )

    # Build final argv
    final_argv = [real_compiler] + compiler_args

    if should_inject:
        assert afdo_dir is not None  # guaranteed by should_inject check
        output = output_basename(compiler_args)
        profile_path = os.path.join(afdo_dir, output + ".gcov")

        if os.path.exists(profile_path):
            final_argv.append(f"-fauto-profile={profile_path}")
        else:
            print(f"afdo-gcc: no profile {profile_path}, building without -fauto-profile",
                  file=sys.stderr)

    # Increment recursion depth guard
    new_env = os.environ.copy()
    new_env["AFDO_WRAP_DEPTH"] = str(int(new_env.get("AFDO_WRAP_DEPTH", "0")) + 1)

    # Execute real compiler
    try:
        os.execve(real_compiler, final_argv, new_env)
    except OSError:
        # Fallback to subprocess if execve fails
        result = subprocess.run(final_argv, env=new_env)
        sys.exit(result.returncode)

if __name__ == "__main__":
    main()
