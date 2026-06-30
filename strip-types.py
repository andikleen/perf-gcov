#!/usr/bin/env python3
# Strip type annotations from Python files for compatibility with older Python versions
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import sys
import argparse
from pathlib import Path

class TypeStripper(ast.NodeTransformer):
    """Remove type annotations from Python AST."""

    def visit_FunctionDef(self, node):
        # Remove return type annotation
        node.returns = None
        # Remove argument annotations
        for arg in node.args.args:
            arg.annotation = None
        for arg in node.args.posonlyargs:
            arg.annotation = None
        for arg in node.args.kwonlyargs:
            arg.annotation = None
        if node.args.vararg:
            node.args.vararg.annotation = None
        if node.args.kwarg:
            node.args.kwarg.annotation = None
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node):
        return self.visit_FunctionDef(node)

    def visit_AnnAssign(self, node):
        # Convert annotated assignment to regular assignment
        # x: int = 5  ->  x = 5
        if node.value is None:
            # Pure annotation with no value (x: int) -> remove entirely
            return None
        # Create a regular assignment
        return ast.Assign(
            targets=[node.target],
            value=node.value,
            lineno=node.lineno,
            col_offset=node.col_offset
        )

    def visit_arg(self, node):
        # Remove type annotation from function argument
        node.annotation = None
        return node

def strip_types(source_code):
    """Strip type annotations from Python source code."""
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        print(f"Syntax error parsing source: {e}", file=sys.stderr)
        return None

    # Strip types
    stripper = TypeStripper()
    new_tree = stripper.visit(tree)
    ast.fix_missing_locations(new_tree)

    # Convert back to source code
    try:
        return ast.unparse(new_tree)
    except AttributeError:
        # ast.unparse() requires Python 3.9+
        print("Error: ast.unparse() requires Python 3.9+", file=sys.stderr)
        print("This script needs Python 3.9+ to run, but produces output for older versions",
              file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser(
        description='Strip type annotations from Python files for older Python compatibility'
    )
    parser.add_argument('input', help='Input Python file')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} does not exist", file=sys.stderr)
        return 1

    source_code = input_path.read_text()

    stripped = strip_types(source_code)
    if stripped is None:
        return 1

    if args.output:
        Path(args.output).write_text(stripped)
        print(f"Stripped types written to {args.output}", file=sys.stderr)
    else:
        print(stripped)

    return 0

if __name__ == '__main__':
    sys.exit(main())
