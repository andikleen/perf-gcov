#!/usr/bin/env python3
# Unit tests for suffix.py
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from collections import Counter, defaultdict
from typing import Callable
import suffix
class FakeNode:
    def __init__(self, name: str) -> None:
        self.name = name
        self.positions: Counter[int] = Counter()
        self.targets: dict[int, Counter[tuple[str, str | None]]] = defaultdict(Counter)
        self.children: dict[tuple[int, str, str | None], "FakeNode"] = {}
def add_child(parent: FakeNode, offset: int, child: FakeNode) -> None:
    parent.children[(offset, child.name, None)] = child
def add_target(node: FakeNode, offset: int, target: tuple[str, str | None], count: int) -> None:
    node.targets[offset][target] += count
def set_positions(node: FakeNode, offsets: list[int]) -> None:
    for i, off in enumerate(offsets):
        node.positions[off] += (i + 1) * 10
def run(name: str, fn: Callable[[], None]) -> None:
    try:
        suffix.reset_suffixes()
        fn()
        print(f"  {name}: OK")
    except Exception as e:
        print(f"  {name}: FAIL ({e})")
        raise
def test_all() -> None:
    assert suffix.get_original_name('', 'all') == ''
    assert suffix.get_original_name('foo', 'all') == 'foo'
    assert suffix.get_original_name('foo.lto_priv.5', 'all') == 'foo'
    assert suffix.get_original_name('.plt', 'all') == '.plt'
    assert suffix.get_original_name('a.b.c', 'all') == 'a'
def test_selected_builtins() -> None:
    assert suffix.get_original_name('foo.lto_priv.5', 'selected') == 'foo'
    assert suffix.get_original_name('bar.cold', 'selected') == 'bar'
    assert suffix.get_original_name('bar.isra.3', 'selected') == 'bar'
    assert suffix.get_original_name('qux.__part.42', 'selected') == 'qux'
def test_selected_no_match() -> None:
    assert suffix.get_original_name('main', 'selected') == 'main'
    assert suffix.get_original_name('foo.bar', 'selected') == 'foo.bar'
    assert suffix.get_original_name('.plt', 'selected') == '.plt'
def test_selected_multiple() -> None:
    assert suffix.get_original_name('foo.lto_priv.1.cold', 'selected') == 'foo'
def test_trailing_digits_not_stripped_without_suffix() -> None:
    assert suffix.get_original_name('func.123', 'selected') == 'func.123'
def test_none() -> None:
    assert suffix.get_original_name('foo.lto_priv.5', 'none') == 'foo.lto_priv.5'
def test_invalid_policy() -> None:
    try:
        suffix.get_original_name('x', 'bogus')
        assert False
    except ValueError:
        pass
def _ck(name: str, src: str | None = None) -> tuple[str, str | None]:
    """Build a composite key for test trees."""
    return (name, src)

def test_rename_toplevel() -> None:
    tree = {_ck('main.lto_priv.5'): FakeNode('main.lto_priv.5')}
    suffix.elide_tree_suffixes(tree, 'all')
    assert list(tree.keys()) == [_ck('main')]
def test_merge_toplevel() -> None:
    a = FakeNode('main')
    set_positions(a, [1, 2])
    b = FakeNode('main.lto_priv.5')
    set_positions(b, [3, 4])
    tree = {_ck('main'): a, _ck('main.lto_priv.5'): b}
    suffix.elide_tree_suffixes(tree, 'all')
    assert list(tree.keys()) == [_ck('main')]
    assert set(tree[_ck('main')].positions.keys()) == {1, 2, 3, 4}
def test_normalize_targets() -> None:
    n = FakeNode('main')
    add_target(n, 1, ('helper.lto_priv.3', None), 200)
    add_target(n, 1, ('helper.lto_priv.5', None), 50)
    tree = {_ck('main'): n}
    suffix.elide_tree_suffixes(tree, 'all')
    tgt = n.targets[1]
    assert list(tgt.keys()) == [('helper', None)]
    assert tgt[('helper', None)] == 250
def test_rename_child() -> None:
    child = FakeNode('helper.lto_priv.7')
    set_positions(child, [5])
    parent = FakeNode('main')
    add_child(parent, 3, child)
    tree = {_ck('main'): parent}
    suffix.elide_tree_suffixes(tree, 'all')
    keys = list(parent.children.keys())
    assert keys == [(3, 'helper', None)], f"got {keys}"
    assert parent.children[(3, 'helper', None)].name == 'helper'
def test_merge_child() -> None:
    existing = FakeNode('helper')
    set_positions(existing, [8])
    suffixed = FakeNode('helper.lto_priv.2')
    set_positions(suffixed, [9])
    parent = FakeNode('main')
    add_child(parent, 5, existing)
    add_child(parent, 5, suffixed)
    tree = {_ck('main'): parent}
    suffix.elide_tree_suffixes(tree, 'all')
    keys = list(parent.children.keys())
    assert keys == [(5, 'helper', None)], f"got {keys}"
    assert parent.children[(5, 'helper', None)].positions[8] == 10
    assert parent.children[(5, 'helper', None)].positions[9] == 10
def test_recursive() -> None:
    leaf = FakeNode('leaf.lto_priv.9')
    set_positions(leaf, [10])
    child = FakeNode('helper.cold')
    set_positions(child, [5])
    add_child(child, 7, leaf)
    parent = FakeNode('main.lto_priv.1')
    set_positions(parent, [1])
    add_child(parent, 3, child)
    tree = {_ck('main.lto_priv.1'): parent}
    suffix.elide_tree_suffixes(tree, 'all')
    assert list(tree.keys()) == [_ck('main')]
    ck = list(tree[_ck('main')].children.keys())
    assert ck == [(3, 'helper', None)], f"got {ck}"
    gk = list(tree[_ck('main')].children[(3, 'helper', None)].children.keys())
    assert gk == [(7, 'leaf', None)], f"got {gk}"
def test_none_policy() -> None:
    tree = {_ck('main'): FakeNode('main.lto_priv.5')}
    suffix.elide_tree_suffixes(tree, 'none')
    assert list(tree.keys()) == [_ck('main')]
def test_tree_empty() -> None:
    tree: dict = {}
    suffix.elide_tree_suffixes(tree, 'all')
    assert tree == {}
def test_tree_invalid_policy() -> None:
    tree = {_ck('main'): FakeNode('main')}
    try:
        suffix.elide_tree_suffixes(tree, 'bogus')
        assert False, "expected ValueError"
    except ValueError:
        pass
def test_tree_no_suffixes() -> None:
    tree = {_ck('main'): FakeNode('main'), _ck('helper'): FakeNode('helper')}
    suffix.elide_tree_suffixes(tree, 'all')
    assert sorted(tree.keys()) == [_ck('helper'), _ck('main')]
if __name__ == '__main__':
    groups = [
        ('Name suffix stripping', [
            test_all, test_selected_builtins, test_selected_no_match,
            test_selected_multiple,
            test_trailing_digits_not_stripped_without_suffix,
            test_none, test_invalid_policy,
        ]),
        ('Tree elision', [
            test_rename_toplevel, test_merge_toplevel, test_normalize_targets,
            test_rename_child, test_merge_child, test_recursive,
            test_none_policy, test_tree_empty,
            test_tree_invalid_policy, test_tree_no_suffixes,
        ]),
    ]
    passed = 0
    failed = 0
    for group_name, tests in groups:
        print(f"\n{group_name}:")
        for fn in tests:
            try:
                run(fn.__name__.replace('_', ' '), fn)
                passed += 1
            except Exception:
                failed += 1
    total = passed + failed
    print(f"\n{'=' * 40}")
    if failed:
        print(f"{passed}/{total} passed, {failed} FAILED")
        sys.exit(1)
    else:
        print(f"{passed}/{total} passed — ALL OK")
