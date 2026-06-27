# Suffix elision for perf-gcov — strips unstable compiler suffixes from
# function names so profiles are stable across LTO rebuilds.
# SPDX-License-Identifier: GPL-3.0-or-later

from format import merge_nodes

ELIDE_POLICIES = ('all', 'selected', 'none')

_BUILTIN_SUFFIXES: list[str] = [
    '.cold',
    '.isra',
    '.__part',
    '.lto_priv',
]

_selected_suffixes: list[str] = list(_BUILTIN_SUFFIXES)

def reset_suffixes() -> None:
    """Restore suffix table to built-in defaults (testing only)."""
    _selected_suffixes.clear()
    _selected_suffixes.extend(_BUILTIN_SUFFIXES)

def elide_suffix_all(name: str) -> str:
    """Strip everything after the first '.'.
    Names starting with '.' (e.g. assembly labels, PLT stubs) are kept as-is."""
    if not name or name[0] == '.':
        return name
    dot = name.find('.')
    if dot == -1:
        return name
    return name[:dot]

def _strip_trailing_digits(name: str) -> str:
    """Strip a trailing .N (digits only) from the name."""
    dot = name.rfind('.')
    if dot == -1:
        return name
    if name[dot + 1:].isdigit():
        return name[:dot]
    return name

def _strip_suffix(name: str, suffix: str) -> str:
    """Strip suffix (last occurrence) and any trailing .[digits] left behind."""
    idx = name.rfind(suffix)
    if idx == -1:
        return name
    result = name[:idx] + name[idx + len(suffix):]
    return _strip_trailing_digits(result)

def elide_suffix_selected(name: str) -> str:
    """Strip matching compiler suffixes from name."""
    for suffix in _selected_suffixes:
        name = _strip_suffix(name, suffix)
    return name

_NAME_FN = {
    'none': lambda n: n,
    'all': elide_suffix_all,
    'selected': elide_suffix_selected,
}

def get_original_name(name: str, policy: str) -> str:
    fn = _NAME_FN.get(policy)
    if fn is None:
        raise ValueError(f"unknown suffix elision policy: {policy}")
    return fn(name)

def _elide_node(node, policy: str) -> None:
    for offset in list(node.targets):
        targets = node.targets[offset]
        normalized: dict[tuple[str, str | None], int] = {}
        for (tgt_name, tgt_src), count in targets.items():
            base = get_original_name(tgt_name, policy)
            key = (base, tgt_src)
            normalized[key] = normalized.get(key, 0) + count
        node.targets[offset] = type(targets)(normalized)

    to_rename = []
    for (off, callee_name, callee_src), child in list(node.children.items()):
        base = get_original_name(callee_name, policy)
        if base != callee_name:
            to_rename.append(((off, callee_name, callee_src), off, base, callee_src, child))

    renamed: set[int] = set()
    for old_key, off, base_name, callee_src, child in to_rename:
        node.children.pop(old_key)
        _elide_node(child, policy)
        renamed.add(id(child))
        new_key = (off, base_name, callee_src)
        if new_key in node.children:
            merge_nodes(node.children[new_key], child)
        else:
            child.name = base_name
            node.children[new_key] = child

    for child in node.children.values():
        if id(child) not in renamed:
            _elide_node(child, policy)

def elide_tree_suffixes(tree: dict, policy: str) -> None:
    if policy == 'none':
        return

    to_rename = [(key, (get_original_name(key[0], policy), key[1]))
                 for key in list(tree.keys())]

    for orig_key, new_key in to_rename:
        if orig_key == new_key:
            continue
        node = tree.pop(orig_key)
        _elide_node(node, policy)
        if new_key in tree:
            merge_nodes(tree[new_key], node)
        else:
            node.name = new_key[0]
            tree[new_key] = node

    for node in tree.values():
        _elide_node(node, policy)
