"""What a module's own source fixes a name to.

``runtime_majority_imports`` asks this module one question about every name a
dynamic import is handed: is there a value the source holds it to? The answer
has to be conservative. A name this module cannot prove is answered ``None``,
which reads as open, so the import site that uses it is counted unresolved and
the scope contract has to declare it. A wrong value here would hide an import
edge from the runtime-majority report altogether.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator
from typing import Any


def literal_strings(node: ast.expr, env: dict[str, set[str] | None]) -> set[str] | None:
    """Every string ``node`` can evaluate to, or ``None`` when the source leaves it open."""
    if isinstance(node, ast.Constant):
        return {node.value} if isinstance(node.value, str) else None
    if isinstance(node, ast.IfExp):
        body = literal_strings(node.body, env)
        orelse = literal_strings(node.orelse, env)
        return None if body is None or orelse is None else body | orelse
    if isinstance(node, ast.Name):
        return env.get(node.id)
    return None


def column_values(rows: list[set[str] | None]) -> set[str] | None:
    """Union of one column of candidate values, or ``None`` if any row is open."""
    if not rows or any(row is None for row in rows):
        return None
    result: set[str] = set()
    for row in rows:
        result |= row or set()
    return result


def _rebound_names(tree: ast.Module) -> set[str]:
    """Module-level names something in the module can point somewhere else.

    An augmented assignment replaces the name's value, and a ``global``
    declaration lets a function assign to it from anywhere in the module, so
    neither name holds the literal the module-level statement gave it.
    """
    rebound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            rebound.add(node.target.id)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            rebound.update(node.names)
    return rebound


def _mutated_names(tree: ast.Module) -> set[str]:
    """Names whose contents something in the module can change in place.

    A list keeps its identity through ``append``, ``extend``, an item
    assignment or a ``del``, so the elements the module-level statement listed
    are not the elements the loop will see. Any method call on the name counts:
    telling a mutating method from a reading one needs the type, which a syntax
    scan does not have.
    """
    mutated: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                mutated.add(node.func.value.id)
            continue
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            targets = [node.target]
        elif isinstance(node, ast.Delete):
            targets = list(node.targets)
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                mutated.add(target.value.id)
    return mutated


def literal_tables(tree: ast.Module) -> dict[str, list[ast.expr]]:
    """Module-level names bound exactly once to a literal tuple or list.

    The name must also keep that value: one the module rebinds through an
    augmented assignment or a ``global``, or whose list contents it can change
    in place, is left out, because the elements a loop reads from it are then
    not the elements written here.
    """
    tables: dict[str, list[ast.expr]] = {}
    seen: set[str] = set()
    rebound = _rebound_names(tree)
    mutated = _mutated_names(tree)
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            name, value = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            name, value = stmt.target.id, stmt.value
        else:
            continue
        if name in seen:
            tables.pop(name, None)
            continue
        seen.add(name)
        if name in rebound:
            continue
        if isinstance(value, ast.Tuple) or (isinstance(value, ast.List) and name not in mutated):
            tables[name] = list(value.elts)
    return tables


def target_names(node: ast.expr) -> Iterator[str]:
    """Every name one assignment target binds, unpacking tuples and stars."""
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, ast.Starred):
        yield from target_names(node.value)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            yield from target_names(item)


def scope_bindings(body: list[ast.stmt], params: Iterable[str] = ()) -> tuple[dict[str, int], dict[str, int]]:
    """How often one scope binds each name, and how often it binds it plainly.

    A plain binding is ``name = <expr>`` or ``name: T = <expr>`` with a single
    name target: the only form a value can be read out of. Every other way a
    scope binds a name -- a parameter, an augmented assignment, a tuple unpack,
    a loop, ``with`` or ``except`` target, a walrus, an import alias, a nested
    ``def`` or ``class``, a ``global`` or ``nonlocal`` declaration, a ``del``,
    a match capture -- is counted but never plain. A name is only worth an
    inferred value when the scope binds it exactly once and plainly; anything
    else reads as open, so the import site that uses it needs a declaration.

    Nested function, lambda and class bodies are scopes of their own and are
    not descended into; the name each one binds is counted here. Comprehension
    targets bind inside the comprehension, so they are not counted, while a
    walrus inside one does bind here and is.
    """
    counts: dict[str, int] = {}
    plain: dict[str, int] = {}

    def bump(name: str, *, is_plain: bool = False) -> None:
        counts[name] = counts.get(name, 0) + 1
        if is_plain:
            plain[name] = plain.get(name, 0) + 1

    for name in params:
        bump(name)

    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bump(node.name)
            return
        if isinstance(node, ast.Lambda):
            return
        if isinstance(node, ast.Assign):
            single = len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
            for target in node.targets:
                for name in target_names(target):
                    bump(name, is_plain=single)
        elif isinstance(node, ast.AnnAssign):
            for name in target_names(node.target):
                bump(name, is_plain=node.value is not None)
        elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor, ast.NamedExpr)):
            for name in target_names(node.target):
                bump(name)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            for name in target_names(node.optional_vars):
                bump(name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bump(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bump(alias.asname or alias.name.partition(".")[0])
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bump(name)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                for name in target_names(target):
                    bump(name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bump(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bump(node.rest)
        for child in ast.iter_child_nodes(node):
            visit(child)

    for stmt in body:
        visit(stmt)
    return counts, plain


def _calls_by_name(tree: ast.Module) -> dict[str, list[tuple[ast.Call, bool]]]:
    """Every ``name(...)`` call in the module, paired with whether it runs at import time."""
    calls: dict[str, list[tuple[ast.Call, bool]]] = {}

    def walk(node: ast.AST, eager: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                calls.setdefault(child.func.id, []).append((child, eager))
            nested = eager and not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
            walk(child, nested)

    walk(tree, True)
    return calls


def wrapper_literals(tree: ast.Module) -> dict[str, dict[str, Any]]:
    """Parameters of module-private helpers that every call site fixes to literals.

    A helper whose name appears only as the callee of a call in its own module
    cannot be reached with other arguments, so its parameters are known to be
    exactly the literals those call sites pass.  ``mode`` is ``eager`` when any
    call site runs at import time, because the helper's imports then run too.
    """
    functions = {
        stmt.name: stmt
        for stmt in tree.body
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name.startswith("_")
    }
    if not functions:
        return {}
    calls = _calls_by_name(tree)
    callee_ids = {id(call.func) for sites in calls.values() for call, _ in sites}
    escaped = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id in functions and id(node) not in callee_ids
    }
    bindings: dict[str, dict[str, Any]] = {}
    for name, function in functions.items():
        sites = calls.get(name, [])
        spec = function.args
        if name in escaped or not sites or spec.posonlyargs or spec.kwonlyargs or spec.vararg or spec.kwarg:
            continue
        params = [argument.arg for argument in spec.args]
        columns: list[list[set[str] | None]] = [[] for _ in params]
        if any(
            call.keywords or len(call.args) != len(params) or any(isinstance(item, ast.Starred) for item in call.args)
            for call, _ in sites
        ):
            continue
        for call, _ in sites:
            for index, argument in enumerate(call.args):
                columns[index].append(literal_strings(argument, {}))
        resolved = {
            param: values
            for param, column in zip(params, columns, strict=True)
            if (values := column_values(column)) is not None
        }
        if resolved:
            bindings[name] = {"params": resolved, "mode": "eager" if any(eager for _, eager in sites) else "lazy"}
    return bindings
