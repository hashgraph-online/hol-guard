"""Static value helpers for Python capability cleanup analysis."""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping
from itertools import product
from pathlib import Path

_MAX_DYNAMIC_IMPORT_DESTINATION = 256
_IMPORT_DESTINATION_RE = re.compile(r"^(?:\.+(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)?|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)$")


class DynamicImport:
    __slots__ = ("destination_count", "destination_kind", "destination_values", "line", "module")

    def __init__(
        self,
        module: str,
        line: int,
        destination_kind: str,
        destination_count: int,
        destination_values: tuple[str, ...] | None,
    ) -> None:
        self.module = module
        self.line = line
        self.destination_kind = destination_kind
        self.destination_count = destination_count
        self.destination_values = destination_values


def module_name(root: Path, path: Path) -> str:
    relative = path.relative_to(root / "src").with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def resolve_import(module_name_value: str, level: int, imported: str | None) -> str:
    if level == 0:
        return imported or ""
    package = module_name_value.split(".")[:-1]
    base = package[: len(package) - level + 1]
    if imported:
        base.append(imported)
    return ".".join(base)


def _assignment_targets(target: ast.AST, value: object) -> dict[str, object]:
    """Bind names in a static tuple assignment without evaluating code."""

    if isinstance(target, ast.Name):
        return {target.id: value}
    if not isinstance(target, (ast.Tuple, ast.List)) or not isinstance(value, tuple):
        return {}
    bindings: dict[str, object] = {}
    if len(target.elts) != len(value):
        return bindings
    for child, child_value in zip(target.elts, value, strict=True):
        bindings.update(_assignment_targets(child, child_value))
    return bindings


def _static_sequence(node: ast.AST, assignments: dict[str, ast.AST], seen: set[str]) -> tuple[object, ...] | None:
    if isinstance(node, ast.Name):
        if node.id in seen or node.id not in assignments:
            return None
        return _static_sequence(assignments[node.id], assignments, {*seen, node.id})
    if not isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return None
    values: list[object] = []
    for element in node.elts:
        if isinstance(element, ast.Constant) and isinstance(element.value, str):
            values.append(element.value)
            continue
        nested = _static_sequence(element, assignments, seen)
        if nested is None:
            return None
        values.append(nested)
    return tuple(values)


def _static_strings(
    node: ast.AST,
    assignments: dict[str, ast.AST],
    bindings: Mapping[str, _StaticValue],
    seen: set[str] | None = None,
) -> frozenset[str] | None:
    """Resolve a bounded string expression, without importing or executing it."""

    seen = seen or set()
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return frozenset({node.value})
    if isinstance(node, ast.Name):
        if node.id in bindings:
            return bindings[node.id]
        assignment = assignments.get(node.id)
        if assignment is None or node.id in seen:
            return None
        return _static_strings(assignment, assignments, bindings, {*seen, node.id})
    if isinstance(node, ast.IfExp):
        left = _static_strings(node.body, assignments, bindings, seen)
        right = _static_strings(node.orelse, assignments, bindings, seen)
        if left is None or right is None:
            return None
        return left | right
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_strings(node.left, assignments, bindings, seen)
        right = _static_strings(node.right, assignments, bindings, seen)
        if left is None or right is None or len(left) * len(right) > 32:
            return None
        return frozenset("".join(parts) for parts in product(left, right))
    return None


def _assigned_names(target: ast.AST) -> tuple[str, ...]:
    if isinstance(target, ast.Name):
        return (target.id,)
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for child in target.elts:
            names.extend(_assigned_names(child))
        return tuple(names)
    return ()


class _StaticScope:
    __slots__ = (
        "assignments",
        "bindings",
        "call_aliases",
        "call_bindings",
        "entry_bindings",
        "entry_function_bindings",
        "entry_import_aliases",
        "entry_importlib_aliases",
        "entry_module_bindings",
        "entry_recorded",
        "entry_sequences",
        "function_bindings",
        "loop_nodes",
        "merged_assignments",
        "merged_bindings",
        "merged_function_bindings",
        "merged_import_aliases",
        "merged_importlib_aliases",
        "merged_module_bindings",
        "merged_sequences",
        "node",
        "parameters",
        "parent",
    )

    def __init__(self, node: ast.AST | None, parent: _StaticScope | None) -> None:
        self.node = node
        self.parent = parent
        self.assignments: dict[str, ast.AST] = {}
        self.bindings: dict[str, frozenset[str]] = {}
        self.loop_nodes: list[ast.For | ast.AsyncFor] = []
        self.merged_assignments: dict[str, ast.AST] = {}
        self.merged_bindings: dict[str, _StaticValue] = {}
        self.merged_function_bindings: dict[str, tuple[str, int] | None] = {}
        self.merged_import_aliases: frozenset[str] = frozenset()
        self.merged_importlib_aliases: frozenset[str] = frozenset()
        self.merged_module_bindings: dict[str, str | None] = {}
        self.merged_sequences: dict[str, tuple[object, ...] | None] = {}
        self.parameters: frozenset[str] = frozenset()
        self.function_bindings: dict[str, tuple[str, int] | None] = {}
        self.call_aliases: dict[int, tuple[frozenset[str], frozenset[str]]] = {}
        self.call_bindings: dict[int, dict[str, frozenset[str] | None]] = {}
        self.entry_bindings: dict[str, _StaticValue] = {}
        self.entry_sequences: dict[str, tuple[object, ...] | None] = {}
        self.entry_import_aliases: frozenset[str] = frozenset()
        self.entry_importlib_aliases: frozenset[str] = frozenset()
        self.entry_function_bindings: dict[str, tuple[str, int] | None] = {}
        self.entry_module_bindings: dict[str, str | None] = {}
        self.entry_recorded = False


def _function_parameters(node: ast.AST | None) -> frozenset[str]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return frozenset()
    arguments = node.args
    parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    if arguments.vararg is not None:
        parameters.append(arguments.vararg)
    if arguments.kwarg is not None:
        parameters.append(arguments.kwarg)
    return frozenset(argument.arg for argument in parameters)


_StaticValue = frozenset[str] | None
_FunctionIdentity = tuple[str, int]
_SequenceValue = tuple[object, ...] | None


def _merge_sequence_values(left: _SequenceValue, right: _SequenceValue) -> _SequenceValue:
    """Retain a sequence only when both control-flow paths agree exactly."""

    return left if left == right else None


def _merge_static_values(left: _StaticValue, right: _StaticValue) -> _StaticValue:
    if left is None or right is None:
        return None
    merged = left | right
    return merged if len(merged) <= 32 else None


def _merge_static_bindings(
    left: Mapping[str, _StaticValue],
    right: Mapping[str, _StaticValue],
) -> dict[str, _StaticValue]:
    return {name: _merge_static_values(left.get(name), right.get(name)) for name in left.keys() | right.keys()}


def _resolve_static_strings(
    node: ast.AST,
    bindings: Mapping[str, _StaticValue],
    seen: set[str] | None = None,
) -> frozenset[str] | None:
    """Resolve a string expression against values proven before one callsite."""

    seen = seen or set()
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return frozenset({node.value})
    if isinstance(node, ast.Name):
        if node.id in seen:
            return None
        value = bindings.get(node.id)
        return value if value is not None else None
    if isinstance(node, ast.IfExp):
        left = _resolve_static_strings(node.body, bindings, seen)
        right = _resolve_static_strings(node.orelse, bindings, seen)
        if left is None or right is None:
            return None
        return _merge_static_values(left, right)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_static_strings(node.left, bindings, seen)
        right = _resolve_static_strings(node.right, bindings, seen)
        if left is None or right is None or len(left) * len(right) > 32:
            return None
        return frozenset("".join(parts) for parts in product(left, right))
    return None


def _resolve_static_sequence(
    node: ast.AST,
    bindings: Mapping[str, _SequenceValue],
    seen: set[str] | None = None,
) -> tuple[object, ...] | None:
    if isinstance(node, ast.Name):
        if node.id in (seen or set()):
            return None
        return bindings.get(node.id)
    if not isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return None
    values: list[object] = []
    for element in node.elts:
        if isinstance(element, ast.Constant) and isinstance(element.value, str):
            values.append(element.value)
            continue
        nested = _resolve_static_sequence(element, bindings, seen)
        if nested is None:
            return None
        values.append(nested)
    return tuple(values)
