"""Conservative Python call-graph resolution for the Rust I/O ownership gate."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from scripts.ci.rust_io_ownership_bindings import (
    _PYTHON_BUILTINS,
    FunctionRecordLike,
    RecordT,
    _local_binding_names,
    _module_level_names,
)
from scripts.ci.rust_io_ownership_cache import cached
from scripts.ci.rust_io_ownership_cache import parsed_module as _parsed_module


@cached
def _module_file(root: Path, target: Path) -> str | None:
    """Resolve a source module/package path to its repository-relative file."""

    candidate = root / target
    if candidate.is_file() and candidate.suffix == ".py":
        return target.as_posix()
    init_file = candidate / "__init__.py"
    if init_file.is_file():
        return init_file.relative_to(root).as_posix()
    module_file = candidate.with_suffix(".py")
    if module_file.is_file():
        return module_file.relative_to(root).as_posix()
    return None


@cached
def _import_target_path(
    root: Path,
    source_path: str,
    node: ast.ImportFrom,
    imported_name: str | None = None,
) -> str | None:
    """Resolve an ``ImportFrom`` target, including package ``__init__`` files."""

    source_file = root / source_path
    if node.level:
        base = source_file.parent
        for _ in range(node.level - 1):
            base = base.parent
        parts = tuple((node.module or "").split(".")) if node.module else ()
    else:
        module = node.module
        if not module:
            return None
        parts = tuple(module.split("."))
        base = root / "src"
    if not node.module and imported_name:
        parts = (imported_name,)
    try:
        relative_target = (base / Path(*parts)).relative_to(root)
    except ValueError:
        return None
    return _module_file(root, relative_target)


@cached
def _repository_module_path(root: Path, module_name: str) -> str | None:
    """Resolve a dotted import to a repository-relative module file."""

    parts = tuple(part for part in module_name.split(".") if part)
    if not parts:
        return None
    for base in (root / "src", root):
        target = base.joinpath(*parts)
        relative_target = target.relative_to(root)
        resolved = _module_file(root, relative_target)
        if resolved is not None:
            return resolved
    return None


@cached
def _module_dunder_all(tree: ast.Module) -> frozenset[str] | None:
    """Return a module's literal ``__all__`` names when statically declared."""

    for item in tree.body:
        if not isinstance(item, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in item.targets):
            continue
        if isinstance(item.value, (ast.List, ast.Tuple)):
            names = [
                element.value
                for element in item.value.elts
                if isinstance(element, ast.Constant) and isinstance(element.value, str)
            ]
            return frozenset(names)
    return None


@cached
def _module_binds_symbol(tree: ast.Module, name: str) -> bool:
    """Return whether a module binds ``name`` at top level (vars() semantics)."""

    for item in tree.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if item.name == name:
                return True
        elif isinstance(item, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == name for target in item.targets):
                return True
        elif isinstance(item, ast.AnnAssign):
            if isinstance(item.target, ast.Name) and item.target.id == name:
                return True
        elif isinstance(item, ast.ImportFrom):
            if any((alias.asname or alias.name) == name for alias in item.names):
                return True
        elif isinstance(item, ast.Import) and any(
            (alias.asname or alias.name.split(".", maxsplit=1)[0]) == name for alias in item.names
        ):
            return True
    return False


@cached
def _union_source_modules(root: Path, module_path: str, tree: ast.Module) -> tuple[str, ...]:
    """Return ordered member modules for a ``_SOURCE_MODULES`` union module.

    Union modules aggregate members with ``from . import member as _member``
    plus a ``_SOURCE_MODULES`` tuple, then resolve exports dynamically.
    """

    bindings: dict[str, str] = {}
    for item in tree.body:
        if not isinstance(item, ast.ImportFrom) or not item.level or item.module:
            continue
        for alias in item.names:
            local = alias.asname or alias.name
            target = _import_target_path(root, module_path, item, alias.name)
            if target is not None:
                bindings[local] = target
    for item in tree.body:
        if isinstance(item, ast.Assign):
            targets: list[ast.expr] = list(item.targets)
            value = item.value
        elif isinstance(item, ast.AnnAssign):
            targets = [item.target]
            value = item.value
        else:
            continue
        if value is None or not isinstance(value, (ast.Tuple, ast.List)):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "_SOURCE_MODULES" for target in targets):
            continue
        members = [
            bindings[element.id] for element in value.elts if isinstance(element, ast.Name) and element.id in bindings
        ]
        if members:
            return tuple(members)
    return ()


def _resolve_exported_symbol(
    root: Path,
    module_path: str,
    name: str,
    seen: set[tuple[str, str]],
) -> str | None:
    """Find the source file defining an exported symbol, following re-exports."""

    identity = (module_path, name)
    if identity in seen:
        return None
    seen.add(identity)
    tree = _parsed_module(root / module_path)
    for item in tree.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name:
            return module_path
        if isinstance(item, ast.ClassDef) and any(
            isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and member.name == name for member in item.body
        ):
            return module_path
    for item in tree.body:
        if not isinstance(item, ast.ImportFrom):
            continue
        for alias in item.names:
            if alias.name == "*":
                target = _import_target_path(root, module_path, item)
                if target is not None:
                    resolved = _resolve_exported_symbol(root, target, name, seen)
                    if resolved is not None:
                        return resolved
                continue
            local_name = alias.asname or alias.name
            if local_name != name:
                continue
            target = _import_target_path(root, module_path, item, alias.name)
            if target is None:
                continue
            resolved = _resolve_exported_symbol(root, target, alias.name, seen)
            if resolved is not None:
                return resolved
    for member_path in _union_source_modules(root, module_path, tree):
        member_tree = _parsed_module(root / member_path)
        exported = _module_dunder_all(member_tree)
        if exported is not None:
            if name not in exported:
                continue
        elif not _module_binds_symbol(member_tree, name):
            continue
        resolved = _resolve_exported_symbol(root, member_path, name, seen)
        if resolved is not None:
            return resolved
    return None


def _class_definition_path(
    root: Path,
    module_path: str,
    name: str,
    seen: set[tuple[str, str]],
) -> str | None:
    """Find the source file defining ``name`` as a class, following imports.

    ``Class.method`` and ``instance.method`` calls resolve through the class
    binding's defining module so method records in that file can match;
    non-class bindings (constants, compiled patterns) are not repository
    helper calls and yield ``None``.
    """

    identity = (module_path, name)
    if identity in seen:
        return None
    seen.add(identity)
    tree = _parsed_module(root / module_path)
    for item in tree.body:
        if isinstance(item, ast.ClassDef) and item.name == name:
            return module_path
    for item in tree.body:
        if not isinstance(item, ast.ImportFrom):
            continue
        for alias in item.names:
            if alias.name == "*":
                target = _import_target_path(root, module_path, item)
                if target is not None:
                    resolved = _class_definition_path(root, target, name, seen)
                    if resolved is not None:
                        return resolved
                continue
            local_name = alias.asname or alias.name
            if local_name != name:
                continue
            target = _import_target_path(root, module_path, item, alias.name)
            if target is None:
                continue
            resolved = _class_definition_path(root, target, alias.name, seen)
            if resolved is not None:
                return resolved
    return None


@dataclass(frozen=True, slots=True)
class _VisibleImport:
    node: ast.Import | ast.ImportFrom
    scope: int


@cached
def _function_scopes(tree: ast.Module, qualname: str) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    """Return enclosing function scopes for a qualified function name."""

    def visit(
        body: list[ast.stmt],
        prefix: str,
        enclosing: tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...],
    ) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...] | None:
        for item in body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                current = f"{prefix}.{item.name}" if prefix else item.name
                if current == qualname:
                    return (*enclosing, item)
                if qualname.startswith(f"{current}."):
                    nested = visit(item.body, current, (*enclosing, item))
                    if nested is not None:
                        return nested
            elif isinstance(item, ast.ClassDef):
                current = f"{prefix}.{item.name}" if prefix else item.name
                if qualname.startswith(f"{current}."):
                    nested = visit(item.body, current, enclosing)
                    if nested is not None:
                        return nested
        return None

    return visit(tree.body, "", ()) or ()


def _scope_imports(body: list[ast.stmt]) -> tuple[ast.Import | ast.ImportFrom, ...]:
    """Collect imports in one lexical scope, excluding nested scopes."""

    imports: list[ast.Import | ast.ImportFrom] = []

    class Collector(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import) -> None:
            imports.append(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            imports.append(node)

        def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, _node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, _node: ast.Lambda) -> None:
            return

    collector = Collector()
    for statement in body:
        collector.visit(statement)
    return tuple(imports)


@cached
def _visible_imports(root: Path, record: FunctionRecordLike) -> tuple[_VisibleImport, ...]:
    """Return module and enclosing-function imports visible to ``record``."""

    tree = _parsed_module(root / record.path)
    visible = [_VisibleImport(node, 0) for node in _scope_imports(tree.body)]
    for scope, function in enumerate(_function_scopes(tree, record.qualname), start=1):
        visible.extend(_VisibleImport(node, scope) for node in _scope_imports(function.body))
    return tuple(visible)


def _qualified_parts(name: str) -> tuple[str, str] | None:
    parts = name.split(".")
    if len(parts) < 2 or any(not part for part in parts):
        return None
    return parts[0], parts[-1]


@cached
def imported_symbol_path(root: Path, record: FunctionRecordLike, name: str) -> tuple[str, str | None] | None:
    """Return the repository path and symbol name imported for ``name``.

    The second element carries the callee's defining name so aliased imports
    (``from m import real as alias``) match records by the real symbol, not
    the local alias.
    """

    qualified = _qualified_parts(name)
    binding_name, symbol_name = qualified or (name, name)
    imports = sorted(_visible_imports(root, record), key=lambda item: (item.scope, item.node.lineno))
    for visible in reversed(imports):
        node = visible.node
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if qualified is not None:
                    local_name = alias.asname or alias.name
                    if alias.name == "*" or local_name != binding_name:
                        continue
                    target = _import_target_path(root, record.path, node, alias.name)
                    if target is None:
                        continue
                    resolved = _resolve_exported_symbol(root, target, symbol_name, set())
                    if resolved is not None:
                        return resolved, symbol_name
                    binding_path = _class_definition_path(root, target, binding_name, set())
                    if binding_path is not None:
                        return binding_path, symbol_name
                    if not node.module:
                        # ``from . import module`` binds a module; an
                        # unresolved attribute on it must fail closed.
                        raise RuntimeError(
                            f"unresolved repository-qualified helper call {name!r} from {record.path}:{record.qualname}"
                        )
                    return None
                else:
                    local_name = alias.asname or alias.name
                    if alias.name != "*" and local_name != name:
                        continue
                    target = _import_target_path(root, record.path, node, alias.name if alias.name != "*" else None)
                    if target is None:
                        continue
                    if alias.name == "*":
                        resolved = _resolve_exported_symbol(root, target, name, set())
                        if resolved is not None:
                            return resolved, name
                    else:
                        resolved = _resolve_exported_symbol(root, target, alias.name, set()) or target
                        return resolved, alias.name
        else:
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                if local_name != binding_name:
                    continue
                target = _repository_module_path(root, alias.name if alias.asname else local_name)
                if target is None:
                    continue
                if qualified is None:
                    return target, None
                resolved = _resolve_exported_symbol(root, target, symbol_name, set())
                if resolved is None:
                    raise RuntimeError(
                        f"unresolved repository-qualified helper call {name!r} from {record.path}:{record.qualname}"
                    )
                return resolved, symbol_name
    return None


class FunctionIndex(dict[tuple[str, str], list[RecordT]]):
    """Index the existing record order once instead of scanning it per call."""

    def __init__(self, records: Mapping[tuple[str, str], list[RecordT]]) -> None:
        super().__init__(records)
        self.by_name: dict[str, list[RecordT]] = {}
        for (_path, name), values in records.items():
            self.by_name.setdefault(name, []).extend(values)


def resolve_call(
    root: Path,
    record: RecordT,
    name: str,
    records: Mapping[tuple[str, str], list[RecordT]],
) -> RecordT | None:
    """Resolve a call or fail closed when duplicate helpers remain ambiguous."""

    if "." not in name:
        nested = [c for c in records.get((record.path, name), []) if c.qualname == f"{record.qualname}.{name}"]
        if len(nested) == 1:
            return nested[0]
        if len(nested) > 1:
            raise RuntimeError(f"ambiguous nested helper call {name!r} from {record.path}:{record.qualname}")
    imported = imported_symbol_path(root, record, name)
    if (
        "." not in name
        and imported is None
        and (
            name in _local_binding_names(record)
            or (name in _PYTHON_BUILTINS and name not in _module_level_names(root, record))
        )
    ):
        return None
    qualifier = name.split(".")[-2] if "." in name else None
    if "." in name:
        if imported is None:
            return None
        name = name.rsplit(".", 1)[-1]
    matches = (
        records.by_name.get(name, [])
        if isinstance(records, FunctionIndex)
        else [
            candidate
            for (_path, candidate_name), values in records.items()
            if candidate_name == name
            for candidate in values
        ]
    )
    if not matches:
        return None
    if imported is not None:
        imported_path, imported_name = imported
        imported_matches = list(records.get((imported_path, imported_name or name), []))
        if qualifier is not None:
            qualified_matches = [
                candidate
                for candidate in imported_matches
                if candidate.qualname == f"{qualifier}.{imported_name or name}"
            ]
            if qualified_matches:
                imported_matches = qualified_matches
        if len(imported_matches) == 1:
            return imported_matches[0]
        if len(imported_matches) > 1:
            matches = imported_matches
    caller_scope = record.qualname.rsplit(".", 1)[0] if "." in record.qualname else ""
    local_scope = [
        candidate
        for candidate in matches
        if candidate.path == record.path
        and (candidate.qualname.rsplit(".", 1)[0] if "." in candidate.qualname else "") == caller_scope
    ]
    if len(local_scope) == 1:
        return local_scope[0]
    if len(local_scope) > 1:
        matches = local_scope
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        enclosing = [
            candidate.qualname.rsplit(".", 1)[0]
            for candidate in matches
            if candidate.path == record.path
            and "." in candidate.qualname
            and (
                record.qualname == candidate.qualname.rsplit(".", 1)[0]
                or record.qualname.startswith(f"{candidate.qualname.rsplit('.', 1)[0]}.")
            )
        ]
        if enclosing:
            deepest = max(enclosing, key=len)
            narrowed = [
                candidate
                for candidate in matches
                if candidate.path == record.path and candidate.qualname.rsplit(".", 1)[0] == deepest
            ]
            if len(narrowed) == 1:
                return narrowed[0]
            matches = narrowed or matches
    if len(matches) == 1:
        return matches[0]
    module_scope = [candidate for candidate in matches if candidate.path == record.path and candidate.qualname == name]
    if len(module_scope) == 1:
        return module_scope[0]
    identity = {(item.path, item.qualname) for item in matches}
    if len(identity) == 1:
        return matches[0]
    candidates = ", ".join(f"{item.path}:{item.qualname}" for item in matches)
    raise RuntimeError(f"ambiguous helper call {name!r} from {record.path}:{record.qualname}: {candidates}")
