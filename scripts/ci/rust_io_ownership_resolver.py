"""Conservative Python call-graph resolution for the Rust I/O ownership gate."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, TypeVar


class FunctionRecordLike(Protocol):
    """Minimum function-record shape needed by the resolver."""

    path: str
    qualname: str
    node: ast.FunctionDef | ast.AsyncFunctionDef


RecordT = TypeVar("RecordT", bound=FunctionRecordLike)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect {path}") from exc


def _local_binding_names(record: FunctionRecordLike) -> frozenset[str]:
    """Return names bound as local values in a function body.

    A direct call such as ``close()`` may invoke a callable stored in a local
    variable rather than a repository helper. Treating every such name as a
    global helper creates false ambiguities and does not improve reachability.
    """

    names: set[str] = set()
    arguments = record.node.args
    for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs):
        names.add(argument.arg)
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)

    def collect_target(target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                collect_target(item)

    for node in ast.walk(record.node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                collect_target(target)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr, ast.For, ast.AsyncFor)):
            collect_target(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    collect_target(item.optional_vars)
        elif isinstance(node, ast.comprehension):
            collect_target(node.target)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return frozenset(names)


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
    return _module_file(root, (base / Path(*parts)).relative_to(root))


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
    tree = ast.parse(_read(root / module_path), filename=module_path)
    for item in tree.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name:
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
    return None


def imported_symbol_path(root: Path, record: FunctionRecordLike, name: str) -> str | None:
    """Return the repository path imported for ``name`` at a call site."""

    tree = ast.parse(_read(root / record.path), filename=record.path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        for alias in node.names:
            local_name = alias.asname or alias.name
            if alias.name != "*" and local_name != name:
                continue
            if alias.name == "*":
                target = _import_target_path(root, record.path, node)
                if target is None:
                    continue
                resolved = _resolve_exported_symbol(root, target, name, set())
                if resolved is not None:
                    return resolved
                continue
            target = _import_target_path(root, record.path, node, alias.name)
            if target is None:
                continue
            return _resolve_exported_symbol(root, target, alias.name, set()) or target
    return None


def resolve_call(
    root: Path,
    record: RecordT,
    name: str,
    records: Mapping[tuple[str, str], list[RecordT]],
) -> RecordT | None:
    """Resolve a call or fail closed when duplicate helpers remain ambiguous."""

    if name in _local_binding_names(record):
        return None
    matches = [
        candidate
        for (_path, candidate_name), values in records.items()
        if candidate_name == name
        for candidate in values
    ]
    if not matches:
        return None
    imported_path = imported_symbol_path(root, record, name)
    if imported_path is not None:
        imported_matches = [candidate for candidate in matches if candidate.path == imported_path]
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
    candidates = ", ".join(f"{item.path}:{item.qualname}" for item in matches)
    raise RuntimeError(f"ambiguous helper call {name!r} from {record.path}:{record.qualname}: {candidates}")
