"""Function-level exclusions for the runtime-majority report.

Some in-scope modules mix runtime code with CLI-only, offline or control-plane
code.  A ``python.function_exclusions`` entry removes named top-level symbols
(functions, classes, module variables) from one module, together with
top-level imports that only those symbols use.  Every entry carries
``evidence`` and the exclusion is validated by a reference closure:

* retained code in the same module may reference an excluded symbol only from
  a listed ``entry_points`` symbol (the reviewed dispatcher into that code);
* no other in-scope module may import an excluded symbol;
* roots are never eligible, so process and hook entry modules stay whole.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MODULE_OWNER = "<module>"
SKIP_TOKENS = frozenset(
    {
        tokenize.COMMENT,
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENCODING,
        tokenize.ENDMARKER,
    }
)


class ScopeError(RuntimeError):
    """The scope configuration is malformed or names a missing root."""


@dataclass
class ModulePlan:
    """What is removed from one module and why."""

    path: str
    symbol_lines: dict[str, tuple[int, int]] = field(default_factory=dict)
    symbol_entry: dict[str, str] = field(default_factory=dict)
    import_ranges: list[tuple[int, int]] = field(default_factory=list)
    skip_linenos: set[int] = field(default_factory=set)
    removed_lines: set[int] = field(default_factory=set)
    symbol_loc: dict[str, int] = field(default_factory=dict)
    import_loc: int = 0


def counted_lines(source: str) -> set[int]:
    lines: set[int] = set()
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type in SKIP_TOKENS:
                continue
            lines.update(range(token.start[0], token.end[0] + 1))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return {
            number
            for number, line in enumerate(source.splitlines(), start=1)
            if line.strip() and not line.lstrip().startswith("#")
        }
    return lines


def _target_names(node: ast.stmt) -> list[str]:
    if isinstance(node, ast.Assign):
        return [target.id for target in node.targets if isinstance(target, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    return []


def _symbol_names(node: ast.stmt) -> list[str]:
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return [node.name]
    return _target_names(node)


def _node_range(node: ast.stmt) -> tuple[int, int]:
    decorators = getattr(node, "decorator_list", [])
    start = min([node.lineno, *(item.lineno for item in decorators)])
    return start, node.end_lineno or node.lineno


def _bound_names(node: ast.Import | ast.ImportFrom) -> list[str]:
    names = []
    for alias in node.names:
        if alias.name == "*":
            return []
        names.append(alias.asname or alias.name.split(".")[0])
    return names


def _name_uses(nodes: list[ast.AST]) -> tuple[set[str], str]:
    """Identifier uses plus all string constants (annotations, ``__all__``) of ``nodes``."""
    used: set[str] = set()
    strings: list[str] = []
    for root in nodes:
        for node in ast.walk(root):
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                strings.append(node.value)
    return used, "\n".join(strings)


def _owner_refs(node: ast.stmt, excluded: set[str]) -> set[str]:
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name) and item.id in excluded}


def plan_module(path: str, source: str, entries: list[dict[str, Any]], *, root_paths: set[str]) -> ModulePlan:
    if path in root_paths:
        raise ScopeError(f"function exclusion {entries[0]['id']!r}: {path} is a runtime root and stays whole")
    tree = ast.parse(source)
    plan = ModulePlan(path=path)
    wanted: dict[str, str] = {}
    for entry in entries:
        for symbol in entry["symbols"]:
            if symbol in wanted:
                raise ScopeError(f"function exclusion {entry['id']!r}: {symbol} is listed twice for {path}")
            wanted[symbol] = entry["id"]
    entry_points = {str(point) for entry in entries for point in entry.get("entry_points", [])}
    retained: list[ast.stmt] = []
    excluded_nodes: list[ast.stmt] = []
    for node in tree.body:
        hit = [name for name in _symbol_names(node) if name in wanted]
        if hit:
            if len(hit) != len(_symbol_names(node)):
                raise ScopeError(f"{path}: statement binds both excluded and retained names {_symbol_names(node)}")
            start, end = _node_range(node)
            for name in hit:
                plan.symbol_lines[name] = (start, end)
                plan.symbol_entry[name] = wanted[name]
            plan.skip_linenos.add(node.lineno)
            excluded_nodes.append(node)
        else:
            retained.append(node)
    missing = sorted(set(wanted) - set(plan.symbol_lines))
    if missing:
        raise ScopeError(f"{path}: excluded symbols not found at module level: {missing}")
    present = {name for node in retained for name in _symbol_names(node)}
    absent = sorted(entry_points - present - {MODULE_OWNER})
    if absent:
        raise ScopeError(f"{path}: entry_points are not retained module-level symbols: {absent}")
    excluded = set(wanted)
    for node in retained:
        if isinstance(node, ast.Import | ast.ImportFrom):
            continue
        refs = _owner_refs(node, excluded)
        owners = _symbol_names(node) or [MODULE_OWNER]
        if refs and not any(owner in entry_points for owner in owners):
            raise ScopeError(
                f"{path}: retained {owners[0]} references excluded {sorted(refs)} but is not a listed entry_point"
            )
    _prune_imports(plan, retained, excluded_nodes)
    counted = counted_lines(source)
    ranges = [*plan.symbol_lines.values(), *plan.import_ranges]
    plan.removed_lines = {line for start, end in ranges for line in range(start, end + 1)} & counted
    plan.symbol_loc = {
        name: len(counted & set(range(start, end + 1))) for name, (start, end) in plan.symbol_lines.items()
    }
    plan.import_loc = sum(len(counted & set(range(start, end + 1))) for start, end in plan.import_ranges)
    return plan


def _prune_imports(plan: ModulePlan, retained: list[ast.stmt], excluded_nodes: list[ast.stmt]) -> None:
    others = [node for node in retained if not isinstance(node, ast.Import | ast.ImportFrom)]
    used_kept, strings_kept = _name_uses(others)
    used_cut, _ = _name_uses(list(excluded_nodes))
    for node in retained:
        if not isinstance(node, ast.Import | ast.ImportFrom):
            continue
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            continue
        bound = _bound_names(node)
        if not bound:
            continue
        if any(name in used_kept or re.search(rf"\b{re.escape(name)}\b", strings_kept) for name in bound):
            continue
        if not all(name in used_cut for name in bound):
            continue
        plan.import_ranges.append((node.lineno, node.end_lineno or node.lineno))
        plan.skip_linenos.add(node.lineno)


def _resolve_from(module_name: str, is_package: bool, node: ast.ImportFrom) -> str:
    if not node.level:
        return node.module or ""
    parts = module_name.split(".")
    if not is_package:
        parts = parts[:-1]
    base = parts[: len(parts) - (node.level - 1)]
    return ".".join([*base, *([node.module] if node.module else [])])


def check_external_references(
    repo: Path,
    modules: dict[str, Any],
    in_scope: dict[str, str],
    plans: dict[str, ModulePlan],
) -> None:
    """Reject any other in-scope module that imports an excluded symbol."""
    by_module = {name: plans[module.path] for name, module in modules.items() if module.path in plans}
    for name in sorted(in_scope):
        module = modules[name]
        if module.path in plans:
            continue
        try:
            tree = ast.parse((repo / module.path).read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            base = _resolve_from(name, module.is_package, node)
            for alias in node.names:
                target = base if alias.name == "*" else f"{base}.{alias.name}"
                plan = by_module.get(base)
                if plan is not None and alias.name in plan.symbol_lines:
                    raise ScopeError(f"{module.path} imports excluded {alias.name} from {plan.path}")
                if target in by_module and alias.name != "*":
                    attr_users = _attribute_uses(tree, alias.asname or alias.name, by_module[target])
                    if attr_users:
                        raise ScopeError(f"{module.path} uses excluded {attr_users} of {by_module[target].path}")


def _attribute_uses(tree: ast.AST, alias: str, plan: ModulePlan) -> list[str]:
    return sorted(
        {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == alias
            and node.attr in plan.symbol_lines
        }
    )


def validate_entries(entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        ident = entry.get("id")
        path = entry.get("path")
        symbols = entry.get("symbols")
        if not isinstance(path, str) or not path:
            raise ScopeError(f"function exclusion {ident!r} needs one path string")
        if not (isinstance(symbols, list) and symbols and all(isinstance(item, str) and item for item in symbols)):
            raise ScopeError(f"function exclusion {ident!r} needs a non-empty symbols list")
        for key in ("reason", "category", "evidence"):
            if not str(entry.get(key, "")).strip():
                raise ScopeError(f"function exclusion {ident!r} needs {key}")
        points = entry.get("entry_points", [])
        if not (isinstance(points, list) and all(isinstance(item, str) and item for item in points)):
            raise ScopeError(f"function exclusion {ident!r}: entry_points must be a list of names")


def plan_modules(repo: Path, entries: list[dict[str, Any]], *, root_paths: set[str]) -> dict[str, ModulePlan]:
    validate_entries(entries)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        grouped.setdefault(entry["path"], []).append(entry)
    plans: dict[str, ModulePlan] = {}
    for path, group in sorted(grouped.items()):
        file = repo / path
        if not file.is_file():
            raise ScopeError(f"function exclusion {group[0]['id']!r}: {path} does not exist")
        plans[path] = plan_module(path, file.read_text(encoding="utf-8"), group, root_paths=root_paths)
    return plans
