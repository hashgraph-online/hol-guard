"""Function-level exclusions for the runtime-majority report.

Some in-scope modules mix runtime code with CLI-only, offline or control-plane
code.  A ``python.function_exclusions`` entry removes named top-level symbols
(functions, classes, module variables) from one module, together with
top-level imports that only those symbols use.  Every entry carries
``evidence`` and the exclusion is validated by a reference closure:

* retained code in the same module may reference an excluded symbol only from
  a listed ``entry_points`` symbol (the reviewed dispatcher into that code);
* no other in-scope module may import an excluded symbol;
* roots are not eligible unless the entry sets ``root_function: true``, which
  marks a reviewed non-request handler (for example a CLI subcommand body or a
  dashboard-only route) inside a mixed dispatcher root; the ``evidence`` must
  then show that no hook, launch or proxy route reaches the symbol.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections.abc import Iterator
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


def _owner_refs(node: ast.AST, names: set[str], attrs: frozenset[str] | set[str]) -> set[str]:
    found: set[str] = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and item.id in names:
            found.add(item.id)
        elif isinstance(item, ast.Attribute) and item.attr in attrs:
            found.add(f".{item.attr}")
    return found


def _is_function(node: ast.AST) -> bool:
    return isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)


def _class_units(
    node: ast.ClassDef, wanted: dict[str, str], plan: ModulePlan, excluded_nodes: list[ast.stmt]
) -> list[tuple[str, ast.AST]]:
    """Retained pieces of a class that loses some methods, one unit per member."""
    units: list[tuple[str, ast.AST]] = [
        (node.name, header) for header in [*node.decorator_list, *node.bases, *node.keywords]
    ]
    for child in node.body:
        full = f"{node.name}.{child.name}" if _is_function(child) else ""
        if full in wanted:
            start, end = _node_range(child)
            plan.symbol_lines[full] = (start, end)
            plan.symbol_entry[full] = wanted[full]
            plan.skip_linenos.add(child.lineno)
            excluded_nodes.append(child)
        else:
            units.append((full or node.name, child))
    return units


def plan_module(
    path: str,
    source: str,
    entries: list[dict[str, Any]],
    *,
    root_paths: set[str],
    method_names: frozenset[str] = frozenset(),
) -> ModulePlan:
    if path in root_paths:
        plain = [entry["id"] for entry in entries if entry.get("root_function") is not True]
        if plain:
            raise ScopeError(
                f"function exclusion {plain[0]!r}: {path} is a runtime root and stays whole "
                "unless the entry sets root_function: true with evidence"
            )
    tree = ast.parse(source)
    plan = ModulePlan(path=path)
    wanted: dict[str, str] = {}
    for entry in entries:
        for symbol in entry["symbols"]:
            if symbol in wanted:
                raise ScopeError(f"function exclusion {entry['id']!r}: {symbol} is listed twice for {path}")
            wanted[symbol] = entry["id"]
    entry_points = {str(point) for entry in entries for point in entry.get("entry_points", [])}
    units: list[tuple[str, ast.AST]] = []
    excluded_nodes: list[ast.stmt] = []
    for node in tree.body:
        names = _symbol_names(node)
        hit = [name for name in names if name in wanted]
        if hit:
            if len(hit) != len(names):
                raise ScopeError(f"{path}: statement binds both excluded and retained names {names}")
            if path in root_paths and not _is_function(node):
                raise ScopeError(f"{path}: root_function exclusions may only name functions, not {names}")
            start, end = _node_range(node)
            for name in hit:
                plan.symbol_lines[name] = (start, end)
                plan.symbol_entry[name] = wanted[name]
            plan.skip_linenos.add(node.lineno)
            excluded_nodes.append(node)
        elif isinstance(node, ast.ClassDef):
            units.extend(_class_units(node, wanted, plan, excluded_nodes))
        else:
            units.append((names[0] if names else MODULE_OWNER, node))
    missing = sorted(set(wanted) - set(plan.symbol_lines))
    if missing:
        raise ScopeError(f"{path}: excluded symbols not found: {missing}")
    present = {owner for owner, _ in units}
    absent = sorted(entry_points - present - {MODULE_OWNER})
    if absent:
        raise ScopeError(f"{path}: entry_points are not retained module-level symbols: {absent}")
    names = {item for item in wanted if "." not in item}
    attrs = {item.split(".", 1)[1] for item in wanted if "." in item} | set(method_names)
    for owner, node in units:
        if isinstance(node, ast.Import | ast.ImportFrom):
            continue
        refs = _owner_refs(node, names, attrs)
        if refs and owner not in entry_points:
            raise ScopeError(
                f"{path}: retained {owner} references excluded {sorted(refs)} but is not a listed entry_point"
            )
    retained = [node for _, node in units]
    pruned_ids = _prune_imports(plan, retained, excluded_nodes)
    counted = counted_lines(source)
    ranges = [*plan.symbol_lines.values(), *plan.import_ranges]
    removed = {line for start, end in ranges for line in range(start, end + 1)}
    for node in retained:
        if id(node) in pruned_ids:
            continue
        start, end = _node_range(node)
        if removed & set(range(start, end + 1)):
            raise ScopeError(f"{path}: a removed and a retained top-level statement share source lines {start}-{end}")
    plan.removed_lines = removed & counted
    plan.symbol_loc = {
        name: len(counted & set(range(start, end + 1))) for name, (start, end) in plan.symbol_lines.items()
    }
    plan.import_loc = sum(len(counted & set(range(start, end + 1))) for start, end in plan.import_ranges)
    return plan


def _prune_imports(plan: ModulePlan, retained: list[ast.AST], excluded_nodes: list[ast.stmt]) -> set[int]:
    pruned: set[int] = set()
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
        pruned.add(id(node))
    return pruned


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
    """Reject retained code in any in-scope module that reaches an excluded symbol."""
    by_module = {name: plans[module.path] for name, module in modules.items() if module.path in plans}
    method_names = method_names_of(plans)
    for name in sorted(in_scope):
        module = modules[name]
        try:
            tree = ast.parse((repo / module.path).read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        own = plans.get(module.path)
        nodes = list(_retained_nodes(tree, own.skip_linenos if own else set()))
        if own is None:
            for node in nodes:
                if isinstance(node, ast.Attribute) and node.attr in method_names:
                    raise ScopeError(f"{module.path} uses attribute {node.attr}, which function exclusions remove")
        bindings = _check_imports(nodes, name, module, {m: p for m, p in by_module.items() if p is not own})
        _check_attribute_chains(nodes, module.path, bindings, {m: p for m, p in by_module.items() if p is not own})


def _retained_nodes(node: ast.AST, skip: set[int]) -> Iterator[ast.AST]:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.stmt) and child.lineno in skip:
            continue
        yield child
        yield from _retained_nodes(child, skip)


def _check_imports(
    nodes: list[ast.AST], name: str, module: Any, by_module: dict[str, ModulePlan]
) -> dict[str, set[str]]:
    """Reject imports of excluded symbols and return local name to dotted target bindings."""
    bindings: dict[str, set[str]] = {}
    for node in nodes:
        if isinstance(node, ast.ImportFrom):
            base = _resolve_from(name, module.is_package, node)
            plan = by_module.get(base)
            for alias in node.names:
                if plan is not None and (alias.name == "*" or alias.name in plan.symbol_lines):
                    raise ScopeError(f"{module.path} imports excluded {alias.name} from {plan.path}")
                if alias.name != "*":
                    bindings.setdefault(alias.asname or alias.name, set()).add(f"{base}.{alias.name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                bindings.setdefault(alias.asname or root, set()).add(alias.name if alias.asname else root)
    return bindings


def _check_attribute_chains(
    nodes: list[ast.AST], path: str, bindings: dict[str, set[str]], by_module: dict[str, ModulePlan]
) -> None:
    """Reject attribute access that resolves to an excluded symbol through any import form."""
    for node in nodes:
        if not isinstance(node, ast.Attribute):
            continue
        parts: list[str] = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if not (isinstance(current, ast.Name) and current.id in bindings):
            continue
        for target in sorted(bindings[current.id]):
            dotted = ".".join([target, *reversed(parts)])
            for module_name, plan in by_module.items():
                if dotted.startswith(f"{module_name}."):
                    symbol = dotted[len(module_name) + 1 :].split(".")[0]
                    if symbol in plan.symbol_lines:
                        raise ScopeError(f"{path} uses excluded {symbol} of {plan.path}")


def method_names_of(plans: dict[str, ModulePlan]) -> frozenset[str]:
    return frozenset(name.split(".", 1)[1] for plan in plans.values() for name in plan.symbol_lines if "." in name)


def validate_entries(entries: list[dict[str, Any]], taken_ids: frozenset[str] = frozenset()) -> None:
    seen = set(taken_ids)
    for entry in entries:
        ident = entry.get("id")
        if ident in seen:
            raise ScopeError(f"function exclusion id {ident!r} is not unique")
        seen.add(ident)
        path = entry.get("path")
        symbols = entry.get("symbols")
        if not isinstance(path, str) or not path:
            raise ScopeError(f"function exclusion {ident!r} needs one path string")
        if not (isinstance(symbols, list) and symbols and all(isinstance(item, str) and item for item in symbols)):
            raise ScopeError(f"function exclusion {ident!r} needs a non-empty symbols list")
        for key in ("reason", "category", "evidence"):
            if not str(entry.get(key, "")).strip():
                raise ScopeError(f"function exclusion {ident!r} needs {key}")
        if "root_function" in entry and not isinstance(entry["root_function"], bool):
            raise ScopeError(f"function exclusion {ident!r}: root_function must be a boolean")
        points = entry.get("entry_points", [])
        if not (isinstance(points, list) and all(isinstance(item, str) and item for item in points)):
            raise ScopeError(f"function exclusion {ident!r}: entry_points must be a list of names")


def plan_modules(repo: Path, entries: list[dict[str, Any]], *, root_paths: set[str]) -> dict[str, ModulePlan]:
    validate_entries(entries)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        grouped.setdefault(entry["path"], []).append(entry)
    method_names = frozenset(
        symbol.split(".", 1)[1] for entry in entries for symbol in entry["symbols"] if "." in symbol
    )
    plans: dict[str, ModulePlan] = {}
    for path, group in sorted(grouped.items()):
        file = repo / path
        if not file.is_file():
            raise ScopeError(f"function exclusion {group[0]['id']!r}: {path} does not exist")
        plans[path] = plan_module(
            path, file.read_text(encoding="utf-8"), group, root_paths=root_paths, method_names=method_names
        )
    return plans
