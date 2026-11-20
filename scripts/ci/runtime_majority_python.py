"""Python side of the runtime-majority report.

Scope is a static import-graph closure (``ast``) from reviewed runtime root
modules.  Edges are classified ``eager`` (executed at import time) or ``lazy``
(inside a function/lambda, or an ``importlib.import_module`` call).  A
dynamic import resolves when its module argument is a string the source fixes:
a literal, a conditional between literals, a name bound to one of those, a loop
variable drawn from a module-level literal table, or the parameter of a
module-private helper every caller passes a literal to.  Anything else is
counted unresolved and must be declared in the scope contract.
Imports under ``if TYPE_CHECKING`` are not runtime edges.  Reviewed exclusions
prune a module and everything reachable only through it.  LOC counts physical
lines holding at least one non-comment token (docstrings count).
"""

from __future__ import annotations

import ast
import fnmatch
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.ci.runtime_majority_functions import ModulePlan, counted_lines
from scripts.ci.runtime_majority_imports import ImportCollector, PythonModule, absolute_name


@dataclass
class ImportGraph:
    """Dotted-name keyed module table and edge sets."""

    modules: dict[str, PythonModule]
    eager: dict[str, set[str]] = field(default_factory=dict)
    lazy: dict[str, set[str]] = field(default_factory=dict)
    dynamic_unresolved: dict[str, int] = field(default_factory=dict)


def count_python_loc(source: str) -> int:
    return len(counted_lines(source))


def discover_modules(
    repo: Path, package_root: str, plans: dict[str, ModulePlan] | None = None
) -> dict[str, PythonModule]:
    root = repo / package_root
    top = root.name
    modules: dict[str, PythonModule] = {}
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        parts = list(relative.with_suffix("").parts)
        is_package = parts[-1] == "__init__"
        if is_package:
            parts = parts[:-1]
        name = ".".join([top, *parts]) if parts else top
        relative_path = path.relative_to(repo).as_posix()
        plan = (plans or {}).get(relative_path)
        counted = counted_lines(path.read_text(encoding="utf-8"))
        modules[name] = PythonModule(
            name=name,
            path=relative_path,
            is_package=is_package,
            loc=len(counted - plan.removed_lines) if plan else len(counted),
        )
    return modules


def _expand(modules: dict[str, PythonModule], target: str) -> set[str]:
    """A module plus the parent packages whose ``__init__`` also executes."""
    result: set[str] = set()
    parts = target.split(".")
    for index in range(1, len(parts) + 1):
        candidate = ".".join(parts[:index])
        if candidate in modules:
            result.add(candidate)
    return result if target in modules else set()


def _resolve(module: PythonModule, mode_found: tuple[str, str, int, tuple[str, ...]], modules: dict[str, PythonModule]):
    mode, name, level, names = mode_found
    if level:
        package_parts = module.name.split(".")
        if not module.is_package:
            package_parts = package_parts[:-1]
        base = package_parts[: len(package_parts) - (level - 1)]
        full = ".".join([*base, *([name] if name else [])])
    else:
        full = name
    targets = set(_expand(modules, full))
    if names or level:
        for item in names:
            if item != "*":
                targets |= _expand(modules, f"{full}.{item}")
    return mode, targets


def build_graph(repo: Path, package_root: str, plans: dict[str, ModulePlan] | None = None) -> ImportGraph:
    modules = discover_modules(repo, package_root, plans)
    graph = ImportGraph(modules=modules)
    for name, module in modules.items():
        source = (repo / module.path).read_text(encoding="utf-8")
        plan = (plans or {}).get(module.path)
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        collector = ImportCollector(module, plan.skip_linenos if plan else None)
        collector.visit(tree)
        graph.eager[name], graph.lazy[name] = set(), set()
        graph.dynamic_unresolved[name] = collector.dynamic_unresolved
        for found in collector.found:
            mode, targets = _resolve(module, found, modules)
            targets.discard(name)
            (graph.eager if mode == "eager" else graph.lazy)[name].update(targets)
        # A package's own __init__ executes before any submodule runs.
        if name.count("."):
            parent = name.rsplit(".", 1)[0]
            if parent in modules:
                graph.eager[name].add(parent)
    return graph


DYNAMIC_RESOLUTIONS = frozenset({"external", "follow", "unfollowed"})


def validate_dynamic_imports(entries: list[dict[str, Any]]) -> None:
    """Reject malformed ``dynamic_imports`` entries (raises ``ValueError``)."""
    seen: set[str] = set()
    for entry in entries:
        path = entry.get("path")
        if not isinstance(path, str) or not path or path in seen:
            raise ValueError(f"dynamic import entry needs one unique path string: {path!r}")
        seen.add(path)
        count = entry.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError(f"dynamic import entry {path!r} needs a positive integer count")
        if entry.get("resolution") not in DYNAMIC_RESOLUTIONS:
            raise ValueError(f"dynamic import entry {path!r} resolution must be one of {sorted(DYNAMIC_RESOLUTIONS)}")
        if not str(entry.get("evidence", "")).strip():
            raise ValueError(f"dynamic import entry {path!r} needs evidence")
        targets = entry.get("targets", [])
        if entry["resolution"] != "external" and not (
            isinstance(targets, list) and targets and all(isinstance(item, str) and item for item in targets)
        ):
            raise ValueError(f"dynamic import entry {path!r} needs a target module list")
        if entry.get("mode", "lazy") not in {"eager", "lazy"}:
            raise ValueError(f"dynamic import entry {path!r} mode must be eager or lazy")


def apply_dynamic_imports(graph: ImportGraph, entries: list[dict[str, Any]]) -> None:
    """Add the declared targets of ``follow`` entries as edges from the declaring module.

    ``external`` (stdlib or third-party) and ``unfollowed`` (reviewed decision
    not to count the targets) add nothing; an unfollowed target is in scope
    only if a static import reaches it. Every declared target must resolve to a
    module (raises ``ValueError``), so a misspelled target cannot shrink the scope.
    """
    by_path = {module.path: module for module in graph.modules.values()}
    for entry in entries:
        module = by_path.get(entry["path"])
        if module is None or entry["resolution"] not in {"follow", "unfollowed"}:
            continue
        package = module.name if module.is_package else module.name.rpartition(".")[0]
        edges = graph.eager if entry.get("mode") == "eager" else graph.lazy
        for target in entry["targets"]:
            name = absolute_name(target, package)
            resolved = _expand(graph.modules, name) if name else set()
            if not resolved:
                raise ValueError(f"dynamic import entry {entry['path']!r}: target {target!r} resolves to no module")
            if entry["resolution"] == "follow":
                edges.setdefault(module.name, set()).update(resolved - {module.name})


def undeclared_dynamic_sites(graph: ImportGraph, in_scope: dict[str, str], entries: list[dict[str, Any]]) -> list[str]:
    """Declarations that disagree with the graph.

    An in-scope module's unresolved dynamic import count must equal its declared
    count, including zero, so a declaration cannot outlive its last import site.
    A declared path must name a module.
    """
    declared = {entry["path"]: entry["count"] for entry in entries}
    known = {module.path for module in graph.modules.values()}
    problems = [f"{path}: declared dynamic import entry names no module" for path in sorted(set(declared) - known)]
    for name in sorted(in_scope):
        found = graph.dynamic_unresolved.get(name, 0)
        path = graph.modules[name].path
        if found != declared.get(path, 0):
            problems.append(f"{path}: {found} non-literal import site(s), declared {declared.get(path, 0)}")
    return problems


def path_matches(path: str, entry: dict[str, Any]) -> bool:
    patterns = entry["path"] if isinstance(entry["path"], list) else [entry["path"]]
    return any(fnmatch.fnmatchcase(path, str(pattern)) for pattern in patterns)


def _walk(
    graph: ImportGraph, roots: list[str], exclusions: list[dict[str, Any]], *, use_lazy: bool
) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    parent: dict[str, str] = {root: "" for root in roots if root in graph.modules}
    excluded: dict[str, dict[str, Any]] = {}
    queue: deque[str] = deque(parent)
    while queue:
        current = queue.popleft()
        edges = set(graph.eager.get(current, ()))
        if use_lazy:
            edges |= graph.lazy.get(current, set())
        for target in sorted(edges):
            if target in parent:
                continue
            entry = next((item for item in exclusions if path_matches(graph.modules[target].path, item)), None)
            if entry is not None:
                excluded.setdefault(target, {"entry": entry, "via": current})
                continue
            parent[target] = current
            queue.append(target)
    return parent, excluded


def closure(
    graph: ImportGraph, roots: list[str], *, exclusions: list[dict[str, Any]]
) -> tuple[dict[str, str], dict[str, dict[str, Any]], dict[str, str]]:
    """Return ``(reached module -> first parent, excluded hits, reach kind)``.

    ``reach kind`` is ``eager`` when an import-time chain from a root reaches
    the module and ``lazy`` when only function-level imports do.
    """
    parent, excluded = _walk(graph, roots, exclusions, use_lazy=True)
    eager_parent, _ = _walk(graph, roots, exclusions, use_lazy=False)
    kind = {module: "eager" if module in eager_parent else "lazy" for module in parent}
    return parent, excluded, kind
