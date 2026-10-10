"""Python side of the runtime-majority report.

Scope is a static import-graph closure (``ast``) from reviewed runtime root
modules.  Edges are classified ``eager`` (executed at import time) or ``lazy``
(inside a function/lambda, or a literal ``importlib.import_module`` call).
Imports under ``if TYPE_CHECKING`` are not runtime edges.  Reviewed exclusions
prune a module and everything reachable only through it.  LOC counts physical
lines holding at least one non-comment token (docstrings count).
"""

from __future__ import annotations

import ast
import fnmatch
import io
import tokenize
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SKIP_TOKENS = frozenset(
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


@dataclass
class PythonModule:
    """One module file under the package root."""

    name: str
    path: str
    is_package: bool
    loc: int


@dataclass
class ImportGraph:
    """Dotted-name keyed module table and edge sets."""

    modules: dict[str, PythonModule]
    eager: dict[str, set[str]] = field(default_factory=dict)
    lazy: dict[str, set[str]] = field(default_factory=dict)
    dynamic_unresolved: dict[str, int] = field(default_factory=dict)


def count_python_loc(source: str) -> int:
    lines: set[int] = set()
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type in _SKIP_TOKENS:
                continue
            lines.update(range(token.start[0], token.end[0] + 1))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return sum(1 for line in source.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    return len(lines)


def discover_modules(repo: Path, package_root: str) -> dict[str, PythonModule]:
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
        modules[name] = PythonModule(
            name=name,
            path=path.relative_to(repo).as_posix(),
            is_package=is_package,
            loc=count_python_loc(path.read_text(encoding="utf-8")),
        )
    return modules


def _is_type_checking(test: ast.expr) -> bool:
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    return isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"


def _literal_package(node: ast.expr, module: PythonModule) -> str | None:
    """Package anchor of a relative ``import_module`` call, when statically known."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id == "__package__":
        return module.name if module.is_package else module.name.rpartition(".")[0]
    if isinstance(node, ast.Name) and node.id == "__name__":
        return module.name
    return None


def _absolute_name(name: str, package: str | None) -> str | None:
    if not name.startswith("."):
        return name
    if not package:
        return None
    level = len(name) - len(name.lstrip("."))
    base = package.split(".")
    if level - 1 >= len(base):
        return None
    return ".".join([*base[: len(base) - (level - 1)], name.lstrip(".")]).rstrip(".")


class _ImportCollector(ast.NodeVisitor):
    def __init__(self, module: PythonModule) -> None:
        self.module = module
        self.found: list[tuple[str, str, int, tuple[str, ...]]] = []
        self.dynamic_unresolved = 0
        self._function_depth = 0

    def _mode(self) -> str:
        return "lazy" if self._function_depth else "eager"

    def visit_If(self, node: ast.If) -> None:
        if _is_type_checking(node.test):
            for child in node.orelse:
                self.visit(child)
            return
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_depth += 1
        self.generic_visit(node)
        self._function_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815
    visit_Lambda = visit_FunctionDef  # type: ignore[assignment]  # noqa: N815

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.found.append((self._mode(), alias.name, 0, ()))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.found.append((self._mode(), node.module or "", node.level, tuple(alias.name for alias in node.names)))

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name in {"import_module", "__import__"} and node.args:
            arg = node.args[0]
            package_node = node.args[1] if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == "package":
                    package_node = keyword.value
            package = _literal_package(package_node, self.module) if package_node is not None else None
            literal = arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else None
            target = _absolute_name(literal, package) if literal is not None else None
            if target:
                self.found.append(("lazy", target, 0, ()))
            else:
                self.dynamic_unresolved += 1
        self.generic_visit(node)


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


def build_graph(repo: Path, package_root: str) -> ImportGraph:
    modules = discover_modules(repo, package_root)
    graph = ImportGraph(modules=modules)
    for name, module in modules.items():
        source = (repo / module.path).read_text(encoding="utf-8")
        collector = _ImportCollector(module)
        try:
            collector.visit(ast.parse(source))
        except SyntaxError:
            continue
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
