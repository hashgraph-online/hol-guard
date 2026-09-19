"""Static Python import analysis used by the capability cleanup gate."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path

from scripts.ci.python_capability_cleanup_core import (
    _DynamicImportVisitor,
    _function_parameter_bindings,
    _StaticScopeAnalysis,
    valid_import_destination,
)
from scripts.ci.python_capability_cleanup_static import (
    DynamicImport,
    _FunctionIdentity,
    module_name,
    resolve_import,
)

__all__ = [
    "DynamicImport",
    "dynamic_import_destinations",
    "module_imports",
    "module_name",
    "production_importers",
    "reachable",
    "resolve_import",
    "valid_import_destination",
]


def _module_analyses(root: Path) -> dict[str, tuple[Path, ast.Module, _StaticScopeAnalysis]]:
    analyses: dict[str, tuple[Path, ast.Module, _StaticScopeAnalysis]] = {}
    for path in (root / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module = module_name(root, path)
        analyses[module] = (path, tree, _StaticScopeAnalysis(tree, module))
    exports: dict[str, dict[str, _FunctionIdentity | None]] = {}
    for module, (_path, _tree, analysis) in analyses.items():
        module_exports: dict[str, _FunctionIdentity | None] = {}
        for scope in analysis.scopes:
            function = scope.node
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) or scope.parent is not analysis.root:
                continue
            identity = analysis.function_identity(function)
            module_exports[function.name] = identity if function.name not in module_exports else None
        exports[module] = module_exports
    for _module, (_path, _tree, analysis) in analyses.items():
        analysis.function_exports = exports
        analysis._compute_callsite_bindings()
    return analyses


def _all_function_calls(
    analyses: Mapping[str, tuple[Path, ast.Module, _StaticScopeAnalysis]],
) -> dict[_FunctionIdentity, list[tuple[ast.Call, _StaticScopeAnalysis]]]:
    calls: dict[_FunctionIdentity, list[tuple[ast.Call, _StaticScopeAnalysis]]] = {}
    for _path, tree, analysis in analyses.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                target = analysis.call_targets.get(id(node))
                if target is not None:
                    calls.setdefault(target, []).append((node, analysis))
    return calls


def _dynamic_import_analysis(
    analyses: Mapping[str, tuple[Path, ast.Module, _StaticScopeAnalysis]],
) -> tuple[list[DynamicImport], list[str]]:
    """Inspect dynamic imports after one parse of every source module."""

    evidence: list[DynamicImport] = []
    unbounded: list[str] = []
    callsites = _all_function_calls(analyses)
    for module, (_path, tree, analysis) in analyses.items():
        parameter_bindings = _function_parameter_bindings(analysis, callsites)
        visitor = _DynamicImportVisitor(module, analysis, parameter_bindings)
        visitor.visit(tree)
        evidence.extend(visitor.evidence)
        unbounded.extend(visitor.unbounded)
    return evidence, unbounded


def dynamic_import_destinations(root: Path) -> tuple[list[DynamicImport], list[str]]:
    """Inspect every importlib destination and reject unbounded provenance."""

    return _dynamic_import_analysis(_module_analyses(root))


def _module_imports_from_analyses(
    analyses: Mapping[str, tuple[Path, ast.Module, _StaticScopeAnalysis]],
    dynamic_evidence: list[DynamicImport],
) -> tuple[dict[str, set[str]], list[str]]:
    modules = {name: path for name, (path, _tree, _analysis) in analyses.items()}
    imports: dict[str, set[str]] = {}
    dynamic: list[str] = []
    for name, (_path, tree, _analysis) in analyses.items():
        targets: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in modules:
                        targets.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                target = resolve_import(name, node.level, node.module)
                if target in modules:
                    targets.add(target)
                for alias in node.names:
                    candidate = f"{target}.{alias.name}" if target else alias.name
                    if candidate in modules:
                        targets.add(candidate)
        imports[name] = targets
    accepted_kinds = {"literal_or_static", "bounded_callsite"}
    for item in dynamic_evidence:
        if item.destination_kind not in accepted_kinds or item.destination_values is None:
            continue
        for destination in item.destination_values:
            if destination in modules:
                imports[item.module].add(destination)
                dynamic.append(f"{item.module}:{item.line}:{destination}")
    return imports, dynamic


def module_imports(root: Path) -> tuple[dict[str, set[str]], list[str]]:
    """Build the static and dynamic import graph from one AST pass."""

    import_graph, dynamic, _evidence, _unbounded = _analyze_import_graph(root)
    return import_graph, dynamic


def _analyze_import_graph(root: Path) -> tuple[dict[str, set[str]], list[str], list[DynamicImport], list[str]]:
    analyses = _module_analyses(root)
    dynamic_evidence, dynamic_unbounded = _dynamic_import_analysis(analyses)
    import_graph, dynamic = _module_imports_from_analyses(analyses, dynamic_evidence)
    return import_graph, dynamic, dynamic_evidence, dynamic_unbounded


def reachable(roots: tuple[str, ...], imports: dict[str, set[str]]) -> set[str]:
    pending = [root for root in roots if root in imports]
    reached: set[str] = set()
    while pending:
        module = pending.pop()
        if module in reached:
            continue
        reached.add(module)
        pending.extend(imported for imported in imports.get(module, ()) if imported not in reached)
    return reached


def production_importers(root: Path, candidate_module: str) -> list[str]:
    import_graph, dynamic, _evidence, _unbounded = _analyze_import_graph(root)
    importers = sorted(module for module, targets in import_graph.items() if candidate_module in targets)
    importers.extend(item for item in dynamic if candidate_module in item)
    return importers
