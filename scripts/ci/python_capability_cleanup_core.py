"""Scope and dynamic-import analysis for Python capability cleanup."""

from __future__ import annotations

import ast
from collections.abc import Mapping

from scripts.ci.python_capability_cleanup_flow import _ScopeBindingFlow
from scripts.ci.python_capability_cleanup_static import (
    _IMPORT_DESTINATION_RE,
    _MAX_DYNAMIC_IMPORT_DESTINATION,
    DynamicImport,
    _assigned_names,
    _assignment_targets,
    _function_parameters,
    _FunctionIdentity,
    _resolve_static_strings,
    _static_sequence,
    _static_strings,
    _StaticScope,
    _StaticValue,
)


class _StaticScopeAnalysis:
    """Collect static bindings without allowing sibling lexical scopes to leak."""

    def __init__(self, tree: ast.Module, module: str = "") -> None:
        self.tree = tree
        self.module = module
        self.function_exports: dict[str, dict[str, _FunctionIdentity | None]] = {}
        self.root = _StaticScope(None, None)
        self.scopes: list[_StaticScope] = [self.root]
        self._node_scopes: dict[int, _StaticScope] = {}
        self.call_aliases: dict[int, tuple[frozenset[str], frozenset[str]]] = {}
        self.call_bindings: dict[int, dict[str, _StaticValue]] = {}
        self.call_targets: dict[int, _FunctionIdentity | None] = {}
        self._walk(tree, self.root)
        for scope in self.scopes:
            self._finalize(scope)
        self._compute_callsite_bindings()

    def function_identity(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> _FunctionIdentity:
        return self.module, id(node)

    def scope_for(self, node: ast.AST) -> _StaticScope:
        return self._node_scopes.get(id(node), self.root)

    def _walk(self, node: ast.AST, scope: _StaticScope) -> None:
        self._node_scopes[id(node)] = scope
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                self._walk(decorator, scope)
            for default in [*node.args.defaults, *node.args.kw_defaults]:
                if default is not None:
                    self._walk(default, scope)
            if node.returns is not None:
                self._walk(node.returns, scope)
            lexical_parent = scope.parent if isinstance(scope.node, ast.ClassDef) else scope
            child = _StaticScope(node, lexical_parent)
            self.scopes.append(child)
            self._node_scopes[id(node)] = child
            for statement in node.body:
                self._walk(statement, child)
            return
        if isinstance(node, ast.ClassDef):
            for decorator in node.decorator_list:
                self._walk(decorator, scope)
            for base in node.bases:
                self._walk(base, scope)
            for keyword in node.keywords:
                self._walk(keyword, scope)
            child = _StaticScope(node, scope)
            self.scopes.append(child)
            self._node_scopes[id(node)] = child
            for statement in node.body:
                self._walk(statement, child)
            return
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for name in _assigned_names(target):
                    scope.assignments[name] = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            for name in _assigned_names(node.target):
                scope.assignments[name] = node.value
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            scope.loop_nodes.append(node)
        for child in ast.iter_child_nodes(node):
            self._walk(child, scope)

    def _finalize(self, scope: _StaticScope) -> None:
        parent = scope.parent
        merged_assignments = dict(parent.merged_assignments) if parent is not None else {}
        merged_assignments.update(scope.assignments)
        scope.parameters = _function_parameters(scope.node)
        for parameter in scope.parameters:
            merged_assignments.pop(parameter, None)
        merged_bindings = dict(parent.merged_bindings) if parent is not None else {}
        for name in scope.assignments:
            merged_bindings.pop(name, None)
        for parameter in scope.parameters:
            merged_bindings.pop(parameter, None)
        local_bindings: dict[str, frozenset[str]] = {}
        for name, value in scope.assignments.items():
            if name in scope.parameters:
                continue
            resolved = _static_strings(value, merged_assignments, merged_bindings)
            if resolved is not None:
                local_bindings[name] = resolved
                merged_bindings[name] = resolved
        for node in scope.loop_nodes:
            sequence = _static_sequence(node.iter, merged_assignments, set())
            if sequence is None:
                continue
            target_values: dict[str, set[str]] = {}
            for item in sequence:
                for name, target_value in _assignment_targets(node.target, item).items():
                    if name not in scope.parameters and isinstance(target_value, str):
                        target_values.setdefault(name, set()).add(target_value)
            for name, values in target_values.items():
                if values:
                    resolved = frozenset(values)
                    local_bindings[name] = resolved
                    merged_bindings[name] = resolved
        scope.bindings = local_bindings
        scope.merged_assignments = merged_assignments
        scope.merged_bindings = merged_bindings

    def _compute_callsite_bindings(self) -> None:
        self.call_aliases.clear()
        self.call_bindings.clear()
        self.call_targets.clear()
        for scope in self.scopes:
            scope.entry_recorded = False
        for scope in self.scopes:
            parent = scope.parent
            if scope.entry_recorded:
                bindings = scope.entry_bindings
                sequences = scope.entry_sequences
                import_aliases = set(scope.entry_import_aliases)
                importlib_aliases = set(scope.entry_importlib_aliases)
                function_bindings = scope.entry_function_bindings
                module_bindings = scope.entry_module_bindings
            else:
                bindings = parent.merged_bindings if parent is not None else {}
                sequences = parent.merged_sequences if parent is not None else {}
                import_aliases = set(parent.merged_import_aliases) if parent is not None else set()
                importlib_aliases = set(parent.merged_importlib_aliases) if parent is not None else set()
                function_bindings = parent.merged_function_bindings if parent is not None else {}
                module_bindings = parent.merged_module_bindings if parent is not None else {}
            if isinstance(scope.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parameters = _function_parameters(scope.node)
                for parameter in parameters:
                    bindings = {**bindings, parameter: None}
                    sequences = {**sequences, parameter: None}
                    import_aliases.discard(parameter)
                    importlib_aliases.discard(parameter)
                    function_bindings = {**function_bindings, parameter: None}
                    module_bindings = {**module_bindings, parameter: None}
            flow = _ScopeBindingFlow(
                self,
                scope,
                bindings,
                sequences,
                import_aliases,
                importlib_aliases,
                function_bindings,
                module_bindings,
            )
            if scope.node is None:
                statements = self.tree.body
            elif isinstance(scope.node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                statements = scope.node.body
            else:
                continue
            for statement in statements:
                flow.visit(statement)
            scope.merged_bindings = dict(flow.bindings)
            scope.merged_sequences = dict(flow.sequences)
            scope.merged_function_bindings = dict(flow.function_bindings)
            scope.merged_import_aliases = frozenset(flow.import_aliases)
            scope.merged_importlib_aliases = frozenset(flow.importlib_aliases)
            scope.merged_module_bindings = dict(flow.module_bindings)


def _static_assignments(tree: ast.Module) -> tuple[dict[str, ast.AST], dict[str, frozenset[str]]]:
    analysis = _StaticScopeAnalysis(tree)
    return analysis.root.assignments, analysis.root.bindings


def _function_parameter_bindings(
    analysis: _StaticScopeAnalysis,
    callsites: Mapping[_FunctionIdentity, list[tuple[ast.Call, _StaticScopeAnalysis]]] | None = None,
) -> dict[tuple[int, int], frozenset[str]]:
    """Prove helper parameters from every statically visible direct callsite."""

    functions = [
        scope.node for scope in analysis.scopes if isinstance(scope.node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    local_calls: dict[_FunctionIdentity, list[tuple[ast.Call, _StaticScopeAnalysis]]] = {}
    if callsites is None:
        for node in ast.walk(analysis.tree):
            if not isinstance(node, ast.Call):
                continue
            target = analysis.call_targets.get(id(node))
            if target is not None:
                local_calls.setdefault(target, []).append((node, analysis))
        callsites = local_calls
    result: dict[tuple[int, int], frozenset[str]] = {}
    for function in functions:
        function_calls = callsites.get(analysis.function_identity(function), [])
        if not function_calls:
            continue
        positional = [*function.args.posonlyargs, *function.args.args]
        for index, _parameter in enumerate(positional):
            values: set[str] = set()
            proven = True
            for call, caller_analysis in function_calls:
                if index >= len(call.args):
                    proven = False
                    break
                caller_bindings = caller_analysis.call_bindings.get(id(call), {})
                resolved = _resolve_static_strings(call.args[index], caller_bindings)
                if resolved is None:
                    proven = False
                    break
                values.update(resolved)
            if proven and values:
                result[(id(function), index)] = frozenset(values)
    return result


def _import_module_call(node: ast.Call, import_aliases: set[str], importlib_aliases: set[str]) -> bool:
    if isinstance(node.func, ast.Name):
        return node.func.id in import_aliases
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "import_module"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in importlib_aliases
    )


class _DynamicImportVisitor(ast.NodeVisitor):
    def __init__(
        self,
        module: str,
        analysis: _StaticScopeAnalysis,
        parameter_bindings: dict[tuple[int, int], frozenset[str]],
    ) -> None:
        self._module = module
        self._analysis = analysis
        self._parameter_bindings = parameter_bindings
        self.evidence: list[DynamicImport] = []
        self.unbounded: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        import_aliases, importlib_aliases = self._analysis.call_aliases.get(id(node), (frozenset(), frozenset()))
        if _import_module_call(node, set(import_aliases), set(importlib_aliases)) and node.args:
            destination = node.args[0]
            bindings = self._analysis.call_bindings.get(id(node), {})
            values = _resolve_static_strings(destination, bindings)
            kind = "literal_or_static"
            if (
                values is None
                and isinstance(destination, ast.Name)
                and isinstance(self._analysis.scope_for(node).node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                function = self._analysis.scope_for(node).node
                assert isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
                positional = list(function.args.posonlyargs) + list(function.args.args)
                try:
                    index = next(index for index, parameter in enumerate(positional) if parameter.arg == destination.id)
                except StopIteration:
                    index = -1
                if index >= 0:
                    values = self._parameter_bindings.get((id(function), index))
                    kind = "bounded_callsite" if values is not None else "unbounded"
            if values is None:
                kind = "unbounded"
                self.unbounded.append(f"{self._module}:{node.lineno}")
                count = 0
            else:
                invalid = sorted(value for value in values if not valid_import_destination(value))
                if invalid:
                    kind = "invalid_static"
                    self.unbounded.append(f"{self._module}:{node.lineno}")
                count = len(values)
            self.evidence.append(
                DynamicImport(
                    self._module,
                    node.lineno,
                    kind,
                    count,
                    tuple(sorted(values)) if values is not None else None,
                )
            )
        self.generic_visit(node)


def valid_import_destination(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= _MAX_DYNAMIC_IMPORT_DESTINATION
        and "\x00" not in value
        and bool(_IMPORT_DESTINATION_RE.fullmatch(value))
    )
