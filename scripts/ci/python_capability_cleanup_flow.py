"""Lexical binding flow for Python capability cleanup analysis."""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from scripts.ci.python_capability_cleanup_static import (
    _assigned_names,
    _assignment_targets,
    _function_parameters,
    _FunctionIdentity,
    _merge_sequence_values,
    _merge_static_bindings,
    _resolve_static_sequence,
    _resolve_static_strings,
    _SequenceValue,
    _StaticScope,
    _StaticValue,
    resolve_import,
)

if TYPE_CHECKING:
    from scripts.ci.python_capability_cleanup_core import _StaticScopeAnalysis


class _ScopeBindingFlow(ast.NodeVisitor):
    """Record lexical values and aliases at each callsite in one scope."""

    def __init__(
        self,
        analysis: _StaticScopeAnalysis,
        scope: _StaticScope,
        bindings: Mapping[str, _StaticValue],
        sequences: Mapping[str, _SequenceValue],
        import_aliases: set[str],
        importlib_aliases: set[str],
        function_bindings: Mapping[str, _FunctionIdentity | None],
        module_bindings: Mapping[str, str | None],
    ) -> None:
        self._analysis = analysis
        self._scope = scope
        self.bindings: dict[str, _StaticValue] = dict(bindings)
        self.sequences: dict[str, _SequenceValue] = dict(sequences)
        self.import_aliases = set(import_aliases)
        self.importlib_aliases = set(importlib_aliases)
        self.function_bindings: dict[str, _FunctionIdentity | None] = dict(function_bindings)
        self.module_bindings: dict[str, str | None] = dict(module_bindings)

    def _snapshot_call(self, node: ast.Call) -> None:
        self._analysis.call_bindings[id(node)] = dict(self.bindings)
        self._analysis.call_aliases[id(node)] = (
            frozenset(self.import_aliases),
            frozenset(self.importlib_aliases),
        )
        target = None
        if isinstance(node.func, ast.Name):
            target = self.function_bindings.get(node.func.id)
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = self.module_bindings.get(node.func.value.id)
            if module is not None:
                target = self._analysis.function_exports.get(module, {}).get(node.func.attr)
        self._analysis.call_targets[id(node)] = target

    def _forget_names(self, names: tuple[str, ...]) -> None:
        for name in names:
            self.bindings[name] = None
            self.sequences[name] = None
            self.import_aliases.discard(name)
            self.importlib_aliases.discard(name)
            self.function_bindings[name] = None
            self.module_bindings[name] = None

    def _state(
        self,
    ) -> tuple[
        dict[str, _StaticValue],
        dict[str, _SequenceValue],
        set[str],
        set[str],
        dict[str, _FunctionIdentity | None],
        dict[str, str | None],
    ]:
        return (
            dict(self.bindings),
            dict(self.sequences),
            set(self.import_aliases),
            set(self.importlib_aliases),
            dict(self.function_bindings),
            dict(self.module_bindings),
        )

    def _branch(
        self,
        statements: Sequence[ast.AST],
        base: tuple[
            dict[str, _StaticValue],
            dict[str, _SequenceValue],
            set[str],
            set[str],
            dict[str, _FunctionIdentity | None],
            dict[str, str | None],
        ],
    ) -> tuple[
        dict[str, _StaticValue],
        dict[str, _SequenceValue],
        set[str],
        set[str],
        dict[str, _FunctionIdentity | None],
        dict[str, str | None],
    ]:
        bindings, sequences, import_aliases, importlib_aliases, function_bindings, module_bindings = base
        self.bindings = dict(bindings)
        self.sequences = dict(sequences)
        self.import_aliases = set(import_aliases)
        self.importlib_aliases = set(importlib_aliases)
        self.function_bindings = dict(function_bindings)
        self.module_bindings = dict(module_bindings)
        for statement in statements:
            self.visit(statement)
        return self._state()

    @staticmethod
    def _merge_aliases(
        left: set[str],
        right: set[str],
    ) -> set[str]:
        return left & right

    def _merge_states(
        self,
        left: tuple[
            dict[str, _StaticValue],
            dict[str, _SequenceValue],
            set[str],
            set[str],
            dict[str, _FunctionIdentity | None],
            dict[str, str | None],
        ],
        right: tuple[
            dict[str, _StaticValue],
            dict[str, _SequenceValue],
            set[str],
            set[str],
            dict[str, _FunctionIdentity | None],
            dict[str, str | None],
        ],
    ) -> None:
        self.bindings = _merge_static_bindings(left[0], right[0])
        self.sequences = {
            name: _merge_sequence_values(left[1].get(name), right[1].get(name))
            for name in left[1].keys() | right[1].keys()
        }
        self.import_aliases = self._merge_aliases(left[2], right[2])
        self.importlib_aliases = self._merge_aliases(left[3], right[3])
        self.function_bindings = {
            name: left[4].get(name) if left[4].get(name) == right[4].get(name) else None
            for name in left[4].keys() | right[4].keys()
        }
        self.module_bindings = {
            name: left[5].get(name) if left[5].get(name) == right[5].get(name) else None
            for name in left[5].keys() | right[5].keys()
        }

    def visit_Call(self, node: ast.Call) -> None:
        self._snapshot_call(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        value = _resolve_static_strings(node.value, self.bindings)
        sequence = _resolve_static_sequence(node.value, self.sequences)
        function = self._resolve_function_value(node.value)
        names: list[str] = []
        for target in node.targets:
            names.extend(_assigned_names(target))
        self._forget_names(tuple(names))
        for name in names:
            self.bindings[name] = value
            self.sequences[name] = sequence
            self.function_bindings[name] = function

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            value = _resolve_static_strings(node.value, self.bindings)
            sequence = _resolve_static_sequence(node.value, self.sequences)
            function = self._resolve_function_value(node.value)
        else:
            value = None
            sequence = None
            function = None
        names = _assigned_names(node.target)
        self._forget_names(names)
        for name in names:
            self.bindings[name] = value
            self.sequences[name] = sequence
            self.function_bindings[name] = function

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._forget_names(_assigned_names(node.target))

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        value = _resolve_static_strings(node.value, self.bindings)
        sequence = _resolve_static_sequence(node.value, self.sequences)
        function = self._resolve_function_value(node.value)
        names = _assigned_names(node.target)
        self._forget_names(names)
        for name in names:
            self.bindings[name] = value
            self.sequences[name] = sequence
            self.function_bindings[name] = function

    def visit_Delete(self, node: ast.Delete) -> None:
        self.generic_visit(node)
        self._forget_names(tuple(name for target in node.targets for name in _assigned_names(target)))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".", 1)[0]
            self._forget_names((bound,))
            if alias.name == "importlib":
                self.importlib_aliases.add(bound)
            else:
                self.module_bindings[bound] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        target_module = resolve_import(self._analysis.module, node.level, node.module)
        for alias in node.names:
            bound = alias.asname or alias.name
            self._forget_names((bound,))
            if node.module == "importlib":
                if alias.name == "import_module":
                    self.import_aliases.add(bound)
            else:
                function = self._analysis.function_exports.get(target_module, {}).get(alias.name)
                self.function_bindings[bound] = function

    def _resolve_function_value(self, node: ast.AST) -> _FunctionIdentity | None:
        if isinstance(node, ast.Name):
            return self.function_bindings.get(node.id)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            module = self.module_bindings.get(node.value.id)
            if module is not None:
                return self._analysis.function_exports.get(module, {}).get(node.attr)
        return None

    def _record_scope_entry(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        scope = self._analysis.scope_for(node)
        scope.entry_bindings = dict(self.bindings)
        scope.entry_sequences = dict(self.sequences)
        scope.entry_import_aliases = frozenset(self.import_aliases)
        scope.entry_importlib_aliases = frozenset(self.importlib_aliases)
        scope.entry_function_bindings = dict(self.function_bindings)
        scope.entry_module_bindings = dict(self.module_bindings)
        scope.entry_recorded = True

    def _visit_definition_header(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        self._record_scope_entry(node)
        for decorator in getattr(node, "decorator_list", ()):
            self.visit(decorator)
        for default in (
            getattr(node.args, "defaults", ()) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else ()
        ):
            self.visit(default)
        for default in (
            getattr(node.args, "kw_defaults", ()) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else ()
        ):
            if default is not None:
                self.visit(default)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            self.visit(node.returns)
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                self.visit(base)
            for keyword in node.keywords:
                self.visit(keyword.value)
        self._forget_names((node.name,))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.function_bindings[node.name] = self._analysis.function_identity(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_definition_header(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_definition_header(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_definition_header(node)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        base = self._state()
        left = self._branch(node.body, base)
        right = self._branch(node.orelse, base) if node.orelse else base
        self._merge_states(left, right)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        after_iter = self._state()
        # Resolve the source from bindings proven before this statement.  The
        # scope-wide assignment index also contains future assignments, which
        # must never make an earlier loop appear statically bounded.
        sequence = _resolve_static_sequence(node.iter, self.sequences)
        self._forget_names(_assigned_names(node.target))
        target_names = _assigned_names(node.target)
        if sequence is not None:
            values: dict[str, set[str]] = {}
            for item in sequence:
                for name, item_value in _assignment_targets(node.target, item).items():
                    if isinstance(item_value, str):
                        values.setdefault(name, set()).add(item_value)
            for name in target_names:
                self.bindings[name] = frozenset(values[name]) if name in values else None
        body = self._branch(node.body, self._state())
        loop_exit = self._branch(node.orelse, body) if node.orelse else body
        self._merge_states(after_iter, loop_exit)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        base = self._state()
        body = self._branch(node.body, base)
        loop_exit = self._branch(node.orelse, body) if node.orelse else body
        self._merge_states(base, loop_exit)

    def visit_Try(self, node: ast.Try) -> None:
        base = self._state()
        body = self._branch(node.body, base)
        exits = [body]
        for handler in node.handlers:
            exits.append(self._branch([handler], base))
        if node.orelse:
            exits = [self._branch(node.orelse, exit_state) for exit_state in exits]
        merged = exits[0]
        for exit_state in exits[1:]:
            merged = (
                _merge_static_bindings(merged[0], exit_state[0]),
                {
                    name: _merge_sequence_values(merged[1].get(name), exit_state[1].get(name))
                    for name in merged[1].keys() | exit_state[1].keys()
                },
                merged[2] & exit_state[2],
                merged[3] & exit_state[3],
                {
                    name: merged[4].get(name) if merged[4].get(name) == exit_state[4].get(name) else None
                    for name in merged[4].keys() | exit_state[4].keys()
                },
                {
                    name: merged[5].get(name) if merged[5].get(name) == exit_state[5].get(name) else None
                    for name in merged[5].keys() | exit_state[5].keys()
                },
            )
        self._merge_states(merged, self._branch(node.finalbody, merged) if node.finalbody else merged)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name is not None:
            self._forget_names((node.name,))
        for statement in node.body:
            self.visit(statement)

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                names = _assigned_names(item.optional_vars)
                self._forget_names(names)
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.visit_With(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # Lambda bodies have a separate lexical parameter environment.  Keep
        # outer proven aliases, but invalidate parameters and restore the
        # enclosing flow after visiting the body.
        outer = self._state()
        for parameter in _function_parameters(node):
            self._forget_names((parameter,))
        self.visit(node.body)
        (
            self.bindings,
            self.sequences,
            self.import_aliases,
            self.importlib_aliases,
            self.function_bindings,
            self.module_bindings,
        ) = outer
