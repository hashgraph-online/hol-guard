"""Inspect Python hook launch syntax without granting registration ownership."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path

from typing_extensions import override


def has_codex_harness_tokens(tokens: Sequence[str | None]) -> bool:
    return any(
        token == "--harness=codex"
        or (token == "--harness" and index + 1 < len(tokens) and tokens[index + 1] == "codex")
        for index, token in enumerate(tokens)
    )


def _python_hook_payload(tokens: Sequence[str]) -> list[str]:
    payload = list(tokens)
    while payload and payload[0].startswith("-") and payload[0] not in {"-", "--"}:
        option = payload[0]
        if option.startswith("--"):
            # A separate operand consumes two tokens; attached long options
            # already contain their operand and consume only their own token.
            payload = payload[2 if option == "--check-hash-based-pycs" else 1 :]
            continue
        for index, flag in enumerate(option[1:], start=1):
            if flag in {"c", "m"}:
                attached = option[index + 1 :]
                return ["-" + flag, *([attached] if attached else []), *payload[1:]]
            if flag in {"W", "X"}:
                payload = payload[1 if index + 1 < len(option) else 2 :]
                break
        else:
            payload = payload[1:]
    return payload


def _codex_hook_arguments(arguments: Sequence[str | None]) -> bool:
    payload = list(arguments)
    if payload[:1] == ["guard"]:
        payload = payload[1:]
    return payload[:1] == ["hook"] and has_codex_harness_tokens(payload)


_IMPORT_APIS = {"runpy.run_module": "mod_name", "importlib.import_module": "name", "builtins.__import__": "name"}


class _GuardImportCalls(ast.NodeVisitor):
    """Track static import bindings without executing Python or claiming ownership."""

    def __init__(self) -> None:
        self.bindings: dict[str, frozenset[str]] = {"__import__": frozenset({"builtins.__import__"})}
        self.found: bool = False
        self.class_globals: dict[str, frozenset[str]] | None = None
        self.walrus_scopes: list[dict[str, frozenset[str]] | None] = []
        self.module_bindings: dict[str, frozenset[str]] = {}
        self.global_names: set[str] = set()
        self.global_updates: dict[str, frozenset[str]] = {}
        self.deferred: list[
            tuple[
                ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
                dict[str, frozenset[str]],
                dict[str, frozenset[str]],
            ]
        ] = []
        self.module_calls: list[tuple[ast.Call, dict[str, frozenset[str]]]] = []
        self.in_function: bool = False

    def _bind(self, name: str, identity: frozenset[str]) -> None:
        self.bindings[name] = identity
        if name in self.global_names:
            self.module_bindings[name] = self.module_bindings.get(name, frozenset()) | identity
            self.global_updates[name] = self.global_updates.get(name, frozenset()) | identity

    @override
    def visit_Global(self, node: ast.Global) -> None:
        self.global_names.update(node.names)

    def finish(self) -> None:
        """Inspect deferred bodies against module bindings available when called."""
        self.module_bindings = self.bindings.copy()
        roots = self.deferred.copy()
        # Nested definitions join the deferred queue during analysis. Count them
        # in the bound; stable bindings still stop after the first pass.
        body_count = sum(
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
            for node, _, _ in roots
            for item in ast.walk(node)
        )
        for _ in range(body_count + 1):
            previous = self.global_updates.copy()
            self.deferred = roots.copy()
            index = 0
            while index < len(self.deferred):
                node, enclosing, parameters = self.deferred[index]
                index += 1
                self.bindings = enclosing.copy()
                self._merge(self.module_bindings)
                self.bindings.update(parameters)
                self.global_names = set()
                self.in_function = True
                if isinstance(node, ast.Lambda):
                    self.visit(node.body)
                else:
                    self._body(node.body)
            if self.found or self.global_updates == previous:
                break
        else:
            # Cyclic attribute aliases can grow without converging. Bound analysis
            # and preserve the possible conflict rather than hanging installation.
            self.found = True
        self.in_function = False
        self.global_names = set()
        # Global imports in deferred bodies can supply later module-level calls.
        for node, bindings in self.module_calls:
            self.bindings = bindings.copy()
            for name, identities in self.global_updates.items():
                self.bindings[name] = self.bindings.get(name, frozenset()) | identities
            self._check_call(node)

    def _identity(self, node: ast.AST) -> frozenset[str]:
        if isinstance(node, ast.Name):
            default: frozenset[str] = frozenset({"builtins.__import__"}) if node.id == "__import__" else frozenset()
            return self.bindings.get(node.id, default)
        if isinstance(node, ast.Attribute):
            return frozenset(f"{base}.{node.attr}" for base in self._identity(node.value))
        if isinstance(node, (ast.Tuple, ast.List)):
            values = self._literal_sequence(node)
            if values is not None:
                return frozenset(
                    f"sequence:{len(values)}:{index}:{identity}"
                    for index, item in enumerate(values)
                    for identity in (self._identity(item) or frozenset({""}))
                )
        if isinstance(node, ast.Subscript):
            index = node.slice
            negative = isinstance(index, ast.UnaryOp) and isinstance(index.op, ast.USub)
            constant = index.operand if negative and isinstance(index, ast.UnaryOp) else index
            if isinstance(constant, ast.Constant) and isinstance(constant.value, int):
                values = [identity.split(":", 3) for identity in self._identity(node.value)]
                entries = [
                    (int(parts[1]), int(parts[2]), parts[3])
                    for parts in values
                    if len(parts) == 4 and parts[0] == "sequence"
                ]
                selected = int(constant.value) * (-1 if negative else 1)
                return frozenset(
                    identity
                    for length, position, identity in entries
                    if position == (selected + length if selected < 0 else selected) and identity
                )
        if isinstance(node, ast.Call):
            for identity in self._identity(node.func):
                keyword = _IMPORT_APIS.get(identity)
                if identity not in {"builtins.__import__", "importlib.import_module"}:
                    continue
                module = (
                    node.args[0]
                    if node.args and not isinstance(node.args[0], ast.Starred)
                    else next((item.value for item in node.keywords if item.arg == keyword), None)
                )
                level = (
                    node.args[4]
                    if len(node.args) > 4
                    else next((item.value for item in node.keywords if item.arg == "level"), ast.Constant(value=0))
                )
                if identity == "builtins.__import__" and not (isinstance(level, ast.Constant) and level.value == 0):
                    continue
                if isinstance(module, ast.Constant) and module.value in {"runpy", "importlib", "builtins"}:
                    return frozenset({str(module.value)})
        return frozenset()

    def _body(self, nodes: Sequence[ast.stmt]) -> None:
        for node in nodes:
            self.visit(node)

    @override
    def visit_Import(self, node: ast.Import) -> None:
        for imported in node.names:
            root = imported.name.split(".")[0]
            self._bind(imported.asname or root, frozenset({imported.name if imported.asname else root}))

    @override
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for imported in node.names:
            identity = f"{node.module}.{imported.name}" if node.module and node.level == 0 else ""
            self._bind(imported.asname or imported.name, frozenset({identity}))

    @override
    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Del):
            _ = self.bindings.pop(node.id, None)
        elif isinstance(node.ctx, ast.Store):
            self._bind(node.id, frozenset())

    @override
    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        bindings = [binding for target in node.targets for binding in self._assignment_bindings(target, node.value)]
        for target in node.targets:
            self.visit(target)
        for name, identity in bindings:
            self._bind(name, identity)

    def _assignment_bindings(self, target: ast.expr, value: ast.expr) -> list[tuple[str, frozenset[str]]]:
        if isinstance(target, ast.Name):
            return [(target.id, self._identity(value))]
        values = self._literal_sequence(value)
        if not isinstance(target, (ast.Tuple, ast.List)) or values is None:
            return []
        stars = [index for index, item in enumerate(target.elts) if isinstance(item, ast.Starred)]
        pairs: list[tuple[ast.expr, ast.expr]]
        if not stars and len(target.elts) == len(values):
            pairs = list(zip(target.elts, values, strict=True))
        elif len(stars) == 1 and len(values) >= len(target.elts) - 1:
            index = stars[0]
            suffix = target.elts[index + 1 :]
            pairs = list(zip(target.elts[:index], values[:index], strict=True))
            target_rest = target.elts[index]
            if isinstance(target_rest, ast.Starred):
                end = len(values) - len(suffix)
                pairs.append((target_rest.value, ast.List(elts=values[index:end], ctx=ast.Load())))
            if suffix:
                pairs.extend(zip(suffix, values[-len(suffix) :], strict=True))
        else:
            return []
        return [binding for item, expression in pairs for binding in self._assignment_bindings(item, expression)]

    def _literal_sequence(self, node: ast.expr) -> list[ast.expr] | None:
        if not isinstance(node, (ast.Tuple, ast.List)):
            return None
        values: list[ast.expr] = []
        for item in node.elts:
            if isinstance(item, ast.Starred):
                nested = self._literal_sequence(item.value)
                if nested is None:
                    return None
                values.extend(nested)
            else:
                values.append(item)
        return values

    @override
    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            identity = self._identity(node.value)
            self.visit(node.target)
            if isinstance(node.target, ast.Name):
                self._bind(node.target.id, identity)

    @override
    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self.visit(node.target)

    @override
    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        identity = self._identity(node.value)
        self.visit(node.target)
        self._bind(node.target.id, identity)
        if self.walrus_scopes and (owner := self.walrus_scopes[-1]) is not None:
            current, self.bindings = self.bindings, owner
            self._bind(node.target.id, identity)
            self.bindings = current

    def _parameters(self, arguments: ast.arguments) -> dict[str, frozenset[str]]:
        positional = [*arguments.posonlyargs, *arguments.args]
        parameters = [*positional, *arguments.kwonlyargs]
        parameters.extend(parameter for parameter in (arguments.vararg, arguments.kwarg) if parameter is not None)
        result: dict[str, frozenset[str]] = {parameter.arg: frozenset() for parameter in parameters}
        if arguments.defaults:
            for parameter, default in zip(positional[-len(arguments.defaults) :], arguments.defaults, strict=True):
                result[parameter.arg] = self._identity(default)
        for parameter, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
            if default is not None:
                result[parameter.arg] = self._identity(default)
        return result

    @override
    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for expression in (*node.decorator_list, *node.args.defaults, *node.args.kw_defaults):
            if expression is not None:
                self.visit(expression)
        self.bindings[node.name] = frozenset()
        parameters = self._parameters(node.args)
        enclosing_class = self.class_globals
        enclosing = (enclosing_class if enclosing_class is not None else self.bindings).copy()
        self.deferred.append((node, enclosing, parameters))

    @override
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    @override
    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        parameters = self._parameters(node.args)
        enclosing_class = self.class_globals
        enclosing = (enclosing_class if enclosing_class is not None else self.bindings).copy()
        self.deferred.append((node, enclosing, parameters))

    @override
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in (*node.decorator_list, *node.bases):
            self.visit(expression)
        self.bindings[node.name] = frozenset()
        outer = self.bindings
        enclosing_class = self.class_globals
        self.class_globals = outer
        self.bindings = outer.copy()
        self._body(node.body)
        self.bindings = outer
        self.class_globals = enclosing_class

    def _comprehension(self, generators: Sequence[ast.comprehension], values: Sequence[ast.expr]) -> None:
        outer = self.bindings
        enclosing_class = self.class_globals
        owner = self.walrus_scopes[-1] if self.walrus_scopes else (outer if enclosing_class is None else None)
        self.walrus_scopes.append(owner)
        if generators:
            self.visit(generators[0].iter)
        self.bindings = (enclosing_class if enclosing_class is not None else outer).copy()
        self.class_globals = None
        for index, generator in enumerate(generators):
            if index:
                self.visit(generator.iter)
            self.visit(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        for value in values:
            self.visit(value)
        self.bindings = outer
        self.class_globals = enclosing_class
        _ = self.walrus_scopes.pop()

    @override
    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._comprehension(node.generators, [node.elt])

    @override
    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._comprehension(node.generators, [node.elt])

    @override
    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._comprehension(node.generators, [node.elt])

    @override
    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._comprehension(node.generators, [node.key, node.value])

    @override
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self.bindings[node.name] = frozenset()
        self._body(node.body)
        if node.name:
            # Python deletes an exception alias at the end of the handler.
            _ = self.bindings.pop(node.name, None)

    def _merge(self, other: dict[str, frozenset[str]]) -> None:
        for name in other.keys() | self.bindings.keys():
            default: frozenset[str] = frozenset({"builtins.__import__"}) if name == "__import__" else frozenset()
            self.bindings[name] = self.bindings.get(name, default) | other.get(name, default)

    @override
    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        before = self.bindings.copy()
        self._body(node.body)
        positive = self.bindings
        self.bindings = before
        self._body(node.orelse)
        self._merge(positive)

    @override
    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        before = self.bindings.copy()
        self.visit(node.target)
        self._body(node.body)
        self._body(node.orelse)
        self._merge(before)

    @override
    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)

    @override
    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        before = self.bindings.copy()
        self._body(node.body)
        self._body(node.orelse)
        self._merge(before)

    @override
    def visit_Try(self, node: ast.Try) -> None:
        before = self.bindings.copy()
        self._body(node.body)
        after_body = self.bindings.copy()
        self._body(node.orelse)
        alternatives = self.bindings.copy()
        for handler in node.handlers:
            self.bindings = before.copy()
            self._merge(after_body)
            self.visit(handler)
            self._merge(alternatives)
            alternatives = self.bindings.copy()
        self.bindings = alternatives
        self._body(node.finalbody)

    @override
    def visit_Call(self, node: ast.Call) -> None:
        if not self.in_function:
            self.module_calls.append((node, self.bindings.copy()))
        self._check_call(node)
        self.generic_visit(node)

    def _check_call(self, node: ast.Call) -> None:
        for identity in self._identity(node.func):
            keyword = _IMPORT_APIS.get(identity)
            if keyword is None:
                continue
            module = (
                node.args[0]
                if node.args and not isinstance(node.args[0], ast.Starred)
                else next((item.value for item in node.keywords if item.arg == keyword), None)
            )
            if isinstance(module, ast.Constant) and module.value in {
                "codex_plugin_scanner.cli",
                "codex_plugin_scanner",
            }:
                self.found = True


def _imports_guard_cli(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(name.name == "codex_plugin_scanner.cli" for name in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and (
            node.module == "codex_plugin_scanner.cli"
            or (node.module == "codex_plugin_scanner" and any(name.name == "cli" for name in node.names))
        ):
            return True
    calls = _GuardImportCalls()
    try:
        calls.visit(tree)
        calls.finish()
    except RecursionError:
        # An unanalyzable handler cannot establish that it is unrelated.
        return True
    return calls.found


def _inline_python_codex_hook(script: str, trailing_arguments: Sequence[str]) -> bool:
    """Inspect static imports/argv without executing code or resolving values."""
    try:
        tree = ast.parse(script)
    except (SyntaxError, ValueError, RecursionError):
        # Parse errors precede import analysis. The traversal recursion guard
        # separately preserves possible conflicts when a valid AST is too deep.
        return False
    if not _imports_guard_cli(tree):
        return False
    if _codex_hook_arguments(trailing_arguments):
        return True
    for node in ast.walk(tree):
        if not isinstance(node, (ast.List, ast.Tuple)):
            continue
        values = [
            item.value if isinstance(item, ast.Constant) and isinstance(item.value, str) else None for item in node.elts
        ]
        if values[:1] == ["guard"]:
            values = values[1:]
        if values[:1] != ["hook"]:
            continue
        # A dynamic harness operand cannot prove this is an unrelated handler.
        if any(value == "--harness" and values[index + 1 : index + 2] == [None] for index, value in enumerate(values)):
            return True
        if _codex_hook_arguments(values):
            return True
    return False


def python_codex_hook_command(tokens: Sequence[str]) -> bool:
    payload = _python_hook_payload(tokens[1:])
    if payload[:1] == ["--"]:
        return len(payload) > 1 and Path(payload[1]).name == "codex_daemon_hook_bridge.py"
    if payload[:2] == ["-m", "codex_plugin_scanner.cli"] and _codex_hook_arguments(payload[2:]):
        return True
    if payload and Path(payload[0]).name == "codex_daemon_hook_bridge.py":
        return True
    return payload[:1] == ["-c"] and len(payload) > 1 and _inline_python_codex_hook(payload[1], payload[2:])
