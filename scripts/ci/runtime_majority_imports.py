"""Resolve one module's import edges from its syntax tree.

``build_graph`` in ``runtime_majority_python`` walks the package; this module
answers the question it asks of each file: which modules does this one import,
and does the import run at import time or only when a function is called.

A dynamic import resolves when its module argument is a string the source
fixes: a literal, a conditional between literals, a name bound to one of those,
a loop variable drawn from a module-level literal table, or the parameter of a
module-private helper every caller passes a literal to. ``runtime_majority_literals``
decides what the source fixes a name to; this module decides which scope's
answer applies, so a name a function shadows, rebinds or only binds through a
loop reads as open and its import site is counted unresolved, which makes the
scope contract declare it.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

from scripts.ci.runtime_majority_functions import is_type_checking_test
from scripts.ci.runtime_majority_literals import (
    column_values,
    literal_strings,
    literal_tables,
    scope_bindings,
    target_names,
    wrapper_literals,
)

_Comprehension = ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp


@dataclass
class PythonModule:
    """One module file under the package root."""

    name: str
    path: str
    is_package: bool
    loc: int


def _literal_package(node: ast.expr, module: PythonModule) -> str | None:
    """Package anchor of a relative ``import_module`` call, when statically known."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id == "__package__":
        return module.name if module.is_package else module.name.rpartition(".")[0]
    if isinstance(node, ast.Name) and node.id == "__name__":
        return module.name
    return None


def absolute_name(name: str, package: str | None) -> str | None:
    if not name.startswith("."):
        return name
    if not package:
        return None
    level = len(name) - len(name.lstrip("."))
    base = package.split(".")
    if level - 1 >= len(base):
        return None
    return ".".join([*base[: len(base) - (level - 1)], name.lstrip(".")]).rstrip(".")


class ImportCollector(ast.NodeVisitor):
    def __init__(self, module: PythonModule, skip_linenos: set[int] | None = None) -> None:
        self.module = module
        self._skip_linenos = skip_linenos or set()
        self.found: list[tuple[str, str, int, tuple[str, ...]]] = []
        self.dynamic_unresolved = 0
        self._function_depth = 0
        self._tables: dict[str, list[ast.expr]] = {}
        self._wrappers: dict[str, dict[str, Any]] = {}
        self._env: list[dict[str, set[str] | None]] = [{}]
        self._counts: list[dict[str, int]] = [{}]
        self._plain: list[dict[str, int]] = [{}]
        # Function scopes only. A ``for`` loop binds its target in the scope
        # around it, so a loop scope never shadows a module-level name.
        self._function_counts: list[dict[str, int]] = []
        self._modes: list[str | None] = [None]

    def _lookup(self) -> dict[str, set[str] | None]:
        merged: dict[str, set[str] | None] = {}
        for scope in self._env:
            merged.update(scope)
        return merged

    def _dynamic_mode(self) -> str:
        for mode in reversed(self._modes):
            if mode is not None:
                return mode
        return "lazy"

    def _push(
        self,
        scope: dict[str, set[str] | None],
        mode: str | None,
        bindings: tuple[dict[str, int], dict[str, int]] | None = None,
    ) -> None:
        """Enter a scope. Without its own bindings it shares the enclosing count."""
        counts, plain = bindings if bindings is not None else (self._counts[-1], self._plain[-1])
        self._env.append(scope)
        self._counts.append(counts)
        self._plain.append(plain)
        self._modes.append(mode)

    def _pop(self) -> None:
        self._env.pop()
        self._counts.pop()
        self._plain.pop()
        self._modes.pop()

    def _refinable(self, name: str) -> bool:
        """Whether the scope binds ``name`` once, plainly, so a value can be read."""
        return self._counts[-1].get(name) == 1 and self._plain[-1].get(name) == 1

    def _shadowed(self, name: str) -> bool:
        """Whether a function scope between here and the module binds ``name``."""
        return any(name in counts for counts in self._function_counts)

    def _mode(self) -> str:
        return "lazy" if self._function_depth else "eager"

    def visit(self, node: ast.AST) -> None:
        """Skip statements removed by a reviewed function-level exclusion."""
        if isinstance(node, ast.stmt) and node.lineno in self._skip_linenos:
            return
        super().visit(node)

    def visit_Module(self, node: ast.Module) -> None:
        self._tables = literal_tables(node)
        self._wrappers = wrapper_literals(node)
        self._counts[0], self._plain[0] = scope_bindings(node.body)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        if is_type_checking_test(node.test):
            for child in node.orelse:
                self.visit(child)
            return
        self.generic_visit(node)

    @staticmethod
    def _parameter_names(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> list[str]:
        spec = node.args
        names = [argument.arg for argument in (*spec.posonlyargs, *spec.args, *spec.kwonlyargs)]
        for extra in (spec.vararg, spec.kwarg):
            if extra is not None:
                names.append(extra.arg)
        return names

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        wrapper = self._wrappers.get(getattr(node, "name", ""))
        # A lambda's body is the single expression it returns, not a block.
        body: list[ast.stmt] = [ast.Expr(value=node.body)] if isinstance(node, ast.Lambda) else list(node.body)
        bindings = scope_bindings(body, self._parameter_names(node))
        counts, _plain = bindings
        # Every name this scope binds starts open, so a parameter or a local
        # does not read the value of a module-level name it shadows. ``_bind``
        # fills in the ones the scope binds once and plainly as it reaches them.
        scope: dict[str, set[str] | None] = dict.fromkeys(counts)
        if wrapper:
            # A call site's literal holds only while the body leaves the
            # parameter alone; a body that rebinds it has bound it twice.
            scope.update({name: values for name, values in wrapper["params"].items() if counts.get(name) == 1})
        self._function_depth += 1
        self._function_counts.append(counts)
        # A nested function's own imports run when it is called, whatever ran
        # the function around it, so an import-time wrapper's mode stops here.
        self._push(scope, wrapper["mode"] if wrapper else "lazy", bindings)
        self.generic_visit(node)
        self._pop()
        self._function_counts.pop()
        self._function_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815
    visit_Lambda = visit_FunctionDef  # noqa: N815

    def _bind(self, target: ast.expr, value: ast.expr) -> None:
        """Record what a single-name assignment leaves the name holding."""
        if not isinstance(target, ast.Name):
            return
        scope = self._env[-1]
        if not self._refinable(target.id):
            # The scope binds this name more than once, or somewhere a value
            # cannot be read out of, so no single static value survives.
            scope[target.id] = None
            return
        scope[target.id] = literal_strings(value, self._lookup())

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        if len(node.targets) == 1:
            self._bind(node.targets[0], node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is not None:
            self._bind(node.target, node.value)

    def _iterated_values(self, iterated: ast.expr, target: ast.expr) -> dict[str, set[str] | None]:
        """What iterating ``iterated`` leaves in ``target``, by tuple position.

        A name the source does not fix to a literal table, or a target shape the
        table's rows do not match, resolves nothing and is left out entirely.
        """
        if isinstance(iterated, ast.Name):
            # A function-scope name of the same spelling is what the loop
            # actually iterates, and its elements are not the module table's.
            elements = None if self._shadowed(iterated.id) else self._tables.get(iterated.id)
        elif isinstance(iterated, (ast.Tuple, ast.List)):
            elements = list(iterated.elts)
        else:
            elements = None
        if not elements:
            return {}
        if isinstance(target, ast.Name):
            return {target.id: column_values([literal_strings(element, {}) for element in elements])}
        if not isinstance(target, ast.Tuple):
            return {}
        targets = [item for item in target.elts if isinstance(item, ast.Name)]
        if len(targets) != len(target.elts):
            return {}
        width = len(targets)
        columns: list[list[set[str] | None]] = [[] for _ in range(width)]
        for element in elements:
            if not isinstance(element, (ast.Tuple, ast.List)) or len(element.elts) != width:
                return {}
            for index, item in enumerate(element.elts):
                columns[index].append(literal_strings(item, {}))
        return {name.id: column_values(column) for name, column in zip(targets, columns, strict=True)}

    def _loop_bindings(self, node: ast.For | ast.AsyncFor) -> dict[str, set[str] | None]:
        """Loop variables drawn from a literal table, resolved by tuple position."""
        resolved = self._iterated_values(node.iter, node.target)
        return {name: self._loop_value(name, values) for name, values in resolved.items()}

    def _comprehension_bindings(self, node: _Comprehension) -> dict[str, set[str] | None]:
        """Every name a comprehension's generators bind, and what each holds.

        Unlike a loop's, these names belong to the comprehension alone, so one
        the source leaves open is bound here to nothing rather than left out:
        leaving it out would let an enclosing binding of the same spelling
        answer for it.
        """
        scope: dict[str, set[str] | None] = {}
        for generator in node.generators:
            iterated = generator.iter
            if isinstance(iterated, ast.Name) and iterated.id in scope:
                # An earlier generator binds the name this one iterates, so a
                # module table of the same spelling is not what it walks.
                resolved: dict[str, set[str] | None] = {}
            else:
                resolved = self._iterated_values(iterated, generator.target)
            for name in target_names(generator.target):
                scope[name] = resolved.get(name)
        return scope

    def _visit_comprehension(self, node: _Comprehension) -> None:
        """Read a comprehension with its targets bound in a scope of its own.

        A comprehension's targets are not the enclosing scope's names, so a
        module-level or function-level literal spelled the same way says nothing
        about what the element expression reads. Without this scope a dynamic
        import inside the comprehension resolves to that outer literal, is
        recorded as a fixed edge, and never counts as unresolved -- the silent
        mis-resolution the scope contract exists to prevent. Only the first
        generator's iterable is evaluated outside the comprehension.
        """
        self.visit(node.generators[0].iter)
        self._push(self._comprehension_bindings(node), None)
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
            for test in generator.ifs:
                self.visit(test)
        for child in (getattr(node, "elt", None), getattr(node, "key", None), getattr(node, "value", None)):
            if child is not None:
                self.visit(child)
        self._pop()

    visit_ListComp = _visit_comprehension  # noqa: N815
    visit_SetComp = _visit_comprehension  # noqa: N815
    visit_DictComp = _visit_comprehension  # noqa: N815
    visit_GeneratorExp = _visit_comprehension  # noqa: N815

    def _loop_value(self, name: str, values: set[str] | None) -> set[str] | None:
        """The loop's own values, unless the scope binds the target elsewhere."""
        return values if self._counts[-1].get(name) == 1 else None

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._push(self._loop_bindings(node), None)
        for child in node.body:
            self.visit(child)
        self._pop()
        for child in node.orelse:
            self.visit(child)

    visit_AsyncFor = visit_For  # noqa: N815

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
            names = literal_strings(arg, self._lookup())
            targets = [absolute_name(item, package) for item in sorted(names)] if names else []
            if targets and all(targets):
                mode = self._dynamic_mode()
                for target in targets:
                    self.found.append((mode, target or "", 0, ()))
            else:
                self.dynamic_unresolved += 1
        self.generic_visit(node)
