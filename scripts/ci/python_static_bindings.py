"""Resolve explicit Python facade and method bindings without executing source."""

from __future__ import annotations

import ast
import copy
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Reference:
    module: str
    name: str | None = None


class StaticBindings:
    """Bounded import/attribute resolution for the daemon's composed source graph."""

    def __init__(self, facade: Path) -> None:
        self.facade = facade.resolve()
        self.source_root = next((p for p in self.facade.parents if p.name == "src"), self.facade.parent)
        self.trees: dict[Path, ast.Module] = {}
        self.active: set[tuple[Path, str]] = set()

    def module_name(self, path: Path) -> str:
        return ".".join(path.resolve().relative_to(self.source_root).with_suffix("").parts)

    def module_path(self, name: str) -> Path | None:
        parts = name.split(".")
        if not all(part.isidentifier() for part in parts):
            raise RuntimeError("invalid static module reference")
        path = self.source_root.joinpath(*parts).with_suffix(".py")
        if not path.is_file():
            return None
        if not path.resolve().is_relative_to(self.source_root):
            raise RuntimeError("static source escaped the source root")
        return path.resolve()

    def tree(self, path: Path) -> ast.Module:
        path = path.resolve()
        if not path.is_relative_to(self.source_root):
            raise RuntimeError("static source escaped the source root")
        if path not in self.trees:
            if len(self.trees) >= 128:
                raise RuntimeError("static binding source limit exceeded")
            try:
                self.trees[path] = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, UnicodeError, SyntaxError) as error:
                raise RuntimeError(f"could not inspect static source {path}") from error
            for statement in self.trees[path].body:
                if isinstance(statement, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef)):
                    continue
                if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                    if statement.value is not None:
                        self._module_value(path, statement.target.id, statement.value)
                    continue
                if isinstance(statement, ast.Assign) and all(isinstance(t, ast.Name) for t in statement.targets):
                    target = statement.targets[0]
                    assert isinstance(target, ast.Name)
                    self._module_value(path, target.id, statement.value)
                    continue
                if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                    continue
                raise RuntimeError("static source contains executable or indirect module bindings")
        return self.trees[path]

    def _module_value(self, path: Path, name: str, value: ast.expr) -> None:
        calls = [n for n in ast.walk(value) if isinstance(n, ast.Call)]
        if not calls:
            return
        fixed = {
            "_LOGGER": "logging.getLogger(__name__)",
            "_HEADLESS_CLOUD_SYNC_STATE_LOCK": "threading.Lock()",
            "_STATIC_DIR": "Path(__file__).with_name('static')",
        }
        expected = fixed.get(name)
        if path == self.facade and expected and ast.dump(value) == ast.dump(ast.parse(expected, mode="eval").body):
            return
        for call in calls:
            if isinstance(call.func, ast.Name) and call.func.id in {"frozenset", "set"} and not call.keywords:
                if any(self._declares(n, call.func.id) for n in self.trees[path].body):
                    raise RuntimeError("literal container constructor is rebound")
                try:
                    for arg in call.args:
                        ast.literal_eval(arg)
                except (ValueError, TypeError):
                    raise RuntimeError("nonliteral module container initialization") from None
                continue
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "join"
                and isinstance(call.func.value, ast.Constant)
                and isinstance(call.func.value.value, str)
                and len(call.args) == 1
                and not call.keywords
            ):
                try:
                    values = ast.literal_eval(call.args[0])
                except (ValueError, TypeError):
                    raise RuntimeError("nonliteral module string initialization") from None
                if isinstance(values, tuple) and all(isinstance(v, str) for v in values):
                    continue
            raise RuntimeError("executable module attribute initialization is unsupported")

    def imported_module(self, path: Path, node: ast.ImportFrom) -> str:
        if node.level == 0:
            return node.module or ""
        parents = self.module_name(path).split(".")[:-1]
        if node.level > len(parents):
            raise RuntimeError("relative static import escaped its package")
        base = parents[: len(parents) - node.level + 1]
        if node.module:
            base.extend(node.module.split("."))
        return ".".join(base)

    @staticmethod
    def _declares(node: ast.AST, name: str) -> bool:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return node.name == name
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return any((a.asname or a.name.split(".")[0]) == name or a.name == "*" for a in node.names)
        return any(
            isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, (ast.Store, ast.Del)) for n in ast.walk(node)
        )

    def declaration(self, path: Path, name: str) -> ast.stmt:
        matches = [n for n in self.tree(path).body if self._declares(n, name)]
        if len(matches) != 1:
            raise RuntimeError(f"expected exactly one static binding for {name} in {path}")
        return matches[0]

    def reference(self, path: Path, name: str) -> tuple[Reference, ast.AST | None]:
        key = (path.resolve(), name)
        if key in self.active or len(self.active) >= 64:
            raise RuntimeError("cyclic or excessive static binding chain")
        self.active.add(key)
        try:
            node = self.declaration(path, name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return Reference(self.module_name(path), name), node
            if isinstance(node, ast.Import):
                alias = next(a for a in node.names if (a.asname or a.name.split(".")[0]) == name)
                return Reference(alias.name if alias.asname else alias.name.split(".")[0]), None
            if isinstance(node, ast.ImportFrom):
                alias = next((a for a in node.names if (a.asname or a.name) == name), None)
                if alias is None:
                    raise RuntimeError("wildcard static binding is unsupported")
                target = self.imported_module(path, node)
                child = self.module_path(f"{target}.{alias.name}")
                if child is not None:
                    return Reference(self.module_name(child)), None
                imported = self.module_path(target)
                if (
                    imported is not None
                    and imported.parent == self.facade.parent
                    and imported.stem.startswith("server_")
                ):
                    return self.reference(imported, alias.name)
                return Reference(target, alias.name), None
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, (ast.Name, ast.Attribute)):
                    return self.expression(path, node.value)
                return Reference(self.module_name(path), name), node
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                return Reference(self.module_name(path), name), node
            raise RuntimeError(f"unsupported static binding for {name} in {path}")
        finally:
            self.active.remove(key)

    def expression(self, path: Path, node: ast.expr) -> tuple[Reference, ast.AST | None]:
        if isinstance(node, ast.Name):
            return self.reference(path, node.id)
        if isinstance(node, ast.Attribute):
            owner, definition = self.expression(path, node.value)
            if definition is not None or owner.name is not None:
                raise RuntimeError("static binding requires an imported module attribute")
            target = self.module_path(owner.module)
            if target is None:
                return Reference(owner.module, node.attr), None
            return self.reference(target, node.attr)
        raise RuntimeError("dynamic static binding is unsupported")

    def normalized(self, path: Path, node: ast.AST) -> ast.AST:
        """Normalize only a verified, unshadowed reference to this exact facade."""
        aliases: set[str] = set()
        for declaration in self.tree(path).body:
            if not isinstance(declaration, (ast.Import, ast.ImportFrom)):
                continue
            for imported in declaration.names:
                name = imported.asname or imported.name.split(".")[0]
                reference, _ = self.reference(path, name)
                if reference.name is None and self.module_path(reference.module) == self.facade:
                    aliases.add(name)
        for child in ast.walk(node):
            named_binding = None
            if isinstance(
                child,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler, ast.MatchAs, ast.MatchStar),
            ):
                named_binding = child.name
            elif isinstance(child, ast.MatchMapping):
                named_binding = child.rest
            if child is not node and named_binding in aliases:
                raise RuntimeError("facade alias is shadowed by a declaration or pattern")
            if (
                isinstance(child, ast.Name) and child.id in aliases and isinstance(child.ctx, (ast.Store, ast.Del))
            ) or (isinstance(child, ast.arg) and child.arg in aliases):
                raise RuntimeError("facade alias is shadowed in the inspected function")
            if isinstance(child, (ast.Import, ast.ImportFrom)) and any(
                (a.asname or a.name.split(".")[0]) in aliases for a in child.names
            ):
                raise RuntimeError("facade alias is rebound in the inspected function")
        if (
            path != self.facade
            and any(isinstance(n, ast.Name) and n.id == "_server" for n in ast.walk(node))
            and "_server" not in aliases
        ):
            raise RuntimeError("server helper does not reference the exact facade")

        class Normalize(ast.NodeTransformer):
            def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
                if isinstance(node.value, ast.Name) and node.value.id in aliases:
                    return ast.copy_location(ast.Name(id=node.attr, ctx=node.ctx), node)
                return self.generic_visit(node)

        return Normalize().visit(copy.deepcopy(node))

    def resolved_class(self, name: str) -> tuple[Path, ast.ClassDef]:
        reference, node = self.reference(self.facade, name)
        if not isinstance(node, ast.ClassDef):
            path = self.module_path(reference.module)
            if path is not None and reference.name is not None:
                reference, node = self.reference(path, reference.name)
        path = self.module_path(reference.module)
        if path is None or not isinstance(node, ast.ClassDef):
            raise RuntimeError(f"expected an explicit class binding for {name}")
        if node.decorator_list or node.keywords:
            raise RuntimeError("decorated or metaclass-driven class binding is unsupported")
        allowed_bases = {
            Reference("http.server", "BaseHTTPRequestHandler"),
            Reference("codex_plugin_scanner.guard.daemon.bounded_http", "BoundedThreadingHTTPServer"),
            Reference("typing", "TypedDict"),
        }
        for base in node.bases:
            if (
                isinstance(base, ast.Name)
                and base.id in {"ValueError", "object"}
                and not any(self._declares(n, base.id) for n in self.tree(path).body)
            ):
                continue
            if self.expression(path, base)[0] not in allowed_bases:
                raise RuntimeError("class construction has an unsupported base binding")
        return path, node

    def class_tree(self, name: str) -> ast.ClassDef:
        path, original = self.resolved_class(name)
        result = copy.deepcopy(original)
        result.name = name
        result.body = []
        seen: set[str] = set()
        for child in original.body:
            if isinstance(child, ast.FunctionDef):
                bound_name = child.name
                if any(
                    not isinstance(d, ast.Name) or d.id not in {"staticmethod", "classmethod"}
                    for d in child.decorator_list
                ):
                    raise RuntimeError("dynamic method decorator is unsupported")
                if any(
                    self._declares(n, d.id)
                    for d in child.decorator_list
                    if isinstance(d, ast.Name)
                    for n in self.tree(path).body + original.body
                ):
                    raise RuntimeError("method descriptor wrapper is rebound")
                function = self.normalized(path, child)
                assert isinstance(function, ast.FunctionDef)
            elif isinstance(child, ast.Assign) and len(child.targets) == 1 and isinstance(child.targets[0], ast.Name):
                bound_name = child.targets[0].id
                value = child.value
                decorator = None
                if isinstance(value, ast.Call):
                    if not (
                        isinstance(value.func, ast.Name)
                        and value.func.id in {"staticmethod", "classmethod"}
                        and len(value.args) == 1
                        and not value.keywords
                    ):
                        raise RuntimeError(f"dynamic class binding for {bound_name}")
                    decorator = value.func.id
                    if any(self._declares(n, decorator) for n in self.tree(path).body + original.body):
                        raise RuntimeError("method descriptor wrapper is rebound")
                    value = value.args[0]
                if not isinstance(value, (ast.Name, ast.Attribute)):
                    try:
                        ast.literal_eval(value)
                    except (ValueError, TypeError):
                        raise RuntimeError("nonliteral class attribute initialization") from None
                    result.body.append(copy.deepcopy(child))
                    continue
                reference, definition = self.expression(path, value)
                if not isinstance(definition, ast.FunctionDef):
                    if decorator is not None or not isinstance(definition, (ast.Assign, ast.AnnAssign)):
                        raise RuntimeError(f"method binding is not an explicit function: {bound_name}")
                    if definition.value is None:
                        raise RuntimeError(f"dynamic class attribute alias: {bound_name}")
                    try:
                        ast.literal_eval(definition.value)
                    except (ValueError, TypeError):
                        raise RuntimeError(f"dynamic class attribute alias: {bound_name}") from None
                    result.body.append(copy.deepcopy(child))
                    continue
                target = self.module_path(reference.module)
                assert target is not None
                function = self.normalized(target, definition)
                assert isinstance(function, ast.FunctionDef)
                if function.decorator_list:
                    raise RuntimeError("decorated free method binding is unsupported")
                function.name = bound_name
                if decorator:
                    function.decorator_list = [ast.Name(id=decorator, ctx=ast.Load())]
            else:
                if isinstance(child, ast.Expr) and isinstance(child.value, ast.Constant):
                    result.body.append(copy.deepcopy(child))
                    continue
                if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                    if child.value is not None:
                        try:
                            ast.literal_eval(child.value)
                        except (ValueError, TypeError):
                            if not (
                                child.target.id == "_quarantine_lock"
                                and isinstance(child.value, ast.Call)
                                and not child.value.args
                                and not child.value.keywords
                                and self.expression(path, child.value.func)[0] == Reference("threading", "Lock")
                            ):
                                raise RuntimeError("executable class annotation value is unsupported") from None
                    result.body.append(copy.deepcopy(child))
                    continue
                raise RuntimeError("executable or indirect class binding is unsupported")
            if bound_name in seen or sum(self._declares(n, bound_name) for n in original.body) != 1:
                raise RuntimeError(f"ambiguous class method binding: {bound_name}")
            seen.add(bound_name)
            result.body.append(function)
        return result

    def logical_tree(self) -> ast.Module:
        """Assemble actual facade exports and actual class method targets for gates."""
        result = ast.Module(body=[], type_ignores=[])
        for child in self.tree(self.facade).body:
            if isinstance(child, ast.ClassDef):
                result.body.append(self.class_tree(child.name))
            elif isinstance(child, ast.Assign) and len(child.targets) == 1 and isinstance(child.targets[0], ast.Name):
                name = child.targets[0].id
                if not isinstance(child.value, (ast.Name, ast.Attribute)):
                    result.body.append(copy.deepcopy(child))
                    continue
                reference, definition = self.reference(self.facade, name)
                path = self.module_path(reference.module)
                if isinstance(definition, ast.ClassDef):
                    result.body.append(self.class_tree(name))
                elif isinstance(definition, ast.FunctionDef) and path is not None:
                    function = self.normalized(path, definition)
                    assert isinstance(function, ast.FunctionDef)
                    function.name = name
                    result.body.append(function)
                elif reference.name is not None:
                    result.body.append(
                        ast.copy_location(
                            ast.ImportFrom(
                                module=reference.module,
                                names=[ast.alias(name=reference.name, asname=name)],
                                level=0,
                            ),
                            child,
                        )
                    )
                else:
                    result.body.append(
                        ast.copy_location(
                            ast.Import(
                                names=[ast.alias(name=reference.module, asname=name)],
                            ),
                            child,
                        )
                    )
            else:
                result.body.append(copy.deepcopy(child))
        return result


def function_node(path: Path, name: str, class_name: str | None = None) -> ast.FunctionDef:
    resolver = StaticBindings(path)
    if path.name == "server.py":
        helper, _ = resolver.reference(path, "_native_mode_requires_rust")
        if helper != Reference("codex_plugin_scanner.guard.native_mode", "native_mode_requires_rust"):
            raise RuntimeError("native authority guard has an unexpected binding")
    body = resolver.class_tree(class_name).body if class_name else resolver.logical_tree().body
    candidates = [n for n in body if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(candidates) != 1:
        raise RuntimeError(f"expected exactly one {class_name or 'module'}.{name} in {path}")
    return candidates[0]
