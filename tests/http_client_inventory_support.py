"""Resolve statically imported HTTP clients through local module facades."""

from __future__ import annotations

import ast
from pathlib import Path

_PACKAGE = "codex_plugin_scanner.guard"


def _expression_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _expression_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent is not None else None
    return None


def _import_bindings(node: ast.stmt, module: str, *, package: bool = False) -> dict[str, str]:
    if isinstance(node, ast.Import):
        return {
            item.asname or item.name.split(".", 1)[0]: item.name if item.asname else item.name.split(".", 1)[0]
            for item in node.names
        }
    if not isinstance(node, ast.ImportFrom):
        return {}
    prefix = node.module or ""
    if node.level:
        components = module.split(".") if package else module.split(".")[:-1]
        if node.level > len(components):
            return {}
        prefix = ".".join([*components[: len(components) - node.level + 1], *([prefix] if prefix else [])])
    return {item.asname or item.name: f"{prefix}.{item.name}" for item in node.names if item.name != "*"}


class HttpClientInventory:
    """Follow actual import/assignment bindings, with bounded cycle refusal."""

    def __init__(self, source_root: Path) -> None:
        self.source_root = source_root
        self._exports: dict[str, dict[str, str]] = {}

    def _module(self, path: Path) -> str:
        parts = list(path.relative_to(self.source_root).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        return ".".join([_PACKAGE, *parts])

    def _path(self, module: str) -> Path | None:
        if module != _PACKAGE and not module.startswith(_PACKAGE + "."):
            return None
        suffix = module.removeprefix(_PACKAGE).lstrip(".")
        base = self.source_root.joinpath(*suffix.split(".")) if suffix else self.source_root
        for candidate in (base.with_suffix(".py"), base / "__init__.py"):
            if candidate.is_file():
                return candidate
        return None

    def _module_exports(self, module: str) -> dict[str, str]:
        if module in self._exports:
            return self._exports[module]
        path = self._path(module)
        if path is None:
            return {}
        aliases: dict[str, str] = {}
        for node in ast.parse(path.read_text(encoding="utf-8"), filename=str(path)).body:
            aliases.update(_import_bindings(node, module, package=path.name == "__init__.py"))
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = _expression_name(node.value, aliases) if node.value is not None else None
                for target in targets:
                    if isinstance(target, ast.Name):
                        if value is None:
                            aliases.pop(target.id, None)
                        else:
                            aliases[target.id] = value
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                aliases.pop(node.name, None)
        self._exports[module] = aliases
        return aliases

    def resolve(self, name: str) -> str:
        seen: set[str] = set()
        for _ in range(64):
            if name in seen:
                return name
            seen.add(name)
            parts = name.split(".")
            replacement = None
            for boundary in range(len(parts) - 1, 0, -1):
                module = ".".join(parts[:boundary])
                exported = self._module_exports(module).get(parts[boundary])
                if exported is not None:
                    replacement = ".".join([exported, *parts[boundary + 1 :]])
                    break
            if replacement is None or replacement == name:
                return name
            name = replacement
        return name

    def calls(self, path: Path) -> list[tuple[int, str]]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module = self._module(path)
        aliases: dict[str, str] = {}
        # Keep the existing inventory's conservative static import scope. Local
        # facade exports themselves use only their real top-level declarations.
        for node in ast.walk(tree):
            if isinstance(node, ast.stmt):
                aliases.update(_import_bindings(node, module, package=path.name == "__init__.py"))
        # Module-level static function aliases remain visible to later calls.
        aliases.update(self._module_exports(module))
        result: list[tuple[int, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _expression_name(node.func, aliases)
                if name is not None:
                    result.append((node.lineno, self.resolve(name)))
        return result
