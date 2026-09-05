#!/usr/bin/env python3
"""Reject semantic Python hook evaluators reachable from production entries."""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

SCHEMA: Final = "hol-guard.python-hook-semantic-callgraph.v1"
_SRC_PACKAGE = "codex_plugin_scanner.guard"
_PRODUCTION_FILES: Final = (
    "src/codex_plugin_scanner/guard/cli/commands_hook.py",
    "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py",
    "src/codex_plugin_scanner/guard/cli/commands_hook_source_ref.py",
    "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py",
    "src/codex_plugin_scanner/guard/daemon/hook_worker.py",
    "src/codex_plugin_scanner/guard/daemon/server.py",
    "src/codex_plugin_scanner/guard/native_pretool.py",
    "src/codex_plugin_scanner/guard/native_runtime.py",
)
_ROOTS: Final = (
    ("src/codex_plugin_scanner/guard/cli/commands_hook.py", None, "_run_guard_hook_command"),
    ("src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py", None, "try_native_hook_authority"),
    ("src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py", None, "try_native_or_source_ref_hook"),
    ("src/codex_plugin_scanner/guard/cli/commands_hook_source_ref.py", None, "_try_source_ref_fast_path"),
    ("src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py", None, "_run_resident_hook_request"),
    ("src/codex_plugin_scanner/guard/daemon/hook_worker.py", "HookWorker", "review_http_payload"),
    ("src/codex_plugin_scanner/guard/daemon/hook_worker.py", "HookWorker", "_review_post_tool_http"),
    ("src/codex_plugin_scanner/guard/daemon/server.py", "_GuardDaemonHandler", "_handle_runtime_hook_fast"),
    ("src/codex_plugin_scanner/guard/daemon/server.py", "_GuardDaemonHandler", "_execute_runtime_hook"),
    ("src/codex_plugin_scanner/guard/native_pretool.py", None, "review_pre_tool_native"),
    ("src/codex_plugin_scanner/guard/native_runtime.py", None, "review_post_tool_native"),
)
_SEMANTIC_MODULES: Final = frozenset(
    {
        f"{_SRC_PACKAGE}.runtime.hook_content_scanner",
        f"{_SRC_PACKAGE}.runtime.hook_decision_cache",
        f"{_SRC_PACKAGE}.runtime.hook_review_engine",
        f"{_SRC_PACKAGE}.runtime.hook_source_read",
    }
)
_SEMANTIC_SYMBOLS: Final = frozenset(
    {
        "ContentScanner",
        "HookDecisionCache",
        "HookReviewEngine",
        "evaluate_source_file_ref",
        "evaluate_command",
        "classify_secret_content",
    }
)


@dataclass(frozen=True, slots=True)
class _Module:
    name: str
    path: Path
    tree: ast.Module
    functions: dict[tuple[str | None, str], ast.FunctionDef | ast.AsyncFunctionDef]
    imports: dict[str, str]


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise RuntimeError(f"could not inspect {path}") from error


def _full_module_name(root: Path, path: Path) -> str:
    relative = path.relative_to(root / "src").with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve_import(module_name: str, level: int, imported: str | None) -> str:
    if level == 0:
        return imported or ""
    package = module_name.split(".")[:-1]
    if level > len(package) + 1:
        return imported or ""
    base = package[: len(package) - level + 1]
    if imported:
        base.append(imported)
    return ".".join(base)


def _functions(tree: ast.Module) -> dict[tuple[str | None, str], ast.FunctionDef | ast.AsyncFunctionDef]:
    result: dict[tuple[str | None, str], ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result[(None, node.name)] = node
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    result[(node.name, child.name)] = child
    return result


def _imports(module_name: str, tree: ast.Module) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                result[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            target = _resolve_import(module_name, node.level, node.module)
            for alias in node.names:
                if alias.name == "*":
                    continue
                result[alias.asname or alias.name] = f"{target}.{alias.name}" if target else alias.name
    return result


def _load_modules(root: Path) -> dict[str, _Module]:
    modules: dict[str, _Module] = {}
    for relative in _PRODUCTION_FILES:
        path = root / relative
        if not path.is_file():
            continue
        tree = ast.parse(_read(path), filename=str(path))
        name = _full_module_name(root, path)
        modules[name] = _Module(name, path, tree, _functions(tree), _imports(name, tree))
    return modules


def _is_semantic_module(value: str) -> bool:
    return value in _SEMANTIC_MODULES or any(value.startswith(f"{module}.") for module in _SEMANTIC_MODULES)


def _call_target(call: ast.Call) -> tuple[str | None, str | None]:
    if isinstance(call.func, ast.Name):
        return call.func.id, None
    if isinstance(call.func, ast.Attribute):
        owner = call.func.value.id if isinstance(call.func.value, ast.Name) else None
        return owner, call.func.attr
    return None, None


def _semantic_import_references(
    node: ast.ImportFrom | ast.Import,
    module_name: str,
) -> list[str]:
    failures: list[str] = []
    if isinstance(node, ast.ImportFrom):
        target = _resolve_import(module_name, node.level, node.module)
        for alias in node.names:
            resolved = f"{target}.{alias.name}" if target else alias.name
            if _is_semantic_module(target) or _is_semantic_module(resolved) or alias.name in _SEMANTIC_SYMBOLS:
                failures.append(f"line {node.lineno}: imports semantic hook evaluator {resolved}")
    else:
        for alias in node.names:
            if _is_semantic_module(alias.name):
                failures.append(f"line {node.lineno}: imports semantic hook evaluator {alias.name}")
    return failures


def _semantic_call_references(call: ast.Call, imports: dict[str, str]) -> list[str]:
    failures: list[str] = []
    owner, attribute = _call_target(call)
    if owner in _SEMANTIC_SYMBOLS or attribute in _SEMANTIC_SYMBOLS:
        failures.append(f"line {call.lineno}: calls semantic hook evaluator {owner or attribute}")
    if owner is not None and owner in imports and _is_semantic_module(imports[owner]):
        failures.append(f"line {call.lineno}: calls semantic hook module {imports[owner]}")
    if isinstance(call.func, ast.Name) and call.func.id in imports:
        target = imports[call.func.id]
        if _is_semantic_module(target) or target.rsplit(".", maxsplit=1)[-1] in _SEMANTIC_SYMBOLS:
            failures.append(f"line {call.lineno}: calls semantic hook evaluator {target}")
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        target = imports.get(call.func.value.id)
        if target is not None and _is_semantic_module(target):
            failures.append(f"line {call.lineno}: calls semantic hook module {target}")
    if (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "importlib"
        and call.func.attr == "import_module"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
        and _is_semantic_module(call.args[0].value)
    ):
        failures.append(f"line {call.lineno}: dynamically imports semantic hook evaluator")
    return failures


def _semantic_references(node: ast.AST, module_name: str, imports: dict[str, str]) -> list[str]:
    failures: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, (ast.ImportFrom, ast.Import)):
            failures.extend(_semantic_import_references(child, module_name))
        elif isinstance(child, ast.Call):
            failures.extend(_semantic_call_references(child, imports))
    return failures


def _root_node(
    module: _Module,
    class_name: str | None,
    function_name: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    return module.functions.get((class_name, function_name))


def _reachable_functions(module: _Module, root: ast.AST) -> tuple[ast.AST, ...]:
    by_name = {name: node for (_, name), node in module.functions.items()}
    queue = [root]
    seen: set[int] = set()
    result: list[ast.AST] = []
    while queue:
        node = queue.pop()
        marker = id(node)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(node)
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            owner, attribute = _call_target(child)
            candidate = attribute if attribute in by_name else owner
            if candidate in by_name:
                queue.append(by_name[candidate])
    return tuple(result)


def _graph_failures(root: Path) -> list[str]:
    """Return production hook entrypoints that can reach semantic Python code."""

    modules = _load_modules(root)
    failures: list[str] = []
    for relative in _PRODUCTION_FILES:
        path = root / relative
        if not path.is_file():
            failures.append(f"required production hook source is missing: {relative}")
            continue
        module = modules.get(_full_module_name(root, path))
        if module is None:
            failures.append(f"could not parse production hook source: {relative}")
            continue
        for child in module.tree.body:
            if isinstance(child, ast.ImportFrom):
                target = _resolve_import(module.name, child.level, child.module)
                if _is_semantic_module(target):
                    failures.append(f"{relative}: line {child.lineno}: imports semantic hook evaluator {target}")
            elif isinstance(child, ast.Import):
                for alias in child.names:
                    if _is_semantic_module(alias.name):
                        failures.append(
                            f"{relative}: line {child.lineno}: imports semantic hook evaluator {alias.name}"
                        )
    for relative, class_name, function_name in _ROOTS:
        path = root / relative
        module = modules.get(_full_module_name(root, path))
        if module is None:
            continue
        node = _root_node(module, class_name, function_name)
        if node is None:
            failures.append(f"{relative}: missing hook entrypoint {class_name or 'module'}.{function_name}")
            continue
        for reachable in _reachable_functions(module, node):
            for failure in _semantic_references(reachable, module.name, module.imports):
                failures.append(f"{relative}:{function_name}: {failure}")
    return list(dict.fromkeys(failures))


def run(root: Path) -> dict[str, object]:
    failures = _graph_failures(root.resolve())
    if failures:
        raise RuntimeError("; ".join(failures))
    return {"schema": SCHEMA, "status": "passed", "roots": len(_ROOTS)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    try:
        payload = run(args.root)
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
