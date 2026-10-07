"""Validate runtime test-retirement references without importing test modules.

This is an integrity gate, not evidence that a replacement test executed. Native
and installed-product CI remain responsible for running the referenced suites.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path, PurePosixPath
from typing import cast

_SCHEMA = "hol-guard.runtime-retirement-ledger.v1"
_RUST_NON_CODE = re.compile(
    r'//[^\n]*|/\*|(?:br|r)(\#*)"|(?:b)?"(?:\\.|[^"\\])*"|b?\'(?:\\.|[^\'\\])\'',
    re.DOTALL,
)
_RUST_TEST = re.compile(
    r"#\s*\[\s*test\s*\]\s*(?:#\s*\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:async\s+)?fn\s+([A-Za-z_][A-Za-z_0-9]*)\s*\("
)


def _strings(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise RuntimeError(f"retirement ledger requires non-empty {label}")
    result = cast(list[str], value)
    if len(set(result)) != len(result):
        raise RuntimeError(f"retirement ledger has duplicate {label}")
    return result


def _path(root: Path, relative: str) -> Path:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or "\\" in relative or path.as_posix() != relative:
        raise RuntimeError(f"retirement ledger has invalid repository path: {relative}")
    result = root / relative
    if not result.resolve().is_relative_to(root.resolve()):
        raise RuntimeError(f"retirement ledger path escapes repository: {relative}")
    return result


def _rust_code(source: str) -> str:
    """Mask comments and literals while preserving code, offsets and newlines."""
    result = list(source)
    position = 0
    while match := _RUST_NON_CODE.search(source, position):
        start, end = match.span()
        if match.group() == "/*":
            depth = 1
            while depth and end < len(source):
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise RuntimeError("retirement ledger cannot parse unterminated Rust comment")
        elif match.group(1) is not None:
            delimiter = '"' + match.group(1)
            closing = source.find(delimiter, end)
            if closing < 0:
                raise RuntimeError("retirement ledger cannot parse unterminated Rust raw string")
            end = closing + len(delimiter)
        for index in range(start, end):
            if source[index] != "\n":
                result[index] = " "
        position = end
    return "".join(result)


# A bracketed reference is only collectible when pytest generated that suffix.
# Values the static reader cannot decode keep the base node's parametrization
# check but forgo exact suffix matching.
_OPAQUE_PARAMS = object()


def _is_pytest_call(node: ast.expr, attribute: str) -> bool:
    """Match ``@pytest.mark.<attribute>(...)`` and ``pytest.<attribute>(...)``."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr != attribute:
        return False
    target = node.func.value
    if isinstance(target, ast.Name):
        return target.id in {"pytest", "mark", "param"}
    if isinstance(target, ast.Attribute):
        if target.attr == "mark" and isinstance(target.value, ast.Name) and target.value.id == "pytest":
            return True
        return target.attr in {"param"}
    return False


def _param_value_id(value: ast.expr) -> str | None:
    """Decode one parametrize argvalue the way pytest renders it, or return
    None when the expression is not statically decodable."""
    if isinstance(value, ast.Call) and _is_pytest_call(value, "param"):
        explicit = next((keyword.value for keyword in value.keywords if keyword.arg == "id"), None)
        if explicit is not None:
            if isinstance(explicit, ast.Constant) and isinstance(explicit.value, str):
                return explicit.value
            return None
        if len(value.args) != 1:
            return None
        return _param_value_id(value.args[0])
    if isinstance(value, ast.Constant):
        literal = value.value
        if isinstance(literal, str):
            return literal
        if isinstance(literal, bytes):
            try:
                return literal.decode("utf-8")
            except UnicodeDecodeError:
                return None
        if isinstance(literal, bool):
            return str(literal)
        if isinstance(literal, (int, float, complex)) or literal is None:
            return str(literal)
        return None
    return None


def _parametrize_suffixes(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str] | object | None:
    """Collect the valid ``[param]`` suffixes for a test function.

    Returns ``None`` when the node carries no parametrize mark, a set of
    suffixes when every layer decodes, or ``_OPAQUE_PARAMS`` when a layer is
    parametrized but its values cannot be statically resolved (e.g. imported
    constants): the base is still proven parametrized, but the exact suffix
    stays unverified.
    """
    layers: list[list[str] | None] = []
    for decorator in node.decorator_list:
        if not _is_pytest_call(decorator, "parametrize"):
            continue
        call = decorator
        argnames_node = call.args[0] if call.args else None
        if not isinstance(argnames_node, ast.Constant) or not isinstance(argnames_node.value, str):
            layers.append(None)
            continue
        argnames = [name.strip() for name in argnames_node.value.split(",")]
        ids_node = next((keyword.value for keyword in call.keywords if keyword.arg == "ids"), None)
        if ids_node is not None:
            if isinstance(ids_node, (ast.List, ast.Tuple)) and all(
                isinstance(item, ast.Constant) and isinstance(item.value, str) for item in ids_node.elts
            ):
                layers.append([item.value for item in ids_node.elts])
            else:
                layers.append(None)
            continue
        values_node = call.args[1] if len(call.args) > 1 else None
        if not isinstance(values_node, (ast.List, ast.Tuple)):
            layers.append(None)
            continue
        layer: list[str] = []
        for element in values_node.elts:
            if isinstance(element, ast.Call) and _is_pytest_call(element, "param"):
                explicit = next((kw.value for kw in element.keywords if kw.arg == "id"), None)
                if explicit is not None:
                    if isinstance(explicit, ast.Constant) and isinstance(explicit.value, str):
                        layer.append(explicit.value)
                        continue
                    layers.append(None)
                    layer = []
                    break
                parts = [_param_value_id(part) for part in element.args]
            elif len(argnames) > 1:
                if isinstance(element, (ast.Tuple, ast.List)) and len(element.elts) == len(argnames):
                    parts = [_param_value_id(part) for part in element.elts]
                else:
                    parts = [None]
            else:
                parts = [_param_value_id(element)]
            if any(part is None for part in parts):
                layers.append(None)
                layer = []
                break
            layer.append("-".join(cast(list[str], parts)))
        else:
            layers.append(layer)
    if not layers:
        return None
    if any(layer is None for layer in layers):
        return _OPAQUE_PARAMS
    # Stacked parametrize decorators produce suffixes bottom-up: the innermost
    # (last) decorator contributes the leftmost id part.
    suffixes = cast(list[list[str]], layers)[-1]
    for layer in reversed(cast(list[list[str]], layers)[:-1]):
        suffixes = [inner + "-" + outer for outer in layer for inner in suffixes]
    return set(suffixes)


def _test_nodes(path: Path) -> dict[str, object]:
    source = path.read_text(encoding="utf-8")
    if path.suffix == ".rs":
        names = _RUST_TEST.findall(_rust_code(source))
        if len(names) != len(set(names)):
            raise RuntimeError(f"retirement ledger has ambiguous Rust test nodes: {path.name}")
        return dict.fromkeys(names, None)
    if path.suffix != ".py":
        raise RuntimeError(f"retirement ledger has unsupported test file: {path.name}")
    tree = ast.parse(source, filename=str(path))
    nodes: dict[str, object] = {}

    def collect(body: list[ast.stmt], prefix: str = "") -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                name = prefix + node.name
                if name in nodes:
                    raise RuntimeError(f"retirement ledger has duplicate Python test node: {path.name}::{name}")
                nodes[name] = _parametrize_suffixes(node)
            elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                # Pytest does not collect test classes with custom constructors.
                if not any(
                    isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name in {"__init__", "__new__"}
                    for child in node.body
                ):
                    collect(node.body, prefix + node.name + "::")

    collect(tree.body)
    return nodes


def validate_retirement_ledger(root: Path, contract: dict[str, object]) -> dict[str, int]:
    relative = contract.get("retirement_ledger")
    if not isinstance(relative, str) or not relative:
        raise RuntimeError("retirement ledger path is required for retired modules")
    ledger_path = _path(root, relative)
    if not ledger_path.is_file():
        raise RuntimeError(f"retirement ledger is missing: {relative}")
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    if not isinstance(ledger, dict) or ledger.get("schema") != _SCHEMA:
        raise RuntimeError("retirement ledger has invalid schema")
    records = contract["retired_modules"]
    if not isinstance(records, list) or not all(isinstance(record, dict) for record in records):
        raise RuntimeError("retirement ledger requires retired module records")
    expected_sources = {record["path"] for record in records}
    if set(_strings(ledger.get("retired_source_paths"), "retired_source_paths")) != expected_sources:
        raise RuntimeError("retirement ledger source paths do not match ownership contract")
    inventory: dict[str, dict[str, object]] = {}

    def node_exists(reference: object) -> bool:
        if not isinstance(reference, str) or "::" not in reference:
            raise RuntimeError("retirement ledger requires a file::test node reference")
        filename, node = reference.split("::", 1)
        path = _path(root, filename)
        base, separator, params = node.partition("[")
        valid_node = bool(base) and all(part.isidentifier() for part in base.split("::"))
        if separator:
            valid_node = valid_node and len(params) > 1 and node.endswith("]")
        if (
            not valid_node
            or path.suffix not in {".py", ".rs"}
            or (path.suffix == ".rs" and ("::" in node or "[" in node))
        ):
            raise RuntimeError(f"retirement ledger has a malformed test node: {reference}")
        if not path.is_file():
            return False
        if filename not in inventory:
            inventory[filename] = _test_nodes(path)
        if base not in inventory[filename]:
            return False
        if not separator:
            return True
        suffixes = inventory[filename][base]
        if suffixes is _OPAQUE_PARAMS:
            # Parametrized, but the values are not statically decodable, so the
            # exact suffix cannot be verified here.
            return True
        # A bracketed reference to a non-parametrized test, or a parameter id
        # pytest never generated, is not a collectible node.
        return suffixes is not None and params[:-1] in suffixes

    old_nodes: set[str] = set()
    replacements_checked: set[str] = set()
    for section, replacement_key in (("retired_tests", "replacement_nodes"), ("preserved_tests", "new_node")):
        entries = ledger.get(section)
        if not isinstance(entries, list) or (section == "retired_tests" and not entries):
            raise RuntimeError(f"retirement ledger requires {section} records")
        for entry in entries:
            if not isinstance(entry, dict):
                raise RuntimeError(f"retirement ledger has invalid {section} record")
            old = entry.get("old_node")
            if node_exists(old):
                raise RuntimeError(f"retirement ledger old test node still exists: {old}")
            assert isinstance(old, str)
            if old in old_nodes:
                raise RuntimeError(f"retirement ledger duplicates old test node: {old}")
            old_nodes.add(old)
            replacements = entry.get(replacement_key)
            if section == "preserved_tests":
                replacements = [replacements]
            if section == "retired_tests" and entry.get("status") == "obsolete_implementation_assertion":
                rationale = entry.get("rationale")
                if not isinstance(rationale, str) or not rationale.strip():
                    raise RuntimeError(f"obsolete retired test requires a rationale: {old}")
                if not isinstance(replacements, list):
                    raise RuntimeError(f"retirement ledger {replacement_key} must be a list: {old}")
                for replacement in replacements:
                    if not isinstance(replacement, str) or not node_exists(replacement):
                        raise RuntimeError(f"retirement ledger replacement test node is missing: {replacement}")
                    replacements_checked.add(replacement)
                continue
            for replacement in _strings(replacements, replacement_key):
                if not node_exists(replacement):
                    raise RuntimeError(f"retirement ledger replacement test node is missing: {replacement}")
                replacements_checked.add(replacement)
    retired_paths = contract.get("retired_test_paths", [])
    if not isinstance(retired_paths, list) or not set(retired_paths) <= {node.split("::", 1)[0] for node in old_nodes}:
        raise RuntimeError("retirement ledger does not map every retired test path")
    suites = _strings(ledger.get("unchanged_regression_suites"), "unchanged_regression_suites")
    for relative in suites:
        path = _path(root, relative)
        if not path.is_file() or not _test_nodes(path):
            raise RuntimeError(f"retirement ledger regression suite is missing or has no tests: {relative}")
    return {
        "mapped_old_tests": len(old_nodes),
        "replacement_tests": len(replacements_checked),
        "regression_suites": len(suites),
    }
