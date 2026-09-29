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


def _test_nodes(path: Path) -> set[str]:
    source = path.read_text(encoding="utf-8")
    if path.suffix == ".rs":
        names = _RUST_TEST.findall(_rust_code(source))
        if len(names) != len(set(names)):
            raise RuntimeError(f"retirement ledger has ambiguous Rust test nodes: {path.name}")
        return set(names)
    if path.suffix != ".py":
        raise RuntimeError(f"retirement ledger has unsupported test file: {path.name}")
    tree = ast.parse(source, filename=str(path))
    nodes: set[str] = set()

    def collect(body: list[ast.stmt], prefix: str = "") -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                name = prefix + node.name
                if name in nodes:
                    raise RuntimeError(f"retirement ledger has duplicate Python test node: {path.name}::{name}")
                nodes.add(name)
            elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                # Pytest does not collect test classes with custom constructors.
                if not any(
                    isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.name in {"__init__", "__new__"}
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
    inventory: dict[str, set[str]] = {}

    def node_exists(reference: object) -> bool:
        if not isinstance(reference, str) or "::" not in reference:
            raise RuntimeError("retirement ledger requires a file::test node reference")
        filename, node = reference.split("::", 1)
        path = _path(root, filename)
        if (
            not node
            or not all(part.isidentifier() for part in node.split("::"))
            or path.suffix not in {".py", ".rs"}
            or (path.suffix == ".rs" and "::" in node)
        ):
            raise RuntimeError(f"retirement ledger requires a non-parametrized test node: {reference}")
        if not path.is_file():
            return False
        if filename not in inventory:
            inventory[filename] = _test_nodes(path)
        return node in inventory[filename]

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
