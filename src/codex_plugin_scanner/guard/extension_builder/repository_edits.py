"""Verified source insertion points for native registration and packaging.

Repository files are parsed as bounded data. No destination Python is imported
or executed, and unknown layouts are conflicts rather than heuristic edits.
"""

from __future__ import annotations

import ast
import importlib
import json
import sys
from typing import TYPE_CHECKING, cast

from .errors import BuilderError
from .io import object_value, parse_json
from .models import Metadata
from .render_native import constant_prefix, contribution_path

if TYPE_CHECKING or sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised by the Python 3.10 CI job
    tomllib = importlib.import_module("tomli")

TRUST_PATH = "contracts/extensions/trust-class-map.v1.json"
CATALOG_PATH = "src/codex_plugin_scanner/guard/runtime/command_builtin_extension_catalog.py"
STAGING_PATH = "scripts/release/stage_guard_cloud_review_artifacts.py"
PYPROJECT_PATH = "pyproject.toml"


def conflict(message: str) -> BuilderError:
    return BuilderError("repository_conflict", message, conflict=True)


def parse_python(content: str) -> ast.Module:
    try:
        tree = ast.parse(content, feature_version=(3, 10))
    except (SyntaxError, RecursionError, ValueError) as exc:
        raise conflict("A repository integration file has unsupported Python syntax.") from exc
    if sum(1 for _ in ast.walk(tree)) > 50_000:
        raise conflict("A repository integration file exceeds the supported syntax budget.")
    return tree


def _assignment(tree: ast.Module, name: str) -> ast.Assign | ast.AnnAssign:
    matches: list[ast.Assign | ast.AnnAssign] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            assert isinstance(node, (ast.Assign, ast.AnnAssign))
            matches.append(node)
    if len(matches) != 1:
        raise conflict("An expected unique repository registration anchor is missing or duplicated.")
    return matches[0]


def trust_members(content: str) -> dict[str, list[str]]:
    payload = object_value(parse_json(content.encode("utf-8")))
    if payload.get("schemaVersion") != "guard.extension-trust-class-map.v1":
        raise conflict("The repository uses an unsupported extension trust map.")
    classes = object_value(payload.get("classes"))
    if set(classes) != {"external", "first-party", "trusted-library"}:
        raise conflict("The repository trust classes do not match the supported contract.")
    seen: set[str] = set()
    result: dict[str, list[str]] = {}
    for name, value in classes.items():
        if not isinstance(value, list) or len(value) > 512 or any(not isinstance(item, str) for item in value):
            raise conflict("The repository trust map has an invalid class inventory.")
        values = cast(list[str], value)
        if len(set(values)) != len(values) or seen.intersection(values):
            raise conflict("The repository trust map contains duplicate extension identities.")
        seen.update(values)
        result[name] = values
    return result


def _line_ending(content: str) -> str:
    return "\r\n" if "\r\n" in content else "\n"


def edit_trust(content: str, metadata: Metadata) -> str:
    classes = trust_members(content)
    if metadata.catalog_id in classes["first-party"] or metadata.catalog_id in classes["trusted-library"]:
        raise conflict("The builder cannot modify an existing trusted extension or change its trust class.")
    if metadata.catalog_id in classes["external"]:
        return content
    payload = object_value(parse_json(content.encode("utf-8")))
    object_value(payload["classes"])["external"] = sorted([*classes["external"], metadata.catalog_id])
    return (json.dumps(payload, ensure_ascii=True, indent=2) + "\n").replace("\n", _line_ending(content))


def _toml(content: str) -> dict[str, object]:
    try:
        return cast(dict[str, object], tomllib.loads(content))
    except (ValueError, RecursionError) as exc:
        raise conflict("The destination pyproject is not valid supported TOML.") from exc


def _wheel_mapping(content: str) -> dict[str, object]:
    payload = _toml(content)
    if object_value(payload.get("project")).get("name") != "hol-guard":
        raise conflict("The destination must be a HOL Guard source checkout.")
    current = payload
    for key in ("tool", "hatch", "build", "targets", "wheel", "force-include"):
        current = object_value(current.get(key))
    return current


def edit_pyproject(content: str, metadata: Metadata) -> str:
    mapping = _wheel_mapping(content)
    source = contribution_path(metadata)
    family = "extensions" if metadata.kind == "cli" else "mcp_servers"
    destination = f"codex_plugin_scanner/guard/contracts/data/{family}/contributions/{metadata.contribution_id}.json"
    if source in mapping:
        if mapping[source] != destination:
            raise conflict("An existing wheel inclusion points this contribution at a different destination.")
        return content
    if destination in mapping.values():
        raise conflict("Another wheel inclusion already owns this contribution destination.")
    lines = content.splitlines(keepends=True)
    anchors = [
        index
        for index, line in enumerate(lines)
        if line.rstrip("\r\n") == "[tool.hatch.build.targets.wheel.force-include]"
    ]
    if len(anchors) != 1:
        raise conflict("The wheel contribution insertion point is missing or ambiguous.")
    index = anchors[0]
    newline = _line_ending(lines[index])
    if not lines[index].endswith("\n"):
        lines[index] += newline
    lines.insert(index + 1, f"{json.dumps(source)} = {json.dumps(destination)}{newline}")
    updated = "".join(lines)
    _wheel_mapping(updated)
    return updated


def _literal_mapping(node: ast.AST | None) -> dict[str, str]:
    if not isinstance(node, ast.Dict):
        raise conflict("The frozen contribution artifact map must remain a literal dictionary.")
    result: dict[str, str] = {}
    for key, value in zip(node.keys, node.values, strict=True):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            raise conflict("The frozen contribution artifact map has a nonliteral key.")
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str) or key.value in result:
            raise conflict("The frozen contribution artifact map has an invalid or duplicate entry.")
        result[key.value] = value.value
    return result


def edit_staging(content: str, metadata: Metadata) -> str:
    assignment = _assignment(parse_python(content), "_ARTIFACTS")
    mapping = _literal_mapping(assignment.value)
    source = contribution_path(metadata)
    family = "extensions" if metadata.kind == "cli" else "mcp_servers"
    destination = f"{family}/contributions/{metadata.contribution_id}.json"
    if source in mapping:
        if mapping[source] != destination:
            raise conflict("The frozen artifact map already assigns a different destination.")
        return content
    if destination in mapping.values():
        raise conflict("Another frozen artifact entry already owns this contribution destination.")
    lines = content.splitlines(keepends=True)
    last_line = assignment.end_lineno
    if last_line is None or lines[last_line - 1].strip() != "}":
        raise conflict("The frozen artifact dictionary has an unsupported insertion layout.")
    entry = f"    {json.dumps(source)}: {json.dumps(destination)},\n"
    if len(entry.rstrip()) > 120:
        entry = f"    {json.dumps(source)}: (\n        {json.dumps(destination)}\n    ),\n"
    lines.insert(last_line - 1, entry.replace("\n", _line_ending(content)))
    updated = "".join(lines)
    _literal_mapping(_assignment(parse_python(updated), "_ARTIFACTS").value)
    return updated


def _catalog_pair_exists(value: ast.AST | None, specs: str, rules: str) -> bool:
    if not isinstance(value, ast.Tuple):
        raise conflict("The direct command catalog must remain an explicit tuple.")
    matches = 0
    for row in value.elts:
        if (
            not isinstance(row, ast.Tuple)
            or len(row.elts) != 2
            or any(not isinstance(item, ast.Name) for item in row.elts)
        ):
            raise conflict("The direct command catalog has an unsupported constructor shape.")
        names = tuple(cast(ast.Name, item).id for item in row.elts)
        if specs in names or rules in names:
            if names != (specs, rules):
                raise conflict("The generated catalog symbols are already bound to another constructor.")
            matches += 1
    if matches > 1:
        raise conflict("The direct catalog contains duplicate contribution registrations.")
    return matches == 1


def edit_catalog(content: str, metadata: Metadata) -> str:
    prefix = constant_prefix(metadata)
    specs, rules = f"{prefix}_COMMAND_EXTENSION_SPECS", f"{prefix}_COMMAND_RULES"
    tree = parse_python(content)
    imports = [node for node in tree.body if isinstance(node, ast.ImportFrom) and node.level == 1]
    owned = [node for node in imports if node.module == metadata.module_leaf]
    if len(owned) > 1:
        raise conflict("The direct catalog contains duplicate generated imports.")
    if owned:
        names = {(item.name, item.asname) for item in owned[0].names}
        if names != {(specs, None), (rules, None)}:
            raise conflict("An existing detector import has incompatible symbols.")
    elif any(item.name in {specs, rules} or item.asname in {specs, rules} for node in imports for item in node.names):
        raise conflict("Another detector import already owns the generated catalog symbols.")
    assignment = _assignment(tree, "_DIRECT_EXTENSION_CATALOGS")
    registered = _catalog_pair_exists(assignment.value, specs, rules)
    if bool(owned) != registered:
        raise conflict("The existing import and direct catalog registration disagree.")
    if registered:
        return content
    if not imports or assignment.end_lineno is None:
        raise conflict("The direct catalog insertion layout is unsupported.")
    lines = content.splitlines(keepends=True)
    if lines[assignment.end_lineno - 1].strip() != ")":
        raise conflict("The direct catalog tuple has an unsupported closing layout.")
    pair = f"    ({specs}, {rules}),\n"
    if len(pair.rstrip()) > 120:
        pair = f"    (\n        {specs},\n        {rules},\n    ),\n"
    lines.insert(assignment.end_lineno - 1, pair.replace("\n", _line_ending(content)))
    before = next((node for node in imports if (node.module or "") > metadata.module_leaf), None)
    insertion = before.lineno - 1 if before is not None else cast(int, imports[-1].end_lineno)
    new_import = f"from .{metadata.module_leaf} import {specs}, {rules}\n"
    if len(new_import.rstrip()) > 120:
        new_import = f"from .{metadata.module_leaf} import (\n    {specs},\n    {rules},\n)\n"
    lines.insert(insertion, new_import.replace("\n", _line_ending(content)))
    updated = "".join(lines)
    _catalog_pair_exists(_assignment(parse_python(updated), "_DIRECT_EXTENSION_CATALOGS").value, specs, rules)
    return updated
