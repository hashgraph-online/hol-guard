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
from .render_native import command_source_path, contribution_path

if TYPE_CHECKING or sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised by the Python 3.10 CI job
    tomllib = importlib.import_module("tomli")

TRUST_PATH = "contracts/extensions/trust-class-map.v1.json"
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


def _artifact_mappings(metadata: Metadata) -> tuple[tuple[str, str], ...]:
    family = "extensions" if metadata.kind == "cli" else "mcp_servers"
    mappings = [
        (
            contribution_path(metadata),
            f"codex_plugin_scanner/guard/contracts/data/{family}/contributions/{metadata.contribution_id}.json",
        )
    ]
    if metadata.kind == "cli":
        mappings.append(
            (
                command_source_path(metadata),
                f"codex_plugin_scanner/guard/contracts/data/extensions/command-sources/{metadata.contribution_id}.json",
            )
        )
    return tuple(mappings)


def edit_pyproject(content: str, metadata: Metadata) -> str:
    mapping = _wheel_mapping(content)
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
    insertion = index + 1
    for source, destination in _artifact_mappings(metadata):
        if source in mapping:
            if mapping[source] != destination:
                raise conflict("An existing wheel inclusion points this contribution at a different destination.")
            continue
        if destination in mapping.values():
            raise conflict("Another wheel inclusion already owns this contribution destination.")
        lines.insert(insertion, f"{json.dumps(source)} = {json.dumps(destination)}{newline}")
        insertion += 1
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
    lines = content.splitlines(keepends=True)
    last_line = assignment.end_lineno
    if last_line is None or lines[last_line - 1].strip() != "}":
        raise conflict("The frozen artifact dictionary has an unsupported insertion layout.")
    insertion = last_line - 1
    for source, packaged in _artifact_mappings(metadata):
        destination = packaged.removeprefix("codex_plugin_scanner/guard/contracts/data/")
        if source in mapping:
            if mapping[source] != destination:
                raise conflict("The frozen artifact map already assigns a different destination.")
            continue
        if destination in mapping.values():
            raise conflict("Another frozen artifact entry already owns this contribution destination.")
        entry = f"    {json.dumps(source)}: {json.dumps(destination)},\n"
        if len(entry.rstrip()) > 120:
            entry = f"    {json.dumps(source)}: (\n        {json.dumps(destination)}\n    ),\n"
        lines.insert(insertion, entry.replace("\n", _line_ending(content)))
        insertion += 1
    updated = "".join(lines)
    _literal_mapping(_assignment(parse_python(updated), "_ARTIFACTS").value)
    return updated
