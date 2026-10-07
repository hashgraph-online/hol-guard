"""Verified source insertion points for native registration and packaging.

Repository files are parsed as bounded data. No destination Python is imported
or executed, and unknown layouts are conflicts rather than heuristic edits.
"""

from __future__ import annotations

import ast
import importlib
import json
import sys
from pathlib import Path
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
BINDINGS_DIR = "contracts/extensions/trust"
STAGING_PATH = "scripts/release/stage_guard_cloud_review_artifacts.py"
PYPROJECT_PATH = "pyproject.toml"


def conflict(message: str) -> BuilderError:
    return BuilderError("repository_conflict", message, conflict=True)


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


def trust_binding_path(metadata: Metadata) -> str:
    """Return the authored-binding path for this contribution's catalog id."""
    return f"{BINDINGS_DIR}/{metadata.catalog_id}.v1.json"


def trust_binding_content(metadata: Metadata) -> str:
    """Render the authored per-extension binding for a new external id."""
    return (
        json.dumps(
            {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": metadata.catalog_id,
                "trustClass": "external",
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n"
    )


def _binding_id(path: str, content: str) -> tuple[str, str]:
    payload = object_value(parse_json(content.encode("utf-8")))
    if payload.get("schemaVersion") != "guard.extension-trust-binding.v1":
        raise conflict(f"The repository trust binding {path} uses an unsupported schema.")
    extension = payload.get("extension")
    trust_class = payload.get("trustClass")
    stem = path.rsplit("/", 1)[-1]
    if not isinstance(extension, str) or extension != stem[: -len(".v1.json")]:
        raise conflict(f"The repository trust binding {path} extension does not match its filename.")
    if not isinstance(trust_class, str) or trust_class not in {"first-party", "trusted-library", "external"}:
        raise conflict(f"The repository trust binding {path} has an unknown trust class.")
    return extension, trust_class


def project_trust_map(bindings: dict[str, str]) -> str:
    """Fold authored binding file contents into the aggregate-map JSON.

    ``bindings`` maps each ``trust/<id>.v1.json`` path to its content. Delegates
    to the runtime folder so the builder's projection is byte-identical to the
    refresh pipeline's; the committed aggregate is regenerated, never hand-edited.
    """
    import tempfile

    from ..runtime.extension_trust import trust_map_from_bindings

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for path, content in bindings.items():
            _binding_id(path, content)  # surface malformed input as a conflict first
            (root / path.rsplit("/", 1)[-1]).write_text(content, encoding="utf-8")
        try:
            aggregate = trust_map_from_bindings(root)
        except ValueError as exc:
            raise conflict(str(exc)) from exc
    return json.dumps(aggregate, ensure_ascii=True, indent=2) + "\n"


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


def edit_staging(content: str, metadata: Metadata) -> str:
    """Assert the enumerated staging covers this contribution.

    The staging script scans `contributions/` for payload JSON rather than a
    per-contribution list, so integration is a no-op here. It still fails
    closed when the script's enumeration table is missing or a payload path
    falls outside the scanned directories — an unknown layout is a conflict,
    not a silent skip.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError as exc:
        raise conflict("The staging script is not parseable Python.") from exc
    assigned: set[str] = set()
    defined: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            assigned.update(target.id for target in node.targets if isinstance(target, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            assigned.add(node.target.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined.add(node.name)
    if "_CONTRIBUTION_SOURCES" not in assigned or not {"_artifacts", "stage_artifacts"} <= defined:
        raise conflict("The staging script no longer enumerates contribution payloads.")
    for source, _packaged in _artifact_mappings(metadata):
        if not source.startswith(("contributions/extensions/", "contributions/mcp-servers/")):
            # Command sources compile into the native program rather than
            # staging individually; only descriptor payloads are enumerated.
            continue
        name = source.rsplit("/", 1)[-1]
        covered = (
            (source.startswith("contributions/extensions/") and name.startswith("command."))
            or (source.startswith("contributions/mcp-servers/") and name.startswith("mcp."))
        ) and name.endswith(".json")
        if not covered:
            raise conflict("The contribution payload is outside the enumerated staging directories.")
    return content
