"""OpenCode ecosystem adapter."""

from __future__ import annotations

import json
from pathlib import Path

from .types import Ecosystem, NormalizedPackage, PackageCandidate

IGNORED_DIRS = {"node_modules", ".git", ".venv", "venv", "dist", "__pycache__"}


def _iter_files(root: Path, pattern: str) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob(pattern):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file():
            files.append(path)
    return files


def _strip_jsonc(text: str) -> str:
    output: list[str] = []
    in_string = False
    escape = False
    in_line_comment = False
    in_block_comment = False
    index = 0

    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
                output.append(char)
            index += 1
            continue

        if in_block_comment:
            if char == "*" and next_char == "/":
                in_block_comment = False
                index += 2
                continue
            if char == "\n":
                output.append(char)
            index += 1
            continue

        if in_string:
            output.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue

        if char == "/" and next_char == "/":
            in_line_comment = True
            index += 2
            continue

        if char == "/" and next_char == "*":
            in_block_comment = True
            index += 2
            continue

        output.append(char)
        index += 1

    return "".join(output)


def _load_json_or_jsonc(path: Path) -> tuple[dict[str, object], bool, str | None]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}, True, "file-not-found"
    except PermissionError:
        return {}, True, "permission-denied"
    except OSError:
        return {}, True, "read-error"
    if path.suffix == ".jsonc":
        text = _strip_jsonc(text)
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            return payload, False, None
    except json.JSONDecodeError:
        return {}, True, "invalid-json"
    return {}, True, "not-object"


class OpenCodeAdapter:
    """Adapter for OpenCode plugin repositories."""

    ecosystem_id = Ecosystem.OPENCODE

    def detect(self, root: Path) -> list[PackageCandidate]:
        candidates: list[PackageCandidate] = []
        seen_roots: set[Path] = set()
        for config_name in ("opencode.json", "opencode.jsonc"):
            for manifest_path in _iter_files(root, config_name):
                package_root = manifest_path.parent
                if package_root in seen_roots:
                    continue
                seen_roots.add(package_root)
                candidates.append(
                    PackageCandidate(
                        ecosystem=Ecosystem.OPENCODE,
                        package_kind="workspace-bundle",
                        root_path=package_root,
                        manifest_path=manifest_path,
                        detection_reason=f"found {config_name}",
                    )
                )

        for opencode_dir in (path for path in root.rglob(".opencode") if path.is_dir()):
            if any(part in IGNORED_DIRS for part in opencode_dir.parts):
                continue
            package_root = opencode_dir.parent
            if package_root in seen_roots:
                continue
            seen_roots.add(package_root)
            candidates.append(
                PackageCandidate(
                    ecosystem=Ecosystem.OPENCODE,
                    package_kind="workspace-bundle",
                    root_path=package_root,
                    manifest_path=None,
                    detection_reason="found .opencode workspace directory",
                )
            )
        return candidates

    def parse(self, candidate: PackageCandidate) -> NormalizedPackage:
        manifest, parse_error, parse_error_reason = (
            _load_json_or_jsonc(candidate.manifest_path) if candidate.manifest_path else ({}, False, None)
        )
        root = candidate.root_path
        components: dict[str, tuple[str, ...]] = {}
        commands_dir = root / ".opencode" / "commands"
        plugins_dir = root / ".opencode" / "plugins"
        if commands_dir.is_dir():
            components["commands"] = tuple(
                sorted(str(path.relative_to(root)) for path in commands_dir.rglob("*.md") if path.is_file())
            )
        if plugins_dir.is_dir():
            components["plugin_modules"] = tuple(
                sorted(
                    str(path.relative_to(root))
                    for path in plugins_dir.rglob("*")
                    if path.is_file() and path.suffix in {".js", ".ts", ".mjs", ".cjs"}
                )
            )
        mcp_config = manifest.get("mcp")
        if isinstance(mcp_config, dict):
            components["mcp_servers"] = tuple(sorted(str(key) for key in mcp_config))

        return NormalizedPackage(
            ecosystem=Ecosystem.OPENCODE,
            package_kind=candidate.package_kind,
            root_path=root,
            manifest_path=candidate.manifest_path,
            name=manifest.get("name") if isinstance(manifest.get("name"), str) else None,
            version=manifest.get("version") if isinstance(manifest.get("version"), str) else None,
            metadata={
                key: value for key in ("description", "repository") if isinstance((value := manifest.get(key)), str)
            },
            components=components,
            raw_manifest=manifest,
            manifest_parse_error=parse_error,
            manifest_parse_error_reason=parse_error_reason,
        )
