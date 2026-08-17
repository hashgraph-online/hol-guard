"""Kimi Code plugin ecosystem adapter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from ..path_support import is_safe_relative_path
from .base import iter_safe_recursive_dirs, iter_safe_recursive_files
from .types import Ecosystem, NormalizedPackage, PackageCandidate


def _load_manifest(path: Path) -> tuple[dict[str, object], bool, str | None]:
    try:
        payload = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except UnicodeDecodeError:
        return {}, True, "invalid-encoding"
    except FileNotFoundError:
        return {}, True, "file-not-found"
    except PermissionError:
        return {}, True, "permission-denied"
    except json.JSONDecodeError:
        return {}, True, "invalid-json"
    except OSError:
        return {}, True, "read-error"
    manifest = _string_mapping(payload)
    if manifest is None:
        return {}, True, "not-object"
    return manifest, False, None


def _string_mapping(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    mapping = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        return None
    return {cast(str, key): item for key, item in mapping.items()}


def _path_values(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        items = cast(list[object], value)
        return tuple(item for item in items if isinstance(item, str))
    return ()


def _declared_files(root: Path, value: object, pattern: str) -> tuple[str, ...]:
    files: set[str] = set()
    for raw_path in _path_values(value):
        if not is_safe_relative_path(root, raw_path, require_prefix=True, require_exists=True):
            continue
        path = root / raw_path
        if path.is_symlink():
            continue
        if path.is_file():
            if pattern == "*" or path.match(pattern):
                files.add(path.relative_to(root).as_posix())
            continue
        files.update(file.relative_to(root).as_posix() for file in iter_safe_recursive_files(root, path, pattern))
    return tuple(sorted(files))


class KimiAdapter:
    """Adapter for native Kimi Code plugin bundles."""

    ecosystem_id: Ecosystem = Ecosystem.KIMI

    def detect(self, root: Path) -> list[PackageCandidate]:
        candidates: dict[Path, PackageCandidate] = {}
        for manifest_path in iter_safe_recursive_files(root, root, "kimi.plugin.json"):
            package_root = manifest_path.parent
            candidates[package_root] = PackageCandidate(
                ecosystem=Ecosystem.KIMI,
                package_kind="plugin",
                root_path=package_root,
                manifest_path=manifest_path,
                detection_reason="found kimi.plugin.json",
            )
        for manifest_dir in iter_safe_recursive_dirs(root, root, ".kimi-plugin"):
            manifest_path = manifest_dir / "plugin.json"
            package_root = manifest_dir.parent
            if package_root in candidates or manifest_path.is_symlink() or not manifest_path.is_file():
                continue
            if not is_safe_relative_path(root, manifest_path.relative_to(root).as_posix(), require_exists=True):
                continue
            candidates[package_root] = PackageCandidate(
                ecosystem=Ecosystem.KIMI,
                package_kind="plugin",
                root_path=package_root,
                manifest_path=manifest_path,
                detection_reason="found .kimi-plugin/plugin.json",
            )
        return sorted(candidates.values(), key=lambda candidate: str(candidate.root_path))

    def parse(self, candidate: PackageCandidate) -> NormalizedPackage:
        manifest, parse_error, parse_error_reason = (
            _load_manifest(candidate.manifest_path) if candidate.manifest_path else ({}, True, "file-not-found")
        )
        root = candidate.root_path
        components: dict[str, tuple[str, ...]] = {}
        path_components = {
            "skills": (manifest.get("skills"), "*"),
            "agents": (manifest.get("agents"), "*.md"),
            "commands": (manifest.get("commands"), "*.md"),
            "system_prompt": (manifest.get("systemPromptPath"), "*"),
        }
        if manifest.get("skills") is None and (root / "SKILL.md").is_file():
            path_components["skills"] = ("./SKILL.md", "*")
        if manifest.get("agents") is None and (root / "agents").is_dir():
            path_components["agents"] = ("./agents/", "*.md")
        for name, (value, pattern) in path_components.items():
            files = _declared_files(root, value, pattern)
            if files:
                components[name] = files

        mcp_servers = manifest.get("mcpServers")
        mcp_mapping = _string_mapping(mcp_servers)
        if mcp_mapping is not None:
            components["mcp_servers"] = tuple(sorted(mcp_mapping))
            local_files: set[str] = set()
            for server_value in mcp_mapping.values():
                server = _string_mapping(server_value)
                if server is None:
                    continue
                command = server.get("command")
                if isinstance(command, str) and command.startswith("./"):
                    local_files.update(_declared_files(root, command, "*"))
                args = server.get("args")
                if isinstance(args, list):
                    for arg in cast(list[object], args):
                        if isinstance(arg, str) and arg.startswith("./"):
                            local_files.update(_declared_files(root, arg, "*"))
            if local_files:
                components["mcp_files"] = tuple(sorted(local_files))

        raw_name = manifest.get("name")
        raw_version = manifest.get("version")
        return NormalizedPackage(
            ecosystem=Ecosystem.KIMI,
            package_kind=candidate.package_kind,
            root_path=root,
            manifest_path=candidate.manifest_path,
            name=raw_name if isinstance(raw_name, str) else None,
            version=raw_version if isinstance(raw_version, str) else None,
            metadata={
                key: value
                for key in ("description", "homepage", "license")
                if isinstance((value := manifest.get(key)), str)
            },
            components=components,
            raw_manifest=manifest,
            manifest_parse_error=parse_error,
            manifest_parse_error_reason=parse_error_reason,
        )
