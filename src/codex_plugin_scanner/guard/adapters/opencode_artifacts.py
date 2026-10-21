"""OpenCode artifact discovery helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..aibom_detection import native_adapter_detection
from ..models import GuardArtifact
from ..runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall
from .base import HarnessContext, detection_request

CONFIG_FILENAMES = ("opencode.json", "opencode.jsonc")


def config_paths(context: HarnessContext) -> tuple[Path, ...]:
    paths: list[Path] = []
    paths.extend(context.home_dir / ".config" / "opencode" / name for name in CONFIG_FILENAMES)
    configured_path = configured_config_path(context)
    if configured_path is not None:
        paths.append(configured_path)
    if context.workspace_dir is not None:
        paths.extend(context.workspace_dir / name for name in CONFIG_FILENAMES)
    deduped_paths: list[Path] = []
    seen_paths: set[str] = set()
    for path in paths:
        candidate = str(path)
        if candidate in seen_paths:
            continue
        seen_paths.add(candidate)
        deduped_paths.append(path)
    return tuple(deduped_paths)


def configured_config_path(context: HarnessContext) -> Path | None:
    raw_path = os.getenv("OPENCODE_CONFIG")
    if not raw_path:
        return None
    candidate = Path(raw_path).expanduser()
    if candidate.is_absolute():
        return candidate
    if context.workspace_dir is not None:
        return context.workspace_dir / candidate
    return Path.cwd() / candidate


def configured_config_dir(context: HarnessContext) -> Path | None:
    raw_path = os.getenv("OPENCODE_CONFIG_DIR")
    if not raw_path:
        return None
    candidate = Path(raw_path).expanduser()
    if candidate.is_absolute():
        return candidate
    if context.workspace_dir is not None:
        return context.workspace_dir / candidate
    return Path.cwd() / candidate


def native_artifacts(
    context: HarnessContext,
    configs: list[tuple[Path, str, dict[str, object]]],
    *,
    skip_verified_mcp_companions: bool = True,
) -> tuple[list[GuardArtifact], list[str]]:
    """The artifacts and found paths of the given configs plus the command,
    plugin and skill directories, from the resident's `opencode_detect`.

    Each payload travels as JSON text so the resident walks its objects in
    file order.
    """

    config_dir = configured_config_dir(context)
    request = {
        **detection_request("opencode", context),
        "configs": [
            {"path": str(path), "scope": scope, "payload": json.dumps(payload)} for path, scope, payload in configs
        ],
        "skip_verified_mcp_companions": skip_verified_mcp_companions,
        "config_dir": None if config_dir is None else str(config_dir),
    }
    artifacts, found_paths = native_adapter_detection("opencode_detect", request)
    return [enrich_artifact_with_mcp_skill_firewall(artifact) for artifact in artifacts], list(found_paths)


def runtime_config_path(context: HarnessContext) -> Path:
    return context.guard_home / "opencode" / "runtime-config.json"


def runtime_overlay(
    *,
    permission_rules: dict[str, object] | None = None,
    mcp_servers: dict[str, object] | None = None,
) -> dict[str, object]:
    permission: dict[str, object] = {}
    if permission_rules:
        permission.update(permission_rules)
    overlay: dict[str, object] = {
        "$schema": "https://opencode.ai/config.json",
        "permission": permission,
    }
    if mcp_servers:
        overlay["mcp"] = mcp_servers
    return overlay


def _command_parts(server_config: dict[str, object]) -> tuple[str | None, tuple[str, ...]]:
    command_value = server_config.get("command")
    args_value = server_config.get("args")
    if isinstance(command_value, list):
        command_list = [value for value in command_value if isinstance(value, str)]
        if not command_list:
            return (None, ())
        return (command_list[0], tuple(command_list[1:]))
    if isinstance(command_value, str):
        args = tuple(value for value in args_value if isinstance(value, str)) if isinstance(args_value, list) else ()
        return (command_value, args)
    return (None, ())
