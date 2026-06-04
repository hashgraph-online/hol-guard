"""OpenCode artifact discovery helpers."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from pathlib import Path

from ..models import GuardArtifact
from .base import HarnessContext

CONFIG_FILENAMES = ("opencode.json", "opencode.jsonc")
PLUGIN_SUFFIXES = {".js", ".ts", ".mjs", ".cjs"}
GLOBAL_SKILL_DIRECTORIES = (
    (".config/opencode/skills", "opencode"),
    (".config/opencode/skill", "opencode"),
    (".claude/skills", "claude"),
    (".agents/skills", "agents"),
)
PROJECT_SKILL_DIRECTORIES = (
    (".opencode/skills", "opencode"),
    (".opencode/skill", "opencode"),
    (".claude/skills", "claude"),
    (".agents/skills", "agents"),
)


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


def append_config_artifacts(
    *,
    artifacts: list[GuardArtifact],
    seen_artifact_ids: set[str],
    scope: str,
    config_path: Path,
    payload: dict[str, object],
) -> None:
    _append_mcp_artifacts(
        artifacts=artifacts,
        seen_artifact_ids=seen_artifact_ids,
        scope=scope,
        config_path=config_path,
        payload=payload,
    )
    _append_plugin_artifacts(
        artifacts=artifacts,
        seen_artifact_ids=seen_artifact_ids,
        scope=scope,
        config_path=config_path,
        payload=payload,
    )
    _append_config_command_artifacts(
        artifacts=artifacts,
        seen_artifact_ids=seen_artifact_ids,
        scope=scope,
        config_path=config_path,
        payload=payload,
    )


def append_directory_artifacts(
    *,
    context: HarnessContext,
    artifacts: list[GuardArtifact],
    found_paths: list[str],
    seen_artifact_ids: set[str],
) -> None:
    directory_specs: list[tuple[Path, str, str]] = [
        (context.home_dir / ".config" / "opencode" / "commands", "global", "command"),
        (context.home_dir / ".config" / "opencode" / "plugins", "global", "plugin-file"),
        (context.home_dir / ".config" / "opencode" / "plugin", "global", "plugin-file"),
    ]
    if context.workspace_dir is not None:
        directory_specs.extend(
            [
                (context.workspace_dir / ".opencode" / "commands", "project", "command"),
                (context.workspace_dir / ".opencode" / "plugins", "project", "plugin-file"),
                (context.workspace_dir / ".opencode" / "plugin", "project", "plugin-file"),
            ]
        )
    configured_dir = configured_config_dir(context)
    if configured_dir is not None:
        scope = (
            "project"
            if context.workspace_dir is not None and configured_dir.is_relative_to(context.workspace_dir)
            else "global"
        )
        directory_specs.extend(
            [
                (configured_dir / "commands", scope, "command"),
                (configured_dir / "plugins", scope, "plugin-file"),
                (configured_dir / "plugin", scope, "plugin-file"),
            ]
        )
    for directory, scope, artifact_kind in directory_specs:
        if not directory.is_dir():
            continue
        allowed_suffixes = None if artifact_kind == "command" else PLUGIN_SUFFIXES
        exact_name = None if artifact_kind == "plugin-file" else "*.md"
        for path in _iter_directory_files(directory, allowed_suffixes=allowed_suffixes, exact_name=exact_name):
            append_found_path(found_paths, path)
            relative_id = _relative_artifact_id(path, directory, strip_suffix=artifact_kind == "command")
            artifact_name = relative_id if artifact_kind == "command" else f"{directory.name}/{relative_id}"
            artifact = GuardArtifact(
                artifact_id=f"opencode:{scope}:{artifact_kind}:{artifact_name}",
                name=artifact_name,
                harness="opencode",
                artifact_type="plugin" if artifact_kind == "plugin-file" else "command",
                source_scope=scope,
                config_path=str(path),
                metadata=_file_metadata(path),
            )
            append_artifact(artifacts, seen_artifact_ids, artifact)
    for skill_root, source_kind in skill_roots(context):
        if not skill_root.is_dir():
            continue
        scope = (
            "project"
            if context.workspace_dir is not None and skill_root.is_relative_to(context.workspace_dir)
            else "global"
        )
        for skill_path in _iter_directory_files(skill_root, exact_name="SKILL.md"):
            append_found_path(found_paths, skill_path)
            relative_id = f"{skill_root.name}/{skill_path.parent.relative_to(skill_root).as_posix()}"
            artifact = GuardArtifact(
                artifact_id=f"opencode:{scope}:skill:{source_kind}:{relative_id}",
                name=relative_id,
                harness="opencode",
                artifact_type="skill",
                source_scope=scope,
                config_path=str(skill_path),
                metadata={"skill_source": source_kind, **_file_metadata(skill_path)},
            )
            append_artifact(artifacts, seen_artifact_ids, artifact)


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


def append_artifact(
    artifacts: list[GuardArtifact],
    seen_artifact_ids: set[str],
    artifact: GuardArtifact,
) -> None:
    if artifact.artifact_id in seen_artifact_ids:
        for index, existing_artifact in enumerate(artifacts):
            if existing_artifact.artifact_id == artifact.artifact_id:
                artifacts[index] = artifact
                return
    seen_artifact_ids.add(artifact.artifact_id)
    artifacts.append(artifact)


def append_found_path(found_paths: list[str], path: Path) -> None:
    candidate = str(path)
    if candidate not in found_paths:
        found_paths.append(candidate)


def skill_roots(context: HarnessContext) -> tuple[tuple[Path, str], ...]:
    roots = [
        (context.home_dir / Path(relative_path), source_kind) for relative_path, source_kind in GLOBAL_SKILL_DIRECTORIES
    ]
    if context.workspace_dir is not None:
        roots.extend(
            (context.workspace_dir / Path(relative_path), source_kind)
            for relative_path, source_kind in PROJECT_SKILL_DIRECTORIES
        )
    return tuple(roots)


def _append_mcp_artifacts(
    *,
    artifacts: list[GuardArtifact],
    seen_artifact_ids: set[str],
    scope: str,
    config_path: Path,
    payload: dict[str, object],
) -> None:
    mcp_config = payload.get("mcp")
    if not isinstance(mcp_config, dict):
        return
    for name, server_config in mcp_config.items():
        if not isinstance(name, str) or not isinstance(server_config, dict):
            continue
        command, args = _command_parts(server_config)
        transport = server_config.get("type") if isinstance(server_config.get("type"), str) else None
        url = server_config.get("url") if isinstance(server_config.get("url"), str) else None
        environment = server_config.get("environment")
        artifact = GuardArtifact(
            artifact_id=f"opencode:{scope}:{name}",
            name=name,
            harness="opencode",
            artifact_type="mcp_server",
            source_scope=scope,
            config_path=str(config_path),
            command=command,
            args=args,
            url=url,
            transport=transport or ("remote" if url is not None else "stdio"),
            metadata={
                "enabled": bool(server_config.get("enabled", True)),
                "env": {
                    str(key): str(value)
                    for key, value in environment.items()
                    if isinstance(key, str) and isinstance(value, str)
                }
                if isinstance(environment, dict)
                else {},
            },
        )
        append_artifact(artifacts, seen_artifact_ids, artifact)


def _append_plugin_artifacts(
    *,
    artifacts: list[GuardArtifact],
    seen_artifact_ids: set[str],
    scope: str,
    config_path: Path,
    payload: dict[str, object],
) -> None:
    for item in _plugin_items(payload):
        plugin_name: str | None = None
        plugin_options: dict[str, object] = {}
        if isinstance(item, str):
            plugin_name = item
        elif isinstance(item, list) and len(item) == 2 and isinstance(item[0], str) and isinstance(item[1], dict):
            plugin_name = item[0]
            plugin_options = item[1]
        if plugin_name is None:
            continue
        artifact = GuardArtifact(
            artifact_id=f"opencode:{scope}:plugin:{plugin_name}",
            name=plugin_name,
            harness="opencode",
            artifact_type="plugin",
            source_scope=scope,
            config_path=str(config_path),
            publisher=_publisher_from_package(plugin_name),
            metadata=plugin_options,
        )
        append_artifact(artifacts, seen_artifact_ids, artifact)


def _append_config_command_artifacts(
    *,
    artifacts: list[GuardArtifact],
    seen_artifact_ids: set[str],
    scope: str,
    config_path: Path,
    payload: dict[str, object],
) -> None:
    command_config = payload.get("command")
    if not isinstance(command_config, dict):
        return
    for name, command_payload in command_config.items():
        if not isinstance(name, str) or not isinstance(command_payload, dict):
            continue
        template = command_payload.get("template")
        if not isinstance(template, str) or not template.strip():
            continue
        metadata = {
            key: value
            for key in ("description", "agent", "model", "subtask")
            if (value := command_payload.get(key)) is not None
        }
        metadata["template"] = template
        artifact = GuardArtifact(
            artifact_id=f"opencode:{scope}:config-command:{name}",
            name=name,
            harness="opencode",
            artifact_type="command",
            source_scope=scope,
            config_path=str(config_path),
            metadata=metadata,
        )
        append_artifact(artifacts, seen_artifact_ids, artifact)


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


def _publisher_from_package(package_name: str) -> str | None:
    if package_name.startswith("@") and "/" in package_name:
        return package_name.split("/", 1)[0][1:]
    return None


def _plugin_items(payload: dict[str, object]) -> Iterator[object]:
    for key in ("plugins", "plugin"):
        plugin_config = payload.get(key)
        if not isinstance(plugin_config, list):
            continue
        yield from plugin_config


def _file_metadata(path: Path) -> dict[str, object]:
    try:
        return {"content_digest": _file_digest(path)}
    except OSError:
        return {"content_digest_unavailable": True}


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _iter_directory_files(
    directory: Path,
    *,
    allowed_suffixes: set[str] | None = None,
    exact_name: str | None = None,
) -> Iterator[Path]:
    for root, dirnames, filenames in os.walk(directory):
        dirnames.sort()
        for filename in sorted(filenames):
            path = Path(root) / filename
            if exact_name == "*.md" and path.suffix != ".md":
                continue
            if exact_name is not None and exact_name != "*.md" and filename != exact_name:
                continue
            if allowed_suffixes is not None and path.suffix not in allowed_suffixes:
                continue
            yield path


def _relative_artifact_id(path: Path, root: Path, *, strip_suffix: bool) -> str:
    relative_path = path.relative_to(root)
    return (relative_path.with_suffix("") if strip_suffix else relative_path).as_posix()
