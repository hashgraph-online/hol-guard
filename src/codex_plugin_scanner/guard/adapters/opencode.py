"""OpenCode harness adapter."""

from __future__ import annotations

import json
from pathlib import Path

from ...ecosystems.opencode import _load_json_or_jsonc
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available, _run_command_probe

_CONFIG_FILENAMES = ("opencode.json", "opencode.jsonc")
_PLUGIN_SUFFIXES = {".js", ".ts", ".mjs", ".cjs"}
_GLOBAL_SKILL_DIRECTORIES = (
    (".config/opencode/skills", "opencode"),
    (".claude/skills", "claude"),
    (".agents/skills", "agents"),
)
_PROJECT_SKILL_DIRECTORIES = (
    (".opencode/skills", "opencode"),
    (".claude/skills", "claude"),
    (".agents/skills", "agents"),
)


class OpenCodeHarnessAdapter(HarnessAdapter):
    """Discover OpenCode config, commands, plugins, and skills."""

    harness = "opencode"
    executable = "opencode"
    approval_tier = "mixed"
    approval_summary = (
        "Guard evaluates OpenCode skills, MCP servers, commands, and plugins before launch, and the managed "
        "runtime overlay keeps native skill loads on ask."
    )
    fallback_hint = (
        "Use Guard approvals for blocked artifacts and OpenCode's native allow once or allow session flow for "
        "skills."
    )

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        seen_artifact_ids: set[str] = set()
        for config_path in _config_paths(context):
            payload, parse_error, _parse_reason = _load_json_or_jsonc(config_path)
            if parse_error or not payload:
                continue
            _append_found_path(found_paths, config_path)
            scope = self._scope_for(context, config_path)
            _append_config_artifacts(
                artifacts=artifacts,
                seen_artifact_ids=seen_artifact_ids,
                scope=scope,
                config_path=config_path,
                payload=payload,
            )
        _append_directory_artifacts(
            context=context,
            artifacts=artifacts,
            found_paths=found_paths,
            seen_artifact_ids=seen_artifact_ids,
        )
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(self.harness, context)
        runtime_config_path = _runtime_config_path(context)
        runtime_config_path.parent.mkdir(parents=True, exist_ok=True)
        runtime_config_path.write_text(json.dumps(_runtime_overlay(), indent=2) + "\n", encoding="utf-8")
        notes = [
            *list(shim_manifest.get("notes", [])),
            "Guard added an OpenCode runtime overlay that keeps native skill loads on ask when you launch "
            "through Guard.",
        ]
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(runtime_config_path),
            **shim_manifest,
            "runtime_config_path": str(runtime_config_path),
            "runtime_env_var": "OPENCODE_CONFIG_CONTENT",
            "notes": notes,
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(self.harness, context)
        notes = [
            *list(shim_manifest.get("notes", [])),
            "Guard leaves the OpenCode runtime overlay on disk for auditability, but it is ignored unless you "
            "launch through Guard.",
        ]
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(_runtime_config_path(context)),
            **shim_manifest,
            "runtime_config_path": str(_runtime_config_path(context)),
            "runtime_env_var": "OPENCODE_CONFIG_CONTENT",
            "notes": notes,
        }

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        runtime_config_path = _runtime_config_path(context)
        if not runtime_config_path.exists():
            return {}
        try:
            runtime_config = runtime_config_path.read_text(encoding="utf-8")
        except OSError:
            return {}
        return {"OPENCODE_CONFIG_CONTENT": runtime_config}

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        if context.workspace_dir is not None and passthrough_args:
            return [self.executable, "run", "--dir", str(context.workspace_dir), *passthrough_args]
        if context.workspace_dir is not None:
            return [self.executable, str(context.workspace_dir)]
        if passthrough_args:
            return [self.executable, "run", *passthrough_args]
        return [self.executable]

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        if not _command_available(self.executable):
            return None
        return {
            "paths": _run_command_probe([self.executable, "debug", "paths"]),
            "config": _run_command_probe([self.executable, "debug", "config"]),
        }


def _config_paths(context: HarnessContext) -> tuple[Path, ...]:
    config_paths = [context.home_dir / ".config" / "opencode" / name for name in _CONFIG_FILENAMES]
    if context.workspace_dir is not None:
        config_paths.extend(context.workspace_dir / name for name in _CONFIG_FILENAMES)
    return tuple(config_paths)


def _append_config_artifacts(
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
            },
        )
        _append_artifact(artifacts, seen_artifact_ids, artifact)


def _append_plugin_artifacts(
    *,
    artifacts: list[GuardArtifact],
    seen_artifact_ids: set[str],
    scope: str,
    config_path: Path,
    payload: dict[str, object],
) -> None:
    plugin_config = payload.get("plugin")
    if not isinstance(plugin_config, list):
        return
    for item in plugin_config:
        plugin_name: str | None = None
        plugin_options: dict[str, object] = {}
        if isinstance(item, str):
            plugin_name = item
        elif (
            isinstance(item, list)
            and len(item) == 2
            and isinstance(item[0], str)
            and isinstance(item[1], dict)
        ):
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
        _append_artifact(artifacts, seen_artifact_ids, artifact)


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
        artifact = GuardArtifact(
            artifact_id=f"opencode:{scope}:config-command:{name}",
            name=name,
            harness="opencode",
            artifact_type="command",
            source_scope=scope,
            config_path=str(config_path),
            metadata=metadata,
        )
        _append_artifact(artifacts, seen_artifact_ids, artifact)


def _append_directory_artifacts(
    *,
    context: HarnessContext,
    artifacts: list[GuardArtifact],
    found_paths: list[str],
    seen_artifact_ids: set[str],
) -> None:
    directory_specs: list[tuple[Path, str, str]] = [
        (context.home_dir / ".config" / "opencode" / "commands", "global", "command"),
        (context.home_dir / ".config" / "opencode" / "plugins", "global", "plugin-file"),
    ]
    if context.workspace_dir is not None:
        directory_specs.extend(
            [
                (context.workspace_dir / ".opencode" / "commands", "project", "command"),
                (context.workspace_dir / ".opencode" / "plugins", "project", "plugin-file"),
            ]
        )
    for directory, scope, artifact_kind in directory_specs:
        if not directory.is_dir():
            continue
        pattern = "*.md" if artifact_kind == "command" else "*"
        iterator = directory.rglob(pattern)
        for path in sorted(iterator):
            if not path.is_file():
                continue
            if artifact_kind == "plugin-file" and path.suffix not in _PLUGIN_SUFFIXES:
                continue
            _append_found_path(found_paths, path)
            artifact = GuardArtifact(
                artifact_id=f"opencode:{scope}:{artifact_kind}:{path.stem}",
                name=path.stem,
                harness="opencode",
                artifact_type="plugin" if artifact_kind == "plugin-file" else "command",
                source_scope=scope,
                config_path=str(path),
            )
            _append_artifact(artifacts, seen_artifact_ids, artifact)
    for skill_root, source_kind in _skill_roots(context):
        if not skill_root.is_dir():
            continue
        scope = (
            "project"
            if context.workspace_dir is not None and skill_root.is_relative_to(context.workspace_dir)
            else "global"
        )
        for skill_path in sorted(skill_root.rglob("SKILL.md")):
            if not skill_path.is_file():
                continue
            _append_found_path(found_paths, skill_path)
            artifact = GuardArtifact(
                artifact_id=f"opencode:{scope}:skill:{source_kind}:{skill_path.parent.name}",
                name=skill_path.parent.name,
                harness="opencode",
                artifact_type="skill",
                source_scope=scope,
                config_path=str(skill_path),
                metadata={"skill_source": source_kind},
            )
            _append_artifact(artifacts, seen_artifact_ids, artifact)


def _skill_roots(context: HarnessContext) -> tuple[tuple[Path, str], ...]:
    roots = [
        (context.home_dir / Path(relative_path), source_kind)
        for relative_path, source_kind in _GLOBAL_SKILL_DIRECTORIES
    ]
    if context.workspace_dir is not None:
        roots.extend(
            (context.workspace_dir / Path(relative_path), source_kind)
            for relative_path, source_kind in _PROJECT_SKILL_DIRECTORIES
        )
    return tuple(roots)


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


def _append_artifact(
    artifacts: list[GuardArtifact],
    seen_artifact_ids: set[str],
    artifact: GuardArtifact,
) -> None:
    if artifact.artifact_id in seen_artifact_ids:
        return
    seen_artifact_ids.add(artifact.artifact_id)
    artifacts.append(artifact)


def _append_found_path(found_paths: list[str], path: Path) -> None:
    candidate = str(path)
    if candidate not in found_paths:
        found_paths.append(candidate)


def _publisher_from_package(package_name: str) -> str | None:
    if package_name.startswith("@") and "/" in package_name:
        return package_name.split("/", 1)[0][1:]
    return None


def _runtime_config_path(context: HarnessContext) -> Path:
    return context.guard_home / "opencode" / "runtime-config.json"


def _runtime_overlay() -> dict[str, object]:
    return {
        "$schema": "https://opencode.ai/config.json",
        "permission": {
            "skill": {
                "*": "ask",
            }
        },
    }


__all__ = ["OpenCodeHarnessAdapter"]
