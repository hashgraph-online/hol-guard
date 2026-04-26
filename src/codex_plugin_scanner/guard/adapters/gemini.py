"""Gemini harness adapter."""

from __future__ import annotations

from pathlib import Path

from ..models import GuardArtifact, HarnessDetection
from .base import HarnessAdapter, HarnessContext, _command_available, _json_payload


class GeminiHarnessAdapter(HarnessAdapter):
    """Discover Gemini CLI settings, extensions, hooks, skills, and MCP definitions."""

    harness = "gemini"
    executable = "gemini"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard scans Gemini settings, extensions, hooks, skills, and MCP registrations "
        "before launch and sends blocked changes to the local approval center."
    )
    fallback_hint = "Gemini gets preflight approval through Guard until it exposes a richer native approval surface."

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    @staticmethod
    def _append_found_path(found_paths: list[str], path: Path) -> None:
        candidate = str(path)
        if candidate not in found_paths:
            found_paths.append(candidate)

    @staticmethod
    def _string_args(server_config: dict[str, object]) -> tuple[str, ...]:
        raw_args = server_config.get("args")
        if not isinstance(raw_args, list):
            return ()
        return tuple(str(value) for value in raw_args if isinstance(value, str))

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".gemini" / "settings.json"
        return context.home_dir / ".gemini" / "settings.json"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        scope_specs = [
            (
                context.home_dir / ".gemini" / "settings.json",
                context.home_dir / ".gemini" / "extensions",
                context.home_dir / ".gemini" / "skills",
            )
        ]
        if context.workspace_dir is not None:
            scope_specs.append(
                (
                    context.workspace_dir / ".gemini" / "settings.json",
                    context.workspace_dir / ".gemini" / "extensions",
                    context.workspace_dir / ".gemini" / "skills",
                )
            )
        for settings_path, extension_root, skill_root in scope_specs:
            scope = self._scope_for(context, settings_path)
            self._append_extension_artifacts(artifacts, found_paths, extension_root, scope)
            payload = _json_payload(settings_path)
            if payload:
                self._append_found_path(found_paths, settings_path)
                self._append_settings_artifacts(artifacts, settings_path, payload, scope)
            self._append_skill_artifacts(artifacts, found_paths, skill_root, scope)
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )

    def _append_extension_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        extension_root: Path,
        scope: str,
    ) -> None:
        if not extension_root.is_dir():
            return
        for manifest_path in sorted(extension_root.glob("*/gemini-extension.json")):
            payload = _json_payload(manifest_path)
            if not payload:
                continue
            self._append_found_path(found_paths, manifest_path)
            raw_name = payload.get("name")
            extension_name = raw_name if isinstance(raw_name, str) else manifest_path.parent.name
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"gemini:{scope}:{extension_name}",
                    name=extension_name,
                    harness=self.harness,
                    artifact_type="extension",
                    source_scope=scope,
                    config_path=str(manifest_path),
                    publisher=payload.get("publisher") if isinstance(payload.get("publisher"), str) else None,
                    metadata={"context_file": payload.get("contextFileName")},
                )
            )
            mcp_servers = payload.get("mcpServers")
            if not isinstance(mcp_servers, dict):
                continue
            for server_name, server_config in mcp_servers.items():
                if not isinstance(server_name, str) or not isinstance(server_config, dict):
                    continue
                command = server_config.get("command")
                url = server_config.get("url")
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"gemini:{scope}:{extension_name}:{server_name}",
                        name=server_name,
                        harness=self.harness,
                        artifact_type="mcp_server",
                        source_scope=scope,
                        config_path=str(manifest_path),
                        command=command if isinstance(command, str) else None,
                        args=self._string_args(server_config),
                        url=url if isinstance(url, str) else None,
                        transport="http" if isinstance(url, str) else "stdio",
                    )
                )

    def _append_settings_artifacts(
        self,
        artifacts: list[GuardArtifact],
        settings_path: Path,
        payload: dict[str, object],
        scope: str,
    ) -> None:
        mcp_servers = payload.get("mcpServers")
        if isinstance(mcp_servers, dict):
            for server_name, server_config in mcp_servers.items():
                if not isinstance(server_name, str) or not isinstance(server_config, dict):
                    continue
                command = server_config.get("command")
                url = server_config.get("url")
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"gemini:{scope}:mcp:{server_name}",
                        name=server_name,
                        harness=self.harness,
                        artifact_type="mcp_server",
                        source_scope=scope,
                        config_path=str(settings_path),
                        command=command if isinstance(command, str) else None,
                        args=self._string_args(server_config),
                        url=url if isinstance(url, str) else None,
                        transport="http" if isinstance(url, str) else "stdio",
                    )
                )
        hooks = payload.get("hooks")
        if not isinstance(hooks, dict):
            return
        for hook_name, hook_entries in hooks.items():
            if not isinstance(hook_name, str) or not isinstance(hook_entries, list):
                continue
            for index, entry in enumerate(hook_entries):
                if not isinstance(entry, dict):
                    continue
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"gemini:{scope}:hook:{hook_name.lower()}:{index}",
                        name=hook_name,
                        harness=self.harness,
                        artifact_type="hook",
                        source_scope=scope,
                        config_path=str(settings_path),
                        command=self._hook_command(entry),
                        metadata={"hook_config": entry},
                    )
                )

    def _append_skill_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        skill_root: Path,
        scope: str,
    ) -> None:
        if not skill_root.is_dir():
            return
        for skill_path in sorted(skill_root.rglob("SKILL.md")):
            self._append_found_path(found_paths, skill_path)
            relative_id = f"skills/{skill_path.parent.relative_to(skill_root).as_posix()}"
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"gemini:{scope}:skill:{relative_id}",
                    name=relative_id,
                    harness=self.harness,
                    artifact_type="skill",
                    source_scope=scope,
                    config_path=str(skill_path),
                )
            )

    @staticmethod
    def _hook_command(entry: dict[str, object]) -> str | None:
        commands: list[str] = []
        direct_command = entry.get("command")
        if isinstance(direct_command, str):
            commands.append(direct_command)
        nested_hooks = entry.get("hooks")
        if isinstance(nested_hooks, list):
            for nested_entry in nested_hooks:
                if not isinstance(nested_entry, dict):
                    continue
                command = nested_entry.get("command")
                if isinstance(command, str):
                    commands.append(command)
        if not commands:
            return None
        if len(commands) == 1:
            return commands[0]
        return "\n".join(commands)
