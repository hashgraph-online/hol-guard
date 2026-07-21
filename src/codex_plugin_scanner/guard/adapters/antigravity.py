"""Antigravity harness adapter."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import GuardArtifact, HarnessDetection
from ..skill_directory_identity import (
    discover_skill_documents,
    incomplete_skill_directory_identity,
    inspect_skill_directory,
    skill_directory_identity_metadata,
)
from .base import HarnessAdapter, HarnessContext, _command_available, _json_payload


class AntigravityHarnessAdapter(HarnessAdapter):
    """Discover Antigravity extensions plus Antigravity-owned MCP and skill roots."""

    harness = "antigravity"
    executable = "antigravity"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard scans Antigravity extensions, MCP registrations, and skills before launch "
        "and routes review through the local approval center."
    )
    fallback_hint = (
        "Use Guard review for new Antigravity artifacts before launch, then hand off to the local editor normally."
    )

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
    def _settings_paths(context: HarnessContext) -> list[Path]:
        return [
            context.home_dir / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json",
            context.home_dir / ".config" / "Antigravity" / "User" / "settings.json",
            context.home_dir / "AppData" / "Roaming" / "Antigravity" / "User" / "settings.json",
        ]

    @staticmethod
    def _contains_antigravity_settings(payload: dict[str, object]) -> bool:
        return any(isinstance(key, str) and key.startswith("antigravity.") for key in payload)

    @staticmethod
    def _string_args(server_config: dict[str, object]) -> tuple[str, ...]:
        raw_args = server_config.get("args")
        if not isinstance(raw_args, list):
            return ()
        return tuple(str(value) for value in raw_args if isinstance(value, str))

    @staticmethod
    def _mcp_source(config_path: Path) -> str:
        if config_path.name == "mcp_config.json":
            return "bridge"
        normalized_path = config_path.as_posix().lower()
        if normalized_path.endswith("/library/application support/antigravity/user/settings.json"):
            return "settings:macos-user"
        if normalized_path.endswith("/.config/antigravity/user/settings.json"):
            return "settings:xdg-user"
        if normalized_path.endswith("/appdata/roaming/antigravity/user/settings.json"):
            return "settings:windows-user"
        if normalized_path.endswith("/.vscode/settings.json"):
            return "settings:workspace-vscode"
        token_parts = []
        for part in config_path.parts[-4:]:
            normalized_part = "".join(character if character.isalnum() else "-" for character in part.lower()).strip(
                "-"
            )
            if normalized_part:
                token_parts.append(normalized_part)
        return f"settings:{'-'.join(token_parts)}"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        warnings: list[str] = []

        extension_index = context.home_dir / ".antigravity" / "extensions" / "extensions.json"
        extension_payload = self._extension_index_payload(extension_index)
        if extension_payload:
            self._append_found_path(found_paths, extension_index)
            artifacts.extend(self._extension_artifacts(extension_payload, found_paths))

        antigravity_config_paths = [context.home_dir / ".gemini" / "antigravity" / "mcp_config.json"]
        if context.workspace_dir is not None:
            antigravity_config_paths.append(context.workspace_dir / ".gemini" / "antigravity" / "mcp_config.json")
        for config_path in antigravity_config_paths:
            payload = _json_payload(config_path)
            if not payload:
                continue
            self._append_found_path(found_paths, config_path)
            scope = self._scope_for(context, config_path)
            self._append_mcp_artifacts(artifacts, config_path, payload, scope)

        skill_roots = [(context.home_dir / ".gemini" / "antigravity" / "skills", context.home_dir)]
        if context.workspace_dir is not None:
            skill_roots.append(
                (
                    context.workspace_dir / ".gemini" / "antigravity" / "skills",
                    context.workspace_dir,
                )
            )
        for skill_root, identity_scope_root in skill_roots:
            scope = self._scope_for(context, skill_root)
            discovery = discover_skill_documents(skill_root)
            for skill_path in discovery.documents:
                self._append_found_path(found_paths, skill_path)
                relative_id = f"skills/{skill_path.parent.relative_to(skill_root).as_posix()}"
                identity = inspect_skill_directory(skill_path, scope_root=identity_scope_root)
                metadata = skill_directory_identity_metadata(identity, version_label=relative_id)
                if identity.status != "complete":
                    warnings.append(
                        f"Antigravity {scope} skill directory identity is incomplete; approval reuse is disabled."
                    )
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"antigravity:{scope}:skill:{relative_id}",
                        name=relative_id,
                        harness=self.harness,
                        artifact_type="skill",
                        source_scope=scope,
                        config_path=str(skill_path),
                        metadata=metadata,
                    )
                )
            for issue in discovery.issues:
                self._append_found_path(found_paths, issue.path)
                relative_id = f"skills/.guard-discovery/{issue.issue_id}"
                identity = incomplete_skill_directory_identity(issue.failure_reason)
                metadata = skill_directory_identity_metadata(identity, version_label=relative_id)
                warnings.append(f"Antigravity {scope} skill discovery is incomplete; approval reuse is disabled.")
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"antigravity:{scope}:skill-discovery:{issue.issue_id}",
                        name="Incomplete Antigravity skill discovery",
                        harness=self.harness,
                        artifact_type="skill",
                        source_scope=scope,
                        config_path=str(issue.path),
                        metadata=metadata,
                    )
                )

        settings_paths = self._settings_paths(context)
        owned_settings_paths = set(settings_paths)
        if context.workspace_dir is not None:
            settings_paths.append(context.workspace_dir / ".vscode" / "settings.json")
        has_antigravity_signal = bool(found_paths)
        for settings_path in settings_paths:
            payload = _json_payload(settings_path)
            if not payload:
                continue
            owns_settings = (
                settings_path in owned_settings_paths
                or self._contains_antigravity_settings(payload)
                or has_antigravity_signal
            )
            if not owns_settings:
                continue
            scope = self._scope_for(context, settings_path)
            before_artifact_count = len(artifacts)
            self._append_mcp_artifacts(artifacts, settings_path, payload, scope)
            if len(artifacts) > before_artifact_count or owns_settings:
                self._append_found_path(found_paths, settings_path)
            has_antigravity_signal = True

        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=tuple(dict.fromkeys(warnings)),
        )

    @staticmethod
    def _extension_index_payload(path: Path) -> list[object]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return payload if isinstance(payload, list) else []

    def _append_mcp_artifacts(
        self,
        artifacts: list[GuardArtifact],
        config_path: Path,
        payload: dict[str, object],
        scope: str,
    ) -> None:
        mcp_servers = payload.get("mcpServers")
        if not isinstance(mcp_servers, dict):
            return
        for name, server_config in mcp_servers.items():
            if not isinstance(name, str) or not isinstance(server_config, dict):
                continue
            command = server_config.get("command")
            url = server_config.get("url")
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"antigravity:{scope}:mcp:{self._mcp_source(config_path)}:{name}",
                    name=name,
                    harness=self.harness,
                    artifact_type="mcp_server",
                    source_scope=scope,
                    config_path=str(config_path),
                    command=command if isinstance(command, str) else None,
                    args=self._string_args(server_config),
                    url=url if isinstance(url, str) else None,
                    transport="http" if isinstance(url, str) else "stdio",
                )
            )

    def _extension_artifacts(
        self,
        payload: list[object],
        found_paths: list[str],
    ) -> list[GuardArtifact]:
        artifacts: list[GuardArtifact] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            identifier = item.get("identifier")
            location = item.get("location")
            metadata = item.get("metadata")
            if not isinstance(identifier, dict) or not isinstance(location, dict):
                continue
            extension_id = identifier.get("id")
            location_path = location.get("path")
            if not isinstance(extension_id, str) or not isinstance(location_path, str):
                continue
            manifest_path = Path(location_path) / "package.json"
            manifest_payload = _json_payload(manifest_path)
            if manifest_payload:
                self._append_found_path(found_paths, manifest_path)
            publisher = (
                manifest_payload.get("publisher")
                if manifest_payload is not None and isinstance(manifest_payload.get("publisher"), str)
                else None
            )
            if publisher is None and isinstance(metadata, dict):
                publisher_display_name = metadata.get("publisherDisplayName")
                if isinstance(publisher_display_name, str):
                    publisher = publisher_display_name
            display_name = (
                manifest_payload.get("displayName")
                if manifest_payload is not None and isinstance(manifest_payload.get("displayName"), str)
                else None
            )
            manifest_description = (
                manifest_payload.get("description")
                if manifest_payload is not None and isinstance(manifest_payload.get("description"), str)
                else None
            )
            resolved_name = display_name if isinstance(display_name, str) and display_name else extension_id
            resolved_config_path = manifest_path if manifest_payload is not None else Path(location_path)
            resolved_publisher = publisher if isinstance(publisher, str) else None
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"antigravity:global:{extension_id}",
                    name=resolved_name,
                    harness=self.harness,
                    artifact_type="extension",
                    source_scope="global",
                    config_path=str(resolved_config_path),
                    publisher=resolved_publisher,
                    metadata={
                        "display_name": display_name,
                        "description": manifest_description,
                        "extension_id": extension_id,
                    },
                )
            )
        return artifacts
