"""Gemini harness adapter."""

from __future__ import annotations

from ..models import GuardArtifact, HarnessDetection
from .base import HarnessAdapter, HarnessContext, _command_available, _json_payload


class GeminiHarnessAdapter(HarnessAdapter):
    """Discover Gemini extensions and local command definitions."""

    harness = "gemini"
    executable = "gemini"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard scans Gemini extensions before launch and sends blocked changes to the local approval center."
    )
    fallback_hint = "Gemini gets preflight approval through Guard until it exposes a richer native approval surface."

    @staticmethod
    def _scope_for(context: HarnessContext, path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        extension_roots = [context.home_dir / ".gemini" / "extensions"]
        if context.workspace_dir is not None:
            extension_roots.append(context.workspace_dir / ".gemini" / "extensions")
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        for extension_root in extension_roots:
            if not extension_root.is_dir():
                continue
            for manifest_path in sorted(extension_root.glob("*/gemini-extension.json")):
                payload = _json_payload(manifest_path)
                if not payload:
                    continue
                found_paths.append(str(manifest_path))
                scope = self._scope_for(context, manifest_path)
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
                if isinstance(mcp_servers, dict):
                    for server_name, server_config in mcp_servers.items():
                        if not isinstance(server_name, str) or not isinstance(server_config, dict):
                            continue
                        command = server_config.get("command")
                        artifacts.append(
                            GuardArtifact(
                                artifact_id=f"gemini:{scope}:{extension_name}:{server_name}",
                                name=server_name,
                                harness=self.harness,
                                artifact_type="mcp_server",
                                source_scope=scope,
                                config_path=str(manifest_path),
                                command=command if isinstance(command, str) else None,
                                args=tuple(
                                    str(value) for value in server_config.get("args", []) if isinstance(value, str)
                                ),
                                transport="stdio",
                            )
                        )
        fallback_mcp_paths = sorted((context.home_dir / ".gemini").glob("*/mcp_config.json"))
        for config_path in fallback_mcp_paths:
            payload = _json_payload(config_path)
            if not payload:
                continue
            found_paths.append(str(config_path))
            mcp_servers = payload.get("mcpServers")
            if isinstance(mcp_servers, dict):
                for server_name, server_config in mcp_servers.items():
                    if not isinstance(server_name, str) or not isinstance(server_config, dict):
                        continue
                    command = server_config.get("command")
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"gemini:global:mcp:{server_name}",
                            name=server_name,
                            harness=self.harness,
                            artifact_type="mcp_server",
                            source_scope="global",
                            config_path=str(config_path),
                            command=command if isinstance(command, str) else None,
                            args=tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str)),
                            transport="stdio",
                        )
                    )
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )
