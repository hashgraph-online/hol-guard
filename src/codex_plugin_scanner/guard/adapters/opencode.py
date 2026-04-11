"""OpenCode harness adapter."""

from __future__ import annotations

from ...ecosystems.opencode import _load_json_or_jsonc
from ..models import GuardArtifact, HarnessDetection
from .base import HarnessAdapter, HarnessContext, _command_available


class OpenCodeHarnessAdapter(HarnessAdapter):
    """Discover OpenCode config and workspace plugins."""

    harness = "opencode"
    executable = "opencode"
    approval_tier = "native-harness"
    approval_summary = (
        "OpenCode already has tool permissions, so Guard authors policy and provenance rules before launch."
    )
    fallback_hint = "Use Guard for artifact-level trust and keep OpenCode's native allow or deny model intact."

    @staticmethod
    def _scope_for(context: HarnessContext, path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_paths = [context.home_dir / ".config" / "opencode" / "opencode.json"]
        if context.workspace_dir is not None:
            config_paths.extend((context.workspace_dir / "opencode.json", context.workspace_dir / "opencode.jsonc"))
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        for config_path in config_paths:
            payload, parse_error, _parse_reason = _load_json_or_jsonc(config_path)
            if parse_error:
                payload = {}
            if not payload:
                continue
            found_paths.append(str(config_path))
            scope = self._scope_for(context, config_path)
            mcp_config = payload.get("mcp")
            if isinstance(mcp_config, dict):
                for name, server_config in mcp_config.items():
                    if not isinstance(name, str) or not isinstance(server_config, dict):
                        continue
                    command = server_config.get("command")
                    command_list = command if isinstance(command, list) else []
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"opencode:{scope}:{name}",
                            name=name,
                            harness=self.harness,
                            artifact_type="mcp_server",
                            source_scope=scope,
                            config_path=str(config_path),
                            command=command_list[0] if command_list and isinstance(command_list[0], str) else None,
                            args=tuple(str(value) for value in command_list[1:] if isinstance(value, str)),
                            transport="stdio",
                        )
                    )
        if context.workspace_dir is not None:
            commands_dir = context.workspace_dir / ".opencode" / "commands"
            if commands_dir.is_dir():
                for command_path in sorted(path for path in commands_dir.glob("*.md") if path.is_file()):
                    found_paths.append(str(command_path))
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"opencode:project:command:{command_path.stem}",
                            name=command_path.stem,
                            harness=self.harness,
                            artifact_type="command",
                            source_scope="project",
                            config_path=str(command_path),
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
