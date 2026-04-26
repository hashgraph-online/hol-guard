"""Cursor harness adapter."""

from __future__ import annotations

from pathlib import Path

from ..models import GuardArtifact, HarnessDetection
from .base import HarnessAdapter, HarnessContext, _command_available, _json_payload, _run_command_probe


class CursorHarnessAdapter(HarnessAdapter):
    """Discover Cursor MCP configuration."""

    harness = "cursor"
    executable = "cursor-agent"
    approval_tier = "native-harness"
    approval_summary = (
        "Cursor already owns tool approval, so Guard focuses on artifact trust, provenance, and preflight review."
    )
    fallback_hint = "Resolve package-level trust in Guard and let Cursor keep its built-in tool approval flow."
    approval_prompt_channel = "native"
    approval_auto_open_browser = False

    @staticmethod
    def _scope_for(context: HarnessContext, path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".cursor" / "mcp.json"
        return context.home_dir / ".cursor" / "mcp.json"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_paths = [context.home_dir / ".cursor" / "mcp.json"]
        if context.workspace_dir is not None:
            config_paths.append(context.workspace_dir / ".cursor" / "mcp.json")
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        for config_path in config_paths:
            payload = _json_payload(config_path)
            if not payload:
                continue
            found_paths.append(str(config_path))
            scope = self._scope_for(context, config_path)
            mcp_servers = payload.get("mcpServers")
            if not isinstance(mcp_servers, dict):
                continue
            for name, server_config in mcp_servers.items():
                if not isinstance(name, str) or not isinstance(server_config, dict):
                    continue
                args = tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str))
                command = server_config.get("command")
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"cursor:{scope}:{name}",
                        name=name,
                        harness=self.harness,
                        artifact_type="mcp_server",
                        source_scope=scope,
                        config_path=str(config_path),
                        command=command if isinstance(command, str) else None,
                        args=args,
                        url=server_config.get("url") if isinstance(server_config.get("url"), str) else None,
                        transport="http" if isinstance(server_config.get("url"), str) else "stdio",
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

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        if not _command_available(self.executable):
            return None
        payload = _run_command_probe([self.executable, "mcp", "list"])
        stdout = payload.get("stdout")
        reported_artifacts = None
        if isinstance(stdout, str):
            if "No MCP servers configured" in stdout:
                reported_artifacts = 0
            else:
                reported_artifacts = sum(
                    1
                    for line in stdout.splitlines()
                    if line.strip().startswith("-") or line.strip().startswith("•") or line.strip().startswith("*")
                )
        payload["reported_artifacts"] = reported_artifacts
        return payload

    def diagnostic_warnings(
        self,
        detection: HarnessDetection,
        runtime_probe: dict[str, object] | None,
    ) -> list[str]:
        warnings = super().diagnostic_warnings(detection, runtime_probe)
        reported_artifacts = runtime_probe.get("reported_artifacts") if runtime_probe is not None else None
        if detection.artifacts and reported_artifacts == 0:
            warnings.append(
                "Cursor CLI reported no MCP servers, but Guard found local definitions. "
                "Cursor may be using a different config root than Guard."
            )
        return warnings
