"""Codex harness adapter."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

try:  # pragma: no cover - Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from ..codex_config import read_toml_payload, write_toml_payload
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available
from .mcp_servers import ManagedMcpServer, managed_stdio_servers, proxy_cli_args, skipped_stdio_server_names


def _read_toml(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
        return payload if isinstance(payload, dict) else {}
    except OSError:
        return {}


class CodexHarnessAdapter(HarnessAdapter):
    """Discover Codex MCP servers and wrapper surfaces."""

    harness = "codex"
    executable = "codex"
    approval_tier = "native-or-center"
    approval_summary = "Guard can stop live Codex MCP tool calls inline and fall back to the local approval center."
    fallback_hint = (
        "If Codex cannot render the inline approval request, Guard will queue it in the local approval center."
    )

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_paths = [context.home_dir / ".codex" / "config.toml"]
        if context.workspace_dir is not None:
            config_paths.append(context.workspace_dir / ".codex" / "config.toml")
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        for config_path in config_paths:
            payload = _read_toml(config_path)
            if not payload:
                continue
            found_paths.append(str(config_path))
            scope = self._scope_for(context, config_path)
            mcp_servers = payload.get("mcp_servers")
            if isinstance(mcp_servers, dict):
                for name, server_config in mcp_servers.items():
                    if not isinstance(name, str) or not isinstance(server_config, dict):
                        continue
                    command = server_config.get("command")
                    args = tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str))
                    url = server_config.get("url")
                    env = server_config.get("env")
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"codex:{scope}:{name}",
                            name=name,
                            harness=self.harness,
                            artifact_type="mcp_server",
                            source_scope=scope,
                            config_path=str(config_path),
                            command=command if isinstance(command, str) else None,
                            args=args,
                            url=url if isinstance(url, str) else None,
                            transport="http" if isinstance(url, str) else "stdio",
                            metadata={
                                "env": {
                                    str(key): str(value)
                                    for key, value in env.items()
                                    if isinstance(key, str) and isinstance(value, str)
                                }
                                if isinstance(env, dict)
                                else {},
                                "env_keys": sorted(env.keys()) if isinstance(env, dict) else [],
                            },
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

    def install(self, context: HarnessContext) -> dict[str, object]:
        detection = self.detect(context)
        managed_servers = managed_stdio_servers(detection)
        skipped_servers = skipped_stdio_server_names(detection)
        target_config_path = self._target_config_path(context)
        original_text = target_config_path.read_text(encoding="utf-8") if target_config_path.is_file() else None
        backup_path = self._backup_path(context)
        if not backup_path.exists():
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_path.write_text(original_text or "", encoding="utf-8")
        payload = read_toml_payload(target_config_path)
        mcp_servers = payload.get("mcp_servers")
        if not isinstance(mcp_servers, dict):
            mcp_servers = {}
        existing_workspace_server_names = {
            name for name, value in mcp_servers.items() if isinstance(name, str) and isinstance(value, dict)
        }
        for server in managed_servers:
            if self._should_skip_workspace_override(
                context=context,
                server=server,
                existing_workspace_server_names=existing_workspace_server_names,
            ):
                continue
            mcp_servers[server.name] = self._proxy_server_entry(context, server)
        payload["mcp_servers"] = mcp_servers
        write_toml_payload(target_config_path, payload)
        shim_manifest = install_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(target_config_path),
            **shim_manifest,
            "mode": "codex-mcp-proxy",
            "managed_config_path": str(target_config_path),
            "backup_path": str(backup_path),
            "managed_servers": [server.name for server in managed_servers],
            "skipped_servers": list(skipped_servers),
            "source_config_paths": list(detection.config_paths),
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        target_config_path = self._target_config_path(context)
        backup_path = self._backup_path(context)
        if backup_path.is_file():
            original_text = backup_path.read_text(encoding="utf-8")
            if original_text:
                target_config_path.parent.mkdir(parents=True, exist_ok=True)
                target_config_path.write_text(original_text, encoding="utf-8")
            elif target_config_path.is_file():
                target_config_path.unlink()
            backup_path.unlink()
        shim_manifest = remove_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(target_config_path),
            **shim_manifest,
            "mode": "codex-mcp-proxy",
            "managed_config_path": str(target_config_path),
            "backup_path": str(backup_path),
        }

    @staticmethod
    def _target_config_path(context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".codex" / "config.toml"
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _backup_path(context: HarnessContext) -> Path:
        target_path = str(CodexHarnessAdapter._target_config_path(context).resolve())
        digest = hashlib.sha256(target_path.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "codex" / f"{digest}.backup.toml"

    def _proxy_server_entry(self, context: HarnessContext, server: ManagedMcpServer) -> dict[str, object]:
        args = proxy_cli_args(
            proxy_command="codex-mcp-proxy",
            guard_home=str(context.guard_home),
            server=server,
            home=str(context.home_dir) if context.home_dir.resolve() != Path.home().resolve() else None,
            workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
        )
        entry: dict[str, object] = {
            "command": sys.executable,
            "args": args,
        }
        env = getattr(server, "env", {})
        if env:
            entry["env"] = env
        return entry

    @staticmethod
    def _should_skip_workspace_override(
        *,
        context: HarnessContext,
        server: ManagedMcpServer,
        existing_workspace_server_names: set[str],
    ) -> bool:
        if context.workspace_dir is None:
            return False
        if server.source_scope == "project":
            return False
        return server.name in existing_workspace_server_names
