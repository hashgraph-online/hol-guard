"""Cursor harness adapter."""

from __future__ import annotations

import json
import sys
from hashlib import sha256
from pathlib import Path

from ..launcher import merge_guard_launcher_env
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available, _json_payload, _run_command_probe
from .mcp_servers import (
    ManagedMcpServer,
    is_guard_proxy_command,
    managed_stdio_servers,
    proxy_cli_args,
    proxy_process_env,
    skipped_stdio_server_names,
)


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

    @staticmethod
    def _editor_config_paths(context: HarnessContext) -> tuple[Path, ...]:
        paths: list[Path] = []
        if context.workspace_dir is not None:
            paths.append(context.workspace_dir / ".cursor" / "mcp.json")
        paths.append(context.home_dir / ".cursor" / "mcp.json")
        return tuple(paths)

    @staticmethod
    def _target_editor_config_path(context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".cursor" / "mcp.json"
        return context.home_dir / ".cursor" / "mcp.json"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        for config_path in self._editor_config_paths(context):
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
                env_payload = server_config.get("env")
                environment_payload = server_config.get("environment")
                environment = env_payload if isinstance(env_payload, dict) else environment_payload
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
                        metadata={
                            "env": {
                                str(key): str(value)
                                for key, value in environment.items()
                                if isinstance(key, str) and isinstance(value, str)
                            }
                            if isinstance(environment, dict)
                            else {},
                            "guard_managed_proxy": is_guard_proxy_command(
                                command if isinstance(command, str) else None,
                                args,
                            ),
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

    def install(self, context: HarnessContext, *, surface: str = "editor") -> dict[str, object]:
        if surface == "cli":
            return self._install_cli(context)
        if surface != "editor":
            raise ValueError(f"Unsupported Cursor surface: {surface}")
        return self._install_editor(context)

    def uninstall(self, context: HarnessContext, *, surface: str = "editor") -> dict[str, object]:
        if surface == "cli":
            return self._uninstall_cli(context)
        if surface != "editor":
            raise ValueError(f"Unsupported Cursor surface: {surface}")
        return self._uninstall_editor(context)

    def _install_editor(self, context: HarnessContext) -> dict[str, object]:
        detection = self.detect(context)
        managed_servers = managed_stdio_servers(detection)
        skipped_servers = skipped_stdio_server_names(detection)
        target_path = self._target_editor_config_path(context)
        original_text = target_path.read_text(encoding="utf-8") if target_path.is_file() else None
        backup_path = self._backup_path(target_path, context)
        if not backup_path.exists():
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_path.write_text(
                json.dumps({"existed": original_text is not None, "content": original_text}, indent=2) + "\n",
                encoding="utf-8",
            )
        state_path = self._state_path(target_path, context)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        workspace_dir = str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None
        state_path.write_text(
            json.dumps(
                {
                    "managed_config_path": str(target_path),
                    "backup_path": str(backup_path),
                    "surface": "editor",
                    "workspace_dir": workspace_dir,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        payload = self._strict_json_object(target_path, label="Cursor editor config", recover_missing=True)
        servers_payload = payload.get("mcpServers")
        normalized_servers = dict(servers_payload) if isinstance(servers_payload, dict) else {}
        for name, server_config in tuple(normalized_servers.items()):
            if not isinstance(name, str) or not isinstance(server_config, dict):
                continue
            command = server_config.get("command")
            args = tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str))
            if not is_guard_proxy_command(command if isinstance(command, str) else None, args):
                continue
            normalized_servers[name] = self._refresh_guard_proxy_entry(server_config)
        for server in managed_servers:
            normalized_servers[server.name] = self._proxy_server_entry(context, server)
        payload["mcpServers"] = normalized_servers
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return {
            "harness": self.harness,
            "active": True,
            "surface": "editor",
            "managed_config_path": str(target_path),
            "backup_path": str(backup_path),
            "state_path": str(state_path),
            "managed_servers": [server.name for server in managed_servers],
            "skipped_servers": list(skipped_servers),
            "notes": ["Guard Cursor editor MCP proxies added to the selected Cursor mcp.json config."],
        }

    def _uninstall_editor(self, context: HarnessContext) -> dict[str, object]:
        target_path = self._target_editor_config_path(context)
        backup_path = self._backup_path(target_path, context)
        state_path = self._state_path(target_path, context)
        backup_payload = self._backup_payload(backup_path)
        restored = False
        if backup_payload["readable"] is True:
            if backup_payload["existed"] and isinstance(backup_payload["content"], str):
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_text(str(backup_payload["content"]), encoding="utf-8")
                restored = True
            elif backup_payload["existed"] is not True and target_path.is_file():
                target_path.unlink()
                restored = True
            elif backup_payload["existed"] is not True:
                restored = True
        if restored and backup_path.is_file():
            backup_path.unlink()
        if restored and state_path.is_file():
            state_path.unlink()
        return {
            "harness": self.harness,
            "active": False,
            "surface": "editor",
            "managed_config_path": str(target_path),
            "backup_path": str(backup_path),
            "state_path": str(state_path),
            "restored": restored,
            "notes": ["Removed Guard Cursor editor MCP proxies and restored the prior Cursor config."],
        }

    def _install_cli(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(
            self.harness,
            context,
            launcher_name="cursor-agent",
            display_name="Cursor CLI",
        )
        return {
            "harness": self.harness,
            "active": True,
            "surface": "cli",
            **shim_manifest,
        }

    def _uninstall_cli(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name="cursor-agent",
            display_name="Cursor CLI",
        )
        return {
            "harness": self.harness,
            "active": False,
            "surface": "cli",
            **shim_manifest,
        }

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

    def _proxy_server_entry(self, context: HarnessContext, server: ManagedMcpServer) -> dict[str, object]:
        args = proxy_cli_args(
            proxy_command="cursor-mcp-proxy",
            guard_home=str(context.guard_home),
            server=server,
            home=str(context.home_dir) if context.home_dir.resolve() != Path.home().resolve() else None,
            workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
        )
        entry: dict[str, object] = {
            "command": sys.executable,
            "args": args,
            "type": "stdio",
        }
        env = merge_guard_launcher_env(proxy_process_env(getattr(server, "env", {})))
        if env:
            entry["env"] = env
        return entry

    @staticmethod
    def _refresh_guard_proxy_entry(server_config: dict[str, object]) -> dict[str, object]:
        refreshed = dict(server_config)
        args = tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str))
        refreshed["command"] = sys.executable
        refreshed["args"] = list(args)
        return refreshed

    @staticmethod
    def _strict_json_object(path: Path, *, label: str, recover_missing: bool = False) -> dict[str, object]:
        if not path.is_file():
            if recover_missing:
                return {}
            raise RuntimeError(f"Guard refused to overwrite missing {label} at {path}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Guard refused to overwrite unreadable {label} at {path}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError(f"Guard refused to overwrite non-object {label} at {path}")
        return payload

    @staticmethod
    def _backup_path(target_path: Path, context: HarnessContext) -> Path:
        target = str(target_path.resolve())
        digest = sha256(target.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "cursor" / f"{digest}.backup.json"

    @staticmethod
    def _state_path(target_path: Path, context: HarnessContext) -> Path:
        target = str(target_path.resolve())
        digest = sha256(target.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "cursor" / f"{digest}.state.json"

    @staticmethod
    def _backup_payload(backup_path: Path) -> dict[str, str | bool | None]:
        try:
            payload = json.loads(backup_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"readable": False, "existed": False, "content": None}
        if not isinstance(payload, dict):
            return {"readable": False, "existed": False, "content": None}
        existed = payload.get("existed") is True
        content = payload.get("content")
        return {"readable": True, "existed": existed, "content": content if isinstance(content, str) else None}
