"""Cursor harness adapter."""

from __future__ import annotations

import json
import sys
from hashlib import sha256
from pathlib import Path

from ..aibom_detection import enrich_mcp_server_metadata, extend_detection_with_workspace_aibom
from ..launcher import merge_guard_launcher_env
from ..models import GuardArtifact, HarnessDetection
from ..runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall
from ..shims import ensure_guard_shim_path_in_shell_profile, install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _json_payload, _run_command_probe
from .cursor_cli import (
    CURSOR_CLI_SHIM_COMMANDS,
    cursor_cli_command_available,
    resolve_cursor_cli_entry,
)
from .cursor_hooks import install_cursor_hooks, uninstall_cursor_hooks
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
    launcher_name = "cursor-agent"
    legacy_launcher_names = ("cursor",)
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
        paths.append(context.home_dir / ".cursor" / "mcp.json")
        if context.workspace_dir is not None:
            paths.append(context.workspace_dir / ".cursor" / "mcp.json")
        return tuple(paths)

    @staticmethod
    def _target_editor_config_path(context: HarnessContext) -> Path:
        """Managed Cursor editor installs always target the global config."""

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
                normalized_environment = (
                    {
                        key.strip(): value
                        for key, value in environment.items()
                        if isinstance(key, str) and key.strip() and isinstance(value, str)
                    }
                    if isinstance(environment, dict)
                    else {}
                )
                url = server_config.get("url")
                raw_headers = server_config.get("headers")
                configured_headers = (
                    {
                        key.strip(): value
                        for key, value in raw_headers.items()
                        if isinstance(key, str) and key.strip() and isinstance(value, str)
                    }
                    if isinstance(raw_headers, dict)
                    else {}
                )
                metadata = enrich_mcp_server_metadata(
                    {
                        "name": name,
                        "env": normalized_environment,
                        "env_keys": sorted(normalized_environment),
                        "headers_keys": sorted(configured_headers),
                        "guard_managed_proxy": is_guard_proxy_command(
                            command if isinstance(command, str) else None,
                            args,
                        ),
                    },
                    command=command if isinstance(command, str) else None,
                    args=args,
                    url=url if isinstance(url, str) else None,
                    transport="http" if isinstance(url, str) else "stdio",
                    configured_headers=configured_headers,
                )
                artifacts.append(
                    enrich_artifact_with_mcp_skill_firewall(
                        GuardArtifact(
                            artifact_id=f"cursor:{scope}:{name}",
                            name=name,
                            harness=self.harness,
                            artifact_type="mcp_server",
                            source_scope=scope,
                            config_path=str(config_path),
                            command=command if isinstance(command, str) else None,
                            args=args,
                            url=url if isinstance(url, str) else None,
                            transport="http" if isinstance(url, str) else "stdio",
                            metadata=metadata,
                        )
                    )
                )
        cli_available = cursor_cli_command_available(context)
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or cli_available,
            command_available=cli_available,
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def resolved_executable(self, context: HarnessContext) -> str | None:
        entry = resolve_cursor_cli_entry(context)
        if entry is None:
            return None
        return entry.executable

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        entry = resolve_cursor_cli_entry(context)
        if entry is None:
            return [self.executable, *passthrough_args]
        return entry.launch_argv(passthrough_args)

    def install(self, context: HarnessContext, *, surface: str = "editor") -> dict[str, object]:
        if surface == "cli":
            return self._install_cli(context)
        if surface == "all":
            return self._install_all(context)
        if surface != "editor":
            raise ValueError(f"Unsupported Cursor surface: {surface}")
        return self._install_editor(context)

    def uninstall(self, context: HarnessContext, *, surface: str = "editor") -> dict[str, object]:
        if surface == "cli":
            return self._uninstall_cli(context)
        if surface == "all":
            return self._uninstall_all(context)
        if surface != "editor":
            raise ValueError(f"Unsupported Cursor surface: {surface}")
        return self._uninstall_editor(context)

    def _install_all(self, context: HarnessContext) -> dict[str, object]:
        editor_manifest = self._install_editor(context)
        cli_manifest = self._install_cli(context)
        return {
            "harness": self.harness,
            "active": True,
            "surface": "all",
            "surfaces": ["editor", "cli"],
            "editor": editor_manifest,
            "cli": cli_manifest,
            "managed_config_path": editor_manifest.get("managed_config_path"),
            "backup_path": editor_manifest.get("backup_path"),
            "state_path": editor_manifest.get("state_path"),
            "guard_cli_identity": editor_manifest.get("guard_cli_identity"),
            "hook_script_sha256": editor_manifest.get("hook_script_sha256"),
            "shim_path": cli_manifest.get("shim_path"),
            "shim_command": cli_manifest.get("shim_command"),
        }

    def _uninstall_all(self, context: HarnessContext) -> dict[str, object]:
        cli_manifest = self._uninstall_cli(context)
        editor_manifest = self._uninstall_editor(context)
        return {
            "harness": self.harness,
            "active": False,
            "surface": "all",
            "surfaces": ["editor", "cli"],
            "editor": editor_manifest,
            "cli": cli_manifest,
            "managed_config_path": editor_manifest.get("managed_config_path"),
            "backup_path": editor_manifest.get("backup_path"),
            "state_path": editor_manifest.get("state_path"),
            "shim_path": cli_manifest.get("shim_path"),
            "removed": cli_manifest.get("removed"),
            "restored": editor_manifest.get("restored"),
        }

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
        hooks_manifest = install_cursor_hooks(context)
        notes = [
            "Guard Cursor editor MCP proxies added to the global Cursor mcp.json config.",
            "Guard native Cursor hooks installed globally for shell, MCP, and file-read interception.",
        ]
        if context.workspace_dir is not None:
            notes.append(
                "Workspace policy context uses the detected project directory; "
                "Guard does not write project-local hook files."
            )
        return {
            "harness": self.harness,
            "active": True,
            "surface": "editor",
            "managed_config_path": str(target_path),
            "backup_path": str(backup_path),
            "state_path": str(state_path),
            "managed_servers": [server.name for server in managed_servers],
            "skipped_servers": list(skipped_servers),
            "managed_hooks_path": hooks_manifest.get("managed_hooks_path"),
            "managed_hook_script_path": hooks_manifest.get("managed_hook_script_path"),
            "guard_cli_identity": hooks_manifest.get("guard_cli_identity"),
            "hook_script_sha256": hooks_manifest.get("hook_script_sha256"),
            "notes": notes,
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
        hooks_manifest = uninstall_cursor_hooks(context)
        return {
            "harness": self.harness,
            "active": False,
            "surface": "editor",
            "managed_config_path": str(target_path),
            "backup_path": str(backup_path),
            "state_path": str(state_path),
            "restored": restored,
            "managed_hooks_path": hooks_manifest.get("managed_hooks_path"),
            "notes": [
                "Removed Guard Cursor editor MCP proxies and restored the prior Cursor config.",
                "Removed Guard native Cursor hooks when a managed hooks backup was available.",
            ],
        }

    def _install_cli(self, context: HarnessContext) -> dict[str, object]:
        agent_shim = install_guard_shim(
            self.harness,
            context,
            launcher_name="cursor-agent",
            display_name="Cursor CLI (cursor-agent)",
        )
        cursor_shim = install_guard_shim(
            self.harness,
            context,
            launcher_name="cursor",
            display_name="Cursor CLI (cursor agent)",
        )
        profile = ensure_guard_shim_path_in_shell_profile(context)
        raw_agent_notes = agent_shim.get("notes")
        agent_notes = (
            [str(note) for note in raw_agent_notes if isinstance(note, str)]
            if isinstance(raw_agent_notes, (list, tuple))
            else []
        )
        notes = [
            *agent_notes,
            "Use guard-cursor-agent for the standalone cursor-agent binary.",
            "Use guard-cursor agent ... when launching through the Cursor app CLI.",
            f"Guard launcher shims live in {context.guard_home / 'bin'}.",
        ]
        if profile.get("changed"):
            notes.append("Prepended the Guard launcher shim directory to your shell profile.")
        elif profile.get("restart_shell_required"):
            notes.append("Restart your shell or open a new terminal so guard-cursor shims are on PATH.")
        return {
            "harness": self.harness,
            "active": True,
            "surface": "cli",
            "shim_path": agent_shim["shim_path"],
            "shim_dir": agent_shim["shim_dir"],
            "shim_command": agent_shim["shim_command"],
            "shim_paths": [agent_shim["shim_path"], cursor_shim["shim_path"]],
            "shim_commands": list(CURSOR_CLI_SHIM_COMMANDS),
            "windows_shim_path": agent_shim.get("windows_shim_path"),
            "shell_profile": profile,
            "notes": notes,
        }

    def _uninstall_cli(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name="cursor-agent",
            legacy_launcher_names=self.legacy_launcher_names,
            display_name="Cursor CLI",
        )
        return {
            "harness": self.harness,
            "active": False,
            "surface": "cli",
            **shim_manifest,
        }

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        entry = resolve_cursor_cli_entry(context)
        if entry is None:
            return None
        payload = _run_command_probe(entry.launch_argv(["mcp", "list"]))
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
        raw_args = server_config.get("args")
        args = tuple(str(value) for value in raw_args if isinstance(value, str)) if isinstance(raw_args, list) else ()
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
