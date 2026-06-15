"""OpenCode harness adapter."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from ...ecosystems.opencode import _load_json_or_jsonc
from ..aibom_detection import extend_detection_with_workspace_aibom
from ..launcher import merge_guard_launcher_env
from ..models import HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available, _run_command_probe
from .hook_python import resolve_guard_hook_python
from .mcp_servers import (
    GUARD_MCP_COMPANION_PREFIX,
    ManagedMcpServer,
    is_guard_mcp_companion_name,
    is_guard_proxy_command,
    managed_stdio_servers,
    proxy_cli_args,
    proxy_process_env,
    skipped_stdio_server_names,
)
from .opencode_artifacts import (
    CONFIG_FILENAMES,
    _command_parts,
    append_config_artifacts,
    append_directory_artifacts,
    append_found_path,
    config_paths,
    configured_config_path,
    runtime_config_path,
    runtime_overlay,
)
from .opencode_pretool import install_pretool_plugin, remove_pretool_plugin

_OPENCODE_SCHEMA = "https://opencode.ai/config.json"
_GUARD_MCP_COMPANION_PREFIX = GUARD_MCP_COMPANION_PREFIX
_DEFAULT_BASH_PERMISSION: dict[str, object] = {
    "*": "allow",
    "git checkout *": "deny",
    "git checkout": "deny",
    "git revert *": "deny",
    "git revert": "deny",
    "git restore *": "deny",
    "git restore": "deny",
    "git reset *": "deny",
    "git reset": "deny",
    "rm -rf *": "deny",
    "rm -r *": "deny",
}


class OpenCodeInstallConfigError(RuntimeError):
    """Raised when Guard cannot safely update an existing OpenCode config file."""


class OpenCodeHarnessAdapter(HarnessAdapter):
    """Discover OpenCode config, commands, plugins, and skills."""

    harness = "opencode"
    executable = "opencode"
    approval_tier = "mixed"
    approval_summary = (
        "Guard evaluates OpenCode skills, MCP servers, commands, and plugins before launch, and the managed "
        "runtime overlay keeps managed MCP tools on native ask."
    )
    fallback_hint = (
        "Use Guard approvals for blocked artifacts and OpenCode's native allow once or allow session flow for "
        "managed MCP tools."
    )
    approval_prompt_channel = "native"
    approval_auto_open_browser = False

    _SUBCOMMANDS = frozenset(
        {
            "completion",
            "acp",
            "mcp",
            "attach",
            "run",
            "auth",
            "agent",
            "upgrade",
            "uninstall",
            "serve",
            "web",
            "models",
            "stats",
            "export",
            "import",
            "github",
            "pr",
            "session",
            "db",
        }
    )
    _REQUIRED_VALUE_OPTIONS = frozenset(
        {
            "--hostname",
            "--mdns-domain",
            "--cors",
            "--model",
            "-m",
            "--session",
            "-s",
            "--prompt",
            "--agent",
            "--variant",
            "--log-level",
            "--command",
            "--format",
            "--file",
            "-f",
            "--attach",
            "--password",
            "-p",
            "--dir",
        }
    )
    _OPTIONAL_VALUE_OPTIONS = frozenset({"--port", "--title"})

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / "opencode.json"
        return context.home_dir / ".config" / "opencode" / "opencode.json"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts = []
        found_paths: list[str] = []
        seen_artifact_ids: set[str] = set()
        for config_path in config_paths(context):
            payload, parse_error, _parse_reason = _load_json_or_jsonc(config_path)
            if parse_error or not payload:
                continue
            append_found_path(found_paths, config_path)
            scope = self._scope_for(context, config_path)
            append_config_artifacts(
                artifacts=artifacts,
                seen_artifact_ids=seen_artifact_ids,
                scope=scope,
                config_path=config_path,
                payload=payload,
            )
        append_directory_artifacts(
            context=context,
            artifacts=artifacts,
            found_paths=found_paths,
            seen_artifact_ids=seen_artifact_ids,
        )
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        detection = self.detect(context)
        managed_servers = managed_stdio_servers(detection)
        skipped_servers = skipped_stdio_server_names(detection)
        target_config_path = self._managed_install_config_path(context)
        original_text = None
        if target_config_path.is_file():
            original_text = target_config_path.read_text(encoding="utf-8")
        backup_path = self._backup_path(context)
        if not backup_path.exists():
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_payload = {"existed": original_text is not None, "content": original_text}
            backup_path.write_text(json.dumps(backup_payload, indent=2) + "\n", encoding="utf-8")
        state_path = self._state_path(context, target_config_path)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(
            json.dumps(
                {
                    "managed_config_path": str(target_config_path),
                    "backup_path": str(backup_path),
                    "scope": "workspace" if context.workspace_dir is not None else "global",
                    "workspace_dir": (
                        str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None
                    ),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        target_payload, parse_error, _parse_reason = _load_json_or_jsonc(target_config_path)
        if target_config_path.is_file() and (parse_error or not isinstance(target_payload, dict)):
            raise OpenCodeInstallConfigError(
                "Refusing to modify an invalid OpenCode root config. "
                "Fix opencode.json (or opencode.jsonc) syntax and retry install."
            )
        if not isinstance(target_payload, dict):
            target_payload = {}
        existing_workspace_server_names = self._workspace_server_names(context)
        _apply_install_baseline(target_payload)
        target_payload["permission"] = self._managed_permission_payload(
            target_payload.get("permission"),
            context=context,
            servers=managed_servers,
            existing_workspace_server_names=existing_workspace_server_names,
        )
        target_payload["mcp"] = _persisted_mcp_with_guard_companions(
            target_payload.get("mcp"),
            context=context,
            servers=managed_servers,
            existing_workspace_server_names=existing_workspace_server_names,
        )
        target_config_path.parent.mkdir(parents=True, exist_ok=True)
        target_config_path.write_text(json.dumps(target_payload, indent=2) + "\n", encoding="utf-8")
        shim_manifest = install_guard_shim(self.harness, context)
        plugin_manifest = install_pretool_plugin(context)
        overlay_path = runtime_config_path(context)
        overlay_path.parent.mkdir(parents=True, exist_ok=True)
        overlay_path.write_text(
            json.dumps(
                runtime_overlay(
                    permission_rules=self._proxy_permission_rules(
                        context,
                        managed_servers,
                        existing_workspace_server_names,
                    ),
                    mcp_servers=self._proxy_mcp_overrides(
                        context,
                        managed_servers,
                        existing_workspace_server_names,
                    ),
                ),
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        notes = [
            *list(shim_manifest.get("notes", [])),
            "Guard installed an OpenCode pretool plugin that reviews bash and shell commands through "
            "hol-guard hook before execution.",
            "Guard updated the global OpenCode root config at ~/.config/opencode/opencode.json with "
            "baseline bash permission rules and hol-guard:: MCP companion servers, and installed the "
            "pretool plugin under ~/.config/opencode/plugins/.",
            "Guard added an OpenCode runtime overlay that keeps managed MCP tools on native ask and routes "
            "managed local MCP servers through Guard runtime interception when you launch through Guard.",
            "Use hol-guard:: MCP servers in OpenCode for Guard-proxied tools, or launch through guard-opencode "
            "or hol-guard run opencode for pre-launch artifact checks and the runtime skill overlay.",
        ]
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(target_config_path),
            **shim_manifest,
            **plugin_manifest,
            "managed_config_path": str(target_config_path),
            "backup_path": str(backup_path),
            "state_path": str(state_path),
            "runtime_config_path": str(overlay_path),
            "runtime_env_var": "OPENCODE_CONFIG_CONTENT",
            "managed_servers": [server.name for server in managed_servers],
            "skipped_servers": list(skipped_servers),
            "source_config_paths": list(detection.config_paths),
            "notes": notes,
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        state_path, state_payload = self._state_entry(context)
        target_config_path = self._managed_config_path_from_state(context, state_payload)
        backup_path = self._backup_path_from_state(context, state_payload, target_config_path)
        state_cleanup_complete = False
        if backup_path.is_file():
            backup_payload = self._backup_payload(backup_path)
            if backup_payload["readable"] is not True:
                pass
            elif backup_payload["existed"]:
                original_text = backup_payload["content"]
                if isinstance(original_text, str):
                    target_config_path.parent.mkdir(parents=True, exist_ok=True)
                    target_config_path.write_text(original_text, encoding="utf-8")
                    backup_path.unlink()
                    state_cleanup_complete = True
            elif target_config_path.is_file():
                target_config_path.unlink()
                backup_path.unlink()
                state_cleanup_complete = True
            else:
                backup_path.unlink()
                state_cleanup_complete = True
        if state_cleanup_complete and state_path.is_file():
            state_path.unlink()
        shim_manifest = remove_guard_shim(self.harness, context)
        plugin_manifest = remove_pretool_plugin(context)
        notes = [
            *list(shim_manifest.get("notes", [])),
            "Guard removed the OpenCode pretool plugin from the global plugin directory.",
            "Guard leaves the OpenCode runtime overlay on disk for auditability, but it is ignored unless you "
            "launch through Guard.",
        ]
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(target_config_path),
            **shim_manifest,
            **plugin_manifest,
            "managed_config_path": str(target_config_path),
            "backup_path": str(backup_path),
            "state_path": str(state_path),
            "runtime_config_path": str(runtime_config_path(context)),
            "runtime_env_var": "OPENCODE_CONFIG_CONTENT",
            "notes": notes,
        }

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        overlay_path = runtime_config_path(context)
        if not overlay_path.exists():
            return {}
        try:
            runtime_config = json.loads(overlay_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        existing_config = _inline_config(os.getenv("OPENCODE_CONFIG_CONTENT"))
        merged_config = _merge_configs(existing_config, runtime_config)
        return {"OPENCODE_CONFIG_CONTENT": json.dumps(merged_config)}

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        if not passthrough_args:
            return self._interactive_command(context)
        if passthrough_args[0] in self._SUBCOMMANDS:
            return [self.executable, *self._subcommand_args(context, passthrough_args)]
        return [*self._interactive_command(context), *self._interactive_args(passthrough_args)]

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        if not _command_available(self.executable):
            return None
        return {
            "paths": _run_command_probe([self.executable, "debug", "paths"]),
            "config": _run_command_probe([self.executable, "debug", "config"]),
        }

    def _proxy_mcp_overrides(
        self,
        context: HarnessContext,
        servers: tuple[ManagedMcpServer, ...],
        existing_workspace_server_names: set[str],
    ) -> dict[str, object]:
        overrides: dict[str, object] = {}
        for server in servers:
            if self._should_skip_workspace_override(
                context=context,
                server=server,
                existing_workspace_server_names=existing_workspace_server_names,
            ):
                continue
            entry: dict[str, object] = {
                "type": "local",
                "command": [
                    str(resolve_guard_hook_python(context)),
                    *proxy_cli_args(
                        proxy_command="opencode-mcp-proxy",
                        guard_home=str(context.guard_home),
                        server=server,
                        home=str(context.home_dir) if context.home_dir.resolve() != Path.home().resolve() else None,
                        workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
                    ),
                ],
                "enabled": server.enabled,
            }
            environment = merge_guard_launcher_env(proxy_process_env(getattr(server, "env", {})))
            if environment:
                entry["environment"] = environment
            overrides[server.name] = entry
        return overrides

    @staticmethod
    def _proxy_permission_rules(
        context: HarnessContext,
        servers: tuple[ManagedMcpServer, ...],
        existing_workspace_server_names: set[str],
    ) -> dict[str, object]:
        rules: dict[str, object] = {}
        for server in servers:
            shadowed = OpenCodeHarnessAdapter._should_skip_workspace_override(
                context=context,
                server=server,
                existing_workspace_server_names=existing_workspace_server_names,
            )
            if shadowed:
                if server.enabled and server.source_scope != "project":
                    rules[f"{_guard_mcp_companion_name(server.name)}_*"] = "ask"
                continue
            if not server.enabled:
                continue
            rules[f"{server.name}_*"] = "ask"
            if server.source_scope != "project":
                rules[f"{_guard_mcp_companion_name(server.name)}_*"] = "ask"
        return rules

    @staticmethod
    def _skip_global_managed_server(server: ManagedMcpServer) -> bool:
        return server.source_scope == "project"

    @staticmethod
    def _should_skip_workspace_override(
        *,
        context: HarnessContext,
        server: ManagedMcpServer,
        existing_workspace_server_names: set[str],
        for_companion: bool = False,
    ) -> bool:
        if context.workspace_dir is None:
            return False
        if server.source_scope == "project":
            return False
        if for_companion and server.source_scope == "global":
            return False
        return server.name in existing_workspace_server_names

    def _workspace_server_names(self, context: HarnessContext) -> set[str]:
        if context.workspace_dir is None:
            return set()
        workspace_server_names: set[str] = set()
        for config_path in config_paths(context):
            if not config_path.is_relative_to(context.workspace_dir):
                continue
            payload, parse_error, _parse_reason = _load_json_or_jsonc(config_path)
            if parse_error or not isinstance(payload, dict):
                continue
            mcp = payload.get("mcp")
            if not isinstance(mcp, dict):
                continue
            for name, value in mcp.items():
                if not isinstance(name, str) or not isinstance(value, dict):
                    continue
                if is_guard_mcp_companion_name(name):
                    continue
                workspace_server_names.add(name)
        return workspace_server_names

    @staticmethod
    def _target_config_path(context: HarnessContext) -> Path:
        workspace_dir = context.workspace_dir
        if workspace_dir is not None:
            for name in CONFIG_FILENAMES:
                candidate = workspace_dir / name
                if candidate.is_file():
                    return candidate
        configured_path = configured_config_path(context)
        if configured_path is not None:
            return configured_path
        if workspace_dir is not None:
            return workspace_dir / CONFIG_FILENAMES[0]
        return OpenCodeHarnessAdapter._managed_install_config_path(context)

    @staticmethod
    def _managed_install_config_path(context: HarnessContext) -> Path:
        """Managed OpenCode installs always target the global root config."""

        global_dir = context.home_dir / ".config" / "opencode"
        for name in CONFIG_FILENAMES:
            candidate = global_dir / name
            if candidate.is_file():
                return candidate
        return global_dir / CONFIG_FILENAMES[0]

    @staticmethod
    def _backup_path(context: HarnessContext) -> Path:
        target_path = str(OpenCodeHarnessAdapter._managed_install_config_path(context).resolve())
        digest = hashlib.sha256(target_path.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "opencode" / f"{digest}.backup.json"

    @staticmethod
    def _state_path(context: HarnessContext, target_config_path: Path) -> Path:
        target_path = str(target_config_path.resolve())
        digest = hashlib.sha256(target_path.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "opencode" / f"{digest}.state.json"

    @classmethod
    def _state_entry(cls, context: HarnessContext) -> tuple[Path, dict[str, str]]:
        state_dir = context.guard_home / "managed" / "opencode"
        target_config_path = cls._managed_install_config_path(context)
        preferred_path = cls._state_path(context, target_config_path)
        current_workspace = str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None
        candidate_entries: list[tuple[Path, dict[str, str]]] = []
        for state_path in sorted(state_dir.glob("*.state.json")):
            payload = cls._state_payload(state_path)
            if not payload:
                continue
            candidate_entries.append((state_path, payload))
        for state_path, payload in candidate_entries:
            if payload.get("managed_config_path") == str(target_config_path):
                return state_path, payload
        if current_workspace is not None:
            workspace_entries = [
                (state_path, payload)
                for state_path, payload in candidate_entries
                if payload.get("workspace_dir") == current_workspace
            ]
            if len(workspace_entries) == 1:
                return workspace_entries[0]
            return preferred_path, {}
        global_entries = [
            (state_path, payload) for state_path, payload in candidate_entries if payload.get("scope") == "global"
        ]
        if len(global_entries) == 1:
            return global_entries[0]
        return preferred_path, {}

    @staticmethod
    def _state_payload(state_path: Path) -> dict[str, str]:
        if not state_path.is_file():
            return {}
        try:
            payload = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        result: dict[str, str] = {}
        for key in ("managed_config_path", "backup_path", "scope", "workspace_dir"):
            value = payload.get(key)
            if isinstance(value, str):
                result[key] = value
        return result

    @classmethod
    def _managed_config_path_from_state(cls, context: HarnessContext, state_payload: dict[str, str]) -> Path:
        managed_config_path = state_payload.get("managed_config_path")
        if isinstance(managed_config_path, str):
            return Path(managed_config_path)
        return cls._managed_install_config_path(context)

    @classmethod
    def _backup_path_from_state(
        cls,
        context: HarnessContext,
        state_payload: dict[str, str],
        target_config_path: Path,
    ) -> Path:
        backup_path = state_payload.get("backup_path")
        if isinstance(backup_path, str):
            return Path(backup_path)
        digest = hashlib.sha256(str(target_config_path.resolve()).encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "opencode" / f"{digest}.backup.json"

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

    def _interactive_command(self, context: HarnessContext) -> list[str]:
        command = [self.executable]
        if context.workspace_dir is not None:
            command.append(str(context.workspace_dir))
        return command

    def _subcommand_args(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        del context
        return list(passthrough_args)

    def _interactive_args(self, passthrough_args: list[str]) -> list[str]:
        if any(value == "--prompt" or value.startswith("--prompt=") for value in passthrough_args):
            return list(passthrough_args)
        normalized: list[str] = []
        prompt_tokens: list[str] = []
        index = 0
        while index < len(passthrough_args):
            value = passthrough_args[index]
            if value == "--":
                prompt_tokens.extend(passthrough_args[index + 1 :])
                break
            if value.startswith("-"):
                normalized.append(value)
                if self._consumes_next_value(value, passthrough_args, index):
                    index += 1
                    normalized.append(passthrough_args[index])
                index += 1
                continue
            prompt_tokens.extend(passthrough_args[index:])
            break
        if prompt_tokens:
            normalized.extend(["--prompt", " ".join(prompt_tokens)])
        return normalized

    def _consumes_next_value(self, value: str, passthrough_args: list[str], index: int) -> bool:
        if index + 1 >= len(passthrough_args) or "=" in value:
            return False
        if value in self._REQUIRED_VALUE_OPTIONS:
            return True
        next_value = passthrough_args[index + 1]
        if value == "--port":
            return next_value.isdigit()
        if value == "--title":
            return not next_value.startswith("-")
        return False

    def _managed_permission_payload(
        self,
        current_permission: object,
        *,
        context: HarnessContext,
        servers: tuple[ManagedMcpServer, ...],
        existing_workspace_server_names: set[str],
    ) -> dict[str, object]:
        permission = self._coerce_permission_payload(current_permission)
        permission.update(
            self._proxy_permission_rules(
                context=context,
                servers=servers,
                existing_workspace_server_names=existing_workspace_server_names,
            )
        )
        return _merge_default_bash_permission(permission)

    @staticmethod
    def _coerce_permission_payload(current_permission: object) -> dict[str, object]:
        payload = _object_dict(current_permission)
        if payload is not None:
            return payload
        if isinstance(current_permission, str):
            return {"*": current_permission}
        return {}


__all__ = ["OpenCodeHarnessAdapter", "OpenCodeInstallConfigError"]


def _apply_install_baseline(payload: dict[str, object]) -> None:
    payload.setdefault("$schema", _OPENCODE_SCHEMA)


def _merge_default_bash_permission(permission: dict[str, object]) -> dict[str, object]:
    bash = permission.get("bash")
    if isinstance(bash, str):
        merged_bash = dict(_DEFAULT_BASH_PERMISSION)
        merged_bash["*"] = bash
        permission["bash"] = merged_bash
        return permission
    if isinstance(bash, dict):
        merged_bash = dict(_DEFAULT_BASH_PERMISSION)
        for key, value in bash.items():
            if isinstance(key, str):
                merged_bash[key] = value
        permission["bash"] = merged_bash
        return permission
    wildcard = permission.get("*")
    if isinstance(wildcard, str):
        merged_bash = dict(_DEFAULT_BASH_PERMISSION)
        merged_bash["*"] = wildcard
        permission["bash"] = merged_bash
        return permission
    permission["bash"] = dict(_DEFAULT_BASH_PERMISSION)
    return permission


def _guard_mcp_companion_name(server_name: str) -> str:
    return f"{_GUARD_MCP_COMPANION_PREFIX}{server_name}"


def _source_mcp_server_config(server: ManagedMcpServer) -> dict[str, object] | None:
    from ...ecosystems.opencode import _load_json_or_jsonc

    payload, parse_error, _ = _load_json_or_jsonc(Path(server.config_path))
    if parse_error or not isinstance(payload, dict):
        return None
    mcp = payload.get("mcp")
    if not isinstance(mcp, dict):
        return None
    entry = mcp.get(server.name)
    return entry if isinstance(entry, dict) else None


def _ensure_native_mcp_entries(
    persisted: dict[str, object],
    *,
    servers: tuple[ManagedMcpServer, ...],
    existing_workspace_server_names: set[str],
    context: HarnessContext,
) -> None:
    for server in servers:
        if OpenCodeHarnessAdapter._skip_global_managed_server(server):
            continue
        if OpenCodeHarnessAdapter._should_skip_workspace_override(
            context=context,
            server=server,
            existing_workspace_server_names=existing_workspace_server_names,
        ):
            continue
        if server.name in persisted or not server.command:
            continue
        source_entry = _source_mcp_server_config(server) or {}
        entry: dict[str, object] = dict(source_entry)
        entry["type"] = entry.get("type", "local")
        entry["command"] = [server.command, *server.args]
        entry["enabled"] = server.enabled
        if server.env:
            entry["environment"] = dict(server.env)
        persisted[server.name] = entry


def _persisted_mcp_with_guard_companions(
    current_mcp: object,
    *,
    context: HarnessContext,
    servers: tuple[ManagedMcpServer, ...],
    existing_workspace_server_names: set[str],
) -> dict[str, object]:
    persisted = _persisted_mcp_payload(current_mcp)
    _ensure_native_mcp_entries(
        persisted,
        servers=servers,
        existing_workspace_server_names=existing_workspace_server_names,
        context=context,
    )
    managed_names = {
        server.name for server in servers if not OpenCodeHarnessAdapter._skip_global_managed_server(server)
    }
    stale_companions = [
        name
        for name in persisted
        if isinstance(name, str)
        and name.startswith(_GUARD_MCP_COMPANION_PREFIX)
        and name.removeprefix(_GUARD_MCP_COMPANION_PREFIX) not in managed_names
    ]
    for name in stale_companions:
        persisted.pop(name, None)
    for server in servers:
        if OpenCodeHarnessAdapter._skip_global_managed_server(server):
            continue
        if OpenCodeHarnessAdapter._should_skip_workspace_override(
            context=context,
            server=server,
            existing_workspace_server_names=existing_workspace_server_names,
            for_companion=True,
        ):
            continue
        companion_name = _guard_mcp_companion_name(server.name)
        entry: dict[str, object] = {
            "type": "local",
            "command": [
                str(resolve_guard_hook_python(context)),
                *proxy_cli_args(
                    proxy_command="opencode-mcp-proxy",
                    guard_home=str(context.guard_home),
                    server=server,
                    home=str(context.home_dir) if context.home_dir.resolve() != Path.home().resolve() else None,
                    workspace=None,
                ),
            ],
            "enabled": server.enabled,
        }
        environment = merge_guard_launcher_env(proxy_process_env(getattr(server, "env", {})))
        if environment:
            entry["environment"] = environment
        persisted[companion_name] = entry
        native_entry = persisted.get(server.name)
        if isinstance(native_entry, dict):
            disabled_native = dict(native_entry)
            disabled_native["enabled"] = False
            persisted[server.name] = disabled_native
    return persisted


def _restore_local_server_from_guard_proxy(server_config: dict[str, object]) -> dict[str, object] | None:
    """Rebuild the original local MCP entry from a persisted Guard proxy wrapper."""

    command_value = server_config.get("command")
    if not isinstance(command_value, list):
        return None
    tokens = [token for token in command_value if isinstance(token, str)]
    if "opencode-mcp-proxy" not in tokens:
        return None
    underlying_command: str | None = None
    underlying_args: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--command" and index + 1 < len(tokens):
            underlying_command = tokens[index + 1]
            index += 2
            continue
        if token.startswith("--arg="):
            underlying_args.append(token.split("=", 1)[1])
        index += 1
    if underlying_command is None:
        return None
    restored: dict[str, object] = {
        "type": server_config.get("type", "local"),
        "command": [underlying_command, *underlying_args],
        "enabled": server_config.get("enabled", True),
    }
    environment = server_config.get("environment")
    if isinstance(environment, dict):
        restored["environment"] = environment
    return restored


def _persisted_mcp_payload(current_mcp: object) -> dict[str, object]:
    """Keep native MCP servers on disk; strip legacy in-place proxy wrappers."""

    payload = _object_dict(current_mcp) or {}
    persisted: dict[str, object] = {}
    for name, entry in payload.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            continue
        if name.startswith(_GUARD_MCP_COMPANION_PREFIX):
            continue
        restored = _restore_local_server_from_guard_proxy(entry)
        if restored is not None:
            persisted[name] = restored
            continue
        command, args = _command_parts(entry)
        if is_guard_proxy_command(command, args):
            continue
        persisted[name] = dict(entry)
    return persisted


def _inline_config(raw_content: str | None) -> dict[str, object]:
    if not raw_content:
        return {}
    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError:
        return {}
    parsed = _object_dict(payload)
    return parsed if parsed is not None else {}


def _merge_configs(base: dict[str, object], overlay: dict[str, object]) -> dict[str, object]:
    merged = dict(base)
    for key, value in overlay.items():
        existing_value = merged.get(key)
        nested_overlay = _object_dict(value)
        nested_existing = _object_dict(existing_value)
        if nested_overlay is not None and nested_existing is not None:
            merged[key] = _merge_configs(nested_existing, nested_overlay)
            continue
        merged[key] = value
    return merged


def _object_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(key, str):
            result[key] = item
    return result
