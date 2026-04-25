"""Codex harness adapter."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import sys
from copy import deepcopy
from pathlib import Path

try:  # pragma: no cover - Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from ..codex_config import read_toml_payload, write_toml_payload
from ..launcher import merge_guard_launcher_env
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available
from .mcp_servers import (
    ManagedMcpServer,
    is_guard_proxy_command,
    managed_stdio_servers,
    proxy_cli_args,
    skipped_stdio_server_names,
)


def _read_toml(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
        return payload if isinstance(payload, dict) else {}
    except (OSError, tomllib.TOMLDecodeError):
        return {}


_MANAGED_HOOK_STATUS_MESSAGE = "HOL Guard checking tool action"
_MANAGED_PROMPT_HOOK_STATUS_MESSAGE = "HOL Guard checking prompt"
_MANAGED_PERMISSION_HOOK_STATUS_MESSAGE = "HOL Guard checking Codex approval request"
_LEGACY_MANAGED_HOOK_STATUS_MESSAGES = {
    "HOL Guard checking Bash command",
    _MANAGED_HOOK_STATUS_MESSAGE,
    _MANAGED_PROMPT_HOOK_STATUS_MESSAGE,
    _MANAGED_PERMISSION_HOOK_STATUS_MESSAGE,
}


def _json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _strict_json_object(path: Path, *, label: str) -> dict[str, object]:
    if path.exists() and not path.is_file():
        raise RuntimeError(f"Guard refused to overwrite non-file {label} at {path}")
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Guard refused to overwrite unreadable {label} at {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Guard refused to overwrite non-object {label} at {path}")
    return payload


def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    guard_args = [
        "guard",
        "hook",
        "--guard-home",
        str(context.guard_home),
        "--harness",
        "codex",
    ]
    if context.home_dir.resolve() != Path.home().resolve():
        guard_args.extend(["--home", str(context.home_dir)])
    if context.workspace_dir is not None:
        guard_args.extend(["--workspace", str(context.workspace_dir)])
    launcher_env = merge_guard_launcher_env()
    pythonpath = launcher_env.get("PYTHONPATH", "")
    if not pythonpath.strip():
        return (sys.executable, "-m", "codex_plugin_scanner.cli", *guard_args)
    path_entries = [entry for entry in pythonpath.split(os.pathsep) if entry.strip()]
    code = (
        "import sys;"
        f"sys.path[:0]={path_entries!r};"
        "from codex_plugin_scanner.cli import main;"
        f"raise SystemExit(main({guard_args!r}))"
    )
    return (sys.executable, "-c", code)


def _hook_command(context: HarnessContext) -> str:
    return shlex.join(_hook_command_parts(context))


def _pre_tool_hook_group(context: HarnessContext) -> dict[str, object]:
    return {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": _hook_command(context),
                "timeoutSec": 30,
                "statusMessage": _MANAGED_HOOK_STATUS_MESSAGE,
            }
        ],
    }


def _prompt_hook_group(context: HarnessContext) -> dict[str, object]:
    return {
        "hooks": [
            {
                "type": "command",
                "command": _hook_command(context),
                "timeoutSec": 30,
                "statusMessage": _MANAGED_PROMPT_HOOK_STATUS_MESSAGE,
            }
        ],
    }


def _permission_request_hook_group(context: HarnessContext) -> dict[str, object]:
    return {
        "matcher": "Bash|^apply_patch$|Edit|Write|mcp__.*",
        "hooks": [
            {
                "type": "command",
                "command": _hook_command(context),
                "timeoutSec": 30,
                "statusMessage": _MANAGED_PERMISSION_HOOK_STATUS_MESSAGE,
            }
        ],
    }


def _managed_hook_groups(context: HarnessContext) -> dict[str, dict[str, object]]:
    return {
        "PreToolUse": _pre_tool_hook_group(context),
        "PermissionRequest": _permission_request_hook_group(context),
        "UserPromptSubmit": _prompt_hook_group(context),
    }


def _is_managed_hook_command(command: object) -> bool:
    if not isinstance(command, str):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if len(tokens) < 3:
        return False
    executable = Path(tokens[0]).name.lower()
    if not executable.startswith("python"):
        return False
    if tokens[1] == "-m":
        if len(tokens) < 5:
            return False
        return (
            tokens[2] == "codex_plugin_scanner.cli"
            and tokens[3] == "guard"
            and tokens[4] == "hook"
            and _argv_targets_codex(tokens[5:])
        )
    if tokens[1] != "-c":
        return False
    code = tokens[2]
    return (
        "codex_plugin_scanner.cli" in code
        and "main([" in code
        and "'guard'" in code
        and "'hook'" in code
        and "'--harness'" in code
        and "'codex'" in code
    )


def _argv_targets_codex(argv: list[str]) -> bool:
    for index, token in enumerate(argv):
        if token == "--harness" and index + 1 < len(argv) and argv[index + 1] == "codex":
            return True
        if token.startswith("--harness=") and token.split("=", 1)[1] == "codex":
            return True
    return False


def _is_managed_hook_group(group: object) -> bool:
    if not isinstance(group, dict):
        return False
    hooks = group.get("hooks")
    if not isinstance(hooks, list):
        return False
    return any(_is_managed_hook_entry(entry) for entry in hooks)


def _is_managed_hook_entry(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    status_message = entry.get("statusMessage")
    has_managed_status = isinstance(status_message, str) and status_message in _LEGACY_MANAGED_HOOK_STATUS_MESSAGES
    return entry.get("type") == "command" and has_managed_status and _is_managed_hook_command(entry.get("command"))


def _remove_managed_hook_entries(group: object) -> object | None:
    if not isinstance(group, dict):
        return group
    hooks = group.get("hooks")
    if not isinstance(hooks, list):
        return group
    remaining_hooks = [entry for entry in hooks if not _is_managed_hook_entry(entry)]
    if len(remaining_hooks) == len(hooks):
        return group
    if not remaining_hooks:
        return None
    updated_group = dict(group)
    updated_group["hooks"] = remaining_hooks
    return updated_group


def _merge_hook_groups(groups: object, managed_group: dict[str, object]) -> list[object]:
    return [*_remove_hook_groups(groups), managed_group]


def _remove_hook_groups(groups: object) -> list[object]:
    if not isinstance(groups, list):
        return []
    remaining: list[object] = []
    for group in groups:
        cleaned_group = _remove_managed_hook_entries(group)
        if cleaned_group is not None:
            remaining.append(cleaned_group)
    return remaining


def _remove_managed_hook_events(hooks: dict[str, object]) -> tuple[dict[str, object], bool]:
    updated_hooks = dict(hooks)
    changed = False
    for event_name in ("PreToolUse", "PermissionRequest", "UserPromptSubmit"):
        original_groups = deepcopy(updated_hooks.get(event_name))
        remaining = _remove_hook_groups(original_groups)
        managed_removed = isinstance(original_groups, list) and remaining != original_groups
        if not managed_removed:
            continue
        changed = True
        if remaining:
            updated_hooks[event_name] = remaining
        else:
            updated_hooks.pop(event_name, None)
    return updated_hooks, changed


def codex_native_hook_state(context: HarnessContext) -> dict[str, object]:
    config_path = CodexHarnessAdapter._target_config_path(context)
    hooks_path = CodexHarnessAdapter._hooks_path(context)
    config_payload = _read_toml(config_path)
    features = config_payload.get("features") if isinstance(config_payload, dict) else None
    hooks_payload = _json_object(hooks_path)
    hooks = hooks_payload.get("hooks") if isinstance(hooks_payload, dict) else None
    pre_tool_groups = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    permission_groups = hooks.get("PermissionRequest") if isinstance(hooks, dict) else None
    prompt_groups = hooks.get("UserPromptSubmit") if isinstance(hooks, dict) else None
    pre_tool_hook_installed = isinstance(pre_tool_groups, list) and any(
        _is_managed_hook_group(group) for group in pre_tool_groups
    )
    permission_hook_installed = isinstance(permission_groups, list) and any(
        _is_managed_hook_group(group) for group in permission_groups
    )
    prompt_hook_installed = isinstance(prompt_groups, list) and any(
        _is_managed_hook_group(group) for group in prompt_groups
    )
    managed_hook_installed = pre_tool_hook_installed and permission_hook_installed and prompt_hook_installed
    return {
        "config_path": str(config_path),
        "config_present": config_path.is_file(),
        "hooks_path": str(hooks_path),
        "hooks_present": hooks_path.is_file(),
        "codex_hooks_enabled": isinstance(features, dict) and features.get("codex_hooks") is True,
        "managed_pre_tool_hook_installed": pre_tool_hook_installed,
        "managed_permission_request_hook_installed": permission_hook_installed,
        "managed_prompt_hook_installed": prompt_hook_installed,
        "managed_hook_installed": managed_hook_installed,
        "protection_active": isinstance(features, dict)
        and features.get("codex_hooks") is True
        and managed_hook_installed,
    }


class CodexHarnessAdapter(HarnessAdapter):
    """Discover Codex MCP servers and wrapper surfaces."""

    harness = "codex"
    executable = "codex"
    approval_tier = "native-or-center"
    approval_summary = (
        "Guard installs native Codex Bash hooks for shell interception, PermissionRequest hooks for Codex approval "
        "prompts, prompt hooks for sensitive file-read requests, keeps same-chat approvals for managed MCP tool "
        "calls, and falls back to the local approval center when Codex cannot answer."
    )
    fallback_hint = (
        "If Codex cannot render or return the inline approval request, or a native Bash hook blocks a "
        "sensitive command, Guard will queue it in the local approval center."
    )
    approval_prompt_channel = "native"
    approval_auto_open_browser = False

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".codex" / "config.toml"
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _hooks_path(context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".codex" / "hooks.json"
        return context.home_dir / ".codex" / "hooks.json"

    @staticmethod
    def _all_hook_paths(context: HarnessContext) -> tuple[Path, ...]:
        paths = [context.home_dir / ".codex" / "hooks.json"]
        if context.workspace_dir is not None:
            paths.append(context.workspace_dir / ".codex" / "hooks.json")
        return tuple(paths)

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
                    if is_guard_proxy_command(command if isinstance(command, str) else None, args):
                        continue
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
        hooks_paths = [context.home_dir / ".codex" / "hooks.json"]
        if context.workspace_dir is not None:
            hooks_paths.append(context.workspace_dir / ".codex" / "hooks.json")
        for hooks_path in hooks_paths:
            hooks_payload = _json_object(hooks_path)
            hooks = hooks_payload.get("hooks")
            if not isinstance(hooks, dict):
                continue
            found_paths.append(str(hooks_path))
            scope = self._scope_for(context, hooks_path)
            hook_groups = hooks.get("PreToolUse")
            if not isinstance(hook_groups, list):
                continue
            for group_index, group in enumerate(hook_groups):
                if not isinstance(group, dict):
                    continue
                handlers = group.get("hooks")
                if not isinstance(handlers, list):
                    continue
                for handler_index, handler in enumerate(handlers):
                    if not isinstance(handler, dict):
                        continue
                    command = handler.get("command")
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"codex:{scope}:pretooluse:{group_index}:{handler_index}",
                            name="PreToolUse",
                            harness=self.harness,
                            artifact_type="hook",
                            source_scope=scope,
                            config_path=str(hooks_path),
                            command=command if isinstance(command, str) else None,
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
        hook_payloads = self._load_hook_payloads(context)
        original_text = target_config_path.read_text(encoding="utf-8") if target_config_path.is_file() else None
        backup_path = self._backup_path(context)
        if not backup_path.exists():
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_path.write_text(original_text or "", encoding="utf-8")
        payload = read_toml_payload(target_config_path)
        mcp_servers = payload.get("mcp_servers")
        if not isinstance(mcp_servers, dict):
            mcp_servers = {}
        features = payload.get("features")
        if not isinstance(features, dict):
            features = {}
        features["codex_hooks"] = True
        payload["features"] = features
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
        hooks_path = self._install_hooks(context, payloads=hook_payloads)
        shim_manifest = install_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(target_config_path),
            **shim_manifest,
            "mode": "codex-mcp-proxy",
            "managed_config_path": str(target_config_path),
            "managed_hooks_path": str(hooks_path),
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
        hooks_path = self._remove_hooks(context)
        shim_manifest = remove_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(target_config_path),
            **shim_manifest,
            "mode": "codex-mcp-proxy",
            "managed_config_path": str(target_config_path),
            "managed_hooks_path": str(hooks_path),
            "backup_path": str(backup_path),
        }

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        payload = super().diagnostics(context)
        hook_state = codex_native_hook_state(context)
        warnings = [str(item) for item in payload.get("warnings", []) if isinstance(item, str)]
        if bool(hook_state["config_present"]) and not bool(hook_state["codex_hooks_enabled"]):
            warnings.append(
                "Codex config was found, but native hooks are disabled. Run `hol-guard install codex` or "
                "`hol-guard update` to repair protection."
            )
        if bool(hook_state["config_present"]) and not bool(hook_state["managed_hook_installed"]):
            warnings.append(
                "Codex config was found, but Guard's managed Codex hooks are missing. Run "
                "`hol-guard install codex` or `hol-guard update` to repair protection."
            )
        payload["warnings"] = warnings
        payload["native_hook_state"] = hook_state
        return payload

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
        env = merge_guard_launcher_env(getattr(server, "env", {}))
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

    def _load_hook_payloads(self, context: HarnessContext) -> dict[Path, dict[str, object]]:
        return {
            hooks_path: _strict_json_object(hooks_path, label="Codex hooks file")
            for hooks_path in self._all_hook_paths(context)
        }

    def _install_hooks(self, context: HarnessContext, *, payloads: dict[Path, dict[str, object]] | None = None) -> Path:
        target_hooks_path = self._hooks_path(context)
        managed_groups = _managed_hook_groups(context)
        hook_payloads = payloads or self._load_hook_payloads(context)
        for hooks_path in self._all_hook_paths(context):
            original_payload = deepcopy(hook_payloads.get(hooks_path, {}))
            payload = deepcopy(original_payload)
            hooks = payload.get("hooks")
            if not isinstance(hooks, dict):
                hooks = {}
            cleaned_hooks, managed_removed = _remove_managed_hook_events(hooks)
            if hooks_path == target_hooks_path:
                for event_name, managed_group in managed_groups.items():
                    cleaned_hooks[event_name] = _merge_hook_groups(cleaned_hooks.get(event_name), managed_group)
                payload["hooks"] = cleaned_hooks
            elif not managed_removed:
                payload = deepcopy(original_payload)
            else:
                if cleaned_hooks:
                    payload["hooks"] = cleaned_hooks
                else:
                    payload.pop("hooks", None)
            self._write_hooks_payload(hooks_path, payload, original_payload=original_payload)
        return target_hooks_path

    def _remove_hooks(self, context: HarnessContext, *, payloads: dict[Path, dict[str, object]] | None = None) -> Path:
        target_hooks_path = self._hooks_path(context)
        hook_payloads = payloads or {}
        for hooks_path in self._all_hook_paths(context):
            original_payload = deepcopy(hook_payloads.get(hooks_path, _json_object(hooks_path)))
            payload = deepcopy(original_payload)
            if not payload and hooks_path.exists():
                continue
            hooks = payload.get("hooks")
            if isinstance(hooks, dict):
                cleaned_hooks, managed_removed = _remove_managed_hook_events(hooks)
                if not managed_removed:
                    payload = deepcopy(original_payload)
                elif cleaned_hooks:
                    payload["hooks"] = cleaned_hooks
                else:
                    payload.pop("hooks", None)
            self._write_hooks_payload(hooks_path, payload, original_payload=original_payload)
        return target_hooks_path

    @staticmethod
    def _write_hooks_payload(
        hooks_path: Path,
        payload: dict[str, object],
        *,
        original_payload: dict[str, object] | None = None,
    ) -> None:
        if original_payload is not None and payload == original_payload:
            return
        if payload:
            hooks_path.parent.mkdir(parents=True, exist_ok=True)
            hooks_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        elif hooks_path.exists():
            hooks_path.unlink()
