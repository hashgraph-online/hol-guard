"""Microsoft Copilot CLI harness adapter."""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

from ..launcher import merge_guard_launcher_env
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _json_payload, _run_command_probe
from .mcp_servers import (
    ManagedMcpServer,
    is_guard_proxy_command,
    managed_stdio_servers,
    proxy_cli_args,
    skipped_stdio_server_names,
)

_MANAGED_HOOK_EVENTS = ("userPromptSubmitted", "preToolUse", "postToolUse", "permissionRequest")
_DETECTABLE_HOOK_EVENTS = (
    "sessionStart",
    "sessionEnd",
    "userPromptSubmitted",
    "preToolUse",
    "postToolUse",
    "permissionRequest",
    "errorOccurred",
)
_MANAGED_HOOK_FILENAME = "hol-guard-copilot.json"
_LEGACY_MANAGED_HOOK_PATTERNS = (
    re.compile(r'(^|["\s])-m["\s]+codex_plugin_scanner\.cli(["\s]|$)'),
    re.compile(r'(^|["\s])guard(["\s]|$)'),
    re.compile(r'(^|["\s])hook(["\s]|$)'),
    re.compile(r'--harness(?:["\s=]+)copilot(["\s]|$)'),
)
_INLINE_GUARD_ARGS_PATTERN = re.compile(r"json\.loads\((?P<payload>'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")\)")


def _hook_command_parts(context: HarnessContext, *, include_workspace: bool) -> tuple[str, ...]:
    guard_args = [
        "guard",
        "hook",
        "--guard-home",
        str(context.guard_home),
        "--harness",
        "copilot",
    ]
    if context.home_dir.resolve() != Path.home().resolve():
        guard_args.extend(["--home", str(context.home_dir)])
    if include_workspace and context.workspace_dir is not None:
        guard_args.extend(["--workspace", str(context.workspace_dir)])
    trusted_path_entries = _trusted_pythonpath_entries()
    guard_args_json = json.dumps(guard_args)
    code = (
        "import json,sys;"
        f"sys.path[:0]={trusted_path_entries!r};"
        "from codex_plugin_scanner.cli import main;"
        f"raise SystemExit(main(json.loads({guard_args_json!r})))"
    )
    return (sys.executable, "-c", code)


def _hook_shell_commands(context: HarnessContext, *, include_workspace: bool) -> tuple[str, str]:
    command_parts = _hook_command_parts(context, include_workspace=include_workspace)
    return shlex.join(command_parts), subprocess.list2cmdline(list(command_parts))


def _hook_entry(context: HarnessContext, *, include_workspace: bool) -> dict[str, object]:
    bash_command, powershell_command = _hook_shell_commands(context, include_workspace=include_workspace)
    entry: dict[str, object] = {
        "type": "command",
        "bash": bash_command,
        "powershell": powershell_command,
        "cwd": str(context.guard_home),
        "timeoutSec": 30,
    }
    env = merge_guard_launcher_env()
    if env:
        entry["env"] = env
    return entry


def _is_managed_hook_command(command: str) -> bool:
    normalized_command = command.lower()
    if all(pattern.search(normalized_command) is not None for pattern in _LEGACY_MANAGED_HOOK_PATTERNS):
        return True
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if len(tokens) < 3:
        return False
    executable = Path(tokens[0]).name.lower()
    if not executable.startswith("python") or tokens[1] != "-c":
        return False
    inline_code = tokens[2]
    inline_args = _inline_guard_args(inline_code)
    return "codex_plugin_scanner.cli" in inline_code and _argv_targets_copilot(inline_args)


def _trusted_pythonpath_entries() -> list[str]:
    launcher_env = merge_guard_launcher_env()
    path_entries = [entry for entry in launcher_env.get("PYTHONPATH", "").split(os.pathsep) if entry.strip()]
    package_root = _trusted_package_root()
    cli_entrypoint = package_root / "codex_plugin_scanner" / "cli.py"
    if not cli_entrypoint.is_file():
        raise RuntimeError(f"Guard could not locate the trusted CLI entrypoint at {cli_entrypoint}")
    package_root_str = str(package_root)
    if package_root_str not in path_entries:
        path_entries.insert(0, package_root_str)
    return path_entries


def _trusted_package_root() -> Path:
    spec = importlib.util.find_spec("codex_plugin_scanner")
    if spec is None:
        raise RuntimeError("Guard could not locate the codex_plugin_scanner package")
    if spec.submodule_search_locations:
        return Path(next(iter(spec.submodule_search_locations))).resolve().parent
    if spec.origin is None:
        raise RuntimeError("Guard could not determine the codex_plugin_scanner package root")
    return Path(spec.origin).resolve().parent.parent


def _inline_guard_args(inline_code: str) -> tuple[str, ...]:
    match = _INLINE_GUARD_ARGS_PATTERN.search(inline_code)
    if match is None:
        return ()
    try:
        payload = ast.literal_eval(match.group("payload"))
    except (SyntaxError, ValueError):
        return ()
    if not isinstance(payload, str):
        return ()
    try:
        guard_args = json.loads(payload)
    except json.JSONDecodeError:
        return ()
    if not isinstance(guard_args, list) or any(not isinstance(item, str) for item in guard_args):
        return ()
    return tuple(item.lower() for item in guard_args)


def _argv_targets_copilot(argv: tuple[str, ...]) -> bool:
    for index, token in enumerate(argv):
        if token == "--harness" and index + 1 < len(argv) and argv[index + 1] == "copilot":
            return "guard" in argv and "hook" in argv
        if token.startswith("--harness=") and token.split("=", 1)[1] == "copilot":
            return "guard" in argv and "hook" in argv
    return False


def _is_managed_hook_entry(entry: object, bash_command: str, powershell_command: str) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry.get("bash") == bash_command and entry.get("powershell") == powershell_command:
        return True
    for command in (entry.get("command"), entry.get("bash"), entry.get("powershell")):
        if not isinstance(command, str):
            continue
        if command in {bash_command, powershell_command}:
            return True
        if _is_managed_hook_command(command):
            return True
    return False


def _merge_hook_entries(entries: object, hook_entry: dict[str, object]) -> list[object]:
    normalized = list(entries) if isinstance(entries, list) else []
    bash_command = str(hook_entry["bash"])
    powershell_command = str(hook_entry["powershell"])
    preserved_entries = [
        entry for entry in normalized if not _is_managed_hook_entry(entry, bash_command, powershell_command)
    ]
    return [*preserved_entries, hook_entry]


def _remove_hook_entries(entries: object, bash_command: str, powershell_command: str) -> list[object]:
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if not _is_managed_hook_entry(entry, bash_command, powershell_command)]


def _hooks_payload(payload: dict[str, object]) -> dict[str, object]:
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        return hooks
    return payload


def _inline_hooks_payload(payload: dict[str, object]) -> dict[str, object]:
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        normalized = {
            str(hook_name): list(entries) if isinstance(entries, list) else entries
            for hook_name, entries in hooks.items()
        }
        payload["hooks"] = normalized
        return normalized
    normalized: dict[str, object] = {}
    payload["hooks"] = normalized
    return normalized


def _hook_command_variants(entry: dict[str, object]) -> tuple[tuple[str, str], ...]:
    variants: list[tuple[str, str]] = []
    for shell_name in ("command", "bash", "powershell"):
        command = entry.get(shell_name)
        if not isinstance(command, str):
            continue
        variants.append((shell_name, command))
    return tuple(variants)


def _managed_hook_payload(payload: dict[str, object]) -> dict[str, object]:
    normalized_payload: dict[str, object] = {"version": 1, "hooks": {}}
    version = payload.get("version")
    if isinstance(version, int):
        normalized_payload["version"] = version
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        normalized_payload["hooks"] = {
            str(hook_name): list(entries) if isinstance(entries, list) else entries
            for hook_name, entries in hooks.items()
        }
        return normalized_payload
    normalized_payload["hooks"] = {
        str(hook_name): list(entries)
        for hook_name, entries in payload.items()
        if hook_name != "version" and hook_name not in _MANAGED_HOOK_EVENTS and isinstance(entries, list)
    }
    return normalized_payload


def _mcp_servers_payload(target_path: Path, payload: dict[str, object]) -> dict[str, object] | None:
    preferred_key = CopilotHarnessAdapter._mcp_payload_key(target_path, payload)
    preferred_servers = payload.get(preferred_key)
    if isinstance(preferred_servers, dict):
        return preferred_servers
    fallback_key = "servers" if preferred_key == "mcpServers" else "mcpServers"
    fallback_servers = payload.get(fallback_key)
    if isinstance(fallback_servers, dict):
        return fallback_servers
    return None


def _command_parts(server_config: dict[str, object]) -> tuple[str | None, tuple[str, ...]]:
    command = server_config.get("command")
    args = tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str))
    if isinstance(command, str):
        return command, args
    if isinstance(command, list):
        command_parts = [str(value) for value in command if isinstance(value, str)]
        if len(command_parts) == 0:
            return None, args
        return command_parts[0], (*tuple(command_parts[1:]), *args)
    return None, args


def _refresh_guard_proxy_entry(
    server_config: dict[str, object],
    *,
    launcher_env: dict[str, str],
) -> dict[str, object]:
    refreshed = dict(server_config)
    _command, args = _command_parts(server_config)
    refreshed["command"] = sys.executable
    refreshed["args"] = list(args)
    if launcher_env:
        refreshed["env"] = launcher_env
    else:
        refreshed.pop("env", None)
        refreshed.pop("environment", None)
    return refreshed


class CopilotHarnessAdapter(HarnessAdapter):
    """Discover Microsoft Copilot CLI repo hooks and MCP config artifacts."""

    harness = "copilot"
    executable = "copilot"
    approval_tier = "native-or-center"
    approval_summary = (
        "Guard uses native Copilot prompts through Copilot CLI hook surfaces and VS Code workspace hooks when "
        "those surfaces are installed. Guard falls back to the local approval center only when the active Copilot "
        "surface cannot prompt."
    )
    fallback_hint = (
        "Guard prefers native Copilot prompts where the active Copilot surface exposes them. Proof for Copilot "
        "should come from native hook responses and Guard runtime receipts in Copilot CLI or VS Code workspace "
        "hooks, or from the local approval center when prompting is unavailable."
    )
    approval_prompt_channel = "hook"
    approval_auto_open_browser = False

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        del context
        return (Path.home() / ".local" / "copilot-cli" / "copilot",)

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    @staticmethod
    def _hook_path(context: HarnessContext) -> Path | None:
        if context.workspace_dir is None:
            return None
        return context.workspace_dir / ".github" / "hooks" / _MANAGED_HOOK_FILENAME

    @staticmethod
    def _config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".copilot" / "config.json"

    @staticmethod
    def _workspace_mcp_paths(context: HarnessContext) -> tuple[Path, ...]:
        if context.workspace_dir is None:
            return ()
        return (
            context.workspace_dir / ".mcp.json",
            context.workspace_dir / ".vscode" / "mcp.json",
        )

    @staticmethod
    def _target_mcp_paths(context: HarnessContext) -> tuple[Path, ...]:
        workspace_paths = CopilotHarnessAdapter._workspace_mcp_paths(context)
        if len(workspace_paths) > 0:
            return workspace_paths
        return (context.home_dir / ".copilot" / "mcp-config.json",)

    @staticmethod
    def _backup_path(target_path: Path, context: HarnessContext) -> Path:
        target = str(target_path.resolve())
        digest = sha256(target.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "copilot" / f"{digest}.backup.json"

    @staticmethod
    def _mcp_payload_key(target_path: Path, payload: dict[str, object]) -> str:
        if "mcpServers" in payload and "servers" not in payload:
            return "mcpServers"
        if "servers" in payload and "mcpServers" not in payload:
            return "servers"
        if target_path.name in {".mcp.json", "mcp-config.json"}:
            return "mcpServers"
        return "servers"

    @staticmethod
    def _strict_json_object(path: Path, *, label: str, recover_malformed: bool = False) -> dict[str, object]:
        if not path.is_file():
            return {}
        try:
            raw_text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Guard refused to overwrite unreadable {label} at {path}") from exc
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            if recover_malformed:
                return {}
            raise RuntimeError(f"Guard refused to overwrite unreadable {label} at {path}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError(f"Guard refused to overwrite non-object {label} at {path}")
        return payload

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_candidates = [
            context.home_dir / ".copilot" / "config.json",
            context.home_dir / ".copilot" / "mcp-config.json",
        ]
        config_candidates.extend(self._workspace_mcp_paths(context))
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        for config_path in config_candidates:
            payload = _json_payload(config_path)
            if not payload:
                continue
            found_paths.append(str(config_path))
            scope = self._scope_for(context, config_path)
            hook_artifacts = self._hook_artifacts(config_path, payload, scope)
            if len(hook_artifacts) > 0:
                artifacts.extend(hook_artifacts)
            if config_path.name == "mcp-config.json" or config_path in self._workspace_mcp_paths(context):
                artifacts.extend(self._mcp_artifacts(config_path, payload, scope))
        if context.workspace_dir is not None:
            hooks_dir = context.workspace_dir / ".github" / "hooks"
            if hooks_dir.is_dir():
                for hook_path in sorted(path for path in hooks_dir.glob("*.json") if path.is_file()):
                    payload = _json_payload(hook_path)
                    if not payload:
                        continue
                    hook_artifacts = self._hook_artifacts(hook_path, payload, "project")
                    if len(hook_artifacts) == 0:
                        continue
                    found_paths.append(str(hook_path))
                    artifacts.extend(hook_artifacts)
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or self.resolved_executable(context) is not None,
            command_available=self.resolved_executable(context) is not None,
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        detection = self.detect(context)
        managed_servers = managed_stdio_servers(detection)
        skipped_servers = skipped_stdio_server_names(detection)
        target_mcp_paths = self._target_mcp_paths(context)
        backup_paths: list[str] = []
        state_paths: list[str] = []
        for target_mcp_path in target_mcp_paths:
            original_text = target_mcp_path.read_text(encoding="utf-8") if target_mcp_path.is_file() else None
            backup_path = self._backup_path(target_mcp_path, context)
            backup_paths.append(str(backup_path))
            if not backup_path.exists():
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                backup_payload = {"existed": original_text is not None, "content": original_text}
                backup_path.write_text(json.dumps(backup_payload, indent=2) + "\n", encoding="utf-8")
            state_path = self._state_path(target_mcp_path, context)
            state_paths.append(str(state_path))
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps(
                    {
                        "managed_config_path": str(target_mcp_path),
                        "backup_path": str(backup_path),
                        "scope": self._scope_for(context, target_mcp_path),
                        "workspace_dir": (
                            str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None
                        ),
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            mcp_payload = _json_payload(target_mcp_path)
            existing_servers = _mcp_servers_payload(target_mcp_path, mcp_payload)
            normalized_servers = dict(existing_servers) if isinstance(existing_servers, dict) else {}
            for name, server_config in tuple(normalized_servers.items()):
                if not isinstance(name, str) or not isinstance(server_config, dict):
                    continue
                command, args = _command_parts(server_config)
                if not is_guard_proxy_command(command, args):
                    continue
                existing_env = server_config.get("env")
                if not isinstance(existing_env, dict):
                    existing_env = server_config.get("environment")
                normalized_servers[name] = _refresh_guard_proxy_entry(
                    server_config,
                    launcher_env=merge_guard_launcher_env(existing_env if isinstance(existing_env, dict) else {}),
                )
            existing_workspace_server_names = {
                name
                for name, server in normalized_servers.items()
                if isinstance(name, str) and isinstance(server, dict)
            }
            for server in self._managed_servers_for_target(managed_servers, target_mcp_path):
                if self._should_skip_workspace_override(
                    context=context,
                    server=server,
                    existing_workspace_server_names=existing_workspace_server_names,
                ):
                    continue
                normalized_servers[server.name] = self._proxy_server_entry(context, server, target_mcp_path)
            payload_key = self._mcp_payload_key(target_mcp_path, mcp_payload)
            mcp_payload[payload_key] = normalized_servers
            alternate_key = "servers" if payload_key == "mcpServers" else "mcpServers"
            mcp_payload.pop(alternate_key, None)
            target_mcp_path.parent.mkdir(parents=True, exist_ok=True)
            target_mcp_path.write_text(json.dumps(mcp_payload, indent=2) + "\n", encoding="utf-8")
        shim_manifest = install_guard_shim(self.harness, context)
        primary_target_mcp_path = target_mcp_paths[0]
        primary_backup_path = backup_paths[0]
        primary_state_path = state_paths[0]
        config_path = self._config_path(context)
        config_payload = self._strict_json_object(config_path, label="Copilot config", recover_malformed=True)
        hooks_payload = _inline_hooks_payload(config_payload)
        hook_entry = _hook_entry(context, include_workspace=False)
        for hook_name in _MANAGED_HOOK_EVENTS:
            hooks_payload[hook_name] = _merge_hook_entries(hooks_payload.get(hook_name), hook_entry)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config_payload, indent=2) + "\n", encoding="utf-8")
        managed_hook_path = self._hook_path(context)
        if managed_hook_path is not None:
            managed_hook_payload = _managed_hook_payload(_json_payload(managed_hook_path))
            managed_workspace_hooks = managed_hook_payload["hooks"]
            managed_workspace_entry = _hook_entry(context, include_workspace=True)
            for hook_name in _MANAGED_HOOK_EVENTS:
                managed_workspace_hooks[hook_name] = _merge_hook_entries(
                    managed_workspace_hooks.get(hook_name),
                    managed_workspace_entry,
                )
            managed_hook_path.parent.mkdir(parents=True, exist_ok=True)
            managed_hook_path.write_text(json.dumps(managed_hook_payload, indent=2) + "\n", encoding="utf-8")
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(config_path),
            **shim_manifest,
            "managed_config_path": str(primary_target_mcp_path),
            "managed_config_paths": [str(path) for path in target_mcp_paths],
            "backup_path": primary_backup_path,
            "backup_paths": backup_paths,
            "state_path": primary_state_path,
            "state_paths": state_paths,
            "managed_servers": [server.name for server in managed_servers],
            "skipped_servers": list(skipped_servers),
            "notes": [
                "Guard hook entries added to ~/.copilot/config.json for Copilot CLI.",
                "Guard workspace hook entries added to .github/hooks/hol-guard-copilot.json for VS Code Copilot.",
                "Guard MCP proxies added to Copilot CLI and VS Code workspace MCP config files.",
                *[str(note) for note in shim_manifest.get("notes", [])],
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        uninstall_targets = self._uninstall_targets(context)
        for state_path, target_mcp_path, backup_path in uninstall_targets:
            cleanup_complete = False
            if not backup_path.is_file():
                continue
            backup_payload = self._backup_payload(backup_path)
            if backup_payload["readable"] is not True:
                continue
            if backup_payload["existed"] and isinstance(backup_payload["content"], str):
                target_mcp_path.parent.mkdir(parents=True, exist_ok=True)
                target_mcp_path.write_text(str(backup_payload["content"]), encoding="utf-8")
                cleanup_complete = True
            elif backup_payload["existed"] is not True and target_mcp_path.is_file():
                target_mcp_path.unlink()
                cleanup_complete = True
            elif backup_payload["existed"] is not True:
                cleanup_complete = True
            if cleanup_complete:
                backup_path.unlink()
            if cleanup_complete and state_path.is_file():
                state_path.unlink()
        shim_manifest = remove_guard_shim(self.harness, context)
        remaining_state_entries = self._state_entries(context)
        managed_config_paths = [str(target_path) for _state_path, target_path, _backup_path in uninstall_targets]
        backup_paths = [str(backup_path) for _state_path, _target_path, backup_path in uninstall_targets]
        state_paths = [str(state_path) for state_path, _target_path, _backup_path in uninstall_targets]
        primary_target_mcp_path = managed_config_paths[0] if managed_config_paths else ""
        primary_backup_path = backup_paths[0] if backup_paths else ""
        primary_state_path = state_paths[0] if state_paths else ""
        config_path = self._config_path(context)
        config_payload = self._strict_json_object(config_path, label="Copilot config")
        hooks_payload = _inline_hooks_payload(config_payload)
        bash_command, powershell_command = _hook_shell_commands(context, include_workspace=False)
        if len(remaining_state_entries) == 0:
            for hook_name in _MANAGED_HOOK_EVENTS:
                updated_entries = _remove_hook_entries(hooks_payload.get(hook_name), bash_command, powershell_command)
                if len(updated_entries) > 0:
                    hooks_payload[hook_name] = updated_entries
                    continue
                hooks_payload.pop(hook_name, None)
            if len(hooks_payload) == 0:
                config_payload.pop("hooks", None)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config_payload, indent=2) + "\n", encoding="utf-8")
        managed_hook_path = self._hook_path(context)
        if managed_hook_path is not None and managed_hook_path.is_file():
            managed_hook_payload = _managed_hook_payload(_json_payload(managed_hook_path))
            managed_workspace_hooks = managed_hook_payload["hooks"]
            managed_bash_command, managed_powershell_command = _hook_shell_commands(
                context,
                include_workspace=True,
            )
            for hook_name in _MANAGED_HOOK_EVENTS:
                updated_entries = _remove_hook_entries(
                    managed_workspace_hooks.get(hook_name),
                    managed_bash_command,
                    managed_powershell_command,
                )
                if len(updated_entries) > 0:
                    managed_workspace_hooks[hook_name] = updated_entries
                    continue
                managed_workspace_hooks.pop(hook_name, None)
            if len(managed_workspace_hooks) > 0:
                managed_hook_path.parent.mkdir(parents=True, exist_ok=True)
                managed_hook_path.write_text(json.dumps(managed_hook_payload, indent=2) + "\n", encoding="utf-8")
            else:
                managed_hook_path.unlink()
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(config_path),
            **shim_manifest,
            "managed_config_path": primary_target_mcp_path,
            "managed_config_paths": managed_config_paths,
            "backup_path": primary_backup_path,
            "backup_paths": backup_paths,
            "state_path": primary_state_path,
            "state_paths": state_paths,
            "notes": [
                "Guard hook entries removed from ~/.copilot/config.json for Copilot CLI.",
                "Guard workspace hook entries removed from .github/hooks/hol-guard-copilot.json for VS Code Copilot.",
                "Guard restored the prior Copilot MCP config for the active Copilot surfaces.",
                *[str(note) for note in shim_manifest.get("notes", [])],
            ],
        }

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        executable = self.resolved_executable(context)
        if executable is None:
            return None
        return _run_command_probe([executable, "--help"])

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        executable = self.resolved_executable(context) or self.executable
        workspace_paths = self._workspace_mcp_paths(context)
        cli_workspace_config = next(
            (path for path in workspace_paths if path.name == ".mcp.json" and path.is_file()),
            None,
        )
        if cli_workspace_config is None:
            return [executable, *passthrough_args]
        return [
            executable,
            "--additional-mcp-config",
            f"@{cli_workspace_config}",
            *passthrough_args,
        ]

    def diagnostic_warnings(
        self,
        detection: HarnessDetection,
        runtime_probe: dict[str, object] | None,
    ) -> list[str]:
        warnings = super().diagnostic_warnings(detection, runtime_probe)
        if (
            runtime_probe is not None
            and runtime_probe.get("ok") is False
            and runtime_probe.get("timed_out") is not True
        ):
            warnings.append("Copilot CLI was found on PATH, but `copilot --help` did not complete successfully.")
        return warnings

    def _mcp_artifacts(
        self,
        config_path: Path,
        payload: dict[str, object],
        scope: str,
    ) -> list[GuardArtifact]:
        servers = _mcp_servers_payload(config_path, payload)
        if servers is None:
            return []
        artifacts: list[GuardArtifact] = []
        for name, server_config in servers.items():
            if not isinstance(name, str) or not isinstance(server_config, dict):
                continue
            command, args = _command_parts(server_config)
            if is_guard_proxy_command(command, args):
                continue
            url = server_config.get("url")
            environment = server_config.get("env")
            if not isinstance(environment, dict):
                environment = server_config.get("environment")
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"copilot:{scope}:{name}",
                    name=name,
                    harness=self.harness,
                    artifact_type="mcp_server",
                    source_scope=scope,
                    config_path=str(config_path),
                    command=command,
                    args=args,
                    url=url if isinstance(url, str) else None,
                    transport="http" if isinstance(url, str) else "stdio",
                    metadata={
                        "env": {
                            str(key): str(value)
                            for key, value in environment.items()
                            if isinstance(key, str) and isinstance(value, str)
                        }
                        if isinstance(environment, dict)
                        else {}
                    },
                )
            )
        return artifacts

    def _hook_artifacts(
        self,
        config_path: Path,
        payload: dict[str, object],
        scope: str,
    ) -> list[GuardArtifact]:
        artifacts: list[GuardArtifact] = []
        hooks_payload = _hooks_payload(payload)
        for hook_name in _DETECTABLE_HOOK_EVENTS:
            entries = hooks_payload.get(hook_name)
            if not isinstance(entries, list):
                continue
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    continue
                for shell_name, command in _hook_command_variants(entry):
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=(
                                f"copilot:{scope}:hook:{config_path.stem}:{hook_name.lower()}:{index}:{shell_name}"
                            ),
                            name=hook_name,
                            harness=self.harness,
                            artifact_type="hook",
                            source_scope=scope,
                            config_path=str(config_path),
                            command=command,
                            metadata={"shell": shell_name},
                        )
                    )
        return artifacts

    def _proxy_server_entry(
        self,
        context: HarnessContext,
        server: ManagedMcpServer,
        target_path: Path,
    ) -> dict[str, object]:
        args = proxy_cli_args(
            proxy_command="copilot-mcp-proxy",
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
        if target_path.name in {".mcp.json", "mcp-config.json"}:
            entry["type"] = "local"
            entry["tools"] = ["*"]
        else:
            entry["type"] = "stdio"
        return entry

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

    @staticmethod
    def _state_path(target_path: Path, context: HarnessContext) -> Path:
        target = str(target_path.resolve())
        digest = sha256(target.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "copilot" / f"{digest}.state.json"

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
    def _state_entries(cls, context: HarnessContext) -> list[tuple[Path, Path, Path, dict[str, str]]]:
        state_dir = context.guard_home / "managed" / "copilot"
        entries: list[tuple[Path, Path, Path, dict[str, str]]] = []
        for state_path in sorted(state_dir.glob("*.state.json")):
            payload = cls._state_payload(state_path)
            managed_config_path = payload.get("managed_config_path")
            backup_path = payload.get("backup_path")
            if not isinstance(managed_config_path, str) or not isinstance(backup_path, str):
                continue
            entries.append((state_path, Path(managed_config_path), Path(backup_path), payload))
        return entries

    @classmethod
    def _uninstall_targets(cls, context: HarnessContext) -> list[tuple[Path, Path, Path]]:
        current_targets = cls._target_mcp_paths(context)
        current_target_paths = {str(target_path.resolve()) for target_path in current_targets}
        state_entries = cls._state_entries(context)
        exact_matches = [
            (state_path, managed_config_path, backup_path)
            for state_path, managed_config_path, backup_path, _payload in state_entries
            if str(managed_config_path.resolve()) in current_target_paths
        ]
        if exact_matches:
            return exact_matches
        if context.workspace_dir is not None:
            current_workspace = str(context.workspace_dir.resolve())
            workspace_matches = [
                (state_path, managed_config_path, backup_path)
                for state_path, managed_config_path, backup_path, payload in state_entries
                if payload.get("workspace_dir") == current_workspace
            ]
            if workspace_matches:
                return workspace_matches
        if context.workspace_dir is None and state_entries:
            return [
                (state_path, managed_config_path, backup_path)
                for state_path, managed_config_path, backup_path, _payload in state_entries
            ]
        return [
            (
                cls._state_path(target_path, context),
                target_path,
                cls._backup_path(target_path, context),
            )
            for target_path in current_targets
        ]

    @staticmethod
    def _managed_servers_for_target(
        servers: tuple[ManagedMcpServer, ...],
        target_mcp_path: Path,
    ) -> tuple[ManagedMcpServer, ...]:
        filtered: list[ManagedMcpServer] = []
        for server in servers:
            if server.source_scope == "global":
                filtered.append(server)
                continue
            if Path(server.config_path) == target_mcp_path:
                filtered.append(server)
        return tuple(filtered)

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
