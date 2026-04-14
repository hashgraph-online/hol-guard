"""Microsoft Copilot CLI harness adapter."""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available, _json_payload, _run_command_probe

_MANAGED_HOOK_EVENTS = ("preToolUse", "postToolUse")
_DETECTABLE_HOOK_EVENTS = (
    "sessionStart",
    "sessionEnd",
    "userPromptSubmitted",
    "preToolUse",
    "postToolUse",
    "errorOccurred",
)
_MANAGED_HOOK_FILENAME = "hol-guard-copilot.json"
_MANAGED_HOOK_COMMAND_PATTERNS = (
    re.compile(r'(^|["\s])-m["\s]+codex_plugin_scanner\.cli(["\s]|$)'),
    re.compile(r'(^|["\s])guard(["\s]|$)'),
    re.compile(r'(^|["\s])hook(["\s]|$)'),
    re.compile(r'--harness(?:["\s=]+)copilot(["\s]|$)'),
)


def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    command = [
        sys.executable,
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "hook",
        "--guard-home",
        str(context.guard_home),
        "--harness",
        "copilot",
    ]
    if context.home_dir.resolve() != Path.home().resolve():
        command.extend(["--home", str(context.home_dir)])
    if context.workspace_dir is not None:
        command.extend(["--workspace", str(context.workspace_dir)])
    return tuple(command)


def _hook_shell_commands(context: HarnessContext) -> tuple[str, str]:
    command_parts = _hook_command_parts(context)
    return shlex.join(command_parts), subprocess.list2cmdline(list(command_parts))


def _hook_entry(context: HarnessContext) -> dict[str, object]:
    bash_command, powershell_command = _hook_shell_commands(context)
    return {
        "type": "command",
        "bash": bash_command,
        "powershell": powershell_command,
        "cwd": ".",
        "timeoutSec": 30,
    }


def _is_managed_hook_command(command: str) -> bool:
    normalized_command = command.lower()
    return all(pattern.search(normalized_command) is not None for pattern in _MANAGED_HOOK_COMMAND_PATTERNS)


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


def _mcp_servers_payload(payload: dict[str, object]) -> dict[str, object] | None:
    servers = payload.get("servers")
    if isinstance(servers, dict):
        return servers
    mcp_servers = payload.get("mcpServers")
    if isinstance(mcp_servers, dict):
        return mcp_servers
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


class CopilotHarnessAdapter(HarnessAdapter):
    """Discover Microsoft Copilot CLI repo hooks and MCP config artifacts."""

    harness = "copilot"
    executable = "copilot"
    approval_tier = "native-or-center"
    approval_summary = (
        "Guard can install documented Copilot CLI repo hooks and falls back to the local approval center when needed."
    )
    fallback_hint = "Use Guard-managed repo hooks for Copilot CLI tool events and the local approval center for review."

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

    def detect(self, context: HarnessContext) -> HarnessDetection:
        workspace_mcp_path = (
            context.workspace_dir / ".vscode" / "mcp.json" if context.workspace_dir is not None else None
        )
        config_candidates = [
            context.home_dir / ".copilot" / "config.json",
            context.home_dir / ".copilot" / "mcp-config.json",
        ]
        if context.workspace_dir is not None:
            config_candidates.append(workspace_mcp_path)
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        for config_path in config_candidates:
            payload = _json_payload(config_path)
            if not payload:
                continue
            found_paths.append(str(config_path))
            scope = self._scope_for(context, config_path)
            if config_path.name == "mcp-config.json" or config_path == workspace_mcp_path:
                artifacts.extend(self._mcp_artifacts(config_path, payload, scope))
        if context.workspace_dir is not None:
            hooks_dir = context.workspace_dir / ".github" / "hooks"
            if hooks_dir.is_dir():
                for hook_path in sorted(path for path in hooks_dir.glob("*.json") if path.is_file()):
                    payload = _json_payload(hook_path)
                    if not payload:
                        continue
                    hook_artifacts = self._hook_artifacts(hook_path, payload)
                    if len(hook_artifacts) == 0:
                        continue
                    found_paths.append(str(hook_path))
                    artifacts.extend(hook_artifacts)
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(self.harness, context)
        hook_path = self._hook_path(context)
        if hook_path is None:
            return {
                "harness": self.harness,
                "active": True,
                "config_path": shim_manifest["shim_path"],
                **shim_manifest,
                "notes": [
                    "Guard created the Copilot launcher shim. Pass --workspace to install repo-local Copilot hooks.",
                    *[str(note) for note in shim_manifest.get("notes", [])],
                ],
            }
        payload = _managed_hook_payload(_json_payload(hook_path))
        hooks_payload = payload["hooks"]
        hook_entry = _hook_entry(context)
        for hook_name in _MANAGED_HOOK_EVENTS:
            hooks_payload[hook_name] = _merge_hook_entries(hooks_payload.get(hook_name), hook_entry)
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(hook_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries added to .github/hooks/hol-guard-copilot.json",
                *[str(note) for note in shim_manifest.get("notes", [])],
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(self.harness, context)
        hook_path = self._hook_path(context)
        if hook_path is None:
            return {
                "harness": self.harness,
                "active": False,
                "config_path": shim_manifest["shim_path"],
                **shim_manifest,
            }
        payload = _json_payload(hook_path)
        payload = _managed_hook_payload(payload)
        hooks_payload = payload["hooks"]
        bash_command, powershell_command = _hook_shell_commands(context)
        for hook_name in _MANAGED_HOOK_EVENTS:
            updated_entries = _remove_hook_entries(hooks_payload.get(hook_name), bash_command, powershell_command)
            if len(updated_entries) > 0:
                hooks_payload[hook_name] = updated_entries
                continue
            hooks_payload.pop(hook_name, None)
        if len(hooks_payload) > 0:
            hook_path.parent.mkdir(parents=True, exist_ok=True)
            hook_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        elif hook_path.exists():
            hook_path.unlink()
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(hook_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries removed from .github/hooks/hol-guard-copilot.json",
                *[str(note) for note in shim_manifest.get("notes", [])],
            ],
        }

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        if not _command_available(self.executable):
            return None
        return _run_command_probe([self.executable, "--help"])

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
        servers = _mcp_servers_payload(payload)
        if servers is None:
            return []
        artifacts: list[GuardArtifact] = []
        for name, server_config in servers.items():
            if not isinstance(name, str) or not isinstance(server_config, dict):
                continue
            command, args = _command_parts(server_config)
            url = server_config.get("url")
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
                )
            )
        return artifacts

    def _hook_artifacts(
        self,
        config_path: Path,
        payload: dict[str, object],
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
                                f"copilot:project:hook:{config_path.stem}:{hook_name.lower()}:{index}:{shell_name}"
                            ),
                            name=hook_name,
                            harness=self.harness,
                            artifact_type="hook",
                            source_scope="project",
                            config_path=str(config_path),
                            command=command,
                            metadata={"shell": shell_name},
                        )
                    )
        return artifacts
