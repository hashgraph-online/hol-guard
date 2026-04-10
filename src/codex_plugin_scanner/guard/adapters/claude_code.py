"""Claude Code harness adapter."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available, _json_payload


def _merge_hook_entry(entries: list[dict[str, object]], command: str) -> list[dict[str, object]]:
    normalized = [entry for entry in entries if isinstance(entry, dict)]
    if any(entry.get("command") == command for entry in normalized):
        return normalized
    normalized.append({"command": command})
    return normalized


def _remove_hook_entry(entries: list[dict[str, object]], command: str) -> list[dict[str, object]]:
    return [entry for entry in entries if not isinstance(entry, dict) or entry.get("command") != command]


class ClaudeCodeHarnessAdapter(HarnessAdapter):
    """Discover Claude Code settings, hooks, and workspace agents."""

    harness = "claude-code"
    executable = "claude"

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_candidates = [context.home_dir / ".claude" / "settings.json"]
        if context.workspace_dir is not None:
            config_candidates.extend(
                (
                    context.workspace_dir / ".claude" / "settings.json",
                    context.workspace_dir / ".claude" / "settings.local.json",
                    context.workspace_dir / ".mcp.json",
                )
            )
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        for config_path in config_candidates:
            payload = _json_payload(config_path)
            if not payload:
                continue
            found_paths.append(str(config_path))
            scope = self._scope_for(context, config_path)
            mcp_servers = payload.get("mcpServers")
            if isinstance(mcp_servers, dict):
                for name, server_config in mcp_servers.items():
                    if not isinstance(name, str) or not isinstance(server_config, dict):
                        continue
                    command = server_config.get("command")
                    url = server_config.get("url")
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"claude-code:{scope}:{name}",
                            name=name,
                            harness=self.harness,
                            artifact_type="mcp_server",
                            source_scope=scope,
                            config_path=str(config_path),
                            command=command if isinstance(command, str) else None,
                            args=tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str)),
                            url=url if isinstance(url, str) else None,
                            transport="http" if isinstance(server_config.get("url"), str) else "stdio",
                        )
                    )
            hooks = payload.get("hooks")
            if isinstance(hooks, dict):
                for hook_name in ("PreToolUse", "PostToolUse"):
                    hook_entries = hooks.get(hook_name)
                    if isinstance(hook_entries, list):
                        for index, entry in enumerate(hook_entries):
                            if isinstance(entry, dict):
                                command = entry.get("command")
                                artifacts.append(
                                    GuardArtifact(
                                        artifact_id=f"claude-code:{scope}:{hook_name.lower()}:{index}",
                                        name=hook_name,
                                        harness=self.harness,
                                        artifact_type="hook",
                                        source_scope=scope,
                                        config_path=str(config_path),
                                        command=command if isinstance(command, str) else None,
                                    )
                                )
        if context.workspace_dir is not None:
            agents_dir = context.workspace_dir / ".claude" / "agents"
            if agents_dir.is_dir():
                found_paths.append(str(agents_dir))
                for agent_path in sorted(path for path in agents_dir.glob("*.md") if path.is_file()):
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"claude-code:agent:{agent_path.stem}",
                            name=agent_path.stem,
                            harness=self.harness,
                            artifact_type="agent",
                            source_scope="project",
                            config_path=str(agent_path),
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

    @staticmethod
    def _hook_command(context: HarnessContext) -> str:
        command = [
            sys.executable,
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "hook",
            "--guard-home",
            str(context.guard_home),
        ]
        if context.home_dir.resolve() != Path.home().resolve():
            command.extend(["--home", str(context.home_dir)])
        if context.workspace_dir is not None:
            command.extend(["--workspace", str(context.workspace_dir)])
        return subprocess.list2cmdline(command)

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(self.harness, context)
        if context.workspace_dir is None:
            return {
                "harness": self.harness,
                "active": True,
                "config_path": shim_manifest["shim_path"],
                **shim_manifest,
            }
        settings_path = context.workspace_dir / ".claude" / "settings.local.json"
        payload = _json_payload(settings_path)
        hook_command = self._hook_command(context)
        hooks = payload.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            hooks = {}
            payload["hooks"] = hooks
        for key in ("PreToolUse", "PostToolUse"):
            existing_entries = hooks.get(key)
            entries = existing_entries if isinstance(existing_entries, list) else []
            hooks[key] = _merge_hook_entry(entries, hook_command)
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(settings_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries added to .claude/settings.local.json",
                *[str(note) for note in shim_manifest.get("notes", [])],
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(self.harness, context)
        if context.workspace_dir is None:
            return {
                "harness": self.harness,
                "active": False,
                "config_path": shim_manifest["shim_path"],
                **shim_manifest,
            }
        settings_path = context.workspace_dir / ".claude" / "settings.local.json"
        payload = _json_payload(settings_path)
        hook_command = self._hook_command(context)
        hooks = payload.get("hooks")
        if isinstance(hooks, dict):
            for key in ("PreToolUse", "PostToolUse"):
                entries = hooks.get(key)
                hooks[key] = _remove_hook_entry(entries if isinstance(entries, list) else [], hook_command)
            settings_path.parent.mkdir(parents=True, exist_ok=True)
            settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(settings_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries removed from .claude/settings.local.json",
                *[str(note) for note in shim_manifest.get("notes", [])],
            ],
        }
