"""Claude Code harness adapter."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from ..launcher import merge_guard_launcher_env
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _json_payload, _run_command_probe


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
    approval_tier = "native-or-center"
    approval_summary = (
        "Guard uses Claude hooks first and falls back to the local approval center when the shell cannot prompt."
    )
    fallback_hint = "Claude is the best current harness for deferred Guard approvals."
    approval_prompt_channel = "hook"
    approval_auto_open_browser = False

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        del context
        return (Path.home() / ".claude" / "local" / "claude",)

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".claude" / "settings.local.json"
        return context.home_dir / ".claude" / "settings.json"

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
        resolved_executable = self.resolved_executable(context)
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or resolved_executable is not None,
            command_available=resolved_executable is not None,
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )

    @staticmethod
    def _hook_command(context: HarnessContext) -> str:
        command = ClaudeCodeHarnessAdapter._hook_command_parts(context)
        return subprocess.list2cmdline(list(command))

    @staticmethod
    def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        guard_args = [
            "guard",
            "hook",
            "--guard-home",
            str(context.guard_home),
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

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        resolved_executable = self.resolved_executable(context)
        if resolved_executable is None:
            return None
        return _run_command_probe([resolved_executable, "--help"], timeout_seconds=5)

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
