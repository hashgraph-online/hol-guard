"""Claude Code harness adapter."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from ..launcher import merge_guard_launcher_env
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _json_payload, _run_command_probe

CLAUDE_GUARD_TOOL_MATCHER = "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*"
CLAUDE_GUARD_TOOL_TIMEOUT_SECONDS = 30
CLAUDE_GUARD_PROMPT_TIMEOUT_SECONDS = 20
CLAUDE_SETTINGS_FILES = ("settings.json", "settings.local.json")


def _guard_hook_handler(command: str, *, timeout: int) -> dict[str, object]:
    return {"type": "command", "command": command, "timeout": timeout}


def _guard_hook_group(matcher: str | None, command: str, *, timeout: int) -> dict[str, object]:
    payload: dict[str, object] = {"hooks": [_guard_hook_handler(command, timeout=timeout)]}
    if isinstance(matcher, str) and matcher.strip():
        payload["matcher"] = matcher
    return payload


def _merge_hook_group(
    entries: list[dict[str, object]],
    matcher: str | None,
    command: str,
    *,
    timeout: int,
) -> list[dict[str, object]]:
    normalized = [entry for entry in entries if isinstance(entry, dict)]
    matcher_key = matcher.strip() if isinstance(matcher, str) and matcher.strip() else None
    handler = _guard_hook_handler(command, timeout=timeout)
    for index, entry in enumerate(normalized):
        if str(entry.get("command", "")) == command:
            normalized[index] = _guard_hook_group(matcher_key, command, timeout=timeout)
            return normalized
        entry_matcher = entry.get("matcher")
        entry_matcher_key = entry_matcher.strip() if isinstance(entry_matcher, str) and entry_matcher.strip() else None
        if entry_matcher_key != matcher_key:
            continue
        hooks = entry.get("hooks")
        if not isinstance(hooks, list):
            hooks = []
        if any(isinstance(item, dict) and item.get("command") == command for item in hooks):
            return normalized
        hooks.append(handler)
        entry["hooks"] = hooks
        return normalized
    normalized.append(_guard_hook_group(matcher_key, command, timeout=timeout))
    return normalized


def _remove_guard_hook_handler(entries: list[dict[str, object]], command: str) -> list[dict[str, object]]:
    remaining: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            remaining.append(entry)
            continue
        if str(entry.get("command", "")) == command:
            continue
        hooks = entry.get("hooks")
        if not isinstance(hooks, list):
            remaining.append(entry)
            continue
        filtered_hooks = [
            item for item in hooks if not (isinstance(item, dict) and str(item.get("command", "")) == command)
        ]
        if filtered_hooks:
            updated_entry = dict(entry)
            updated_entry["hooks"] = filtered_hooks
            remaining.append(updated_entry)
    return remaining


def _claude_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _metadata_with_digest(path: Path) -> dict[str, object]:
    try:
        digest = _claude_digest(path)
    except OSError:
        return {}
    return {"content_digest": digest}


def _discover_project_markdown_artifacts(
    *,
    base_dir: Path,
    pattern: str,
    harness: str,
    artifact_type: str,
    artifact_id_prefix: str,
    name_for_path: Callable[[Path, Path], str],
) -> list[GuardArtifact]:
    if not base_dir.is_dir():
        return []
    artifacts: list[GuardArtifact] = []
    for artifact_path in sorted(path for path in base_dir.glob(pattern) if path.is_file()):
        artifact_name = name_for_path(artifact_path, base_dir)
        artifacts.append(
            GuardArtifact(
                artifact_id=f"claude-code:project:{artifact_id_prefix}:{artifact_name}",
                name=artifact_name,
                harness=harness,
                artifact_type=artifact_type,
                source_scope="project",
                config_path=str(artifact_path),
                metadata=_metadata_with_digest(artifact_path),
            )
        )
    return artifacts


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
        config_candidates = [context.home_dir / ".claude" / name for name in CLAUDE_SETTINGS_FILES]
        if context.workspace_dir is not None:
            config_candidates.extend(
                (
                    *(context.workspace_dir / ".claude" / name for name in CLAUDE_SETTINGS_FILES),
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
                            metadata={
                                "env_keys": sorted(key for key in server_config.get("env", {}))
                                if isinstance(server_config.get("env"), dict)
                                else [],
                                "headers_keys": sorted(key for key in server_config.get("headers", {}))
                                if isinstance(server_config.get("headers"), dict)
                                else [],
                            },
                        )
                    )
            hooks = payload.get("hooks")
            if isinstance(hooks, dict):
                for hook_name, hook_entries in hooks.items():
                    if not isinstance(hook_name, str) or not isinstance(hook_entries, list):
                        continue
                    normalized_event = hook_name.strip().lower()
                    for group_index, entry in enumerate(hook_entries):
                        if not isinstance(entry, dict):
                            continue
                        flat_command = entry.get("command")
                        if isinstance(flat_command, str):
                            artifacts.append(
                                GuardArtifact(
                                    artifact_id=f"claude-code:{scope}:{normalized_event}:{group_index}",
                                    name=hook_name,
                                    harness=self.harness,
                                    artifact_type="hook",
                                    source_scope=scope,
                                    config_path=str(config_path),
                                    command=flat_command,
                                )
                            )
                            continue
                        matcher = entry.get("matcher")
                        handlers = entry.get("hooks")
                        if not isinstance(handlers, list):
                            continue
                        for handler_index, handler in enumerate(handlers):
                            if not isinstance(handler, dict):
                                continue
                            command = handler.get("command")
                            metadata: dict[str, object] = {}
                            if isinstance(matcher, str):
                                metadata["matcher"] = matcher
                            handler_type = handler.get("type")
                            if isinstance(handler_type, str):
                                metadata["type"] = handler_type
                            timeout = handler.get("timeout")
                            if isinstance(timeout, int):
                                metadata["timeout"] = timeout
                            condition = handler.get("if")
                            if isinstance(condition, str):
                                metadata["if"] = condition
                            artifacts.append(
                                GuardArtifact(
                                    artifact_id=f"claude-code:{scope}:{normalized_event}:{group_index}:{handler_index}",
                                    name=hook_name,
                                    harness=self.harness,
                                    artifact_type="hook",
                                    source_scope=scope,
                                    config_path=str(config_path),
                                    command=command if isinstance(command, str) else None,
                                    metadata=metadata,
                                )
                            )
        if context.workspace_dir is not None:
            agents_dir = context.workspace_dir / ".claude" / "agents"
            if agents_dir.is_dir():
                found_paths.append(str(agents_dir))
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        base_dir=agents_dir,
                        pattern="*.md",
                        harness=self.harness,
                        artifact_type="agent",
                        artifact_id_prefix="agent",
                        name_for_path=lambda artifact_path, _base_dir: artifact_path.stem,
                    )
                )
            skills_dir = context.workspace_dir / ".claude" / "skills"
            if skills_dir.is_dir():
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        base_dir=skills_dir,
                        pattern="**/SKILL.md",
                        harness=self.harness,
                        artifact_type="skill",
                        artifact_id_prefix="skill",
                        name_for_path=lambda artifact_path, base_dir: (
                            artifact_path.parent.relative_to(base_dir).as_posix() or artifact_path.parent.name
                        ),
                    )
                )
            commands_dir = context.workspace_dir / ".claude" / "commands"
            if commands_dir.is_dir():
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        base_dir=commands_dir,
                        pattern="*.md",
                        harness=self.harness,
                        artifact_type="command",
                        artifact_id_prefix="command",
                        name_for_path=lambda artifact_path, _base_dir: artifact_path.stem,
                    )
                )
            rules_dir = context.workspace_dir / ".claude" / "rules"
            if rules_dir.is_dir():
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        base_dir=rules_dir,
                        pattern="*.md",
                        harness=self.harness,
                        artifact_type="instruction",
                        artifact_id_prefix="instruction",
                        name_for_path=lambda artifact_path, _base_dir: artifact_path.stem,
                    )
                )
            project_claude_md = context.workspace_dir / "CLAUDE.md"
            if project_claude_md.is_file():
                artifacts.append(
                    GuardArtifact(
                        artifact_id="claude-code:project:instruction:claude-md",
                        name="CLAUDE.md",
                        harness=self.harness,
                        artifact_type="instruction",
                        source_scope="project",
                        config_path=str(project_claude_md),
                        metadata=_metadata_with_digest(project_claude_md),
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
            hooks[key] = _merge_hook_group(
                entries,
                CLAUDE_GUARD_TOOL_MATCHER,
                hook_command,
                timeout=CLAUDE_GUARD_TOOL_TIMEOUT_SECONDS,
            )
        prompt_entries = hooks.get("UserPromptSubmit")
        hooks["UserPromptSubmit"] = _merge_hook_group(
            prompt_entries if isinstance(prompt_entries, list) else [],
            None,
            hook_command,
            timeout=CLAUDE_GUARD_PROMPT_TIMEOUT_SECONDS,
        )
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
            for key in ("PreToolUse", "PostToolUse", "UserPromptSubmit"):
                entries = hooks.get(key)
                hooks[key] = _remove_guard_hook_handler(entries if isinstance(entries, list) else [], hook_command)
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
