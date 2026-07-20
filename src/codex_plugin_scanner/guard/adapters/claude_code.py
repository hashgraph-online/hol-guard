"""Claude Code harness adapter."""

from __future__ import annotations

import hashlib
import importlib
import json
from collections.abc import Callable, Sequence
from pathlib import Path

from ...path_support import iter_safe_matching_files, resolves_within_root
from ..aibom_detection import enrich_mcp_server_metadata
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from . import claude_hook_argv as _hook_argv
from . import claude_hook_config as _hook_config
from .base import (
    HarnessAdapter,
    HarnessContext,
    _ensure_path_within_root,
    _json_payload,
    _run_command_probe,
    _shell_command,
)

CLAUDE_GUARD_DAEMON_HOOK_MARKER = _hook_config.CLAUDE_GUARD_DAEMON_HOOK_MARKER
CLAUDE_GUARD_SESSION_START_HOOK_MARKER = _hook_config.CLAUDE_GUARD_SESSION_START_HOOK_MARKER
CLAUDE_GUARD_SESSION_START_MATCHERS = _hook_config.CLAUDE_GUARD_SESSION_START_MATCHERS
CLAUDE_GUARD_SESSION_START_TIMEOUT_SECONDS = _hook_config.CLAUDE_GUARD_SESSION_START_TIMEOUT_SECONDS
CLAUDE_GUARD_TOOL_MATCHER = _hook_config.CLAUDE_GUARD_TOOL_MATCHER
_claude_managed_settings_path = _hook_config.claude_managed_settings_path
_command_handler_argv = _hook_config.command_handler_argv
_guard_command_handler = _hook_config.guard_command_handler
_handler_identity = _hook_config.handler_identity
_is_guard_hook_command = _hook_config.is_guard_hook_command
_is_guard_hook_url = _hook_config.is_guard_hook_url
_manifest_notes = _hook_config.manifest_notes
_merge_hook_group = _hook_config.merge_hook_group
_prune_guard_hook_entries = _hook_config.prune_guard_hook_entries
_remove_unsupported_guard_hook_groups = _hook_config.remove_unsupported_guard_hook_groups
_sync_runtime_hook_groups = _hook_config.sync_runtime_hook_groups

CLAUDE_SETTINGS_FILES = ("settings.json", "settings.local.json")


def _aibom_detection_module():
    return importlib.import_module("..aibom_detection", __package__)


def _daemon_module():
    return importlib.import_module("..daemon", __package__)


def guard_daemon_url_for_home(guard_home: Path) -> str:
    return _daemon_module().guard_daemon_url_for_home(guard_home)


def load_guard_daemon_url(guard_home: Path) -> str | None:
    return _daemon_module().load_guard_daemon_url(guard_home)


def _run_session_start_from_argv(argv: Sequence[str]) -> int:
    return _hook_argv.run_session_start_from_argv(
        argv,
        ensure_guard_daemon=_daemon_module().ensure_guard_daemon,
        refresh_installed_hook_urls=ClaudeCodeHarnessAdapter.refresh_installed_hook_urls,
    )


def _claude_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _claude_mcp_artifact_id(scope: str, server_name: str) -> str:
    return f"claude-code:{scope}:mcp:{server_name}"


_CLAUDE_BUILTIN_HOOK_TOOL_NAMES = frozenset(
    {
        "bash",
        "shell",
        "sh",
        "zsh",
        "terminal",
        "run_command",
        "run_terminal_command",
        "read",
        "read_file",
        "open_file",
        "view",
        "view_file",
        "cat_file",
        "write",
        "edit",
        "multiedit",
        "write_file",
        "edit_file",
        "webfetch",
        "websearch",
        "askuserquestion",
    }
)


def claude_hook_fallback_artifact_id(scope: str, tool_name: str) -> str:
    normalized_tool = tool_name.strip()
    if normalized_tool.lower() in _CLAUDE_BUILTIN_HOOK_TOOL_NAMES:
        return f"claude-code:{scope}:{normalized_tool}"
    return _claude_mcp_artifact_id(scope, normalized_tool)


def _metadata_with_digest(path: Path) -> dict[str, object]:
    try:
        digest = _claude_digest(path)
    except OSError:
        return {}
    return {"content_digest": digest}


def _discover_project_markdown_artifacts(
    *,
    root_dir: Path,
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
    for artifact_path in iter_safe_matching_files(root_dir, base_dir, pattern):
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
    aliases = ("claude",)
    launcher_name = "claude"
    legacy_launcher_names = ("claude-code",)
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
                    args = tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str))
                    raw_env = server_config.get("env")
                    environment = (
                        {
                            key.strip(): value
                            for key, value in raw_env.items()
                            if isinstance(key, str) and key.strip() and isinstance(value, str)
                        }
                        if isinstance(raw_env, dict)
                        else {}
                    )
                    headers = server_config.get("headers")
                    configured_headers = (
                        {
                            key.strip(): value
                            for key, value in headers.items()
                            if isinstance(key, str) and key.strip() and isinstance(value, str)
                        }
                        if isinstance(headers, dict)
                        else {}
                    )
                    metadata = enrich_mcp_server_metadata(
                        {
                            "name": name,
                            "env": environment,
                            "env_keys": sorted(environment),
                            "headers_keys": (
                                sorted(key for key in headers if isinstance(key, str))
                                if isinstance(headers, dict)
                                else []
                            ),
                        },
                        command=command if isinstance(command, str) else None,
                        args=args,
                        url=url if isinstance(url, str) else None,
                        transport="http" if isinstance(url, str) else "stdio",
                        configured_headers=configured_headers,
                    )
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=_claude_mcp_artifact_id(scope, name),
                            name=name,
                            harness=self.harness,
                            artifact_type="mcp_server",
                            source_scope=scope,
                            config_path=str(config_path),
                            command=command if isinstance(command, str) else None,
                            args=args,
                            url=url if isinstance(url, str) else None,
                            transport="http" if isinstance(server_config.get("url"), str) else "stdio",
                            metadata=metadata,
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
                            flat_argv = _command_handler_argv(entry)
                            artifacts.append(
                                GuardArtifact(
                                    artifact_id=f"claude-code:{scope}:{normalized_event}:{group_index}",
                                    name=hook_name,
                                    harness=self.harness,
                                    artifact_type="hook",
                                    source_scope=scope,
                                    config_path=str(config_path),
                                    command=flat_command,
                                    args=flat_argv[1:] if flat_argv is not None else (),
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
                            handler_argv = _command_handler_argv(handler)
                            metadata: dict[str, object] = {}
                            if isinstance(matcher, str):
                                metadata["matcher"] = matcher
                            handler_type = handler.get("type")
                            if isinstance(handler_type, str):
                                metadata["type"] = handler_type
                            url = handler.get("url")
                            if isinstance(url, str):
                                metadata["url"] = url
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
                                    args=handler_argv[1:] if handler_argv is not None else (),
                                    url=url if isinstance(url, str) else None,
                                    metadata=metadata,
                                )
                            )
        if context.workspace_dir is not None:
            agents_dir = context.workspace_dir / ".claude" / "agents"
            if agents_dir.is_dir() and resolves_within_root(context.workspace_dir, agents_dir, require_exists=True):
                found_paths.append(str(agents_dir))
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        root_dir=context.workspace_dir,
                        base_dir=agents_dir,
                        pattern="*.md",
                        harness=self.harness,
                        artifact_type="agent",
                        artifact_id_prefix="agent",
                        name_for_path=lambda artifact_path, _base_dir: artifact_path.stem,
                    )
                )
            skills_dir = context.workspace_dir / ".claude" / "skills"
            if skills_dir.is_dir() and resolves_within_root(context.workspace_dir, skills_dir, require_exists=True):
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        root_dir=context.workspace_dir,
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
            if commands_dir.is_dir() and resolves_within_root(context.workspace_dir, commands_dir, require_exists=True):
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        root_dir=context.workspace_dir,
                        base_dir=commands_dir,
                        pattern="*.md",
                        harness=self.harness,
                        artifact_type="command",
                        artifact_id_prefix="command",
                        name_for_path=lambda artifact_path, _base_dir: artifact_path.stem,
                    )
                )
            rules_dir = context.workspace_dir / ".claude" / "rules"
            if rules_dir.is_dir() and resolves_within_root(context.workspace_dir, rules_dir, require_exists=True):
                artifacts.extend(
                    _discover_project_markdown_artifacts(
                        root_dir=context.workspace_dir,
                        base_dir=rules_dir,
                        pattern="*.md",
                        harness=self.harness,
                        artifact_type="instruction",
                        artifact_id_prefix="instruction",
                        name_for_path=lambda artifact_path, _base_dir: f"rules-{artifact_path.stem}",
                    )
                )
        resolved_executable = self.resolved_executable(context)
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or resolved_executable is not None,
            command_available=resolved_executable is not None,
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )
        return _aibom_detection_module().extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    @staticmethod
    def _hook_command(context: HarnessContext) -> str:
        command = ClaudeCodeHarnessAdapter._hook_command_parts(context)
        return _shell_command(command)

    @staticmethod
    def _daemon_hook_command(context: HarnessContext) -> str:
        command = ClaudeCodeHarnessAdapter._daemon_hook_command_parts(context)
        return _shell_command(command)

    @staticmethod
    def _session_start_command(context: HarnessContext) -> str:
        command = ClaudeCodeHarnessAdapter._session_start_command_parts(context)
        return _shell_command(command)

    @staticmethod
    def _hook_http_url(context: HarnessContext) -> str:
        daemon_url = load_guard_daemon_url(context.guard_home) or guard_daemon_url_for_home(context.guard_home)
        return _hook_argv.hook_http_url(context, daemon_url=daemon_url)

    @staticmethod
    def _daemon_hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        fallback_daemon_url = load_guard_daemon_url(context.guard_home) or guard_daemon_url_for_home(context.guard_home)
        return _hook_argv.daemon_hook_command_parts(context, fallback_daemon_url=fallback_daemon_url)

    @staticmethod
    def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        return _hook_argv.guard_hook_command_parts(context)

    @staticmethod
    def _session_start_command_parts(context: HarnessContext) -> tuple[str, ...]:
        return _hook_argv.session_start_command_parts(context)

    @classmethod
    def refresh_installed_hook_urls(cls, *, home_dir: Path, workspace_dir: Path | None, guard_home: Path) -> None:
        cls().refresh_runtime_hook_urls(
            HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
        )

    def refresh_runtime_hook_urls(self, context: HarnessContext) -> None:
        settings_path = _claude_managed_settings_path(context)
        payload = _json_payload(settings_path)
        hooks = payload.get("hooks")
        if not isinstance(hooks, dict):
            return
        _sync_runtime_hook_groups(hooks, self._daemon_hook_command_parts(context))
        _remove_unsupported_guard_hook_groups(hooks)
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        resolved_executable = self.resolved_executable(context)
        if resolved_executable is None:
            return None
        return _run_command_probe([resolved_executable, "--help"], timeout_seconds=5)

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(
            self.harness,
            context,
            launcher_name="claude",
            display_name="claude",
        )
        settings_path = _claude_managed_settings_path(context)
        _ensure_path_within_root(context.home_dir, settings_path, label="Claude Code")
        payload = _json_payload(settings_path)
        session_start_argv = self._session_start_command_parts(context)
        hook_argv = self._daemon_hook_command_parts(context)
        hooks_payload = payload.get("hooks")
        if isinstance(hooks_payload, dict):
            hooks: dict[str, object] = {str(key): value for key, value in hooks_payload.items()}
        else:
            hooks = {}
        payload["hooks"] = hooks
        session_start_payload = hooks.get("SessionStart")
        session_start_entries = _prune_guard_hook_entries(
            session_start_payload if isinstance(session_start_payload, list) else []
        )
        session_start_handler = _guard_command_handler(
            session_start_argv,
            timeout=CLAUDE_GUARD_SESSION_START_TIMEOUT_SECONDS,
        )
        for matcher in CLAUDE_GUARD_SESSION_START_MATCHERS:
            session_start_entries = _merge_hook_group(session_start_entries, matcher, session_start_handler)
        hooks["SessionStart"] = session_start_entries
        _sync_runtime_hook_groups(hooks, hook_argv)
        _remove_unsupported_guard_hook_groups(hooks)
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(settings_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries added to ~/.claude/settings.json",
                *_manifest_notes(shim_manifest),
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name="claude",
            display_name="claude",
            legacy_launcher_names=("claude-code",),
        )
        settings_path = _claude_managed_settings_path(context)
        _ensure_path_within_root(context.home_dir, settings_path, label="Claude Code")
        payload = _json_payload(settings_path)
        hooks = payload.get("hooks")
        if isinstance(hooks, dict):
            for key in (
                "SessionStart",
                "PreToolUse",
                "PermissionRequest",
                "PostToolUse",
                "UserPromptSubmit",
                "Notification",
                "Stop",
            ):
                entries = hooks.get(key)
                hooks[key] = _prune_guard_hook_entries(entries if isinstance(entries, list) else [])
            _remove_unsupported_guard_hook_groups(hooks)
            settings_path.parent.mkdir(parents=True, exist_ok=True)
            settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(settings_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries removed from ~/.claude/settings.json",
                *_manifest_notes(shim_manifest),
            ],
        }
