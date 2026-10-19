"""Claude Code harness adapter."""

from __future__ import annotations

import importlib
import json
import os
from collections.abc import Sequence
from pathlib import Path

from ..aibom_detection import native_adapter_detection_with_warnings
from ..models import HarnessDetection
from ..shims import prepare_guard_shim, remove_guard_shim
from . import claude_hook_argv as _hook_argv
from . import claude_hook_config as _hook_config
from .base import (
    HarnessAdapter,
    HarnessContext,
    PreparedHarnessInstall,
    _ensure_path_within_root,
    _json_payload,
    _owned_adapter_mutation,
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
_mark_missing_guard_hooks = _hook_config.mark_missing_guard_hooks
_prune_guard_hook_entries = _hook_config.prune_guard_hook_entries
_remove_unsupported_guard_hook_groups = _hook_config.remove_unsupported_guard_hook_groups
_sync_runtime_hook_groups = _hook_config.sync_runtime_hook_groups


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

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".claude" / "settings.local.json"
        return context.home_dir / ".claude" / "settings.json"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        workspace = context.workspace_dir
        request: dict[str, object] = {
            "harness": self.harness,
            "home": str(context.home_dir),
            "workspace": None if workspace is None else str(workspace),
        }
        if not context.home_dir.is_absolute() or (workspace is not None and not workspace.is_absolute()):
            request["cwd"] = os.getcwd()
        artifacts, found_paths, _warnings = native_adapter_detection_with_warnings("claude_code_detect", request)
        resolved_executable = self.resolved_executable(context)
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or resolved_executable is not None,
            command_available=resolved_executable is not None,
            config_paths=found_paths,
            artifacts=artifacts,
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

    @_owned_adapter_mutation
    def refresh_runtime_hook_urls(self, context: HarnessContext) -> None:
        settings_path = _claude_managed_settings_path(context)
        _ensure_path_within_root(context.home_dir, settings_path, label="Claude Code")
        payload = _json_payload(settings_path)
        hooks = payload.get("hooks")
        if not isinstance(hooks, dict):
            return
        _sync_runtime_hook_groups(hooks, self._daemon_hook_command_parts(context))
        _remove_unsupported_guard_hook_groups(hooks)
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        payload = super().diagnostics(context)
        if payload.get("setup_status") == "active":
            settings_path = _claude_managed_settings_path(context)
            _mark_missing_guard_hooks(payload, settings_path, _json_payload(settings_path))
        return payload

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        resolved_executable = self.resolved_executable(context)
        if resolved_executable is None:
            return None
        return _run_command_probe([resolved_executable, "--help"], timeout_seconds=5)

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import TransitionFile

        prepared_shim = prepare_guard_shim(
            self.harness,
            context,
            launcher_name="claude",
            display_name="claude",
        )
        shim_manifest = prepared_shim.manifest
        settings_path = _claude_managed_settings_path(context)
        _ensure_path_within_root(context.home_dir, settings_path, label="Claude Code")
        before = _snapshot(settings_path)
        payload = json.loads(before.decode("utf-8")) if before is not None else {}
        if not isinstance(payload, dict):
            raise ValueError("Claude Code settings must be a JSON object before installation.")
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
        mode = settings_path.stat().st_mode & 0o777 if before is not None else 0o644
        settings = TransitionFile(
            settings_path.resolve(strict=False),
            before,
            json.dumps(payload, indent=2).encode("utf-8"),
            before_mode=mode,
            after_mode=mode,
        )
        settings.payload()
        manifest: dict[str, object] = {
            "harness": self.harness,
            "active": True,
            "config_path": str(settings_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries added to ~/.claude/settings.json",
                *(
                    [
                        f"Hooks are installed globally (not in {context.workspace_dir}/.claude); "
                        "the workspace only scopes the hook URL and Guard policy."
                    ]
                    if context.workspace_dir is not None
                    else []
                ),
                *_manifest_notes(shim_manifest),
            ],
        }
        return PreparedHarnessInstall((*prepared_shim.files, settings), manifest)

    def install(self, context: HarnessContext) -> dict[str, object]:
        return self.prepare_install(context).publish(context.guard_home)

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
