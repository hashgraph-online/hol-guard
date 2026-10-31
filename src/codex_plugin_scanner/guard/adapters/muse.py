"""Muse harness adapter for HOL Guard.

Muse's user config lives under ``$XDG_CONFIG_HOME/muse`` (or
``~/.config/muse``). Its ``settings.json`` ``hooks`` key is
Claude-Code-shaped: ``{"<Event>": [{"matcher": <regex>, "hooks": [{"type":
"command", "command": ..., "timeout": 30}]}]}``, and ``mcpServers`` holds
its MCP registrations. Guard inventories hooks, MCP servers, skills, and
installed plugin manifests through the native ``muse_detect`` kind;
installs Guard-managed ``PreToolUse``, ``PermissionRequest``,
``UserPromptSubmit``, ``PostToolUse``, ``SessionStart``, and ``Stop``
hooks into the user ``settings.json`` ``hooks`` section (idempotently,
without touching other keys); and routes Muse hook events through the shared Guard
runtime. A blocked ``PreToolUse`` call whose approval is granted resumes
the identical call inside the hook, like Oh My Pi's approval resume: the
bounded bridge waits for the approval and then allows the original call
to proceed unchanged.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ..aibom_detection import extend_detection_with_workspace_aibom, native_adapter_detection_with_warnings
from ..codex_hook_integrity import atomic_write_text
from ..config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, load_guard_config
from ..models import HarnessDetection
from ..shims import prepare_guard_shim, remove_guard_shim
from .base import (
    HarnessAdapter,
    HarnessContext,
    PreparedHarnessInstall,
    _command_available,
    _ensure_path_within_root,
    _shell_command,
    detection_request,
)
from .bounded_cli_hook_bridge import bounded_cli_hook_command
from .hook_group_merge import merge_hook_entry, prune_managed_hook_entries
from .muse_config import MUSE_GUARD_EVENTS, MUSE_SETTINGS_FILE, is_guard_managed_hook_command

_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS = 25
_MUSE_MANAGED_HOOK_TIMEOUT_SECONDS = 30
_MUSE_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS = 5

if TYPE_CHECKING:
    from ..runtime_transition import TransitionFile


def _write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    target = path.resolve() if path.is_symlink() else path
    mode = target.stat().st_mode & 0o777 if target.exists() else 0o600
    atomic_write_text(target, json.dumps(payload, indent=2) + "\n", mode=mode)


def _adapter_result(
    harness: str,
    *,
    active: bool,
    config_path: Path,
    shim_manifest: dict[str, object],
    notes: list[str],
) -> dict[str, object]:
    raw_notes = shim_manifest.get("notes")
    shim_notes = (
        [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
    )
    return {
        "harness": harness,
        "active": active,
        "config_path": str(config_path),
        **shim_manifest,
        "notes": [*notes, *shim_notes],
    }


class MuseHarnessAdapter(HarnessAdapter):
    """Discover Muse settings, hooks, MCP, and skills; manage Guard protection."""

    harness = "muse"
    aliases = ("muse", "muse-code")
    executable = "muse"
    launcher_name = "muse"
    approval_tier = "native-or-center"
    approval_summary = (
        "Guard scans Muse config, hooks, skills, plugins, and MCP registrations before launch "
        "and routes blocked actions to the local approval center. Approving a blocked tool call "
        "resumes that exact call."
    )
    fallback_hint = (
        "Muse resumes an approved tool call inside the pending hook. "
        "Use the Guard approval center when native prompting is unavailable."
    )
    approval_prompt_channel = "hook"
    approval_auto_open_browser = False

    @staticmethod
    def _muse_config_dir(context: HarnessContext) -> Path:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if isinstance(xdg, str) and xdg.strip() and context.home_dir.resolve() == Path.home().resolve():
            return Path(xdg.strip()) / "muse"
        return context.home_dir / ".config" / "muse"

    @classmethod
    def _user_settings_path(cls, context: HarnessContext) -> Path:
        return cls._muse_config_dir(context) / MUSE_SETTINGS_FILE

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            project_settings = context.workspace_dir / ".muse" / MUSE_SETTINGS_FILE
            if project_settings.is_file():
                return project_settings
        return self._user_settings_path(context)

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        return (context.home_dir / ".local" / "bin" / self.executable,)

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_dir = self._muse_config_dir(context)
        request = {**detection_request(self.harness, context), "config_dir": str(config_dir)}
        if not config_dir.is_absolute() and "cwd" not in request:
            request["cwd"] = os.getcwd()
        artifacts, found_paths, warnings = native_adapter_detection_with_warnings("muse_detect", request)
        command_available = _command_available(self.executable)
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or command_available,
            command_available=command_available,
            config_paths=found_paths,
            artifacts=artifacts,
            warnings=warnings,
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def _managed_state_paths(self, context: HarnessContext) -> tuple[Path, Path, Path]:
        state_dir = context.guard_home / "managed" / "muse"
        backup_path = state_dir / "settings.json.backup"
        state_path = state_dir / "install.state.json"
        _ensure_path_within_root(context.guard_home, state_dir, label="Muse state")
        _ensure_path_within_root(state_dir, backup_path, label="Muse backup")
        _ensure_path_within_root(state_dir, state_path, label="Muse state")
        return state_dir, backup_path, state_path

    @staticmethod
    def _hook_command_parts(
        context: HarnessContext, *, prepared_files: list[TransitionFile] | None = None
    ) -> tuple[str, ...]:
        guard_args = [
            "guard",
            "hook",
            "--guard-home",
            str(context.guard_home),
            "--harness",
            "muse",
        ]
        if context.home_dir.resolve() != Path.home().resolve():
            guard_args.extend(["--home", str(context.home_dir)])
        if context.workspace_dir is not None:
            guard_args.extend(["--workspace", str(context.workspace_dir)])
        return bounded_cli_hook_command(
            python_executable=sys.executable,
            package_root=Path(__file__).resolve().parents[3],
            guard_home=context.guard_home,
            cli_args=guard_args,
            harness="muse",
            timeout_seconds=MuseHarnessAdapter._bridge_timeout_seconds(context),
            prepared_files=prepared_files,
        )

    @staticmethod
    def _bridge_timeout_seconds(context: HarnessContext) -> int:
        """Deadline the bridge client enforces on itself, in seconds.

        Muse's own hook timeout has to outlast this, or Muse kills the bridge
        before it can answer and the call falls through unjudged.
        """

        return max(
            _GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS,
            MuseHarnessAdapter._approval_wait_hook_timeout_seconds(context) + _MUSE_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS,
        )

    @staticmethod
    def _approval_wait_hook_timeout_seconds(context: HarnessContext) -> int:
        configured_wait_timeout = load_guard_config(
            context.guard_home,
            context.workspace_dir,
            create_home=False,
        ).approval_wait_timeout_seconds
        return (
            min(
                max(configured_wait_timeout, 0),
                MAX_APPROVAL_WAIT_TIMEOUT_SECONDS,
            )
            + _MUSE_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS
        )

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..codex_hook_file_integrity import CodexHookIntegrityError
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import TransitionFile

        settings_path = self._user_settings_path(context)
        _ensure_path_within_root(self._muse_config_dir(context).parent, settings_path, label="Muse")
        try:
            settings_before = _snapshot(settings_path)
        except CodexHookIntegrityError as exc:
            raise ValueError("Muse settings could not be parsed safely; Guard will not rewrite it.") from exc
        payload: dict[str, object] = {}
        if settings_before is not None:
            try:
                parsed = json.loads(settings_before.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(
                    "Muse settings at ~/.config/muse/settings.json could not be parsed as a JSON object; "
                    "Guard will not rewrite it. Fix the file, then rerun hol-guard install muse."
                ) from exc
            if not isinstance(parsed, dict):
                raise ValueError("Muse settings must be a JSON object before installation.")
            payload = parsed
            existing_hooks = payload.get("hooks")
            if existing_hooks is not None and not isinstance(existing_hooks, dict):
                raise ValueError("Muse settings have a non-object hooks value; Guard will not rewrite it.")
            if isinstance(existing_hooks, dict):
                for event_name, entries in existing_hooks.items():
                    if entries is not None and not isinstance(entries, list):
                        raise ValueError(
                            f"Muse settings have a non-list hooks.{event_name} value; Guard will not rewrite it. "
                            "Fix the file, then rerun hol-guard install muse."
                        )
        prepared_shim = prepare_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="muse",
        )
        shim_manifest = prepared_shim.manifest
        _state_dir, backup_path, state_path = self._managed_state_paths(context)
        backup_before = _snapshot(backup_path)
        state_before = _snapshot(state_path)
        hook_files: list[TransitionFile] = []
        hook_command = _shell_command(self._hook_command_parts(context, prepared_files=hook_files))
        # Muse refuses a settings file without schema_version; a file
        # Guard creates (or repairs) must carry it.
        payload.setdefault("schema_version", 1)
        hooks_value = payload.get("hooks")
        hooks: dict[str, object] = hooks_value if isinstance(hooks_value, dict) else {}
        payload["hooks"] = hooks

        self._sync_managed_hook_groups(context, hooks, hook_command)
        settings_mode = settings_path.stat().st_mode & 0o777 if settings_before is not None else 0o600
        backup_mode = backup_path.stat().st_mode & 0o777 if backup_before is not None else settings_mode
        state_mode = state_path.stat().st_mode & 0o777 if state_before is not None else 0o600
        state_after = (json.dumps({"managed_settings_path": str(settings_path)}, indent=2) + "\n").encode("utf-8")
        files = (
            *prepared_shim.files,
            *hook_files,
            TransitionFile(
                backup_path.resolve(strict=False),
                backup_before,
                backup_before if backup_before is not None else settings_before,
                before_mode=backup_mode,
                after_mode=backup_mode,
            ),
            TransitionFile(
                settings_path.resolve(strict=False),
                settings_before,
                (json.dumps(payload, indent=2) + "\n").encode("utf-8"),
                before_mode=settings_mode,
                after_mode=settings_mode,
            ),
            TransitionFile(
                state_path.resolve(strict=False),
                state_before,
                state_after,
                before_mode=state_mode,
                after_mode=state_mode,
            ),
        )
        for change in files:
            change.payload()
        manifest = _adapter_result(
            self.harness,
            active=True,
            config_path=settings_path,
            shim_manifest=shim_manifest,
            notes=[
                "Guard hook entries added to ~/.config/muse/settings.json under the hooks section",
                "User model, skills, MCP servers, and any pre-existing hooks were preserved",
                "Approving a blocked Muse tool call resumes that exact call inside the pending hook",
            ],
        )
        return PreparedHarnessInstall(files, manifest)

    def install(self, context: HarnessContext) -> dict[str, object]:
        return self.prepare_install(context).publish(context.guard_home)

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="muse",
        )
        settings_path = self._user_settings_path(context)
        settings_unreadable = False
        if settings_path.is_file():
            _ensure_path_within_root(self._muse_config_dir(context).parent, settings_path, label="Muse")
            try:
                payload = json.loads(settings_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                settings_unreadable = True
                payload = None
            if isinstance(payload, dict):
                hooks = payload.get("hooks")
                if isinstance(hooks, dict):
                    for event_name in list(hooks):
                        entries = hooks.get(event_name)
                        if not isinstance(entries, list):
                            continue
                        remaining = prune_managed_hook_entries(
                            entries,
                            is_managed=is_guard_managed_hook_command,
                        )
                        if remaining:
                            hooks[event_name] = remaining
                        else:
                            hooks.pop(event_name, None)
                    if not hooks:
                        payload.pop("hooks", None)
                    else:
                        payload["hooks"] = hooks
                    _write_json_atomic(settings_path, payload)

        _state_dir, _backup_path, state_path = self._managed_state_paths(context)
        if state_path.is_file():
            state_path.unlink()

        if settings_unreadable:
            hook_notes = ["Muse settings could not be parsed; Guard left the file untouched."]
        else:
            hook_notes = [
                "Guard-managed hook entries removed from ~/.config/muse/settings.json",
                "User model, skills, MCP servers, and any pre-existing hooks were preserved",
            ]
        return _adapter_result(
            self.harness,
            active=False,
            config_path=settings_path,
            shim_manifest=shim_manifest,
            notes=hook_notes,
        )

    def _sync_managed_hook_groups(
        self,
        context: HarnessContext,
        hooks: dict[str, object],
        managed_command: str,
    ) -> None:
        """Reconcile Guard-managed hook groups inside ``hooks``.

        User entries are preserved; stale Guard-managed handlers are pruned
        before the current managed handler is merged back in so repeated
        installs stay idempotent. No matcher is set: Muse reads an omitted
        matcher as every tool, so shell, file, search, web, and MCP calls
        all reach Guard.
        """

        for event_name in list(hooks):
            entries = hooks.get(event_name)
            if not isinstance(entries, list):
                continue
            remaining = prune_managed_hook_entries(
                entries,
                is_managed=is_guard_managed_hook_command,
            )
            if remaining:
                hooks[event_name] = remaining
            else:
                hooks.pop(event_name, None)

        # Every managed timeout stays above the bridge's own deadline so Muse
        # waits for Guard's answer instead of killing the bridge mid-review.
        bridge_timeout = self._bridge_timeout_seconds(context)
        long_timeout = bridge_timeout + _MUSE_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS
        # Events that never wait for an approval only have to outlast the
        # client's own floor.
        short_timeout = max(
            _MUSE_MANAGED_HOOK_TIMEOUT_SECONDS,
            _GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS + _MUSE_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS,
        )
        managed_groups: list[tuple[str, int]] = [
            ("PreToolUse", long_timeout),
            ("PermissionRequest", short_timeout),
            ("UserPromptSubmit", short_timeout),
            ("PostToolUse", long_timeout),
            ("SessionStart", short_timeout),
            ("Stop", short_timeout),
        ]
        for event_name, timeout in managed_groups:
            handler: dict[str, object] = {
                "type": "command",
                "command": managed_command,
                "timeout": timeout,
                "statusMessage": "HOL Guard is checking this action",
            }
            entries = hooks.get(event_name)
            hooks[event_name] = merge_hook_entry(
                entries if isinstance(entries, list) else [],
                None,
                handler,
                is_managed=is_guard_managed_hook_command,
            )


__all__ = ["MUSE_GUARD_EVENTS", "MuseHarnessAdapter"]
