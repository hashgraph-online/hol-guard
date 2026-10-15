"""Devin CLI harness adapter for HOL Guard.

Devin's user config lives under ``~/.config/devin/config.json`` (or
``%APPDATA%\\devin\\config.json`` on Windows). Its ``hooks`` key is
Claude-Code-shaped: ``{"<Event>": [{"matcher": <regex>, "hooks": [{"type":
"command", "command": ..., "timeout": 30}]}]}``. Project hooks live in
``.devin/hooks.v1.json`` (the hooks object is the whole file),
``.devin/config.json``, and ``.devin/config.local.json``. All config files are
JSONC; Guard inventories them through a tolerant read but refuses to rewrite
a file it cannot preserve byte-for-byte.

This adapter discovers hooks, MCP servers (``mcpServers`` in the
``mcp_config`` files and in legacy ``config.json`` files), and skill roots;
installs Guard-managed ``PreToolUse``, ``PermissionRequest``,
``UserPromptSubmit``, and ``PostToolUse`` hooks into the user ``config.json``
``hooks`` section (idempotently, without touching other keys); and routes
Devin hook events through the shared Guard runtime.
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
from .devin_config import (
    DEVIN_CONFIG_FILE,
    DEVIN_DIR,
    DEVIN_GUARD_TOOL_MATCHER,
    is_guard_managed_hook_command,
    load_devin_jsonc,
    parse_devin_jsonc,
)
from .hook_group_merge import merge_hook_entry, prune_managed_hook_entries

_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS = 25
_DEVIN_MANAGED_HOOK_TIMEOUT_SECONDS = 30
_DEVIN_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS = 5

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


class DevinHarnessAdapter(HarnessAdapter):
    """Discover Devin settings, hooks, MCP, and skills; manage Guard protection."""

    harness = "devin"
    aliases = ("devin", "devin-cli", "cognition-devin")
    executable = "devin"
    launcher_name = "devin"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard scans Devin config, hooks, skills, and MCP registrations before launch "
        "and routes blocked actions to the local approval center."
    )
    fallback_hint = (
        "Devin gets preflight approval through Guard until it exposes a richer native approval surface. "
        "Use the Guard approval center when native prompting is unavailable."
    )

    @staticmethod
    def _devin_config_dir(context: HarnessContext) -> Path:
        if os.name == "nt":
            appdata = os.environ.get("APPDATA")
            if isinstance(appdata, str) and appdata.strip():
                return Path(appdata.strip()) / "devin"
        return context.home_dir / ".config" / "devin"

    @classmethod
    def _user_config_path(cls, context: HarnessContext) -> Path:
        return cls._devin_config_dir(context) / DEVIN_CONFIG_FILE

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            project_config = context.workspace_dir / DEVIN_DIR / DEVIN_CONFIG_FILE
            if project_config.is_file():
                return project_config
        return self._user_config_path(context)

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        del context
        return ()

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_dir = self._devin_config_dir(context)
        request = {**detection_request(self.harness, context), "config_dir": str(config_dir)}
        if not config_dir.is_absolute() and "cwd" not in request:
            request["cwd"] = os.getcwd()
        artifacts, found_paths, warnings = native_adapter_detection_with_warnings("devin_detect", request)
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
        state_dir = context.guard_home / "managed" / "devin"
        backup_path = state_dir / "config.json.backup"
        state_path = state_dir / "install.state.json"
        _ensure_path_within_root(context.guard_home, state_dir, label="Devin state")
        _ensure_path_within_root(state_dir, backup_path, label="Devin backup")
        _ensure_path_within_root(state_dir, state_path, label="Devin state")
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
            "devin",
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
            harness="devin",
            timeout_seconds=_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS,
            prepared_files=prepared_files,
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
            + _DEVIN_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS
        )

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..codex_hook_file_integrity import CodexHookIntegrityError
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import TransitionFile

        config_path = self._user_config_path(context)
        _ensure_path_within_root(self._devin_config_dir(context).parent, config_path, label="Devin")
        try:
            config_before = _snapshot(config_path)
        except CodexHookIntegrityError as exc:
            raise ValueError("Devin config could not be parsed safely; Guard will not rewrite it.") from exc
        payload: dict[str, object] = {}
        if config_before is not None:
            try:
                document = parse_devin_jsonc(config_before.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise ValueError(
                    "Devin config could not be parsed as a JSON object; Guard will not rewrite it."
                ) from exc
            if document.parse_failed:
                raise ValueError(
                    "Devin config at ~/.config/devin/config.json could not be parsed as a JSON object; "
                    "Guard will not rewrite it. Fix the file, then rerun hol-guard install devin."
                )
            if document.had_comments:
                raise ValueError(
                    "Devin config at ~/.config/devin/config.json contains comments or trailing commas; Guard "
                    "will not rewrite it. Remove the comments or move them to another file, then rerun "
                    "hol-guard install devin."
                )
            payload = document.payload
            existing_hooks = payload.get("hooks")
            if existing_hooks is not None and not isinstance(existing_hooks, dict):
                raise ValueError("Devin config has a non-object hooks value; Guard will not rewrite it.")
        prepared_shim = prepare_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="devin",
        )
        shim_manifest = prepared_shim.manifest
        _state_dir, backup_path, state_path = self._managed_state_paths(context)
        backup_before = _snapshot(backup_path)
        state_before = _snapshot(state_path)
        hook_files: list[TransitionFile] = []
        hook_command = _shell_command(self._hook_command_parts(context, prepared_files=hook_files))
        hooks_value = payload.get("hooks")
        hooks: dict[str, object] = hooks_value if isinstance(hooks_value, dict) else {}
        payload["hooks"] = hooks

        self._sync_managed_hook_groups(context, hooks, hook_command)
        config_mode = config_path.stat().st_mode & 0o777 if config_before is not None else 0o600
        backup_mode = backup_path.stat().st_mode & 0o777 if backup_before is not None else config_mode
        state_mode = state_path.stat().st_mode & 0o777 if state_before is not None else 0o600
        state_after = (json.dumps({"managed_config_path": str(config_path)}, indent=2) + "\n").encode("utf-8")
        files = (
            *prepared_shim.files,
            *hook_files,
            TransitionFile(
                backup_path.resolve(strict=False),
                backup_before,
                backup_before if backup_before is not None else config_before,
                before_mode=backup_mode,
                after_mode=backup_mode,
            ),
            TransitionFile(
                config_path.resolve(strict=False),
                config_before,
                (json.dumps(payload, indent=2) + "\n").encode("utf-8"),
                before_mode=config_mode,
                after_mode=config_mode,
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
            config_path=config_path,
            shim_manifest=shim_manifest,
            notes=[
                "Guard hook entries added to ~/.config/devin/config.json under the hooks section",
                "User permissions, read_config_from, MCP servers, and any pre-existing hooks were preserved",
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
            display_name="devin",
        )
        config_path = self._user_config_path(context)
        managed_hooks_left_in_place = False
        config_unreadable = False
        if config_path.is_file():
            _ensure_path_within_root(self._devin_config_dir(context).parent, config_path, label="Devin")
            document = load_devin_jsonc(config_path)
            # A JSONC or unparseable file is never rewritten: pruning would
            # silently strip the user's comments or data. Guard-managed
            # handlers inside it stay behind.
            if document.parse_failed:
                config_unreadable = True
            elif document.had_comments:
                managed_hooks_left_in_place = True
            else:
                payload = document.payload
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
                    _write_json_atomic(config_path, payload)

        _state_dir, _backup_path, state_path = self._managed_state_paths(context)
        if state_path.is_file():
            state_path.unlink()

        if config_unreadable:
            hook_notes = ["Devin config could not be parsed; Guard left the file untouched."]
        elif managed_hooks_left_in_place:
            hook_notes = [
                "Devin config is JSONC (comments or trailing commas); Guard left its managed hook entries "
                "in place rather than rewriting the file. Remove the entries under the hooks key manually."
            ]
        else:
            hook_notes = [
                "Guard-managed hook entries removed from ~/.config/devin/config.json",
                "User permissions, read_config_from, MCP servers, and any pre-existing hooks were preserved",
            ]
        return _adapter_result(
            self.harness,
            active=False,
            config_path=config_path,
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
        installs stay idempotent.
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

        long_timeout = self._approval_wait_hook_timeout_seconds(context)
        managed_groups: list[tuple[str, str | None, int]] = [
            ("PreToolUse", DEVIN_GUARD_TOOL_MATCHER, long_timeout),
            ("PermissionRequest", DEVIN_GUARD_TOOL_MATCHER, _DEVIN_MANAGED_HOOK_TIMEOUT_SECONDS),
            ("UserPromptSubmit", None, _DEVIN_MANAGED_HOOK_TIMEOUT_SECONDS),
            ("PostToolUse", DEVIN_GUARD_TOOL_MATCHER, long_timeout),
        ]
        for event_name, matcher, timeout in managed_groups:
            handler: dict[str, object] = {
                "type": "command",
                "command": managed_command,
                "timeout": timeout,
            }
            entries = hooks.get(event_name)
            hooks[event_name] = merge_hook_entry(
                entries if isinstance(entries, list) else [],
                matcher,
                handler,
                is_managed=is_guard_managed_hook_command,
            )


__all__ = ["DevinHarnessAdapter"]
