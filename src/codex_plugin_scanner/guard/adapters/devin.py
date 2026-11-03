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

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ..aibom_detection import extend_detection_with_workspace_aibom, native_adapter_detection_with_warnings
from ..config import load_guard_config
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
from .devin_config import DEVIN_CONFIG_FILE, DEVIN_DIR
from .harness_hook_settings import plan_settings_uninstall, prepare_settings_install, write_settings

_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS = 25

if TYPE_CHECKING:
    from ..runtime_transition import TransitionFile


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
        command_available = _command_available(self.executable, context.home_dir)
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

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..codex_hook_file_integrity import CodexHookIntegrityError
        from ..codex_hook_recovery import _snapshot

        config_path = self._user_config_path(context)
        _ensure_path_within_root(self._devin_config_dir(context).parent, config_path, label="Devin")
        try:
            config_before = _snapshot(config_path)
        except CodexHookIntegrityError as exc:
            raise ValueError("Devin config could not be parsed safely; Guard will not rewrite it.") from exc
        approval_wait_seconds = load_guard_config(
            context.guard_home,
            context.workspace_dir,
            create_home=False,
        ).approval_wait_timeout_seconds
        hook_files: list[TransitionFile] = []
        hook_command = _shell_command(self._hook_command_parts(context, prepared_files=hook_files))
        _state_dir, backup_path, state_path = self._managed_state_paths(context)
        # Native: the JSONC read and its refusals, Guard's hook groups and the
        # rendered settings and install state.
        settings_files, notes = prepare_settings_install(
            "devin",
            config_path=config_path,
            config_before=config_before,
            backup_path=backup_path,
            state_path=state_path,
            command=hook_command,
            timing_seconds=approval_wait_seconds,
        )
        prepared_shim = prepare_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="devin",
        )
        files = (*prepared_shim.files, *hook_files, *settings_files)
        for change in files:
            change.payload()
        manifest = _adapter_result(
            self.harness,
            active=True,
            config_path=config_path,
            shim_manifest=prepared_shim.manifest,
            notes=notes,
        )
        return PreparedHarnessInstall(files, manifest)

    def install(self, context: HarnessContext) -> dict[str, object]:
        return self.prepare_install(context).publish(context.guard_home)

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        config_path = self._user_config_path(context)
        if config_path.is_file():
            _ensure_path_within_root(self._devin_config_dir(context).parent, config_path, label="Devin")
        # The prune asks the native runtime first, so a refusal leaves the
        # launcher, the settings and the install state as they were.
        text, notes = plan_settings_uninstall("devin", config_path)
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="devin",
        )
        if text is not None:
            write_settings(config_path, text)

        _state_dir, _backup_path, state_path = self._managed_state_paths(context)
        if state_path.is_file():
            state_path.unlink()
        return _adapter_result(
            self.harness,
            active=False,
            config_path=config_path,
            shim_manifest=shim_manifest,
            notes=notes,
        )


__all__ = ["DevinHarnessAdapter"]
