"""Kimi Code CLI harness adapter for HOL Guard."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ..aibom_detection import extend_detection_with_workspace_aibom, native_adapter_detection_with_warnings
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

_KIMI_HOME_ENV_VAR = "KIMI_CODE_HOME"
_KIMI_DIR = ".kimi-code"
_KIMI_CONFIG_FILE = "config.toml"
_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS = 25


_GUARD_MANAGED_BEGIN = "# BEGIN HOL GUARD MANAGED HOOKS"
_GUARD_MANAGED_END = "# END HOL GUARD MANAGED HOOKS"
_GUARD_MANAGED_MARKER = "HOL GUARD MANAGED HOOKS"


if TYPE_CHECKING:
    from ..runtime_transition import TransitionFile


class KimiHarnessAdapter(HarnessAdapter):
    """Discover Kimi Code CLI settings, hooks, MCP servers, and manage Guard hooks."""

    harness = "kimi"
    aliases = ("kimi", "kimi-code", "kimi-cli")
    executable = "kimi"
    launcher_name = "kimi"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard scans Kimi Code config, hooks, and MCP registrations before launch "
        "and routes blocked changes to the local approval center."
    )
    fallback_hint = "Kimi Code gets preflight approval through Guard until it exposes a richer native approval surface."

    @staticmethod
    def _kimi_home_dir(context: HarnessContext) -> Path:
        value = os.environ.get(_KIMI_HOME_ENV_VAR)
        if value:
            return Path(value).expanduser().resolve()
        return context.home_dir

    def policy_path(self, context: HarnessContext) -> Path:
        home = self._kimi_home_dir(context)
        if context.workspace_dir is not None:
            return context.workspace_dir / _KIMI_DIR / _KIMI_CONFIG_FILE
        return home / _KIMI_DIR / _KIMI_CONFIG_FILE

    def _managed_config_path(self, context: HarnessContext) -> Path:
        home = self._kimi_home_dir(context)
        return home / _KIMI_DIR / _KIMI_CONFIG_FILE

    def detect(self, context: HarnessContext) -> HarnessDetection:
        request = {**detection_request(self.harness, context), "home": str(self._kimi_home_dir(context))}
        artifacts, found_paths, warnings = native_adapter_detection_with_warnings("kimi_detect", request)
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
            "kimi",
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
            harness="kimi",
            timeout_seconds=_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS,
            prepared_files=prepared_files,
        )

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import TransitionFile

        prepared_shim = prepare_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="kimi",
        )
        shim_manifest = prepared_shim.manifest
        config_path = self._managed_config_path(context)
        _ensure_path_within_root(context.home_dir, config_path, label="Kimi Code")
        hook_files: list[TransitionFile] = []
        hook_command = _shell_command(self._hook_command_parts(context, prepared_files=hook_files))
        managed_block = self._build_managed_block(hook_command)
        before = _snapshot(config_path)
        existing_text = before.decode("utf-8") if before is not None else ""
        cleaned_text = _remove_managed_block(existing_text)
        new_text = f"{cleaned_text.rstrip()}\n\n{managed_block}\n".lstrip()
        mode = config_path.stat().st_mode & 0o777 if before is not None else 0o644
        config = TransitionFile(
            config_path.resolve(strict=False),
            before,
            new_text.encode("utf-8"),
            before_mode=mode,
            after_mode=mode,
        )
        config.payload()

        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        manifest: dict[str, object] = {
            "harness": self.harness,
            "active": True,
            "config_path": str(config_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries added to ~/.kimi-code/config.toml",
                *shim_notes,
            ],
        }
        return PreparedHarnessInstall((*prepared_shim.files, *hook_files, config), manifest)

    def install(self, context: HarnessContext) -> dict[str, object]:
        return self.prepare_install(context).publish(context.guard_home)

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="kimi",
        )
        config_path = self._managed_config_path(context)
        if config_path.is_file():
            _ensure_path_within_root(context.home_dir, config_path, label="Kimi Code")
            existing_text = config_path.read_text(encoding="utf-8")
            cleaned_text = _remove_managed_block(existing_text)
            config_path.write_text(cleaned_text.rstrip() + "\n", encoding="utf-8")
        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(config_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries removed from ~/.kimi-code/config.toml",
                *shim_notes,
            ],
        }

    @staticmethod
    def _build_managed_block(hook_command: str) -> str:
        escaped_command = _toml_escape(hook_command)
        lines = [
            _GUARD_MANAGED_BEGIN,
            "# The hooks below are managed by HOL Guard. Do not edit manually.",
        ]
        for event in ("PreToolUse", "UserPromptSubmit", "PostToolUse", "SessionStart", "Stop"):
            lines.extend(
                [
                    "[[hooks]]",
                    f'event = "{event}"',
                    f'command = "{escaped_command}"',
                    "timeout = 30",
                ]
            )
        lines.append(_GUARD_MANAGED_END)
        return "\n".join(lines)


def _toml_escape(value: str) -> str:
    """Escape backslashes and double quotes for a TOML double-quoted string."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _remove_managed_block(text: str) -> str:
    pattern = re.compile(
        rf"^\s*{re.escape(_GUARD_MANAGED_BEGIN)}.*?{re.escape(_GUARD_MANAGED_END)}\s*\n?",
        re.MULTILINE | re.DOTALL,
    )
    cleaned = pattern.sub("", text)
    # Also remove any leftover marker-only lines from partial edits.
    cleaned = re.sub(rf"^\s*#.*{re.escape(_GUARD_MANAGED_MARKER)}.*$\n?", "", cleaned, flags=re.MULTILINE)
    return cleaned
