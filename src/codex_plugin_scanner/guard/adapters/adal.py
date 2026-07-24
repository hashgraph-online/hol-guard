"""AdaL harness adapter for HOL Guard."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from ..aibom_detection import extend_detection_with_workspace_aibom
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import (
    HarnessAdapter,
    HarnessContext,
    _command_available,
    _ensure_path_within_root,
    _shell_command,
)

ADAL_HOOK_EVENTS = (
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "UserPromptSubmit",
    "PermissionRequest",
    "Stop",
)
ADAL_TOOL_SCOPED_EVENTS = frozenset({"PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest"})
_ADAL_HOOK_TIMEOUT_SECONDS = 30
_MANAGED_COMMAND_TOKENS = (
    "codex_plugin_scanner.cli",
    "guard",
    "hook",
    "--harness",
    "adal",
)


def _is_guard_managed_hook_command(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return all(token in value for token in _MANAGED_COMMAND_TOKENS)


def _load_settings(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot update malformed AdaL settings at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Cannot update AdaL settings at {path}: root value must be an object")
    return payload


def _write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            temporary_path = Path(stream.name)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


class AdaLHarnessAdapter(HarnessAdapter):
    """Discover AdaL settings and manage lifecycle hook registration."""

    harness = "adal"
    aliases = ("adal", "adal-cli")
    executable = "adal"
    launcher_name = "adal"
    approval_summary = (
        "Guard reviews AdaL prompts and tool calls through managed lifecycle hooks. "
        "PreToolUse and UserPromptSubmit can block; later lifecycle events are observational."
    )
    fallback_hint = "Resolve the Guard finding, then retry the blocked AdaL prompt or tool call."

    @staticmethod
    def _settings_path(context: HarnessContext) -> Path:
        return context.home_dir / ".adal" / "settings.json"

    def policy_path(self, context: HarnessContext) -> Path:
        return self._settings_path(context)

    def detect(self, context: HarnessContext) -> HarnessDetection:
        settings_path = self._settings_path(context)
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        warnings: list[str] = []
        if settings_path.is_file():
            found_paths.append(str(settings_path))
            try:
                payload = _load_settings(settings_path)
            except ValueError as exc:
                warnings.append(str(exc))
            else:
                hooks = payload.get("hooks")
                if isinstance(hooks, dict):
                    artifacts.extend(self._hook_artifacts(settings_path, hooks))
        command_available = _command_available(self.executable)
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or command_available,
            command_available=command_available,
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=tuple(warnings),
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    @staticmethod
    def _hook_artifacts(settings_path: Path, hooks: dict[str, object]) -> list[GuardArtifact]:
        artifacts: list[GuardArtifact] = []
        for event_name, groups in hooks.items():
            if not isinstance(event_name, str) or not isinstance(groups, list):
                continue
            for group_index, group in enumerate(groups):
                if not isinstance(group, dict):
                    continue
                handlers = group.get("hooks")
                if not isinstance(handlers, list):
                    continue
                for handler_index, handler in enumerate(handlers):
                    if not isinstance(handler, dict):
                        continue
                    command = handler.get("command")
                    if not isinstance(command, str) or not command.strip():
                        continue
                    matcher = group.get("matcher")
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"adal:global:hook:{event_name}:{group_index}:{handler_index}",
                            name=f"{event_name} hook",
                            harness="adal",
                            artifact_type="hook",
                            source_scope="global",
                            config_path=str(settings_path),
                            command=command,
                            metadata={
                                "event": event_name,
                                "matcher": matcher if isinstance(matcher, str) else None,
                                "guard_managed": _is_guard_managed_hook_command(command),
                            },
                        )
                    )
        return artifacts

    @staticmethod
    def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        guard_args = [
            "guard",
            "hook",
            "--guard-home",
            str(context.guard_home),
            "--harness",
            "adal",
        ]
        if context.home_dir.resolve() != Path.home().resolve():
            guard_args.extend(["--home", str(context.home_dir)])
        if context.workspace_dir is not None:
            guard_args.extend(["--workspace", str(context.workspace_dir)])
        package_root = Path(__file__).resolve().parents[3]
        code = (
            "import sys;"
            f"sys.path.insert(0, {str(package_root)!r});"
            "from codex_plugin_scanner.cli import main;"
            f"raise SystemExit(main({guard_args!r}))"
        )
        return (sys.executable, "-c", code)

    def install(self, context: HarnessContext) -> dict[str, object]:
        settings_path = self._settings_path(context)
        _ensure_path_within_root(context.home_dir, settings_path, label="AdaL")
        payload = _load_settings(settings_path)
        hooks = payload.get("hooks")
        if hooks is None:
            hooks = {}
        elif not isinstance(hooks, dict):
            raise ValueError(f"Cannot update AdaL settings at {settings_path}: hooks must be an object")
        for event_name in ADAL_HOOK_EVENTS:
            if event_name in hooks and not isinstance(hooks[event_name], list):
                raise ValueError(f"Cannot update AdaL settings at {settings_path}: {event_name} hooks must be a list")
        payload["hooks"] = hooks

        shim_manifest = install_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="adal",
        )
        command = _shell_command(self._hook_command_parts(context))
        self._sync_managed_hooks(hooks, command)
        _write_json_atomic(settings_path, payload)

        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(settings_path),
            **shim_manifest,
            "notes": [
                "Guard lifecycle hooks added to ~/.adal/settings.json",
                "Existing AdaL settings and user hooks were preserved",
                "PreToolUse and UserPromptSubmit enforce decisions; remaining events are observational",
                *shim_notes,
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="adal",
        )
        settings_path = self._settings_path(context)
        if settings_path.is_file():
            _ensure_path_within_root(context.home_dir, settings_path, label="AdaL")
            payload = _load_settings(settings_path)
            hooks = payload.get("hooks")
            if isinstance(hooks, dict):
                self._prune_managed_hooks(hooks)
                if hooks:
                    payload["hooks"] = hooks
                else:
                    payload.pop("hooks", None)
                _write_json_atomic(settings_path, payload)

        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(settings_path),
            **shim_manifest,
            "notes": [
                "Guard-managed hooks removed from ~/.adal/settings.json",
                "Existing AdaL settings and user hooks were preserved",
                *shim_notes,
            ],
        }

    @staticmethod
    def _sync_managed_hooks(hooks: dict[str, object], command: str) -> None:
        AdaLHarnessAdapter._prune_managed_hooks(hooks)
        handler = {
            "type": "command",
            "command": command,
            "timeout": _ADAL_HOOK_TIMEOUT_SECONDS,
        }
        for event_name in ADAL_HOOK_EVENTS:
            entries = hooks.get(event_name)
            normalized_entries = list(entries) if isinstance(entries, list) else []
            group: dict[str, object] = {"hooks": [dict(handler)]}
            if event_name in ADAL_TOOL_SCOPED_EVENTS:
                group["matcher"] = "*"
            normalized_entries.append(group)
            hooks[event_name] = normalized_entries

    @staticmethod
    def _prune_managed_hooks(hooks: dict[str, object]) -> None:
        for event_name in ADAL_HOOK_EVENTS:
            entries = hooks.get(event_name)
            if not isinstance(entries, list):
                continue
            remaining: list[object] = []
            for entry in entries:
                if not isinstance(entry, dict):
                    remaining.append(entry)
                    continue
                handlers = entry.get("hooks")
                if not isinstance(handlers, list):
                    remaining.append(entry)
                    continue
                filtered = [
                    handler
                    for handler in handlers
                    if not (isinstance(handler, dict) and _is_guard_managed_hook_command(handler.get("command")))
                ]
                if filtered:
                    updated = dict(entry)
                    updated["hooks"] = filtered
                    remaining.append(updated)
            if remaining:
                hooks[event_name] = remaining
            else:
                hooks.pop(event_name, None)


__all__ = [
    "ADAL_HOOK_EVENTS",
    "ADAL_TOOL_SCOPED_EVENTS",
    "AdaLHarnessAdapter",
]
