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

from ..aibom_detection import extend_detection_with_workspace_aibom
from ..codex_hook_integrity import atomic_write_text
from ..config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, load_guard_config
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import (
    HarnessAdapter,
    HarnessContext,
    _command_available,
    _ensure_path_within_root,
    _json_payload,
    _shell_command,
)
from .bounded_cli_hook_bridge import bounded_cli_hook_command
from .devin_config import (
    CLAUDE_HOOK_SETTINGS_BASENAMES,
    CLAUDE_HOOK_USER_PATHS,
    DEVIN_AGENTS_SKILLS_DIR,
    DEVIN_CONFIG_FILE,
    DEVIN_DIR,
    DEVIN_GUARD_TOOL_MATCHER,
    DEVIN_HOOKS_FILE,
    DEVIN_LOCAL_CONFIG_FILE,
    DEVIN_LOCAL_MCP_CONFIG_FILE,
    DEVIN_MCP_CONFIG_FILE,
    DEVIN_SKILLS_DIR,
    append_devin_hook_artifacts,
    append_devin_skill_artifacts,
    append_found_path,
    append_mcp_server_artifacts,
    has_guard_managed_claude_hooks,
    is_guard_managed_hook_command,
    load_devin_jsonc,
)
from .hook_group_merge import merge_hook_entry, prune_managed_hook_entries

_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS = 25
_DEVIN_MANAGED_HOOK_TIMEOUT_SECONDS = 30
_DEVIN_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS = 5


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

    @classmethod
    def _user_mcp_path(cls, context: HarnessContext) -> Path:
        return cls._devin_config_dir(context) / DEVIN_MCP_CONFIG_FILE

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            project_config = context.workspace_dir / DEVIN_DIR / DEVIN_CONFIG_FILE
            if project_config.is_file():
                return project_config
        return self._user_config_path(context)

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        del context
        return ()

    def _config_candidates(self, context: HarnessContext) -> list[tuple[Path, str]]:
        candidates: list[tuple[Path, str]] = [(self._user_config_path(context), "global")]
        if context.workspace_dir is not None:
            project_root = context.workspace_dir / DEVIN_DIR
            candidates.extend(
                [
                    (project_root / DEVIN_CONFIG_FILE, "project"),
                    (project_root / DEVIN_LOCAL_CONFIG_FILE, "project"),
                ]
            )
        return candidates

    def _mcp_candidates(self, context: HarnessContext) -> list[tuple[Path, str]]:
        candidates: list[tuple[Path, str]] = [(self._user_mcp_path(context), "global")]
        if context.workspace_dir is not None:
            project_root = context.workspace_dir / DEVIN_DIR
            candidates.extend(
                [
                    (project_root / DEVIN_MCP_CONFIG_FILE, "project"),
                    (project_root / DEVIN_LOCAL_MCP_CONFIG_FILE, "project"),
                ]
            )
        return candidates

    def _skill_candidates(self, context: HarnessContext) -> list[tuple[Path, Path, str]]:
        candidates: list[tuple[Path, Path, str]] = [
            (
                self._devin_config_dir(context) / DEVIN_SKILLS_DIR,
                self._devin_config_dir(context).parent,
                "global",
            ),
            (
                context.home_dir / DEVIN_AGENTS_SKILLS_DIR,
                context.home_dir,
                "global",
            ),
        ]
        if context.workspace_dir is not None:
            candidates.extend(
                [
                    (
                        context.workspace_dir / DEVIN_DIR / DEVIN_SKILLS_DIR,
                        context.workspace_dir,
                        "project",
                    ),
                    (
                        context.workspace_dir / DEVIN_AGENTS_SKILLS_DIR,
                        context.workspace_dir,
                        "project",
                    ),
                ]
            )
        return candidates

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        warnings: list[str] = []

        user_config_payload: dict[str, object] = {}
        for config_path, scope in self._config_candidates(context):
            if not config_path.is_file():
                continue
            append_found_path(found_paths, config_path)
            document = load_devin_jsonc(config_path)
            if document.parse_failed:
                warnings.append(
                    f"Devin config at {config_path} could not be parsed; "
                    "hooks and MCP servers in it were not inventoried."
                )
                continue
            payload = document.payload
            if config_path == self._user_config_path(context):
                user_config_payload = payload
            if not payload:
                continue
            append_devin_hook_artifacts(
                artifacts=artifacts,
                hooks=payload.get("hooks"),
                config_path=config_path,
                scope=scope,
            )
            # Legacy Devin versions kept mcpServers inside config.json.
            append_mcp_server_artifacts(
                harness=self.harness,
                artifacts=artifacts,
                servers=payload.get("mcpServers"),
                config_path=config_path,
                scope=scope,
            )

        if context.workspace_dir is not None:
            hooks_v1_path = context.workspace_dir / DEVIN_DIR / DEVIN_HOOKS_FILE
            if hooks_v1_path.is_file():
                append_found_path(found_paths, hooks_v1_path)
                document = load_devin_jsonc(hooks_v1_path)
                if document.parse_failed:
                    warnings.append(
                        f"Devin config at {hooks_v1_path} could not be parsed; "
                        "hooks and MCP servers in it were not inventoried."
                    )
                else:
                    # hooks.v1.json is the hooks object itself, not wrapped.
                    append_devin_hook_artifacts(
                        artifacts=artifacts,
                        hooks=document.payload,
                        config_path=hooks_v1_path,
                        scope="project",
                    )

        for mcp_path, scope in self._mcp_candidates(context):
            if not mcp_path.is_file():
                continue
            append_found_path(found_paths, mcp_path)
            document = load_devin_jsonc(mcp_path)
            if document.parse_failed:
                warnings.append(
                    f"Devin config at {mcp_path} could not be parsed; hooks and MCP servers in it were not inventoried."
                )
                continue
            payload = document.payload
            append_mcp_server_artifacts(
                harness=self.harness,
                artifacts=artifacts,
                servers=payload.get("mcpServers"),
                config_path=mcp_path,
                scope=scope,
            )

        for skill_root, identity_scope_root, scope in self._skill_candidates(context):
            append_devin_skill_artifacts(
                artifacts=artifacts,
                found_paths=found_paths,
                warnings=warnings,
                skill_root=skill_root,
                identity_scope_root=identity_scope_root,
                scope=scope,
            )

        command_available = _command_available(self.executable)
        if self._claude_hooks_overlap(context, user_config_payload):
            warnings.append(
                "Devin also loads Claude Code hooks by default, so Guard's Claude Code hooks will run inside "
                "Devin sessions and attribute them to Claude Code. Set read_config_from.claude to false in "
                "Devin's user config if you want Devin events attributed only to the Devin adapter."
            )

        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or command_available,
            command_available=command_available,
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=tuple(dict.fromkeys(warnings)),
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def _claude_hooks_overlap(self, context: HarnessContext, user_config: dict[str, object]) -> bool:
        """Return True when Guard-managed Claude hooks would also run in Devin."""

        read_config_from = user_config.get("read_config_from")
        if isinstance(read_config_from, dict) and read_config_from.get("claude") is False:
            return False

        candidates = [context.home_dir / relative for relative in CLAUDE_HOOK_USER_PATHS]
        if context.workspace_dir is not None:
            candidates.extend(context.workspace_dir / relative for relative in CLAUDE_HOOK_SETTINGS_BASENAMES)
        for path in candidates:
            if not path.is_file():
                continue
            payload = _json_payload(path)
            if payload and has_guard_managed_claude_hooks(payload):
                return True
        return False

    def _managed_state_paths(self, context: HarnessContext) -> tuple[Path, Path, Path]:
        state_dir = context.guard_home / "managed" / "devin"
        backup_path = state_dir / "config.json.backup"
        state_path = state_dir / "install.state.json"
        _ensure_path_within_root(context.guard_home, state_dir, label="Devin state")
        _ensure_path_within_root(state_dir, backup_path, label="Devin backup")
        _ensure_path_within_root(state_dir, state_path, label="Devin state")
        return state_dir, backup_path, state_path

    @staticmethod
    def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
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
        )

    @staticmethod
    def _approval_wait_hook_timeout_seconds(context: HarnessContext) -> int:
        configured_wait_timeout = load_guard_config(
            context.guard_home,
            context.workspace_dir,
        ).approval_wait_timeout_seconds
        return (
            min(
                max(configured_wait_timeout, 0),
                MAX_APPROVAL_WAIT_TIMEOUT_SECONDS,
            )
            + _DEVIN_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        config_path = self._user_config_path(context)
        _ensure_path_within_root(self._devin_config_dir(context).parent, config_path, label="Devin")
        payload: dict[str, object] = {}
        if config_path.is_file():
            document = load_devin_jsonc(config_path)
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
        shim_manifest = install_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="devin",
        )
        config_path.parent.mkdir(parents=True, exist_ok=True)

        state_dir, backup_path, state_path = self._managed_state_paths(context)
        state_dir.mkdir(parents=True, exist_ok=True)
        # The backup preserves the pre-Guard original so uninstall can restore
        # it; it is intentionally not refreshed on reinstall.
        if config_path.is_file() and not backup_path.exists():
            import shutil

            shutil.copy2(config_path, backup_path)

        hook_command = _shell_command(self._hook_command_parts(context))
        hooks_value = payload.get("hooks")
        hooks: dict[str, object] = hooks_value if isinstance(hooks_value, dict) else {}
        payload["hooks"] = hooks

        self._sync_managed_hook_groups(context, hooks, hook_command)
        _write_json_atomic(config_path, payload)

        _write_json_atomic(state_path, {"managed_config_path": str(config_path)})

        return _adapter_result(
            self.harness,
            active=True,
            config_path=config_path,
            shim_manifest=shim_manifest,
            notes=[
                "Guard hook entries added to ~/.config/devin/config.json under the hooks section",
                "User permissions, read_config_from, MCP servers, and any pre-existing hooks were preserved",
            ],
        )

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
