"""z.ai ZCode harness adapter for HOL Guard.

ZCode is z.ai's local AI coding harness. Its CLI app config lives under
``~/.zcode/cli/config.json`` and is Claude-Code-shaped: an ``mcp`` section, a
``plugins`` section, and an optional ``hooks`` section that follows Claude
Code's hook group schema. Plugins are cached under
``~/.zcode/cli/plugins/cache/<marketplace>/<plugin>/<version>/``.

This adapter discovers MCP servers, enabled plugins, plugin manifests and
provenance, plugin hooks, skills, commands, and marketplaces; installs
Guard-managed ``PreToolUse`` and ``UserPromptSubmit`` hooks into the CLI
config ``hooks`` section (idempotently, without touching ``mcp`` or
``plugins``); and routes ZCode hook events through the shared Guard runtime.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from ..aibom_detection import extend_detection_with_workspace_aibom
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
from .zcode_config import (
    GUARD_MANAGED_MARKER,
    ZCODE_BUNDLE_IDENTIFIER,
    ZCODE_CLI_CONFIG_FILE,
    ZCODE_CLI_DIR,
    ZCODE_DIR,
    ZCODE_ENV_HINTS,
    ZCODE_MARKETPLACE_FILE,
    ZCODE_PLUGIN_CACHE_DIR,
    ZCODE_PLUGIN_MANIFEST_DIR,
    ZCODE_PLUGIN_MANIFEST_FILE,
    ZCODE_PLUGIN_MARKETPLACES_DIR,
    ZCODE_PRETOOL_MATCHERS,
    append_cli_config_artifacts,
    append_found_path,
    append_marketplace_artifacts,
    append_plugin_manifest_artifacts,
    is_guard_managed_hook_command,
)

_ZCODE_HOME_ENV_VAR = "ZCODE_HOME"
_ZCODE_PRETOOL_TIMEOUT_SECONDS = 30
_ZCODE_PROMPT_TIMEOUT_SECONDS = 30


class ZCodeHarnessAdapter(HarnessAdapter):
    """Discover z.ai ZCode settings, plugins, hooks, MCP, and manage Guard protection."""

    harness = "zcode"
    aliases = ("zcode", "zai", "z-code", "zai-zcode")
    executable = "zcode"
    launcher_name = "zcode"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard scans ZCode config, plugins, hooks, skills, and MCP registrations before launch "
        "and routes blocked actions to the local approval center."
    )
    fallback_hint = (
        "ZCode gets preflight approval through Guard until it exposes a richer native approval surface. "
        "Use the Guard approval center when native prompting is unavailable."
    )

    @staticmethod
    def _zcode_home_dir(context: HarnessContext) -> Path:
        value = os.environ.get(_ZCODE_HOME_ENV_VAR)
        if value:
            return Path(value).expanduser().resolve()
        return context.home_dir

    @classmethod
    def _cli_root(cls, context: HarnessContext) -> Path:
        return cls._zcode_home_dir(context) / ZCODE_CLI_DIR

    @classmethod
    def _config_path(cls, context: HarnessContext) -> Path:
        return cls._cli_root(context) / ZCODE_CLI_CONFIG_FILE

    @classmethod
    def _plugins_root(cls, context: HarnessContext) -> Path:
        return cls._cli_root(context) / ZCODE_PLUGIN_CACHE_DIR

    @classmethod
    def _marketplaces_root(cls, context: HarnessContext) -> Path:
        return cls._cli_root(context) / ZCODE_PLUGIN_MARKETPLACES_DIR

    @classmethod
    def _project_cli_root(cls, context: HarnessContext) -> Path | None:
        if context.workspace_dir is None:
            return None
        return context.workspace_dir / ZCODE_DIR / "cli"

    def policy_path(self, context: HarnessContext) -> Path:
        project_cli_root = self._project_cli_root(context)
        if project_cli_root is not None and (project_cli_root / ZCODE_CLI_CONFIG_FILE).is_file():
            return project_cli_root / ZCODE_CLI_CONFIG_FILE
        return self._config_path(context)

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        del context
        return ()

    @staticmethod
    def _detect_runtime_signal() -> bool:
        """Return True when ZCode runtime env hints or bundle id are present.

        These are non-secret process identifiers (app version, base URL, OAuth
        origin host). They are read only as a presence signal and never stored.
        """

        bundle = os.environ.get("__CFBundleIdentifier", "")  # noqa: SIM112 -- macOS sets this exact case-sensitive var
        if bundle.strip() == ZCODE_BUNDLE_IDENTIFIER:
            return True
        return any(os.environ.get(name) for name in ZCODE_ENV_HINTS)

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []

        for config_path in self._config_candidates(context):
            if not config_path.is_file():
                continue
            append_found_path(found_paths, config_path)
            payload = _json_payload(config_path)
            if payload:
                scope = self._scope_for(context, config_path)
                append_cli_config_artifacts(
                    harness=self.harness,
                    artifacts=artifacts,
                    payload=payload,
                    config_path=config_path,
                    scope=scope,
                )

        for plugins_root, scope in self._plugins_candidates(context):
            if not plugins_root.is_dir():
                continue
            for marketplace_dir in sorted(entry for entry in plugins_root.iterdir() if entry.is_dir()):
                for plugin_dir in sorted(entry for entry in marketplace_dir.iterdir() if entry.is_dir()):
                    for version_dir in sorted(entry for entry in plugin_dir.iterdir() if entry.is_dir()):
                        manifest_path = version_dir / ZCODE_PLUGIN_MANIFEST_DIR / ZCODE_PLUGIN_MANIFEST_FILE
                        if not manifest_path.is_file():
                            continue
                        append_plugin_manifest_artifacts(
                            harness=self.harness,
                            artifacts=artifacts,
                            found_paths=found_paths,
                            plugin_root=version_dir,
                            scope=scope,
                        )

        for marketplaces_root, scope in self._marketplaces_candidates(context):
            if not marketplaces_root.is_dir():
                continue
            for marketplace_dir in sorted(entry for entry in marketplaces_root.iterdir() if entry.is_dir()):
                marketplace_file = marketplace_dir / ZCODE_MARKETPLACE_FILE
                if marketplace_file.is_file():
                    append_marketplace_artifacts(
                        harness=self.harness,
                        artifacts=artifacts,
                        found_paths=found_paths,
                        marketplace_file=marketplace_file,
                        scope=scope,
                    )

        runtime_signal = self._detect_runtime_signal()
        command_available = _command_available(self.executable)
        installed = bool(found_paths) or runtime_signal or command_available
        warnings: list[str] = []
        if runtime_signal and not found_paths:
            warnings.append(
                "ZCode runtime was detected through process environment signals, but no "
                "~/.zcode/cli/config.json or plugin cache was found. Run ZCode once so it can "
                "initialize its local config before Guard install."
            )

        detection = HarnessDetection(
            harness=self.harness,
            installed=installed,
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

    def _config_candidates(self, context: HarnessContext) -> list[Path]:
        candidates = [self._config_path(context)]
        project_cli_root = self._project_cli_root(context)
        if project_cli_root is not None:
            candidates.append(project_cli_root / ZCODE_CLI_CONFIG_FILE)
        return candidates

    def _plugins_candidates(self, context: HarnessContext) -> list[tuple[Path, str]]:
        candidates: list[tuple[Path, str]] = [(self._plugins_root(context), "global")]
        project_cli_root = self._project_cli_root(context)
        if project_cli_root is not None:
            candidates.append((project_cli_root / ZCODE_PLUGIN_CACHE_DIR, "project"))
        return candidates

    def _marketplaces_candidates(self, context: HarnessContext) -> list[tuple[Path, str]]:
        candidates: list[tuple[Path, str]] = [(self._marketplaces_root(context), "global")]
        project_cli_root = self._project_cli_root(context)
        if project_cli_root is not None:
            candidates.append((project_cli_root / ZCODE_PLUGIN_MARKETPLACES_DIR, "project"))
        return candidates

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    # ---- install / uninstall -------------------------------------------------

    def _managed_state_dir(self, context: HarnessContext) -> Path:
        return context.guard_home / "managed" / "zcode"

    def _state_path(self, context: HarnessContext) -> Path:
        return self._managed_state_dir(context) / "install.state.json"

    def _backup_path(self, context: HarnessContext) -> Path:
        return self._managed_state_dir(context) / "config.json.backup"

    @staticmethod
    def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        guard_args = [
            "guard",
            "hook",
            "--guard-home",
            str(context.guard_home),
            "--harness",
            "zcode",
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

    @staticmethod
    def _managed_command_wrapper(hook_command: str) -> str:
        """Wrap a hook command so the Guard-managed marker travels with it.

        The marker is appended as a trailing shell comment so ZCode still runs
        the command verbatim while Guard can later detect and prune only its
        own managed hook entries.
        """

        return f"{hook_command} # {GUARD_MANAGED_MARKER}"

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="zcode",
        )
        config_path = self._config_path(context)
        _ensure_path_within_root(context.home_dir, config_path, label="ZCode")
        config_path.parent.mkdir(parents=True, exist_ok=True)

        payload = _json_payload(config_path)
        if not isinstance(payload.get("mcp"), dict):
            payload["mcp"] = {}
        if not isinstance(payload.get("plugins"), dict):
            payload["plugins"] = {}

        state_dir = self._managed_state_dir(context)
        state_dir.mkdir(parents=True, exist_ok=True)
        if config_path.is_file() and not self._backup_path(context).exists():
            import shutil

            shutil.copy2(config_path, self._backup_path(context))

        hook_command = _shell_command(self._hook_command_parts(context))
        managed_hook_command = self._managed_command_wrapper(hook_command)
        hooks = payload.get("hooks")
        if not isinstance(hooks, dict):
            hooks = {}
        payload["hooks"] = hooks

        self._sync_managed_hook_groups(hooks, managed_hook_command)
        config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

        self._state_path(context).write_text(
            json.dumps({"managed_config_path": str(config_path)}, indent=2) + "\n",
            encoding="utf-8",
        )

        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(config_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries added to ~/.zcode/cli/config.json under the hooks section",
                "User mcp, plugins, and any pre-existing hooks were preserved",
                *shim_notes,
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="zcode",
        )
        config_path = self._config_path(context)
        if config_path.is_file():
            _ensure_path_within_root(context.home_dir, config_path, label="ZCode")
            payload = _json_payload(config_path)
            hooks = payload.get("hooks")
            if isinstance(hooks, dict):
                self._prune_managed_hook_groups(hooks)
                if not hooks:
                    payload.pop("hooks", None)
                else:
                    payload["hooks"] = hooks
                config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

        state_path = self._state_path(context)
        if state_path.is_file():
            state_path.unlink()

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
                "Guard-managed hook entries removed from ~/.zcode/cli/config.json",
                "User mcp, plugins, and any pre-existing hooks were preserved",
                *shim_notes,
            ],
        }

    def _sync_managed_hook_groups(self, hooks: dict[str, object], managed_command: str) -> None:
        """Reconcile Guard-managed PreToolUse and UserPromptSubmit hook groups."""

        pretool_raw = hooks.get("PreToolUse")
        pretool_entries = self._prune_managed_entries(pretool_raw if isinstance(pretool_raw, list) else [])
        prompt_raw = hooks.get("UserPromptSubmit")
        prompt_entries = self._prune_managed_entries(prompt_raw if isinstance(prompt_raw, list) else [])
        pretool_handler: dict[str, object] = {
            "type": "command",
            "command": managed_command,
            "timeout": _ZCODE_PRETOOL_TIMEOUT_SECONDS,
        }
        prompt_handler: dict[str, object] = {
            "type": "command",
            "command": managed_command,
            "timeout": _ZCODE_PROMPT_TIMEOUT_SECONDS,
        }
        for matcher in ZCODE_PRETOOL_MATCHERS:
            pretool_entries = _merge_hook_entry(pretool_entries, matcher, pretool_handler)
        prompt_entries = _merge_hook_entry(prompt_entries, None, prompt_handler)
        hooks["PreToolUse"] = pretool_entries
        hooks["UserPromptSubmit"] = prompt_entries

    def _prune_managed_hook_groups(self, hooks: dict[str, object]) -> None:
        for event_name in ("PreToolUse", "UserPromptSubmit"):
            entries = hooks.get(event_name)
            remaining = self._prune_managed_entries(entries if isinstance(entries, list) else [])
            if remaining:
                hooks[event_name] = remaining
            else:
                hooks.pop(event_name, None)

    @staticmethod
    def _prune_managed_entries(entries: list[object]) -> list[object]:
        remaining: list[object] = []
        for entry in entries:
            if not isinstance(entry, dict):
                remaining.append(entry)
                continue
            if is_guard_managed_hook_command(entry.get("command")):
                continue
            nested_hooks = entry.get("hooks")
            if isinstance(nested_hooks, list):
                filtered = [item for item in nested_hooks if not _is_managed_handler(item)]
                if filtered:
                    updated = dict(entry)
                    updated["hooks"] = filtered
                    remaining.append(updated)
                continue
            remaining.append(entry)
        return remaining


def _is_managed_handler(handler: object) -> bool:
    return isinstance(handler, dict) and is_guard_managed_hook_command(handler.get("command"))


def _merge_hook_entry(entries: list[object], matcher: str | None, handler: dict[str, object]) -> list[object]:
    """Add or refresh the Guard handler for a given matcher, preserving user hooks.

    Non-dict entries (kept defensively by ``_prune_managed_entries``) are
    passed through unchanged so the merge never drops user data.
    """

    normalized: list[object] = list(entries)
    matcher_key = matcher.strip() if isinstance(matcher, str) and matcher.strip() else None
    for index, entry in enumerate(normalized):
        if not isinstance(entry, dict):
            continue
        entry_matcher = entry.get("matcher")
        entry_matcher_key = entry_matcher.strip() if isinstance(entry_matcher, str) and entry_matcher.strip() else None
        if entry_matcher_key != matcher_key:
            continue
        nested_hooks = entry.get("hooks")
        if not isinstance(nested_hooks, list):
            nested_hooks = []
        if any(_is_managed_handler(item) for item in nested_hooks):
            updated = dict(entry)
            updated["hooks"] = [
                handler if isinstance(item, dict) and _is_managed_handler(item) else item for item in nested_hooks
            ]
            normalized[index] = updated
            return normalized
        merged_hooks = [*nested_hooks, handler]
        updated = dict(entry)
        updated["hooks"] = merged_hooks
        normalized[index] = updated
        return normalized
    group: dict[str, object] = {"hooks": [handler]}
    if matcher_key is not None:
        group["matcher"] = matcher_key
    normalized.append(group)
    return normalized


__all__ = ["ZCodeHarnessAdapter"]
