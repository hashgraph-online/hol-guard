"""z.ai ZCode harness adapter for HOL Guard.

ZCode is z.ai's local AI coding harness. Its CLI app config lives under
``~/.zcode/cli/config.json`` and is Claude-Code-shaped: an ``mcp`` section, a
``plugins`` section, and an optional ``hooks`` section whose event groups are
nested under ``hooks.events`` (current ZCode rejects the legacy flat
``hooks.<Event>`` layout and fails to load the entire config file, so Guard
migrates legacy groups on install). Plugins are cached under
``~/.zcode/cli/plugins/cache/<marketplace>/<plugin>/<version>/``.

This adapter discovers MCP servers, enabled plugins, plugin manifests and
provenance, plugin hooks, skills, commands, and marketplaces; installs
Guard-managed ``PreToolUse`` and ``UserPromptSubmit`` hooks into the CLI
config ``hooks.events`` section (idempotently, without touching ``mcp`` or
``plugins``); and routes ZCode hook events through the shared Guard runtime.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ..aibom_detection import extend_detection_with_workspace_aibom, native_adapter_detection
from ..models import HarnessDetection
from ..native_path_anchor import anchor_to_process_directory
from ..shims import prepare_guard_shim, remove_guard_shim
from .adapter_safe_output import write_text_at_authorized_path
from .base import (
    HarnessAdapter,
    HarnessContext,
    PreparedHarnessInstall,
    _command_available,
    _ensure_path_within_root,
    _json_payload,
    _shell_command,
)
from .bounded_cli_hook_bridge import bounded_cli_hook_command
from .zcode_config import (
    GUARD_MANAGED_MARKER,
    ZCODE_BUNDLE_IDENTIFIER,
    ZCODE_CLI_CONFIG_FILE,
    ZCODE_CLI_DIR,
    ZCODE_DIR,
    ZCODE_ENV_HINTS,
    ZCODE_PLUGIN_CACHE_DIR,
    ZCODE_PLUGIN_MARKETPLACES_DIR,
    ZCODE_V2_CONFIG_FILE,
    ZCODE_V2_DIR,
)
from .zcode_hook_settings import plan_hook_settings

_ZCODE_HOME_ENV_VAR = "ZCODE_HOME"
# Current ZCode renders this label beside the hook in its Hooks settings UI
# instead of the full managed command string.
_GUARD_HOOK_STATUS_MESSAGE = "HOL Guard runtime policy enforcement"
# The npm CLI's file-config and hook surface; the Desktop app reads config.json.
_ZCODE_CLI_FILE_CONFIG = "setting.json"
_ZCODE_PRETOOL_TIMEOUT_SECONDS = 30
_ZCODE_PROMPT_TIMEOUT_SECONDS = 30
_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS = 25


if TYPE_CHECKING:
    from ..runtime_transition import TransitionFile


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
    def _file_config_path(cls, context: HarnessContext) -> Path:
        """The npm CLI's setting.json file-config; the CLI's own hook source."""

        return cls._cli_root(context) / _ZCODE_CLI_FILE_CONFIG

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
        # The native resident reads the configs, plugin cache and marketplaces;
        # Python anchors the paths and scopes and fails closed without it.
        artifacts, found_paths = native_adapter_detection(
            "zcode_detect",
            {
                "harness": self.harness,
                "configs": [
                    {"path": anchor_to_process_directory(path), "scope": self._scope_for(context, path)}
                    for path in self._config_candidates(context)
                ],
                "v2_config": anchor_to_process_directory(
                    self._zcode_home_dir(context) / ZCODE_V2_DIR / ZCODE_V2_CONFIG_FILE
                ),
                "plugin_roots": [
                    {"path": anchor_to_process_directory(path), "scope": scope}
                    for path, scope in self._plugins_candidates(context)
                ],
                "marketplace_roots": [
                    {"path": anchor_to_process_directory(path), "scope": scope}
                    for path, scope in self._marketplaces_candidates(context)
                ],
            },
        )

        runtime_signal = self._detect_runtime_signal()
        command_available = _command_available(self.executable, context.home_dir)
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
            config_paths=found_paths,
            artifacts=artifacts,
            warnings=tuple(dict.fromkeys(warnings)),
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def _config_candidates(self, context: HarnessContext) -> list[Path]:
        candidates = [self._config_path(context), self._file_config_path(context)]
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

    def _managed_state_paths(self, context: HarnessContext) -> tuple[Path, Path, Path]:
        state_dir = context.guard_home / "managed" / "zcode"
        backup_path = state_dir / "config.json.backup"
        state_path = state_dir / "install.state.json"
        _ensure_path_within_root(context.guard_home, state_dir, label="ZCode state")
        _ensure_path_within_root(state_dir, backup_path, label="ZCode backup")
        _ensure_path_within_root(state_dir, state_path, label="ZCode state")
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
            "zcode",
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
            harness="zcode",
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
            display_name="zcode",
        )
        shim_manifest = prepared_shim.manifest
        _state_dir, backup_path, state_path = self._managed_state_paths(context)
        backup_before = _snapshot(backup_path)
        state_before = _snapshot(state_path)
        previous_state = _json_payload(state_path) if state_before is not None else {}

        hook_files: list[TransitionFile] = []
        hook_command = _shell_command(self._hook_command_parts(context, prepared_files=hook_files))
        # The marker rides along as a trailing shell comment, so ZCode runs the
        # command verbatim while Guard can later find and prune only its own.
        managed_hook_command = f"{hook_command} # {GUARD_MANAGED_MARKER}"
        handlers: dict[str, dict[str, object]] = {
            event: {
                "type": "command",
                "command": managed_hook_command,
                "timeout": timeout,
                "statusMessage": _GUARD_HOOK_STATUS_MESSAGE,
            }
            for event, timeout in (
                ("PreToolUse", _ZCODE_PRETOOL_TIMEOUT_SECONDS),
                ("UserPromptSubmit", _ZCODE_PROMPT_TIMEOUT_SECONDS),
            )
        }

        config_path = self._config_path(context)
        surfaces: list[tuple[Path, dict[str, object], bytes | None, int]] = []
        enabled_history: dict[str, object] = {}
        for path, payload in self._hook_surface_payloads(context):
            hooks = payload.get("hooks")
            if not isinstance(hooks, dict):
                hooks = {}
            payload["hooks"] = hooks
            # Native plan: legacy flat groups fold into hooks.events (current
            # ZCode rejects the flat keys and drops the whole file), then Guard's
            # PreToolUse groups per matcher and UserPromptSubmit group refresh.
            plan = plan_hook_settings("install", hooks, path=path, state=previous_state, handlers=handlers)
            enabled_history[str(path)] = plan.enabled
            if hooks.get("enabled") is False and plan.has_handlers:
                raise ValueError(
                    f"ZCode user hooks are disabled in {path.name}; explicitly enable them before installing Guard."
                )
            plan.apply(hooks)
            # Each ZCode surface only registers hooks when its own config
            # opts in with hooks.enabled: true; without the flag entries
            # never run.
            hooks["enabled"] = True
            surfaces.append(
                (path, payload, _snapshot(path), (path.stat().st_mode & 0o777) if path.is_file() else 0o644)
            )

        file_config = self._file_config_path(context)
        if str(file_config) not in enabled_history and str(config_path) in enabled_history:
            # The CLI migration will copy config.json (including Guard's opt-in)
            # into setting.json; remember the pre-install value for it too.
            enabled_history[str(file_config)] = enabled_history[str(config_path)]

        config_before = _snapshot(config_path)
        state_mode = state_path.stat().st_mode & 0o777 if state_before is not None else 0o644
        backup_mode = backup_path.stat().st_mode & 0o777 if backup_before is not None else 0o644
        state_after = (
            json.dumps(
                {
                    "managed_config_path": str(config_path),
                    "managed_file_config_path": str(self._file_config_path(context)),
                    "hooks_enabled_before": enabled_history,
                },
                indent=2,
            )
            + "\n"
        ).encode("utf-8")
        files: tuple[TransitionFile, ...] = (
            *prepared_shim.files,
            *hook_files,
            TransitionFile(
                backup_path.resolve(strict=False),
                backup_before,
                backup_before if backup_before is not None else config_before,
                before_mode=backup_mode,
                after_mode=backup_mode,
            ),
        )
        for path, payload, before, mode in surfaces:
            files = (
                *files,
                TransitionFile(
                    path.resolve(strict=False),
                    before,
                    (json.dumps(payload, indent=2) + "\n").encode("utf-8"),
                    before_mode=mode,
                    after_mode=mode,
                ),
            )
        files = (
            *files,
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
                *self._surface_notes(context, surfaces),
                "hooks.enabled was set to true on every written surface; ZCode only runs hooks after that opt-in",
                "User mcp, plugins, and any pre-existing hooks were preserved",
                "Legacy flat hook groups were migrated into hooks.events for current ZCode",
                "Hook entries carry a statusMessage label rendered by ZCode's Hooks settings UI",
                *shim_notes,
            ],
        }
        return PreparedHarnessInstall(files, manifest)

    def _surface_notes(
        self, context: HarnessContext, surfaces: list[tuple[Path, dict[str, object], bytes | None, int]]
    ) -> list[str]:
        """Report only the hook surfaces install actually wrote."""

        wrote_cli = any(path == self._file_config_path(context) for path, _payload, _before, _mode in surfaces)
        if wrote_cli:
            return [
                "Guard hook entries added to ~/.zcode/cli/config.json (Desktop) and ~/.zcode/cli/setting.json (CLI)"
            ]
        return [
            "Guard hook entries added to ~/.zcode/cli/config.json (Desktop)",
            "The CLI's ~/.zcode/cli/setting.json does not exist yet; its own settings migration carries the hooks over",
        ]

    def _hook_surface_payloads(self, context: HarnessContext) -> list[tuple[Path, dict[str, object]]]:
        """Load both ZCode hook surfaces.

        Current ZCode splits hook loading per surface: the Desktop app reads
        user hooks from ``~/.zcode/cli/config.json`` while the npm CLI reads
        them from its ``~/.zcode/cli/setting.json`` file-config (which the CLI
        migrates config.json into once). Each surface reads only its own
        file, so Guard maintains managed hooks in both.
        """

        surfaces: list[tuple[Path, dict[str, object]]] = []
        for path in (self._config_path(context), self._file_config_path(context)):
            _ensure_path_within_root(self._zcode_home_dir(context), path, label="ZCode")
            if not path.is_file():
                if path == self._config_path(context):
                    surfaces.append((path, {}))
                # An absent setting.json means the npm CLI has not migrated
                # yet; creating it here would mark that migration done and
                # strand the user's config.json settings. The CLI's own
                # migration copies Guard's config.json hooks over instead.
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as error:
                raise ValueError(f"ZCode config must be a JSON object: {path.name}") from error
            if not isinstance(payload, dict):
                raise ValueError(f"ZCode config must be a JSON object: {path.name}")
            if path == self._config_path(context):
                if not isinstance(payload.get("mcp"), dict):
                    payload["mcp"] = {}
                if not isinstance(payload.get("plugins"), dict):
                    payload["plugins"] = {}
            surfaces.append((path, payload))
        return surfaces

    def install(self, context: HarnessContext) -> dict[str, object]:
        return self.prepare_install(context).publish(context.guard_home)

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        _state_dir, _backup_path, state_path = self._managed_state_paths(context)
        state = _json_payload(state_path) if state_path.is_file() else {}
        config_path = self._config_path(context)
        # Plan both hook surfaces (including installs that predate the
        # dual-surface layout) before anything changes, so a refused plan
        # leaves the shim, the files and the install state in place.
        writes: list[tuple[Path, str]] = []
        for candidate in (self._file_config_path(context), self._config_path(context)):
            if not candidate.is_file():
                continue
            _ensure_path_within_root(self._zcode_home_dir(context), candidate, label="ZCode")
            payload = _json_payload(candidate)
            hooks = payload.get("hooks")
            if not isinstance(hooks, dict):
                continue
            hooks_before = json.dumps(hooks, sort_keys=True)
            plan = plan_hook_settings("uninstall", hooks, path=candidate, state=state)
            plan.apply(hooks)
            if json.dumps(hooks, sort_keys=True) == hooks_before:
                continue
            if not hooks:
                payload.pop("hooks", None)
            else:
                payload["hooks"] = hooks
            writes.append((candidate, json.dumps(payload, indent=2) + "\n"))

        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="zcode",
        )
        for candidate, text in writes:
            write_text_at_authorized_path(candidate, text)
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
                "Guard-managed hook entries removed from ~/.zcode/cli/config.json and the CLI file-config",
                "User mcp, plugins, and any pre-existing hooks were preserved",
                *shim_notes,
            ],
        }


__all__ = ["ZCodeHarnessAdapter"]
