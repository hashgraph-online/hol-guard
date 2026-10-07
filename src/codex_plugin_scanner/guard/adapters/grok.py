"""Grok Build CLI harness adapter for HOL Guard."""

from __future__ import annotations

import json
import os
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..aibom_detection import extend_detection_with_workspace_aibom
from ..codex_config import read_toml_payload
from ..models import GuardArtifact, HarnessDetection
from ..shims import prepare_guard_shim, remove_guard_shim
from .base import (
    HarnessAdapter,
    HarnessContext,
    PreparedHarnessInstall,
    _ensure_path_within_root,
    _json_payload,
    _run_command_probe,
    _shell_command,
)
from .bounded_cli_hook_bridge import bounded_cli_hook_command
from .grok_config import (
    GROK_CONFIG_FILE,
    GROK_DIR,
    GROK_HOOK_INTERNAL_TIMEOUT_SECONDS,
    GROK_HOOKS_DIR,
    GROK_MANAGED_CONFIG_FILE,
    GROK_PROJECT_SURFACE_RELATIVES,
    GROK_REQUIREMENTS_FILE,
    GROK_SURFACE_RELATIVES,
    GUARD_HOOK_PRETOOL_FILE,
    GUARD_HOOK_PROMPT_FILE,
    GUARD_MANAGED_BEGIN,
    SYSTEM_MANAGED_CONFIG,
    SYSTEM_REQUIREMENTS,
    append_found_path,
    append_hooks_dir_artifacts,
    append_mcp_artifacts,
    append_permission_artifacts,
    build_observe_hook_json,
    build_pretool_hook_json,
    degraded_mode_warnings,
    remove_managed_block,
)
from .grok_executable import (
    GrokExecutableResolution,
    register_trusted_grok_executable,
    resolve_trusted_grok_executable,
    sanitized_grok_launch_environment,
)
from .grok_install_settings import parse_install_state, remove_legacy_settings, uninstall_settings
from .grok_state import grok_runtime_hooks_verified as grok_runtime_hooks_verified
from .grok_user_config import prepare_user_config_text
from .grok_version_probe import probe_grok_version

_GROK_HOME_ENV_VAR = "GROK_HOME"
_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS = GROK_HOOK_INTERNAL_TIMEOUT_SECONDS


if TYPE_CHECKING:
    from ..runtime_transition import TransitionFile


class GrokHarnessAdapter(HarnessAdapter):
    """Discover Grok Build settings, hooks, plugins, and manage Guard protection."""

    harness = "grok"
    aliases = ("grok-build", "grok-build-cli", "xai-grok")
    executable = "grok"
    launcher_name = "grok"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard intercepts every Grok tool call, including subagent and MCP tools, through a "
        "catch-all PreToolUse hook and routes blocked actions to the local approval center."
    )
    fallback_hint = (
        "Guard screens submitted prompts and intercepts tool calls on PreToolUse. "
        "Use the Guard approval center when a tool call is denied."
    )

    @staticmethod
    def _grok_home_dir(context: HarnessContext) -> Path:
        value = os.environ.get(_GROK_HOME_ENV_VAR)
        if value:
            return Path(value).expanduser().resolve()
        return context.home_dir

    @classmethod
    def _grok_root(cls, context: HarnessContext) -> Path:
        return cls._grok_home_dir(context) / GROK_DIR

    @classmethod
    def _protection_config_path(cls, context: HarnessContext) -> Path:
        return cls._config_path(context)

    @classmethod
    def _managed_config_path(cls, context: HarnessContext) -> Path:
        return cls._grok_root(context) / GROK_MANAGED_CONFIG_FILE

    @classmethod
    def _config_path(cls, context: HarnessContext) -> Path:
        return cls._grok_root(context) / GROK_CONFIG_FILE

    @classmethod
    def _requirements_path(cls, context: HarnessContext) -> Path:
        return cls._grok_root(context) / GROK_REQUIREMENTS_FILE

    @classmethod
    def _hooks_dir(cls, context: HarnessContext) -> Path:
        return cls._grok_root(context) / GROK_HOOKS_DIR

    @classmethod
    def _project_grok_root(cls, context: HarnessContext) -> Path | None:
        if context.workspace_dir is None:
            return None
        return context.workspace_dir / GROK_DIR

    def policy_path(self, context: HarnessContext) -> Path:
        project_root = self._project_grok_root(context)
        if project_root is not None and (project_root / GROK_CONFIG_FILE).is_file():
            return project_root / GROK_CONFIG_FILE
        return self._config_path(context)

    _read_toml = staticmethod(read_toml_payload)

    @staticmethod
    def _version_probe(context: HarnessContext, resolution: GrokExecutableResolution) -> dict[str, object]:
        return probe_grok_version(
            context,
            resolution,
            run_probe=_run_command_probe,
            sanitize_environment=sanitized_grok_launch_environment,
        )

    def resolved_executable(self, context: HarnessContext) -> str | None:
        executable = resolve_trusted_grok_executable(context).executable
        return str(executable.path) if executable is not None else None

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        resolution = resolve_trusted_grok_executable(context)
        executable = resolution.executable
        if executable is None:
            raise FileNotFoundError(resolution.error or "Trusted Grok executable not found.")
        if executable.source == "explicit":
            executable = register_trusted_grok_executable(context, executable)
        return [str(executable.path), *passthrough_args]

    def preview_launch_commands(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
    ) -> tuple[list[str], ...]:
        """Resolve Grok without persisting an explicit-path registration."""

        resolution = resolve_trusted_grok_executable(context)
        executable = resolution.executable
        if executable is None:
            raise FileNotFoundError(resolution.error or "Trusted Grok executable not found.")
        return ([str(executable.path), *passthrough_args],)

    def prepare_launch_environment(
        self,
        context: HarnessContext,
        inherited: Mapping[str, str],
    ) -> dict[str, str]:
        environment = sanitized_grok_launch_environment(context, inherited)
        environment.update(self.launch_environment(context))
        return environment

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        warnings: list[str] = []
        grok_root = self._grok_root(context)

        for config_path in (
            self._config_path(context),
            self._managed_config_path(context),
            self._requirements_path(context),
        ):
            if config_path.is_file():
                append_found_path(found_paths, config_path)
                payload = self._read_toml(config_path)
                if payload:
                    append_permission_artifacts(
                        harness=self.harness,
                        artifacts=artifacts,
                        payload=payload,
                        config_path=config_path,
                        scope="global",
                    )
                    append_mcp_artifacts(
                        harness=self.harness,
                        artifacts=artifacts,
                        payload=payload,
                        config_path=config_path,
                        scope="global",
                    )
                    warnings.extend(degraded_mode_warnings(config_path, payload))

        for system_path in (SYSTEM_MANAGED_CONFIG, SYSTEM_REQUIREMENTS):
            if system_path.is_file() and os.access(system_path, os.R_OK):
                append_found_path(found_paths, system_path)
                warnings.append(f"Enterprise Grok policy detected at {system_path.name}.")

        append_hooks_dir_artifacts(
            harness=self.harness,
            artifacts=artifacts,
            found_paths=found_paths,
            hooks_dir=self._hooks_dir(context),
            scope="global",
        )
        project_root = self._project_grok_root(context)
        if project_root is not None:
            if (project_root / GROK_CONFIG_FILE).is_file():
                append_found_path(found_paths, project_root / GROK_CONFIG_FILE)
            append_hooks_dir_artifacts(
                harness=self.harness,
                artifacts=artifacts,
                found_paths=found_paths,
                hooks_dir=project_root / GROK_HOOKS_DIR,
                scope="project",
            )

        hooks_paths_file = grok_root / "hooks-paths"
        if hooks_paths_file.is_file():
            append_found_path(found_paths, hooks_paths_file)

        marketplaces_file = grok_root / "plugins" / "known_marketplaces.json"
        if marketplaces_file.is_file():
            append_found_path(found_paths, marketplaces_file)
            payload = _json_payload(marketplaces_file)
            if payload:
                artifacts.append(
                    GuardArtifact(
                        artifact_id="grok:global:marketplace-metadata",
                        name="known_marketplaces",
                        harness=self.harness,
                        artifact_type="marketplace",
                        source_scope="global",
                        config_path=str(marketplaces_file),
                        metadata={"entries": len(payload) if isinstance(payload, dict) else 0},
                    )
                )

        for relative in GROK_SURFACE_RELATIVES:
            candidate = grok_root / relative
            if candidate.exists():
                append_found_path(found_paths, candidate)

        if project_root is not None:
            for relative in GROK_PROJECT_SURFACE_RELATIVES:
                candidate = project_root / relative
                if candidate.exists():
                    append_found_path(found_paths, candidate)

        for agents_path in (context.home_dir / ".agents" / "skills", context.home_dir / ".agents" / "commands"):
            if agents_path.exists():
                append_found_path(found_paths, agents_path)

        if context.workspace_dir is not None:
            for agents_file in ("AGENTS.md", "CLAUDE.md"):
                candidate = context.workspace_dir / agents_file
                if candidate.is_file():
                    append_found_path(found_paths, candidate)
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"grok:project:instruction:{agents_file.lower()}",
                            name=agents_file,
                            harness=self.harness,
                            artifact_type="instruction_surface",
                            source_scope="project",
                            config_path=str(candidate),
                        )
                    )

        executable_resolution = resolve_trusted_grok_executable(context)
        version_probe = self._version_probe(context, executable_resolution)
        command_available = executable_resolution.executable is not None or bool(version_probe.get("ok"))
        installed = bool(found_paths) or command_available
        if executable_resolution.error is not None:
            warnings.append(executable_resolution.error)
        if self._has_stale_guard_entries(context):
            warnings.append("Stale or duplicate Guard-managed Grok entries detected.")

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

    def _managed_state_dir(self, context: HarnessContext) -> Path:
        return context.guard_home / "managed" / "grok"

    def _backup_path(self, context: HarnessContext, label: str) -> Path:
        return self._managed_state_dir(context) / f"{label}.backup"

    def _state_path(self, context: HarnessContext) -> Path:
        return self._managed_state_dir(context) / "install.state.json"

    def _has_stale_guard_entries(self, context: HarnessContext) -> bool:
        hooks_dir = self._hooks_dir(context)
        if not hooks_dir.is_dir():
            return False
        managed_files = list(hooks_dir.glob("hol-guard-*.json"))
        if len(managed_files) > 2:
            return True
        managed_config = self._managed_config_path(context)
        if managed_config.is_file():
            text = managed_config.read_text(encoding="utf-8")
            return text.count(GUARD_MANAGED_BEGIN) > 1
        return False

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
            "grok",
        ]
        if context.home_dir.resolve() != Path.home().resolve():
            guard_args.extend(["--home", str(context.home_dir)])
        if context.workspace_dir is not None:
            guard_args.extend(["--workspace", str(context.workspace_dir)])
        guard_args.append("--json")
        return bounded_cli_hook_command(
            python_executable=sys.executable,
            package_root=Path(__file__).resolve().parents[3],
            guard_home=context.guard_home,
            cli_args=guard_args,
            harness="grok",
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
            display_name="grok",
        )
        shim_manifest = prepared_shim.manifest
        managed_config_path = self._protection_config_path(context)
        legacy_path = self._managed_config_path(context)
        hooks_dir = self._hooks_dir(context)
        _ensure_path_within_root(self._grok_home_dir(context), managed_config_path, label="Grok")
        _ensure_path_within_root(self._grok_home_dir(context), legacy_path, label="Grok")
        hook_files: list[TransitionFile] = []
        hook_command = _shell_command(self._hook_command_parts(context, prepared_files=hook_files))
        pretool_path = hooks_dir / GUARD_HOOK_PRETOOL_FILE
        prompt_path = hooks_dir / GUARD_HOOK_PROMPT_FILE
        paths = (managed_config_path, pretool_path, prompt_path, self._state_path(context), legacy_path)
        snapshots = {path: _snapshot(path) for path in paths}
        config_before = snapshots[managed_config_path]
        existing_text = config_before.decode("utf-8") if config_before is not None else ""
        state_before = snapshots[self._state_path(context)]
        state_payload = parse_install_state(state_before)
        previous_settings = state_payload.get("user_config_settings")
        merged_text, owned_settings = prepare_user_config_text(
            existing_text,
            hook_command,
            previous_state=previous_settings if isinstance(previous_settings, Mapping) else {},
        )
        state = {
            "managed_config_path": str(managed_config_path),
            "pretool_hook_path": str(pretool_path),
            "prompt_hook_path": str(prompt_path),
            "user_config_settings": owned_settings,
        }
        after = {
            managed_config_path: merged_text.encode("utf-8"),
            pretool_path: (json.dumps(build_pretool_hook_json(hook_command), indent=2) + "\n").encode("utf-8"),
            prompt_path: (json.dumps(build_observe_hook_json(hook_command), indent=2) + "\n").encode("utf-8"),
            self._state_path(context): (json.dumps(state, indent=2) + "\n").encode("utf-8"),
            legacy_path: remove_legacy_settings(snapshots[legacy_path], self._state_path(context), state_payload),
        }
        files = [*prepared_shim.files, *hook_files]
        for path in paths[:3]:
            backup = self._backup_path(context, path.name)
            before = _snapshot(backup)
            mode = backup.stat().st_mode & 0o777 if before is not None else 0o644
            source = snapshots[path]
            after_mode = path.stat().st_mode & 0o777 if before is None and source is not None else mode
            change = TransitionFile(
                backup.resolve(strict=False),
                before,
                before if before is not None else source,
                before_mode=mode,
                after_mode=after_mode,
            )
            change.payload()
            files.append(change)
        for path in paths:
            mode = path.stat().st_mode & 0o777 if snapshots[path] is not None else 0o644
            change = TransitionFile(
                path.resolve(strict=False), snapshots[path], after[path], before_mode=mode, after_mode=mode
            )
            change.payload()
            files.append(change)

        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        manifest: dict[str, object] = {
            "harness": self.harness,
            "active": True,
            **shim_manifest,
            "config_path": str(managed_config_path),
            "managed_config_path": str(managed_config_path),
            "managed_hooks_path": str(pretool_path),
            "pretool_hook_path": str(pretool_path),
            "prompt_hook_path": str(prompt_path),
            "protection_artifact_paths": [
                str(managed_config_path),
                str(pretool_path),
                str(prompt_path),
            ],
            "notes": [
                "Guard catch-all PreToolUse hook installed in .grok/hooks/hol-guard-pretooluse.json",
                "Guard prompt screening and lifecycle observation hooks installed",
                "Guard permission rules and backup hooks installed in .grok/config.toml",
                *shim_notes,
            ],
        }
        return PreparedHarnessInstall(tuple(files), manifest)

    def install(self, context: HarnessContext) -> dict[str, object]:
        return self.prepare_install(context).publish(context.guard_home)

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        settings_notes = uninstall_settings(self, context)
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="grok",
        )
        managed_config_path = self._protection_config_path(context)
        hooks_dir = self._hooks_dir(context)

        for hook_name in (GUARD_HOOK_PRETOOL_FILE, GUARD_HOOK_PROMPT_FILE):
            hook_path = hooks_dir / hook_name
            backup_path = self._backup_path(context, hook_name)
            if backup_path.is_file():
                shutil.copy2(backup_path, hook_path)
                backup_path.unlink(missing_ok=True)
            elif hook_path.is_file():
                hook_path.unlink()

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
            "config_path": str(managed_config_path),
            **shim_manifest,
            "notes": [
                "Guard hook files and launcher removed.",
                "User .grok/config.toml, auth, skills, plugins, and sessions were preserved.",
                *settings_notes,
                *shim_notes,
            ],
        }


_remove_managed_block = remove_managed_block

__all__ = ["GrokHarnessAdapter", "_remove_managed_block", "grok_runtime_hooks_verified"]
