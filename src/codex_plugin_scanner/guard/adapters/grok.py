"""Grok Build CLI harness adapter for HOL Guard."""

from __future__ import annotations

import importlib
import json
import os
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..aibom_detection import extend_detection_with_workspace_aibom
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import (
    HarnessAdapter,
    HarnessContext,
    _ensure_path_within_root,
    _json_payload,
    _run_command_probe,
    _shell_command,
)
from .grok_config import (
    GROK_CONFIG_FILE,
    GROK_DIR,
    GROK_HOOKS_DIR,
    GROK_MANAGED_CONFIG_FILE,
    GROK_REQUIREMENTS_FILE,
    GUARD_HOOK_PRETOOL_FILE,
    GUARD_HOOK_PROMPT_FILE,
    GUARD_MANAGED_BEGIN,
    SYSTEM_MANAGED_CONFIG,
    SYSTEM_REQUIREMENTS,
    append_found_path,
    append_hooks_dir_artifacts,
    append_mcp_artifacts,
    append_permission_artifacts,
    build_managed_config_block,
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

tomllib: Any
try:
    import tomllib as tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:
    tomllib = importlib.import_module("tomli")

_GROK_HOME_ENV_VAR = "GROK_HOME"


class GrokHarnessAdapter(HarnessAdapter):
    """Discover Grok Build settings, hooks, plugins, and manage Guard protection."""

    harness = "grok"
    aliases = ("grok-build", "grok-build-cli", "xai-grok")
    executable = "grok"
    launcher_name = "grok"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard intercepts Grok tool calls through native PreToolUse hooks and routes blocked "
        "actions to the local approval center."
    )
    fallback_hint = (
        "Grok receives plain-language allow or deny responses from Guard hooks. "
        "Use the Guard approval center when native prompting is unavailable."
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

    @staticmethod
    def _read_toml(path: Path) -> dict[str, object]:
        if not path.is_file():
            return {}
        try:
            with path.open("rb") as handle:
                payload = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _version_probe(
        context: HarnessContext,
        resolution: GrokExecutableResolution,
    ) -> dict[str, object]:
        executable = resolution.executable
        if executable is None:
            return {
                "command": [],
                "ok": False,
                "return_code": None,
                "stdout": "",
                "stderr": resolution.error or "trusted Grok executable not found",
            }
        probe_cwd = context.guard_home / "runtime" / "grok-probe"
        try:
            probe_cwd.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name != "nt":
                probe_cwd.chmod(0o700)
        except OSError as error:
            return {
                "command": [str(executable.path), "--no-auto-update", "--version"],
                "ok": False,
                "return_code": None,
                "stdout": "",
                "stderr": f"trusted probe directory unavailable: {error}",
            }
        return _run_command_probe(
            [str(executable.path), "--no-auto-update", "--version"],
            timeout_seconds=8,
            cwd=probe_cwd,
            env=sanitized_grok_launch_environment(context, os.environ),
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

        for relative in ("skills", "plugins", "plugins/marketplaces", "plugins/known_marketplaces.json", "sessions"):
            candidate = grok_root / relative
            if candidate.exists():
                append_found_path(found_paths, candidate)

        if project_root is not None:
            for relative in ("skills", "plugins", "hooks"):
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
    def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
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
        package_root = Path(__file__).resolve().parents[3]
        code = (
            "import sys;"
            f"sys.path.insert(0, {str(package_root)!r});"
            "from codex_plugin_scanner.cli import main;"
            f"raise SystemExit(main({guard_args!r}))"
        )
        return (sys.executable, "-c", code)

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="grok",
        )
        grok_root = self._grok_root(context)
        managed_config_path = self._managed_config_path(context)
        hooks_dir = self._hooks_dir(context)
        _ensure_path_within_root(context.home_dir, managed_config_path, label="Grok")
        grok_root.mkdir(parents=True, exist_ok=True)
        hooks_dir.mkdir(parents=True, exist_ok=True)
        state_dir = self._managed_state_dir(context)
        state_dir.mkdir(parents=True, exist_ok=True)

        if managed_config_path.is_file() and not self._backup_path(context, "managed_config.toml").exists():
            shutil.copy2(managed_config_path, self._backup_path(context, "managed_config.toml"))

        hook_command = _shell_command(self._hook_command_parts(context))
        pretool_path = hooks_dir / GUARD_HOOK_PRETOOL_FILE
        prompt_path = hooks_dir / GUARD_HOOK_PROMPT_FILE
        for hook_path in (pretool_path, prompt_path):
            if hook_path.is_file() and not self._backup_path(context, hook_path.name).exists():
                shutil.copy2(hook_path, self._backup_path(context, hook_path.name))

        pretool_payload = build_pretool_hook_json(hook_command)
        pretool_path.write_text(json.dumps(pretool_payload, indent=2) + "\n", encoding="utf-8")
        prompt_payload = {
            "hooks": {
                "UserPromptSubmit": [
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": hook_command,
                                "timeout": 30,
                            }
                        ]
                    }
                ]
            }
        }
        prompt_path.write_text(json.dumps(prompt_payload, indent=2) + "\n", encoding="utf-8")

        existing_text = managed_config_path.read_text(encoding="utf-8") if managed_config_path.is_file() else ""
        cleaned_text = remove_managed_block(existing_text)
        managed_block = build_managed_config_block()
        managed_config_path.write_text(f"{cleaned_text.rstrip()}\n\n{managed_block}\n".lstrip(), encoding="utf-8")

        self._state_path(context).write_text(
            json.dumps(
                {
                    "managed_config_path": str(managed_config_path),
                    "pretool_hook_path": str(pretool_path),
                    "prompt_hook_path": str(prompt_path),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(managed_config_path),
            **shim_manifest,
            "notes": [
                "Guard hooks installed in .grok/hooks/hol-guard-*.json",
                "Guard permission rules installed in .grok/managed_config.toml",
                *shim_notes,
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="grok",
        )
        managed_config_path = self._managed_config_path(context)
        hooks_dir = self._hooks_dir(context)
        if managed_config_path.is_file():
            _ensure_path_within_root(context.home_dir, managed_config_path, label="Grok")
            existing_text = managed_config_path.read_text(encoding="utf-8")
            managed_config_path.write_text(remove_managed_block(existing_text).rstrip() + "\n", encoding="utf-8")

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
                "Guard-managed Grok hooks and permission rules removed.",
                "User .grok/config.toml, auth, skills, plugins, and sessions were preserved.",
                *shim_notes,
            ],
        }


_remove_managed_block = remove_managed_block

__all__ = ["GrokHarnessAdapter", "_remove_managed_block"]
