"""Grok Build CLI harness adapter for HOL Guard."""

from __future__ import annotations

import json
import os
import re
import shutil
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
    _run_command_probe,
    _shell_command,
)

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

_GROK_HOME_ENV_VAR = "GROK_HOME"
_GROK_DIR = ".grok"
_GROK_CONFIG_FILE = "config.toml"
_GROK_MANAGED_CONFIG_FILE = "managed_config.toml"
_GROK_REQUIREMENTS_FILE = "requirements.toml"
_GROK_HOOKS_DIR = "hooks"
_GUARD_MANAGED_BEGIN = "# BEGIN HOL GUARD MANAGED GROK"
_GUARD_MANAGED_END = "# END HOL GUARD MANAGED GROK"
_GUARD_MANAGED_MARKER = "HOL GUARD MANAGED GROK"
_GUARD_HOOK_PRETOOL_FILE = "hol-guard-pretooluse.json"
_GUARD_HOOK_PROMPT_FILE = "hol-guard-prompt.json"
_PRETOOL_MATCHERS = ("Bash", "Read", "Edit", "Grep", "MCPTool", "WebFetch")
_SYSTEM_MANAGED_CONFIG = Path("/etc/grok/managed_config.toml")
_SYSTEM_REQUIREMENTS = Path("/etc/grok/requirements.toml")
_DEGRADED_MODE_MARKERS = (
    "always-approve",
    "bypasspermissions",
    "bypass_permissions",
    'defaultmode = "bypasspermissions"',
    'defaultMode": "bypassPermissions"',
    'sandbox = "off"',
    'sandbox="off"',
)


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
        "Use `hol-guard approvals` if you want to resolve pending requests from the terminal."
    )

    @staticmethod
    def _grok_home_dir(context: HarnessContext) -> Path:
        value = os.environ.get(_GROK_HOME_ENV_VAR)
        if value:
            return Path(value).expanduser().resolve()
        return context.home_dir

    @classmethod
    def _grok_root(cls, context: HarnessContext) -> Path:
        return cls._grok_home_dir(context) / _GROK_DIR

    @classmethod
    def _managed_config_path(cls, context: HarnessContext) -> Path:
        return cls._grok_root(context) / _GROK_MANAGED_CONFIG_FILE

    @classmethod
    def _config_path(cls, context: HarnessContext) -> Path:
        return cls._grok_root(context) / _GROK_CONFIG_FILE

    @classmethod
    def _requirements_path(cls, context: HarnessContext) -> Path:
        return cls._grok_root(context) / _GROK_REQUIREMENTS_FILE

    @classmethod
    def _hooks_dir(cls, context: HarnessContext) -> Path:
        return cls._grok_root(context) / _GROK_HOOKS_DIR

    @classmethod
    def _project_grok_root(cls, context: HarnessContext) -> Path | None:
        if context.workspace_dir is None:
            return None
        return context.workspace_dir / _GROK_DIR

    def policy_path(self, context: HarnessContext) -> Path:
        project_root = self._project_grok_root(context)
        if project_root is not None and (project_root / _GROK_CONFIG_FILE).is_file():
            return project_root / _GROK_CONFIG_FILE
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
    def _version_probe() -> dict[str, object]:
        return _run_command_probe(["grok", "--no-auto-update", "--version"], timeout_seconds=8)

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
                self._append_found_path(found_paths, config_path)
                payload = self._read_toml(config_path)
                if payload:
                    self._append_permission_artifacts(artifacts, payload, config_path, "global")
                    self._append_mcp_artifacts(artifacts, payload, config_path, "global")
                    degraded = self._degraded_mode_warnings(config_path, payload)
                    warnings.extend(degraded)

        for system_path in (_SYSTEM_MANAGED_CONFIG, _SYSTEM_REQUIREMENTS):
            if system_path.is_file() and os.access(system_path, os.R_OK):
                self._append_found_path(found_paths, system_path)
                warnings.append(f"Enterprise Grok policy detected at {system_path.name}.")

        self._append_hooks_dir_artifacts(artifacts, found_paths, self._hooks_dir(context), "global")
        project_root = self._project_grok_root(context)
        if project_root is not None:
            if (project_root / _GROK_CONFIG_FILE).is_file():
                self._append_found_path(found_paths, project_root / _GROK_CONFIG_FILE)
            self._append_hooks_dir_artifacts(artifacts, found_paths, project_root / _GROK_HOOKS_DIR, "project")

        hooks_paths_file = grok_root / "hooks-paths"
        if hooks_paths_file.is_file():
            self._append_found_path(found_paths, hooks_paths_file)

        marketplaces_file = grok_root / "plugins" / "known_marketplaces.json"
        if marketplaces_file.is_file():
            self._append_found_path(found_paths, marketplaces_file)
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
                self._append_found_path(found_paths, candidate)

        if project_root is not None:
            for relative in ("skills", "plugins", "hooks"):
                candidate = project_root / relative
                if candidate.exists():
                    self._append_found_path(found_paths, candidate)

        for agents_path in (context.home_dir / ".agents" / "skills", context.home_dir / ".agents" / "commands"):
            if agents_path.exists():
                self._append_found_path(found_paths, agents_path)

        if context.workspace_dir is not None:
            for agents_file in ("AGENTS.md", "CLAUDE.md"):
                candidate = context.workspace_dir / agents_file
                if candidate.is_file():
                    self._append_found_path(found_paths, candidate)
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

        version_probe = self._version_probe()
        command_available = _command_available(self.executable) or bool(version_probe.get("ok"))
        installed = bool(found_paths) or command_available
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

    @staticmethod
    def _append_found_path(found_paths: list[str], path: Path) -> None:
        candidate = str(path)
        if candidate not in found_paths:
            found_paths.append(candidate)

    def _append_hooks_dir_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        hooks_dir: Path,
        scope: str,
    ) -> None:
        if not hooks_dir.is_dir():
            return
        for hook_file in sorted(hooks_dir.glob("*.json")):
            payload = _json_payload(hook_file)
            if not payload:
                continue
            self._append_found_path(found_paths, hook_file)
            hooks = payload.get("hooks")
            if not isinstance(hooks, dict):
                continue
            for event_name, entries in hooks.items():
                if not isinstance(event_name, str) or not isinstance(entries, list):
                    continue
                for index, entry in enumerate(entries):
                    if not isinstance(entry, dict):
                        continue
                    nested = entry.get("hooks")
                    matcher = entry.get("matcher")
                    if isinstance(nested, list):
                        for nested_index, hook_entry in enumerate(nested):
                            if not isinstance(hook_entry, dict):
                                continue
                            command = hook_entry.get("command")
                            if not isinstance(command, str) or not command.strip():
                                continue
                            artifacts.append(
                                GuardArtifact(
                                    artifact_id=f"grok:{scope}:hook:{event_name.lower()}:{index}:{nested_index}",
                                    name=f"{event_name}:{matcher}" if isinstance(matcher, str) else event_name,
                                    harness=self.harness,
                                    artifact_type="hook",
                                    source_scope=scope,
                                    config_path=str(hook_file),
                                    command=command,
                                    metadata={"event": event_name, "matcher": matcher},
                                )
                            )

    def _append_permission_artifacts(
        self,
        artifacts: list[GuardArtifact],
        payload: dict[str, object],
        config_path: Path,
        scope: str,
    ) -> None:
        permission = payload.get("permission")
        if not isinstance(permission, dict):
            return
        for key in ("allow", "deny", "ask", "rules"):
            value = permission.get(key)
            if isinstance(value, list) and value:
                artifacts.append(
                    GuardArtifact(
                        artifact_id=f"grok:{scope}:permission:{key}",
                        name=f"permission:{key}",
                        harness=self.harness,
                        artifact_type="policy",
                        source_scope=scope,
                        config_path=str(config_path),
                        metadata={"entries": len(value)},
                    )
                )

    def _append_mcp_artifacts(
        self,
        artifacts: list[GuardArtifact],
        payload: dict[str, object],
        config_path: Path,
        scope: str,
    ) -> None:
        servers: dict[str, object] = {}
        nested = payload.get("mcp_servers")
        if isinstance(nested, dict):
            servers.update(nested)
        for key, value in payload.items():
            if not isinstance(key, str) or not key.startswith("mcp_servers."):
                continue
            if isinstance(value, dict):
                servers[key.split(".", 1)[1]] = value
        for server_name, server_config in servers.items():
            if not isinstance(server_name, str) or not isinstance(server_config, dict):
                continue
            command = server_config.get("command")
            url = server_config.get("url")
            if not isinstance(command, str) and not isinstance(url, str):
                continue
            raw_args = server_config.get("args")
            args = tuple(str(item) for item in raw_args) if isinstance(raw_args, list) else ()
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"grok:{scope}:mcp:{server_name}",
                    name=server_name,
                    harness=self.harness,
                    artifact_type="mcp_server",
                    source_scope=scope,
                    config_path=str(config_path),
                    command=command if isinstance(command, str) else None,
                    args=args,
                    url=url if isinstance(url, str) else None,
                    transport="http" if isinstance(url, str) else "stdio",
                )
            )

    def _degraded_mode_warnings(self, config_path: Path, payload: dict[str, object]) -> list[str]:
        warnings: list[str] = []
        serialized = json.dumps(payload, sort_keys=True).lower()
        raw_text = config_path.read_text(encoding="utf-8").lower() if config_path.is_file() else ""
        for marker in _DEGRADED_MODE_MARKERS:
            marker_lower = marker.lower()
            if marker_lower in serialized or marker_lower in raw_text:
                warnings.append(
                    f"Degraded Grok protection signal in {config_path.name}: {marker}. "
                    "Guard hooks still run, but Grok may auto-approve some actions."
                )
        sandbox = payload.get("sandbox")
        if isinstance(sandbox, str) and sandbox.strip().lower() == "off":
            warnings.append(
                f"Degraded Grok protection signal in {config_path.name}: sandbox off. "
                "Guard hooks still run, but Grok may auto-approve some actions."
            )
        return warnings

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
            return text.count(_GUARD_MANAGED_BEGIN) > 1
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

    @classmethod
    def _build_pretool_hook_json(cls, hook_command: str) -> dict[str, object]:
        entries: list[dict[str, object]] = []
        for matcher in _PRETOOL_MATCHERS:
            entries.append(
                {
                    "matcher": matcher,
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 30,
                        }
                    ],
                }
            )
        return {"hooks": {"PreToolUse": entries, "UserPromptSubmit": [{"hooks": [{"type": "command", "command": hook_command, "timeout": 30}]}]}}

    @classmethod
    def _build_managed_config_block(cls) -> str:
        lines = [
            _GUARD_MANAGED_BEGIN,
            "# Permission rules below are managed by HOL Guard. Do not edit manually.",
            "[permission]",
            "deny = [",
            '  "Bash(hol-guard apps disconnect grok*)",',
            '  "Bash(rm -rf ~/.grok/hooks/hol-guard*)",',
            '  "Read(~/.grok/auth/**)",',
            '  "Read(~/.env)",',
            '  "Read(**/.env)",',
            '  "Read(**/.npmrc)",',
            '  "Read(~/.ssh/**)",',
            "]",
            _GUARD_MANAGED_END,
        ]
        return "\n".join(lines)

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
        pretool_path = hooks_dir / _GUARD_HOOK_PRETOOL_FILE
        prompt_path = hooks_dir / _GUARD_HOOK_PROMPT_FILE
        for hook_path in (pretool_path, prompt_path):
            if hook_path.is_file() and not self._backup_path(context, hook_path.name).exists():
                shutil.copy2(hook_path, self._backup_path(context, hook_path.name))

        pretool_payload = self._build_pretool_hook_json(hook_command)
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
        cleaned_text = _remove_managed_block(existing_text)
        managed_block = self._build_managed_config_block()
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

        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(managed_config_path),
            **shim_manifest,
            "notes": [
                "Guard hooks installed in ~/.grok/hooks/hol-guard-*.json",
                "Guard permission rules installed in ~/.grok/managed_config.toml",
                *[str(note) for note in shim_manifest.get("notes", [])],
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
            managed_config_path.write_text(_remove_managed_block(existing_text).rstrip() + "\n", encoding="utf-8")

        for hook_name in (_GUARD_HOOK_PRETOOL_FILE, _GUARD_HOOK_PROMPT_FILE):
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

        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(managed_config_path),
            **shim_manifest,
            "notes": [
                "Guard-managed Grok hooks and permission rules removed.",
                "User ~/.grok/config.toml, auth, skills, plugins, and sessions were preserved.",
                *[str(note) for note in shim_manifest.get("notes", [])],
            ],
        }


def _remove_managed_block(text: str) -> str:
    pattern = re.compile(
        rf"^\s*{re.escape(_GUARD_MANAGED_BEGIN)}.*?{re.escape(_GUARD_MANAGED_END)}\s*\n?",
        re.MULTILINE | re.DOTALL,
    )
    cleaned = pattern.sub("", text)
    cleaned = re.sub(rf"^\s*#.*{re.escape(_GUARD_MANAGED_MARKER)}.*$\n?", "", cleaned, flags=re.MULTILINE)
    return cleaned
