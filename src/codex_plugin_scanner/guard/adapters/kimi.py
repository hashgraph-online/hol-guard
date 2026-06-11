"""Kimi Code CLI harness adapter for HOL Guard."""

from __future__ import annotations

import os
import re
import shlex
import sys
from pathlib import Path

from ..aibom_detection import extend_detection_with_workspace_aibom
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available, _ensure_path_within_root, _json_payload

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


_KIMI_HOME_ENV_VAR = "KIMI_CODE_HOME"
_KIMI_DIR = ".kimi-code"
_KIMI_CONFIG_FILE = "config.toml"
_KIMI_MCP_FILE = "mcp.json"

_GUARD_MANAGED_BEGIN = "# BEGIN HOL GUARD MANAGED HOOKS"
_GUARD_MANAGED_END = "# END HOL GUARD MANAGED HOOKS"
_GUARD_MANAGED_MARKER = "HOL GUARD MANAGED HOOKS"


class KimiHarnessAdapter(HarnessAdapter):
    """Discover Kimi Code CLI settings, hooks, MCP servers, and manage Guard hooks."""

    harness = "kimi"
    aliases = ("kimi",)
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

    @classmethod
    def _config_candidates(cls, context: HarnessContext) -> list[tuple[Path, str]]:
        home = cls._kimi_home_dir(context)
        candidates: list[tuple[Path, str]] = [
            (home / _KIMI_DIR / _KIMI_CONFIG_FILE, "global"),
        ]
        if context.workspace_dir is not None:
            candidates.append((context.workspace_dir / _KIMI_DIR / _KIMI_CONFIG_FILE, "project"))
        return candidates

    @classmethod
    def _mcp_candidates(cls, context: HarnessContext) -> list[tuple[Path, str]]:
        home = cls._kimi_home_dir(context)
        candidates: list[tuple[Path, str]] = [
            (home / _KIMI_DIR / _KIMI_MCP_FILE, "global"),
        ]
        if context.workspace_dir is not None:
            candidates.append((context.workspace_dir / _KIMI_DIR / _KIMI_MCP_FILE, "project"))
        return candidates

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

    def policy_path(self, context: HarnessContext) -> Path:
        home = self._kimi_home_dir(context)
        if context.workspace_dir is not None:
            return context.workspace_dir / _KIMI_DIR / _KIMI_CONFIG_FILE
        return home / _KIMI_DIR / _KIMI_CONFIG_FILE

    def _managed_config_path(self, context: HarnessContext) -> Path:
        home = self._kimi_home_dir(context)
        return home / _KIMI_DIR / _KIMI_CONFIG_FILE

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []

        for config_path, scope in self._config_candidates(context):
            if not config_path.is_file():
                continue
            found_paths.append(str(config_path))
            payload = self._read_toml(config_path)
            if payload:
                self._append_hook_artifacts(artifacts, payload, config_path, scope)

        for mcp_path, scope in self._mcp_candidates(context):
            if not mcp_path.is_file():
                continue
            found_paths.append(str(mcp_path))
            payload = _json_payload(mcp_path)
            if payload:
                self._append_mcp_artifacts(artifacts, payload, mcp_path, scope)

        installed = bool(found_paths) or _command_available(self.executable)
        detection = HarnessDetection(
            harness=self.harness,
            installed=installed,
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def _append_hook_artifacts(
        self,
        artifacts: list[GuardArtifact],
        payload: dict[str, object],
        config_path: Path,
        scope: str,
    ) -> None:
        hooks = payload.get("hooks")
        if not isinstance(hooks, list):
            return
        for index, entry in enumerate(hooks):
            if not isinstance(entry, dict):
                continue
            command = entry.get("command")
            if not isinstance(command, str) or not command.strip():
                continue
            event = entry.get("event")
            event_name = event if isinstance(event, str) else ""
            matcher = entry.get("matcher")
            timeout = entry.get("timeout")
            metadata: dict[str, object] = {"event": event_name, "command": command}
            if isinstance(matcher, str):
                metadata["matcher"] = matcher
            if isinstance(timeout, (int, float)):
                metadata["timeout"] = timeout
            artifact_id = f"kimi:{scope}:hook:{event_name.lower() or 'unknown'}:{index}"
            name = (
                f"{event_name or 'hook'}:{matcher}"
                if isinstance(matcher, str) and matcher
                else event_name or "hook"
            )
            artifacts.append(
                GuardArtifact(
                    artifact_id=artifact_id,
                    name=name,
                    harness=self.harness,
                    artifact_type="hook",
                    source_scope=scope,
                    config_path=str(config_path),
                    command=command,
                    metadata=metadata,
                )
            )

    def _append_mcp_artifacts(
        self,
        artifacts: list[GuardArtifact],
        payload: dict[str, object],
        mcp_path: Path,
        scope: str,
    ) -> None:
        servers = payload.get("mcpServers")
        if not isinstance(servers, dict):
            return
        for server_name, server_config in servers.items():
            if not isinstance(server_name, str) or not isinstance(server_config, dict):
                continue
            command = server_config.get("command")
            url = server_config.get("url")
            if not isinstance(command, str) and not isinstance(url, str):
                continue
            raw_args = server_config.get("args")
            args = tuple(str(value) for value in raw_args) if isinstance(raw_args, list) else ()
            transport = "http" if isinstance(url, str) else "stdio"
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"kimi:{scope}:mcp:{server_name}",
                    name=server_name,
                    harness=self.harness,
                    artifact_type="mcp_server",
                    source_scope=scope,
                    config_path=str(mcp_path),
                    command=command if isinstance(command, str) else None,
                    args=args,
                    url=url if isinstance(url, str) else None,
                    transport=transport,
                )
            )

    @staticmethod
    def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
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
            display_name="kimi",
        )
        config_path = self._managed_config_path(context)
        _ensure_path_within_root(context.home_dir, config_path, label="Kimi Code")
        config_path.parent.mkdir(parents=True, exist_ok=True)

        hook_command = shlex.join(self._hook_command_parts(context))
        managed_block = self._build_managed_block(hook_command)
        existing_text = config_path.read_text(encoding="utf-8") if config_path.is_file() else ""
        cleaned_text = _remove_managed_block(existing_text)
        new_text = f"{cleaned_text.rstrip()}\n\n{managed_block}\n".lstrip()
        config_path.write_text(new_text, encoding="utf-8")

        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(config_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries added to ~/.kimi-code/config.toml",
                *[str(note) for note in shim_manifest.get("notes", [])],
            ],
        }

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
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(config_path),
            **shim_manifest,
            "notes": [
                "Guard hook entries removed from ~/.kimi-code/config.toml",
                *[str(note) for note in shim_manifest.get("notes", [])],
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
            lines.extend([
                "[[hooks]]",
                f'event = "{event}"',
                f'command = "{escaped_command}"',
                "timeout = 30",
            ])
        lines.append(_GUARD_MANAGED_END)
        return "\n".join(lines)


def _toml_escape(value: str) -> str:
    """Escape backslashes and double quotes for a TOML double-quoted string."""
    return value.replace("\\", "\\\\").replace('"', "\\\"")


def _remove_managed_block(text: str) -> str:
    pattern = re.compile(
        rf"^\s*{re.escape(_GUARD_MANAGED_BEGIN)}.*?{re.escape(_GUARD_MANAGED_END)}\s*\n?",
        re.MULTILINE | re.DOTALL,
    )
    cleaned = pattern.sub("", text)
    # Also remove any leftover marker-only lines from partial edits.
    cleaned = re.sub(rf"^\s*#.*{re.escape(_GUARD_MANAGED_MARKER)}.*$\n?", "", cleaned, flags=re.MULTILINE)
    return cleaned
