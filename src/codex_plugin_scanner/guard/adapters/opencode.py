"""OpenCode harness adapter."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Literal, overload

from ...ecosystems.opencode import _load_json_or_jsonc
from ..aibom_detection import extend_detection_with_workspace_aibom
from ..models import HarnessDetection
from ..shims import install_guard_shim, prepare_guard_shim, remove_guard_shim
from ._modules.opencode.opencode_config_lock import opencode_config_lock
from ._modules.opencode.opencode_install_snapshot import (
    OpenCodeInstallSnapshotError,
    load_opencode_install_snapshot,
    write_json_transaction,
)
from .base import HarnessAdapter, HarnessContext, PreparedHarnessInstall, _command_available, _run_command_probe
from .mcp_servers import managed_stdio_servers, skipped_stdio_server_names
from .opencode_artifacts import (
    CONFIG_FILENAMES,
    config_paths,
    configured_config_path,
    native_artifacts,
    runtime_config_path,
)
from .opencode_install_plan import plan_opencode_install
from .opencode_pretool import (
    global_plugin_path,
    install_pretool_plugin,
    managed_plugin_path,
    pretool_plugin_source,
    remove_pretool_plugin,
)
from .state_files import load_backup_payload, load_string_state_payload

if TYPE_CHECKING:
    from ..runtime_transition import TransitionFile


class OpenCodeInstallConfigError(RuntimeError):
    """Raised when Guard cannot safely update an existing OpenCode config file."""


class OpenCodeHarnessAdapter(HarnessAdapter):
    """Discover OpenCode config, commands, plugins, and skills."""

    harness = "opencode"
    executable = "opencode"
    approval_tier = "mixed"
    approval_summary = (
        "Guard evaluates OpenCode skills, MCP servers, commands, and plugins before launch, and the managed "
        "runtime overlay keeps managed MCP tools on native ask."
    )
    fallback_hint = (
        "Use Guard approvals for blocked artifacts and OpenCode's native allow once or allow session flow for "
        "managed MCP tools."
    )
    approval_prompt_channel = "native"
    approval_auto_open_browser = False

    _SUBCOMMANDS = frozenset(
        {
            "completion",
            "acp",
            "mcp",
            "attach",
            "run",
            "auth",
            "agent",
            "upgrade",
            "uninstall",
            "serve",
            "web",
            "models",
            "stats",
            "export",
            "import",
            "github",
            "pr",
            "session",
            "db",
        }
    )
    _REQUIRED_VALUE_OPTIONS = frozenset(
        {
            "--hostname",
            "--mdns-domain",
            "--cors",
            "--model",
            "-m",
            "--session",
            "-s",
            "--prompt",
            "--agent",
            "--variant",
            "--log-level",
            "--command",
            "--format",
            "--file",
            "-f",
            "--attach",
            "--password",
            "-p",
            "--dir",
        }
    )
    _OPTIONAL_VALUE_OPTIONS = frozenset({"--port", "--title"})

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / "opencode.json"
        return context.home_dir / ".config" / "opencode" / "opencode.json"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        configs = []
        for config_path in config_paths(context):
            payload, parse_error, _parse_reason = _load_json_or_jsonc(config_path)
            if not parse_error and payload:
                configs.append((config_path, self._scope_for(context, config_path), payload))
        artifacts, found_paths = native_artifacts(context, configs)
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable, context.home_dir),
            command_available=_command_available(self.executable, context.home_dir),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        with opencode_config_lock(context.home_dir):
            return self._install_locked(context)

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Render the whole install without acquiring the write-creating config lock."""

        from .hook_python import disposable_guard_hook_probe

        with disposable_guard_hook_probe():
            return self._install_locked(context, prepare=True)

    @overload
    def _install_locked(self, context: HarnessContext, *, prepare: Literal[True]) -> PreparedHarnessInstall: ...

    @overload
    def _install_locked(self, context: HarnessContext, *, prepare: Literal[False] = False) -> dict[str, object]: ...

    def _install_locked(
        self, context: HarnessContext, *, prepare: bool = False
    ) -> dict[str, object] | PreparedHarnessInstall:
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import TransitionFile

        contents = {path: _snapshot(path) for path in config_paths(context)} if prepare else None
        try:
            snapshot = load_opencode_install_snapshot(
                context,
                command_available=_command_available(self.executable, context.home_dir),
                config_contents=contents,
            )
        except OpenCodeInstallSnapshotError as error:
            raise OpenCodeInstallConfigError(str(error)) from error
        detection = extend_detection_with_workspace_aibom(
            snapshot.detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )
        target_config_path = self._managed_install_config_path(context)
        target_payload = snapshot.payload_for(target_config_path)
        original_text = None
        if contents is not None:
            target_before = contents[target_config_path]
            original_text = target_before.decode("utf-8") if target_before is not None else None
        elif target_config_path.is_file():
            original_text = target_config_path.read_text(encoding="utf-8")
        backup_path = self._backup_path(context)
        state_path = self._state_path(context, target_config_path)
        state_payload: dict[str, object] = {
            "managed_config_path": str(target_config_path),
            "backup_path": str(backup_path),
            "scope": "workspace" if context.workspace_dir is not None else "global",
            "workspace_dir": str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None,
        }
        try:
            plan = plan_opencode_install(
                context,
                servers=managed_stdio_servers(detection),
                skipped=skipped_stdio_server_names(detection),
                artifacts=tuple(
                    artifact.name for artifact in detection.artifacts if artifact.artifact_type == "mcp_server"
                ),
                workspace_servers=snapshot.workspace_server_names(),
                permission=target_payload.get("permission"),
                mcp=target_payload.get("mcp"),
            )
        except ValueError as error:
            raise OpenCodeInstallConfigError(str(error)) from error
        managed_servers = plan.managed
        skipped_servers = plan.skipped
        target_payload.setdefault("$schema", "https://opencode.ai/config.json")
        target_payload["permission"] = plan.permission
        target_payload["mcp"] = plan.mcp
        overlay_path = runtime_config_path(context)
        overlay_payload = plan.overlay
        writes: list[tuple[Path, dict[str, object]]] = []
        if not backup_path.exists():
            writes.append((backup_path, {"existed": original_text is not None, "content": original_text}))
        writes.extend(
            (
                (state_path, state_payload),
                (target_config_path, target_payload),
                (overlay_path, overlay_payload),
            )
        )
        files: list[TransitionFile] = []
        if prepare:
            prepared_shim = prepare_guard_shim(self.harness, context)
            shim_manifest = prepared_shim.manifest
            files.extend(prepared_shim.files)
            assert contents is not None
            after: dict[Path, bytes | None] = {
                path: (json.dumps(payload, indent=2) + "\n").encode("utf-8")
                for path, payload in writes
                if path != backup_path
            }
            backup_before = _snapshot(backup_path)
            after[backup_path] = (
                backup_before
                if backup_before is not None
                else (
                    json.dumps({"existed": original_text is not None, "content": original_text}, indent=2) + "\n"
                ).encode("utf-8")
            )
            source = pretool_plugin_source(context).encode("utf-8")
            managed_plugin = managed_plugin_path(context)
            global_plugin = global_plugin_path(context)
            after[managed_plugin] = after[global_plugin] = source
            plugin_manifest: dict[str, object] = {
                "managed_plugin_path": str(managed_plugin),
                "global_plugin_path": str(global_plugin),
            }
            for path, payload in contents.items():
                if path not in after:
                    after[path] = payload
            for path, payload in after.items():
                before = (
                    contents[path] if path in contents else backup_before if path == backup_path else _snapshot(path)
                )
                before_mode = path.stat().st_mode & 0o777 if before is not None else 0o600
                after_mode = before_mode if path in contents and path != target_config_path else 0o600
                if path in {managed_plugin, global_plugin}:
                    after_mode = before_mode if before is not None else 0o644
                if path == backup_path and backup_before is not None:
                    after_mode = before_mode
                change = TransitionFile(
                    path.resolve(strict=False), before, payload, before_mode=before_mode, after_mode=after_mode
                )
                change.payload()
                files.append(change)
        else:
            try:
                write_json_transaction(tuple(writes))
            except OpenCodeInstallSnapshotError as error:
                raise OpenCodeInstallConfigError(str(error)) from error
            shim_manifest = install_guard_shim(self.harness, context)
            plugin_manifest = install_pretool_plugin(context)
        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        notes = [
            *shim_notes,
            "Guard installed an OpenCode pretool plugin that reviews bash and shell commands through "
            "hol-guard hook before execution.",
            "Guard updated the global OpenCode root config at ~/.config/opencode/opencode.json with "
            "baseline bash permission rules and hol-guard:: MCP companion servers, and installed the "
            "pretool plugin under ~/.config/opencode/plugins/.",
            "Guard added an OpenCode runtime overlay that keeps managed MCP tools on native ask and routes "
            "managed local MCP servers through Guard runtime interception when you launch through Guard.",
            "Use hol-guard:: MCP servers in OpenCode for Guard-proxied tools, or launch through guard-opencode "
            "or hol-guard run opencode for pre-launch artifact checks and the runtime skill overlay.",
        ]
        manifest: dict[str, object] = {
            "harness": self.harness,
            "active": True,
            "config_path": str(target_config_path),
            **shim_manifest,
            **plugin_manifest,
            "managed_config_path": str(target_config_path),
            "backup_path": str(backup_path),
            "state_path": str(state_path),
            "runtime_config_path": str(overlay_path),
            "runtime_env_var": "OPENCODE_CONFIG_CONTENT",
            "managed_servers": [server.name for server in managed_servers],
            "skipped_servers": list(skipped_servers),
            "source_config_paths": list(detection.config_paths),
            "notes": notes,
        }
        return PreparedHarnessInstall(tuple(files), manifest) if prepare else manifest

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        with opencode_config_lock(context.home_dir):
            return self._uninstall_locked(context)

    def _uninstall_locked(self, context: HarnessContext) -> dict[str, object]:
        state_path, state_payload = self._state_entry(context)
        target_config_path = self._managed_config_path_from_state(context, state_payload)
        backup_path = self._backup_path_from_state(context, state_payload, target_config_path)
        state_cleanup_complete = False
        if backup_path.is_file():
            backup_payload = self._backup_payload(backup_path)
            if backup_payload["readable"] is not True:
                pass
            elif backup_payload["existed"]:
                original_text = backup_payload["content"]
                if isinstance(original_text, str):
                    target_config_path.parent.mkdir(parents=True, exist_ok=True)
                    target_config_path.write_text(original_text, encoding="utf-8")
                    backup_path.unlink()
                    state_cleanup_complete = True
            elif target_config_path.is_file():
                target_config_path.unlink()
                backup_path.unlink()
                state_cleanup_complete = True
            else:
                backup_path.unlink()
                state_cleanup_complete = True
        if state_cleanup_complete and state_path.is_file():
            state_path.unlink()
        shim_manifest = remove_guard_shim(self.harness, context)
        plugin_manifest = remove_pretool_plugin(context)
        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        notes = [
            *shim_notes,
            "Guard removed the OpenCode pretool plugin from the global plugin directory.",
            "Guard leaves the OpenCode runtime overlay on disk for auditability, but it is ignored unless you "
            "launch through Guard.",
        ]
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(target_config_path),
            **shim_manifest,
            **plugin_manifest,
            "managed_config_path": str(target_config_path),
            "backup_path": str(backup_path),
            "state_path": str(state_path),
            "runtime_config_path": str(runtime_config_path(context)),
            "runtime_env_var": "OPENCODE_CONFIG_CONTENT",
            "notes": notes,
        }

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        overlay_path = runtime_config_path(context)
        if not overlay_path.exists():
            return {}
        try:
            runtime_config = json.loads(overlay_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        existing_config = _inline_config(os.getenv("OPENCODE_CONFIG_CONTENT"))
        merged_config = _merge_configs(existing_config, runtime_config)
        return {"OPENCODE_CONFIG_CONTENT": json.dumps(merged_config)}

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        if not passthrough_args:
            return self._interactive_command(context)
        if passthrough_args[0] in self._SUBCOMMANDS:
            return [self.executable, *self._subcommand_args(context, passthrough_args)]
        return [*self._interactive_command(context), *self._interactive_args(passthrough_args)]

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        if shutil.which(self.executable) is None:
            return None
        return {
            "paths": _run_command_probe([self.executable, "debug", "paths"]),
            "config": _run_command_probe([self.executable, "debug", "config"]),
        }

    @staticmethod
    def _target_config_path(context: HarnessContext) -> Path:
        workspace_dir = context.workspace_dir
        if workspace_dir is not None:
            for name in CONFIG_FILENAMES:
                candidate = workspace_dir / name
                if candidate.is_file():
                    return candidate
        configured_path = configured_config_path(context)
        if configured_path is not None:
            return configured_path
        if workspace_dir is not None:
            return workspace_dir / CONFIG_FILENAMES[0]
        return OpenCodeHarnessAdapter._managed_install_config_path(context)

    @staticmethod
    def _managed_install_config_path(context: HarnessContext) -> Path:
        """Managed OpenCode installs always target the global root config."""

        global_dir = context.home_dir / ".config" / "opencode"
        for name in CONFIG_FILENAMES:
            candidate = global_dir / name
            if candidate.is_file():
                return candidate
        return global_dir / CONFIG_FILENAMES[0]

    @staticmethod
    def _backup_path(context: HarnessContext) -> Path:
        target_path = str(OpenCodeHarnessAdapter._managed_install_config_path(context).resolve())
        digest = hashlib.sha256(target_path.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "opencode" / f"{digest}.backup.json"

    @staticmethod
    def _state_path(context: HarnessContext, target_config_path: Path) -> Path:
        target_path = str(target_config_path.resolve())
        digest = hashlib.sha256(target_path.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "opencode" / f"{digest}.state.json"

    @classmethod
    def _state_entry(cls, context: HarnessContext) -> tuple[Path, dict[str, str]]:
        state_dir = context.guard_home / "managed" / "opencode"
        target_config_path = cls._managed_install_config_path(context)
        preferred_path = cls._state_path(context, target_config_path)
        current_workspace = str(context.workspace_dir.resolve()) if context.workspace_dir is not None else None
        candidate_entries: list[tuple[Path, dict[str, str]]] = []
        for state_path in sorted(state_dir.glob("*.state.json")):
            payload = cls._state_payload(state_path)
            if not payload:
                continue
            candidate_entries.append((state_path, payload))
        for state_path, payload in candidate_entries:
            if payload.get("managed_config_path") == str(target_config_path):
                return state_path, payload
        if current_workspace is not None:
            workspace_entries = [
                (state_path, payload)
                for state_path, payload in candidate_entries
                if payload.get("workspace_dir") == current_workspace
            ]
            if len(workspace_entries) == 1:
                return workspace_entries[0]
            return preferred_path, {}
        global_entries = [
            (state_path, payload) for state_path, payload in candidate_entries if payload.get("scope") == "global"
        ]
        if len(global_entries) == 1:
            return global_entries[0]
        return preferred_path, {}

    _state_payload = staticmethod(load_string_state_payload)

    @classmethod
    def _managed_config_path_from_state(cls, context: HarnessContext, state_payload: dict[str, str]) -> Path:
        managed_config_path = state_payload.get("managed_config_path")
        if isinstance(managed_config_path, str):
            return Path(managed_config_path)
        return cls._managed_install_config_path(context)

    @classmethod
    def _backup_path_from_state(
        cls,
        context: HarnessContext,
        state_payload: dict[str, str],
        target_config_path: Path,
    ) -> Path:
        backup_path = state_payload.get("backup_path")
        if isinstance(backup_path, str):
            return Path(backup_path)
        digest = hashlib.sha256(str(target_config_path.resolve()).encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "opencode" / f"{digest}.backup.json"

    _backup_payload = staticmethod(load_backup_payload)

    def _interactive_command(self, context: HarnessContext) -> list[str]:
        command = [self.executable]
        if context.workspace_dir is not None:
            command.append(str(context.workspace_dir))
        return command

    def _subcommand_args(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        del context
        return list(passthrough_args)

    def _interactive_args(self, passthrough_args: list[str]) -> list[str]:
        if any(value == "--prompt" or value.startswith("--prompt=") for value in passthrough_args):
            return list(passthrough_args)
        normalized: list[str] = []
        prompt_tokens: list[str] = []
        index = 0
        while index < len(passthrough_args):
            value = passthrough_args[index]
            if value == "--":
                prompt_tokens.extend(passthrough_args[index + 1 :])
                break
            if value.startswith("-"):
                normalized.append(value)
                if self._consumes_next_value(value, passthrough_args, index):
                    index += 1
                    normalized.append(passthrough_args[index])
                index += 1
                continue
            prompt_tokens.extend(passthrough_args[index:])
            break
        if prompt_tokens:
            normalized.extend(["--prompt", " ".join(prompt_tokens)])
        return normalized

    def _consumes_next_value(self, value: str, passthrough_args: list[str], index: int) -> bool:
        if index + 1 >= len(passthrough_args) or "=" in value:
            return False
        if value in self._REQUIRED_VALUE_OPTIONS:
            return True
        next_value = passthrough_args[index + 1]
        if value == "--port":
            return next_value.isdigit()
        if value == "--title":
            return not next_value.startswith("-")
        return False


__all__ = ["OpenCodeHarnessAdapter", "OpenCodeInstallConfigError"]


def _inline_config(raw_content: str | None) -> dict[str, object]:
    if not raw_content:
        return {}
    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError:
        return {}
    parsed = _object_dict(payload)
    return parsed if parsed is not None else {}


def _merge_configs(base: dict[str, object], overlay: dict[str, object]) -> dict[str, object]:
    merged = dict(base)
    for key, value in overlay.items():
        existing_value = merged.get(key)
        nested_overlay = _object_dict(value)
        nested_existing = _object_dict(existing_value)
        if nested_overlay is not None and nested_existing is not None:
            merged[key] = _merge_configs(nested_existing, nested_overlay)
            continue
        merged[key] = value
    return merged


def _object_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(key, str):
            result[key] = item
    return result
