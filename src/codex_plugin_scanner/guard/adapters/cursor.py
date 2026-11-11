"""Cursor harness adapter."""

from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import cast

from ..aibom_detection import extend_detection_with_workspace_aibom, native_adapter_detection
from ..models import HarnessDetection
from ..runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall
from ..shims import (
    ensure_guard_shim_path_in_shell_profile,
    install_guard_shim,
    prepare_guard_shim,
    prepare_guard_shim_shell_profile,
    remove_guard_shim,
)
from ..stable_guard_cli import guard_cli_launcher
from .base import (
    HarnessAdapter,
    HarnessContext,
    PreparedHarnessInstall,
    _ensure_path_within_root,
    _json_payload,
    _run_command_probe,
    detection_request,
)
from .cursor_cli import (
    CURSOR_CLI_SHIM_COMMANDS,
    cursor_cli_command_available,
    resolve_cursor_cli_entry,
)
from .cursor_hook_config import detect_managed_cursor_hook_artifact
from .cursor_hooks import cursor_hooks_path

# isort: split
from .cursor_hooks import install_cursor_hooks, prepare_cursor_hooks, uninstall_cursor_hooks
from .mcp_relay_native import mcp_proxy_launch, python_proxy_launch
from .mcp_servers import (
    ManagedMcpServer,
    managed_stdio_servers,
    observable_stdio_servers_with_proxy,
    proxy_launcher_entry,
    skipped_stdio_server_names,
)
from .state_files import restore_from_backup


class CursorHarnessAdapter(HarnessAdapter):
    """Discover Cursor MCP configuration."""

    harness = "cursor"
    executable = "cursor-agent"
    launcher_name = "cursor-agent"
    legacy_launcher_names = ("cursor",)
    approval_tier = "native-harness"
    approval_summary = (
        "Cursor already owns tool approval, so Guard focuses on artifact trust, provenance, and preflight review."
    )
    fallback_hint = "Resolve package-level trust in Guard and let Cursor keep its built-in tool approval flow."
    approval_prompt_channel = "native"
    approval_auto_open_browser = False
    # The editor runs Guard's hooks on its own, so a missing `cursor-agent` says
    # nothing about whether Cursor is installed.
    command_absence_proves_uninstalled = False

    @staticmethod
    def _scope_for(context: HarnessContext, path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".cursor" / "mcp.json"
        return context.home_dir / ".cursor" / "mcp.json"

    @staticmethod
    def _editor_config_paths(context: HarnessContext) -> tuple[Path, ...]:
        paths: list[Path] = []
        paths.append(context.home_dir / ".cursor" / "mcp.json")
        if context.workspace_dir is not None:
            paths.append(context.workspace_dir / ".cursor" / "mcp.json")
        return tuple(paths)

    @staticmethod
    def _target_editor_config_path(context: HarnessContext) -> Path:
        """Managed Cursor editor installs always target the global config."""

        return context.home_dir / ".cursor" / "mcp.json"

    def detect(
        self,
        context: HarnessContext,
        *,
        config_contents: dict[Path, bytes | None] | None = None,
    ) -> HarnessDetection:
        def captured_payload(path: Path) -> dict[str, object]:
            if config_contents is None:
                return _json_payload(path)
            raw = config_contents[path]
            if raw is None:
                return {}
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                return {}
            return payload if isinstance(payload, dict) else {}

        configs = []
        for config_path in self._editor_config_paths(context):
            payload = captured_payload(config_path)
            if payload:
                configs.append({"path": str(config_path), "payload": json.dumps(payload)})
        request = {**detection_request(self.harness, context), "configs": configs}
        native, native_paths = native_adapter_detection("cursor_detect", request)
        artifacts = [
            enrich_artifact_with_mcp_skill_firewall(
                replace(
                    artifact,
                    runtime_private_metadata=dict(
                        self._managed_mcp_origin(
                            context, Path(artifact.config_path), artifact.source_scope, artifact.name
                        )
                    ),
                )
            )
            for artifact in native
        ]
        found_paths = list(native_paths)
        hooks_path = cursor_hooks_path(context)
        hook_artifact = detect_managed_cursor_hook_artifact(hooks_path, captured_payload(hooks_path))
        if hook_artifact is not None:
            found_paths.append(hook_artifact.config_path)
            artifacts.append(hook_artifact)
        cli_available = cursor_cli_command_available(context)
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or cli_available,
            command_available=cli_available,
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def resolved_executable(self, context: HarnessContext) -> str | None:
        entry = resolve_cursor_cli_entry(context)
        if entry is None:
            return None
        return entry.executable

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        entry = resolve_cursor_cli_entry(context)
        if entry is None:
            return [self.executable, *passthrough_args]
        return entry.launch_argv(passthrough_args)

    def install(self, context: HarnessContext, *, surface: str = "editor") -> dict[str, object]:
        if surface == "cli":
            return self._install_cli(context)
        if surface == "all":
            return self._install_all(context)
        if surface != "editor":
            raise ValueError(f"Unsupported Cursor surface: {surface}")
        return self._install_editor(context)

    def prepare_install(self, context: HarnessContext, *, surface: str = "editor") -> PreparedHarnessInstall:
        """Prepare every selected surface before any binding or profile publication."""
        from ..runtime_transition import RuntimeTransition

        if surface == "cli":
            return self._prepare_cli(context)
        if surface == "all":
            editor, cli = self._prepare_editor(context), self._prepare_cli(context)
            prepared = PreparedHarnessInstall(
                (*editor.files, *cli.files), self._all_install_manifest(editor.manifest, cli.manifest)
            )
            RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
            return prepared
        if surface != "editor":
            raise ValueError(f"Unsupported Cursor surface: {surface}")
        return self._prepare_editor(context)

    def _prepare_editor(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import RuntimeTransition, TransitionFile

        target = self._target_editor_config_path(context)
        backup, state_path = self._backup_path(target, context), self._state_path(target, context)
        _ensure_path_within_root(context.home_dir, target, label="Cursor editor")
        for path in (backup, state_path):
            _ensure_path_within_root(context.guard_home, path, label="Cursor lifecycle")
        paths = {*self._editor_config_paths(context), cursor_hooks_path(context), backup, state_path}
        contents = {path: _snapshot(path) for path in paths}
        original = contents[target]
        payload = json.loads(original) if original is not None else {}
        if not isinstance(payload, dict):
            raise RuntimeError(f"Guard refused to overwrite non-object Cursor editor config at {target}")
        detection = self.detect(context, config_contents=contents)
        managed_servers = managed_stdio_servers(detection)
        origins, refresh, notes = self._editor_plan(
            context, detection, managed_servers, _json_payload(state_path), payload
        )
        self._apply_editor_servers(context, payload, refresh, managed_servers)
        hooks = prepare_cursor_hooks(context)
        files = list(hooks.files)
        state = self._editor_state(context, target, backup, origins)
        backup_data = contents[backup]
        if backup_data is None:
            backup_data = self._backup_document(None if original is None else original.decode("utf-8")).encode()
        after: dict[Path, bytes | None] = {
            target: (json.dumps(payload, indent=2) + "\n").encode("utf-8"),
            state_path: (json.dumps(state, indent=2) + "\n").encode("utf-8"),
            backup: backup_data,
        }
        for path in self._editor_config_paths(context):
            if path not in after:
                after[path] = contents[path]
        for path, data in after.items():
            mode = path.stat().st_mode & 0o777 if contents[path] is not None else 0o600
            files.append(
                TransitionFile(
                    path.resolve(strict=False), contents[path], data, before_mode=mode, after_mode=mode, no_follow=True
                )
            )
        manifest = self._editor_manifest(target, backup, state_path, managed_servers, detection, hooks.manifest, notes)
        prepared = PreparedHarnessInstall(tuple(files), manifest)
        RuntimeTransition._compare({"files": [change.payload() for change in files]}, "before")
        return prepared

    def uninstall(self, context: HarnessContext, *, surface: str = "editor") -> dict[str, object]:
        if surface == "cli":
            return self._uninstall_cli(context)
        if surface == "all":
            return self._uninstall_all(context)
        if surface != "editor":
            raise ValueError(f"Unsupported Cursor surface: {surface}")
        return self._uninstall_editor(context)

    def _install_all(self, context: HarnessContext) -> dict[str, object]:
        editor_manifest = self._install_editor(context)
        cli_manifest = self._install_cli(context)
        return self._all_install_manifest(editor_manifest, cli_manifest)

    def _all_install_manifest(
        self,
        editor_manifest: dict[str, object],
        cli_manifest: dict[str, object],
    ) -> dict[str, object]:
        return {
            "harness": self.harness,
            "active": True,
            "surface": "all",
            "surfaces": ["editor", "cli"],
            "editor": editor_manifest,
            "cli": cli_manifest,
            "managed_config_path": editor_manifest.get("managed_config_path"),
            "backup_path": editor_manifest.get("backup_path"),
            "state_path": editor_manifest.get("state_path"),
            "guard_cli_identity": editor_manifest.get("guard_cli_identity"),
            "hook_script_sha256": editor_manifest.get("hook_script_sha256"),
            "shim_path": cli_manifest.get("shim_path"),
            "shim_command": cli_manifest.get("shim_command"),
        }

    def _uninstall_all(self, context: HarnessContext) -> dict[str, object]:
        cli_manifest = self._uninstall_cli(context)
        editor_manifest = self._uninstall_editor(context)
        return {
            "harness": self.harness,
            "active": False,
            "surface": "all",
            "surfaces": ["editor", "cli"],
            "editor": editor_manifest,
            "cli": cli_manifest,
            "managed_config_path": editor_manifest.get("managed_config_path"),
            "backup_path": editor_manifest.get("backup_path"),
            "state_path": editor_manifest.get("state_path"),
            "shim_path": cli_manifest.get("shim_path"),
            "removed": cli_manifest.get("removed"),
            "restored": editor_manifest.get("restored"),
        }

    def _install_editor(self, context: HarnessContext) -> dict[str, object]:
        detection = self.detect(context)
        managed_servers = managed_stdio_servers(detection)
        target_path = self._target_editor_config_path(context)
        _ensure_path_within_root(context.home_dir, target_path, label="Cursor editor")
        original_text = target_path.read_text(encoding="utf-8") if target_path.is_file() else None
        backup_path = self._backup_path(target_path, context)
        _ensure_path_within_root(context.guard_home, backup_path, label="Cursor backup")
        state_path = self._state_path(target_path, context)
        _ensure_path_within_root(context.guard_home, state_path, label="Cursor state")
        # Parsed before any write so the native plan sees it; a parse error is
        # still raised after the backup and state writes, as before.
        parsed = self._editor_payload(target_path, original_text)
        payload = parsed if isinstance(parsed, dict) else None
        origins, refresh, notes = self._editor_plan(
            context, detection, managed_servers, _json_payload(state_path), payload
        )
        if not backup_path.exists():
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_path.write_text(self._backup_document(original_text), encoding="utf-8")
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state = self._editor_state(context, target_path, backup_path, origins)
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        if not isinstance(parsed, dict):
            raise parsed
        self._apply_editor_servers(context, parsed, refresh, managed_servers)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(json.dumps(parsed, indent=2) + "\n", encoding="utf-8")
        hooks_manifest = install_cursor_hooks(context)
        return self._editor_manifest(
            target_path, backup_path, state_path, managed_servers, detection, hooks_manifest, notes
        )

    def _editor_manifest(
        self,
        target: Path,
        backup: Path,
        state_path: Path,
        managed_servers: tuple[ManagedMcpServer, ...],
        detection: HarnessDetection,
        hooks: dict[str, object],
        notes: list[str],
    ) -> dict[str, object]:
        return {
            "harness": self.harness,
            "active": True,
            "surface": "editor",
            "managed_config_path": str(target),
            "backup_path": str(backup),
            "state_path": str(state_path),
            "managed_servers": [server.name for server in managed_servers],
            "skipped_servers": list(skipped_stdio_server_names(detection)),
            "managed_hooks_path": hooks.get("managed_hooks_path"),
            "managed_hook_script_path": hooks.get("managed_hook_script_path"),
            "guard_cli_identity": hooks.get("guard_cli_identity"),
            "hook_script_sha256": hooks.get("hook_script_sha256"),
            "notes": notes,
        }

    @staticmethod
    def _editor_state(
        context: HarnessContext, target: Path, backup: Path, origins: dict[str, object]
    ) -> dict[str, object]:
        workspace = context.workspace_dir
        return {
            "managed_config_path": str(target),
            "backup_path": str(backup),
            "surface": "editor",
            "workspace_dir": None if workspace is None else str(workspace.resolve()),
            "managed_origins": origins,
        }

    @staticmethod
    def _backup_document(original: str | None) -> str:
        return json.dumps({"existed": original is not None, "content": original}, indent=2) + "\n"

    @staticmethod
    def _editor_payload(target: Path, text: str | None) -> dict[str, object] | Exception:
        """The editor config object, or the error the install raises for it."""
        try:
            payload = {} if text is None else json.loads(text)
        except json.JSONDecodeError as exc:
            refusal = RuntimeError(f"Guard refused to overwrite unreadable Cursor editor config at {target}")
            refusal.__cause__ = exc
            return refusal
        except RecursionError as exc:
            return exc
        if not isinstance(payload, dict):
            return RuntimeError(f"Guard refused to overwrite non-object Cursor editor config at {target}")
        return cast(dict[str, object], payload)

    @staticmethod
    def _editor_plan(
        context: HarnessContext,
        detection: HarnessDetection,
        managed_servers: tuple[ManagedMcpServer, ...],
        previous_state: dict[str, object],
        payload: dict[str, object] | None,
    ) -> tuple[dict[str, object], tuple[int, ...], list[str]]:
        """Ask the native ``cursor_editor_plan`` kind for the state origins, the proxies to refresh and the notes."""
        from ..native_runner_authority import native_runner_authority

        def rows(servers: tuple[ManagedMcpServer, ...]) -> list[list[str]]:
            return [[server.name, server.source_scope, server.config_path] for server in servers]

        def launch(config: object) -> dict[str, object] | None:
            # Only the launch fields cross to the resident, never env values.
            if not isinstance(config, dict):
                return None
            return {key: value for key, value in cast(dict[str, object], config).items() if key in ("command", "args")}

        servers = None if payload is None else payload.get("mcpServers")
        configs = [launch(config) for config in servers.values()] if isinstance(servers, dict) else None
        previous = previous_state.get("managed_origins")
        request: dict[str, object] = {
            "previous_origins": list(map(list, previous.items())) if isinstance(previous, dict) else None,
            "observed": rows(observable_stdio_servers_with_proxy(detection)),
            "managed": rows(managed_servers),
            "servers": configs,
            "workspace": context.workspace_dir is not None,
        }
        answer = native_runner_authority("cursor_editor_plan", request)
        origins, refresh, notes = answer.get("origins"), answer.get("refresh"), answer.get("notes")
        configs = configs or []
        if (
            set(answer) != {"origins", "refresh", "notes"}
            or not isinstance(origins, list)
            or not all(isinstance(row, list) and len(row) == 2 and isinstance(row[0], str) for row in origins)
            or len({row[0] for row in origins}) != len(origins)
            or not isinstance(refresh, list)
            or not all(type(index) is int and 0 <= index < len(configs) for index in refresh)
            or refresh != sorted(set(refresh))
            or not all(isinstance(configs[index], dict) for index in refresh)
            or not isinstance(notes, list)
            or not all(isinstance(note, str) for note in notes)
        ):
            raise ValueError("Cursor editor plan answer is malformed")
        return {row[0]: row[1] for row in origins}, tuple(refresh), notes

    def _apply_editor_servers(
        self,
        context: HarnessContext,
        payload: dict[str, object],
        refresh: tuple[int, ...],
        managed_servers: tuple[ManagedMcpServer, ...],
    ) -> None:
        servers = payload.get("mcpServers")
        normalized = dict(cast(dict[str, object], servers)) if isinstance(servers, dict) else {}
        names = list(normalized)
        for index in refresh:
            normalized[names[index]] = self._refresh_guard_proxy_entry(
                cast(dict[str, object], normalized[names[index]])
            )
        for server in managed_servers:
            normalized[server.name] = self._proxy_server_entry(context, server)
        payload["mcpServers"] = normalized

    def _uninstall_editor(self, context: HarnessContext) -> dict[str, object]:
        target_path = self._target_editor_config_path(context)
        backup_path = self._backup_path(target_path, context)
        state_path = self._state_path(target_path, context)
        _ensure_path_within_root(context.home_dir, target_path, label="Cursor editor")
        _ensure_path_within_root(context.guard_home, backup_path, label="Cursor backup")
        _ensure_path_within_root(context.guard_home, state_path, label="Cursor state")
        restored = restore_from_backup(
            backup_path, target_path, write=lambda path, text: path.write_text(text, encoding="utf-8")
        )
        if restored and backup_path.is_file():
            backup_path.unlink()
        if restored and state_path.is_file():
            state_path.unlink()
        hooks_manifest = uninstall_cursor_hooks(context)
        return {
            "harness": self.harness,
            "active": False,
            "surface": "editor",
            "managed_config_path": str(target_path),
            "backup_path": str(backup_path),
            "state_path": str(state_path),
            "restored": restored,
            "managed_hooks_path": hooks_manifest.get("managed_hooks_path"),
            "notes": [
                "Removed Guard Cursor editor MCP proxies and restored the prior Cursor config.",
                "Removed Guard native Cursor hooks when a managed hooks backup was available.",
            ],
        }

    def _install_cli(self, context: HarnessContext) -> dict[str, object]:
        agent_shim = install_guard_shim(
            self.harness,
            context,
            launcher_name="cursor-agent",
            display_name="Cursor CLI (cursor-agent)",
        )
        cursor_shim = install_guard_shim(
            self.harness,
            context,
            launcher_name="cursor",
            display_name="Cursor CLI (cursor agent)",
        )
        profile = ensure_guard_shim_path_in_shell_profile(context)
        return self._cli_install_manifest(context, agent_shim, cursor_shim, profile)

    def _prepare_cli(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..runtime_transition import RuntimeTransition

        agent = prepare_guard_shim(
            self.harness, context, launcher_name="cursor-agent", display_name="Cursor CLI (cursor-agent)"
        )
        cursor = prepare_guard_shim(
            self.harness, context, launcher_name="cursor", display_name="Cursor CLI (cursor agent)"
        )
        profile = prepare_guard_shim_shell_profile(context)
        files = (*agent.files, *cursor.files, *profile.files)
        RuntimeTransition._compare({"files": [change.payload() for change in files]}, "before")
        return PreparedHarnessInstall(
            files, self._cli_install_manifest(context, agent.manifest, cursor.manifest, profile.manifest)
        )

    def _cli_install_manifest(
        self,
        context: HarnessContext,
        agent_shim: dict[str, object],
        cursor_shim: dict[str, object],
        profile: dict[str, object],
    ) -> dict[str, object]:
        raw_agent_notes = agent_shim.get("notes")
        agent_notes = (
            [str(note) for note in raw_agent_notes if isinstance(note, str)]
            if isinstance(raw_agent_notes, (list, tuple))
            else []
        )
        notes = [
            *agent_notes,
            "Use guard-cursor-agent for the standalone cursor-agent binary.",
            "Use guard-cursor agent ... when launching through the Cursor app CLI.",
            f"Guard launcher shims live in {context.guard_home / 'bin'}.",
        ]
        if profile.get("changed"):
            notes.append("Prepended the Guard launcher shim directory to your shell profile.")
        elif profile.get("restart_shell_required"):
            notes.append("Restart your shell or open a new terminal so guard-cursor shims are on PATH.")
        elif profile.get("manual_path_required"):
            notes.append(f"Put {context.guard_home / 'bin'} first on your PATH so guard-cursor shims run.")
        return {
            "harness": self.harness,
            "active": True,
            "surface": "cli",
            "shim_path": agent_shim["shim_path"],
            "shim_dir": agent_shim["shim_dir"],
            "shim_command": agent_shim["shim_command"],
            "shim_paths": [agent_shim["shim_path"], cursor_shim["shim_path"]],
            "shim_commands": list(CURSOR_CLI_SHIM_COMMANDS),
            "windows_shim_path": agent_shim.get("windows_shim_path"),
            "shell_profile": profile,
            "notes": notes,
        }

    def _uninstall_cli(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name="cursor-agent",
            legacy_launcher_names=self.legacy_launcher_names,
            display_name="Cursor CLI",
        )
        return {
            "harness": self.harness,
            "active": False,
            "surface": "cli",
            **shim_manifest,
        }

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        entry = resolve_cursor_cli_entry(context)
        if entry is None:
            return None
        payload = _run_command_probe(entry.launch_argv(["mcp", "list"]))
        stdout = payload.get("stdout")
        reported_artifacts = None
        if isinstance(stdout, str):
            if "No MCP servers configured" in stdout:
                reported_artifacts = 0
            else:
                reported_artifacts = sum(
                    1
                    for line in stdout.splitlines()
                    if line.strip().startswith("-") or line.strip().startswith("•") or line.strip().startswith("*")
                )
        payload["reported_artifacts"] = reported_artifacts
        return payload

    def _proxy_server_entry(self, context: HarnessContext, server: ManagedMcpServer) -> dict[str, object]:
        entry = proxy_launcher_entry(proxy_command="cursor-mcp-proxy", context=context, server=server)
        env = entry.pop("env", None)
        entry["type"] = "stdio"
        if env is not None:
            entry["env"] = env
        return entry

    @staticmethod
    def _refresh_guard_proxy_entry(server_config: dict[str, object]) -> dict[str, object]:
        refreshed = dict(server_config)
        raw_args = server_config.get("args")
        args = tuple(str(value) for value in raw_args if isinstance(value, str)) if isinstance(raw_args, list) else ()
        _, python_args = python_proxy_launch(None, args)
        refreshed["command"], refreshed["args"] = mcp_proxy_launch(guard_cli_launcher(), python_args)
        return refreshed

    @staticmethod
    def _backup_path(target_path: Path, context: HarnessContext) -> Path:
        target = str(target_path.resolve())
        digest = sha256(target.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "cursor" / f"{digest}.backup.json"

    @staticmethod
    def _state_path(target_path: Path, context: HarnessContext) -> Path:
        target = str(target_path.resolve())
        digest = sha256(target.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "cursor" / f"{digest}.state.json"

    def _managed_mcp_origin(
        self,
        context: HarnessContext,
        config_path: Path,
        scope: str,
        server_name: str,
    ) -> dict[str, object]:
        if scope != "global" or config_path != self._target_editor_config_path(context):
            return {}
        state = _json_payload(self._state_path(config_path, context))
        managed_origins = state.get("managed_origins")
        origin = managed_origins.get(server_name) if isinstance(managed_origins, dict) else None
        if "managed_origins" not in state:
            # Older installs recorded only the active workspace. Resolve that
            # bounded legacy origin before a reinstall rewrites the state.
            workspace = state.get("workspace_dir")
            if isinstance(workspace, str) and Path(workspace).is_absolute():
                origin = ["project", str(Path(workspace) / ".cursor" / "mcp.json")]
        if (
            state.get("managed_config_path") != str(config_path)
            or state.get("surface") != "editor"
            or not isinstance(origin, list)
            or len(origin) != 2
            or not all(isinstance(value, str) for value in origin)
            or origin[0] != "project"
            or not Path(origin[1]).is_absolute()
        ):
            return {}
        return {
            "managed_mcp_origin": tuple(origin),
            "managed_guard_home": str(context.guard_home),
        }
