"""Microsoft Copilot CLI harness adapter."""

from __future__ import annotations

import json
import os
import sys
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ...ecosystems.opencode import _strip_jsonc
from ..aibom_detection import native_adapter_detection_with_warnings
from ..launcher import merge_guard_launcher_env
from ..models import HarnessDetection
from ..native_path_anchor import anchor_to_process_directory
from ..shims import install_guard_shim, prepare_guard_shim, remove_guard_shim
from ..stable_guard_cli import guard_cli_launcher
from ._modules.copilot.copilot_state_paths import (
    commit_copilot_target_and_state,
    copilot_lifecycle_install,
    copilot_lifecycle_uninstall,
    copilot_state_authorizes_backup_reuse,
    copilot_state_payload,
    validated_copilot_state_entries,
)
from .adapter_safe_output import write_text_at_authorized_path
from .base import (
    HarnessAdapter,
    HarnessContext,
    PreparedHarnessInstall,
    _ensure_path_within_root,
    _json_payload,
    _run_command_probe,
)
from .bounded_cli_hook_bridge import bounded_cli_hook_command
from .codex_detect_sources import path_restorations, restore_paths
from .copilot_hook_config import CopilotHookOwnershipError, CopilotHookPlan, plan_copilot_hooks
from .hook_payloads import inline_hooks_payload
from .mcp_relay_native import mcp_proxy_launch
from .mcp_servers import (
    ManagedMcpServer,
    managed_stdio_servers,
    proxy_launcher_entry,
    skipped_stdio_server_names,
)
from .state_files import load_backup_payload

if TYPE_CHECKING:
    from ..runtime_transition import TransitionFile

_MANAGED_HOOK_FILENAME = "hol-guard-copilot.json"
_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS = 25
__all__ = ["CopilotHarnessAdapter", "CopilotHookOwnershipError"]
_MCP_KEYS = ("mcpServers", "servers")
_PLAN_KEYS = ("key", "source", "refresh", "add", "fields")
_MALFORMED = "Copilot MCP plan answer is malformed"


def _manifest_notes(payload: dict[str, object]) -> list[str]:
    notes = payload.get("notes")
    if not isinstance(notes, list):
        return []
    return [str(note) for note in notes]


def _parse_copilot_json_text(raw_text: str) -> dict[str, object] | None:
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        try:
            payload = json.loads(_strip_jsonc(raw_text))
        except json.JSONDecodeError:
            return None
    return payload if isinstance(payload, dict) else None


def _copilot_json_payload(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    return _parse_copilot_json_text(raw_text) or {}


def _hook_command_parts(
    context: HarnessContext,
    *,
    include_workspace: bool,
    prepared_files: list[TransitionFile] | None = None,
) -> tuple[str, ...]:
    guard_args = [
        "guard",
        "hook",
        "--guard-home",
        str(context.guard_home),
        "--harness",
        "copilot",
    ]
    if context.home_dir.resolve() != Path.home().resolve():
        guard_args.extend(["--home", str(context.home_dir)])
    if include_workspace and context.workspace_dir is not None:
        guard_args.extend(["--workspace", str(context.workspace_dir)])
    return bounded_cli_hook_command(
        python_executable=sys.executable,
        package_root=Path(__file__).resolve().parents[3],
        guard_home=context.guard_home,
        cli_args=guard_args,
        harness="copilot",
        timeout_seconds=_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS,
        prepared_files=prepared_files,
    )


def _hook_entry(context: HarnessContext, plan: CopilotHookPlan) -> dict[str, object]:
    entry: dict[str, object] = {
        "type": "command",
        "bash": plan.bash,
        "powershell": plan.powershell,
        "cwd": str(context.guard_home),
        "timeoutSec": 30,
    }
    env = merge_guard_launcher_env()
    if env:
        entry["env"] = env
    return entry


_inline_hooks_payload = inline_hooks_payload


def _launch_slot(payload: dict[str, object], key: str) -> object:
    """A servers key as the native plan reads it: absent, not an object, or launch-only pairs."""
    if key not in payload:
        return None
    servers = payload[key]
    if not isinstance(servers, dict):
        return False
    return [
        [name, {k: v for k, v in config.items() if k in ("command", "args")} if isinstance(config, dict) else None]
        for name, config in cast(dict[str, object], servers).items()
    ]


def _plan_mcp_targets(
    context: HarnessContext,
    targets: list[tuple[Path, dict[str, object]]],
    managed: tuple[ManagedMcpServer, ...],
) -> tuple[list[Any], list[str]]:
    """Ask the native ``copilot_mcp_plan`` kind for each MCP target's plan and the install notes."""
    from ..native_runner_authority import native_runner_authority

    def key(path: str | Path) -> str:
        return os.path.normcase(str(Path(path)))

    request: dict[str, object] = {
        "workspace": context.workspace_dir is not None,
        "managed": [[server.name, server.source_scope, key(server.config_path)] for server in managed],
        "targets": [
            {"path": key(path), "name": path.name, **{name: _launch_slot(payload, name) for name in _MCP_KEYS}}
            for path, payload in targets
        ],
    }
    answer = native_runner_authority("copilot_mcp_plan", request)
    plans, notes = _list(answer.get("targets")), _list(answer.get("notes"))
    if set(answer) != {"targets", "notes"} or len(plans) != len(targets) or not _strings(notes):
        raise ValueError(_MALFORMED)
    return plans, notes


def _list(value: object) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(_MALFORMED)
    return cast(list[Any], value)


def _strings(value: object) -> bool:
    return all(isinstance(item, str) for item in _list(value))


def _increasing(value: object, bound: int) -> bool:
    items = _list(value)
    return all(type(item) is int and 0 <= item < bound for item in items) and items == sorted(set(items))


def _apply_mcp_plan(
    context: HarnessContext, plan: object, payload: dict[str, object], managed: tuple[ManagedMcpServer, ...]
) -> None:
    """Apply one target's native plan to its payload in place, refusing a malformed plan."""
    if not isinstance(plan, dict) or set(plan) != set(_PLAN_KEYS):
        raise ValueError(_MALFORMED)
    key, source, refresh, add, fields = (cast(dict[str, object], plan)[name] for name in _PLAN_KEYS)
    if source is None:
        servers: object = {}
    elif source in _MCP_KEYS:
        servers = payload.get(source)
    else:
        servers = None
    configs: list[tuple[str, Any]] = list(cast(dict[str, object], servers).items()) if isinstance(servers, dict) else []
    rows, pairs = _list(refresh), _list(fields)
    if (
        key not in _MCP_KEYS
        or not isinstance(servers, dict)
        or not all(len(_list(row)) == 2 and _strings(row[1]) for row in rows)
        or not _increasing([row[0] for row in rows], len(configs))
        or not all(isinstance(configs[row[0]][1], dict) for row in rows)
        or not _increasing(add, len(managed))
        or not all(len(_list(pair)) == 2 and isinstance(pair[0], str) for pair in pairs)
    ):
        raise ValueError(_MALFORMED)
    normalized = dict(configs)
    for index, python_args in rows:
        name, config = configs[index]
        env = config.get("env") if isinstance(config.get("env"), dict) else config.get("environment")
        env = cast(dict[str, str], env) if isinstance(env, dict) else {}
        normalized[name] = _refresh_guard_proxy_entry(config, python_args, launcher_env=merge_guard_launcher_env(env))
    for index in _list(add):
        entry = proxy_launcher_entry(proxy_command="copilot-mcp-proxy", context=context, server=managed[index])
        entry.update(pairs)
        normalized[managed[index].name] = entry
    payload[cast(str, key)] = normalized
    payload.pop("servers" if key == "mcpServers" else "mcpServers", None)


def _refresh_guard_proxy_entry(
    server_config: dict[str, object],
    python_args: list[str],
    *,
    launcher_env: dict[str, str],
) -> dict[str, object]:
    refreshed = dict(server_config)
    refreshed["command"], refreshed["args"] = mcp_proxy_launch(guard_cli_launcher(), python_args)
    if launcher_env:
        refreshed["env"] = launcher_env
    else:
        refreshed.pop("env", None)
        refreshed.pop("environment", None)
    return refreshed


class CopilotHarnessAdapter(HarnessAdapter):
    """Discover Microsoft Copilot CLI repo hooks and MCP config artifacts."""

    harness = "copilot"
    executable = "copilot"
    approval_tier = "native-or-center"
    approval_summary = (
        "Guard uses native Copilot prompts through Copilot CLI hook surfaces and VS Code workspace hooks when "
        "those surfaces are installed. Guard falls back to the local approval center only when the active Copilot "
        "surface cannot prompt."
    )
    fallback_hint = (
        "Guard prefers native Copilot prompts where the active Copilot surface exposes them. Proof for Copilot "
        "should come from native hook responses and Guard runtime receipts in Copilot CLI or VS Code workspace "
        "hooks, or from the local approval center when prompting is unavailable."
    )
    approval_prompt_channel = "hook"
    approval_auto_open_browser = False

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        del context
        return (Path.home() / ".local" / "copilot-cli" / "copilot",)

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    @staticmethod
    def _hook_path(context: HarnessContext) -> Path | None:
        if context.workspace_dir is None:
            return None
        return context.workspace_dir / ".github" / "hooks" / _MANAGED_HOOK_FILENAME

    @staticmethod
    def _config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".copilot" / "config.json"

    @staticmethod
    def _workspace_mcp_paths(context: HarnessContext) -> tuple[Path, ...]:
        if context.workspace_dir is None:
            return ()
        return (
            context.workspace_dir / ".mcp.json",
            context.workspace_dir / ".vscode" / "mcp.json",
        )

    @staticmethod
    def _target_mcp_paths(context: HarnessContext) -> tuple[Path, ...]:
        workspace_paths = CopilotHarnessAdapter._workspace_mcp_paths(context)
        if len(workspace_paths) > 0:
            return workspace_paths
        return (context.home_dir / ".copilot" / "mcp-config.json",)

    @staticmethod
    def _backup_path(target_path: Path, context: HarnessContext) -> Path:
        target = str(target_path.resolve())
        digest = sha256(target.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "copilot" / f"{digest}.backup.json"

    @staticmethod
    def _strict_json_object(path: Path, *, label: str, recover_malformed: bool = False) -> dict[str, object]:
        if not path.is_file():
            return {}
        try:
            raw_text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Guard refused to overwrite unreadable {label} at {path}") from exc
        payload = _parse_copilot_json_text(raw_text)
        if payload is None:
            if recover_malformed:
                return {}
            raise RuntimeError(f"Guard refused to overwrite unreadable {label} at {path}")
        return payload

    def detect(
        self,
        context: HarnessContext,
        *,
        config_contents: dict[Path, bytes | None] | None = None,
    ) -> HarnessDetection:
        # The native resident parses each config and owns hook and MCP server
        # discovery. Python resolves the candidates, their scopes and the
        # `.github/hooks` listing, and fails closed without the resident.
        sources: list[tuple[Path, str]] = [
            (context.home_dir / ".copilot" / "config.json", "config"),
            (context.home_dir / ".copilot" / "mcp-config.json", "mcp"),
            *((path, "mcp") for path in self._workspace_mcp_paths(context)),
        ]
        if context.workspace_dir is not None:
            hooks_dir = context.workspace_dir / ".github" / "hooks"
            if hooks_dir.is_dir() or config_contents is not None:
                hook_paths = (
                    sorted(path for path in config_contents if path.parent == hooks_dir and path.suffix == ".json")
                    if config_contents is not None
                    else sorted(path for path in hooks_dir.glob("*.json") if path.is_file())
                )
                sources.extend((path, "hooks") for path in hook_paths)
        request: dict[str, object] = {
            "harness": self.harness,
            "sources": [
                {"path": anchor_to_process_directory(path), "scope": self._scope_for(context, path), "kind": kind}
                for path, kind in sources
            ],
        }
        if config_contents is not None:
            request["contents"] = {
                anchor_to_process_directory(path): None if (data := config_contents.get(path)) is None else data.hex()
                for path, _kind in sources
            }
        artifacts, found_paths, _warnings = native_adapter_detection_with_warnings("copilot_detect", request)
        artifacts, found_paths, _warnings = restore_paths(
            path_restorations(tuple(path for path, _kind in sources)), artifacts, found_paths, ()
        )
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or self.resolved_executable(context) is not None,
            command_available=self.resolved_executable(context) is not None,
            config_paths=found_paths,
            artifacts=artifacts,
            warnings=(),
        )

    @copilot_lifecycle_install
    def install(self, context: HarnessContext) -> dict[str, object]:
        return self._render_install(context)

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Prepare a rebind using existing enrolled lifecycle authority; never create a key."""
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import RuntimeTransition, TransitionError, TransitionFile

        # A runtime rebind must retain the installation's authority. Enrollment
        # remains the normal installer responsibility, outside this transition.
        try:
            copilot_state_payload(
                context,
                target_path=self._target_mcp_paths(context)[0],
                backup_path=self._backup_path(self._target_mcp_paths(context)[0], context),
                state_path=self._state_path(self._target_mcp_paths(context)[0], context),
                scope="global",
                create_key=False,
            )
        except FileNotFoundError as error:
            raise TransitionError("adapter_preparation_authority_missing") from error
        except (OSError, ValueError) as error:
            raise TransitionError("adapter_preparation_authority_invalid") from error
        files = [TransitionFile.identity_dependency(context.guard_home / "managed/adapter-state.key")]
        paths = {
            self._config_path(context),
            context.home_dir / ".copilot/mcp-config.json",
            *self._workspace_mcp_paths(context),
        }
        hook_path = self._hook_path(context)
        if hook_path is not None:
            paths.add(hook_path)
            paths.update(path for path in hook_path.parent.glob("*.json") if path.is_file())
        contents = {path: _snapshot(path) for path in paths}
        manifest = self._render_install(context, prepared_files=files, config_contents=contents)
        planned = {change.path for change in files}
        for path, data in contents.items():
            if path.resolve(strict=False) not in planned:
                mode = path.stat().st_mode & 0o777 if data is not None else 0o600
                files.append(TransitionFile(path.resolve(strict=False), data, data, before_mode=mode, after_mode=mode))
        unique: dict[Path, TransitionFile] = {}
        for change in files:
            if change.path in unique and change != unique[change.path]:
                raise TransitionError("adapter_preparation_generation_conflict")
            unique[change.path] = change
        prepared = PreparedHarnessInstall(tuple(unique.values()), manifest)
        RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
        return prepared

    def _render_install(
        self,
        context: HarnessContext,
        *,
        prepared_files: list[TransitionFile] | None = None,
        config_contents: dict[Path, bytes | None] | None = None,
    ) -> dict[str, object]:
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import TransitionFile

        def captured(path: Path) -> bytes | None:
            return config_contents[path] if config_contents is not None and path in config_contents else _snapshot(path)

        def parsed(path: Path) -> dict[str, object]:
            if config_contents is None:
                return _copilot_json_payload(path)
            data = captured(path)
            return _parse_copilot_json_text(data.decode("utf-8")) or {} if data is not None else {}

        def prepare_file(path: Path, after: bytes | None, *, before: bytes | None) -> None:
            assert prepared_files is not None
            mode = path.stat().st_mode & 0o777 if before is not None else 0o600
            change = TransitionFile(
                path.resolve(strict=False), before, after, before_mode=mode, after_mode=mode, no_follow=True
            )
            change.payload()
            prepared_files.append(change)

        # Read which hook commands Guard owns before anything is written, so a
        # runtime that cannot answer leaves every file as it was.
        config_path = self._config_path(context)
        _ensure_path_within_root(context.home_dir, config_path, label="Copilot config")
        config_payload = (
            self._strict_json_object(config_path, label="Copilot config", recover_malformed=True)
            if prepared_files is None
            else parsed(config_path)
        )
        hooks_payload = _inline_hooks_payload(config_payload)
        managed_hook_path = self._hook_path(context)
        workspace_payload: dict[str, object] | None = None
        if managed_hook_path is not None:
            if context.workspace_dir is None:
                raise ValueError("Copilot workspace hook requires a workspace root")
            _ensure_path_within_root(context.workspace_dir, managed_hook_path, label="Copilot hook")
            workspace_payload = (
                _json_payload(managed_hook_path) if prepared_files is None else parsed(managed_hook_path)
            )
        # Stage Guard's hook script so a refused plan leaves it as it was.
        staged: list[TransitionFile] = [] if prepared_files is None else prepared_files
        config_parts = _hook_command_parts(context, include_workspace=False, prepared_files=staged)
        workspace = (
            None
            if workspace_payload is None
            else (
                workspace_payload,
                _hook_command_parts(context, include_workspace=True, prepared_files=staged),
            )
        )
        config_plan, workspace_plan = plan_copilot_hooks(context.guard_home, (hooks_payload, config_parts), workspace)
        if prepared_files is None and _hook_command_parts(context, include_workspace=False) != config_parts:
            raise RuntimeError("Guard could not write its Copilot hook script")
        detection = self.detect(context, config_contents=config_contents)
        managed_servers = managed_stdio_servers(detection)
        skipped_servers = skipped_stdio_server_names(detection)
        target_mcp_paths = self._target_mcp_paths(context)
        backup_paths: list[str] = []
        state_paths: list[str] = []
        gathered: list[tuple[Path, Path, bytes | None, str | None, dict[str, object]]] = []
        for target_mcp_path in target_mcp_paths:
            target_root = context.workspace_dir if context.workspace_dir is not None else context.home_dir
            _ensure_path_within_root(target_root, target_mcp_path, label="Copilot MCP")
            target_before = captured(target_mcp_path) if prepared_files is not None else None
            original_text = (
                (target_before.decode("utf-8") if target_before is not None else None)
                if (prepared_files is not None)
                else (target_mcp_path.read_text(encoding="utf-8") if target_mcp_path.is_file() else None)
            )
            backup_path = self._backup_path(target_mcp_path, context)
            _ensure_path_within_root(context.guard_home, backup_path, label="Copilot backup")
            backup_paths.append(str(backup_path))
            state_path = self._state_path(target_mcp_path, context)
            _ensure_path_within_root(context.guard_home, state_path, label="Copilot state")
            state_paths.append(str(state_path))
            gathered.append((backup_path, state_path, target_before, original_text, parsed(target_mcp_path)))
        plans, mcp_notes = _plan_mcp_targets(
            context, [(path, item[4]) for path, item in zip(target_mcp_paths, gathered, strict=True)], managed_servers
        )
        # Every plan is checked and applied in memory before the first write, so
        # a malformed plan for a later target leaves every file untouched.
        for item, plan in zip(gathered, plans, strict=True):
            _apply_mcp_plan(context, plan, item[4], managed_servers)
        for target_mcp_path, (backup_path, state_path, target_before, original_text, mcp_payload) in zip(
            target_mcp_paths, gathered, strict=True
        ):
            if prepared_files is None:
                target_mcp_path.parent.mkdir(parents=True, exist_ok=True)
                commit_copilot_target_and_state(
                    context,
                    target_path=target_mcp_path,
                    target_payload=json.dumps(mcp_payload, indent=2) + "\n",
                    original_text=original_text,
                    backup_path=backup_path,
                    state_path=state_path,
                    scope=self._scope_for(context, target_mcp_path),
                )
            else:
                backup_before, state_before = _snapshot(backup_path), _snapshot(state_path)
                state_before_payload = json.loads(state_before) if state_before is not None else {}
                reuse = copilot_state_authorizes_backup_reuse(
                    context,
                    target_path=target_mcp_path,
                    backup_path=backup_path,
                    state_path=state_path,
                    state_payload=state_before_payload if isinstance(state_before_payload, dict) else {},
                )
                backup_after = (
                    backup_before
                    if reuse
                    else (
                        json.dumps({"existed": original_text is not None, "content": original_text}, indent=2) + "\n"
                    ).encode("utf-8")
                )
                state_after = copilot_state_payload(
                    context,
                    target_path=target_mcp_path,
                    backup_path=backup_path,
                    state_path=state_path,
                    scope=self._scope_for(context, target_mcp_path),
                    create_key=False,
                )
                prepare_file(backup_path, backup_after, before=backup_before)
                prepare_file(
                    target_mcp_path, (json.dumps(mcp_payload, indent=2) + "\n").encode("utf-8"), before=target_before
                )
                prepare_file(
                    state_path, (json.dumps(state_after, indent=2) + "\n").encode("utf-8"), before=state_before
                )
        if prepared_files is None:
            shim_manifest = install_guard_shim(self.harness, context)
        else:
            shim = prepare_guard_shim(self.harness, context)
            prepared_files.extend(shim.files)
            shim_manifest = shim.manifest
        primary_target_mcp_path = target_mcp_paths[0]
        primary_backup_path = backup_paths[0]
        primary_state_path = state_paths[0]
        config_plan.install(_hook_entry(context, config_plan))
        if prepared_files is None:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            write_text_at_authorized_path(config_path, json.dumps(config_payload, indent=2) + "\n")
        else:
            prepare_file(
                config_path, (json.dumps(config_payload, indent=2) + "\n").encode("utf-8"), before=captured(config_path)
            )
        if managed_hook_path is not None and workspace_plan is not None:
            workspace_plan.install(_hook_entry(context, workspace_plan))
            managed_hook_payload = workspace_plan.payload
            if prepared_files is None:
                managed_hook_path.parent.mkdir(parents=True, exist_ok=True)
                write_text_at_authorized_path(managed_hook_path, json.dumps(managed_hook_payload, indent=2) + "\n")
            else:
                prepare_file(
                    managed_hook_path,
                    (json.dumps(managed_hook_payload, indent=2) + "\n").encode("utf-8"),
                    before=captured(managed_hook_path),
                )
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(config_path),
            **shim_manifest,
            "managed_config_path": str(primary_target_mcp_path),
            "managed_config_paths": [str(path) for path in target_mcp_paths],
            "backup_path": primary_backup_path,
            "backup_paths": backup_paths,
            "state_path": primary_state_path,
            "state_paths": state_paths,
            "managed_servers": [server.name for server in managed_servers],
            "skipped_servers": list(skipped_servers),
            "notes": [*mcp_notes, *_manifest_notes(shim_manifest)],
        }

    @copilot_lifecycle_uninstall
    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        # Read which hook commands Guard owns before anything is restored or
        # removed, so a runtime that cannot answer leaves every file as it was.
        config_path = self._config_path(context)
        config_payload = self._strict_json_object(config_path, label="Copilot config")
        hooks_payload = _inline_hooks_payload(config_payload)
        managed_hook_path = self._hook_path(context)
        # Uninstall only reads which entries Guard owns; the staged hook script is never written.
        staged: list[TransitionFile] = []
        config_parts = _hook_command_parts(context, include_workspace=False, prepared_files=staged)
        workspace: tuple[dict[str, object], tuple[str, ...]] | None = None
        if managed_hook_path is not None and managed_hook_path.is_file():
            workspace = (
                _json_payload(managed_hook_path),
                _hook_command_parts(context, include_workspace=True, prepared_files=staged),
            )
        config_plan, workspace_plan = plan_copilot_hooks(context.guard_home, (hooks_payload, config_parts), workspace)
        uninstall_targets = self._uninstall_targets(context)
        for state_path, target_mcp_path, backup_path in uninstall_targets:
            cleanup_complete = False
            if not backup_path.is_file():
                continue
            backup_payload = self._backup_payload(backup_path)
            if backup_payload["readable"] is not True:
                continue
            if backup_payload["existed"] and isinstance(backup_payload["content"], str):
                target_mcp_path.parent.mkdir(parents=True, exist_ok=True)
                write_text_at_authorized_path(target_mcp_path, str(backup_payload["content"]))
                cleanup_complete = True
            elif backup_payload["existed"] is not True and target_mcp_path.is_file():
                target_mcp_path.unlink()
                cleanup_complete = True
            elif backup_payload["existed"] is not True:
                cleanup_complete = True
            if cleanup_complete:
                backup_path.unlink()
            if cleanup_complete and state_path.is_file():
                state_path.unlink()
        shim_manifest = remove_guard_shim(self.harness, context)
        remaining_state_entries = self._state_entries(context)
        managed_config_paths = [str(target_path) for _state_path, target_path, _backup_path in uninstall_targets]
        backup_paths = [str(backup_path) for _state_path, _target_path, backup_path in uninstall_targets]
        state_paths = [str(state_path) for state_path, _target_path, _backup_path in uninstall_targets]
        primary_target_mcp_path = managed_config_paths[0] if managed_config_paths else ""
        primary_backup_path = backup_paths[0] if backup_paths else ""
        primary_state_path = state_paths[0] if state_paths else ""
        if len(remaining_state_entries) == 0:
            config_plan.uninstall()
            if len(hooks_payload) == 0:
                config_payload.pop("hooks", None)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        write_text_at_authorized_path(config_path, json.dumps(config_payload, indent=2) + "\n")
        if managed_hook_path is not None and workspace_plan is not None:
            workspace_plan.uninstall()
            managed_hook_payload = workspace_plan.payload
            if len(workspace_plan.hooks) > 0:
                managed_hook_path.parent.mkdir(parents=True, exist_ok=True)
                write_text_at_authorized_path(managed_hook_path, json.dumps(managed_hook_payload, indent=2) + "\n")
            else:
                managed_hook_path.unlink()
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(config_path),
            **shim_manifest,
            "managed_config_path": primary_target_mcp_path,
            "managed_config_paths": managed_config_paths,
            "backup_path": primary_backup_path,
            "backup_paths": backup_paths,
            "state_path": primary_state_path,
            "state_paths": state_paths,
            "notes": [
                "Guard hook entries removed from ~/.copilot/config.json for Copilot CLI.",
                "Guard workspace hook entries removed from .github/hooks/hol-guard-copilot.json for VS Code Copilot.",
                "Guard restored the prior Copilot MCP config for the active Copilot surfaces.",
                *_manifest_notes(shim_manifest),
            ],
        }

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        executable = self.resolved_executable(context)
        if executable is None:
            return None
        return _run_command_probe([executable, "--help"])

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        executable = self.resolved_executable(context) or self.executable
        workspace_paths = self._workspace_mcp_paths(context)
        cli_workspace_config = next(
            (path for path in workspace_paths if path.name == ".mcp.json" and path.is_file()),
            None,
        )
        if cli_workspace_config is None:
            return [executable, *passthrough_args]
        return [
            executable,
            "--additional-mcp-config",
            f"@{cli_workspace_config}",
            *passthrough_args,
        ]

    _backup_payload = staticmethod(load_backup_payload)

    @staticmethod
    def _state_path(target_path: Path, context: HarnessContext) -> Path:
        target = str(target_path.resolve())
        digest = sha256(target.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "copilot" / f"{digest}.state.json"

    @classmethod
    def _state_entries(cls, context: HarnessContext) -> list[tuple[Path, Path, Path, dict[str, object]]]:
        return validated_copilot_state_entries(
            context,
            state_path_for=cls._state_path,
            backup_path_for=cls._backup_path,
        )

    @classmethod
    def _uninstall_targets(cls, context: HarnessContext) -> list[tuple[Path, Path, Path]]:
        current_targets = cls._target_mcp_paths(context)
        current_target_paths = {str(target_path.resolve()) for target_path in current_targets}
        state_entries = cls._state_entries(context)
        exact_matches = [
            (state_path, managed_config_path, backup_path)
            for state_path, managed_config_path, backup_path, _payload in state_entries
            if str(managed_config_path.resolve()) in current_target_paths
        ]
        if exact_matches:
            return exact_matches
        if context.workspace_dir is not None:
            current_workspace = str(context.workspace_dir.resolve())
            workspace_matches = [
                (state_path, managed_config_path, backup_path)
                for state_path, managed_config_path, backup_path, payload in state_entries
                if payload.get("workspace_dir") == current_workspace
            ]
            if workspace_matches:
                return workspace_matches
        if context.workspace_dir is None and state_entries:
            return [
                (state_path, managed_config_path, backup_path)
                for state_path, managed_config_path, backup_path, _payload in state_entries
            ]
        # Unsigned legacy backups are migrated by the next install, which
        # replaces the orphaned backup and writes authenticated lifecycle
        # state. They never authorize destructive cleanup on their own.
        return []
