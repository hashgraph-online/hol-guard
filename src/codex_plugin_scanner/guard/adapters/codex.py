"""Codex harness adapter."""

from __future__ import annotations

import hashlib
import importlib
import json
import shlex
import sys
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from ...version import __version__
from ..aibom_detection import (
    enrich_mcp_server_metadata,
    extend_codex_runtime_inventory,
    extend_detection_with_workspace_aibom,
)
from ..codex_config import dump_toml, read_toml_payload, write_toml_payload
from ..codex_hook_file_integrity import validate_regular_file
from ..codex_hook_integrity import (
    atomic_write_text,
    hook_manifest_path,
    hook_secret_path,
    remove_hook_manifest,
    remove_hook_secret_if_unused,
    restore_private_file,
    snapshot_regular_file,
    write_hook_manifest,
)
from ..codex_hook_inventory import (
    CODEX_HOOK_INVENTORY_SOURCE_CHANGED,
    CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE,
    CODEX_HOOK_INVENTORY_SOURCE_MALFORMED,
    CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE,
    CODEX_HOOK_INVENTORY_UNMANAGED_EXECUTABLE,
    CodexHookInventory,
    enumerate_codex_hooks,
)
from ..codex_hook_manifest import (
    CodexHookManifestSpec,
    build_authenticated_hook_manifest,
    load_hook_manifest_baseline,
    verify_live_hook_manifest,
)
from ..codex_hook_manifest import (
    assert_package_reauthentication_is_safe as _assert_package_reauthentication_is_safe,
)
from ..codex_hook_manifest import (
    manifest_bindings as _manifest_bindings,
)
from ..codex_hook_registration import (
    exact_legacy_hook_bindings,
)
from ..codex_hook_registration import (
    remove_manifest_bound_hook_events as _remove_manifest_bound_hook_events,
)
from ..config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, load_guard_config, resolve_guard_home
from ..launcher import merge_guard_launcher_env
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available, _warnings_include_setup_failure
from .codex_remote_control import (
    codex_remote_launch_environment,
    guarded_codex_launch_command,
    guarded_codex_launch_command_candidates,
    guarded_codex_launch_command_from_prefix,
)
from .mcp_servers import (
    ManagedMcpServer,
    is_guard_proxy_command,
    managed_stdio_servers,
    proxy_cli_args,
    proxy_process_env,
    skipped_stdio_server_names,
)

tomllib: Any
try:  # pragma: no cover - Python 3.11+
    import tomllib as tomllib  # pyright: ignore[reportMissingImports]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    tomllib = importlib.import_module("tomli")


def _read_toml(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
        return payload if isinstance(payload, dict) else {}
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _artifact_from_guard_proxy_args(
    *,
    args: tuple[str, ...],
    fallback_name: str,
    fallback_scope: str,
    fallback_config_path: Path,
    harness: str,
    environment: object = None,
) -> GuardArtifact | None:
    """Expose the wrapped server for status/review without re-wrapping it."""

    parsed = _parse_guard_proxy_args(args)
    command = parsed.get("command")
    if not isinstance(command, str) or not command:
        return None
    name_value = parsed.get("server-name")
    name = name_value if isinstance(name_value, str) and name_value else fallback_name
    source_scope_value = parsed.get("source-scope")
    source_scope = source_scope_value if isinstance(source_scope_value, str) and source_scope_value else fallback_scope
    config_path_value = parsed.get("config-path")
    config_path = (
        config_path_value if isinstance(config_path_value, str) and config_path_value else str(fallback_config_path)
    )
    transport_value = parsed.get("transport")
    transport = transport_value if isinstance(transport_value, str) and transport_value else "stdio"
    server_args_value = parsed.get("arg")
    server_args = server_args_value if isinstance(server_args_value, tuple) else ()
    env_keys_value = parsed.get("server-env-key")
    env_keys = tuple(sorted(env_keys_value)) if isinstance(env_keys_value, tuple) else ()
    raw_environment = environment if isinstance(environment, dict) else {}
    configured_environment = {key: value for key in env_keys if isinstance((value := raw_environment.get(key)), str)}
    metadata = enrich_mcp_server_metadata(
        {
            "env": configured_environment,
            "env_keys": list(env_keys),
            "guard_managed_proxy": True,
            "name": name,
        },
        command=command,
        args=server_args,
        url=None,
        transport=transport,
    )
    return GuardArtifact(
        artifact_id=f"codex:{source_scope}:{name}",
        name=name,
        harness=harness,
        artifact_type="mcp_server",
        source_scope=source_scope,
        config_path=config_path,
        command=command,
        args=server_args,
        transport=transport,
        metadata=metadata,
    )


def _parse_guard_proxy_args(args: tuple[str, ...]) -> dict[str, str | tuple[str, ...]]:
    parsed: dict[str, str | tuple[str, ...]] = {}
    repeated: dict[str, list[str]] = {"arg": [], "server-env-key": []}
    index = 0
    while index < len(args):
        token = args[index]
        if not token.startswith("--"):
            index += 1
            continue
        key_value = token[2:]
        if "=" in key_value:
            key, value = key_value.split("=", 1)
            if key in repeated:
                repeated[key].append(value)
            else:
                parsed[key] = value
            index += 1
            continue
        key = key_value
        if key in repeated:
            if index + 1 < len(args):
                repeated[key].append(args[index + 1])
                index += 2
            else:
                index += 1
            continue
        if index + 1 < len(args) and not args[index + 1].startswith("--"):
            parsed[key] = args[index + 1]
            index += 2
        else:
            index += 1
    for key, values in repeated.items():
        parsed[key] = tuple(values)
    return parsed


_MANAGED_HOOK_STATUS_MESSAGE = "HOL Guard checking tool action"
_MANAGED_PROMPT_HOOK_STATUS_MESSAGE = "HOL Guard checking prompt"
_MANAGED_PERMISSION_HOOK_STATUS_MESSAGE = "HOL Guard checking Codex approval request"
_MANAGED_POST_TOOL_HOOK_STATUS_MESSAGE = "HOL Guard checking tool result"
_LEGACY_MANAGED_HOOK_STATUS_MESSAGES = {
    "HOL Guard checking Bash command",
    _MANAGED_HOOK_STATUS_MESSAGE,
    _MANAGED_PROMPT_HOOK_STATUS_MESSAGE,
    _MANAGED_PERMISSION_HOOK_STATUS_MESSAGE,
    _MANAGED_POST_TOOL_HOOK_STATUS_MESSAGE,
}
_MANAGED_HOOK_TIMEOUT_SECONDS = 30
_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS = 5
_CODEX_GUARD_TOOL_MATCHER = "Bash|Read|Write|Edit|MultiEdit|^apply_patch$|mcp__.*"
_CODEX_GUARD_PERMISSION_MATCHER = "Bash|Read|Write|Edit|MultiEdit|^apply_patch$|mcp__.*"
_SHELL_GUARD_BEGIN = "# >>> HOL Guard Codex shell guard >>>"
_SHELL_GUARD_END = "# <<< HOL Guard Codex shell guard <<<"
_AUTHORITATIVE_ENFORCEMENT_BOUNDARY = "codex-native-hooks"
_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON = "codex_authoritative_hook_unavailable"


def _json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _strict_json_object(path: Path, *, label: str) -> dict[str, object]:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE}: Guard refused to overwrite non-file {label} at {path}. "
            "Replace it with a readable regular file before retrying install."
        )
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
    except _DuplicateJsonKeyError as exc:
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE}: Guard found duplicate key {exc.key!r} in {label} at "
            f"{path}. Remove the duplicate before retrying install."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE}: Guard could not read {label} at {path}. Repair file "
            "permissions before retrying install."
        ) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_MALFORMED}: Guard refused to overwrite unreadable {label} at {path} "
            "because its JSON is malformed. Repair the JSON before retrying install."
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_MALFORMED}: Guard refused to overwrite non-object {label} at {path}. "
            "Replace it with a JSON object before retrying install."
        )
    return payload


class _DuplicateJsonKeyError(ValueError):
    key: str

    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise _DuplicateJsonKeyError(key)
        payload[key] = value
    return payload


def _strict_toml_object(path: Path, *, label: str) -> dict[str, object]:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE}: Guard refused to overwrite non-file {label} at {path}. "
            "Replace it with a readable regular file before retrying install."
        )
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
    except OSError as exc:
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE}: Guard could not read {label} at {path}. Repair file "
            "permissions before retrying install."
        ) from exc
    except tomllib.TOMLDecodeError as exc:
        reason = (
            CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE
            if "overwrite" in str(exc).lower()
            else CODEX_HOOK_INVENTORY_SOURCE_MALFORMED
        )
        raise RuntimeError(
            f"{reason}: Guard could not parse {label} at {path}. Repair the TOML before retrying install."
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_SOURCE_MALFORMED}: Guard refused to overwrite non-object {label} at {path}."
        )
    return payload


def _require_hook_inventory_sources_unchanged(
    *,
    config_payloads: Mapping[Path, dict[str, object]],
    hook_payloads: Mapping[Path, dict[str, object]],
) -> None:
    for path, expected in config_payloads.items():
        if _strict_toml_object(path, label="Codex config file") != expected:
            raise RuntimeError(
                f"{CODEX_HOOK_INVENTORY_SOURCE_CHANGED}: Codex config changed after pre-activation inventory at "
                f"{path}. Retry install after configuration writes have stopped."
            )
    for path, expected in hook_payloads.items():
        if _strict_json_object(path, label="Codex hooks file") != expected:
            raise RuntimeError(
                f"{CODEX_HOOK_INVENTORY_SOURCE_CHANGED}: Codex hooks changed after pre-activation inventory at "
                f"{path}. Retry install after configuration writes have stopped."
            )


def _local_hook_command_parts_for_home_mode(
    context: HarnessContext,
    *,
    home_is_current: bool,
    python_executable: str,
) -> tuple[str, ...]:
    guard_args = [
        "guard",
        "hook",
        "--harness",
        "codex",
    ]
    if not home_is_current:
        guard_args.extend(["--home", str(context.home_dir)])
        if context.guard_home.resolve() != context.home_dir.resolve():
            guard_args.extend(["--guard-home", str(context.guard_home)])
    if context.workspace_dir is not None:
        guard_args.extend(["--workspace", str(context.workspace_dir)])
    return (python_executable, "-m", "codex_plugin_scanner.cli", *guard_args)


def _guard_python_executable() -> str:
    """Use an absolute interpreter invocation while preserving virtualenv identity."""

    return str(Path(sys.executable).expanduser().absolute())


def _home_is_current(context: HarnessContext) -> bool:
    return not context.home_override_explicit and context.home_dir.resolve() == Path.home().resolve()


def _runtime_guard_home(context: HarnessContext) -> Path:
    return resolve_guard_home() if _home_is_current(context) else context.guard_home


def _local_hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    return _local_hook_command_parts_for_home_mode(
        context,
        home_is_current=_home_is_current(context),
        python_executable=_guard_python_executable(),
    )


def _daemon_start_command(guard_home: Path, *, python_executable: str = sys.executable) -> tuple[str, ...]:
    package_root = Path(__file__).resolve().parents[3]
    code = (
        "import sys;"
        f"sys.path.insert(0, {str(package_root)!r});"
        "from pathlib import Path;"
        "from codex_plugin_scanner.guard.daemon import ensure_guard_daemon;"
        f"ensure_guard_daemon(Path({str(guard_home)!r}))"
    )
    return (python_executable, "-c", code)


def _hook_command_parts_for_home_mode(
    context: HarnessContext,
    *,
    home_is_current: bool,
    python_executable: str,
) -> tuple[str, ...]:
    guard_home = resolve_guard_home() if home_is_current else context.guard_home
    query = {"guard-home": str(guard_home)}
    if not home_is_current:
        query["home"] = str(context.home_dir)
    if context.workspace_dir is not None:
        query["workspace"] = str(context.workspace_dir)
    long_timeout = _post_tool_hook_timeout_seconds(context)
    config = {
        "state_path": str(guard_home / "daemon-state.json"),
        "fallback_command": list(
            _local_hook_command_parts_for_home_mode(
                context,
                home_is_current=home_is_current,
                python_executable=python_executable,
            )
        ),
        "start_command": list(_daemon_start_command(guard_home, python_executable=python_executable)),
        "query": urlencode(query),
        "hook_timeouts": {
            "PreToolUse": long_timeout,
            "PermissionRequest": _MANAGED_HOOK_TIMEOUT_SECONDS,
            "UserPromptSubmit": _MANAGED_HOOK_TIMEOUT_SECONDS,
            "PostToolUse": long_timeout,
        },
    }
    bridge_path = Path(__file__).with_name("codex_daemon_hook_bridge.py").resolve()
    return (python_executable, str(bridge_path), json.dumps(config, separators=(",", ":")))


def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    return _hook_command_parts_for_home_mode(
        context,
        home_is_current=_home_is_current(context),
        python_executable=_guard_python_executable(),
    )


def _hook_command(context: HarnessContext) -> str:
    return shlex.join(_hook_command_parts(context))


def _managed_hook_entry(
    context: HarnessContext,
    status_message: str,
    *,
    timeout_seconds: int = _MANAGED_HOOK_TIMEOUT_SECONDS,
) -> dict[str, object]:
    environment = merge_guard_launcher_env(pin_package=True)
    environment.update(codex_remote_launch_environment(context.home_dir))
    return {
        "type": "command",
        "command": _hook_command(context),
        "timeout": timeout_seconds,
        "statusMessage": status_message,
        "env": environment,
    }


def _pre_tool_hook_group(context: HarnessContext) -> dict[str, object]:
    return {
        "matcher": _CODEX_GUARD_TOOL_MATCHER,
        "hooks": [
            _managed_hook_entry(
                context,
                _MANAGED_HOOK_STATUS_MESSAGE,
                timeout_seconds=_post_tool_hook_timeout_seconds(context),
            )
        ],
    }


def _prompt_hook_group(context: HarnessContext) -> dict[str, object]:
    return {
        "hooks": [_managed_hook_entry(context, _MANAGED_PROMPT_HOOK_STATUS_MESSAGE)],
    }


def _permission_request_hook_group(context: HarnessContext) -> dict[str, object]:
    return {
        "matcher": _CODEX_GUARD_PERMISSION_MATCHER,
        "hooks": [_managed_hook_entry(context, _MANAGED_PERMISSION_HOOK_STATUS_MESSAGE)],
    }


def _post_tool_hook_timeout_seconds(context: HarnessContext) -> int:
    configured_wait_timeout = load_guard_config(
        context.guard_home,
        context.workspace_dir,
    ).approval_wait_timeout_seconds
    return (
        min(
            max(configured_wait_timeout, 0),
            MAX_APPROVAL_WAIT_TIMEOUT_SECONDS,
        )
        + _MANAGED_HOOK_TIMEOUT_GRACE_SECONDS
    )


def _post_tool_hook_group(context: HarnessContext) -> dict[str, object]:
    return {
        "matcher": "Bash",
        "hooks": [
            _managed_hook_entry(
                context,
                _MANAGED_POST_TOOL_HOOK_STATUS_MESSAGE,
                timeout_seconds=_post_tool_hook_timeout_seconds(context),
            )
        ],
    }


def _managed_hook_groups(context: HarnessContext) -> dict[str, dict[str, object]]:
    return {
        "PreToolUse": _pre_tool_hook_group(context),
        "PermissionRequest": _permission_request_hook_group(context),
        "UserPromptSubmit": _prompt_hook_group(context),
        "PostToolUse": _post_tool_hook_group(context),
    }


def _manifest_event_bindings(context: HarnessContext) -> list[dict[str, object]]:
    argv = list(_hook_command_parts(context))
    bindings: list[dict[str, object]] = []
    for event_name, group in _managed_hook_groups(context).items():
        handlers = group.get("hooks")
        if not isinstance(handlers, list) or len(handlers) != 1 or not isinstance(handlers[0], dict):
            raise RuntimeError(f"Guard's {event_name} hook definition is not canonical.")
        bindings.append(
            {
                "argv": argv,
                "event": event_name,
                "group": deepcopy(group),
                "group_matcher": group.get("matcher"),
                "handler": deepcopy(handlers[0]),
                "handler_id": f"codex:{event_name}:guard-handler-v1",
                "handler_index": 0,
            }
        )
    return bindings


def _hook_packaged_file_paths() -> tuple[tuple[str, Path], ...]:
    scanner_root = Path(__file__).resolve().parents[2]
    daemon_root = Path(__file__).resolve().parents[1] / "daemon"
    return (
        ("bridge", Path(__file__).with_name("codex_daemon_hook_bridge.py").resolve()),
        ("fallback_entrypoint", scanner_root / "cli.py"),
        ("daemon_entrypoint", daemon_root / "__init__.py"),
        ("daemon_manager", daemon_root / "manager.py"),
    )


def _hook_manifest_spec(context: HarnessContext) -> CodexHookManifestSpec:
    return CodexHookManifestSpec(
        guard_home=context.guard_home,
        home_dir=context.home_dir,
        runtime_guard_home=_runtime_guard_home(context),
        workspace_dir=context.workspace_dir,
        config_path=CodexHarnessAdapter._hook_config_path(context),
        interpreter_path=Path(_guard_python_executable()),
        package_version=__version__,
        packaged_file_paths=_hook_packaged_file_paths(),
        fallback_argv=_local_hook_command_parts(context),
        daemon_start_argv=_daemon_start_command(
            _runtime_guard_home(context),
            python_executable=_guard_python_executable(),
        ),
        event_bindings=tuple(_manifest_event_bindings(context)),
    )


def _build_authenticated_hook_manifest(context: HarnessContext) -> dict[str, object]:
    return build_authenticated_hook_manifest(_hook_manifest_spec(context))


def _current_install_legacy_bindings(context: HarnessContext, hooks: dict[str, object]) -> list[dict[str, object]]:
    """Select exact current bridge entries for explicit legacy re-adoption only."""

    current_argv = list(_hook_command_parts(context))
    return exact_legacy_hook_bindings(
        hooks,
        expected_bindings=_manifest_event_bindings(context),
        current_argv=current_argv,
        legacy_argv=[sys.executable, *current_argv[1:]],
        legacy_status_messages=_LEGACY_MANAGED_HOOK_STATUS_MESSAGES,
    )


def _append_unique_hook_groups(existing_groups: object, incoming_groups: object) -> list[object]:
    merged = list(existing_groups) if isinstance(existing_groups, list) else []
    if not isinstance(incoming_groups, list):
        return merged
    for group in incoming_groups:
        if group not in merged:
            merged.append(group)
    return merged


def _migrate_hooks_json_into_config(
    config_payload: dict[str, object],
    hooks_payload: dict[str, object],
    *,
    context: HarnessContext,
    owned_bindings: Sequence[Mapping[str, object]] = (),
) -> bool:
    json_hooks = hooks_payload.get("hooks")
    if not isinstance(json_hooks, dict):
        return False
    config_hooks = config_payload.get("hooks")
    if not isinstance(config_hooks, dict):
        config_hooks = {}
    cleaned_json_hooks, _ = _remove_manifest_bound_hook_events(json_hooks, owned_bindings)
    legacy_bindings = _current_install_legacy_bindings(context, cleaned_json_hooks)
    cleaned_json_hooks, _ = _remove_manifest_bound_hook_events(cleaned_json_hooks, legacy_bindings)
    changed = False
    for event_name, groups in cleaned_json_hooks.items():
        merged_groups = _append_unique_hook_groups(config_hooks.get(event_name), groups)
        if merged_groups != config_hooks.get(event_name):
            changed = True
        config_hooks[event_name] = merged_groups
    if config_hooks:
        config_payload["hooks"] = config_hooks
    return changed


def _codex_hook_inventory(
    payload: dict[str, object],
    *,
    source_path: Path,
    source_scope: str,
    source_format: str,
    source_hooks_enabled: bool,
    context: HarnessContext,
    authenticated_bindings: Sequence[Mapping[str, object]] = (),
) -> CodexHookInventory:
    hooks = payload.get("hooks")
    legacy_bindings = _current_install_legacy_bindings(context, hooks if isinstance(hooks, dict) else {})
    return enumerate_codex_hooks(
        payload,
        source_path=source_path,
        source_scope=source_scope,
        source_format="json" if source_format == "json" else "toml",
        source_hooks_enabled=source_hooks_enabled,
        authenticated_bindings=authenticated_bindings,
        legacy_bindings=legacy_bindings,
    )


def _require_complete_preactivation_inventory(inventory: CodexHookInventory) -> None:
    if inventory.issues:
        issue = inventory.issues[0]
        raise RuntimeError(f"{issue.reason_code}: {issue.coordinate} in {issue.source_path}. {issue.message}")
    unmanaged = inventory.unmanaged_active_executables
    if inventory.records and not inventory.records[0].source_hooks_enabled and unmanaged:
        coordinates = ", ".join(record.coordinate for record in unmanaged)
        raise RuntimeError(
            f"{CODEX_HOOK_INVENTORY_UNMANAGED_EXECUTABLE}: Guard refused to enable existing Codex hook entries "
            f"without explicit approval; unmanaged executable hooks are present at {coordinates} in "
            f"{inventory.source_path}. Review or remove those hooks before running install."
        )


def _payload_has_hooks_feature_enabled(config_payload: dict[str, object]) -> bool:
    features = config_payload.get("features")
    if not isinstance(features, dict):
        return False
    return features.get("hooks") is True or features.get("codex_hooks") is True


def _line_marker_at(content: bytes, index: int, marker: bytes) -> bool:
    if index < 0 or content[index : index + len(marker)] != marker:
        return False
    before_is_boundary = index == 0 or content[index - 1 : index] == b"\n"
    after_index = index + len(marker)
    after_is_boundary = after_index == len(content) or content[after_index : after_index + 1] in {b"\r", b"\n"}
    return before_is_boundary and after_is_boundary


def _find_line_marker(content: bytes, marker: bytes, start: int) -> int:
    index = content.find(marker, start)
    while index >= 0 and not _line_marker_at(content, index, marker):
        index = content.find(marker, index + len(marker))
    return index


def _trailing_line_break_length(content: bytes) -> int:
    if content.endswith(b"\r\n"):
        return 2
    if content.endswith(b"\n"):
        return 1
    return 0


def _remove_managed_shell_guard_blocks(content: bytes) -> bytes:
    """Remove only legacy Guard marker blocks while preserving every other byte."""

    begin = _SHELL_GUARD_BEGIN.encode("utf-8")
    end = _SHELL_GUARD_END.encode("utf-8")
    search_from = 0
    while (block_start := _find_line_marker(content, begin, search_from)) >= 0:
        block_end_start = _find_line_marker(content, end, block_start + len(begin))
        if block_end_start < 0:
            break
        removal_start = block_start
        prefix = content[:block_start]
        last_break_length = _trailing_line_break_length(prefix)
        if last_break_length and _trailing_line_break_length(prefix[:-last_break_length]):
            # Legacy installation inserted one blank separator before its block.
            removal_start -= last_break_length
        removal_end = block_end_start + len(end)
        if content[removal_end : removal_end + 2] == b"\r\n":
            removal_end += 2
        elif content[removal_end : removal_end + 1] == b"\n":
            removal_end += 1
        content = content[:removal_start] + content[removal_end:]
        search_from = removal_start
    return content


def _hooks_have_registered_entries(hooks: object) -> bool:
    if not isinstance(hooks, dict):
        return False
    return any(isinstance(groups, list) and bool(groups) for groups in hooks.values())


def _verify_live_hook_manifest(
    context: HarnessContext,
    *,
    config_path: Path,
    hooks: object,
) -> dict[str, object]:
    spec = _hook_manifest_spec(context)
    if spec.config_path != config_path:
        raise RuntimeError("Codex hook verification received a non-canonical config target.")
    return verify_live_hook_manifest(spec, hooks=hooks)


def codex_native_hook_state(context: HarnessContext) -> dict[str, object]:
    config_path = CodexHarnessAdapter._hook_config_path(context)
    hooks_path = CodexHarnessAdapter._hooks_path(context)
    config_payload = _read_toml(config_path)
    features = config_payload.get("features") if isinstance(config_payload, dict) else None
    toml_hooks = config_payload.get("hooks") if isinstance(config_payload, dict) else None
    hooks_payload = _json_object(hooks_path)
    json_hooks = hooks_payload.get("hooks") if isinstance(hooks_payload, dict) else None
    hooks = toml_hooks if isinstance(toml_hooks, dict) else json_hooks
    integrity = _verify_live_hook_manifest(context, config_path=config_path, hooks=hooks)
    event_matches_value = integrity.get("event_matches")
    event_matches = event_matches_value if isinstance(event_matches_value, dict) else {}
    pre_tool_hook_installed = event_matches.get("PreToolUse") is True
    permission_hook_installed = event_matches.get("PermissionRequest") is True
    prompt_hook_installed = event_matches.get("UserPromptSubmit") is True
    post_tool_hook_installed = event_matches.get("PostToolUse") is True
    managed_hook_installed = all(
        (pre_tool_hook_installed, permission_hook_installed, prompt_hook_installed, post_tool_hook_installed)
    )
    authoritative_shell_hook_installed = pre_tool_hook_installed and permission_hook_installed
    integrity_valid = integrity.get("integrity_status") == "valid"
    features_is_table = isinstance(features, dict)
    hooks_feature_enabled = not features_is_table or features.get("hooks") is not False
    legacy_codex_hooks_enabled = features_is_table and features.get("codex_hooks") is True
    return {
        "config_path": str(config_path),
        "config_present": config_path.is_file(),
        "hooks_path": str(hooks_path),
        "hooks_present": hooks_path.is_file(),
        "toml_hooks_present": _hooks_have_registered_entries(toml_hooks),
        "json_hooks_present": _hooks_have_registered_entries(json_hooks),
        "hooks_enabled": hooks_feature_enabled,
        "codex_hooks_enabled": hooks_feature_enabled,
        "legacy_codex_hooks_enabled": legacy_codex_hooks_enabled,
        "managed_pre_tool_hook_installed": pre_tool_hook_installed,
        "managed_permission_request_hook_installed": permission_hook_installed,
        "managed_prompt_hook_installed": prompt_hook_installed,
        "managed_post_tool_hook_installed": post_tool_hook_installed,
        "managed_hook_installed": managed_hook_installed,
        "shell_enforcement_boundary": _AUTHORITATIVE_ENFORCEMENT_BOUNDARY,
        "shell_hook_installed": authoritative_shell_hook_installed,
        "shell_protection_active": hooks_feature_enabled and authoritative_shell_hook_installed and integrity_valid,
        "shell_reason_code": (
            None
            if hooks_feature_enabled and authoritative_shell_hook_installed and integrity_valid
            else _AUTHORITATIVE_HOOK_UNAVAILABLE_REASON
        ),
        "protection_active": hooks_feature_enabled and managed_hook_installed and integrity_valid,
        **{key: value for key, value in integrity.items() if key != "event_matches"},
    }


def _require_codex_authoritative_shell_hook(context: HarnessContext) -> None:
    hook_state = codex_native_hook_state(context)
    if bool(hook_state["shell_protection_active"]):
        return
    raise RuntimeError(
        f"{_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON}: Guard refused to launch Codex because the managed "
        "PreToolUse and PermissionRequest hooks are missing or disabled. Run `hol-guard install codex` "
        "or `hol-guard update` to repair the native-hook enforcement boundary."
    )


class CodexHarnessAdapter(HarnessAdapter):
    """Discover Codex MCP servers and wrapper surfaces."""

    harness = "codex"
    executable = "codex"
    approval_tier = "native-or-center"
    approval_summary = (
        "Guard uses native Codex PreToolUse hooks as the authoritative complete-command boundary, "
        "PermissionRequest hooks for Codex approval prompts, prompt hooks for sensitive file-read requests, "
        "keeps same-chat approvals for managed MCP tool calls, and falls back to the local approval center when "
        "Codex cannot answer."
    )
    fallback_hint = (
        "If Codex cannot render or return the inline approval request, or the native PreToolUse hook blocks a "
        "sensitive complete command, Guard will queue it in the local approval center."
    )
    approval_prompt_channel = "native"
    approval_auto_open_browser = False

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        _require_codex_authoritative_shell_hook(context)
        return guarded_codex_launch_command(
            executable=self.resolved_executable(context) or self.executable,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
        )

    def preview_launch_commands(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
    ) -> tuple[list[str], ...]:
        _require_codex_authoritative_shell_hook(context)
        return guarded_codex_launch_command_candidates(
            executable=self.resolved_executable(context) or self.executable,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
        )

    def launch_command_from_authorized_plan(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
        *,
        authorized_executable_prefixes: Sequence[Sequence[str]],
        launch_environment: Mapping[str, str],
    ) -> list[str]:
        _require_codex_authoritative_shell_hook(context)
        prefixes = {tuple(prefix) for prefix in authorized_executable_prefixes if prefix}
        if len(prefixes) != 1:
            raise ValueError("Codex launch candidates do not share one authorized executable prefix.")
        return guarded_codex_launch_command_from_prefix(
            executable_prefix=prefixes.pop(),
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
            environ=launch_environment,
        )

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        return codex_remote_launch_environment(context.home_dir)

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def policy_path(self, context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _hooks_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "hooks.json"

    @staticmethod
    def _all_hook_paths(context: HarnessContext) -> tuple[Path, ...]:
        paths = [context.home_dir / ".codex" / "hooks.json"]
        if context.workspace_dir is not None:
            paths.append(context.workspace_dir / ".codex" / "hooks.json")
        return tuple(paths)

    @staticmethod
    def _config_hook_pairs(context: HarnessContext) -> tuple[tuple[Path, Path], ...]:
        pairs = [(context.home_dir / ".codex" / "config.toml", context.home_dir / ".codex" / "hooks.json")]
        if context.workspace_dir is not None:
            pairs.append(
                (context.workspace_dir / ".codex" / "config.toml", context.workspace_dir / ".codex" / "hooks.json")
            )
        return tuple(pairs)

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_paths = [context.home_dir / ".codex" / "config.toml"]
        if context.workspace_dir is not None:
            config_paths.append(context.workspace_dir / ".codex" / "config.toml")
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        for config_path in config_paths:
            payload = _read_toml(config_path)
            if not payload:
                continue
            found_paths.append(str(config_path))
            scope = self._scope_for(context, config_path)
            mcp_servers = payload.get("mcp_servers")
            if isinstance(mcp_servers, dict):
                for name, server_config in mcp_servers.items():
                    if not isinstance(name, str) or not isinstance(server_config, dict):
                        continue
                    command = server_config.get("command")
                    args = tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str))
                    if is_guard_proxy_command(command if isinstance(command, str) else None, args):
                        proxy_artifact = _artifact_from_guard_proxy_args(
                            args=args,
                            fallback_name=name,
                            fallback_scope=scope,
                            fallback_config_path=config_path,
                            harness=self.harness,
                            environment=server_config.get("env"),
                        )
                        if proxy_artifact is not None:
                            artifacts.append(proxy_artifact)
                        continue
                    url = server_config.get("url")
                    env = server_config.get("env")
                    environment = (
                        {
                            key.strip(): value
                            for key, value in env.items()
                            if isinstance(key, str) and key.strip() and isinstance(value, str)
                        }
                        if isinstance(env, dict)
                        else {}
                    )
                    enabled = server_config.get("enabled", True) is not False
                    mcp_metadata = enrich_mcp_server_metadata(
                        {
                            "name": name,
                            "enabled": enabled,
                            "env": environment,
                            "env_keys": sorted(environment),
                        },
                        command=command if isinstance(command, str) else None,
                        args=args,
                        url=url if isinstance(url, str) else None,
                        transport="http" if isinstance(url, str) else "stdio",
                    )
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"codex:{scope}:{name}",
                            name=name,
                            harness=self.harness,
                            artifact_type="mcp_server",
                            source_scope=scope,
                            config_path=str(config_path),
                            command=command if isinstance(command, str) else None,
                            args=args,
                            url=url if isinstance(url, str) else None,
                            transport="http" if isinstance(url, str) else "stdio",
                            metadata=mcp_metadata,
                        )
                    )
        hooks_paths = [context.home_dir / ".codex" / "hooks.json"]
        if context.workspace_dir is not None:
            hooks_paths.append(context.workspace_dir / ".codex" / "hooks.json")
        for hooks_path in hooks_paths:
            hooks_payload = _json_object(hooks_path)
            hooks = hooks_payload.get("hooks")
            if not isinstance(hooks, dict):
                continue
            found_paths.append(str(hooks_path))
            scope = self._scope_for(context, hooks_path)
            hook_groups = hooks.get("PreToolUse")
            if not isinstance(hook_groups, list):
                continue
            for group_index, group in enumerate(hook_groups):
                if not isinstance(group, dict):
                    continue
                handlers = group.get("hooks")
                if not isinstance(handlers, list):
                    continue
                for handler_index, handler in enumerate(handlers):
                    if not isinstance(handler, dict):
                        continue
                    command = handler.get("command")
                    artifacts.append(
                        GuardArtifact(
                            artifact_id=f"codex:{scope}:pretooluse:{group_index}:{handler_index}",
                            name="PreToolUse",
                            harness=self.harness,
                            artifact_type="hook",
                            source_scope=scope,
                            config_path=str(hooks_path),
                            command=command if isinstance(command, str) else None,
                        )
                    )
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )
        extended = extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )
        return extend_codex_runtime_inventory(
            extended,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        detection = self.detect(context)
        managed_servers = managed_stdio_servers(detection)
        skipped_servers = skipped_stdio_server_names(detection)
        target_config_path = self._target_config_path(context)
        hook_config_path = self._hook_config_path(context)
        previous_manifest = load_hook_manifest_baseline(_hook_manifest_spec(context))
        owned_bindings = _manifest_bindings(previous_manifest)
        hook_payloads = self._load_hook_payloads(context)
        config_payloads = {
            config_path: _strict_toml_object(config_path, label="Codex config file")
            for config_path, _hooks_path in self._config_hook_pairs(context)
        }
        inventory_hook_payloads = deepcopy(hook_payloads)
        inventory_config_payloads = deepcopy(config_payloads)
        original_text = target_config_path.read_text(encoding="utf-8") if target_config_path.is_file() else None
        payload = config_payloads[target_config_path]
        hook_payload = payload if hook_config_path == target_config_path else config_payloads[hook_config_path]
        for config_path, hooks_path in self._config_hook_pairs(context):
            json_hook_payload = hook_payloads.get(hooks_path, {})
            if config_path == target_config_path:
                hook_config_payload = payload
            elif config_path == hook_config_path:
                hook_config_payload = hook_payload
            else:
                hook_config_payload = config_payloads[config_path]
            hooks_feature_enabled = _payload_has_hooks_feature_enabled(hook_config_payload)
            source_scope = self._scope_for(context, config_path)
            config_inventory = _codex_hook_inventory(
                hook_config_payload,
                source_path=config_path,
                source_scope=source_scope,
                source_format="toml",
                source_hooks_enabled=hooks_feature_enabled,
                context=context,
                authenticated_bindings=owned_bindings if config_path == hook_config_path else (),
            )
            json_inventory = _codex_hook_inventory(
                json_hook_payload,
                source_path=hooks_path,
                source_scope=source_scope,
                source_format="json",
                source_hooks_enabled=hooks_feature_enabled,
                context=context,
            )
            _require_complete_preactivation_inventory(config_inventory)
            _require_complete_preactivation_inventory(json_inventory)
        _require_hook_inventory_sources_unchanged(
            config_payloads=inventory_config_payloads,
            hook_payloads=inventory_hook_payloads,
        )
        target_hooks_path = self._hooks_path(context)
        target_hook_payload = hook_payloads.get(target_hooks_path, {})
        target_hooks_migrated = _migrate_hooks_json_into_config(
            hook_payload,
            target_hook_payload,
            context=context,
            owned_bindings=owned_bindings,
        )
        backup_path = self._backup_path(context)
        if not backup_path.exists():
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_text = dump_toml(payload) if target_hooks_migrated else original_text or ""
            backup_path.write_text(backup_text, encoding="utf-8")
        mcp_servers = payload.get("mcp_servers")
        if not isinstance(mcp_servers, dict):
            mcp_servers = {}
        features = hook_payload.get("features")
        if not isinstance(features, dict):
            features = {}
        features.pop("codex_hooks", None)
        features["hooks"] = True
        hook_payload["features"] = features
        self._install_config_hooks(hook_payload, context, owned_bindings=owned_bindings)
        workspace_payload = (
            read_toml_payload(context.workspace_dir / ".codex" / "config.toml")
            if context.workspace_dir is not None
            else {}
        )
        workspace_servers = workspace_payload.get("mcp_servers")
        existing_workspace_server_names = (
            {name for name, value in workspace_servers.items() if isinstance(name, str) and isinstance(value, dict)}
            if isinstance(workspace_servers, dict)
            else set()
        )
        for server in managed_servers:
            if self._should_skip_workspace_override(
                context=context,
                server=server,
                existing_workspace_server_names=existing_workspace_server_names,
            ):
                mcp_servers.pop(server.name, None)
                continue
            mcp_servers[server.name] = self._proxy_server_entry(context, server)
        payload["mcp_servers"] = mcp_servers
        hook_state = self._write_authenticated_hook_config(
            context,
            config_path=target_config_path,
            payload=payload,
            previous_manifest=previous_manifest,
        )
        if hook_config_path != target_config_path:
            raise RuntimeError("Codex hook authentication currently requires one canonical global config target.")
        self._migrate_alternate_hook_configs(
            context,
            payloads=hook_payloads,
            config_payloads=config_payloads,
            skip_config_path=hook_config_path,
            owned_bindings=(),
        )
        self._remove_managed_hooks_from_alternate_configs(context, skip_config_path=hook_config_path)
        self._remove_managed_mcp_servers_from_alternate_configs(
            context,
            managed_servers=managed_servers,
            skip_config_path=target_config_path,
        )
        hooks_path = self._remove_json_hook_files(context, payloads=hook_payloads)
        self._uninstall_shell_guard(context)
        _require_codex_authoritative_shell_hook(context)
        shim_manifest = install_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(target_config_path),
            **shim_manifest,
            "mode": "codex-mcp-proxy",
            "managed_config_path": str(target_config_path),
            "managed_hook_config_path": str(hook_config_path),
            "managed_hook_manifest_path": str(hook_state["manifest_path"]),
            "managed_hook_integrity": str(hook_state["integrity_status"]),
            "managed_hooks_path": str(hooks_path),
            "enforcement_boundary": _AUTHORITATIVE_ENFORCEMENT_BOUNDARY,
            "legacy_shell_guard_cleanup": "complete",
            "backup_path": str(backup_path),
            "managed_servers": [server.name for server in managed_servers],
            "skipped_servers": list(skipped_servers),
            "source_config_paths": list(detection.config_paths),
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        target_config_path = self._target_config_path(context)
        hook_config_path = self._hook_config_path(context)
        authenticated_manifest = load_hook_manifest_baseline(_hook_manifest_spec(context))
        owned_bindings = _manifest_bindings(authenticated_manifest)
        backup_path = self._backup_path(context)
        if backup_path.is_file():
            original_text = backup_path.read_text(encoding="utf-8")
            if original_text:
                atomic_write_text(target_config_path, original_text, mode=0o600)
            elif target_config_path.is_file():
                target_config_path.unlink()
            backup_path.unlink()
        elif target_config_path.is_file() and owned_bindings:
            target_payload = read_toml_payload(target_config_path)
            target_hooks = target_payload.get("hooks")
            if isinstance(target_hooks, dict):
                cleaned_hooks, managed_removed = _remove_manifest_bound_hook_events(target_hooks, owned_bindings)
                if managed_removed:
                    if cleaned_hooks:
                        target_payload["hooks"] = cleaned_hooks
                    else:
                        target_payload.pop("hooks", None)
                    atomic_write_text(target_config_path, dump_toml(target_payload), mode=0o600)
        hooks_path = self._remove_hooks(context)
        self._remove_managed_hooks_from_alternate_configs(context, skip_config_path=target_config_path)
        self._remove_managed_mcp_servers_from_alternate_configs(
            context,
            managed_servers=(),
            skip_config_path=target_config_path,
        )
        remove_hook_manifest(context.guard_home, hook_config_path)
        remove_hook_secret_if_unused(context.guard_home)
        self._uninstall_shell_guard(context)
        shim_manifest = remove_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(target_config_path),
            **shim_manifest,
            "mode": "codex-mcp-proxy",
            "managed_config_path": str(target_config_path),
            "managed_hook_config_path": str(hook_config_path),
            "managed_hooks_path": str(hooks_path),
            "backup_path": str(backup_path),
        }

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        payload = super().diagnostics(context)
        hook_state = codex_native_hook_state(context)
        warning_items = payload.get("warnings")
        warnings = (
            [str(item) for item in warning_items if isinstance(item, str)] if isinstance(warning_items, list) else []
        )
        if bool(hook_state["config_present"]) and not bool(hook_state["codex_hooks_enabled"]):
            warnings.append(
                "Codex config was found, but native hooks are disabled. Run `hol-guard install codex` or "
                "`hol-guard update` to repair protection."
            )
        if bool(hook_state["config_present"]) and not bool(hook_state["managed_hook_installed"]):
            warnings.append(
                "Codex config was found, but Guard's managed Codex hooks are missing. Run "
                "`hol-guard install codex` or `hol-guard update` to repair protection."
            )
        payload["warnings"] = warnings
        if payload.get("setup_status") == "active" and _warnings_include_setup_failure(warnings):
            payload["setup_status"] = "broken"
        payload["native_hook_state"] = hook_state
        return payload

    @staticmethod
    def _target_config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _hook_config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _backup_path(context: HarnessContext) -> Path:
        target_path = str(CodexHarnessAdapter._target_config_path(context).resolve())
        digest = hashlib.sha256(target_path.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "codex" / f"{digest}.backup.toml"

    def _proxy_server_entry(self, context: HarnessContext, server: ManagedMcpServer) -> dict[str, object]:
        args = proxy_cli_args(
            proxy_command="codex-mcp-proxy",
            guard_home=str(context.guard_home),
            server=server,
            home=str(context.home_dir) if context.home_dir.resolve() != Path.home().resolve() else None,
            workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
        )
        entry: dict[str, object] = {
            "command": sys.executable,
            "args": args,
        }
        env = merge_guard_launcher_env(proxy_process_env(getattr(server, "env", {})))
        if env:
            entry["env"] = env
        return entry

    @staticmethod
    def _should_skip_workspace_override(
        *,
        context: HarnessContext,
        server: ManagedMcpServer,
        existing_workspace_server_names: set[str],
    ) -> bool:
        if context.workspace_dir is None:
            return False
        if server.source_scope == "project":
            return False
        return server.name in existing_workspace_server_names

    def _load_hook_payloads(self, context: HarnessContext) -> dict[Path, dict[str, object]]:
        return {
            hooks_path: _strict_json_object(hooks_path, label="Codex hooks file")
            for hooks_path in self._all_hook_paths(context)
        }

    def _migrate_alternate_hook_configs(
        self,
        context: HarnessContext,
        *,
        payloads: dict[Path, dict[str, object]],
        config_payloads: dict[Path, dict[str, object]],
        skip_config_path: Path,
        owned_bindings: Sequence[Mapping[str, object]] = (),
    ) -> None:
        for config_path, hooks_path in self._config_hook_pairs(context):
            if config_path == skip_config_path:
                continue
            hooks_payload = payloads.get(hooks_path, {})
            if not hooks_payload:
                continue
            config_payload = config_payloads[config_path]
            if (
                _migrate_hooks_json_into_config(
                    config_payload,
                    hooks_payload,
                    context=context,
                    owned_bindings=owned_bindings,
                )
                and config_payload
            ):
                atomic_write_text(config_path, dump_toml(config_payload), mode=0o600)

    def _remove_managed_hooks_from_alternate_configs(
        self,
        context: HarnessContext,
        *,
        skip_config_path: Path,
    ) -> None:
        # No authenticated manifest is issued for alternate Codex configs.
        # Only an exact current bridge can be re-adopted during explicit repair;
        # basename, status-message, and path-suffix matches remain untouched.
        for config_path, _hooks_path in self._config_hook_pairs(context):
            if config_path == skip_config_path or not config_path.is_file():
                continue
            config_payload = read_toml_payload(config_path)
            hooks = config_payload.get("hooks")
            changed = False
            if isinstance(hooks, dict):
                legacy_bindings = _current_install_legacy_bindings(context, hooks)
                cleaned_hooks, managed_removed = _remove_manifest_bound_hook_events(hooks, legacy_bindings)
                if managed_removed:
                    changed = True
                    if cleaned_hooks:
                        config_payload["hooks"] = cleaned_hooks
                    else:
                        config_payload.pop("hooks", None)
            if not _hooks_have_registered_entries(config_payload.get("hooks")):
                features = config_payload.get("features")
                if isinstance(features, dict):
                    for feature_name in ("codex_hooks", "hooks"):
                        if feature_name in features:
                            features.pop(feature_name, None)
                            changed = True
                    if features:
                        config_payload["features"] = features
                    else:
                        config_payload.pop("features", None)
            if changed:
                atomic_write_text(config_path, dump_toml(config_payload), mode=0o600)

    def _remove_managed_mcp_servers_from_alternate_configs(
        self,
        context: HarnessContext,
        *,
        managed_servers: tuple[ManagedMcpServer, ...],
        skip_config_path: Path,
    ) -> None:
        managed_names_by_path: dict[Path, set[str]] = {}
        for server in managed_servers:
            managed_names_by_path.setdefault(Path(server.config_path), set()).add(server.name)
        for config_path, _hooks_path in self._config_hook_pairs(context):
            if config_path == skip_config_path or not config_path.is_file():
                continue
            config_payload = read_toml_payload(config_path)
            mcp_servers = config_payload.get("mcp_servers")
            if not isinstance(mcp_servers, dict):
                continue
            names = managed_names_by_path.get(config_path, set())
            changed = False
            cleaned_servers: dict[str, object] = {}
            for name, server_config in mcp_servers.items():
                if (
                    isinstance(name, str)
                    and name in names
                    and isinstance(server_config, dict)
                    and not is_guard_proxy_command(
                        server_config.get("command") if isinstance(server_config.get("command"), str) else None,
                        tuple(str(value) for value in server_config.get("args", []) if isinstance(value, str)),
                    )
                ):
                    changed = True
                    continue
                cleaned_servers[name] = server_config
            if not changed:
                continue
            if cleaned_servers:
                config_payload["mcp_servers"] = cleaned_servers
            else:
                config_payload.pop("mcp_servers", None)
            write_toml_payload(config_path, config_payload)

    def _remove_json_hook_files(
        self,
        context: HarnessContext,
        *,
        payloads: dict[Path, dict[str, object]],
    ) -> Path:
        target_hooks_path = self._hooks_path(context)
        for hooks_path in self._all_hook_paths(context):
            if hooks_path in payloads and hooks_path.is_file():
                hooks_path.unlink()
        return target_hooks_path

    def _install_hooks(self, context: HarnessContext, *, payloads: dict[Path, dict[str, object]] | None = None) -> Path:
        target_hooks_path = self._hooks_path(context)
        hook_payloads = payloads or self._load_hook_payloads(context)
        for hooks_path in self._all_hook_paths(context):
            original_payload = deepcopy(hook_payloads.get(hooks_path, {}))
            payload = deepcopy(original_payload)
            hooks = payload.get("hooks")
            if not isinstance(hooks, dict):
                hooks = {}
            legacy_bindings = _current_install_legacy_bindings(context, hooks)
            cleaned_hooks, managed_removed = _remove_manifest_bound_hook_events(hooks, legacy_bindings)
            if not managed_removed:
                payload = deepcopy(original_payload)
            elif cleaned_hooks:
                payload["hooks"] = cleaned_hooks
            else:
                payload.pop("hooks", None)
            self._write_hooks_payload(hooks_path, payload, original_payload=original_payload)
        return target_hooks_path

    @staticmethod
    def _install_config_hooks(
        payload: dict[str, object],
        context: HarnessContext,
        *,
        owned_bindings: Sequence[Mapping[str, object]] = (),
    ) -> None:
        hooks = payload.get("hooks")
        if not isinstance(hooks, dict):
            hooks = {}
        cleaned_hooks, _ = _remove_manifest_bound_hook_events(hooks, owned_bindings)
        legacy_bindings = _current_install_legacy_bindings(context, cleaned_hooks)
        cleaned_hooks, _ = _remove_manifest_bound_hook_events(cleaned_hooks, legacy_bindings)
        for event_name, managed_group in _managed_hook_groups(context).items():
            existing_groups = cleaned_hooks.get(event_name)
            cleaned_hooks[event_name] = [
                *(existing_groups if isinstance(existing_groups, list) else []),
                managed_group,
            ]
        payload["hooks"] = cleaned_hooks

    @staticmethod
    def _write_authenticated_hook_config(
        context: HarnessContext,
        *,
        config_path: Path,
        payload: dict[str, object],
        previous_manifest: dict[str, object] | None,
    ) -> dict[str, object]:
        """Commit manifest first, then config, rolling both back on any failure.

        During the short manifest-first window an old config fails closed against
        the new manifest.  Codex never observes a newly registered hook before
        its complete authenticated identity has been durably committed.
        """

        if config_path.exists() or config_path.is_symlink():
            validate_regular_file(config_path, role="config_target", executable_required=False)
            original_config = config_path.read_text(encoding="utf-8")
        else:
            original_config = None
        manifest_path = hook_manifest_path(context.guard_home, config_path)
        secret_path = hook_secret_path(context.guard_home)
        original_manifest = snapshot_regular_file(manifest_path)
        original_secret = snapshot_regular_file(secret_path)
        try:
            manifest = _build_authenticated_hook_manifest(context)
            _assert_package_reauthentication_is_safe(previous_manifest, manifest)
            write_hook_manifest(context.guard_home, config_path, manifest)
            atomic_write_text(config_path, dump_toml(payload), mode=0o600)
            state = codex_native_hook_state(context)
            if not bool(state.get("protection_active")):
                reason = str(state.get("integrity_reason") or "codex_hook_integrity_readback_failed")
                raise RuntimeError(
                    f"{_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON}: Codex hook authentication readback failed: {reason}"
                )
            return state
        except BaseException:
            rollback_error: BaseException | None = None
            try:
                if original_config is None:
                    if config_path.is_symlink():
                        raise RuntimeError("Guard refused to unlink a symlink while rolling back Codex config.")
                    config_path.unlink(missing_ok=True)
                else:
                    atomic_write_text(config_path, original_config, mode=0o600)
                restore_private_file(manifest_path, original_manifest)
                restore_private_file(secret_path, original_secret)
            except BaseException as exc:  # pragma: no cover - catastrophic local I/O failure
                rollback_error = exc
            if rollback_error is not None:
                raise RuntimeError(
                    "Codex hook transaction failed and rollback could not be completed."
                ) from rollback_error
            raise

    @staticmethod
    def _uninstall_shell_guard(context: HarnessContext) -> None:
        guard_root = context.guard_home / "managed" / "codex"
        for guard_path in (
            guard_root / "codex-zshenv-guard.zsh",
            guard_root / "codex-bashenv-guard.bash",
            guard_root / "codex-fish-guard.fish",
        ):
            if guard_path.is_file():
                guard_path.unlink()

        for startup_path in (
            context.home_dir / ".zshenv",
            context.home_dir / ".bashrc",
            context.home_dir / ".bash_profile",
            context.home_dir / ".bash_login",
            context.home_dir / ".profile",
            context.home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish",
        ):
            CodexHarnessAdapter._remove_shell_guard_block(startup_path)

    @staticmethod
    def _remove_shell_guard_block(path: Path) -> None:
        if not path.is_file():
            return
        original = path.read_bytes()
        cleaned = _remove_managed_shell_guard_blocks(original)
        if cleaned == original:
            return
        if cleaned:
            path.write_bytes(cleaned)
        else:
            path.unlink()

    def _remove_hooks(self, context: HarnessContext, *, payloads: dict[Path, dict[str, object]] | None = None) -> Path:
        target_hooks_path = self._hooks_path(context)
        # JSON hook files created after install are foreign to the authenticated
        # TOML registration and must be preserved byte-for-byte on uninstall.
        del payloads
        return target_hooks_path

    @staticmethod
    def _write_hooks_payload(
        hooks_path: Path,
        payload: dict[str, object],
        *,
        original_payload: dict[str, object] | None = None,
    ) -> None:
        if original_payload is not None and payload == original_payload:
            return
        if payload:
            hooks_path.parent.mkdir(parents=True, exist_ok=True)
            hooks_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        elif hooks_path.exists():
            hooks_path.unlink()
