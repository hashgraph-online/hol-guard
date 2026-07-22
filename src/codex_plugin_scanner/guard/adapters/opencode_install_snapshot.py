"""Canonical OpenCode install snapshots and transactional JSON writes."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ...ecosystems.opencode import _load_json_or_jsonc
from ..models import GuardArtifact, HarnessDetection
from .base import HarnessContext
from .mcp_servers import (
    GUARD_MCP_COMPANION_PREFIX,
    ManagedMcpServer,
    is_guard_proxy_command,
    stable_mcp_server_identifier,
)
from .opencode_artifacts import (
    _command_parts,
    append_config_artifacts,
    append_directory_artifacts,
    append_found_path,
    config_paths,
)


class OpenCodeInstallSnapshotError(RuntimeError):
    """Raised before writes when an applicable OpenCode config is invalid."""


@dataclass(frozen=True, slots=True)
class NormalizedOpenCodeConfig:
    path: Path
    scope: str
    payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class OpenCodeInstallSnapshot:
    configs: tuple[NormalizedOpenCodeConfig, ...]
    detection: HarnessDetection

    def payload_for(self, path: Path) -> dict[str, object]:
        for config in self.configs:
            if config.path == path:
                return _copy_object(config.payload)
        return {}

    def workspace_server_names(self) -> set[str]:
        names: set[str] = set()
        for config in self.configs:
            if config.scope != "project":
                continue
            mcp = config.payload.get("mcp")
            if not isinstance(mcp, dict):
                continue
            names.update(name for name, entry in mcp.items() if isinstance(name, str) and isinstance(entry, dict))
        return names


@dataclass(frozen=True, slots=True)
class _ProxyBinding:
    native_name: str
    source_scope: str
    config_path: str
    transport: str
    command: str
    args: tuple[str, ...]
    env_keys: tuple[str, ...]
    enabled: bool


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    payload: bytes | None


def load_opencode_install_snapshot(
    context: HarnessContext,
    *,
    command_available: bool,
) -> OpenCodeInstallSnapshot:
    """Load and normalize every config before deriving managed servers."""

    configs: list[NormalizedOpenCodeConfig] = []
    artifacts: list[GuardArtifact] = []
    found_paths: list[str] = []
    seen_artifact_ids: set[str] = set()
    for config_path in config_paths(context):
        if not config_path.exists():
            continue
        payload, parse_error, _parse_reason = _load_json_or_jsonc(config_path)
        if parse_error or not isinstance(payload, dict):
            raise OpenCodeInstallSnapshotError(
                f"Refusing to install with an invalid OpenCode config at {config_path}. Fix its syntax and retry."
            )
        scope = _scope_for(context, config_path)
        normalized = _normalized_config_payload(
            payload,
            context=context,
            scope=scope,
            config_path=config_path,
        )
        configs.append(NormalizedOpenCodeConfig(path=config_path, scope=scope, payload=normalized))
        append_found_path(found_paths, config_path)
        append_config_artifacts(
            artifacts=artifacts,
            seen_artifact_ids=seen_artifact_ids,
            scope=scope,
            config_path=config_path,
            payload=normalized,
            skip_verified_mcp_companions=False,
        )
    append_directory_artifacts(
        context=context,
        artifacts=artifacts,
        found_paths=found_paths,
        seen_artifact_ids=seen_artifact_ids,
    )
    detection = HarnessDetection(
        harness="opencode",
        installed=bool(found_paths) or command_available,
        command_available=command_available,
        config_paths=tuple(found_paths),
        artifacts=tuple(artifacts),
        warnings=(),
    )
    return OpenCodeInstallSnapshot(configs=tuple(configs), detection=detection)


def write_json_transaction(writes: tuple[tuple[Path, dict[str, object]], ...]) -> None:
    """Atomically write and semantically read back a related JSON file set."""

    snapshots = {path: _snapshot_regular_file(path) for path, _payload in writes}
    try:
        for path, payload in writes:
            _atomic_write_bytes(path, _json_bytes(payload))
        for path, expected in writes:
            try:
                actual: object = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise OpenCodeInstallSnapshotError(f"OpenCode install readback failed for {path}.") from error
            if actual != expected:
                raise OpenCodeInstallSnapshotError(
                    f"OpenCode install readback did not match the derived payload at {path}."
                )
    except BaseException:
        rollback_error: BaseException | None = None
        for path, snapshot in reversed(tuple(snapshots.items())):
            try:
                _restore_file(path, snapshot)
            except BaseException as error:  # pragma: no cover - catastrophic local I/O failure
                rollback_error = error
        if rollback_error is not None:
            raise OpenCodeInstallSnapshotError(
                "OpenCode install failed and its config transaction could not be rolled back."
            ) from rollback_error
        raise


def _normalized_config_payload(
    payload: dict[str, object],
    *,
    context: HarnessContext,
    scope: str,
    config_path: Path,
) -> dict[str, object]:
    normalized = _copy_object(payload)
    mcp = payload.get("mcp")
    if not isinstance(mcp, dict):
        return normalized
    entries = {
        name: _copy_object(entry) for name, entry in mcp.items() if isinstance(name, str) and isinstance(entry, dict)
    }
    trusted_companions: dict[str, _ProxyBinding] = {}
    for name, entry in entries.items():
        binding = _verified_proxy_binding(
            name,
            entry,
            context=context,
            scope=scope,
            expected_config_path=config_path,
        )
        if binding is None:
            continue
        native_entry = entries.get(binding.native_name)
        if native_entry is not None and not _binding_matches_native(binding, native_entry):
            continue
        trusted_companions[name] = binding

    reconstructed: dict[str, object] = {}
    for name, entry in entries.items():
        binding = trusted_companions.get(name)
        if binding is not None:
            native_entry = entries.get(binding.native_name)
            reconstructed[binding.native_name] = _native_entry_from_binding(binding, native_entry, entry)
            continue
        if name in {binding.native_name for binding in trusted_companions.values()}:
            if name not in reconstructed:
                reconstructed[name] = _copy_object(entry)
            continue
        restored = _restore_legacy_proxy(entry)
        reconstructed[name] = restored if restored is not None else _copy_object(entry)
    normalized["mcp"] = reconstructed
    return normalized


def _verified_proxy_binding(
    name: str,
    entry: dict[str, object],
    *,
    context: HarnessContext,
    scope: str,
    expected_config_path: Path,
) -> _ProxyBinding | None:
    if not name.startswith(GUARD_MCP_COMPANION_PREFIX):
        return None
    native_name = name.removeprefix(GUARD_MCP_COMPANION_PREFIX)
    if not native_name or native_name.startswith(GUARD_MCP_COMPANION_PREFIX):
        return None
    proxy_command, proxy_args = _command_parts(entry)
    if not is_guard_proxy_command(proxy_command, proxy_args) or "opencode-mcp-proxy" not in proxy_args:
        return None
    options = _proxy_options(proxy_args)
    required = {
        "--guard-home",
        "--server-name",
        "--server-id",
        "--source-scope",
        "--config-path",
        "--transport",
        "--command",
    }
    if not required.issubset(options) or any(len(options[key]) != 1 for key in required):
        return None
    if options["--server-name"][0] != native_name or options["--source-scope"][0] != scope:
        return None
    try:
        guard_home_matches = Path(options["--guard-home"][0]).resolve() == context.guard_home.resolve()
    except OSError:
        return None
    if not guard_home_matches:
        return None
    transport = options["--transport"][0]
    if transport not in {"local", "stdio"}:
        return None
    config_path = options["--config-path"][0]
    try:
        config_path_matches = Path(config_path).resolve() == expected_config_path.resolve()
    except OSError:
        return None
    if not Path(config_path).is_absolute() or not config_path_matches:
        return None
    command = options["--command"][0]
    args = tuple(options.get("--arg", ()))
    env_keys = tuple(options.get("--server-env-key", ()))
    enabled_value = entry.get("enabled", True)
    enabled = enabled_value if isinstance(enabled_value, bool) else True
    binding = _ProxyBinding(
        native_name=native_name,
        source_scope=scope,
        config_path=config_path,
        transport=transport,
        command=command,
        args=args,
        env_keys=env_keys,
        enabled=enabled,
    )
    environment = _selected_environment(entry, env_keys)
    server = ManagedMcpServer(
        harness="opencode",
        name=native_name,
        source_scope=scope,
        config_path=config_path,
        command=command,
        args=args,
        transport=transport,
        env=environment,
        enabled=enabled,
    )
    return binding if options["--server-id"][0] == stable_mcp_server_identifier(server) else None


def _proxy_options(args: tuple[str, ...]) -> dict[str, list[str]]:
    options: dict[str, list[str]] = {}
    index = 0
    while index < len(args):
        token = args[index]
        if token.startswith("--arg="):
            options.setdefault("--arg", []).append(token.split("=", 1)[1])
        elif token.startswith("--server-env-key="):
            options.setdefault("--server-env-key", []).append(token.split("=", 1)[1])
        elif token.startswith("--") and index + 1 < len(args):
            options.setdefault(token, []).append(args[index + 1])
            index += 1
        index += 1
    return options


def _binding_matches_native(binding: _ProxyBinding, entry: dict[str, object]) -> bool:
    restored = _restore_legacy_proxy(entry) or entry
    command, args = _command_parts(restored)
    return command == binding.command and args == binding.args


def _native_entry_from_binding(
    binding: _ProxyBinding,
    native_entry: dict[str, object] | None,
    companion_entry: dict[str, object],
) -> dict[str, object]:
    restored: dict[str, object]
    if native_entry is not None:
        restored = _restore_legacy_proxy(native_entry) or _copy_object(native_entry)
    else:
        restored = {
            "type": binding.transport,
            "command": [binding.command, *binding.args],
        }
        environment = _selected_environment(companion_entry, binding.env_keys)
        if environment:
            restored["environment"] = environment
    restored["enabled"] = binding.enabled
    return restored


def _restore_legacy_proxy(entry: dict[str, object]) -> dict[str, object] | None:
    command, args = _command_parts(entry)
    if not is_guard_proxy_command(command, args) or "opencode-mcp-proxy" not in args:
        return None
    options = _proxy_options(args)
    commands = options.get("--command", ())
    if len(commands) != 1:
        return None
    restored: dict[str, object] = {
        "type": entry.get("type", "local"),
        "command": [commands[0], *options.get("--arg", ())],
        "enabled": entry.get("enabled", True),
    }
    environment = entry.get("environment")
    if isinstance(environment, dict):
        restored["environment"] = _copy_object(environment)
    return restored


def _selected_environment(entry: dict[str, object], keys: tuple[str, ...]) -> dict[str, str]:
    raw = entry.get("environment")
    if not isinstance(raw, dict):
        return {}
    return {key: value for key in keys if isinstance(key, str) and isinstance((value := raw.get(key)), str)}


def _scope_for(context: HarnessContext, path: Path) -> str:
    if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
        return "project"
    return "global"


def _copy_object(value: Mapping[str, object]) -> dict[str, object]:
    return {key: _copy_value(item) for key, item in value.items()}


def _copy_value(value: object) -> object:
    if isinstance(value, dict):
        return _copy_object(value)
    if isinstance(value, list):
        return [_copy_value(item) for item in value]
    return value


def _json_bytes(payload: dict[str, object]) -> bytes:
    return (json.dumps(payload, indent=2) + "\n").encode("utf-8")


def _snapshot_regular_file(path: Path) -> _FileSnapshot:
    if not path.exists() and not path.is_symlink():
        return _FileSnapshot(payload=None)
    if path.is_symlink() or not path.is_file():
        raise OpenCodeInstallSnapshotError(f"Refusing to replace a non-regular OpenCode managed file at {path}.")
    return _FileSnapshot(payload=path.read_bytes())


def _restore_file(path: Path, snapshot: _FileSnapshot) -> None:
    if snapshot.payload is None:
        if path.is_symlink():
            raise OpenCodeInstallSnapshotError(f"Refusing to unlink a symlink while rolling back {path}.")
        path.unlink(missing_ok=True)
        return
    _atomic_write_bytes(path, snapshot.payload)


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise OpenCodeInstallSnapshotError(f"Refusing to replace a non-regular OpenCode managed file at {path}.")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


__all__ = [
    "OpenCodeInstallSnapshot",
    "OpenCodeInstallSnapshotError",
    "load_opencode_install_snapshot",
    "write_json_transaction",
]
