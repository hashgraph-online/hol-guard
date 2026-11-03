"""Canonical OpenCode install snapshots and transactional JSON writes."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .....ecosystems.opencode import _load_json_or_jsonc, _load_json_or_jsonc_text
from ....models import HarnessDetection
from ...base import HarnessContext
from ...opencode_artifacts import config_paths, native_artifacts


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
class _FileSnapshot:
    payload: bytes | None


def load_opencode_install_snapshot(
    context: HarnessContext,
    *,
    command_available: bool,
    config_contents: dict[Path, bytes | None] | None = None,
) -> OpenCodeInstallSnapshot:
    """Load and normalize every config before deriving managed servers."""

    configs: list[NormalizedOpenCodeConfig] = []
    for config_path in config_paths(context):
        if config_contents is None:
            if not config_path.exists():
                continue
            payload, parse_error, _parse_reason = _load_json_or_jsonc(config_path)
        else:
            raw = config_contents[config_path]
            if raw is None:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as error:
                raise OpenCodeInstallSnapshotError(f"Invalid OpenCode config encoding at {config_path}.") from error
            payload, parse_error, _parse_reason = _load_json_or_jsonc_text(config_path, text)
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
    artifacts, found_paths = native_artifacts(
        context,
        [(config.path, config.scope, config.payload) for config in configs],
        skip_verified_mcp_companions=False,
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
    """Return the config with Guard's MCP wrappers taken off.

    The native ``opencode_config_normalize`` kind folds each verified
    ``hol-guard::`` companion back into the server it wraps and restores any
    in-place proxy wrapper; the install derives Guard's entries again from it.
    """

    from ....native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        cwd = os.getcwd()
    except OSError:
        cwd = ""
    request = {
        "config": json.dumps(payload),
        "scope": scope,
        "config_path": str(config_path),
        "guard_home": str(context.guard_home),
        "cwd": cwd,
    }
    try:
        answer = native_runner_authority("opencode_config_normalize", request)
        normalized: object = json.loads(answer["config"]) if answer.keys() == {"config"} else None
    except (NativeRunnerAuthorityError, TypeError, ValueError) as error:
        raise OpenCodeInstallSnapshotError(f"Could not read the OpenCode config at {config_path}.") from error
    if not isinstance(normalized, dict):
        raise OpenCodeInstallSnapshotError(f"Could not read the OpenCode config at {config_path}.")
    return normalized


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
