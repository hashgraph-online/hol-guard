"""Thin client for the native effective Guard configuration loader.

Rust reads the Guard home and workspace files, composes the managed policy this
client resolved, and coerces every value. This module only spawns the loader,
fails closed when it is unavailable, and keeps a stat-validated memo so an
unchanged configuration is not reloaded.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from .config_file_io import ConfigFileTrustError

GUARD_CONFIG_LOAD_COMMAND = "guard-config-load"
GUARD_CONFIG_LOAD_FEATURE = "native-guard-config-load-v1"
GUARD_CONFIG_LOAD_SCHEMA = "guard-config-load.v1"
GUARD_CONFIG_LOAD_TIMEOUT_SECONDS = 10.0
# Home, two workspace files and a managed policy are each bounded at 1 MiB, so
# the composed response may exceed the default one-shot output allowance.
GUARD_CONFIG_LOAD_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024
WORKSPACE_CONFIG_FILENAMES = (".ai-plugin-scanner-guard.toml", ".hol-guard.toml")
# A file modified this recently may still change within one timestamp tick, so
# its result is neither stored nor reused.
_RACY_WINDOW_NS = 2_000_000_000
_MEMO_LIMIT = 64
_MEMO: OrderedDict[str, dict[str, Any]] = OrderedDict()
_MEMO_LOCK = threading.Lock()


class _Flight:
    """One in-progress native load that concurrent identical loads wait on."""

    __slots__ = ("config", "done")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.config: dict[str, Any] | None = None


# Concurrent first loads of one exact configuration (a burst of hook requests
# after a restart) share a single native process; unrelated keys never wait.
_FLIGHTS: dict[str, _Flight] = {}

FileSignature = tuple[int, ...] | None


def _file_signature(path: Path) -> FileSignature:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return (-1,)
    return (
        metadata.st_mode,
        metadata.st_ino,
        metadata.st_dev,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_signature(path: Path) -> FileSignature:
    """Identity and permissions of a config directory (not its changing mtime)."""

    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return (-1,)
    return (metadata.st_mode, metadata.st_ino, metadata.st_dev, metadata.st_uid)


def _signatures(guard_home: Path, workspace: Path | None) -> tuple[FileSignature, ...] | None:
    """Return the config file signatures, or None when a file is too fresh to trust."""

    paths = [guard_home / "config.toml"]
    if workspace is not None:
        paths.extend(workspace / name for name in WORKSPACE_CONFIG_FILENAMES)
    now_ns = time.time_ns()
    signatures: list[FileSignature] = []
    for path in paths:
        signature = _file_signature(path)
        if signature is not None and (
            len(signature) == 1 or now_ns - max(signature[4], signature[5]) < _RACY_WINDOW_NS
        ):
            return None
        signatures.append(signature)
    signatures.append(_directory_signature(guard_home))
    if workspace is not None:
        signatures.append(_directory_signature(workspace))
    return tuple(signatures)


def _request_text(
    guard_home: Path,
    workspace: Path | None,
    *,
    require_canonical_workspace: bool,
    managed: Mapping[str, object] | None,
) -> str:
    request: dict[str, object] = {
        "schema": GUARD_CONFIG_LOAD_SCHEMA,
        "guard_home": str(guard_home),
        "workspace": str(workspace) if workspace is not None else None,
        "require_canonical_workspace": require_canonical_workspace,
        "managed": dict(managed) if managed is not None else None,
    }
    return json.dumps(request, sort_keys=True, separators=(",", ":"))


def _runtime_identity(deadline_monotonic: float) -> tuple[Path, str]:
    """Return the capable runtime's path and digest, or fail closed."""

    from .native_runtime import native_runtime_status

    status = native_runtime_status(deadline_monotonic=deadline_monotonic)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or GUARD_CONFIG_LOAD_FEATURE not in status.capabilities.features
    ):
        raise ConfigFileTrustError("native_guard_config_unavailable")
    return status.identity.path, status.identity.sha256


def _spawn(request_text: str, path: Path, deadline_monotonic: float) -> dict[str, Any]:
    from .native_runtime import _run_native_process

    remaining = deadline_monotonic - time.monotonic()
    if remaining <= 0:
        raise ConfigFileTrustError("native_guard_config_unavailable")
    output = _run_native_process(
        path,
        (GUARD_CONFIG_LOAD_COMMAND, "--stdin"),
        input_text=request_text,
        timeout_seconds=remaining,
        output_limit=GUARD_CONFIG_LOAD_OUTPUT_LIMIT_BYTES,
    )
    if output is None:
        raise ConfigFileTrustError("native_guard_config_unavailable")
    try:
        response = json.loads(output)
    except ValueError as error:
        raise ConfigFileTrustError("native_guard_config_invalid") from error
    if not isinstance(response, dict):
        raise ConfigFileTrustError("native_guard_config_invalid")
    if response.get("ok") is not True:
        reason = response.get("error")
        raise ConfigFileTrustError(reason if isinstance(reason, str) and reason else "native_guard_config_invalid")
    config = response.get("config")
    if not isinstance(config, dict):
        raise ConfigFileTrustError("native_guard_config_invalid")
    return cast("dict[str, Any]", config)


def load_native_guard_config(
    guard_home: Path,
    workspace: Path | None,
    *,
    require_canonical_workspace: bool,
    managed: Mapping[str, object] | None,
) -> dict[str, Any]:
    """Load the coerced configuration fields from the native runtime."""

    request_text = _request_text(
        guard_home,
        workspace,
        require_canonical_workspace=require_canonical_workspace,
        managed=managed,
    )
    # One deadline covers the capability probe and the load process.
    deadline = time.monotonic() + GUARD_CONFIG_LOAD_TIMEOUT_SECONDS
    # A memo hit still requires the native runtime to be present, compatible
    # and capable, and is bound to its exact identity.
    path, runtime_sha = _runtime_identity(deadline)
    before = _signatures(guard_home, workspace)
    if before is None:
        return _spawn(request_text, path, deadline)
    key = f"{runtime_sha}\0{path}\0{request_text}\0{before!r}"
    cached = _memo_get(key)
    if cached is not None:
        return cached
    with _MEMO_LOCK:
        flight = _FLIGHTS.get(key)
        leader = flight is None
        if flight is None:
            flight = _Flight()
            _FLIGHTS[key] = flight
    if not leader:
        # Bounded by this caller's own deadline; on a miss or a failed leader
        # the waiter spawns for itself exactly as it would have alone.
        flight.done.wait(max(0.0, deadline - time.monotonic()))
        shared = flight.config
        if shared is not None:
            return cast("dict[str, Any]", json.loads(json.dumps(shared)))
        cached = _memo_get(key)
        if cached is not None:
            return cached
        return _spawn(request_text, path, deadline)
    try:
        config = _spawn(request_text, path, deadline)
        if _signatures(guard_home, workspace) == before:
            flight.config = cast("dict[str, Any]", json.loads(json.dumps(config)))
            with _MEMO_LOCK:
                _MEMO[key] = json.loads(json.dumps(config))
                while len(_MEMO) > _MEMO_LIMIT:
                    _MEMO.popitem(last=False)
        return config
    finally:
        with _MEMO_LOCK:
            _FLIGHTS.pop(key, None)
        flight.done.set()


def _memo_get(key: str) -> dict[str, Any] | None:
    with _MEMO_LOCK:
        cached = _MEMO.get(key)
        if cached is None:
            return None
        _MEMO.move_to_end(key)
        return cast("dict[str, Any]", json.loads(json.dumps(cached)))


def clear_native_guard_config_memo() -> None:
    with _MEMO_LOCK:
        _MEMO.clear()
