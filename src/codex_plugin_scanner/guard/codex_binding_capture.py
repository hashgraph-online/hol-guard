"""Opt-in, private evidence for binding Codex hook input to a Rust receipt.

This module is deliberately independent from normal activity evidence.  It is
enabled only by a short-lived marker under the managed Guard home and never
authenticates hook ingress or participates in a hook decision.
"""

from __future__ import annotations

import errno
import json
import os
import re
import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from .codex_binding_capture_join import join_binding_records

try:  # pragma: no cover - Windows diagnostic capture fails closed.
    import fcntl
except ImportError:  # pragma: no cover - Windows has no flock.
    fcntl = None  # type: ignore[assignment]

from .codex_binding_capture_bounds import bounded_utf8_bytes, validate_json_value
from .codex_binding_capture_crypto import (
    CAPTURE_SCHEMA,
    FINGERPRINT_SCHEME,
    MAX_CANONICAL_PAYLOAD_BYTES,
    MAX_CAPTURE_BYTES,
    MAX_CAPTURE_RECORDS,
    MAX_MARKER_BYTES,
    CaptureSession,
    canonical_json_bytes,
    parse_marker,
    payload_hmac,
    row_hmac,
    seal_receipt,
)
from .codex_binding_capture_crypto import receipt_projection as _receipt_projection
from .codex_binding_capture_fs import _private_directory, _private_regular, initialize_private_capture_marker
from .codex_hook_manifest import MANAGED_CODEX_HOOK_EVENTS
from .daemon.hook_request_parsing import runtime_hook_event_name
from .evaluation_json import reject_duplicate_keys

CAPTURE_DIRECTORY_NAME: Final = "diagnostics"
CAPTURE_MARKER_NAME: Final = "codex-binding-capture.v2.json"
CAPTURE_OUTPUT_PREFIX: Final = "codex-binding-capture."
CAPTURE_OUTPUT_SUFFIX: Final = ".jsonl"
MAX_TOOL_USE_ID_BYTES: Final = 256
BINDABLE_CODEX_HOOK_EVENTS: Final = frozenset({"PreToolUse", "PostToolUse"})
_PRIVATE_FILE_MODE: Final = 0o600
_ASCII_OPAQUE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_MISSING = object()
_INVALID = object()


def _json_object(raw: bytes) -> dict[str, object] | None:
    if type(raw) is not bytes or len(raw) > MAX_CANONICAL_PAYLOAD_BYTES:
        return None
    try:
        decoded = raw.decode("utf-8")
        value = cast(object, json.loads(decoded, object_pairs_hook=reject_duplicate_keys))
    except (UnicodeError, ValueError, RecursionError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    typed_value = cast(dict[str, object], value)
    return typed_value if validate_json_value(typed_value) else None


def _canonical_json(value: object) -> bytes | None:
    return canonical_json_bytes(value)


def _open_guard_home_directory(guard_home: Path) -> int | None:
    supports_dir_fd = cast(set[object], getattr(os, "supports_dir_fd", cast(set[object], set())))
    if (
        fcntl is None
        or not guard_home.is_absolute()
        or ".." in guard_home.parts
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in supports_dir_fd
    ):
        return None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(guard_home.anchor, flags)
        for component in guard_home.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        if not _private_directory(descriptor):
            os.close(descriptor)
            return None
        return descriptor
    except (OSError, TypeError):
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        return None


def _open_diagnostics_directory(guard_home: Path) -> int | None:
    guard_descriptor = _open_guard_home_directory(guard_home)
    if guard_descriptor is None:
        return None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(CAPTURE_DIRECTORY_NAME, flags, dir_fd=guard_descriptor)
    except (OSError, TypeError):
        return None
    finally:
        with suppress(OSError):
            os.close(guard_descriptor)
    if not _private_directory(descriptor):
        with suppress(OSError):
            os.close(descriptor)
        return None
    return descriptor


def _read_descriptor(descriptor: int, *, maximum: int) -> bytes | None:
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size < 0 or metadata.st_size > maximum:
            return None
        _ = os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except OSError:
        return None


def _load_capture_config(guard_home: Path) -> CaptureSession | None:
    directory = _open_diagnostics_directory(guard_home)
    if directory is None:
        return None
    marker: int | None = None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            marker = os.open(CAPTURE_MARKER_NAME, flags, dir_fd=directory)
        except (OSError, TypeError):
            return None
        if not _private_regular(marker):
            return None
        raw_marker = _read_descriptor(marker, maximum=MAX_MARKER_BYTES)
        if raw_marker is None:
            return None
        payload = _json_object(raw_marker)
        if payload is None:
            return None
        return parse_marker(payload)
    except (OSError, TypeError, ValueError, UnicodeError):
        return None
    finally:
        if marker is not None:
            with suppress(OSError):
                os.close(marker)
        with suppress(OSError):
            os.close(directory)


def read_capture_session(guard_home: Path) -> CaptureSession | None:
    """Read the private v2 marker for an evaluator-supplied capture session."""

    return _load_capture_config(guard_home)


def initialize_capture_marker(
    guard_home: Path,
    *,
    run_id: str,
    expires_at: int,
    max_records: int = MAX_CAPTURE_RECORDS,
    max_bytes: int = MAX_CAPTURE_BYTES,
) -> CaptureSession | None:
    """Explicitly create one private v2 marker and its per-run key.

    Capture is never enabled implicitly.  The caller must provide the marker
    destination and retain the returned session only for local evaluation.
    """

    return initialize_private_capture_marker(
        guard_home,
        directory_name=CAPTURE_DIRECTORY_NAME,
        marker_name=CAPTURE_MARKER_NAME,
        run_id=run_id,
        expires_at=expires_at,
        max_records=max_records,
        max_bytes=max_bytes,
    )


def _bounded_text(value: object, *, maximum: int) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value)
    ):
        return None
    return value


def _tool_use_id(payload: Mapping[str, object]) -> str | object:
    value = payload.get("tool_use_id", _MISSING)
    if value is _MISSING:
        return _MISSING
    if (
        not isinstance(value, str)
        or len(value) > MAX_TOOL_USE_ID_BYTES
        or len(value.encode("ascii", errors="ignore")) != len(value)
        or _ASCII_OPAQUE.fullmatch(value) is None
    ):
        return _INVALID
    return value


def _base_row(
    *, config: CaptureSession, route: str, harness: str, event_name: str, payload: Mapping[str, object]
) -> dict[str, object] | None:
    bounded_harness = _bounded_text(harness, maximum=64)
    raw_event = _bounded_text(event_name, maximum=64)
    if bounded_harness is None or raw_event is None:
        return None
    bounded_event = runtime_hook_event_name({"hook_event_name": raw_event})
    if bounded_event not in MANAGED_CODEX_HOOK_EVENTS:
        return None
    identifier = _tool_use_id(payload)
    if identifier is _MISSING:
        identifier_state = "missing"
    elif identifier is _INVALID:
        identifier_state = "unsupported"
    else:
        identifier_state = "present"
    row: dict[str, object] = {
        "schema": CAPTURE_SCHEMA,
        "fingerprint_scheme": FINGERPRINT_SCHEME,
        "key_id": config.key_id,
        "run_id": config.run_id,
        "route": route,
        "harness": bounded_harness,
        "event_name": bounded_event,
        "tool_use_id_state": identifier_state,
    }
    if identifier not in {_MISSING, _INVALID}:
        row["tool_use_id"] = cast(str, identifier)
    return row


def _output_name(run_id: str) -> str:
    return f"{CAPTURE_OUTPUT_PREFIX}{run_id}{CAPTURE_OUTPUT_SUFFIX}"


def _append_row(config: CaptureSession, *, guard_home: Path, row: Mapping[str, object]) -> bool:
    if fcntl is None or time.time() >= config.expires_at:
        return False
    serialized = _canonical_json(dict(row))
    if serialized is None:
        return False
    serialized += b"\n"
    if len(serialized) > config.max_bytes:
        return False
    directory = _open_diagnostics_directory(guard_home)
    if directory is None:
        return False
    output: int | None = None
    locked = False
    try:
        flags = (
            os.O_RDWR
            | os.O_APPEND
            | os.O_CREAT
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            output = os.open(_output_name(config.run_id), flags, _PRIVATE_FILE_MODE, dir_fd=directory)
        except (OSError, TypeError):
            return False
        if not _private_regular(output):
            return False
        deadline = time.monotonic() + 0.02
        while True:
            try:
                fcntl.flock(output, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError as error:
                if not isinstance(error, BlockingIOError) and error.errno != errno.EINTR:
                    return False
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.001)
        metadata = os.fstat(output)
        if metadata.st_size > config.max_bytes:
            return False
        existing = _read_descriptor(output, maximum=config.max_bytes)
        if existing is None:
            return False
        from .codex_binding_capture_join import valid_existing_records

        existing_count = valid_existing_records(existing, run_id=config.run_id, capture_session=config)
        if existing_count is None or existing_count >= config.max_records:
            return False
        if len(existing) + len(serialized) > config.max_bytes:
            return False
        _ = os.lseek(output, 0, os.SEEK_END)
        offset = 0
        try:
            while offset < len(serialized):
                try:
                    written = os.write(output, serialized[offset:])
                except OSError as error:
                    if error.errno != errno.EINTR or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.001)
                    continue
                if written <= 0:
                    raise OSError(errno.EIO, "capture write made no progress")
                offset += written
        except OSError:
            with suppress(OSError):
                os.ftruncate(output, len(existing))
            return False
        return True
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if output is not None:
            if locked:
                with suppress(OSError):
                    fcntl.flock(output, fcntl.LOCK_UN)
            with suppress(OSError):
                os.close(output)
        with suppress(OSError):
            os.close(directory)


def _record_row(*, guard_home: Path, config: CaptureSession, row: dict[str, object]) -> bool:
    row_mac = row_hmac(config, row)
    if row_mac is None:
        return False
    row["row_mac"] = row_mac
    return _append_row(config, guard_home=guard_home, row=row)


def record_bridge_ingress(
    *,
    guard_home: Path,
    raw_payload: str | bytes,
    event_name: str,
    forwarded_payload: str | bytes | None = None,
    harness: str = "codex",
) -> bool:
    """Record raw and forwarded ingress fingerprints when a marker enables it."""

    if harness != "codex":
        return False
    config = _load_capture_config(guard_home)
    if config is None:
        return False
    raw_encoded = bounded_utf8_bytes(raw_payload)
    if raw_encoded is None:
        return False
    forwarded_encoded = bounded_utf8_bytes(raw_payload if forwarded_payload is None else forwarded_payload)
    if forwarded_encoded is None:
        return False
    payload = _json_object(raw_encoded)
    forwarded = _json_object(forwarded_encoded)
    if payload is None or forwarded is None:
        return False
    # Daemon admission removes these transport fields before native review.
    # Preserve them in the raw digest, but bind the forwarded digest to the
    # same payload that reaches the native edge.
    forwarded = {
        key: value
        for key, value in forwarded.items()
        if key not in {"guard_remaining_seconds", "guard_remaining_ms", "hook_env"}
    }
    raw_fingerprint = payload_hmac(config, "raw", payload)
    forwarded_fingerprint = payload_hmac(config, "forwarded", forwarded)
    if raw_fingerprint is None or forwarded_fingerprint is None:
        return False
    row = _base_row(config=config, route="bridge_ingress", harness=harness, event_name=event_name, payload=payload)
    if row is None:
        return False
    row["raw_payload_hmac_sha256"] = raw_fingerprint
    row["forwarded_payload_hmac_sha256"] = forwarded_fingerprint
    return _record_row(guard_home=guard_home, config=config, row=row)


def record_native_worker(
    *,
    guard_home: Path,
    payload: Mapping[str, object],
    harness: str,
    event_name: str,
    receipt: object,
) -> bool:
    """Record the actual forwarded payload and validated native-edge receipt.

    The receipt describes the Rust native edge only.  It is not a final host
    approval or execution witness.
    """

    if harness != "codex":
        return False
    config = _load_capture_config(guard_home)
    if config is None:
        return False
    fingerprint = payload_hmac(config, "forwarded", payload)
    projection = _receipt_projection(receipt)
    if fingerprint is None or projection is None:
        return False
    row = _base_row(config=config, route="native_worker", harness=harness, event_name=event_name, payload=payload)
    if row is None:
        return False
    if projection["event_name"] != row["event_name"] or projection["harness"] != harness:
        return False
    row["forwarded_payload_hmac_sha256"] = fingerprint
    row["decision_scope"] = "native_edge"
    sealed = seal_receipt(config, row, projection)
    if sealed is None:
        return False
    row["sealed_receipt"] = sealed
    return _record_row(guard_home=guard_home, config=config, row=row)


def __getattr__(name: str) -> object:
    if name == "join_binding_records":
        from .codex_binding_capture_join import join_binding_records

        return join_binding_records
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BINDABLE_CODEX_HOOK_EVENTS",
    "CAPTURE_MARKER_NAME",
    "CAPTURE_OUTPUT_PREFIX",
    "CAPTURE_OUTPUT_SUFFIX",
    "CAPTURE_SCHEMA",
    "FINGERPRINT_SCHEME",
    "MAX_CANONICAL_PAYLOAD_BYTES",
    "MAX_CAPTURE_BYTES",
    "MAX_CAPTURE_RECORDS",
    "CaptureSession",
    "initialize_capture_marker",
    "join_binding_records",
    "read_capture_session",
    "record_bridge_ingress",
    "record_native_worker",
]
