"""Resident bridge for the ``compound_git_inspection`` op.

The runtime forwards modeled shell segments plus observed facts (home, account
home, groups, a bounded environment snapshot) to the resident. Rust owns every
verdict. This module never inspects Git arguments, configuration, binaries or
paths; any transport failure, malformed result, or missing capability returns
a denying answer carrying a typed error code. There is no Python fallback.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from . import native_git_execution_safety as _git_safety
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_path_anchor import anchor_to_process_directory
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
    native_runtime_health_snapshot,
)

if TYPE_CHECKING:
    from .runtime.shell_execution_context import ShellExecutionSegment

_MAX_REQUEST_BYTES = 256 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_FEATURE = "compound-git-inspection-v1"
_REQUEST_SCHEMA = "guard-compound-git-inspection-request.v1"
_RESULT_SCHEMA = "guard-compound-git-inspection-result.v1"
_DEFAULT_TIMEOUT_SECONDS = 8.0
_UNAVAILABLE = "native_compound_git_inspection_unavailable"

_request_counter = 0


@dataclass(frozen=True)
class CompoundGitAnswer:
    """The resident's verdict, or a denial with a typed error code."""

    allowed: bool
    value: str | None = None
    error_code: str | None = None


def _deny(code: str) -> CompoundGitAnswer:
    return CompoundGitAnswer(False, None, code)


def _segment_payload(segment: ShellExecutionSegment) -> dict[str, object]:
    payload: dict[str, object] = {
        "tokens": list(segment.tokens),
        "control_before": list(segment.control_before),
        "control_after": list(segment.control_after),
    }
    if segment.effective_cwd is not None:
        payload["effective_cwd"] = anchor_to_process_directory(segment.effective_cwd)
    if segment.directory_operation is not None:
        payload["directory_operation"] = segment.directory_operation
    return payload


def compound_git_inspection_native(
    check: str,
    *,
    segments: Iterable[ShellExecutionSegment] = (),
    complete: bool = False,
    command_text: str | None = None,
    value: str | None = None,
    values: Iterable[str] = (),
    cwd: str | os.PathLike[str] | None = None,
    home_dir: str | os.PathLike[str] | None = None,
    repository_path: str | None = None,
    pager_key: str | None = None,
    git_binary: str | os.PathLike[str] | None = None,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> CompoundGitAnswer:
    """Ask the resident for one compound-git-inspection verdict."""

    global _request_counter
    effective_deadline = time.monotonic() + timeout_seconds
    status = native_runtime_status(deadline_monotonic=effective_deadline)
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
        or _FEATURE not in status.capabilities.features
    ):
        return _deny(_UNAVAILABLE)
    guard_home = _resolve_digest_home(None)
    if native_runtime_health_snapshot(status.identity.sha256, guard_home).circuit_open:
        return _deny(_UNAVAILABLE)
    if not ensure_resident_prerequisite(guard_home):
        return _deny(_UNAVAILABLE)
    try:
        request: dict[str, object] = {
            "schema": _REQUEST_SCHEMA,
            "check": check,
            "segments": [_segment_payload(segment) for segment in segments],
            "complete": complete,
            "home": str(Path.home()),
            "groups": _git_safety._process_groups(),
            "environment": _git_safety._environment_snapshot(),
        }
        optional: tuple[tuple[str, str | None], ...] = (
            ("command_text", command_text),
            ("value", value),
            ("cwd", None if cwd is None else anchor_to_process_directory(cwd)),
            ("home_dir", None if home_dir is None else anchor_to_process_directory(home_dir)),
            ("repository_path", repository_path),
            ("pager_key", pager_key),
            ("git_binary", None if git_binary is None else anchor_to_process_directory(git_binary)),
            ("account_home", _git_safety._account_home_directory()),
        )
    except (OSError, RuntimeError):
        return _deny(_UNAVAILABLE)
    for name, item in optional:
        if item is not None:
            request[name] = item
    pathspecs = list(values)
    if pathspecs:
        request["values"] = pathspecs
    _request_counter += 1
    request["request_id"] = f"cgi-{os.getpid()}-{_request_counter}"
    remaining_seconds = effective_deadline - time.monotonic()
    if remaining_seconds <= 0:
        return _deny(_UNAVAILABLE)
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        resident = json.dumps(
            {
                "operation": "compound_git_inspection",
                "deadline_budget_ms": max(1, min(9_000, int(remaining_seconds * 1_000))),
                "request": request,
            },
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return _deny("native_compound_git_inspection_invalid")
    if len(resident) > _MAX_REQUEST_BYTES or time.monotonic() >= effective_deadline:
        return _deny(_UNAVAILABLE)
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=resident,
        deadline_monotonic=effective_deadline,
    )
    if output is None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_UNAVAILABLE)
        return _deny(_UNAVAILABLE)
    try:
        decoded: object = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_compound_git_inspection_decode_failed"
        )
        return _deny("native_compound_git_inspection_decode_failed")
    if _native_error(decoded) == "native_overloaded":
        native_record_overload(status.identity.sha256, guard_home)
        return _deny("native_overloaded")
    envelope = cast("dict[str, object]", decoded) if isinstance(decoded, dict) else None
    if (
        envelope is None
        or envelope.get("schema") != _RESULT_SCHEMA
        or envelope.get("request_id") != request["request_id"]
        or envelope.get("request_sha256") != request_sha256
        or not isinstance(envelope.get("allowed"), bool)
    ):
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_compound_git_inspection_schema_mismatch"
        )
        return _deny("native_compound_git_inspection_schema_mismatch")
    native_record_resident_success(status.identity.sha256, guard_home)
    if envelope.get("status") != "ok" or envelope.get("code") != "ok":
        code = envelope.get("code")
        return _deny(code if isinstance(code, str) else "native_compound_git_inspection_invalid")
    result_value = envelope.get("value")
    return CompoundGitAnswer(bool(envelope["allowed"]), result_value if isinstance(result_value, str) else None)
