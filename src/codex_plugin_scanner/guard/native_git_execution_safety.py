"""Resident bridge for the ``git_execution_safety`` op (RTM-032).

``runtime.git_execution_safety`` forwards observed facts (cwd, home, account
home, groups, a bounded environment snapshot, and the arguments under review)
to the resident. Rust owns every verdict. This module never evaluates Git
configuration, binaries, or hooks; any transport failure, malformed result, or
missing capability returns ``None`` and callers fail closed.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
    native_runtime_health_snapshot,
)

_MAX_REQUEST_BYTES = 128 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_FEATURE = "git-execution-safety-v1"
_REQUEST_SCHEMA = "guard-git-execution-safety-request.v1"
_RESULT_SCHEMA = "guard-git-execution-safety-result.v1"
_SNAPSHOT_NAMES = frozenset(
    {
        "SSH_ASKPASS",
        "PATH",
        "HOME",
        "XDG_CONFIG_HOME",
        "PAGER",
        "USERPROFILE",
        "SYSTEMROOT",
        "WINDIR",
    }
)
_DEFAULT_TIMEOUT_SECONDS = 8.0

_request_counter = 0


@dataclass(frozen=True)
class GitSafetyAnswer:
    """The resident's verdict for one check."""

    allowed: bool
    resolved_path: str | None


def _environment_snapshot() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key.startswith("GIT_") or key in _SNAPSHOT_NAMES}


def _account_home_directory() -> str | None:
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError, OSError, RuntimeError, AttributeError):
        return None


def _process_groups() -> list[int]:
    getgroups = getattr(os, "getgroups", None)
    if getgroups is None:
        return []
    try:
        return sorted({int(group) for group in getgroups()})
    except OSError:
        return []


def git_execution_safety_native(
    check: str,
    *,
    cwd: Path | None = None,
    git_binary: Path | None = None,
    git_path: Path | None = None,
    arguments: list[str] | None = None,
    branch: str | None = None,
    reference: str | None = None,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> GitSafetyAnswer | None:
    """Ask the resident for a git-execution-safety verdict.

    Returns ``None`` when no authoritative answer is available.
    """

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
        return None
    guard_home = _resolve_digest_home(None)
    if native_runtime_health_snapshot(status.identity.sha256, guard_home).circuit_open:
        return None
    if not ensure_resident_prerequisite(guard_home):
        return None
    try:
        home = str(Path.home())
        # The resident resolves relative paths against its own directory, so
        # the caller cwd must be made absolute here (the retired Python
        # implementation did) before it is sent.
        request_cwd = os.path.abspath(cwd) if cwd is not None else home
    except (OSError, RuntimeError):
        return None
    _request_counter += 1
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"ges-{os.getpid()}-{_request_counter}",
        "check": check,
        "cwd": request_cwd,
        "home": home,
        "groups": _process_groups(),
        "environment": _environment_snapshot(),
        "arguments": list(arguments or []),
    }
    account_home = _account_home_directory()
    if account_home is not None:
        request["account_home"] = account_home
    for name, value in (
        ("git_binary", git_binary),
        ("git_path", git_path),
        ("branch", branch),
        ("reference", reference),
    ):
        if value is not None:
            request[name] = str(value)
    remaining_seconds = effective_deadline - time.monotonic()
    if remaining_seconds <= 0:
        return None
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        resident = json.dumps(
            {
                "operation": "git_execution_safety",
                "deadline_budget_ms": max(1, min(9_000, int(remaining_seconds * 1_000))),
                "request": request,
            },
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    if len(resident) > _MAX_REQUEST_BYTES or time.monotonic() >= effective_deadline:
        return None
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=resident,
        deadline_monotonic=effective_deadline,
    )
    if output is None:
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_git_execution_safety_unavailable"
        )
        return None
    try:
        envelope = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_git_execution_safety_decode_failed"
        )
        return None
    if _native_error(envelope) == "native_overloaded":
        native_record_overload(status.identity.sha256, guard_home)
        return None
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != _RESULT_SCHEMA
        or envelope.get("request_id") != request["request_id"]
        or envelope.get("request_sha256") != request_sha256
        or not isinstance(envelope.get("allowed"), bool)
    ):
        native_record_resident_failure(
            status.identity.sha256, guard_home, reason="native_git_execution_safety_schema_mismatch"
        )
        return None
    native_record_resident_success(status.identity.sha256, guard_home)
    if envelope.get("status") != "ok" or envelope.get("code") != "ok":
        return GitSafetyAnswer(False, None)
    resolved = envelope.get("resolved_path")
    return GitSafetyAnswer(bool(envelope["allowed"]), resolved if isinstance(resolved, str) else None)
