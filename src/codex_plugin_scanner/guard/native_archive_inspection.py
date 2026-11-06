"""Mechanical transport adapter for native archive inspection.

This module is transport plumbing only: it validates request shape, forwards a
bounded JSON request to ``hol-guard-runtime archive-inspect --stdin``, and
projects the typed result back to the package evaluator. Archive admission —
including the one-inspector lease — hashing, decompression, member policy, and
manifest risk evaluation are owned by the Rust worker; there is no Python
semantic fallback.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_runtime import native_runtime_status

ArchiveInspectionStatus = Literal["clean", "blocked", "incomplete"]

_REQUEST_SCHEMA = "guard-archive-inspection.v1"
_RESULT_SCHEMA = "guard-archive-inspection-result.v1"
_NATIVE_FEATURE = "archive-inspection-v1"
_RESULT_MAX_BYTES = 16 * 1024
_MAX_CODE_CHARS = 128
_MAX_MESSAGE_CHARS = 512
_MAX_COUNTER = 2**62
_RESULT_KEYS = frozenset(
    {
        "schema",
        "request_id",
        "request_sha256",
        "status",
        "code",
        "message",
        "severity",
        "sha256",
        "runtime_sha256",
        "counters",
    }
)
_COUNTER_KEYS = frozenset({"members", "expanded_bytes", "elapsed_ms"})
_HEX_64_RE = re.compile(r"[0-9a-f]{64}")

# Caller-facing defaults identical to the retired Python worker contract.
_DEFAULT_TIMEOUT_SECONDS = 2.0
_DEFAULT_MAX_ARCHIVE_BYTES = 6 * 1024 * 1024
_DEFAULT_MAX_FILES = 500
_DEFAULT_MAX_EXPANDED_BYTES = 32 * 1024 * 1024
_DEFAULT_MAX_MEMBER_BYTES = 8 * 1024 * 1024
_DEFAULT_MAX_PACKAGE_JSON_BYTES = 256 * 1024
_DEFAULT_MAX_MEMORY_BYTES = 512 * 1024 * 1024
_DEFAULT_MAX_DECOMPRESSION_RATIO = 200.0
_DEFAULT_MAX_NESTED_ARCHIVES = 8
_DEFAULT_MAX_PATH_DEPTH = 64


@dataclass(frozen=True, slots=True)
class ArchiveInspectionResult:
    status: ArchiveInspectionStatus
    code: str
    message: str
    severity: str
    sha256: str | None = None


def _result(
    status: ArchiveInspectionStatus,
    code: str,
    message: str,
    *,
    severity: str,
    sha256: str | None = None,
) -> ArchiveInspectionResult:
    return ArchiveInspectionResult(
        status=status,
        code=code,
        message=message,
        severity=severity,
        sha256=sha256,
    )


def _worker_environment() -> dict[str, str]:
    environment = {"LC_ALL": "C"}
    for key in ("SYSTEMROOT", "WINDIR"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


def inspect_archive_native(
    path: Path,
    *,
    expected_sha256: str,
    state_dir: Path,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    max_archive_bytes: int = _DEFAULT_MAX_ARCHIVE_BYTES,
    max_files: int = _DEFAULT_MAX_FILES,
    max_expanded_bytes: int = _DEFAULT_MAX_EXPANDED_BYTES,
    max_member_bytes: int = _DEFAULT_MAX_MEMBER_BYTES,
    max_package_json_bytes: int = _DEFAULT_MAX_PACKAGE_JSON_BYTES,
    max_memory_bytes: int = _DEFAULT_MAX_MEMORY_BYTES,
    max_decompression_ratio: float = _DEFAULT_MAX_DECOMPRESSION_RATIO,
    max_nested_archives: int = _DEFAULT_MAX_NESTED_ARCHIVES,
    max_path_depth: int = _DEFAULT_MAX_PATH_DEPTH,
) -> ArchiveInspectionResult:
    """Inspect a digest-bound local blob through the native worker."""

    # The caller's timeout covers the whole adapter — including the cold-start
    # capabilities probe — so capture the deadline up front and hand it to the
    # bounded runner rather than starting a fresh timeout at spawn time.
    deadline_monotonic = time.monotonic() + timeout_seconds + 0.5
    if (
        timeout_seconds <= 0
        or not math.isfinite(timeout_seconds)
        or max_archive_bytes <= 0
        or max_files <= 0
        or max_expanded_bytes <= 0
        or max_member_bytes <= 0
        or max_package_json_bytes <= 0
        or max_memory_bytes <= 0
        or not math.isfinite(max_decompression_ratio)
        or max_decompression_ratio <= 0
        or max_nested_archives < 0
        or max_path_depth <= 0
        or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
    ):
        return _result(
            "incomplete",
            "external_archive_inspection_policy_invalid",
            "External archive inspection policy is invalid.",
            severity="high",
        )
    try:
        # Resolve ancestors only; the leaf keeps its on-disk identity so the
        # native worker's own lstat still sees a symlink leaf and rejects it.
        resolved_parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive is unavailable for offline inspection.",
            severity="high",
        )
    archive_path = resolved_parent / path.name
    # The caller's timeout covers the whole adapter; pass the absolute
    # deadline through so a cold capabilities probe can never spend longer
    # than the request has left.
    status = native_runtime_status(deadline_monotonic=deadline_monotonic)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _NATIVE_FEATURE not in status.capabilities.features
    ):
        return _result(
            "incomplete",
            "external_archive_native_unavailable",
            "External archive inspection requires the Guard native runtime.",
            severity="high",
        )
    # No wrapper is applied here: macOS refuses a nested sandbox_init, so the
    # worker must self-apply its seatbelt profile as the first containment
    # step and prove the denial before any untrusted bytes are parsed.
    command = [str(status.identity.path), "archive-inspect", "--stdin"]
    worker_budget = deadline_monotonic - time.monotonic() - 0.5
    if worker_budget <= 0:
        return _result(
            "incomplete",
            "external_archive_inspection_timeout",
            "External archive inspection exceeded Guard's time limit.",
            severity="high",
        )
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        canonical_state_dir = state_dir.resolve(strict=True)
    except OSError:
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive inspection lease could not be established.",
            severity="high",
        )
    request = {
        "schema": _REQUEST_SCHEMA,
        "request_id": secrets.token_hex(16),
        "archive_path": str(archive_path),
        "state_dir": str(canonical_state_dir),
        "expected_sha256": expected_sha256,
        "timeout_ms": math.ceil(worker_budget * 1000),
        "caps": {
            "max_archive_bytes": max_archive_bytes,
            "max_files": max_files,
            "max_expanded_bytes": max_expanded_bytes,
            "max_member_bytes": max_member_bytes,
            "max_package_json_bytes": max_package_json_bytes,
            "max_memory_bytes": max_memory_bytes,
            "max_decompression_ratio": max_decompression_ratio,
            "max_nested_archives": max_nested_archives,
            "max_path_depth": max_path_depth,
        },
    }
    request_bytes = json.dumps(request, separators=(",", ":"), sort_keys=True).encode("utf-8")
    request_digest = hashlib.sha256(request_bytes).hexdigest()
    completed = run_isolated_hook_process(
        command,
        input_text=request_bytes.decode("utf-8"),
        cwd=archive_path.parent,
        environment=_worker_environment(),
        deadline_monotonic=deadline_monotonic,
        output_limit=_RESULT_MAX_BYTES + 1024,
        parent_liveness=True,
    )
    if completed.timed_out:
        return _result(
            "incomplete",
            "external_archive_inspection_timeout",
            "External archive inspection exceeded Guard's time limit.",
            severity="high",
        )
    if (
        completed.returncode != 0
        or completed.output_limit_exceeded
        or completed.containment_failed
        or len(completed.stdout.encode("utf-8")) > _RESULT_MAX_BYTES
    ):
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive offline inspector did not complete successfully.",
            severity="high",
        )
    try:
        payload = json.loads(completed.stdout.strip())
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive offline inspector returned an invalid result.",
            severity="high",
        )
    if not isinstance(payload, dict) or not _RESULT_KEYS.issuperset(payload):
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive offline inspector returned an invalid result.",
            severity="high",
        )
    status_value = payload.get("status")
    code = payload.get("code")
    message = payload.get("message")
    severity = payload.get("severity")
    sha256 = payload.get("sha256")
    runtime_sha256 = payload.get("runtime_sha256")
    counters = payload.get("counters")
    counters_valid = (
        isinstance(counters, dict)
        and _COUNTER_KEYS.issuperset(counters)
        and all(
            isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_COUNTER
            for value in counters.values()
        )
    )
    if (
        payload.get("schema") != _RESULT_SCHEMA
        or payload.get("request_id") != request["request_id"]
        or payload.get("request_sha256") != request_digest
        or status_value not in {"clean", "blocked", "incomplete"}
        or not isinstance(code, str)
        or not 0 < len(code) <= _MAX_CODE_CHARS
        or not isinstance(message, str)
        or not 0 < len(message) <= _MAX_MESSAGE_CHARS
        or severity not in {"low", "medium", "high", "critical"}
        or (sha256 is not None and (not isinstance(sha256, str) or not _HEX_64_RE.fullmatch(sha256)))
        or not isinstance(runtime_sha256, str)
        or not _HEX_64_RE.fullmatch(runtime_sha256)
        or runtime_sha256 != status.identity.sha256
        or not counters_valid
    ):
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive offline inspector returned an invalid result.",
            severity="high",
        )
    if status_value == "clean" and sha256 != expected_sha256:
        return _result(
            "blocked",
            "external_archive_digest_mismatch",
            "External archive inspector did not verify the expected digest.",
            severity="high",
            sha256=sha256,
        )
    return ArchiveInspectionResult(status_value, code, message, severity, sha256)


__all__ = ["ArchiveInspectionResult", "inspect_archive_native"]
