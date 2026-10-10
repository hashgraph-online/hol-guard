"""Resident bridge for the ``codex_tool_output`` op.

The runtime forwards one command (or several post-tool commands) plus observed
facts (process directory, home, account home, groups, a bounded environment
snapshot and the resolved ``git`` executable) to the resident. Rust owns every
verdict: read-only source inspection, secret-like source names, git pathspec
identities, local-content reads, focused pytest and git metadata. This module
never inspects command text, paths or Git state; any transport failure,
malformed result, or missing capability returns a denying answer carrying a
typed error code. There is no Python fallback.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

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

_MAX_REQUEST_BYTES = 256 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_FEATURE = "codex-tool-output-v1"
_REQUEST_SCHEMA = "guard-codex-tool-output-request.v1"
_RESULT_SCHEMA = "guard-codex-tool-output-result.v1"
_DEFAULT_TIMEOUT_SECONDS = 8.0
_UNAVAILABLE = "native_codex_tool_output_unavailable"
_EXTRA_SNAPSHOT_NAMES = frozenset({"RIPGREP_CONFIG_PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMP", "TEMP", "TMPDIR"})

_request_counter = 0


@dataclass(frozen=True)
class ToolOutputAnswer:
    """The resident's verdict, or a denial with a typed error code."""

    allowed: bool
    value: str | None = None
    error_code: str | None = None


def _deny(code: str) -> ToolOutputAnswer:
    return ToolOutputAnswer(False, None, code)


def _environment_snapshot() -> dict[str, str]:
    snapshot = _git_safety._environment_snapshot()
    snapshot.update({key: value for key, value in os.environ.items() if key in _EXTRA_SNAPSHOT_NAMES})
    return snapshot


def _anchored(path: str | os.PathLike[str] | None) -> str | None:
    return None if path is None else anchor_to_process_directory(path)


def codex_tool_output_native(
    kind: str,
    *,
    command: str | None = None,
    commands: Iterable[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    home_dir: str | os.PathLike[str] | None = None,
    exec_context: bool = False,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> ToolOutputAnswer:
    """Ask the resident for one Codex tool-output verdict."""

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
        action: dict[str, object] = {"kind": kind}
        if kind == "post_tool_read_only":
            action.update({"commands": list(commands or ()), "cwd": _anchored(cwd), "home_dir": _anchored(home_dir)})
        elif kind in {"read_only_inspection", "secret_like_source_name"}:
            action.update({"command": command, "cwd": _anchored(cwd), "home_dir": _anchored(home_dir)})
            if kind == "secret_like_source_name":
                action["exec_context"] = exec_context
        elif kind in {"git_pathspec_identity", "local_content_tail", "git_metadata"}:
            action.update({"command": command, "cwd": _anchored(cwd)})
        else:
            action["command"] = command
        facts: dict[str, object] = {
            "process_cwd": os.getcwd(),
            "home": str(Path.home()),
            "account_home": _git_safety._account_home_directory(),
            "groups": _git_safety._process_groups(),
            "environment": _environment_snapshot(),
            "git_executable": shutil.which("git"),
        }
    except (OSError, RuntimeError):
        return _deny(_UNAVAILABLE)
    _request_counter += 1
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"cto-{os.getpid()}-{_request_counter}",
        "action": action,
        "facts": facts,
    }
    remaining_seconds = effective_deadline - time.monotonic()
    if remaining_seconds <= 0:
        return _deny(_UNAVAILABLE)
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        resident = json.dumps(
            {
                "operation": "codex_tool_output",
                "deadline_budget_ms": max(1, min(9_000, int(remaining_seconds * 1_000))),
                "request": request,
            },
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return _deny("native_codex_tool_output_invalid")
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
            status.identity.sha256, guard_home, reason="native_codex_tool_output_decode_failed"
        )
        return _deny("native_codex_tool_output_decode_failed")
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
            status.identity.sha256, guard_home, reason="native_codex_tool_output_schema_mismatch"
        )
        return _deny("native_codex_tool_output_schema_mismatch")
    native_record_resident_success(status.identity.sha256, guard_home)
    if envelope.get("status") != "ok" or envelope.get("code") != "ok":
        code = envelope.get("code")
        return _deny(code if isinstance(code, str) else "native_codex_tool_output_invalid")
    result_value = envelope.get("value")
    return ToolOutputAnswer(bool(envelope["allowed"]), result_value if isinstance(result_value, str) else None)
