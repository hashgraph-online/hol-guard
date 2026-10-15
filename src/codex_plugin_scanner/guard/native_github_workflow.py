"""Resident bridge for the ``github_workflow_prepare`` op.

The Rust runtime owns GitHub workflow command understanding: it parses the hook
command, collects the live ``git``/``gh`` context, derives every digest and
returns the privacy-safe approval record, and re-verifies a persisted command
against a record. This module only frames one request, binds the response by
``request_id`` plus ``request_sha256``, and decodes the result. Any transport
failure (resident unavailable, capability absent, timeout, overload, malformed
or mismatched result) yields ``None``/``False``; callers must treat that as "no
exactly bindable GitHub workflow operation" and never recompute one in Python.
"""

from __future__ import annotations

import itertools
import json
import os
import time
from collections.abc import Mapping
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
from .runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord

_MAX_REQUEST_BYTES = 1024 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_FEATURE = "github-workflow-prepare-v1"
_REQUEST_SCHEMA = "guard-github-workflow-prepare-request.v1"
_RESULT_SCHEMA = "guard-github-workflow-prepare-result.v1"
_REQUEST_IDS = itertools.count()
_DEFAULT_TIMEOUT_SECONDS = 9.0


@dataclass(frozen=True, slots=True)
class GitHubWorkflowDescriptor:
    """The native verdict for one hook command: its approval record and identity."""

    record: GitHubWorkflowApprovalRecord
    command_identity: str


def github_workflow_describe_native(
    command_text: str,
    *,
    workspace: Path | None,
    config_path: str,
    configuration: Mapping[str, object],
    sandbox: Mapping[str, object],
    policy_version: str,
    environment: Mapping[str, str] | None = None,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> GitHubWorkflowDescriptor | None:
    """Describe an exactly bindable GitHub workflow command, or return ``None``."""
    if workspace is None or not _may_name_gh(command_text):
        return None
    envelope = _resident_envelope(
        {
            "mode": "describe",
            "command_text": command_text,
            "workspace": os.fspath(workspace),
            "config_path": config_path,
            "configuration": dict(configuration),
            "sandbox": dict(sandbox),
            "environment": dict(os.environ if environment is None else environment),
            "policy_version": policy_version,
        },
        timeout_seconds=timeout_seconds,
    )
    if envelope is None or envelope.get("code") != "ok":
        return None
    record_payload = envelope.get("record")
    identity = envelope.get("command_identity")
    if not isinstance(record_payload, dict) or not isinstance(identity, str) or not identity:
        return None
    try:
        record = GitHubWorkflowApprovalRecord.from_dict(record_payload)
    except (TypeError, ValueError):
        return None
    return GitHubWorkflowDescriptor(record=record, command_identity=identity)


def github_workflow_persisted_command_matches(
    command_text: str,
    record: GitHubWorkflowApprovalRecord,
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> bool:
    """Whether a persisted hook command still derives the record's exact operation."""
    envelope = _resident_envelope(
        {"mode": "verify", "command_text": command_text, "record": record.to_dict()},
        timeout_seconds=timeout_seconds,
    )
    return envelope is not None and envelope.get("code") == "ok" and envelope.get("verified") is True


def _may_name_gh(command_text: str) -> bool:
    """Cheap negative filter: a ``gh`` executable path cannot be spelled without these letters.

    The resident parser decides everything else. Quote and escape characters
    are dropped first so an obscured spelling still reaches the resident; a
    command that cannot contain the two letters never costs a round trip.
    """
    return "gh" in command_text.translate({ord("'"): None, ord('"'): None, ord("\\"): None})


def _resident_envelope(fields: dict[str, object], *, timeout_seconds: float) -> dict[str, object] | None:
    effective_deadline = time.monotonic() + timeout_seconds
    status = native_runtime_status(deadline_monotonic=effective_deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
        or _FEATURE not in status.capabilities.features
    ):
        return None
    guard_home = _resolve_digest_home(None)
    if not ensure_resident_prerequisite(guard_home):
        return None
    if native_runtime_health_snapshot(status.identity.sha256, guard_home).circuit_open:
        return None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"ghwf-{next(_REQUEST_IDS)}",
        **fields,
    }
    remaining_seconds = effective_deadline - time.monotonic()
    if remaining_seconds <= 0:
        return None
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        resident = json.dumps(
            {
                "operation": "github_workflow_prepare",
                "deadline_budget_ms": max(1, min(9_000, int(remaining_seconds * 1_000))),
                "request": request,
            },
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    if len(resident) > _MAX_REQUEST_BYTES:
        return None
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=resident,
        deadline_monotonic=effective_deadline,
    )
    identity = status.identity.sha256
    if output is None:
        native_record_resident_failure(identity, guard_home, reason="native_github_workflow_prepare_unavailable")
        return None
    try:
        envelope = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        native_record_resident_failure(identity, guard_home, reason="native_github_workflow_prepare_decode_failed")
        return None
    if _native_error(envelope) == "native_overloaded":
        native_record_overload(identity, guard_home)
        return None
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != _RESULT_SCHEMA
        or envelope.get("request_id") != request["request_id"]
        or envelope.get("request_sha256") != request_sha256
    ):
        native_record_resident_failure(identity, guard_home, reason="native_github_workflow_prepare_schema_mismatch")
        return None
    if envelope.get("status") != "ok":
        native_record_resident_failure(identity, guard_home, reason="native_github_workflow_prepare_bad_result")
        return None
    native_record_resident_success(identity, guard_home)
    return envelope
