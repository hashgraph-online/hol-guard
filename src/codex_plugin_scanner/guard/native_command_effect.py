"""Resident bridge for the ``command_effect_decide`` op (RTM-008).

The resident owns the command/effect composition: positive-proof and
uncertainty precedence, the floor lattice, extension control resolution and
the local read/write/Git/workflow floors. This module only binds one request
to one result (or, for offline corpus evaluation, a bounded batch of requests
to the same number of bound results: every item keeps its own request id and
request hash and is judged by the single-op rules). Python never recomputes any part of the decision: a ``None``
return means the resident could not service the call (unavailable, capability
absent, timeout, overload) and callers must fail closed; a malformed or
unbound answer raises.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
    native_runtime_health_snapshot,
)
from .native_runtime_values import NativeRuntimeIdentity

COMMAND_EFFECT_FEATURE = "command-effect-v1"
COMMAND_EFFECT_BATCH_FEATURE = "command-effect-batch-v1"
COMMAND_EFFECT_BATCH_MAX_ITEMS = 64
COMMAND_EFFECT_BATCH_MAX_BYTES = 4 * 1024 * 1024
NATIVE_COMMAND_CONTROL_BINDING_SCHEMA = "guard.native-command-control-binding.v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_REQUEST_SCHEMA = "guard-command-effect-request.v1"
_RESULT_SCHEMA = "guard-command-effect-result.v1"
_BATCH_REQUEST_SCHEMA = "guard-command-effect-batch-request.v1"
_BATCH_RESULT_SCHEMA = "guard-command-effect-batch-result.v1"
_MAX_REQUEST_BYTES = 1024 * 1024
# A batch the resident refuses only for size is re-sent as two halves, never
# relaxed: the same bounds apply to every half.
_BATCH_SPLITTABLE_CODES = frozenset(
    {
        "native_command_effect_batch_too_large",
        "native_command_effect_batch_response_too_large",
        "native_command_effect_batch_too_many_items",
    }
)
_WRAPPER_PARSER_PROFILE = "posix-bounded-wrappers-v2"
_PARSER_PROFILE = "posix-simple-v1"

_request_counter = 0


class NativeCommandEffectMalformedError(RuntimeError):
    """The resident answered, but the answer is not a bound command-effect result."""


class NativeCommandEffectRejectedError(RuntimeError):
    """The resident refused the request; ``code`` is its bound refusal code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CommandEffectItem:
    """One command's inputs, exactly as the single op takes them."""

    command_text: str
    canonical_command: Mapping[str, object]
    native_extension_evidence: Mapping[str, object]
    control_snapshot: Mapping[str, object]
    compatibility_action_class: str | None = None
    compatibility_reason: str | None = None
    workflow_authorization: Mapping[str, object] | None = None
    cwd: Path | None = None
    home_dir: Path | None = None


def _build_request(
    *,
    command_text: str,
    canonical_command: Mapping[str, object],
    native_extension_evidence: Mapping[str, object],
    control_snapshot: Mapping[str, object],
    compatibility_action_class: str | None,
    compatibility_reason: str | None,
    workflow_authorization: Mapping[str, object] | None,
    cwd: Path | None,
    home_dir: Path | None,
    counterfactual_enabled_permission_ids: Sequence[str] = (),
) -> dict[str, object]:
    global _request_counter
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"ce-{_request_counter}",
        "command_text": command_text,
        "canonical_command": dict(canonical_command),
        "native_extension_evidence": dict(native_extension_evidence),
        "control_snapshot": dict(control_snapshot),
    }
    _request_counter += 1
    if compatibility_action_class is not None:
        request["compatibility_action_class"] = compatibility_action_class
    if compatibility_reason is not None:
        request["compatibility_reason"] = compatibility_reason
    if workflow_authorization is not None:
        request["workflow_authorization"] = dict(workflow_authorization)
    if cwd is not None:
        request["cwd"] = str(cwd)
    if home_dir is not None:
        request["home_dir"] = str(home_dir)
    if counterfactual_enabled_permission_ids:
        # Counterfactual only: the resident validates the real binding first,
        # then treats these permissions as enabled for this one evaluation.
        request["counterfactual_enabled_permission_ids"] = list(counterfactual_enabled_permission_ids)
    return request


def _resident_ready(
    guard_home: Path,
    feature: str,
    timeout_seconds: float,
    deadline_monotonic: float | None,
) -> tuple[NativeRuntimeIdentity, float] | None:
    """Return the compatible resident's identity and the request deadline, or ``None``."""
    effective_deadline = time.monotonic() + timeout_seconds
    if deadline_monotonic is not None:
        effective_deadline = min(effective_deadline, deadline_monotonic)
    if effective_deadline <= time.monotonic():
        return None
    status = native_runtime_status(deadline_monotonic=effective_deadline)
    identity = status.identity
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or identity is None
        or status.capabilities is None
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
        or feature not in status.capabilities.features
    ):
        return None
    if native_runtime_health_snapshot(identity.sha256, guard_home).circuit_open:
        return None
    # The one-time on-disk prerequisite is provisioning, not request work, so
    # its first-use cost must not consume this request's own time budget.
    if not ensure_resident_prerequisite(guard_home):
        return None
    effective_deadline = time.monotonic() + timeout_seconds
    if deadline_monotonic is not None:
        effective_deadline = min(effective_deadline, deadline_monotonic)
    return identity, effective_deadline


def command_effect_decide_native(
    *,
    command_text: str,
    canonical_command: Mapping[str, object],
    native_extension_evidence: Mapping[str, object],
    control_snapshot: Mapping[str, object],
    guard_home: Path,
    compatibility_action_class: str | None = None,
    compatibility_reason: str | None = None,
    workflow_authorization: Mapping[str, object] | None = None,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    timeout_seconds: float = 5.0,
    deadline_monotonic: float | None = None,
    counterfactual_enabled_permission_ids: Sequence[str] = (),
) -> dict[str, object] | None:
    """Return the resident's evaluation payload, or ``None`` when unavailable."""
    ready = _resident_ready(guard_home, COMMAND_EFFECT_FEATURE, timeout_seconds, deadline_monotonic)
    if ready is None:
        return None
    identity, effective_deadline = ready

    request = _build_request(
        command_text=command_text,
        canonical_command=canonical_command,
        native_extension_evidence=native_extension_evidence,
        control_snapshot=control_snapshot,
        compatibility_action_class=compatibility_action_class,
        compatibility_reason=compatibility_reason,
        workflow_authorization=workflow_authorization,
        cwd=cwd,
        home_dir=home_dir,
        counterfactual_enabled_permission_ids=counterfactual_enabled_permission_ids,
    )

    remaining_seconds = effective_deadline - time.monotonic()
    if remaining_seconds <= 0:
        return None
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        resident = json.dumps(
            {
                "operation": "command_effect_decide",
                "deadline_budget_ms": max(1, min(9_000, int(remaining_seconds * 1_000))),
                "request": request,
            },
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NativeCommandEffectMalformedError("command_effect request is not JSON data") from exc
    if len(resident) > _MAX_REQUEST_BYTES or time.monotonic() >= effective_deadline:
        return None

    output = native_resident_client_request(
        executable=identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=resident,
        deadline_monotonic=effective_deadline,
    )
    if output is None:
        native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_unavailable")
        return None
    try:
        envelope = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_decode_failed")
        raise NativeCommandEffectMalformedError("command_effect result is not valid JSON") from None
    if _native_error(envelope) == "native_overloaded":
        native_record_overload(identity.sha256, guard_home)
        return None
    if isinstance(envelope, dict) and isinstance(envelope.get("error"), str) and "schema" not in envelope:
        # A resident-level refusal (for example an older resident that does not
        # know this operation) is an outage for this feature, never an answer.
        native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_resident_error")
        return None
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != _RESULT_SCHEMA
        or envelope.get("request_id") != request["request_id"]
        or envelope.get("request_sha256") != request_sha256
    ):
        native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_schema_mismatch")
        raise NativeCommandEffectMalformedError("command_effect result does not match the request")
    code = envelope.get("code")
    if envelope.get("status") == "error":
        # A bound refusal is an answer, not an outage: the resident rejected
        # this exact request. Surface its code so callers fail closed on it.
        native_record_resident_success(identity.sha256, guard_home)
        raise NativeCommandEffectRejectedError(code if isinstance(code, str) else "native_command_effect_rejected")
    payload = envelope.get("payload")
    if envelope.get("status") != "ok" or code != "ok" or not isinstance(payload, dict):
        native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_bad_status")
        raise NativeCommandEffectMalformedError("command_effect result has no evaluation payload")
    native_record_resident_success(identity.sha256, guard_home)
    return payload


def command_effect_decide_batch_native(
    items: Sequence[CommandEffectItem],
    *,
    guard_home: Path,
    timeout_seconds: float = 30.0,
    deadline_monotonic: float | None = None,
) -> list[dict[str, object] | NativeCommandEffectRejectedError] | None:
    """Evaluate many commands in few resident round trips (offline corpora).

    One result per item, in order: the evaluation payload, or the bound
    ``NativeCommandEffectRejectedError`` the resident gave that item. ``None``
    means the resident could not service the call and nothing was decided.
    A result that is not bound to its request (schema, id, hash, count or
    order) raises ``NativeCommandEffectMalformedError``. Per-hook callers keep
    using ``command_effect_decide_native``.
    """
    ready = _resident_ready(guard_home, COMMAND_EFFECT_BATCH_FEATURE, timeout_seconds, deadline_monotonic)
    if ready is None:
        return None
    identity, effective_deadline = ready
    requests = [
        _build_request(
            command_text=item.command_text,
            canonical_command=item.canonical_command,
            native_extension_evidence=item.native_extension_evidence,
            control_snapshot=item.control_snapshot,
            compatibility_action_class=item.compatibility_action_class,
            compatibility_reason=item.compatibility_reason,
            workflow_authorization=item.workflow_authorization,
            cwd=item.cwd,
            home_dir=item.home_dir,
        )
        for item in items
    ]
    try:
        hashes = ["sha256:" + _canonical_request_sha256(request) for request in requests]
    except (TypeError, ValueError) as exc:
        raise NativeCommandEffectMalformedError("command_effect request is not JSON data") from exc
    results: list[dict[str, object] | NativeCommandEffectRejectedError] = []
    for start in range(0, len(requests), COMMAND_EFFECT_BATCH_MAX_ITEMS):
        chunk = _batch_chunk(
            identity,
            guard_home,
            requests[start : start + COMMAND_EFFECT_BATCH_MAX_ITEMS],
            hashes[start : start + COMMAND_EFFECT_BATCH_MAX_ITEMS],
            effective_deadline,
        )
        if chunk is None:
            return None
        results.extend(chunk)
    return results


def _batch_chunk(
    identity: NativeRuntimeIdentity,
    guard_home: Path,
    requests: list[dict[str, object]],
    hashes: list[str],
    deadline: float,
) -> list[dict[str, object] | NativeCommandEffectRejectedError] | None:
    global _request_counter
    remaining_seconds = deadline - time.monotonic()
    if remaining_seconds <= 0:
        return None
    batch_id = f"ceb-{_request_counter}"
    _request_counter += 1
    try:
        resident = json.dumps(
            {
                "operation": "command_effect_decide_batch",
                "deadline_budget_ms": max(1, min(9_000, int(remaining_seconds * 1_000))),
                "request": {"schema": _BATCH_REQUEST_SCHEMA, "request_id": batch_id, "items": requests},
            },
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NativeCommandEffectMalformedError("command_effect request is not JSON data") from exc
    if len(resident) > COMMAND_EFFECT_BATCH_MAX_BYTES + _MAX_REQUEST_BYTES // 8:
        return _split_batch(identity, guard_home, requests, hashes, deadline, "native_command_effect_batch_too_large")
    output = native_resident_client_request(
        executable=identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=resident,
        deadline_monotonic=deadline,
    )
    if output is None:
        native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_unavailable")
        return None
    try:
        envelope = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError):
        native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_decode_failed")
        raise NativeCommandEffectMalformedError("command_effect batch result is not valid JSON") from None
    if _native_error(envelope) == "native_overloaded":
        native_record_overload(identity.sha256, guard_home)
        return None
    if isinstance(envelope, dict) and isinstance(envelope.get("error"), str) and "schema" not in envelope:
        native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_resident_error")
        return None
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != _BATCH_RESULT_SCHEMA
        or envelope.get("request_id") != batch_id
    ):
        native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_schema_mismatch")
        raise NativeCommandEffectMalformedError("command_effect batch result does not match the request")
    code = envelope.get("code")
    if envelope.get("status") == "error":
        native_record_resident_success(identity.sha256, guard_home)
        refusal = code if isinstance(code, str) else "native_command_effect_rejected"
        if refusal in _BATCH_SPLITTABLE_CODES and len(requests) > 1:
            return _split_batch(identity, guard_home, requests, hashes, deadline, refusal)
        raise NativeCommandEffectRejectedError(refusal)
    answers = envelope.get("items")
    if envelope.get("status") != "ok" or code != "ok" or not isinstance(answers, list) or len(answers) != len(requests):
        native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_bad_status")
        raise NativeCommandEffectMalformedError("command_effect batch result has the wrong item count")
    outcomes: list[dict[str, object] | NativeCommandEffectRejectedError] = []
    for request, expected_hash, answer in zip(requests, hashes, answers, strict=True):
        if (
            not isinstance(answer, dict)
            or answer.get("schema") != _RESULT_SCHEMA
            or answer.get("request_id") != request["request_id"]
            or answer.get("request_sha256") != expected_hash
        ):
            native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_schema_mismatch")
            raise NativeCommandEffectMalformedError("command_effect batch item does not match its request")
        item_code = answer.get("code")
        if answer.get("status") == "error":
            outcomes.append(
                NativeCommandEffectRejectedError(
                    item_code if isinstance(item_code, str) else "native_command_effect_rejected"
                )
            )
            continue
        payload = answer.get("payload")
        if answer.get("status") != "ok" or item_code != "ok" or not isinstance(payload, dict):
            native_record_resident_failure(identity.sha256, guard_home, reason="native_command_effect_bad_status")
            raise NativeCommandEffectMalformedError("command_effect batch item has no evaluation payload")
        outcomes.append(payload)
    native_record_resident_success(identity.sha256, guard_home)
    return outcomes


def _split_batch(
    identity: NativeRuntimeIdentity,
    guard_home: Path,
    requests: list[dict[str, object]],
    hashes: list[str],
    deadline: float,
    refusal: str,
) -> list[dict[str, object] | NativeCommandEffectRejectedError] | None:
    if len(requests) <= 1:
        raise NativeCommandEffectRejectedError(refusal)
    middle = len(requests) // 2
    outcomes: list[dict[str, object] | NativeCommandEffectRejectedError] = []
    for part_requests, part_hashes in ((requests[:middle], hashes[:middle]), (requests[middle:], hashes[middle:])):
        part = _batch_chunk(identity, guard_home, part_requests, part_hashes, deadline)
        if part is None:
            return None
        outcomes.extend(part)
    return outcomes


def wire_canonical_command(canonical: Mapping[str, object]) -> dict[str, object]:
    """Add the wire-only parser profile to a ``CanonicalCommand.to_dict()`` model."""
    wire = dict(canonical)
    if "parser_profile" not in wire:
        wire["parser_profile"] = _WRAPPER_PARSER_PROFILE if wire.get("wrapper_chain") else _PARSER_PROFILE
    return wire


__all__ = [
    "COMMAND_EFFECT_BATCH_FEATURE",
    "COMMAND_EFFECT_BATCH_MAX_BYTES",
    "COMMAND_EFFECT_BATCH_MAX_ITEMS",
    "COMMAND_EFFECT_FEATURE",
    "NATIVE_COMMAND_CONTROL_BINDING_SCHEMA",
    "CommandEffectItem",
    "NativeCommandEffectMalformedError",
    "NativeCommandEffectRejectedError",
    "command_effect_decide_batch_native",
    "command_effect_decide_native",
    "wire_canonical_command",
]
