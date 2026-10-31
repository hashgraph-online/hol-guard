"""Typed client for the native ``guard run`` authority owner; no Python verdicts.

Rust owns the authority transforms of the guard-run flow: composing runtime
detector authority, binding it into per-artifact decisions, recording terminal
approval-claim failures, classifying saved claims, trusted request overrides,
the pre/post-claim launch-authority signature, the final authority gate and the
policy-shadow comparison. Python ships typed inputs, binds each answer to its
request by ``request_id`` and canonical ``request_sha256``, and merges the
returned patch. Any transport, scope or binding failure raises
``NativeRunnerAuthorityError`` (a ``ValueError``); callers treat it as a refusal
to launch. Nothing here ever computes an action, reason or signature locally.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_context import (
    _native_runtime_status_memo,
    _resolve_digest_home,
)
from .native_resident_decision import BoundCall, bound_resident_call

_FEATURE = "runner-authority-v1"
_REQUEST_SCHEMA = "guard-runner-authority-request.v1"
_RESULT_SCHEMA = "guard-runner-authority-result.v1"
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# The authority answer gates a launch, so a slow resident fails closed rather
# than degrading; the budget is generous but bounded below the resident cap.
_TIMEOUT_SECONDS = 5.0


class NativeRunnerAuthorityError(ValueError):
    """The native owner could not supply a bound, typed runner-authority answer."""


class NativeRunnerAuthorityRefusalError(NativeRunnerAuthorityError):
    """A healthy owner, or the bounded encoder, refused invalid input."""


_CALL = BoundCall(
    operation="runner_authority",
    feature=_FEATURE,
    prefix="native_runner_authority",
    result_schema=_RESULT_SCHEMA,
    max_request_bytes=_MAX_REQUEST_BYTES,
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeRunnerAuthorityError,
    refusal=NativeRunnerAuthorityRefusalError,
    sha_prefix="",
    clock_after_prerequisite=True,
)


def native_runner_authority(
    kind: str,
    args: Mapping[str, Any],
    guard_home: Path | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    """Run one authority ``kind`` in the resident and return its bound payload.

    ``timeout_seconds`` widens the per-call budget for file-heavy kinds; the
    envelope deadline stays bounded by the resident call cap.
    """

    guard_home = _resolve_digest_home(guard_home)
    if kind in {
        "projection_surfaces_batch",
        "projection_artifact_surfaces",
    }:
        guard_home = _projection_carrier_home(guard_home)
    request: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": uuid.uuid4().hex,
        "guard_home": str(guard_home),
        "kind": kind,
        "args": dict(args),
    }
    reply = bound_resident_call(
        _CALL,
        request,
        guard_home=guard_home,
        status=_native_runtime_status_memo(),
        timeout_seconds=timeout_seconds,
        cold_start=True,
    )
    return reply.payload()


def _projection_carrier_home(requested: Path) -> Path:
    """Pure field projection prefers an initialized carrier over signing-state creation.

    When neither the requested home nor the default carrier is initialized, the
    requested home is returned so the resident prerequisite provisions it, as
    the write path that follows would do anyway.
    """
    from .native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME, NATIVE_RUNTIME_STATE_DIRECTORY

    key = Path(NATIVE_RUNTIME_STATE_DIRECTORY) / NATIVE_POLICY_VERIFIER_KEY_NAME
    if os.path.lexists(requested / key):
        return requested
    carrier = _resolve_digest_home(None)
    return carrier if os.path.lexists(carrier / key) else requested
