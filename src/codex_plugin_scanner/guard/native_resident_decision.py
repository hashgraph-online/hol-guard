"""Shared lifecycle for resident operations that return a bound, strictly shaped reply.

Hook decisions and daemon route policy both ask the resident a question and
accept only a reply that is bound to the request (schema, request id and
canonical digest), carries an ``ok`` status and passes the caller's payload
validation. Anything else raises the operation's own error so callers fail
closed. Only the operation constants and the error type differ between them.

:func:`bound_resident_call` is the same round trip for the bridges that frame
their own request: it gates on the runtime's features, encodes and bounds the
envelope, sends it, and returns the reply only once it is bound to the request.
Every failure raises the bridge's error with a code under the bridge's prefix.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import (
    _COLD_START_ALLOWANCE_SECONDS,
    _canonical_request_sha256,
    _resolve_digest_home,
    ensure_resident_prerequisite,
)
from .native_resident_client import native_resident_client_ready, native_resident_client_request
from .native_resident_prerequisite_reason import prerequisite_unavailable_code
from .native_runtime import NativeRuntimeStatus, _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
    native_runtime_health_snapshot,
)

_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_MAX_DEADLINE_BUDGET_MS = 9_000


@dataclass(frozen=True, slots=True)
class ResidentOperation:
    """Constants of one resident operation; ``prefix`` namespaces every error code."""

    operation: str
    feature: str
    prefix: str
    request_schema: str
    result_schema: str
    request_id_prefix: str
    timeout_seconds: float
    error: type[RuntimeError]
    # Optional services keep their own native health and cannot change the
    # shared authority transport circuit. This never skips reply validation.
    shared_resident_health: bool = True

    @property
    def unavailable(self) -> str:
        return f"{self.prefix}_unavailable"

    @property
    def invalid(self) -> str:
        return f"{self.prefix}_payload_invalid"

    def fail(self, code: str) -> RuntimeError:
        return self.error(code)

    def code_pattern(self) -> re.Pattern[str]:
        return re.compile(rf"^{re.escape(self.prefix)}_[a-z_]{{1,64}}$")


def shape_fields(value: object, fields: Mapping[str, Any], invalid: Callable[[], RuntimeError]) -> dict[str, Any]:
    """Return ``value`` when it is a dict with exactly ``fields`` of the given types."""

    if not isinstance(value, dict) or set(value) != set(fields):
        raise invalid()
    for key, kinds in fields.items():
        item = value[key]
        allowed = kinds if isinstance(kinds, tuple) else (kinds,)
        if isinstance(item, bool) and bool not in allowed:
            raise invalid()
        if not isinstance(item, allowed):
            raise invalid()
    return value


def record_resident(
    guard_home: Path,
    *,
    success: bool,
    reason: str = "",
    status: NativeRuntimeStatus | None = None,
) -> None:
    """Record resident health only once a reply has passed binding and validation.

    The shared transport would otherwise reset the failure streak on every
    reply that parses, so a resident that keeps sending unusable replies would
    never open the circuit.
    """

    if status is None:
        status = native_runtime_status()
    if status.identity is None:
        return
    if success:
        native_record_resident_success(status.identity.sha256, guard_home)
    else:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=reason)


def resident_decide(
    spec: ResidentOperation,
    transport: Callable[..., dict[str, Any] | None],
    query: Mapping[str, object],
    guard_home: Path | None,
    validate: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    """Ask the resident and return its payload once ``validate`` accepts it.

    ``transport`` is the caller's resident request function. Resident health is
    recorded only after binding and payload validation, so a resident that
    keeps sending well-bound but malformed payloads opens the circuit instead
    of resetting the failure streak on every reply.
    """

    try:
        home = _resolve_digest_home(guard_home)
    except (OSError, RuntimeError, ValueError):
        raise spec.fail(f"{spec.prefix}_home_unbound") from None
    request: dict[str, object] = {
        "schema": spec.request_schema,
        "request_id": f"{spec.request_id_prefix}-{uuid4().hex}",
        "query": dict(query),
    }
    try:
        if not ensure_resident_prerequisite(home):
            raise spec.fail(spec.unavailable)
        digest = "sha256:" + _canonical_request_sha256(request)
    except (OSError, TypeError, ValueError):
        raise spec.fail(f"{spec.prefix}_request_invalid") from None
    # This status is a starting point for the transport, not a gate. The daemon
    # route transport pins the runtime for the duration of its own call and
    # re-resolves the status under that pin, so every read outside the transport
    # -- including this one -- reports the ambient mode. Refusing here on that
    # ambient read, as an entry gate would, fails a pinned route closed; the
    # transport applies the protocol and feature gate against the pinned status.
    runtime_status = native_runtime_status()
    response = transport(
        operation=spec.operation,
        request=request,
        guard_home=home,
        timeout_seconds=spec.timeout_seconds,
        required_feature=spec.feature,
        response_schema=spec.result_schema,
        record_success=False,
        status=runtime_status,
        **({"record_resilience": False} if not spec.shared_resident_health else {}),
    )
    if response is None:
        raise spec.fail(spec.unavailable)
    if not isinstance(response, dict):
        if spec.shared_resident_health:
            record_resident(home, success=False, reason=f"{spec.prefix}_unbound", status=runtime_status)
        raise spec.fail(spec.unavailable)
    if (
        response.get("schema") != spec.result_schema
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        if spec.shared_resident_health:
            record_resident(home, success=False, reason=f"{spec.prefix}_unbound", status=runtime_status)
        raise spec.fail(spec.unavailable)
    status, code = response.get("status"), response.get("code")
    if status == "error":
        if spec.shared_resident_health:
            record_resident(home, success=True, status=runtime_status)
        raise spec.fail(code if isinstance(code, str) and spec.code_pattern().fullmatch(code) else spec.unavailable)
    payload = response.get("payload")
    if status != "ok" or code != "ok" or not isinstance(payload, dict) or payload.get("kind") != query.get("kind"):
        if spec.shared_resident_health:
            record_resident(home, success=False, reason=f"{spec.prefix}_bad_status", status=runtime_status)
        raise spec.fail(spec.unavailable)
    try:
        validate(payload)
    except spec.error:
        if spec.shared_resident_health:
            record_resident(home, success=False, reason=f"{spec.prefix}_invalid", status=runtime_status)
        raise
    if spec.shared_resident_health:
        record_resident(home, success=True, status=runtime_status)
    return payload


class ResidentCallError(ValueError):
    """A bridge that answers ``None`` or a denial instead of raising its own error."""


@dataclass(frozen=True, slots=True)
class BoundCall:
    """Constants of one resident operation whose bridge frames its own request.

    ``prefix`` namespaces every error code. ``bound_canonical`` also bounds the
    ASCII-escaped canonical request, which Rust measures and which can exceed
    the UTF-8 envelope for non-ASCII text. ``refusal`` is raised for a request
    the encoder or a healthy resident refused, when the bridge tells those
    apart from an outage. ``check_circuit`` skips the call while the shared
    availability circuit is open. ``clock_after_prerequisite`` gives the
    resident its whole transport window once setup is done, for bridges that
    never charged provisioning to it.
    """

    operation: str
    feature: str
    prefix: str
    result_schema: str
    max_request_bytes: int
    timeout_seconds: float
    error: type[ValueError] = ResidentCallError
    refusal: type[ValueError] | None = None
    sha_prefix: str = "sha256:"
    bound_canonical: bool = False
    check_circuit: bool = False
    transport_failure: str = "resident_unavailable"
    clock_after_prerequisite: bool = False

    @property
    def invalid(self) -> str:
        return f"{self.prefix}_result_invalid"

    def refuse(self, code: str) -> ValueError:
        return (self.refusal or self.error)(code)


@dataclass(frozen=True, slots=True)
class BoundReply:
    """A reply bound to its request; resident health is still unrecorded."""

    envelope: dict[str, Any]
    spec: BoundCall
    identity: str
    guard_home: Path

    def healthy(self) -> None:
        native_record_resident_success(self.identity, self.guard_home)

    def fail(self, code: str | None = None) -> ValueError:
        """Record an unusable reply and return the error to raise."""

        native_record_resident_failure(self.identity, self.guard_home, reason=self.spec.invalid)
        return self.spec.error(code or self.spec.invalid)

    def payload(self, key: str | None = "payload", validate: Callable[[Any], Any] | None = None) -> Any:
        """The ``ok`` reply's ``key`` object (the whole reply for ``None``), recorded healthy.

        A bound ``error`` carrying the bridge's own code is the resident
        refusing the request: with a ``refusal`` type the resident stays
        healthy, otherwise the code is raised as an unusable reply.
        """

        envelope = self.envelope
        code = envelope.get("code")
        prefixed = code if isinstance(code, str) and code.startswith(f"{self.spec.prefix}_") else None
        if self.spec.refusal is not None and envelope.get("status") == "error" and prefixed is not None:
            # A bound refusal is the resident answering, not an outage, so a bad
            # request can never open the shared availability circuit.
            self.healthy()
            raise self.spec.refusal(prefixed)
        value = envelope if key is None else envelope.get(key)
        if envelope.get("status") != "ok" or code != "ok" or not isinstance(value, dict):
            raise self.fail(prefixed)
        if validate is not None:
            try:
                value = validate(value)
            except self.spec.error:
                native_record_resident_failure(self.identity, self.guard_home, reason=self.spec.invalid)
                raise
        self.healthy()
        return value


def bound_resident_call(
    spec: BoundCall,
    request: dict[str, Any],
    *,
    guard_home: Path | None = None,
    status: NativeRuntimeStatus | None = None,
    deadline_monotonic: float | None = None,
    timeout_seconds: float | None = None,
    extra_features: tuple[str, ...] = (),
    cold_start: bool = False,
) -> BoundReply:
    """Send ``request`` to the resident and return its reply once bound to it.

    ``status`` defaults to a fresh runtime status read within the deadline.
    ``cold_start`` widens the budget while the resident client is not ready.
    A transport failure that only ran out the caller's shorter deadline is not
    recorded against the resident.
    """

    started_at = time.monotonic()
    local_deadline = started_at + (spec.timeout_seconds if timeout_seconds is None else timeout_seconds)
    deadline = local_deadline if deadline_monotonic is None else min(local_deadline, deadline_monotonic)
    unavailable = f"{spec.prefix}_unavailable"
    if deadline <= started_at:
        raise spec.error(unavailable)
    if status is None:
        status = native_runtime_status(deadline_monotonic=deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or any(
            feature not in status.capabilities.features
            for feature in (_RESIDENT_PROTOCOL_FEATURE, spec.feature, *extra_features)
        )
    ):
        raise spec.error(unavailable)
    identity = status.identity.sha256
    home = _resolve_digest_home(guard_home)
    if spec.check_circuit and native_runtime_health_snapshot(identity, home).circuit_open:
        raise spec.error(unavailable)
    try:
        prerequisite = ensure_resident_prerequisite(home)
    except Exception as error:
        raise spec.error(f"{spec.prefix}_prerequisite_unavailable") from error
    if not prerequisite:
        raise spec.error(prerequisite_unavailable_code(f"{spec.prefix}_prerequisite_unavailable", home))
    if spec.clock_after_prerequisite:
        # Runtime status and provisioning ran before this point. These bridges used
        # to start their allowance here, so charging that setup to the transport
        # would hand the resident a shorter window than the operation is budgeted.
        started_at = time.monotonic()
        local_deadline = started_at + (spec.timeout_seconds if timeout_seconds is None else timeout_seconds)
        deadline = local_deadline if deadline_monotonic is None else min(local_deadline, deadline_monotonic)
    if cold_start and not native_resident_client_ready(status.identity.path, home):
        local_deadline += _COLD_START_ALLOWANCE_SECONDS
        deadline = local_deadline if deadline_monotonic is None else min(local_deadline, deadline_monotonic)
    remaining_ms = int((deadline - time.monotonic()) * 1_000)
    if remaining_ms <= 0:
        raise spec.error(unavailable)
    # The budget is the call's own allowance; only a caller deadline shortens it.
    budget_ms = min(_MAX_DEADLINE_BUDGET_MS, round((local_deadline - started_at) * 1_000))
    if deadline_monotonic is not None:
        budget_ms = min(budget_ms, remaining_ms)
    try:
        request_sha256 = spec.sha_prefix + _canonical_request_sha256(request)
        canonical_size = (
            len(json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False))
            if spec.bound_canonical
            else 0
        )
        envelope = json.dumps(
            {"operation": spec.operation, "deadline_budget_ms": budget_ms, "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        # Lone surrogates or NaN cannot cross a strict JSON transport.
        raise spec.refuse(f"{spec.prefix}_component_unencodable") from error
    if max(len(envelope), canonical_size) > spec.max_request_bytes:
        raise spec.refuse(f"{spec.prefix}_request_too_large")
    try:
        output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=home,
            environment=_isolated_environment(),
            payload=envelope,
            deadline_monotonic=min(deadline, time.monotonic() + budget_ms / 1_000),
        )
    except Exception:
        # RuntimeError (thread start), OSError, timeouts: all one typed failure.
        output = None
    if output is None:
        reason = f"{spec.prefix}_{spec.transport_failure}"
        caller_budget_expired = (
            deadline_monotonic is not None
            and deadline_monotonic < local_deadline
            and time.monotonic() >= deadline_monotonic
        )
        if not caller_budget_expired:
            native_record_resident_failure(identity, home, reason=reason)
        raise spec.error(reason)
    reply = BoundReply({}, spec, identity, home)
    try:
        decoded = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise reply.fail() from error
    error_code = _native_error(decoded)
    if error_code is not None:
        if error_code == "native_overloaded":
            native_record_overload(identity, home)
        else:
            native_record_resident_failure(identity, home, reason=error_code)
        raise spec.error(error_code)
    if (
        not isinstance(decoded, dict)
        or decoded.get("schema") != spec.result_schema
        or decoded.get("request_id") != request.get("request_id")
        or decoded.get("request_sha256") != request_sha256
    ):
        raise reply.fail()
    return BoundReply(decoded, spec, identity, home)
