"""Shared lifecycle for resident operations that return a bound, strictly shaped reply.

Hook decisions and daemon route policy both ask the resident a question and
accept only a reply that is bound to the request (schema, request id and
canonical digest), carries an ``ok`` status and passes the caller's payload
validation. Anything else raises the operation's own error so callers fail
closed. Only the operation constants and the error type differ between them.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success


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


def record_resident(guard_home: Path, *, success: bool, reason: str = "") -> None:
    """Record resident health only once a reply has passed binding and validation.

    The shared transport would otherwise reset the failure streak on every
    reply that parses, so a resident that keeps sending unusable replies would
    never open the circuit.
    """

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
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    """Ask the resident and return its payload once ``validate`` accepts it.

    ``timeout_seconds`` bounds the resident round trip and defaults to the
    operation's own deadline. A caller that already spent part of that budget
    waiting passes the remainder; a remainder that is not positive fails closed.

    ``transport`` is the caller's resident request function. Resident health is
    recorded only after binding and payload validation, so a resident that
    keeps sending well-bound but malformed payloads opens the circuit instead
    of resetting the failure streak on every reply.
    """

    budget = spec.timeout_seconds if timeout_seconds is None else timeout_seconds
    if budget <= 0:
        raise spec.fail(spec.unavailable)
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
    response = transport(
        operation=spec.operation,
        request=request,
        guard_home=home,
        timeout_seconds=budget,
        required_feature=spec.feature,
        response_schema=spec.result_schema,
        record_success=False,
    )
    if response is None:
        raise spec.fail(spec.unavailable)
    if not isinstance(response, dict):
        record_resident(home, success=False, reason=f"{spec.prefix}_unbound")
        raise spec.fail(spec.unavailable)
    if (
        response.get("schema") != spec.result_schema
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        record_resident(home, success=False, reason=f"{spec.prefix}_unbound")
        raise spec.fail(spec.unavailable)
    status, code = response.get("status"), response.get("code")
    if status == "error":
        record_resident(home, success=True)
        raise spec.fail(code if isinstance(code, str) and spec.code_pattern().fullmatch(code) else spec.unavailable)
    payload = response.get("payload")
    if status != "ok" or code != "ok" or not isinstance(payload, dict) or payload.get("kind") != query.get("kind"):
        record_resident(home, success=False, reason=f"{spec.prefix}_bad_status")
        raise spec.fail(spec.unavailable)
    try:
        validate(payload)
    except spec.error:
        record_resident(home, success=False, reason=f"{spec.prefix}_invalid")
        raise
    record_resident(home, success=True)
    return payload
