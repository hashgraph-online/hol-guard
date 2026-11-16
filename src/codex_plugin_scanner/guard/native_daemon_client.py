"""Thin adapter over the native daemon client (`daemon-client --stdin`).

The native runtime owns the loopback HTTP exchange with the local Guard
daemon: the address check, the single deadline, the size cap, the truncation
retry and the JSON decode. This module sends one request per call and maps the
classified reply onto the exceptions the CLI already handles.
"""

from __future__ import annotations

import json
import math
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypeGuard, cast

from .native_daemon_manage import (
    clear_guard_daemon_state,
    ensure_guard_daemon,
    load_guard_daemon_auth_token,
    load_guard_daemon_url,
    load_running_guard_daemon_identity,
)
from .runtime.extension_control_limits import MAX_DAEMON_CATALOG_RESPONSE_BYTES, MAX_DAEMON_GET_RESPONSE_BYTES

_FEATURE: Final = "daemon-client-v1"
_SCHEMA: Final = "daemon-client.v1"
# The runtime enforces the request deadline; this only reaps a stuck process.
_PROCESS_MARGIN_S: Final = 5.0
_HEALTH_PROBE_DEADLINE_SECONDS: Final = 1.0
_DEFAULT_REQUEST_TIMEOUT_S: Final = 5.0
_STATUS_REQUEST_TIMEOUT_S: Final = 0.25
_DASHBOARD_SESSION_TIMEOUT_S: Final = 1.0
_MAX_GET_RESPONSE_BYTES: Final = MAX_DAEMON_GET_RESPONSE_BYTES

# How long the client waits for an extension-control preview or apply. The
# daemon answers only after the resident calls it makes have answered, so each
# budget is the sum of the deadlines of the resident calls the request can make
# in turn. ``tests/test_guard_extension_control_preview_shape.py`` pins each one
# to the module that grants it.
AUTHORITY_ROUND_TIMEOUT_S: Final = 10.0
AUTHORITY_READ_ROUNDS: Final = 6
AUTHORITY_READ_TIMEOUT_S: Final = AUTHORITY_ROUND_TIMEOUT_S * AUTHORITY_READ_ROUNDS
COMPOSE_TIMEOUT_S: Final = 5.0
SEMANTIC_PREVIEW_TIMEOUT_S: Final = 15.0
MUTATION_TIMEOUT_S: Final = 5.0
PREVIEW_MUTATION_ASKS: Final = 5
APPLY_MUTATION_ASKS: Final = 1
COMMIT_PLAN_ROUNDS: Final = 4
TRANSPORT_MARGIN_S: Final = 10.0
PREVIEW_REQUEST_TIMEOUT_S: Final = (
    2 * AUTHORITY_READ_TIMEOUT_S
    + PREVIEW_MUTATION_ASKS * MUTATION_TIMEOUT_S
    + COMPOSE_TIMEOUT_S
    + SEMANTIC_PREVIEW_TIMEOUT_S
    + TRANSPORT_MARGIN_S
)
CATALOG_V2_TIMEOUT_S: Final = 5.0
CATALOG_V2_TRAVERSAL_TIMEOUT_S: Final = 60.0
APPLY_AUTHORITY_READS: Final = 4
APPLY_REQUEST_TIMEOUT_S: Final = (
    APPLY_AUTHORITY_READS * AUTHORITY_READ_TIMEOUT_S
    + APPLY_MUTATION_ASKS * MUTATION_TIMEOUT_S
    + SEMANTIC_PREVIEW_TIMEOUT_S
    + COMMIT_PLAN_ROUNDS * AUTHORITY_ROUND_TIMEOUT_S
    + TRANSPORT_MARGIN_S
)


class GuardDaemonRequestError(RuntimeError):
    """Raised with stable daemon error metadata for caller recovery."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: str | None = None,
        recovery_action: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.recovery_action = recovery_action


class GuardDaemonTransportError(GuardDaemonRequestError):
    """Raised when the Guard daemon request fails due to transport issues."""


class GuardDaemonTimeoutError(GuardDaemonTransportError):
    """Raised when a bounded Guard daemon request exceeds its deadline."""


class GuardDaemonResponseSchemaError(GuardDaemonRequestError):
    """Raised when the daemon response is not valid JSON object data."""


class CatalogV2UnsupportedError(GuardDaemonRequestError):
    """The daemon does not serve the v2 catalog read model; v1 fallback is allowed."""


class CatalogTraversalError(GuardDaemonRequestError):
    """A multi-page catalog traversal could not be verified as complete and consistent."""


@dataclass(frozen=True, slots=True)
class CatalogTraversal:
    snapshot_id: str
    native_catalog_digest: str
    total_count: int
    items: list[dict[str, object]]


@dataclass(frozen=True, slots=True)
class ConditionalResponse:
    """A conditional GET: `payload` is None when the daemon answered 304."""

    status: int
    etag: str | None
    payload: dict[str, object] | None
    size: int


def _is_string_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, Mapping) and all(isinstance(key, str) for key in value)


def _runtime_path() -> str:
    from .native_recovery_store import recovery_runtime_path

    try:
        return recovery_runtime_path(_FEATURE)
    except RuntimeError as error:
        raise GuardDaemonTransportError("Guard daemon client needs the native runtime") from error


def _exchange(daemon_url: str, auth: str, op: str, timeout: float, **fields: object) -> dict[str, object]:
    if not math.isfinite(timeout) or timeout <= 0.0:
        raise GuardDaemonTimeoutError("Guard daemon request timed out")
    request: dict[str, object] = {
        "schema": _SCHEMA,
        "op": op,
        "daemon_url": daemon_url,
        "auth": auth,
        "timeout_ms": max(1, math.ceil(timeout * 1000)),
    }
    request.update({key: value for key, value in fields.items() if value is not None})
    try:
        completed = subprocess.run(
            [_runtime_path(), "daemon-client", "--stdin"],
            input=json.dumps(request).encode("utf-8"),
            capture_output=True,
            timeout=timeout + _PROCESS_MARGIN_S,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise GuardDaemonTimeoutError("Guard daemon request timed out") from error
    except OSError as error:
        raise GuardDaemonTransportError("Guard daemon request failed") from error
    try:
        reply = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise GuardDaemonTransportError("Guard daemon client sent an invalid reply") from error
    if not _is_string_object_dict(reply):
        raise GuardDaemonTransportError("Guard daemon client sent an invalid reply")
    return reply


def _raise_failure(reply: dict[str, object]) -> None:
    kind = reply.get("error")
    if kind is None:
        return
    message = str(reply.get("message") or "Guard daemon request failed")
    status = reply.get("status")
    status = status if type(status) is int else None
    if kind == "http":
        code = reply.get("code")
        action = reply.get("recovery_action")
        raise GuardDaemonRequestError(
            message,
            status=status,
            code=code if isinstance(code, str) else None,
            recovery_action=action if isinstance(action, str) else None,
        )
    if kind in {"unsupported", "traversal"}:
        code = reply.get("code")
        error_type = CatalogV2UnsupportedError if kind == "unsupported" else CatalogTraversalError
        raise error_type(message, status=status, code=code if isinstance(code, str) else None)
    if kind == "timeout":
        raise GuardDaemonTimeoutError(message)
    if kind == "schema":
        raise GuardDaemonResponseSchemaError(message)
    raise GuardDaemonTransportError(message)


def _object(reply: dict[str, object]) -> dict[str, object]:
    _raise_failure(reply)
    payload = reply.get("ok")
    if not _is_string_object_dict(payload):
        raise GuardDaemonResponseSchemaError("Guard daemon response schema is invalid")
    return payload


def read_guard_health_details(
    daemon_url: str,
    auth_token: str,
    *,
    timeout: float | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, object] | None:
    """Read bounded authenticated health details over direct, non-redirecting loopback IPC."""
    import time

    try:
        budget = _HEALTH_PROBE_DEADLINE_SECONDS if timeout is None else float(timeout)
        if deadline_monotonic is not None:
            if isinstance(deadline_monotonic, bool) or not math.isfinite(deadline_monotonic):
                return None
            budget = min(budget, deadline_monotonic - time.monotonic())
        if not math.isfinite(budget) or budget <= 0.0:
            return None
        reply = _exchange(daemon_url, auth_token, "health_details", budget)
    except (GuardDaemonRequestError, TypeError, ValueError, OverflowError):
        return None
    payload = reply.get("ok")
    return cast(dict[str, object], payload) if _is_string_object_dict(payload) else None


class GuardSurfaceDaemonClient:
    """Small authenticated client for the local Guard daemon."""

    def __init__(self, daemon_url: str, auth_token: str) -> None:
        self.daemon_url = daemon_url.rstrip("/")
        self.auth_token = auth_token

    def start_session(
        self,
        *,
        harness: str,
        surface: str,
        workspace: str | None,
        client_name: str,
        client_title: str | None,
        client_version: str | None,
        capabilities: list[str],
    ) -> dict[str, object]:
        return self._post(
            "/v1/sessions/start",
            {
                "harness": harness,
                "surface": surface,
                "workspace": workspace,
                "client_name": client_name,
                "client_title": client_title,
                "client_version": client_version,
                "capabilities": capabilities,
            },
        )

    def start_operation(
        self,
        *,
        session_id: str,
        operation_type: str,
        harness: str,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return self._post(
            "/v1/operations/start",
            {
                "session_id": session_id,
                "operation_type": operation_type,
                "harness": harness,
                "metadata": metadata or {},
            },
        )

    def queue_blocked_operation(
        self,
        *,
        session_id: str,
        operation_type: str,
        harness: str,
        metadata: dict[str, object],
        detection: dict[str, object],
        evaluation: dict[str, object],
        approval_center_url: str,
        approval_surface_policy: str,
        open_key: str | None = None,
        redaction_level: str = "full",
    ) -> dict[str, object]:
        return self._post(
            "/v1/operations/block",
            {
                "session_id": session_id,
                "operation_type": operation_type,
                "harness": harness,
                "metadata": metadata,
                "detection": detection,
                "evaluation": evaluation,
                "approval_center_url": approval_center_url,
                "approval_surface_policy": approval_surface_policy,
                "open_key": open_key,
                "redaction_level": redaction_level,
            },
        )

    def update_operation_status(
        self,
        *,
        operation_id: str,
        status: str,
        approval_request_ids: list[str] | None = None,
    ) -> dict[str, object]:
        response = self._post(
            f"/v1/operations/{operation_id}/status",
            {"status": status, "approval_request_ids": approval_request_ids or []},
        )
        operation = response.get("operation")
        return dict(operation) if _is_string_object_dict(operation) else response

    def extension_control_catalog(self) -> dict[str, object]:
        # The legacy full catalog enumerates every built-in extension and has its own local budget.
        return self._get(
            "/v1/extension-controls/catalog",
            timeout=_DEFAULT_REQUEST_TIMEOUT_S,
            max_bytes=MAX_DAEMON_CATALOG_RESPONSE_BYTES,
        )

    def effective_extension_controls(self) -> dict[str, object]:
        return self._get("/v1/extension-controls/effective", timeout=_DEFAULT_REQUEST_TIMEOUT_S)

    def refresh_extension_controls(self) -> dict[str, object]:
        return self._post("/v1/extension-controls/refresh", {})

    def refresh_command_queue_worker(self) -> dict[str, object]:
        return self._post("/v1/command-queue/worker/refresh", {})

    def recover_extension_control_authority(self, payload: dict[str, object]) -> dict[str, object]:
        return self._post("/v1/extension-controls/recover-authority", payload)

    def acknowledge_degraded_extension_controls(self, payload: dict[str, object]) -> dict[str, object]:
        return self._post("/v1/extension-controls/acknowledge-degraded", payload)

    def preview_extension_controls(self, payload: dict[str, object]) -> dict[str, object]:
        return self._post(
            "/v1/extension-controls/preview",
            payload,
            timeout=PREVIEW_REQUEST_TIMEOUT_S,
            max_bytes=MAX_DAEMON_CATALOG_RESPONSE_BYTES,
        )

    def inspect_command(self, payload: dict[str, object]) -> dict[str, object]:
        return self._post("/v1/extension-controls/inspect", payload)

    def apply_extension_controls(self, payload: dict[str, object]) -> dict[str, object]:
        return self._post(
            "/v1/extension-controls/apply",
            payload,
            timeout=APPLY_REQUEST_TIMEOUT_S,
            max_bytes=MAX_DAEMON_CATALOG_RESPONSE_BYTES,
        )

    def containment_health(self) -> dict[str, object]:
        response = self._get("/v1/runtime/containment-health", timeout=5.0)
        value = response.get("containment_health")
        if not _is_string_object_dict(value):
            raise GuardDaemonRequestError("Guard daemon returned invalid containment health")
        return value

    def network_status(self) -> dict[str, object]:
        """Read current network protection truth without starting the daemon."""

        return self._get("/v1/network/status", timeout=_STATUS_REQUEST_TIMEOUT_S)

    def dashboard_session_capabilities(self, *, timeout: float = _DASHBOARD_SESSION_TIMEOUT_S) -> dict[str, object]:
        """Seed a dashboard session, initialize the surface, then read capabilities with the refreshed session."""

        if timeout <= 0.0:
            raise GuardDaemonTimeoutError("Guard daemon dashboard session timed out")
        return _object(_exchange(self.daemon_url, self.auth_token, "dashboard_capabilities", timeout))

    def resolve_policy_decision(self, payload: dict[str, object]) -> dict[str, object]:
        return self._post("/v1/policy/resolve", payload)

    def claim_policy_decision(self, payload: dict[str, object]) -> bool:
        response = self._post("/v1/policy/claim", payload)
        return response.get("claimed") is True

    def conditional_get(
        self,
        path: str,
        *,
        if_none_match: str | None,
        timeout: float,
        max_bytes: int,
    ) -> ConditionalResponse:
        """One GET that distinguishes 200 from 304 and reports the ETag."""

        reply = _exchange(
            self.daemon_url,
            self.auth_token,
            "request",
            timeout,
            method="GET",
            path=path,
            max_bytes=max_bytes,
            if_none_match=if_none_match,
        )
        etag = reply.get("etag")
        etag = etag if isinstance(etag, str) else None
        if reply.get("not_modified") is True:
            return ConditionalResponse(304, etag, None, 0)
        payload = _object(reply)
        size = reply.get("size")
        return ConditionalResponse(200, etag, payload, size if type(size) is int else 0)

    def catalog_get(self, route: str, *, timeout: float = CATALOG_V2_TIMEOUT_S) -> dict[str, object]:
        """One bounded v2 catalog representation (ADR 0014)."""

        return _object(_exchange(self.daemon_url, self.auth_token, "catalog_get", timeout, route=route))

    def catalog_traverse(
        self,
        route: str,
        *,
        item_key: str,
        params: dict[str, str] | None = None,
        timeout: float = CATALOG_V2_TRAVERSAL_TIMEOUT_S,
    ) -> CatalogTraversal:
        """Every page of one v2 catalog resource, verified by the native client."""

        payload = _object(
            _exchange(
                self.daemon_url,
                self.auth_token,
                "catalog_traverse",
                timeout,
                route=route,
                item_key=item_key,
                params=params or None,
            )
        )
        snapshot_id = payload.get("snapshot_id")
        digest = payload.get("native_catalog_digest")
        total_count = payload.get("total_count")
        items = payload.get("items")
        if (
            not isinstance(snapshot_id, str)
            or not isinstance(digest, str)
            or type(total_count) is not int
            or not isinstance(items, list)
            or not all(_is_string_object_dict(item) for item in items)
        ):
            raise GuardDaemonResponseSchemaError("Guard daemon catalog page schema is invalid")
        return CatalogTraversal(snapshot_id, digest, total_count, cast(list[dict[str, object]], items))

    def catalog_extension(
        self, extension_id: str, *, timeout: float = CATALOG_V2_TRAVERSAL_TIMEOUT_S
    ) -> dict[str, object]:
        """One extension in the legacy v1 shape, assembled from bounded v2 reads."""

        return _object(
            _exchange(self.daemon_url, self.auth_token, "catalog_extension", timeout, extension_id=extension_id)
        )

    def _get(self, path: str, *, timeout: float, max_bytes: int = _MAX_GET_RESPONSE_BYTES) -> dict[str, object]:
        if type(max_bytes) is not int or not 0 < max_bytes <= MAX_DAEMON_CATALOG_RESPONSE_BYTES:
            raise ValueError("Guard daemon response limit must be a positive bounded integer")
        return _object(
            _exchange(
                self.daemon_url, self.auth_token, "request", timeout, method="GET", path=path, max_bytes=max_bytes
            )
        )

    def _post(
        self,
        path: str,
        payload: dict[str, object],
        *,
        timeout: float = _DEFAULT_REQUEST_TIMEOUT_S,
        max_bytes: int | None = None,
    ) -> dict[str, object]:
        return _object(
            _exchange(
                self.daemon_url,
                self.auth_token,
                "request",
                timeout,
                method="POST",
                path=path,
                body=payload,
                max_bytes=max_bytes,
            )
        )


def load_guard_surface_daemon_client(guard_home: Path) -> GuardSurfaceDaemonClient:
    daemon_url = load_guard_daemon_url(guard_home)
    auth_token = load_guard_daemon_auth_token(guard_home)
    if daemon_url is None or auth_token is None:
        clear_guard_daemon_state(guard_home)
        daemon_url = ensure_guard_daemon(guard_home)
        daemon_url = load_guard_daemon_url(guard_home) or daemon_url
        auth_token = load_guard_daemon_auth_token(guard_home)
    if daemon_url is None or auth_token is None:
        raise RuntimeError(f"Guard daemon state is incomplete for {guard_home}.")
    return GuardSurfaceDaemonClient(daemon_url, auth_token)


def load_running_guard_surface_daemon_client(
    guard_home: Path, *, identity_timeout: float = 1.0
) -> GuardSurfaceDaemonClient:
    """Load the current daemon authority without starting or repairing a daemon."""

    identity = (
        load_running_guard_daemon_identity(guard_home)
        if identity_timeout == 1.0
        else load_running_guard_daemon_identity(guard_home, health_timeout=identity_timeout)
    )
    if identity is None:
        raise GuardDaemonTransportError("Guard daemon authority is unavailable")
    daemon_url, auth_token = identity
    return GuardSurfaceDaemonClient(daemon_url, auth_token)
