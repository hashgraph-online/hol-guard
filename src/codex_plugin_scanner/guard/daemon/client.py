"""Local Guard Surface Server client."""

from __future__ import annotations

import http.client
import io
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Protocol, TypeGuard, cast

from .manager import (
    clear_guard_daemon_state,
    ensure_guard_daemon,
    load_guard_daemon_auth_token,
    load_guard_daemon_url,
    load_running_guard_daemon_identity,
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


_DEFAULT_REQUEST_TIMEOUT_S: float = 5.0
_STATUS_REQUEST_TIMEOUT_S: float = 0.25
_MAX_GET_RESPONSE_BYTES: int = 1_048_576


class _ReadableResponse(Protocol):
    def read(self, n: int = -1) -> bytes: ...


def _bound_response_read(response: object, timeout: float) -> bool:
    """Apply a socket deadline before a blocking urllib response read."""

    if isinstance(response, io.BytesIO):
        return True
    candidates: list[object] = [response]
    seen: set[int] = set()
    while candidates and len(seen) < 12:
        candidate = candidates.pop(0)
        if id(candidate) in seen:
            continue
        seen.add(id(candidate))
        if isinstance(candidate, io.BytesIO):
            return True
        set_timeout = getattr(candidate, "settimeout", None)
        if callable(set_timeout):
            set_timeout(timeout)
            return True
        for attribute in ("fp", "raw", "_sock", "sock", "socket"):
            nested = getattr(candidate, attribute, None)
            if nested is not None:
                candidates.append(nested)
    return False


def _response_is_closed(response: object) -> bool:
    candidates: list[object] = [response]
    seen: set[int] = set()
    while candidates and len(seen) < 12:
        candidate = candidates.pop(0)
        if id(candidate) in seen:
            continue
        seen.add(id(candidate))
        is_closed = getattr(candidate, "isclosed", None)
        if callable(is_closed) and is_closed() is True:
            return True
        for attribute in ("fp", "raw"):
            nested = getattr(candidate, attribute, None)
            if nested is not None:
                candidates.append(nested)
    return False


def _is_string_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, Mapping) and all(isinstance(key, str) for key in value)


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

    def add_operation_item(
        self,
        *,
        operation_id: str,
        item_type: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        response = self._post(
            f"/v1/operations/{operation_id}/items",
            {"item_type": item_type, "payload": payload},
        )
        item = response.get("item")
        return dict(item) if _is_string_object_dict(item) else response

    def update_operation_status(
        self,
        *,
        operation_id: str,
        status: str,
        approval_request_ids: list[str] | None = None,
    ) -> dict[str, object]:
        response = self._post(
            f"/v1/operations/{operation_id}/status",
            {
                "status": status,
                "approval_request_ids": approval_request_ids or [],
            },
        )
        operation = response.get("operation")
        return dict(operation) if _is_string_object_dict(operation) else response

    def extension_control_catalog(self) -> dict[str, object]:
        return self._get("/v1/extension-controls/catalog", timeout=_DEFAULT_REQUEST_TIMEOUT_S)

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
        return self._post("/v1/extension-controls/preview", payload)

    def apply_extension_controls(self, payload: dict[str, object]) -> dict[str, object]:
        return self._post("/v1/extension-controls/apply", payload)

    def containment_health(self) -> dict[str, object]:
        response = self._get("/v1/runtime/containment-health", timeout=5.0)
        value = response.get("containment_health")
        if not _is_string_object_dict(value):
            raise GuardDaemonRequestError("Guard daemon returned invalid containment health")
        return value

    def network_status(self) -> dict[str, object]:
        """Read current network protection truth without starting the daemon.

        Network status is an interactive, loopback-only health read. A 250 ms
        transport timeout plus a monotonic body deadline prevents daemon limbo.
        """

        return self._get("/v1/network/status", timeout=_STATUS_REQUEST_TIMEOUT_S)

    def resolve_policy_decision(self, payload: dict[str, object]) -> dict[str, object]:
        return self._post("/v1/policy/resolve", payload)

    def claim_policy_decision(self, payload: dict[str, object]) -> bool:
        response = self._post("/v1/policy/claim", payload)
        return response.get("claimed") is True

    def _get(self, path: str, *, timeout: float) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        request = urllib.request.Request(
            f"{self.daemon_url}{path}",
            headers={"X-Guard-Token": self.auth_token},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = self._read_response_with_deadline(response, deadline=deadline)
                return self._decode_json_response(payload.decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise self._http_request_error(error, deadline=deadline) from error
        except GuardDaemonRequestError:
            raise
        except UnicodeDecodeError as error:
            raise GuardDaemonResponseSchemaError("Guard daemon response schema is invalid") from error
        except http.client.IncompleteRead as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0.05:
                raise GuardDaemonTransportError("Guard daemon response was truncated") from error
            try:
                with urllib.request.urlopen(request, timeout=remaining) as retry_response:
                    payload = self._read_response_with_deadline(retry_response, deadline=deadline)
                    return self._decode_json_response(payload.decode("utf-8"))
            except (OSError, UnicodeDecodeError, http.client.IncompleteRead, urllib.error.URLError) as retry_error:
                raise GuardDaemonTransportError("Guard daemon response was truncated") from retry_error
        except TimeoutError as error:
            raise GuardDaemonTimeoutError("Guard daemon request timed out") from error
        except urllib.error.URLError as error:
            if isinstance(error.reason, TimeoutError):
                raise GuardDaemonTimeoutError("Guard daemon request timed out") from error
            raise GuardDaemonTransportError("Guard daemon request failed") from error
        except OSError as error:
            raise GuardDaemonTransportError("Guard daemon request failed") from error

    @staticmethod
    def _read_response_with_deadline(
        response: _ReadableResponse,
        *,
        deadline: float,
    ) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            raise GuardDaemonTimeoutError("Guard daemon request timed out")
        if not _bound_response_read(response, remaining):
            raise GuardDaemonTransportError("Guard daemon response does not support bounded reads")
        read1 = getattr(response, "read1", None)
        if not callable(read1):
            try:
                payload = response.read(_MAX_GET_RESPONSE_BYTES + 1)
            except TimeoutError as error:
                raise GuardDaemonTimeoutError("Guard daemon request timed out") from error
            if time.monotonic() >= deadline:
                raise GuardDaemonTimeoutError("Guard daemon request timed out")
            if len(payload) > _MAX_GET_RESPONSE_BYTES:
                raise GuardDaemonResponseSchemaError("Guard daemon response exceeded the size limit")
            return payload

        bounded_read = cast(Callable[[int], bytes], read1)
        chunks: list[bytes] = []
        total_bytes = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                raise GuardDaemonTimeoutError("Guard daemon request timed out")
            if not _bound_response_read(response, remaining):
                raise GuardDaemonTransportError("Guard daemon response does not support bounded reads")
            try:
                chunk = bounded_read(min(65_536, _MAX_GET_RESPONSE_BYTES + 1 - total_bytes))
            except TimeoutError as error:
                raise GuardDaemonTimeoutError("Guard daemon request timed out") from error
            if time.monotonic() >= deadline:
                raise GuardDaemonTimeoutError("Guard daemon request timed out")
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > _MAX_GET_RESPONSE_BYTES:
                raise GuardDaemonResponseSchemaError("Guard daemon response exceeded the size limit")
            chunks.append(chunk)
            if _response_is_closed(response):
                break
        return b"".join(chunks)

    def _post(
        self,
        path: str,
        payload: dict[str, object],
        *,
        timeout: float = _DEFAULT_REQUEST_TIMEOUT_S,
    ) -> dict[str, object]:
        request = urllib.request.Request(
            f"{self.daemon_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Guard-Token": self.auth_token,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return self._decode_json_response(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise self._http_request_error(error) from error
        except GuardDaemonRequestError:
            raise
        except UnicodeDecodeError as error:
            raise GuardDaemonResponseSchemaError("Guard daemon response schema is invalid") from error
        except http.client.IncompleteRead as error:
            try:
                with urllib.request.urlopen(request, timeout=timeout) as retry_response:
                    return self._decode_json_response(retry_response.read().decode("utf-8"))
            except (OSError, UnicodeDecodeError, http.client.IncompleteRead, urllib.error.URLError):
                raise GuardDaemonTransportError("Guard daemon response was truncated") from error
        except (OSError, urllib.error.URLError) as error:
            raise GuardDaemonTransportError(f"Guard daemon request failed: {error}") from error

    def _http_request_error(
        self,
        error: urllib.error.HTTPError,
        *,
        deadline: float | None = None,
    ) -> GuardDaemonRequestError:
        code: str | None = None
        recovery_action: str | None = None
        try:
            raw_payload = (
                self._read_response_with_deadline(error, deadline=deadline)
                if deadline is not None
                else error.read(_MAX_GET_RESPONSE_BYTES + 1)
            )
            if len(raw_payload) > _MAX_GET_RESPONSE_BYTES:
                raise GuardDaemonResponseSchemaError("Guard daemon response exceeded the size limit")
            payload = self._decode_json_response(raw_payload.decode("utf-8"))
            raw_code = payload.get("error")
            code = raw_code if isinstance(raw_code, str) else None
            recovery = payload.get("recovery")
            if _is_string_object_dict(recovery):
                raw_action = recovery.get("action")
                recovery_action = raw_action if isinstance(raw_action, str) else None
        except GuardDaemonTimeoutError:
            raise
        except (
            OSError,
            UnicodeDecodeError,
            http.client.IncompleteRead,
            json.JSONDecodeError,
            GuardDaemonRequestError,
        ):
            pass
        finally:
            with suppress(OSError):
                error.close()
        message = code or str(error)
        return GuardDaemonRequestError(
            f"Guard daemon request failed: {message}",
            status=error.code,
            code=code,
            recovery_action=recovery_action,
        )

    @staticmethod
    def _decode_json_response(raw_payload: str) -> dict[str, object]:
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError as error:
            raise GuardDaemonResponseSchemaError("Guard daemon response schema is invalid") from error
        if not isinstance(payload, dict):
            raise GuardDaemonResponseSchemaError("Guard daemon response schema is invalid")
        return payload


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
