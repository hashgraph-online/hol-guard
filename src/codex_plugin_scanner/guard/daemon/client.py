"""Local Guard Surface Server client."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import TypeGuard

from .manager import (
    clear_guard_daemon_state,
    ensure_guard_daemon,
    load_guard_daemon_auth_token,
    load_guard_daemon_url,
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


_DEFAULT_REQUEST_TIMEOUT_S: float = 5.0
_STATUS_REQUEST_TIMEOUT_S: float = 0.25


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

    def acknowledge_degraded_extension_controls(self) -> dict[str, object]:
        return self._post("/v1/extension-controls/acknowledge-degraded", {})

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

    def _get(self, path: str, *, timeout: float) -> dict[str, object]:
        request = urllib.request.Request(
            f"{self.daemon_url}{path}",
            headers={"X-Guard-Token": self.auth_token},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return self._decode_json_response(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise self._http_request_error(error) from error
        except GuardDaemonRequestError:
            raise
        except (OSError, urllib.error.URLError) as error:
            raise GuardDaemonTransportError(f"Guard daemon request failed: {error}") from error

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
        except (OSError, urllib.error.URLError) as error:
            raise GuardDaemonTransportError(f"Guard daemon request failed: {error}") from error

    def _http_request_error(self, error: urllib.error.HTTPError) -> GuardDaemonRequestError:
        code: str | None = None
        recovery_action: str | None = None
        try:
            payload = self._decode_json_response(error.read().decode("utf-8"))
            raw_code = payload.get("error")
            code = raw_code if isinstance(raw_code, str) else None
            recovery = payload.get("recovery")
            if _is_string_object_dict(recovery):
                raw_action = recovery.get("action")
                recovery_action = raw_action if isinstance(raw_action, str) else None
        except (OSError, json.JSONDecodeError, GuardDaemonRequestError):
            pass
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
            raise GuardDaemonRequestError(f"Guard daemon request failed: {error}") from error
        if not isinstance(payload, dict):
            raise GuardDaemonRequestError("Guard daemon request failed: invalid daemon response")
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
