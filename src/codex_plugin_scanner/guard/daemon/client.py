"""Local Guard Surface Server client."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .manager import (
    clear_guard_daemon_state,
    ensure_guard_daemon,
    load_guard_daemon_auth_token,
    load_guard_daemon_url,
)


class GuardDaemonRequestError(RuntimeError):
    """Raised when the Guard daemon returns a non-retryable request failure."""


class GuardDaemonTransportError(GuardDaemonRequestError):
    """Raised when the Guard daemon request fails due to transport issues."""


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
        return dict(response["item"]) if isinstance(response.get("item"), dict) else response

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
        return dict(response["operation"]) if isinstance(response.get("operation"), dict) else response

    def create_connect_request(
        self,
        *,
        sync_url: str,
        allowed_origin: str,
        lifetime_seconds: int = 300,
    ) -> dict[str, object]:
        return self._post(
            "/v1/connect/requests",
            {
                "sync_url": sync_url,
                "allowed_origin": allowed_origin,
                "lifetime_seconds": lifetime_seconds,
            },
        )

    def get_connect_state(self, *, request_id: str) -> dict[str, object]:
        query = urllib.parse.urlencode({"request_id": request_id})
        request = urllib.request.Request(
            f"{self.daemon_url}/v1/connect/state?{query}",
            headers={
                "X-Guard-Token": self.auth_token,
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            try:
                payload = json.loads(error.read().decode("utf-8"))
                message = payload.get("error", str(error))
            except (OSError, json.JSONDecodeError):
                message = str(error)
            raise GuardDaemonRequestError(f"Guard daemon request failed: {message}") from error
        except (OSError, urllib.error.URLError) as error:
            raise GuardDaemonTransportError(f"Guard daemon request failed: {error}") from error
        state = payload.get("state")
        if isinstance(state, dict):
            return state
        return payload

    def report_connect_result(
        self,
        *,
        request_id: str,
        status: str,
        milestone: str,
        reason: str | None = None,
        sync: dict[str, object] | None = None,
    ) -> dict[str, object]:
        payload = {
            "request_id": request_id,
            "status": status,
            "milestone": milestone,
            "reason": reason,
            "sync": sync or {},
        }
        response = self._post("/v1/connect/result", payload)
        state = response.get("state")
        if isinstance(state, dict):
            return state
        return response

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
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
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            try:
                payload = json.loads(error.read().decode("utf-8"))
                message = payload.get("error", str(error))
            except (OSError, json.JSONDecodeError):
                message = str(error)
            raise GuardDaemonRequestError(f"Guard daemon request failed: {message}") from error
        except (OSError, urllib.error.URLError) as error:
            raise GuardDaemonTransportError(f"Guard daemon request failed: {error}") from error


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
