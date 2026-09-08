"""Authenticated test client for daemon hook endpoints."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import io
import urllib.error
import urllib.request
from urllib.parse import urlparse

from codex_plugin_scanner.guard.adapters.claude_daemon_hook_transport import authenticated_claude_hook_response
from codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth import _DaemonResponseError
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer


class AuthenticatedHookResponse(io.BytesIO):
    """Minimal context-managed response returned by the test transport."""

    status = 200


def open_authenticated_claude_request(
    daemon: GuardDaemonServer,
    request: urllib.request.Request,
    *,
    timeout: float,
) -> AuthenticatedHookResponse:
    """Send an existing Claude request through the production challenge flow."""

    body = request.data.decode("utf-8") if isinstance(request.data, bytes) else "{}"
    try:
        response = authenticated_claude_hook_response(
            state_path=daemon._server.store.guard_home / "daemon-state.json",
            query=urlparse(request.full_url).query,
            data=body,
            timeout_seconds=timeout,
        )
    except _DaemonResponseError as error:
        raise urllib.error.HTTPError(
            request.full_url,
            error.status,
            error.detail,
            {},
            io.BytesIO(error.detail.encode("utf-8")),
        ) from error
    return AuthenticatedHookResponse(response.encode("utf-8"))
