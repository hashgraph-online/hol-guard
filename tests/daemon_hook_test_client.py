"""Authenticated test client for daemon hook endpoints."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import io
import urllib.error
import urllib.request
from urllib.parse import urlparse

from ci.guard_daemon_harness import GuardDaemonServer
from ci.native_daemon_harness import NativeGuardDaemon
from scripts.daemon_hook_auth import _DaemonResponseError
from scripts.daemon_hook_client import authenticated_claude_hook_response


class AuthenticatedHookResponse(io.BytesIO):
    """Minimal context-managed response returned by the test transport."""

    status = 200


def open_authenticated_claude_request(
    daemon: NativeGuardDaemon | GuardDaemonServer,
    request: urllib.request.Request,
    *,
    timeout: float,
) -> AuthenticatedHookResponse:
    """Send an existing Claude request the way the hook bridge sends it.

    The native daemon answers the identity challenge, so a request to it goes
    through the production challenge flow. The in-process handler harness has
    no challenge; it stands where the native daemon hands a replay a hook whose
    proof it already checked.
    """

    if isinstance(daemon, GuardDaemonServer):
        daemon._server.daemon_proof_verified = True
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return AuthenticatedHookResponse(response.read())
    body = request.data.decode("utf-8") if isinstance(request.data, bytes) else "{}"
    try:
        response = authenticated_claude_hook_response(
            state_path=daemon.store.guard_home / "daemon-state.json",
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
