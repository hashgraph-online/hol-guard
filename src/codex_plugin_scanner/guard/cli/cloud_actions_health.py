"""Live checks behind `cloud-actions status` and `cloud-actions doctor`.

The `hol-guard connect` pairing says only what was true when this computer
connected: Guard Cloud may have turned Cloud actions off since, the member may
have lost access, or this computer may be offline. These checks ask Guard
Cloud, and report what it answered:

- the service check reads the public Cloud actions description (nothing sent
  but the request) and compares it with the address the pairing expects;
- the connection check sends one AI tool's Cloud actions access, exchanged
  from the pairing, to the Cloud actions server on the pairing's own Guard
  Cloud. Redirects are refused, so the access never follows a redirect
  elsewhere.

Each check returns a stable state code and a message that is safe to print.
Neither ever includes the access, a server reply body or a header value.
Python sends the requests, so the access never leaves this module; what Guard
Cloud's reply means is decided by the native runtime's one-shot
``cloud-actions-health`` command.
"""

from __future__ import annotations

import base64
import http.client
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from urllib3.exceptions import HTTPError as Urllib3HTTPError

from ...version import __version__
from ..mdm.network import ManagedNetworkError, managed_urlopen
from .cloud_actions_access import CLOUD_ACTIONS_RESOURCE_PATH, CloudActionsPairing

HEALTH_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BYTES = 64 * 1024
_USER_AGENT = f"hol-guard/{__version__}"
_WORKSPACE_HEADER = "X-Guard-Workspace-Id"
_PING_ID = "hol-guard-status"
_FEATURE = "native-cloud-actions-health-v1"
_COMMAND = "cloud-actions-health"
_NATIVE_UNAVAILABLE_MESSAGE = (
    "Guard's native runtime is not available, so HOL Guard could not read Guard Cloud's answer. "
    "Run hol-guard doctor, then try again."
)


@dataclass(frozen=True)
class HealthCheck:
    """One check's outcome. `state` is a stable code; `message` is safe to print."""

    state: str
    message: str
    http_status: int | None = None
    details: tuple[tuple[str, object], ...] = ()

    @property
    def ok(self) -> bool:
        return self.state in {"current", "connected"}

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"state": self.state, "message": self.message}
        if self.http_status is not None:
            payload["http_status"] = self.http_status
        payload.update(dict(self.details))
        return payload


def checked_at(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# A reply cut off mid-body raises from the standard library (`IncompleteRead`) or,
# through a managed proxy, from urllib3 (`ProtocolError`). Both mean no usable answer.
_TRANSPORT_ERRORS = (OSError, ManagedNetworkError, http.client.HTTPException, Urllib3HTTPError)


def _send(request: urllib.request.Request, timeout: float) -> tuple[int, bytes] | None:
    """Guard Cloud's status and reply, read one byte past the limit; `None` when it could not be reached."""

    try:
        with managed_urlopen(request, timeout=timeout, allow_redirects=False) as response:
            return int(response.status), response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        try:
            return error.code, error.read(_MAX_RESPONSE_BYTES + 1)
        except _TRANSPORT_ERRORS:
            return error.code, b""
    except _TRANSPORT_ERRORS:
        return None


def _classify(op: str, answer: tuple[int, bytes] | None, **fields: str) -> HealthCheck:
    from ..mdm.runtime_request import runtime_answer

    status, raw = answer if answer is not None else (None, b"")
    request = {"op": op, "status": status, "body": base64.b64encode(raw).decode("ascii"), **fields}
    verdict = runtime_answer(_FEATURE, _COMMAND, request, output_limit=4096, timeout_seconds=5.0)
    state = verdict.get("state") if isinstance(verdict, dict) else None
    message = verdict.get("message") if isinstance(verdict, dict) else None
    if not isinstance(verdict, dict) or not isinstance(state, str) or not isinstance(message, str):
        return HealthCheck("native_unavailable", _NATIVE_UNAVAILABLE_MESSAGE, status)
    http_status, actions = verdict.get("http_status"), verdict.get("actions")
    return HealthCheck(
        state,
        message,
        http_status if isinstance(http_status, int) else None,
        (("actions", actions),) if isinstance(actions, str) else (),
    )


def check_service(pairing: CloudActionsPairing, *, timeout: float = HEALTH_TIMEOUT_SECONDS) -> HealthCheck:
    """Compare Guard Cloud's public Cloud actions description with what the pairing expects."""

    url = f"{pairing.origin}/.well-known/oauth-protected-resource{CLOUD_ACTIONS_RESOURCE_PATH}"
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": _USER_AGENT})
    return _classify("service", _send(request, timeout), resource=pairing.gateway_resource)


def check_connection(
    pairing: CloudActionsPairing, access_token: str, workspace_id: str, *, timeout: float = HEALTH_TIMEOUT_SECONDS
) -> HealthCheck:
    """Ask Guard Cloud whether it accepts Cloud actions access exchanged from the pairing."""

    body = json.dumps({"jsonrpc": "2.0", "id": _PING_ID, "method": "ping"}).encode()
    request = urllib.request.Request(
        pairing.gateway_url,
        data=body,
        method="POST",
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT,
            _WORKSPACE_HEADER: workspace_id,
        },
    )
    return _classify("connection", _send(request, timeout))


def redact_home(path: str, home: str) -> str:
    """Show paths under the home folder as `~/...` so a bundle does not carry the user name."""

    if home and (path == home or path.startswith(home.rstrip("/\\") + ("\\" if "\\" in home else "/"))):
        return "~" + path[len(home.rstrip("/\\")) :]
    return path
