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
"""

from __future__ import annotations

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
from .connect_cloud_actions import CLOUD_ACTIONS_RECONNECT_COMMAND

HEALTH_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BYTES = 64 * 1024
_USER_AGENT = f"hol-guard/{__version__}"
_WORKSPACE_HEADER = "X-Guard-Workspace-Id"
# JSON-RPC "method not found": Guard Cloud accepted the access but serves no actions yet.
_METHOD_NOT_FOUND = -32601
_PING_ID = "hol-guard-status"


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


@dataclass(frozen=True)
class _Answer:
    status: int
    body: object


class _UnreachableError(Exception):
    pass


def checked_at(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# A reply cut off mid-body raises from the standard library (`IncompleteRead`) or,
# through a managed proxy, from urllib3 (`ProtocolError`). Both mean no usable answer.
_TRANSPORT_ERRORS = (OSError, ManagedNetworkError, http.client.HTTPException, Urllib3HTTPError)


def _send(request: urllib.request.Request, timeout: float) -> _Answer:
    try:
        with managed_urlopen(request, timeout=timeout, allow_redirects=False) as response:
            status = int(response.status)
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        try:
            raw = error.read(_MAX_RESPONSE_BYTES + 1)
        except _TRANSPORT_ERRORS:
            raw = b""
    except _TRANSPORT_ERRORS as error:
        raise _UnreachableError from error
    return _Answer(status=status, body=_decode_body(raw))


def _decode_body(raw: bytes) -> object:
    """Read a JSON reply, or the first JSON event of an event-stream reply."""

    if len(raw) > _MAX_RESPONSE_BYTES:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Deep nesting raises RecursionError and an overlong integer raises a plain ValueError.
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        pass
    data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
    if not data:
        return None
    try:
        return json.loads(data[0])
    except (ValueError, RecursionError):
        return None


def check_service(pairing: CloudActionsPairing, *, timeout: float = HEALTH_TIMEOUT_SECONDS) -> HealthCheck:
    """Compare Guard Cloud's public Cloud actions description with what the pairing expects."""

    url = f"{pairing.origin}/.well-known/oauth-protected-resource{CLOUD_ACTIONS_RESOURCE_PATH}"
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": _USER_AGENT})
    try:
        answer = _send(request, timeout)
    except _UnreachableError:
        return HealthCheck("offline", "Guard Cloud could not be reached.")
    if answer.status == 404:
        return HealthCheck("not_turned_on", "Cloud actions are not turned on for this Guard Cloud.", 404)
    if answer.status != 200 or not isinstance(answer.body, dict):
        return HealthCheck("unexpected_answer", f"Guard Cloud answered HTTP {answer.status}.", answer.status)
    if answer.body.get("resource") != pairing.gateway_resource:
        return HealthCheck("changed", "Guard Cloud now describes a different Cloud actions address.", 200)
    supported = answer.body.get("scopes_supported")
    if not isinstance(supported, list):
        return HealthCheck("unexpected_answer", "Guard Cloud did not list the Cloud actions permissions.", 200)
    if "gateway:invoke" not in supported:
        return HealthCheck("changed", "Guard Cloud no longer offers Cloud actions to AI tools.", 200)
    return HealthCheck("current", "Guard Cloud offers Cloud actions.", 200)


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
    try:
        answer = _send(request, timeout)
    except _UnreachableError:
        return HealthCheck("offline", "Guard Cloud could not be reached.")
    status = answer.status
    if 200 <= status < 300:
        return _classify_ping_reply(answer.body, status)
    if status == 501 and _rpc_error_code(answer.body) == _METHOD_NOT_FOUND:
        return HealthCheck(
            "connected",
            "Guard Cloud accepted this computer. Actions are not available on this Guard Cloud yet.",
            status,
            (("actions", "not_available_yet"),),
        )
    if status == 401:
        return HealthCheck(
            "reconnect", f"Guard Cloud no longer accepts this computer. Run {CLOUD_ACTIONS_RECONNECT_COMMAND}.", status
        )
    if status == 403:
        return HealthCheck(
            "not_permitted", "Guard Cloud accepted this computer, but this member may not use Cloud actions.", status
        )
    if status == 400:
        return HealthCheck(
            "workspace_mismatch", "Guard Cloud refused the workspace this computer is connected to.", status
        )
    if status == 404:
        return HealthCheck("not_turned_on", "Cloud actions are not turned on for this Guard Cloud.", status)
    return HealthCheck("unexpected_answer", f"Guard Cloud answered HTTP {status}.", status)


def _classify_ping_reply(body: object, status: int) -> HealthCheck:
    """A success status alone proves nothing: a proxy page or an error inside HTTP 200 is not a ping reply."""

    if isinstance(body, dict) and body.get("jsonrpc") == "2.0":
        if "result" in body and body.get("id") == _PING_ID:
            return HealthCheck("connected", "Guard Cloud accepted this computer.", status, (("actions", "available"),))
        reply_id = body.get("id")
        if _rpc_error_code(body) == _METHOD_NOT_FOUND and (reply_id is None or reply_id == _PING_ID):
            return HealthCheck(
                "connected",
                "Guard Cloud accepted this computer. Actions are not available on this Guard Cloud yet.",
                status,
                (("actions", "not_available_yet"),),
            )
    return HealthCheck(
        "unexpected_answer", f"Guard Cloud answered HTTP {status} without a Cloud actions reply.", status
    )


def _rpc_error_code(body: object) -> object:
    if not isinstance(body, dict):
        return None
    error = body.get("error")
    return error.get("code") if isinstance(error, dict) else None


def redact_home(path: str, home: str) -> str:
    """Show paths under the home folder as `~/...` so a bundle does not carry the user name."""

    if home and (path == home or path.startswith(home.rstrip("/\\") + ("\\" if "\\" in home else "/"))):
        return "~" + path[len(home.rstrip("/\\")) :]
    return path
