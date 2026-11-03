"""Live checks behind `cloud-actions status` and `cloud-actions doctor`.

A saved sign-in says only what was true when it was made: Guard Cloud may
have ended it since, the member may have lost access, or this computer may be
offline. These checks ask Guard Cloud, and report what it answered:

- the service check reads the public Cloud actions description (no sign-in
  sent) and compares it with what the saved sign-in expects;
- the connection check sends the saved access, and only to the Cloud actions
  address saved at sign-in, which must sit on the same Guard Cloud. Redirects
  are refused, so the access never follows a redirect elsewhere.

Each check returns a stable state code and a message that is safe to print.
Neither ever includes the saved access, a server reply body or a header value.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from ...version import __version__
from ..mdm.network import ManagedNetworkError, managed_urlopen
from .cloud_actions_oauth import CLOUD_ACTIONS_RESOURCE_PATH
from .cloud_actions_session import CloudActionsProfile

HEALTH_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BYTES = 64 * 1024
_USER_AGENT = f"hol-guard/{__version__}"
_WORKSPACE_HEADER = "X-Guard-Workspace-Id"
# JSON-RPC "method not found": Guard Cloud accepted the sign-in but serves no actions yet.
_METHOD_NOT_FOUND = -32601


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


def resource_on_issuer(profile: CloudActionsProfile) -> bool:
    """The saved Cloud actions address must be the one on the saved Guard Cloud."""

    return profile.resource == f"{profile.issuer}{CLOUD_ACTIONS_RESOURCE_PATH}"


def _send(request: urllib.request.Request, timeout: float) -> _Answer:
    try:
        with managed_urlopen(request, timeout=timeout, allow_redirects=False) as response:
            status = int(response.status)
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        try:
            raw = error.read(_MAX_RESPONSE_BYTES + 1)
        except OSError:
            raw = b""
    except (OSError, ManagedNetworkError) as error:
        raise _UnreachableError from error
    body: object = None
    if len(raw) <= _MAX_RESPONSE_BYTES:
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = None
    return _Answer(status=status, body=body)


def check_service(profile: CloudActionsProfile, *, timeout: float = HEALTH_TIMEOUT_SECONDS) -> HealthCheck:
    """Compare Guard Cloud's public Cloud actions description with the saved sign-in."""

    if not resource_on_issuer(profile):
        return HealthCheck("profile_damaged", "The saved sign-in names a Cloud actions address on another site.")
    url = f"{profile.issuer}/.well-known/oauth-protected-resource{CLOUD_ACTIONS_RESOURCE_PATH}"
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": _USER_AGENT})
    try:
        answer = _send(request, timeout)
    except _UnreachableError:
        return HealthCheck("offline", "Guard Cloud could not be reached.")
    if answer.status == 404:
        return HealthCheck("not_turned_on", "Cloud actions are not turned on for this Guard Cloud.", 404)
    if answer.status != 200 or not isinstance(answer.body, dict):
        return HealthCheck("unexpected_answer", f"Guard Cloud answered HTTP {answer.status}.", answer.status)
    if answer.body.get("resource") != profile.resource:
        return HealthCheck("changed", "Guard Cloud now describes a different Cloud actions address.", 200)
    supported = answer.body.get("scopes_supported")
    if not isinstance(supported, list):
        return HealthCheck("unexpected_answer", "Guard Cloud did not list the Cloud actions permissions.", 200)
    missing = sorted(scope for scope in profile.scopes if scope not in supported)
    if missing:
        return HealthCheck(
            "changed",
            "Guard Cloud no longer offers every permission this sign-in holds. Sign in again.",
            200,
            (("scopes_missing", missing),),
        )
    return HealthCheck("current", "Guard Cloud offers Cloud actions as this sign-in expects.", 200)


def check_connection(
    profile: CloudActionsProfile, access_token: str, *, timeout: float = HEALTH_TIMEOUT_SECONDS
) -> HealthCheck:
    """Ask Guard Cloud whether it still accepts the saved sign-in for its workspace."""

    if profile.is_expired():
        return HealthCheck("sign_in_expired", "The saved sign-in has expired. Sign in again.")
    if not resource_on_issuer(profile):
        return HealthCheck("profile_damaged", "The saved sign-in names a Cloud actions address on another site.")
    body = json.dumps({"jsonrpc": "2.0", "id": "hol-guard-status", "method": "ping"}).encode()
    request = urllib.request.Request(
        profile.resource,
        data=body,
        method="POST",
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT,
            _WORKSPACE_HEADER: profile.workspace_id,
        },
    )
    try:
        answer = _send(request, timeout)
    except _UnreachableError:
        return HealthCheck("offline", "Guard Cloud could not be reached.")
    status = answer.status
    if 200 <= status < 300:
        return HealthCheck("connected", "Guard Cloud accepted this sign-in.", status, (("actions", "available"),))
    if status == 501 and _rpc_error_code(answer.body) == _METHOD_NOT_FOUND:
        return HealthCheck(
            "connected",
            "Guard Cloud accepted this sign-in. Actions are not available on this Guard Cloud yet.",
            status,
            (("actions", "not_available_yet"),),
        )
    if status == 401:
        return HealthCheck("sign_in_again", "Guard Cloud no longer accepts this sign-in. Sign in again.", status)
    if status == 403:
        return HealthCheck(
            "not_permitted", "Guard Cloud accepted the sign-in, but this member may not use Cloud actions.", status
        )
    if status == 400:
        return HealthCheck("workspace_mismatch", "Guard Cloud refused the workspace this sign-in names.", status)
    if status == 404:
        return HealthCheck("not_turned_on", "Cloud actions are not turned on for this Guard Cloud.", status)
    return HealthCheck("unexpected_answer", f"Guard Cloud answered HTTP {status}.", status)


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
