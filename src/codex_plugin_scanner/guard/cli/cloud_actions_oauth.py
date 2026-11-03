"""Browser sign-in for Cloud actions.

Cloud actions use their own OAuth resource on Guard Cloud, separate from the
sign-in that pairs this device (`hol-guard connect`). This module never reads
or reuses that device sign-in. It:

- discovers the Cloud actions resource and its authorization server, and
  refuses metadata that names another origin or resource;
- registers a public client with loopback redirects (RFC 7591, RFC 8252);
- runs the authorization code flow with PKCE S256, the exact resource and
  only the Cloud actions scopes, with an optional Guard Cloud workspace hint;
- checks the answer before anything is stored: issuer on the callback,
  bearer type, scopes, and the audience, client and workspace the access
  credential names.

The access credential's claims are read, not verified: Guard Cloud verifies
them on every call. Reading them here stops a credential for another resource,
client or workspace from being stored under a profile.
"""

from __future__ import annotations

import http.server
import json
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ...version import __version__
from ..mdm.network import managed_urlopen
from ..oauth_token_claims import decode_oauth_access_token_claims, oauth_claim_string
from .oauth_client import _require_allowlisted_guard_oauth_origin  # pyright: ignore[reportPrivateUsage]

CLOUD_ACTIONS_RESOURCE_PATH = "/api/guard/gateway/mcp"
CLOUD_ACTIONS_SCOPES = (
    "gateway:discover",
    "gateway:invoke",
    "gateway:execution.read",
    "gateway:connection.read",
)
CLIENT_NAME = "HOL Guard CLI"
CALLBACK_PATH = "/oauth/callback"
# Registered once per Guard Cloud. Guard Cloud matches any high port on these
# loopback IPs (RFC 8252 section 7.3), so each sign-in can bind a fresh port.
REGISTERED_REDIRECT_URIS = (
    f"http://127.0.0.1:49152{CALLBACK_PATH}",
    f"http://[::1]:49152{CALLBACK_PATH}",
)
_HTTP_TIMEOUT_SECONDS = 20
_MAX_RESPONSE_BYTES = 256 * 1024
_USER_AGENT = f"hol-guard/{__version__}"
_LOOPBACK_PORT_MIN = 49152
_LOOPBACK_PORT_MAX = 65535


class CloudActionsSignInError(RuntimeError):
    """A sign-in step failed. `reason` is a stable code; the message is safe to print."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class CloudActionsServer:
    origin: str
    issuer: str
    resource: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str
    revocation_endpoint: str | None
    issuer_in_callback: bool


@dataclass(frozen=True)
class CloudActionsGrant:
    access_token: str
    refresh_token: str | None
    expires_at: str
    scopes: tuple[str, ...]
    workspace_id: str
    grant_id: str | None


def resolve_cloud_origin(cloud_url: str) -> str:
    """Reduce a Guard Cloud URL to its origin; only HOL origins or local loopback qualify."""

    parsed = urllib.parse.urlsplit(cloud_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise CloudActionsSignInError("cloud_url_invalid", "The Guard Cloud URL must be an absolute https URL.")
    if parsed.username is not None or parsed.password is not None:
        raise CloudActionsSignInError("cloud_url_invalid", "The Guard Cloud URL must not contain a user name.")
    try:
        origin = _require_allowlisted_guard_oauth_origin(cloud_url)
    except ValueError as error:
        raise CloudActionsSignInError(
            "cloud_url_not_allowed", "The Guard Cloud URL must be a HOL Guard Cloud address or this computer."
        ) from error
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" and host not in {"127.0.0.1", "localhost", "::1", "host.docker.internal"}:
        raise CloudActionsSignInError("cloud_url_invalid", "The Guard Cloud URL must use https.")
    return origin


def _read_json(request: urllib.request.Request, *, step: str) -> dict[str, object]:
    try:
        with managed_urlopen(request, timeout=_HTTP_TIMEOUT_SECONDS, allow_redirects=False) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise _http_error(error, step=step) from None
    except OSError as error:
        raise CloudActionsSignInError(f"{step}_unreachable", f"Guard Cloud could not be reached ({step}).") from error
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise CloudActionsSignInError(f"{step}_invalid", f"Guard Cloud sent an oversized answer ({step}).")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CloudActionsSignInError(f"{step}_invalid", f"Guard Cloud sent an unreadable answer ({step}).") from None
    if not isinstance(payload, dict):
        raise CloudActionsSignInError(f"{step}_invalid", f"Guard Cloud sent an unreadable answer ({step}).")
    return payload


def _http_error(error: urllib.error.HTTPError, *, step: str) -> CloudActionsSignInError:
    if step == "discovery" and error.code == 404:
        return CloudActionsSignInError(
            "cloud_actions_not_enabled", "Cloud actions are not turned on for this Guard Cloud yet."
        )
    code = ""
    try:
        payload = json.loads(error.read(_MAX_RESPONSE_BYTES).decode("utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("error"), str):
            code = str(payload["error"])[:64]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    detail = f": {code}" if code.replace("_", "").isalnum() else ""
    return CloudActionsSignInError(
        f"{step}_refused", f"Guard Cloud refused the {step} request (HTTP {error.code}{detail})."
    )


def _get(url: str, *, step: str) -> dict[str, object]:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": _USER_AGENT})
    return _read_json(request, step=step)


def _post(url: str, body: bytes, content_type: str, *, step: str) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Accept": "application/json", "Content-Type": content_type, "User-Agent": _USER_AGENT},
    )
    return _read_json(request, step=step)


def _same_origin_url(value: object, origin: str, field: str) -> str:
    if not isinstance(value, str):
        raise CloudActionsSignInError("metadata_invalid", f"Guard Cloud metadata is missing {field}.")
    parsed = urllib.parse.urlsplit(value)
    if urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")) != origin or parsed.fragment:
        raise CloudActionsSignInError("metadata_origin_mismatch", f"Guard Cloud metadata points {field} elsewhere.")
    return value


def discover_cloud_actions_server(origin: str) -> CloudActionsServer:
    resource = f"{origin}{CLOUD_ACTIONS_RESOURCE_PATH}"
    protected = _get(f"{origin}/.well-known/oauth-protected-resource{CLOUD_ACTIONS_RESOURCE_PATH}", step="discovery")
    if protected.get("resource") != resource:
        raise CloudActionsSignInError("metadata_resource_mismatch", "Guard Cloud described a different resource.")
    servers = protected.get("authorization_servers")
    if not isinstance(servers, list) or origin not in servers:
        raise CloudActionsSignInError("metadata_origin_mismatch", "Guard Cloud named another sign-in server.")
    authorization = _get(f"{origin}/.well-known/oauth-authorization-server", step="discovery")
    if authorization.get("issuer") != origin:
        raise CloudActionsSignInError("metadata_issuer_mismatch", "Guard Cloud's sign-in server named another issuer.")
    challenge_methods = authorization.get("code_challenge_methods_supported")
    if not isinstance(challenge_methods, list) or "S256" not in challenge_methods:
        raise CloudActionsSignInError("metadata_invalid", "Guard Cloud's sign-in server does not offer PKCE S256.")
    revocation = authorization.get("revocation_endpoint")
    return CloudActionsServer(
        origin=origin,
        issuer=origin,
        resource=resource,
        authorization_endpoint=_same_origin_url(
            authorization.get("authorization_endpoint"), origin, "authorization_endpoint"
        ),
        token_endpoint=_same_origin_url(authorization.get("token_endpoint"), origin, "token_endpoint"),
        registration_endpoint=_same_origin_url(
            authorization.get("registration_endpoint"), origin, "registration_endpoint"
        ),
        revocation_endpoint=None if revocation is None else _same_origin_url(revocation, origin, "revocation_endpoint"),
        issuer_in_callback=authorization.get("authorization_response_iss_parameter_supported") is True,
    )


def register_cloud_actions_client(server: CloudActionsServer) -> str:
    body = json.dumps(
        {
            "client_name": CLIENT_NAME,
            "redirect_uris": list(REGISTERED_REDIRECT_URIS),
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": " ".join(CLOUD_ACTIONS_SCOPES),
        }
    ).encode("utf-8")
    payload = _post(server.registration_endpoint, body, "application/json", step="registration")
    client_id = payload.get("client_id")
    if not isinstance(client_id, str) or not client_id or len(client_id) > 200:
        raise CloudActionsSignInError("registration_invalid", "Guard Cloud did not return a client ID.")
    return client_id


def build_authorize_url(
    server: CloudActionsServer,
    *,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    workspace_id: str | None,
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": " ".join(CLOUD_ACTIONS_SCOPES),
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "resource": server.resource,
    }
    if workspace_id is not None:
        params["workspace_id"] = workspace_id
    return f"{server.authorization_endpoint}?{urllib.parse.urlencode(params)}"


@dataclass(frozen=True)
class _Callback:
    code: str | None
    issuer: str | None
    error: str | None


class _IPv6Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


class LoopbackCallbackListener:
    """One-shot listener on a random high loopback port for the authorization callback."""

    def __init__(self, *, expected_state: str) -> None:
        self._expected_state = expected_state
        self._ready = threading.Event()
        self._callback: _Callback | None = None
        self._server = self._bind()
        host, port = self._server.server_address[:2]
        formatted = f"[{host}]" if ":" in str(host) else str(host)
        self.redirect_uri = f"http://{formatted}:{port}{CALLBACK_PATH}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _bind(self) -> http.server.ThreadingHTTPServer:
        listener = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urllib.parse.urlsplit(self.path)
                params = urllib.parse.parse_qs(parsed.query)

                def first(name: str) -> str | None:
                    values = params.get(name)
                    return values[0] if values else None

                state = first("state") or ""
                if parsed.path != CALLBACK_PATH or not secrets.compare_digest(state, listener._expected_state):
                    self._reply(400, "This sign-in link is not for this terminal.")
                    return
                if listener._ready.is_set():
                    self._reply(400, "This sign-in already finished.")
                    return
                error = first("error")
                listener._callback = _Callback(
                    code=None if error else first("code"), issuer=first("iss"), error=(error or "")[:64] or None
                )
                listener._ready.set()
                self._reply(200, "You can close this tab and return to your terminal.")

            def _reply(self, status: int, text: str) -> None:
                body = text.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                del format, args

        for host in ("127.0.0.1", "::1"):
            for _ in range(20):
                port = secrets.randbelow(_LOOPBACK_PORT_MAX - _LOOPBACK_PORT_MIN + 1) + _LOOPBACK_PORT_MIN
                server_class = _IPv6Server if ":" in host else http.server.ThreadingHTTPServer
                try:
                    return server_class((host, port), _Handler)
                except OSError:
                    continue
        raise CloudActionsSignInError("callback_unavailable", "Could not listen on a local port for the sign-in.")

    def wait(self, timeout_seconds: float, *, server: CloudActionsServer) -> str:
        deadline = time.monotonic() + timeout_seconds
        # Short slices keep Ctrl-C responsive where a long wait would block it.
        while not self._ready.wait(min(0.5, max(0.0, deadline - time.monotonic()))):
            if time.monotonic() >= deadline:
                break
        if not self._ready.is_set() or self._callback is None:
            raise CloudActionsSignInError("sign_in_timed_out", "The sign-in was not finished in the browser in time.")
        callback = self._callback
        if server.issuer_in_callback and callback.issuer != server.issuer:
            raise CloudActionsSignInError("callback_issuer_mismatch", "The sign-in answer came from another server.")
        if callback.error is not None:
            if callback.error == "access_denied":
                raise CloudActionsSignInError("sign_in_declined", "The sign-in was declined in the browser.")
            raise CloudActionsSignInError("sign_in_refused", f"Guard Cloud refused the sign-in ({callback.error}).")
        if not callback.code:
            raise CloudActionsSignInError("callback_invalid", "The sign-in answer had no authorization code.")
        return callback.code

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def _form(values: Mapping[str, str]) -> bytes:
    return urllib.parse.urlencode(values).encode("utf-8")


def exchange_authorization_code(
    server: CloudActionsServer, *, client_id: str, code: str, redirect_uri: str, code_verifier: str
) -> dict[str, object]:
    return _post(
        server.token_endpoint,
        _form(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": code_verifier,
                "resource": server.resource,
            }
        ),
        "application/x-www-form-urlencoded",
        step="exchange",
    )


def _audiences(claims: Mapping[str, object]) -> list[str]:
    audience = claims.get("aud")
    if isinstance(audience, str):
        return [audience]
    if isinstance(audience, list):
        return [item for item in audience if isinstance(item, str)]
    return []


def read_cloud_actions_grant(
    payload: Mapping[str, object],
    *,
    server: CloudActionsServer,
    client_id: str,
    requested_workspace_id: str | None,
    now: datetime | None = None,
) -> CloudActionsGrant:
    """Accept a token answer only when it is a Cloud actions grant for this client."""

    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise CloudActionsSignInError("grant_invalid", "Guard Cloud's answer had no access.")
    token_type = payload.get("token_type")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise CloudActionsSignInError("grant_invalid", "Guard Cloud granted an unexpected kind of access.")
    scope_text = payload.get("scope")
    scopes = tuple(scope_text.split()) if isinstance(scope_text, str) else ()
    if not scopes or any(scope not in CLOUD_ACTIONS_SCOPES for scope in scopes):
        raise CloudActionsSignInError("grant_scope_mismatch", "Guard Cloud granted access other than Cloud actions.")
    expires_in = payload.get("expires_in")
    if not isinstance(expires_in, int) or isinstance(expires_in, bool) or expires_in <= 0:
        raise CloudActionsSignInError("grant_invalid", "Guard Cloud's answer had no expiry.")
    claims = decode_oauth_access_token_claims(access_token)
    if not claims:
        raise CloudActionsSignInError("grant_invalid", "Guard Cloud's access could not be read.")
    if server.resource not in _audiences(claims):
        raise CloudActionsSignInError("grant_audience_mismatch", "Guard Cloud granted access for something else.")
    claimed_client = oauth_claim_string(claims, "client_id")
    if claimed_client != client_id:
        raise CloudActionsSignInError("grant_client_mismatch", "Guard Cloud granted access to another client.")
    workspace_id = oauth_claim_string(claims, "workspace", "workspaceId")
    if workspace_id is None:
        raise CloudActionsSignInError("grant_invalid", "Guard Cloud's access does not name a workspace.")
    if requested_workspace_id is not None and workspace_id.lower() != requested_workspace_id:
        raise CloudActionsSignInError(
            "workspace_mismatch", "The workspace chosen in the browser is not the one this command asked for."
        )
    refresh_token = payload.get("refresh_token")
    issued = now or datetime.now(timezone.utc)
    return CloudActionsGrant(
        access_token=access_token,
        refresh_token=refresh_token if isinstance(refresh_token, str) and refresh_token else None,
        expires_at=(issued + timedelta(seconds=expires_in)).isoformat().replace("+00:00", "Z"),
        scopes=scopes,
        workspace_id=workspace_id.lower(),
        grant_id=oauth_claim_string(claims, "grant", "grantId"),
    )


def revoke_cloud_actions_grant(server: CloudActionsServer, *, client_id: str, token: str, hint: str) -> bool:
    if server.revocation_endpoint is None:
        return False
    try:
        _ = _post(
            server.revocation_endpoint,
            _form({"token": token, "token_type_hint": hint, "client_id": client_id}),
            "application/x-www-form-urlencoded",
            step="revocation",
        )
    except CloudActionsSignInError as error:
        # RFC 7009 answers 200 with an empty body; an unreadable body still means success.
        return error.reason == "revocation_invalid"
    return True


__all__ = [
    "CLOUD_ACTIONS_RESOURCE_PATH",
    "CLOUD_ACTIONS_SCOPES",
    "REGISTERED_REDIRECT_URIS",
    "CloudActionsGrant",
    "CloudActionsServer",
    "CloudActionsSignInError",
    "LoopbackCallbackListener",
    "build_authorize_url",
    "discover_cloud_actions_server",
    "exchange_authorization_code",
    "read_cloud_actions_grant",
    "register_cloud_actions_client",
    "resolve_cloud_origin",
    "revoke_cloud_actions_grant",
]
