"""Guard OAuth connect helpers for browser and device-code flows."""

from __future__ import annotations

import base64
import http.server
import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from ...version import __version__
from ..mdm.network import managed_urlopen
from ..package_firewall_defaults import extract_cloud_user_profile as _extract_cloud_user_profile
from ..package_firewall_entitlement import (
    build_oauth_package_firewall_entitlement,
    reconcile_connect_state_with_oauth_entitlement,
)
from ..runtime.runner import prepare_guard_cloud_connect_authorization
from ..store import GuardStore
from ..store_connect import build_connect_state_response
from .oauth_client import (
    GuardDpopKeyMaterial,
    GuardOAuthClientConfig,
    build_pkce_s256_challenge,
    generate_dpop_key_pair,
    generate_pkce_verifier,
    guard_api_base_path,
    resolve_guard_oauth_client_config,
)

DEFAULT_GUARD_SYNC_URL = "https://hol.org/api/guard/receipts/sync"
DEFAULT_GUARD_CONNECT_URL = "https://hol.org/guard/connect"
DEFAULT_GUARD_DEVICE_SCOPES = (
    "guard:runtime.sync",
    "guard:receipt.write",
    "guard:runtime.session.write",
    "guard:insights.share",
    "guard:offline_access",
)
CI_SAFE_GUARD_DEVICE_SCOPES = (
    "guard:runtime.sync",
    "guard:offline_access",
)
CONNECT_COMMAND = "hol-guard connect"
CONNECT_STATUS_COMMAND = "hol-guard connect status"
CONNECT_REPAIR_COMMAND = "hol-guard connect repair"
DISCONNECT_COMMAND = "hol-guard disconnect"
HEADLESS_CONNECT_COMMAND = "hol-guard connect --headless"
CONNECT_SYNC_AUTH_CONTEXT_KEY = "_guard_sync_auth_context"
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
DEVICE_CODE_SLOW_DOWN_SECONDS = 5
HEADLESS_RUNTIME_ID = "hol-guard"
HEADLESS_RUNTIME_LABEL = "HOL Guard CLI"
_GUARD_OAUTH_USER_AGENT = f"hol-guard/{__version__}"
_LOOPBACK_REDIRECT_PATH = "/oauth/callback"
_SELF_REVOKE_PATH = "/api/guard/oauth/revoke/self"


def _guard_oauth_request_headers(*, dpop: str | None = None) -> dict[str, str]:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": _GUARD_OAUTH_USER_AGENT,
    }
    if dpop is not None:
        headers["DPoP"] = dpop
    return headers


_LOOPBACK_HOSTS = ("127.0.0.1", "::1")
_LOOPBACK_PORT_MIN = 49152
_LOOPBACK_PORT_MAX = 65535


@dataclass(frozen=True)
class GuardOAuthLoopbackCallback:
    code: str | None
    state: str
    error: str | None = None
    error_description: str | None = None


@dataclass(frozen=True)
class GuardOAuthTokenExchangeResult:
    access_token: str
    refresh_token: str | None
    expires_in: int
    scope: str
    token_type: str
    grant_id: str | None
    machine_id: str | None
    supply_chain_entitlement: dict[str, object] | None
    workspace_id: str | None
    cloud_user_profile: dict[str, str] | None = None
    access_token_expires_at: str | None = None

    def __post_init__(self) -> None:
        if self.access_token_expires_at is not None:
            return
        object.__setattr__(
            self,
            "access_token_expires_at",
            _guard_access_token_expires_at(
                access_token=self.access_token,
                expires_in=self.expires_in,
                now=datetime.now(timezone.utc),
            ),
        )


@dataclass
class GuardOAuthBrowserSession:
    authorize_url: str
    redirect_uri: str
    pkce_verifier: str
    state: str
    dpop_key_material: GuardDpopKeyMaterial
    _server: http.server.ThreadingHTTPServer
    _thread: threading.Thread
    _callback_ready: threading.Event
    _callback: GuardOAuthLoopbackCallback | None = None

    def wait_for_callback(self, timeout_seconds: float) -> GuardOAuthLoopbackCallback:
        if timeout_seconds <= 0:
            raise TimeoutError("Guard OAuth browser callback timed out.")
        if not self._callback_ready.wait(timeout_seconds):
            raise TimeoutError("Guard OAuth browser callback timed out.")
        callback = self._callback or getattr(self._server, "guard_callback", None)
        if callback is None:
            raise TimeoutError("Guard OAuth browser callback timed out.")
        if callback.error is not None:
            description = callback.error_description or callback.error
            raise RuntimeError(f"Guard OAuth authorization was denied: {description}")
        return callback

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(f"{data}{padding}")


def _decode_access_token_claims(access_token: str) -> dict[str, object]:
    parts = access_token.split(".")
    if len(parts) != 3:
        return {}
    try:
        payload = json.loads(_base64url_decode(parts[1]).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _read_nested_string(payload: dict[str, object], *path: str) -> str | None:
    current: object = payload
    for segment in path:
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current if isinstance(current, str) and current else None


def _guard_access_token_expires_at(
    *,
    access_token: str,
    expires_in: int,
    now: datetime,
) -> str | None:
    claims = _decode_access_token_claims(access_token)
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and float(exp) > 0:
        return datetime.fromtimestamp(float(exp), tz=timezone.utc).isoformat()
    if expires_in <= 0:
        return None
    return (now + timedelta(seconds=expires_in)).isoformat()


def _encode_jwt_segment(payload: dict[str, object]) -> str:
    return _base64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _int_payload_value(payload: dict[str, object], key: str, default: int) -> int:
    value = payload.get(key)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _sign_dpop_proof(
    *,
    token_endpoint: str,
    dpop_key_material: GuardDpopKeyMaterial,
    now: datetime,
    nonce: str | None = None,
) -> str:
    issued_at = int(now.timestamp())
    header: dict[str, object] = {
        "alg": dpop_key_material.algorithm,
        "jwk": dpop_key_material.public_jwk,
        "typ": "dpop+jwt",
    }
    claims: dict[str, object] = {
        "htu": token_endpoint,
        "htm": "POST",
        "iat": issued_at,
        "jti": str(uuid4()),
    }
    if isinstance(nonce, str):
        normalized_nonce = nonce.strip()
        if normalized_nonce:
            claims["nonce"] = normalized_nonce
    signing_input = f"{_encode_jwt_segment(header)}.{_encode_jwt_segment(claims)}".encode("ascii")
    private_key = serialization.load_pem_private_key(
        dpop_key_material.private_key_pem.encode("ascii"),
        password=None,
    )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise RuntimeError("Guard DPoP key must be an EC private key.")
    der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der_signature)
    jose_signature = _base64url_encode(r_value.to_bytes(32, byteorder="big") + s_value.to_bytes(32, byteorder="big"))
    return f"{signing_input.decode('ascii')}.{jose_signature}"


def _oauth_response_header_value(response: object, header_name: str) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    value = headers.get(header_name)
    if value is None:
        header_items = getattr(headers, "items", None)
        if callable(header_items):
            target_header = header_name.lower()
            items = header_items()
            if isinstance(items, Iterable):
                for header_item in items:
                    if not isinstance(header_item, tuple) or len(header_item) != 2:
                        continue
                    current_name, current_value = header_item
                    if isinstance(current_name, str) and current_name.lower() == target_header:
                        value = current_value
                        break
    if not isinstance(value, str):
        return None
    normalized_value = value.strip()
    return normalized_value or None


def _oauth_dpop_nonce_from_http_error(
    error: urllib.error.HTTPError,
    payload: object,
) -> str | None:
    if error.code not in {400, 401}:
        return None
    nonce = _oauth_response_header_value(error, "DPoP-Nonce")
    if nonce is None:
        return None
    if isinstance(payload, dict):
        oauth_error = str(payload.get("error") or "").strip()
        if oauth_error and oauth_error not in {"use_dpop_nonce", "invalid_dpop_proof"}:
            return None
    return nonce


def _build_browser_authorize_url(
    *,
    authorize_endpoint: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    machine_id: str,
    machine_label: str,
) -> str:
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "scope": " ".join(DEFAULT_GUARD_DEVICE_SCOPES),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "requested_machine_id": machine_id,
            "requested_machine_label": machine_label,
            "requested_runtime_id": "hol-guard",
            "requested_runtime_label": "HOL Guard CLI",
        }
    )
    return f"{authorize_endpoint}?{query}"


def start_guard_loopback_callback_listener(
    *,
    expected_state: str,
    authorize_url: str | None = None,
    client_id: str | None = None,
    machine_id: str | None = None,
    machine_label: str | None = None,
    dpop_key_material: GuardDpopKeyMaterial | None = None,
    pkce_verifier: str | None = None,
) -> GuardOAuthBrowserSession:
    callback_ready = threading.Event()

    class _CallbackServer(http.server.ThreadingHTTPServer):
        allow_reuse_address = False
        guard_callback: GuardOAuthLoopbackCallback | None = None

    class _CallbackHandler(http.server.BaseHTTPRequestHandler):
        def _callback_server(self) -> _CallbackServer:
            if not isinstance(self.server, _CallbackServer):
                raise RuntimeError("Guard OAuth callback server is unavailable.")
            return self.server

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != _LOOPBACK_REDIRECT_PATH:
                self.send_error(404)
                return
            params = urllib.parse.parse_qs(parsed.query)
            state = str(params.get("state", [""])[0] or "")
            code = str(params.get("code", [""])[0] or "")
            error = str(params.get("error", [""])[0] or "")
            error_description = str(params.get("error_description", [""])[0] or "")
            if state != expected_state:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Guard OAuth state mismatch.")
                return
            if error:
                self._callback_server().guard_callback = GuardOAuthLoopbackCallback(
                    code=None,
                    state=state,
                    error=error,
                    error_description=error_description or None,
                )
                callback_ready.set()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"HOL Guard authorization was denied. Return to your terminal.")
                return
            if not code:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Guard OAuth callback is missing the authorization code.")
                return
            self._callback_server().guard_callback = GuardOAuthLoopbackCallback(code=code, state=state)
            callback_ready.set()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"HOL Guard connected. Return to your terminal.")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    for host in _LOOPBACK_HOSTS:
        for _ in range(20):
            port = secrets.randbelow(_LOOPBACK_PORT_MAX - _LOOPBACK_PORT_MIN + 1) + _LOOPBACK_PORT_MIN
            try:
                server = _CallbackServer((host, port), _CallbackHandler)
            except OSError:
                continue
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            formatted_host = f"[{host}]" if ":" in host else host
            redirect_uri = f"http://{formatted_host}:{port}{_LOOPBACK_REDIRECT_PATH}"
            return GuardOAuthBrowserSession(
                authorize_url=authorize_url or "",
                redirect_uri=redirect_uri,
                pkce_verifier=pkce_verifier or "",
                state=expected_state,
                dpop_key_material=dpop_key_material or generate_dpop_key_pair(),
                _server=server,
                _thread=thread,
                _callback_ready=callback_ready,
            )
    raise RuntimeError("Guard OAuth loopback callback listener could not bind a random high port.")


def start_guard_browser_session(
    *,
    connect_url: str,
    machine_id: str,
    machine_label: str,
) -> GuardOAuthBrowserSession:
    _, allowed_origin = resolve_connect_url(connect_url)
    client = resolve_guard_oauth_client_config(allowed_origin)
    pkce_verifier = generate_pkce_verifier()
    state = secrets.token_urlsafe(32)
    dpop_key_material = generate_dpop_key_pair()
    session = start_guard_loopback_callback_listener(
        expected_state=state,
        client_id=client.client_id,
        machine_id=machine_id,
        machine_label=machine_label,
        dpop_key_material=dpop_key_material,
        pkce_verifier=pkce_verifier,
    )
    authorize_url = _build_browser_authorize_url(
        authorize_endpoint=client.authorize_endpoint,
        client_id=client.client_id,
        redirect_uri=session.redirect_uri,
        state=state,
        code_challenge=build_pkce_s256_challenge(pkce_verifier),
        machine_id=machine_id,
        machine_label=machine_label,
    )
    session.authorize_url = authorize_url
    session.pkce_verifier = pkce_verifier
    return session


def resolve_connect_url(connect_url: str) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(connect_url.strip() or DEFAULT_GUARD_CONNECT_URL)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Guard connect URL must be an absolute http(s) URL.")
    path = parsed.path or "/guard/connect"
    normalized_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))
    allowed_origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return normalized_url, allowed_origin


def _oauth_sync_url_from_issuer(issuer: str) -> str:
    oauth_client = resolve_guard_oauth_client_config(issuer)
    prefix = guard_api_base_path(issuer)
    return f"{oauth_client.issuer}{prefix}/api/guard/receipts/sync"


def _build_sync_auth_context(
    *,
    access_token: str,
    dpop_key_material: GuardDpopKeyMaterial,
    sync_url: str,
) -> dict[str, object]:
    return {
        "access_token": access_token,
        "dpop_key_material": dpop_key_material,
        "sync_url": sync_url,
    }


def build_device_authorization_request_body(
    *,
    machine_id: str,
    machine_label: str,
    machine_location_label: str | None = None,
    runtime_id: str,
    runtime_label: str,
    client_id: str,
    scopes: tuple[str, ...] = DEFAULT_GUARD_DEVICE_SCOPES,
) -> str:
    payload = {
        "client_id": client_id,
        "scope": " ".join(scopes),
        "requested_machine_id": machine_id,
        "requested_machine_label": machine_label,
        "requested_runtime_id": runtime_id,
        "requested_runtime_label": runtime_label,
    }
    if isinstance(machine_location_label, str) and machine_location_label.strip():
        payload["requested_machine_location_label"] = machine_location_label.strip()
    return urllib.parse.urlencode(payload)


def resolve_machine_location_label() -> str | None:
    tzinfo = datetime.now().astimezone().tzinfo
    timezone_key = getattr(tzinfo, "key", None)
    if isinstance(timezone_key, str) and timezone_key.strip():
        return timezone_key.strip()
    timezone_name = datetime.now().astimezone().tzname()
    if isinstance(timezone_name, str) and timezone_name.strip():
        return timezone_name.strip()
    return None


def _resolve_guard_device_scopes(*, ci_safe: bool) -> tuple[str, ...]:
    return CI_SAFE_GUARD_DEVICE_SCOPES if ci_safe else DEFAULT_GUARD_DEVICE_SCOPES


def _require_string(payload: dict[str, object], key: str) -> str:
    value = str(payload.get(key) or "").strip()
    if not value:
        raise RuntimeError(f"Guard OAuth token exchange failed: missing {key}.")
    return value


def _parse_guard_token_exchange_payload(payload: dict[str, object]) -> GuardOAuthTokenExchangeResult:
    access_token = _require_string(payload, "access_token")
    token_type = _require_string(payload, "token_type")
    if token_type.lower() != "bearer":
        raise RuntimeError("Guard OAuth token exchange failed: missing access token.")
    now = datetime.now(timezone.utc)
    claims = _decode_access_token_claims(access_token)
    expires_in = _int_payload_value(payload, "expires_in", 0)
    return GuardOAuthTokenExchangeResult(
        access_token=access_token,
        access_token_expires_at=_guard_access_token_expires_at(
            access_token=access_token,
            expires_in=expires_in,
            now=now,
        ),
        refresh_token=str(payload.get("refresh_token") or "").strip() or None,
        expires_in=expires_in,
        scope=str(payload.get("scope") or "").strip(),
        token_type=token_type,
        grant_id=_read_nested_string(claims, "grant", "grantId"),
        machine_id=_read_nested_string(claims, "machine", "machineId"),
        supply_chain_entitlement=build_oauth_package_firewall_entitlement(
            payload,
            now=now,
        ),
        workspace_id=_read_nested_string(claims, "workspace", "workspaceId"),
        cloud_user_profile=_extract_cloud_user_profile(payload),
    )


def build_device_authorization_copy_payload(response: dict[str, object]) -> dict[str, object]:
    user_code = str(response.get("user_code") or "").strip()
    verification_uri = str(response.get("verification_uri") or "").strip()
    verification_uri_complete = str(response.get("verification_uri_complete") or "").strip()
    if not user_code or not verification_uri:
        raise ValueError("Device authorization response is missing approval instructions.")
    return {
        "status": "waiting_for_approval",
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete or None,
        "expires_in": _int_payload_value(response, "expires_in", 0),
        "interval": _int_payload_value(response, "interval", 5),
        "next_action": {
            "command": "open",
            "target": verification_uri,
            "message": f"Open {verification_uri} and enter code {user_code}.",
        },
    }


def _device_token_request_body(*, client_id: str, device_code: str) -> bytes:
    return urllib.parse.urlencode(
        {
            "grant_type": DEVICE_CODE_GRANT_TYPE,
            "client_id": client_id,
            "device_code": device_code,
        }
    ).encode("utf-8")


def _refresh_token_request_body(*, client_id: str, refresh_token: str) -> bytes:
    return urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
        }
    ).encode("utf-8")


def _self_revoke_request_body(
    *,
    workspace_id: str,
    revoke_cloud_grant: bool,
) -> bytes:
    return urllib.parse.urlencode(
        {
            "workspace_id": workspace_id,
            "reason": "user_disconnect",
            "revoke_machine_grant": "true" if revoke_cloud_grant else "false",
            "revoke_runtime_grant": "true" if revoke_cloud_grant else "false",
        }
    ).encode("utf-8")


def _load_error_payload(error: urllib.error.HTTPError) -> dict[str, object] | None:
    try:
        raw_body = error.read().decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not raw_body.strip():
        return None
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def device_authorization_endpoint_from_connect_url(connect_url: str) -> str:
    _, allowed_origin = resolve_connect_url(connect_url)
    return resolve_guard_oauth_client_config(allowed_origin).device_authorization_endpoint


def request_device_authorization(url: str, body: str) -> dict[str, object]:
    encoded_body = body.encode("utf-8")
    request = urllib.request.Request(
        url,
        data=encoded_body,
        method="POST",
        headers=_guard_oauth_request_headers(),
    )
    with managed_urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Guard Device Code authorization failed: invalid response.")
    return payload


def exchange_guard_device_code(
    *,
    token_endpoint: str,
    client_id: str,
    device_code: str,
    dpop_key_material: GuardDpopKeyMaterial,
    interval_seconds: int,
    expires_in_seconds: int,
    wait_timeout_seconds: float | None = None,
    urlopen=managed_urlopen,
    sleep=time.sleep,
    now: datetime | None = None,
) -> GuardOAuthTokenExchangeResult:
    wait_window_seconds = max(expires_in_seconds, 1)
    if wait_timeout_seconds is not None:
        wait_window_seconds = min(wait_window_seconds, max(wait_timeout_seconds, 0))
    deadline = time.monotonic() + wait_window_seconds
    current_interval = max(interval_seconds, 1)
    dpop_nonce: str | None = None
    nonce_retry_count = 0
    while True:
        request = urllib.request.Request(
            token_endpoint,
            data=_device_token_request_body(client_id=client_id, device_code=device_code),
            method="POST",
            headers=_guard_oauth_request_headers(
                dpop=_sign_dpop_proof(
                    token_endpoint=token_endpoint,
                    dpop_key_material=dpop_key_material,
                    now=now or datetime.now(timezone.utc),
                    nonce=dpop_nonce,
                ),
            ),
        )
        try:
            with urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            payload = _load_error_payload(error)
            challenge_nonce = _oauth_dpop_nonce_from_http_error(error, payload)
            if challenge_nonce is not None and challenge_nonce != dpop_nonce and nonce_retry_count < 3:
                dpop_nonce = challenge_nonce
                nonce_retry_count += 1
                continue
            oauth_error = str(payload.get("error") or "").strip() if isinstance(payload, dict) else ""
            if oauth_error == "authorization_pending":
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "Guard OAuth approval timed out. Retry `hol-guard connect --headless` to request a new code."
                    ) from error
                sleep(float(current_interval))
                continue
            if oauth_error == "slow_down":
                current_interval = max(current_interval + DEVICE_CODE_SLOW_DOWN_SECONDS, 1)
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "Guard OAuth approval timed out. Retry `hol-guard connect --headless` to request a new code."
                    ) from error
                sleep(float(current_interval))
                continue
            if oauth_error == "expired_token":
                raise RuntimeError(
                    "Guard OAuth device approval expired. Retry `hol-guard connect --headless` to request a new code."
                ) from error
            if oauth_error in {"access_denied", "authorization_declined"}:
                raise RuntimeError(
                    "Guard OAuth approval was denied. Retry `hol-guard connect --headless` to request a new code."
                ) from error
            message = (
                str(payload.get("error_description") or oauth_error or error.reason)
                if isinstance(payload, dict)
                else str(error.reason)
            )
            raise RuntimeError(f"Guard OAuth token exchange failed: {message}") from error
        if not isinstance(payload, dict):
            raise RuntimeError("Guard OAuth token exchange failed: invalid response.")
        return _parse_guard_token_exchange_payload(payload)


def exchange_guard_authorization_code(
    *,
    token_endpoint: str,
    client_id: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    dpop_key_material: GuardDpopKeyMaterial,
    urlopen=managed_urlopen,
    now: datetime | None = None,
) -> GuardOAuthTokenExchangeResult:
    request_body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
    ).encode("utf-8")
    dpop_nonce: str | None = None
    nonce_retry_count = 0
    while True:
        request = urllib.request.Request(
            token_endpoint,
            data=request_body,
            method="POST",
            headers=_guard_oauth_request_headers(
                dpop=_sign_dpop_proof(
                    token_endpoint=token_endpoint,
                    dpop_key_material=dpop_key_material,
                    now=now or datetime.now(timezone.utc),
                    nonce=dpop_nonce,
                ),
            ),
        )
        try:
            with urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            payload = _load_error_payload(error)
            challenge_nonce = _oauth_dpop_nonce_from_http_error(error, payload)
            if challenge_nonce is not None and challenge_nonce != dpop_nonce and nonce_retry_count < 3:
                dpop_nonce = challenge_nonce
                nonce_retry_count += 1
                continue
            raise
        if not isinstance(payload, dict):
            raise RuntimeError("Guard OAuth token exchange failed: invalid response.")
        return _parse_guard_token_exchange_payload(payload)


def refresh_guard_access_token(
    *,
    token_endpoint: str,
    client_id: str,
    refresh_token: str,
    dpop_key_material: GuardDpopKeyMaterial,
    urlopen=managed_urlopen,
    now: datetime | None = None,
) -> GuardOAuthTokenExchangeResult:
    dpop_nonce: str | None = None
    nonce_retry_count = 0
    while True:
        request = urllib.request.Request(
            token_endpoint,
            data=_refresh_token_request_body(
                client_id=client_id,
                refresh_token=refresh_token,
            ),
            method="POST",
            headers=_guard_oauth_request_headers(
                dpop=_sign_dpop_proof(
                    token_endpoint=token_endpoint,
                    dpop_key_material=dpop_key_material,
                    now=now or datetime.now(timezone.utc),
                    nonce=dpop_nonce,
                ),
            ),
        )
        try:
            with urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            payload = _load_error_payload(error)
            challenge_nonce = _oauth_dpop_nonce_from_http_error(error, payload)
            if challenge_nonce is not None and challenge_nonce != dpop_nonce and nonce_retry_count < 3:
                dpop_nonce = challenge_nonce
                nonce_retry_count += 1
                continue
            raise _guard_oauth_token_exchange_error_from_http_error(error, payload) from error
        if not isinstance(payload, dict):
            raise RuntimeError("Guard OAuth token exchange failed: invalid response.")
        return _parse_guard_token_exchange_payload(payload)


class GuardOAuthTokenExchangeError(RuntimeError):
    def __init__(
        self,
        *,
        oauth_error: str | None,
        oauth_error_description: str | None,
        status_code: int | None,
        reason: str | None,
    ) -> None:
        self.oauth_error = oauth_error
        self.oauth_error_description = oauth_error_description
        self.status_code = status_code
        self.reason = reason
        message = oauth_error_description or oauth_error or reason or "token exchange failed."
        super().__init__(f"Guard OAuth token exchange failed: {message}")


def _guard_oauth_token_exchange_error_from_http_error(
    error: urllib.error.HTTPError,
    payload: object,
) -> GuardOAuthTokenExchangeError:
    oauth_error = payload.get("error") if isinstance(payload, dict) else None
    oauth_error_description = payload.get("error_description") if isinstance(payload, dict) else None
    return GuardOAuthTokenExchangeError(
        oauth_error=str(oauth_error).strip() if isinstance(oauth_error, str) and oauth_error.strip() else None,
        oauth_error_description=(
            str(oauth_error_description).strip()
            if isinstance(oauth_error_description, str) and oauth_error_description.strip()
            else None
        ),
        status_code=error.code,
        reason=str(error.reason).strip() if str(error.reason).strip() else None,
    )


def _oauth_refresh_error_means_grant_inactive(error: Exception) -> bool:
    if isinstance(error, GuardOAuthTokenExchangeError):
        oauth_error = (error.oauth_error or "").strip().lower()
        if error.status_code not in {400, 401, 403}:
            return False
        return oauth_error == "invalid_grant"
    message = str(error).strip().lower()
    return "missing, expired, or already consumed" in message


def revoke_guard_self_oauth_grant(
    *,
    oauth_client: GuardOAuthClientConfig,
    access_token: str,
    workspace_id: str,
    revoke_cloud_grant: bool,
    dpop_key_material: GuardDpopKeyMaterial,
    urlopen=managed_urlopen,
    now: datetime | None = None,
) -> None:
    revoke_url = f"{oauth_client.issuer.rstrip('/')}/api/guard/oauth/revoke/self"
    dpop_nonce: str | None = None
    nonce_retry_count = 0
    while True:
        request = urllib.request.Request(
            revoke_url,
            data=_self_revoke_request_body(
                workspace_id=workspace_id,
                revoke_cloud_grant=revoke_cloud_grant,
            ),
            method="POST",
            headers={
                **_guard_oauth_request_headers(
                    dpop=_sign_dpop_proof(
                        token_endpoint=revoke_url,
                        dpop_key_material=dpop_key_material,
                        now=now or datetime.now(timezone.utc),
                        nonce=dpop_nonce,
                    ),
                ),
                "Authorization": f"Bearer {access_token}",
            },
        )
        try:
            with urlopen(request, timeout=20):
                return
        except urllib.error.HTTPError as error:
            payload = _load_error_payload(error)
            challenge_nonce = _oauth_dpop_nonce_from_http_error(error, payload)
            if challenge_nonce is not None and challenge_nonce != dpop_nonce and nonce_retry_count < 3:
                dpop_nonce = challenge_nonce
                nonce_retry_count += 1
                continue
            message = (
                str(payload.get("error_description") or payload.get("error") or error.reason)
                if isinstance(payload, dict)
                else str(error.reason)
            )
            raise RuntimeError(f"Guard OAuth disconnect failed: {message}") from error


def _require_oauth_credential_string(credentials: dict[str, object], key: str) -> str:
    value = credentials.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise RuntimeError("Guard Cloud is not connected yet. Run `hol-guard connect`.")


def _oauth_dpop_key_material_from_credentials(
    credentials: dict[str, object],
) -> GuardDpopKeyMaterial:
    dpop_private_key_pem = _require_oauth_credential_string(credentials, "dpop_private_key_pem")
    dpop_public_jwk = credentials.get("dpop_public_jwk")
    if not isinstance(dpop_public_jwk, dict):
        raise RuntimeError("Guard Cloud is not connected yet. Run `hol-guard connect`.")
    return GuardDpopKeyMaterial(
        algorithm="ES256",
        private_key_pem=dpop_private_key_pem,
        public_jwk={str(key): str(value) for key, value in dpop_public_jwk.items()},
        public_jwk_thumbprint=_require_oauth_credential_string(
            credentials,
            "dpop_public_jwk_thumbprint",
        ),
    )


def _persist_oauth_local_credentials(
    *,
    store: GuardStore,
    issuer: str,
    client_id: str,
    refresh_token: str,
    dpop_key_material: GuardDpopKeyMaterial,
    now: str,
    grant_id: str | None = None,
    machine_id: str | None = None,
    supply_chain_entitlement: dict[str, object] | None = None,
    workspace_id: str | None = None,
    cloud_user_profile: dict[str, str] | None = None,
    runtime_id: str | None = None,
    runtime_label: str | None = None,
    access_token: str | None = None,
    access_token_expires_at: str | None = None,
) -> None:
    store.set_oauth_local_credentials(
        issuer=issuer,
        client_id=client_id,
        refresh_token=refresh_token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id=grant_id,
        machine_id=machine_id,
        supply_chain_entitlement_expires_at=(
            str(supply_chain_entitlement.get("supply_chain_entitlement_expires_at"))
            if isinstance(supply_chain_entitlement, dict)
            and isinstance(supply_chain_entitlement.get("supply_chain_entitlement_expires_at"), str)
            else None
        ),
        supply_chain_firewall=(
            bool(supply_chain_entitlement.get("supply_chain_firewall"))
            if isinstance(supply_chain_entitlement, dict)
            and isinstance(supply_chain_entitlement.get("supply_chain_firewall"), bool)
            else None
        ),
        supply_chain_plan_id=(
            str(supply_chain_entitlement.get("supply_chain_plan_id"))
            if isinstance(supply_chain_entitlement, dict)
            and isinstance(supply_chain_entitlement.get("supply_chain_plan_id"), str)
            else None
        ),
        workspace_id=workspace_id,
        cloud_user_profile=cloud_user_profile,
        runtime_id=runtime_id,
        runtime_label=runtime_label,
        access_token=access_token,
        access_token_expires_at=access_token_expires_at,
        now=now,
    )
    reconcile_connect_state_with_oauth_entitlement(store, now=now)


def run_guard_disconnect_command(
    *,
    store: GuardStore,
    revoke_cloud_grant: bool,
    now: str | None = None,
    urlopen=managed_urlopen,
) -> dict[str, object]:
    store.repair_oauth_local_credential_storage_from_primary()
    credentials = store.get_oauth_local_credentials(allow_primary=True)
    if credentials is None:
        return {
            "status": "not_connected",
            "cloud_grant_revoked": False,
            "reconnect_command": CONNECT_COMMAND,
        }

    issuer = _require_oauth_credential_string(credentials, "issuer")
    client_id = _require_oauth_credential_string(credentials, "client_id")
    refresh_token = _require_oauth_credential_string(credentials, "refresh_token")
    workspace_id = _require_oauth_credential_string(credentials, "workspace_id")
    dpop_key_material = _oauth_dpop_key_material_from_credentials(credentials)
    oauth_client = resolve_guard_oauth_client_config(issuer)
    exchange_now = datetime.fromisoformat(now) if isinstance(now, str) else datetime.now(timezone.utc)
    timestamp = now or exchange_now.isoformat()
    try:
        token_result = refresh_guard_access_token(
            token_endpoint=oauth_client.token_endpoint,
            client_id=client_id,
            refresh_token=refresh_token,
            dpop_key_material=dpop_key_material,
            urlopen=urlopen,
            now=exchange_now,
        )
    except RuntimeError as error:
        if not _oauth_refresh_error_means_grant_inactive(error):
            raise
        store.clear_oauth_local_credentials()
        return {
            "status": "disconnected",
            "cloud_grant_revoked": False,
            "cloud_grant_status": "already_inactive",
            "detail": "Guard Cloud grant was already expired. Cleared local sign-in on this machine.",
            "reconnect_command": CONNECT_COMMAND,
        }
    rotated_refresh_token = token_result.refresh_token
    if rotated_refresh_token and rotated_refresh_token != refresh_token:
        _persist_oauth_local_credentials(
            store=store,
            issuer=oauth_client.issuer,
            client_id=client_id,
            refresh_token=rotated_refresh_token,
            dpop_key_material=dpop_key_material,
            grant_id=_read_nested_string(credentials, "grant_id"),
            machine_id=_read_nested_string(credentials, "machine_id"),
            supply_chain_entitlement=token_result.supply_chain_entitlement,
            workspace_id=workspace_id,
            cloud_user_profile=token_result.cloud_user_profile,
            runtime_id=_read_nested_string(credentials, "runtime_id"),
            runtime_label=_read_nested_string(credentials, "runtime_label"),
            access_token=token_result.access_token,
            access_token_expires_at=token_result.access_token_expires_at,
            now=timestamp,
        )
    revoke_guard_self_oauth_grant(
        oauth_client=oauth_client,
        access_token=token_result.access_token,
        workspace_id=workspace_id,
        revoke_cloud_grant=revoke_cloud_grant,
        dpop_key_material=dpop_key_material,
        urlopen=urlopen,
        now=exchange_now,
    )
    store.clear_oauth_local_credentials()
    return {
        "status": "disconnected",
        "cloud_grant_revoked": revoke_cloud_grant,
        "reconnect_command": CONNECT_COMMAND,
    }


def run_guard_connect_repair_command(
    *,
    store: GuardStore,
    sync_url: str,
    connect_url: str,
) -> dict[str, object]:
    repair_result = prepare_guard_cloud_connect_authorization(store)
    payload = build_connect_status_payload(
        store=store,
        sync_url=sync_url,
        connect_url=connect_url,
        action="repair",
    )
    payload.update(repair_result)
    if repair_result.get("cleared_stale_sign_in"):
        payload["repair_message"] = (
            "Cleared expired Guard Cloud sign-in on this device. Run hol-guard connect to sign in again."
        )
        payload["recovery_command"] = CONNECT_COMMAND
    elif not repair_result.get("existing_sign_in_valid"):
        payload["repair_message"] = "Run hol-guard connect to sign in to Guard Cloud on this device."
        payload["recovery_command"] = CONNECT_COMMAND
    return payload


def run_guard_device_connect_command(
    *,
    store: GuardStore,
    connect_url: str,
    request_device_authorization=request_device_authorization,
    token_urlopen=managed_urlopen,
    sleep=time.sleep,
    now: str | None = None,
    wait_timeout_seconds: float | None = None,
    announce_copy=None,
    open_browser=None,
    ci_safe: bool = False,
    machine_label: str | None = None,
    include_sync_auth_context: bool = False,
) -> dict[str, object]:
    prepare_guard_cloud_connect_authorization(store)
    device = store.get_device_metadata()
    _, allowed_origin = resolve_connect_url(connect_url)
    oauth_client = resolve_guard_oauth_client_config(allowed_origin)
    dpop_key_material = generate_dpop_key_pair()
    resolved_machine_label = machine_label.strip() if isinstance(machine_label, str) else ""
    request_body = build_device_authorization_request_body(
        machine_id=str(device["installation_id"]),
        machine_label=resolved_machine_label or str(device["device_label"]),
        machine_location_label=resolve_machine_location_label(),
        runtime_id=HEADLESS_RUNTIME_ID,
        runtime_label=HEADLESS_RUNTIME_LABEL,
        client_id=oauth_client.client_id,
        scopes=_resolve_guard_device_scopes(ci_safe=ci_safe),
    )
    response = request_device_authorization(
        oauth_client.device_authorization_endpoint,
        request_body,
    )
    payload = build_device_authorization_copy_payload(response)
    payload["connect_mode"] = "device_code"
    if open_browser is not None:
        next_action = payload.get("next_action")
        target = next_action.get("target") if isinstance(next_action, dict) else None
        opened = False
        if isinstance(target, str) and target:
            opened = bool(open_browser(target))
        payload["browser_opened"] = opened
    if announce_copy is not None:
        announce_copy(payload)
    device_code = str(response.get("device_code") or "").strip()
    if not device_code:
        raise ValueError("Device authorization response is missing device_code.")
    token_result = exchange_guard_device_code(
        token_endpoint=oauth_client.token_endpoint,
        client_id=oauth_client.client_id,
        device_code=device_code,
        dpop_key_material=dpop_key_material,
        interval_seconds=_int_payload_value(response, "interval", 5),
        expires_in_seconds=_int_payload_value(response, "expires_in", 0),
        wait_timeout_seconds=wait_timeout_seconds,
        urlopen=token_urlopen,
        sleep=sleep,
        now=datetime.fromisoformat(now) if now else None,
    )
    if token_result.refresh_token is None:
        raise RuntimeError("Guard OAuth token exchange failed: missing refresh token.")
    timestamp = now or datetime.now(timezone.utc).isoformat()
    _persist_oauth_local_credentials(
        store=store,
        issuer=oauth_client.issuer,
        client_id=oauth_client.client_id,
        refresh_token=token_result.refresh_token,
        dpop_key_material=dpop_key_material,
        grant_id=token_result.grant_id,
        machine_id=token_result.machine_id,
        supply_chain_entitlement=token_result.supply_chain_entitlement,
        workspace_id=token_result.workspace_id,
        cloud_user_profile=token_result.cloud_user_profile,
        runtime_id=HEADLESS_RUNTIME_ID,
        runtime_label=HEADLESS_RUNTIME_LABEL,
        access_token=token_result.access_token,
        access_token_expires_at=token_result.access_token_expires_at,
        now=timestamp,
    )
    sync_url = _oauth_sync_url_from_issuer(oauth_client.issuer)
    payload.update(
        {
            "status": "connected",
            "grant_id": token_result.grant_id,
            "machine_id": token_result.machine_id,
            "workspace_id": token_result.workspace_id,
            "connect_url": connect_url,
            "sync_url": sync_url,
            "connect_command": CONNECT_COMMAND,
            "connect_status_command": CONNECT_STATUS_COMMAND,
            "connect_repair_command": CONNECT_REPAIR_COMMAND,
        }
    )
    if include_sync_auth_context:
        payload[CONNECT_SYNC_AUTH_CONTEXT_KEY] = _build_sync_auth_context(
            access_token=token_result.access_token,
            dpop_key_material=dpop_key_material,
            sync_url=sync_url,
        )
    return payload


def run_guard_browser_connect_command(
    *,
    store: GuardStore,
    connect_url: str,
    start_browser_session=start_guard_browser_session,
    open_browser=None,
    exchange_authorization_code=exchange_guard_authorization_code,
    now: str | None = None,
    wait_timeout_seconds: float = 180,
    include_sync_auth_context: bool = False,
) -> dict[str, object]:
    from .progress import GuardProgress

    with GuardProgress(total=6, title="Guard Connect") as bar:
        bar.step("Preparing authorization...")
        prepare_guard_cloud_connect_authorization(store)
        device = store.get_device_metadata()
        _, allowed_origin = resolve_connect_url(connect_url)
        oauth_client = resolve_guard_oauth_client_config(allowed_origin)
        browser_opener = open_browser if open_browser is not None else __import__("webbrowser").open

        bar.step("Starting browser session...")
        session = start_browser_session(
            connect_url=connect_url,
            machine_id=str(device["installation_id"]),
            machine_label=str(device["device_label"]),
        )
        try:
            bar.step("Opening browser for sign-in...")
            browser_opened = bool(browser_opener(session.authorize_url))
            bar.step("Waiting for authentication (complete sign-in in your browser)...")
            callback = session.wait_for_callback(wait_timeout_seconds)
            bar.step("Exchanging authorization code for tokens...")
            token_result = exchange_authorization_code(
                token_endpoint=oauth_client.token_endpoint,
                client_id=oauth_client.client_id,
                code=callback.code,
                redirect_uri=session.redirect_uri,
                code_verifier=session.pkce_verifier,
                dpop_key_material=session.dpop_key_material,
            )
        finally:
            session.close()
        if token_result.refresh_token is None:
            raise RuntimeError("Guard OAuth token exchange failed: missing refresh token.")
        bar.step("Saving credentials locally...")
        timestamp = now or datetime.now(timezone.utc).isoformat()
        _persist_oauth_local_credentials(
            store=store,
            issuer=oauth_client.issuer,
            client_id=oauth_client.client_id,
            refresh_token=token_result.refresh_token,
            dpop_key_material=session.dpop_key_material,
            grant_id=token_result.grant_id,
            machine_id=token_result.machine_id,
            supply_chain_entitlement=token_result.supply_chain_entitlement,
            workspace_id=token_result.workspace_id,
            cloud_user_profile=token_result.cloud_user_profile,
            runtime_id=HEADLESS_RUNTIME_ID,
            runtime_label=HEADLESS_RUNTIME_LABEL,
            access_token=token_result.access_token,
            access_token_expires_at=token_result.access_token_expires_at,
            now=timestamp,
        )
        bar.done("Authorization complete")

    sync_url = _oauth_sync_url_from_issuer(oauth_client.issuer)
    payload: dict[str, object] = {
        "status": "connected",
        "connect_mode": "browser_oauth",
        "browser_opened": browser_opened,
        "authorize_url": session.authorize_url,
        "redirect_uri": session.redirect_uri,
        "grant_id": token_result.grant_id,
        "machine_id": token_result.machine_id,
        "workspace_id": token_result.workspace_id,
        "connect_url": connect_url,
        "sync_url": sync_url,
        "connect_command": CONNECT_COMMAND,
        "connect_status_command": CONNECT_STATUS_COMMAND,
        "connect_repair_command": CONNECT_REPAIR_COMMAND,
    }
    if include_sync_auth_context:
        payload[CONNECT_SYNC_AUTH_CONTEXT_KEY] = _build_sync_auth_context(
            access_token=token_result.access_token,
            dpop_key_material=session.dpop_key_material,
            sync_url=sync_url,
        )
    return payload


def build_connect_status_payload(
    *,
    store: GuardStore,
    sync_url: str,
    connect_url: str,
    action: str = "status",
) -> dict[str, object]:
    latest_state = store.get_effective_guard_connect_state(now=datetime.now(timezone.utc).isoformat())
    cloud_profile = store.get_cloud_sync_profile()
    oauth_storage_health = store.get_oauth_local_credential_health()
    oauth_required = connect_state_requires_oauth(latest_state=latest_state, cloud_profile=cloud_profile)
    latest_state = normalize_connect_state_for_missing_oauth(
        latest_state=latest_state,
        oauth_storage_health=oauth_storage_health,
        oauth_required=oauth_required,
    )
    oauth_repair_required = (
        bool(oauth_storage_health.get("configured")) and oauth_storage_health.get("state") == "degraded"
    )
    has_sync_summary = bool(store.get_sync_payload("sync_summary"))
    status = str(latest_state.get("status") or "not_paired") if latest_state is not None else "not_paired"
    milestone = str(latest_state.get("milestone") or "not_started") if latest_state is not None else "not_started"
    reason = latest_state.get("reason") if latest_state is not None else None
    stored_sync_url = latest_state.get("sync_url") if latest_state is not None else None
    if latest_state is None and cloud_profile is not None:
        status = "connected"
        milestone = "first_sync_succeeded" if has_sync_summary else "first_sync_pending"
    recovery_command = connect_recovery_command(latest_state)
    if latest_state is None and cloud_profile is not None and has_sync_summary:
        recovery_command = "hol-guard sync"
    if oauth_repair_required and cloud_profile is None:
        status = "retry_required"
        milestone = "first_sync_failed"
        reason = "Guard Cloud authorization on this machine is incomplete. Run hol-guard connect again."
        recovery_command = CONNECT_COMMAND
    elif oauth_required and not bool(oauth_storage_health.get("configured")) and status == "connected":
        status = "retry_required"
        milestone = "first_sync_failed"
        if not isinstance(reason, str) or not reason.strip():
            reason = "Guard Cloud authorization on this machine is incomplete. Run hol-guard connect again."
        recovery_command = CONNECT_COMMAND
    payload: dict[str, object] = {
        "status": status,
        "milestone": milestone,
        "reason": reason,
        "latest_connect_state": latest_state,
        "sync_url": (
            stored_sync_url
            if isinstance(stored_sync_url, str) and stored_sync_url.strip()
            else (cloud_profile["sync_url"] if cloud_profile is not None else sync_url)
        ),
        "connect_url": connect_url,
        "connect_command": CONNECT_COMMAND,
        "recovery_command": recovery_command,
        "connect_status_command": CONNECT_STATUS_COMMAND,
        "connect_repair_command": CONNECT_REPAIR_COMMAND,
    }
    if action in {"repair", "re-pair"}:
        payload["repair_action"] = "rerun_connect"
        payload["repair_message"] = "Run hol-guard connect to start browser sign-in."
    elif (oauth_repair_required and cloud_profile is None) or (
        oauth_required and not bool(oauth_storage_health.get("configured")) and payload["status"] == "retry_required"
    ):
        payload["repair_message"] = "Run hol-guard connect again to repair local Guard Cloud authorization."
    return payload


def connect_state_requires_oauth(
    *,
    latest_state: Mapping[str, object] | None,
    cloud_profile: Mapping[str, object] | None,
) -> bool:
    request_id = latest_state.get("request_id") if latest_state is not None else None
    if isinstance(request_id, str) and bool(request_id.strip()):
        return True
    auth_mode = cloud_profile.get("auth_mode") if isinstance(cloud_profile, dict) else None
    return auth_mode == "oauth"


def normalize_connect_state_for_missing_oauth(
    *,
    latest_state: dict[str, object] | None,
    oauth_storage_health: dict[str, object],
    oauth_required: bool,
) -> dict[str, object] | None:
    if latest_state is None:
        return latest_state
    if not oauth_required:
        return latest_state
    oauth_state = str(oauth_storage_health.get("state") or "")
    oauth_configured = bool(oauth_storage_health.get("configured"))
    if oauth_state != "degraded" and oauth_configured:
        return latest_state
    status = str(latest_state.get("status") or "")
    if status != "connected":
        return latest_state
    normalized = dict(latest_state)
    normalized["status"] = "retry_required"
    normalized["milestone"] = "first_sync_failed"
    normalized["reason"] = "Guard Cloud authorization on this machine is incomplete. Run hol-guard connect again."
    poll_after_ms = latest_state.get("poll_after_ms")
    return build_connect_state_response(
        normalized,
        poll_after_ms=poll_after_ms if isinstance(poll_after_ms, int) else None,
    )


def connect_recovery_command(latest_state: dict[str, object] | None) -> str:
    if latest_state is None:
        return CONNECT_COMMAND
    milestone = str(latest_state.get("milestone") or "")
    status = str(latest_state.get("status") or "")
    if status in {"retry_required", "expired"} or milestone in {"first_sync_failed", "expired", "sync_not_available"}:
        return CONNECT_COMMAND
    if status == "connected" and milestone == "first_sync_succeeded":
        return "hol-guard sync"
    return CONNECT_COMMAND


def connect_retry_refresh_race_from_reason(reason: str | None) -> bool:
    return isinstance(reason, str) and "already consumed" in reason.lower()


def resolve_guard_cloud_state(
    *,
    sync_configured: bool,
    sync_completed: bool,
    remote_payload_active: bool,
    oauth_repair_required: bool = False,
    connect_retry_required: bool = False,
) -> str:
    if not sync_configured:
        return "local_only"
    if oauth_repair_required:
        return "local_only"
    if connect_retry_required:
        return "local_only" if sync_completed or remote_payload_active else "paired_waiting"
    if sync_completed or remote_payload_active:
        return "paired_active"
    return "paired_waiting"


def resolve_guard_cloud_repair_detail(
    *,
    shared_proof_recorded: bool,
    first_sync_message: str,
    resume_message: str,
) -> str:
    return resume_message if shared_proof_recorded else first_sync_message
