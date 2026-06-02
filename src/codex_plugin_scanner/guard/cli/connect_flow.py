"""OAuth Device Code Guard connect helpers."""

from __future__ import annotations

import base64
import http.server
import json
import secrets
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from ..store import GuardStore
from .oauth_client import (
    GuardDpopKeyMaterial,
    build_pkce_s256_challenge,
    generate_dpop_key_pair,
    generate_pkce_verifier,
    resolve_guard_oauth_client_config,
)

DEFAULT_GUARD_SYNC_URL = "https://hol.org/api/guard/receipts/sync"
DEFAULT_GUARD_CONNECT_URL = "https://hol.org/guard/connect"
DEFAULT_GUARD_DEVICE_SCOPES = (
    "guard:runtime.sync",
    "guard:receipt.write",
    "guard:runtime.session.write",
    "guard:offline_access",
)
CONNECT_COMMAND = "hol-guard connect"
CONNECT_STATUS_COMMAND = "hol-guard connect status"
CONNECT_REPAIR_COMMAND = "hol-guard connect repair"
HEADLESS_CONNECT_COMMAND = "hol-guard connect --headless"
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
DEVICE_CODE_SLOW_DOWN_SECONDS = 5
HEADLESS_RUNTIME_ID = "hol-guard"
HEADLESS_RUNTIME_LABEL = "HOL Guard CLI"
_LOOPBACK_REDIRECT_PATH = "/oauth/callback"
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
    workspace_id: str | None


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


def _encode_jwt_segment(payload: dict[str, object]) -> str:
    return _base64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _sign_dpop_proof(*, token_endpoint: str, dpop_key_material: GuardDpopKeyMaterial, now: datetime) -> str:
    issued_at = int(now.timestamp())
    header = {
        "alg": dpop_key_material.algorithm,
        "jwk": dpop_key_material.public_jwk,
        "typ": "dpop+jwt",
    }
    claims = {
        "htu": token_endpoint,
        "htm": "POST",
        "iat": issued_at,
        "jti": str(uuid4()),
    }
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

    class _CallbackHandler(http.server.BaseHTTPRequestHandler):
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
                self.server.guard_callback = GuardOAuthLoopbackCallback(  # type: ignore[attr-defined]
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
            self.server.guard_callback = GuardOAuthLoopbackCallback(code=code, state=state)  # type: ignore[attr-defined]
            callback_ready.set()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"HOL Guard connected. Return to your terminal.")

        def log_message(self, _message: str, *args: object) -> None:
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


def build_device_authorization_request_body(
    *,
    machine_id: str,
    machine_label: str,
    runtime_id: str,
    runtime_label: str,
    client_id: str,
    scopes: tuple[str, ...] = DEFAULT_GUARD_DEVICE_SCOPES,
) -> str:
    return urllib.parse.urlencode(
        {
            "client_id": client_id,
            "scope": " ".join(scopes),
            "requested_machine_id": machine_id,
            "requested_machine_label": machine_label,
            "requested_runtime_id": runtime_id,
            "requested_runtime_label": runtime_label,
        }
    )


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
    claims = _decode_access_token_claims(access_token)
    return GuardOAuthTokenExchangeResult(
        access_token=access_token,
        refresh_token=str(payload.get("refresh_token") or "").strip() or None,
        expires_in=int(payload.get("expires_in") or 0),
        scope=str(payload.get("scope") or "").strip(),
        token_type=token_type,
        grant_id=_read_nested_string(claims, "grant", "grantId"),
        machine_id=_read_nested_string(claims, "machine", "machineId"),
        workspace_id=_read_nested_string(claims, "workspace", "workspaceId"),
    )


def build_device_authorization_copy_payload(response: dict[str, object]) -> dict[str, object]:
    user_code = str(response.get("user_code") or "").strip()
    verification_uri = str(response.get("verification_uri") or "").strip()
    verification_uri_complete = str(response.get("verification_uri_complete") or "").strip()
    if not user_code or not verification_uri:
        raise ValueError("Device authorization response is missing approval instructions.")
    next_target = verification_uri_complete or verification_uri
    return {
        "status": "waiting_for_approval",
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete or None,
        "expires_in": int(response.get("expires_in") or 0),
        "interval": int(response.get("interval") or 5),
        "next_action": {
            "command": "open",
            "target": next_target,
            "message": f"Open {next_target} and enter code {user_code}.",
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
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
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
    urlopen=urllib.request.urlopen,
    sleep=time.sleep,
    now: datetime | None = None,
) -> GuardOAuthTokenExchangeResult:
    deadline = time.monotonic() + max(expires_in_seconds, 1)
    current_interval = max(interval_seconds, 1)
    while True:
        request = urllib.request.Request(
            token_endpoint,
            data=_device_token_request_body(client_id=client_id, device_code=device_code),
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "DPoP": _sign_dpop_proof(
                    token_endpoint=token_endpoint,
                    dpop_key_material=dpop_key_material,
                    now=now or datetime.now(timezone.utc),
                ),
            },
        )
        try:
            with urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            payload = _load_error_payload(error)
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
    urlopen=urllib.request.urlopen,
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
    request = urllib.request.Request(
        token_endpoint,
        data=request_body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "DPoP": _sign_dpop_proof(
                token_endpoint=token_endpoint,
                dpop_key_material=dpop_key_material,
                now=now or datetime.now(timezone.utc),
            ),
        },
    )
    with urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Guard OAuth token exchange failed: invalid response.")
    return _parse_guard_token_exchange_payload(payload)


def run_guard_device_connect_command(
    *,
    store: GuardStore,
    connect_url: str,
    request_device_authorization=request_device_authorization,
    token_urlopen=urllib.request.urlopen,
    sleep=time.sleep,
    now: str | None = None,
    announce_copy=None,
    open_browser=None,
) -> dict[str, object]:
    device = store.get_device_metadata()
    _, allowed_origin = resolve_connect_url(connect_url)
    oauth_client = resolve_guard_oauth_client_config(allowed_origin)
    dpop_key_material = generate_dpop_key_pair()
    request_body = build_device_authorization_request_body(
        machine_id=str(device["installation_id"]),
        machine_label=str(device["device_label"]),
        runtime_id=HEADLESS_RUNTIME_ID,
        runtime_label=HEADLESS_RUNTIME_LABEL,
        client_id=oauth_client.client_id,
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
        interval_seconds=int(response.get("interval") or 5),
        expires_in_seconds=int(response.get("expires_in") or 0),
        urlopen=token_urlopen,
        sleep=sleep,
        now=datetime.fromisoformat(now) if now else None,
    )
    if token_result.refresh_token is None:
        raise RuntimeError("Guard OAuth token exchange failed: missing refresh token.")
    timestamp = now or datetime.now(timezone.utc).isoformat()
    store.set_oauth_local_credentials(
        issuer=oauth_client.issuer,
        client_id=oauth_client.client_id,
        refresh_token=token_result.refresh_token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id=token_result.grant_id,
        machine_id=token_result.machine_id,
        workspace_id=token_result.workspace_id,
        runtime_id=HEADLESS_RUNTIME_ID,
        runtime_label=HEADLESS_RUNTIME_LABEL,
        now=timestamp,
    )
    payload.update(
        {
            "status": "connected",
            "grant_id": token_result.grant_id,
            "machine_id": token_result.machine_id,
            "workspace_id": token_result.workspace_id,
            "connect_command": CONNECT_COMMAND,
            "connect_status_command": CONNECT_STATUS_COMMAND,
            "connect_repair_command": CONNECT_REPAIR_COMMAND,
        }
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
) -> dict[str, object]:
    device = store.get_device_metadata()
    _, allowed_origin = resolve_connect_url(connect_url)
    oauth_client = resolve_guard_oauth_client_config(allowed_origin)
    browser_opener = open_browser if open_browser is not None else __import__("webbrowser").open
    session = start_browser_session(
        connect_url=connect_url,
        machine_id=str(device["installation_id"]),
        machine_label=str(device["device_label"]),
    )
    try:
        browser_opened = bool(browser_opener(session.authorize_url))
        callback = session.wait_for_callback(wait_timeout_seconds)
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
    timestamp = now or datetime.now(timezone.utc).isoformat()
    store.set_oauth_local_credentials(
        issuer=oauth_client.issuer,
        client_id=oauth_client.client_id,
        refresh_token=token_result.refresh_token,
        dpop_private_key_pem=session.dpop_key_material.private_key_pem,
        dpop_public_jwk=session.dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=session.dpop_key_material.public_jwk_thumbprint,
        grant_id=token_result.grant_id,
        machine_id=token_result.machine_id,
        workspace_id=token_result.workspace_id,
        runtime_id=HEADLESS_RUNTIME_ID,
        runtime_label=HEADLESS_RUNTIME_LABEL,
        now=timestamp,
    )
    return {
        "status": "connected",
        "connect_mode": "browser_oauth",
        "browser_opened": browser_opened,
        "authorize_url": session.authorize_url,
        "redirect_uri": session.redirect_uri,
        "grant_id": token_result.grant_id,
        "machine_id": token_result.machine_id,
        "workspace_id": token_result.workspace_id,
        "connect_command": CONNECT_COMMAND,
        "connect_status_command": CONNECT_STATUS_COMMAND,
        "connect_repair_command": CONNECT_REPAIR_COMMAND,
    }


def build_connect_status_payload(
    *,
    store: GuardStore,
    sync_url: str,
    connect_url: str,
    action: str = "status",
) -> dict[str, object]:
    latest_state = store.get_latest_guard_connect_state(now=datetime.now(timezone.utc).isoformat())
    status = str(latest_state.get("status") or "not_paired") if latest_state is not None else "not_paired"
    milestone = str(latest_state.get("milestone") or "not_started") if latest_state is not None else "not_started"
    reason = latest_state.get("reason") if latest_state is not None else None
    stored_sync_url = latest_state.get("sync_url") if latest_state is not None else None
    payload: dict[str, object] = {
        "status": status,
        "milestone": milestone,
        "reason": reason,
        "latest_connect_state": latest_state,
        "sync_url": stored_sync_url if isinstance(stored_sync_url, str) and stored_sync_url.strip() else sync_url,
        "connect_url": connect_url,
        "connect_command": CONNECT_COMMAND,
        "recovery_command": connect_recovery_command(latest_state),
        "connect_status_command": CONNECT_STATUS_COMMAND,
        "connect_repair_command": CONNECT_REPAIR_COMMAND,
    }
    if action in {"repair", "re-pair"}:
        payload["repair_action"] = "rerun_connect"
        payload["repair_message"] = "Run hol-guard connect to start OAuth Device Code approval."
    return payload


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
