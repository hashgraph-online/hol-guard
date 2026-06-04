import base64
import io
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from codex_plugin_scanner.cli import _build_parser
from codex_plugin_scanner.guard.cli import commands as guard_commands
from codex_plugin_scanner.guard.cli import connect_flow
from codex_plugin_scanner.guard.cli.commands import run_guard_command
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


class _Args:
    guard_command = "login"
    token = None
    sync_url = "https://hol.org/api/guard/receipts/sync"
    connect_url = "https://hol.org/guard/connect"
    wait_timeout_seconds = 0
    json = True
    home = None
    guard_home = None
    workspace = None


class _ServiceLoginArgs:
    guard_command = "service"
    service_command = "login"
    runtime = "codex"
    label = "Hosted Codex"
    workspace = None
    sync_url = "https://hol.org/api/guard/receipts/sync"
    token = "guard_live_secret"
    json = True
    home = None
    guard_home = None


class _HeadlessConnectArgs:
    guard_command = "connect"
    connect_command = None
    headless = True
    sync_url = "https://hol.org/api/guard/receipts/sync"
    connect_url = "https://hol.org/guard/connect"
    wait_timeout_seconds = 180
    open_browser = False
    json = True
    home = None
    guard_home = None
    workspace = None


class _ConnectArgs:
    guard_command = "connect"
    connect_command = None
    headless = False
    sync_url = "https://hol.org/api/guard/receipts/sync"
    connect_url = "https://hol.org/guard/connect"
    wait_timeout_seconds = 180
    json = True
    home = None
    guard_home = None
    workspace = None


def _fake_access_token(*, grant_id: str, machine_id: str, workspace_id: str) -> str:
    def encode_part(payload: dict[str, object]) -> str:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")

    header = encode_part({"alg": "none", "typ": "JWT"})
    claims = encode_part(
        {
            "grant": {"grantId": grant_id},
            "machine": {"machineId": machine_id},
            "workspace": {"workspaceId": workspace_id},
        }
    )
    return f"{header}.{claims}.signature"


def test_request_device_authorization_sets_hol_guard_user_agent(monkeypatch) -> None:
    captured: dict[str, str] = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "device_code": "device-secret-value",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://hol.org/guard/oauth/device",
                    "expires_in": 600,
                    "interval": 5,
                }
            ).encode("utf-8")

    def fake_urlopen(request: urllib.request.Request, timeout: int):
        del timeout
        captured["user_agent"] = request.get_header("User-agent") or ""
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    connect_flow.request_device_authorization(
        "https://hol.org/api/guard/oauth/device/authorize",
        connect_flow.build_device_authorization_request_body(
            machine_id="machine-123",
            machine_label="Test Machine",
            runtime_id=connect_flow.HEADLESS_RUNTIME_ID,
            runtime_label=connect_flow.HEADLESS_RUNTIME_LABEL,
            client_id="guard-local-daemon",
        ),
    )

    assert captured["user_agent"].startswith("hol-guard/")


def test_device_authorization_request_uses_oauth_scopes_without_token_material() -> None:
    assert hasattr(connect_flow, "build_device_authorization_request_body")
    encoded = connect_flow.build_device_authorization_request_body(
        machine_id="machine-123",
        machine_label="Michaels MacBook",
        machine_location_label="America/New_York",
        runtime_id="hol-guard",
        runtime_label="HOL Guard CLI",
        client_id="guard-local-daemon",
    )
    parsed = urllib.parse.parse_qs(encoded)

    assert parsed["client_id"] == ["guard-local-daemon"]
    assert parsed["scope"] == [
        "guard:runtime.sync guard:receipt.write guard:runtime.session.write guard:offline_access"
    ]
    assert parsed["requested_machine_id"] == ["machine-123"]
    assert parsed["requested_machine_label"] == ["Michaels MacBook"]
    assert parsed["requested_machine_location_label"] == ["America/New_York"]
    assert parsed["requested_runtime_id"] == ["hol-guard"]
    assert parsed["requested_runtime_label"] == ["HOL Guard CLI"]
    assert "token" not in encoded
    assert "secret" not in encoded


def test_ci_safe_device_authorization_request_uses_restricted_scopes() -> None:
    encoded = connect_flow.build_device_authorization_request_body(
        machine_id="machine-123",
        machine_label="CI Runner",
        machine_location_label=None,
        runtime_id="hol-guard",
        runtime_label="HOL Guard CLI",
        client_id="guard-local-daemon",
        scopes=connect_flow.CI_SAFE_GUARD_DEVICE_SCOPES,
    )
    parsed = urllib.parse.parse_qs(encoded)

    assert parsed["scope"] == ["guard:runtime.sync guard:offline_access"]
    assert "guard:receipt.write" not in encoded
    assert "guard:runtime.session.write" not in encoded
    assert "requested_machine_location_label" not in parsed


def test_device_authorization_copy_payload_hides_device_code_secret() -> None:
    assert hasattr(connect_flow, "build_device_authorization_copy_payload")
    payload = connect_flow.build_device_authorization_copy_payload(
        {
            "device_code": "device-secret-value",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 5,
        }
    )
    rendered = json.dumps(payload, sort_keys=True)

    assert payload["status"] == "waiting_for_approval"
    assert payload["user_code"] == "ABCD-EFGH"
    assert payload["verification_uri"] == "https://hol.org/guard/oauth/device"
    assert payload["next_action"]["target"] == "https://hol.org/guard/oauth/device"
    assert "device-secret-value" not in rendered
    assert "device_code" not in rendered


def test_headless_connect_requests_device_code_without_persisting_secrets(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_device_label("CI Runner", "2026-05-31T00:00:00Z")
    requests: list[tuple[str, str]] = []
    opened: list[str] = []

    def fake_request(url: str, body: str) -> dict[str, object]:
        requests.append((url, body))
        return {
            "device_code": "device-secret-value",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 5,
        }

    class _Response:
        def __enter__(self):
            assert opened == ["https://hol.org/guard/oauth/device"]
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_token": _fake_access_token(
                        grant_id="grant-123",
                        machine_id="machine-123",
                        workspace_id="workspace-123",
                    ),
                    "refresh_token": "refresh-123",
                    "expires_in": 3600,
                    "scope": "guard:runtime.sync guard:offline_access",
                    "token_type": "Bearer",
                }
            ).encode("utf-8")

    payload = connect_flow.run_guard_device_connect_command(
        store=store,
        connect_url="https://hol.org/guard/connect",
        request_device_authorization=fake_request,
        token_urlopen=lambda request, timeout: _Response(),
        open_browser=lambda target: opened.append(target) or True,
        now="2026-06-01T12:00:00+00:00",
    )
    rendered = json.dumps(payload, sort_keys=True)
    credentials = store.get_oauth_local_credentials()

    assert requests
    assert requests[0][0] == "https://hol.org/api/guard/oauth/device/authorize"
    assert "requested_machine_label=CI+Runner" in requests[0][1]
    assert payload["status"] == "connected"
    assert payload["browser_opened"] is True
    assert payload["user_code"] == "ABCD-EFGH"
    assert "device-secret-value" not in rendered
    assert credentials is not None
    assert credentials["refresh_token"] == "refresh-123"
    assert credentials["runtime_label"] == "HOL Guard CLI"


def test_headless_connect_uses_staging_client_defaults(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_device_label("CI Runner", "2026-05-31T00:00:00Z")
    requests: list[tuple[str, str]] = []

    def fake_request(url: str, body: str) -> dict[str, object]:
        requests.append((url, body))
        return {
            "device_code": "device-secret-value",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://staging.hol.org/guard/oauth/device",
            "verification_uri_complete": "https://staging.hol.org/guard/oauth/device?user_code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 5,
        }

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_token": _fake_access_token(
                        grant_id="grant-123",
                        machine_id="machine-123",
                        workspace_id="workspace-123",
                    ),
                    "refresh_token": "refresh-rotated",
                    "expires_in": 3600,
                    "scope": "guard:runtime.sync guard:offline_access",
                    "token_type": "Bearer",
                }
            ).encode("utf-8")

    connect_flow.run_guard_device_connect_command(
        store=store,
        connect_url="https://staging.hol.org/guard/connect",
        request_device_authorization=fake_request,
        token_urlopen=lambda request, timeout: _Response(),
        now="2026-06-01T12:00:00+00:00",
    )
    parsed = urllib.parse.parse_qs(requests[0][1])

    assert requests[0][0] == "https://staging.hol.org/api/guard/oauth/device/authorize"
    assert parsed["client_id"] == ["guard-local-daemon-staging"]


def test_headless_connect_ci_safe_uses_explicit_label_and_restricted_scopes(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_device_label("Local Laptop", "2026-05-31T00:00:00Z")
    requests: list[tuple[str, str]] = []

    def fake_request(url: str, body: str) -> dict[str, object]:
        requests.append((url, body))
        return {
            "device_code": "device-secret-value",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 5,
        }

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_token": _fake_access_token(
                        grant_id="grant-123",
                        machine_id="machine-123",
                        workspace_id="workspace-123",
                    ),
                    "refresh_token": "refresh-rotated",
                    "expires_in": 3600,
                    "scope": "guard:runtime.sync guard:offline_access",
                    "token_type": "Bearer",
                }
            ).encode("utf-8")

    payload = connect_flow.run_guard_device_connect_command(
        store=store,
        connect_url="https://hol.org/guard/connect",
        request_device_authorization=fake_request,
        token_urlopen=lambda request, timeout: _Response(),
        now="2026-06-01T12:00:00+00:00",
        ci_safe=True,
        machine_label="CI Runner",
    )
    parsed = urllib.parse.parse_qs(requests[0][1])

    assert payload["status"] == "connected"
    assert parsed["requested_machine_label"] == ["CI Runner"]
    assert parsed["scope"] == ["guard:runtime.sync guard:offline_access"]


def test_disconnect_revokes_cloud_grant_with_runtime_access_token_and_clears_local_oauth_credentials(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-123",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        runtime_id="hol-guard",
        runtime_label="HOL Guard CLI",
        now="2026-06-01T12:00:00+00:00",
    )
    access_token = _fake_access_token(
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
    )
    requests: list[dict[str, object]] = []

    class _Response:
        def __init__(self, payload: dict[str, object] | None = None) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            if self._payload is None:
                return b""
            return json.dumps(self._payload).encode("utf-8")

    def fake_urlopen(request: urllib.request.Request, timeout: int):
        del timeout
        body = request.data.decode("utf-8") if request.data else ""
        requests.append(
            {
                "authorization": request.get_header("Authorization"),
                "body": body,
                "headers": dict(request.header_items()),
                "url": request.full_url,
            }
        )
        if request.full_url == "https://hol.org/api/guard/oauth/token":
            return _Response(
                {
                    "access_token": access_token,
                    "refresh_token": "refresh-123",
                    "expires_in": 3600,
                    "scope": "guard:runtime.sync guard:offline_access",
                    "token_type": "Bearer",
                }
            )
        if request.full_url == "https://hol.org/api/guard/oauth/revoke/self":
            return _Response()
        raise AssertionError(f"Unexpected request URL: {request.full_url}")

    payload = connect_flow.run_guard_disconnect_command(
        store=store,
        revoke_cloud_grant=True,
        urlopen=fake_urlopen,
        now="2026-06-01T12:05:00+00:00",
    )

    assert payload["status"] == "disconnected"
    assert payload["cloud_grant_revoked"] is True
    assert payload["reconnect_command"] == "hol-guard connect"
    assert store.get_oauth_local_credentials() is None
    assert [request["url"] for request in requests] == [
        "https://hol.org/api/guard/oauth/token",
        "https://hol.org/api/guard/oauth/revoke/self",
    ]

    token_body = urllib.parse.parse_qs(str(requests[0]["body"]))
    revoke_body = urllib.parse.parse_qs(str(requests[1]["body"]))
    assert token_body["grant_type"] == ["refresh_token"]
    assert token_body["client_id"] == ["guard-local-daemon"]
    assert token_body["refresh_token"] == ["refresh-123"]
    assert revoke_body == {
        "reason": ["user_disconnect"],
        "revoke_machine_grant": ["true"],
        "revoke_runtime_grant": ["true"],
        "workspace_id": ["workspace-123"],
    }
    assert requests[1]["authorization"] == f"Bearer {access_token}"
    assert isinstance(requests[1]["headers"], dict)
    assert requests[1]["headers"].get("Dpop")
    assert "refresh-123" not in str(requests[1]["body"])


def test_disconnect_keeps_local_oauth_credentials_when_self_revoke_fails(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-123",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-123",
        machine_id="machine-123",
        workspace_id="workspace-123",
        runtime_id="hol-guard",
        runtime_label="HOL Guard CLI",
        now="2026-06-01T12:00:00+00:00",
    )

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_token": _fake_access_token(
                        grant_id="grant-123",
                        machine_id="machine-123",
                        workspace_id="workspace-123",
                    ),
                    "refresh_token": "refresh-rotated",
                    "expires_in": 3600,
                    "scope": "guard:runtime.sync guard:offline_access",
                    "token_type": "Bearer",
                }
            ).encode("utf-8")

    def fake_urlopen(request: urllib.request.Request, timeout: int):
        del timeout
        if request.full_url == "https://hol.org/api/guard/oauth/token":
            return _Response()
        raise urllib.error.HTTPError(
            request.full_url,
            500,
            "server_error",
            hdrs={"Content-Type": "application/json"},
            fp=io.BytesIO(
                json.dumps(
                    {
                        "error": "server_error",
                        "error_description": "temporary failure",
                    }
                ).encode("utf-8")
            ),
        )

    try:
        connect_flow.run_guard_disconnect_command(
            store=store,
            revoke_cloud_grant=True,
            urlopen=fake_urlopen,
            now="2026-06-01T12:05:00+00:00",
        )
    except RuntimeError as error:
        assert str(error) == "Guard OAuth disconnect failed: temporary failure"
    else:
        raise AssertionError("disconnect should fail when self-revocation fails")

    credentials = store.get_oauth_local_credentials()
    assert credentials is not None
    assert credentials["refresh_token"] == "refresh-rotated"


def test_headless_connect_polls_until_success_and_persists_oauth_credentials(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_device_label("CI Runner", "2026-05-31T00:00:00Z")
    sleeps: list[float] = []
    token_bodies: list[str] = []

    def fake_request(url: str, body: str) -> dict[str, object]:
        assert url == "https://hol.org/api/guard/oauth/device/authorize"
        assert "requested_machine_label=CI+Runner" in body
        return {
            "device_code": "device-secret-value",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 3,
        }

    class _Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(self._payload).encode("utf-8")

    attempt = {"count": 0}

    def fake_urlopen(request: urllib.request.Request, timeout: int):
        token_bodies.append(request.data.decode("utf-8") if request.data else "")
        attempt["count"] += 1
        if attempt["count"] == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                400,
                "authorization_pending",
                hdrs={"Content-Type": "application/json"},
                fp=io.BytesIO(json.dumps({"error": "authorization_pending"}).encode("utf-8")),
            )
        return _Response(
            {
                "access_token": _fake_access_token(
                    grant_id="grant-123",
                    machine_id="machine-123",
                    workspace_id="workspace-123",
                ),
                "refresh_token": "refresh-123",
                "expires_in": 3600,
                "scope": "guard:runtime.sync guard:offline_access",
                "token_type": "Bearer",
            }
        )

    payload = connect_flow.run_guard_device_connect_command(
        store=store,
        connect_url="https://hol.org/guard/connect",
        request_device_authorization=fake_request,
        token_urlopen=fake_urlopen,
        sleep=sleeps.append,
        now="2026-06-01T12:00:00+00:00",
    )
    credentials = store.get_oauth_local_credentials()
    rendered = json.dumps(payload, sort_keys=True)

    assert payload["status"] == "connected"
    assert payload["connect_mode"] == "device_code"
    assert payload["grant_id"] == "grant-123"
    assert payload["machine_id"] == "machine-123"
    assert payload["workspace_id"] == "workspace-123"
    assert payload["user_code"] == "ABCD-EFGH"
    assert payload["verification_uri"] == "https://hol.org/guard/oauth/device"
    assert "device-secret-value" not in rendered
    assert "refresh-123" not in rendered
    assert "access_token" not in rendered
    assert sleeps == [3]
    assert len(token_bodies) == 2
    assert urllib.parse.parse_qs(token_bodies[0])["grant_type"] == ["urn:ietf:params:oauth:grant-type:device_code"]
    assert credentials is not None
    assert credentials["grant_id"] == "grant-123"
    assert credentials["machine_id"] == "machine-123"
    assert credentials["workspace_id"] == "workspace-123"
    assert credentials["refresh_token"] == "refresh-123"
    assert credentials["runtime_label"] == "HOL Guard CLI"


def test_headless_connect_respects_client_wait_timeout(tmp_path: Path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    sleeps: list[float] = []
    clock = {"value": 0.0}

    def fake_request(_url: str, _body: str) -> dict[str, object]:
        return {
            "device_code": "device-secret-value",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 5,
        }

    def fake_urlopen(request: urllib.request.Request, timeout: int):
        del timeout
        raise urllib.error.HTTPError(
            request.full_url,
            400,
            "authorization_pending",
            hdrs={"Content-Type": "application/json"},
            fp=io.BytesIO(json.dumps({"error": "authorization_pending"}).encode("utf-8")),
        )

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock["value"] += seconds

    monkeypatch.setattr(connect_flow.time, "monotonic", lambda: clock["value"])

    try:
        connect_flow.run_guard_device_connect_command(
            store=store,
            connect_url="https://hol.org/guard/connect",
            request_device_authorization=fake_request,
            token_urlopen=fake_urlopen,
            sleep=fake_sleep,
            now="2026-06-01T12:00:00+00:00",
            wait_timeout_seconds=2,
        )
    except RuntimeError as error:
        message = str(error)
    else:
        raise AssertionError("client wait timeout must stop device-code polling")

    assert "timed out" in message
    assert sleeps == [5]


def test_headless_connect_slows_down_polling_when_server_requests_it(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    sleeps: list[float] = []

    def fake_request(_url: str, _body: str) -> dict[str, object]:
        return {
            "device_code": "device-secret-value",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "expires_in": 600,
            "interval": 2,
        }

    class _Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(self._payload).encode("utf-8")

    attempt = {"count": 0}

    def fake_urlopen(request: urllib.request.Request, timeout: int):
        del timeout
        attempt["count"] += 1
        if attempt["count"] == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                400,
                "slow_down",
                hdrs={"Content-Type": "application/json"},
                fp=io.BytesIO(json.dumps({"error": "slow_down"}).encode("utf-8")),
            )
        return _Response(
            {
                "access_token": _fake_access_token(
                    grant_id="grant-123",
                    machine_id="machine-123",
                    workspace_id="workspace-123",
                ),
                "refresh_token": "refresh-123",
                "expires_in": 3600,
                "scope": "guard:runtime.sync guard:offline_access",
                "token_type": "Bearer",
            }
        )

    payload = connect_flow.run_guard_device_connect_command(
        store=store,
        connect_url="https://hol.org/guard/connect",
        request_device_authorization=fake_request,
        token_urlopen=fake_urlopen,
        sleep=sleeps.append,
        now="2026-06-01T12:00:00+00:00",
    )

    assert payload["status"] == "connected"
    assert sleeps == [7]


def test_headless_connect_expired_code_surfaces_retry_command(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)

    def fake_request(_url: str, _body: str) -> dict[str, object]:
        return {
            "device_code": "device-secret-value",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "expires_in": 600,
            "interval": 2,
        }

    def fake_urlopen(request: urllib.request.Request, timeout: int):
        del timeout
        raise urllib.error.HTTPError(
            request.full_url,
            400,
            "expired_token",
            hdrs={"Content-Type": "application/json"},
            fp=io.BytesIO(json.dumps({"error": "expired_token"}).encode("utf-8")),
        )

    try:
        connect_flow.run_guard_device_connect_command(
            store=store,
            connect_url="https://hol.org/guard/connect",
            request_device_authorization=fake_request,
            token_urlopen=fake_urlopen,
            now="2026-06-01T12:00:00+00:00",
        )
    except RuntimeError as error:
        message = str(error)
    else:
        raise AssertionError("expired device code must raise a retry-safe runtime error")

    assert "hol-guard connect --headless" in message
    assert "device-secret-value" not in message
    assert store.get_oauth_local_credentials() is None


def test_login_token_alias_rejects_raw_token_without_persisting_credentials(tmp_path: Path, capsys) -> None:
    guard_home = tmp_path / "guard-home"
    args = _Args()
    args.guard_home = str(guard_home)
    args.token = "guard_live_secret"

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()
    store = GuardStore(guard_home)

    assert exit_code == 2
    assert "hol-guard connect" in captured.err
    assert "guard_live_secret" not in captured.err
    assert store.get_sync_credentials() is None


def test_service_login_rejects_raw_token_without_persisting_credentials(tmp_path: Path, capsys) -> None:
    guard_home = tmp_path / "guard-home"
    args = _ServiceLoginArgs()
    args.guard_home = str(guard_home)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()
    store = GuardStore(guard_home)

    assert exit_code == 2
    assert "hol-guard connect --headless" in captured.out
    assert "guard_live_secret" not in captured.out
    assert store.get_sync_credentials() is None


def test_service_login_without_token_points_to_ci_safe_connect(tmp_path: Path, capsys) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    args = _ServiceLoginArgs()
    args.guard_home = str(guard_home)
    args.token = None
    args.workspace = str(workspace)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 2
    assert "hol-guard connect --headless --ci-safe" in payload["next_action"]["command"]
    assert "--workspace" in payload["next_action"]["command"]
    assert str(workspace) in payload["next_action"]["command"]
    assert "--label" in payload["next_action"]["command"]
    assert "Hosted Codex" in payload["next_action"]["command"]


def test_connect_headless_emits_device_code_payload_without_pairing_secret(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    args = _HeadlessConnectArgs()
    args.guard_home = str(guard_home)

    def fake_headless_flow(
        *,
        store: GuardStore,
        connect_url: str,
        wait_timeout_seconds: int = 180,
        announce_copy=None,
        ci_safe: bool = False,
        machine_label: str | None = None,
    ) -> dict[str, object]:
        del ci_safe, machine_label
        if announce_copy is not None:
            announce_copy(
                {
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://hol.org/guard/oauth/device",
                    "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH",
                }
            )
        return {
            "status": "connected",
            "connect_mode": "device_code",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "next_action": {
                "command": "open",
                "target": "https://hol.org/guard/oauth/device",
            },
        }

    monkeypatch.setattr(guard_commands, "_run_guard_device_connect_flow", fake_headless_flow)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "ABCD-EFGH" in captured.out
    assert "guardPairSecret" not in captured.out
    assert "guardPairRequest" not in captured.out
    assert "guard_live_" not in captured.out


def test_connect_no_browser_alias_uses_headless_device_code_flow(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"

    parser = _build_parser("hol-guard", program_mode="guard")
    args = parser.parse_args(["connect", "--no-browser", "--home", str(guard_home), "--json"])

    assert args.guard_command == "connect"
    assert args.headless is True


def test_connect_ci_safe_requires_explicit_workspace(tmp_path: Path, capsys) -> None:
    guard_home = tmp_path / "guard-home"
    parser = _build_parser("hol-guard", program_mode="guard")
    args = parser.parse_args(
        [
            "connect",
            "--headless",
            "--ci-safe",
            "--label",
            "CI Runner",
            "--home",
            str(guard_home),
            "--json",
        ]
    )

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "--workspace" in captured.err


def test_connect_ci_safe_requires_headless_mode(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    parser = _build_parser("hol-guard", program_mode="guard")
    args = parser.parse_args(
        [
            "connect",
            "--ci-safe",
            "--workspace",
            str(workspace),
            "--label",
            "CI Runner",
            "--home",
            str(guard_home),
            "--json",
        ]
    )
    browser_called = {"value": False}

    def fake_browser_flow(*, store: GuardStore, connect_url: str, wait_timeout_seconds: int) -> dict[str, object]:
        del store, connect_url, wait_timeout_seconds
        browser_called["value"] = True
        return {"status": "connected", "connect_mode": "browser_oauth"}

    monkeypatch.setattr(guard_commands, "_run_guard_browser_connect_flow", fake_browser_flow)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "--headless" in captured.err
    assert browser_called["value"] is False


def test_connect_ci_safe_requires_explicit_label(tmp_path: Path, capsys) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    parser = _build_parser("hol-guard", program_mode="guard")
    args = parser.parse_args(
        [
            "connect",
            "--headless",
            "--ci-safe",
            "--workspace",
            str(workspace),
            "--home",
            str(guard_home),
            "--json",
        ]
    )

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "--label" in captured.err


def test_connect_headless_open_browser_opens_device_approval_before_polling(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    args = _HeadlessConnectArgs()
    args.guard_home = str(guard_home)
    args.open_browser = True
    opened: list[str] = []

    def fake_headless_flow(
        *,
        store: GuardStore,
        connect_url: str,
        wait_timeout_seconds: int = 180,
        announce_copy=None,
        open_browser=None,
        ci_safe: bool = False,
        machine_label: str | None = None,
    ) -> dict[str, object]:
        del ci_safe, machine_label
        assert connect_url == "https://hol.org/guard/connect"
        assert open_browser is not None
        if announce_copy is not None:
            announce_copy(
                {
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://hol.org/guard/oauth/device",
                    "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH",
                }
            )
        opened.append("before-poll")
        browser_opened = bool(open_browser("https://hol.org/guard/oauth/device"))
        opened.append("after-open")
        return {
            "status": "connected",
            "connect_mode": "device_code",
            "browser_opened": browser_opened,
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "next_action": {
                "command": "open",
                "target": "https://hol.org/guard/oauth/device",
            },
        }

    monkeypatch.setattr(guard_commands, "_run_guard_device_connect_flow", fake_headless_flow)
    monkeypatch.setattr(guard_commands.webbrowser, "open", lambda target: opened.append(target) or True)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert opened == [
        "before-poll",
        "https://hol.org/guard/oauth/device",
        "after-open",
    ]
    assert "device_code" in captured.out
    assert "browser_opened" in captured.out


def test_connect_default_uses_device_code_flow_with_browser_open(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    args = _ConnectArgs()
    args.guard_home = str(guard_home)
    args.wait_timeout_seconds = 5
    opened: list[str] = []

    def fail_browser_flow(*, store: GuardStore, connect_url: str, wait_timeout_seconds: int) -> dict[str, object]:
        raise AssertionError("default connect should not use browser oauth")

    def fake_device_flow(
        *,
        store: GuardStore,
        connect_url: str,
        wait_timeout_seconds: int = 180,
        announce_copy=None,
        open_browser=None,
        ci_safe: bool = False,
        machine_label: str | None = None,
    ) -> dict[str, object]:
        del store, ci_safe, machine_label
        assert connect_url == "https://hol.org/guard/connect"
        assert wait_timeout_seconds == 5
        assert open_browser is not None
        if announce_copy is not None:
            announce_copy(
                {
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://hol.org/guard/oauth/device",
                    "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH",
                }
            )
        browser_opened = bool(open_browser("https://hol.org/guard/oauth/device"))
        return {
            "status": "connected",
            "connect_mode": "device_code",
            "browser_opened": browser_opened,
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "next_action": {
                "command": "open",
                "target": "https://hol.org/guard/oauth/device",
            },
        }

    monkeypatch.setattr(guard_commands, "_run_guard_browser_connect_flow", fail_browser_flow)
    monkeypatch.setattr(guard_commands, "_run_guard_device_connect_flow", fake_device_flow)
    monkeypatch.setattr(guard_commands.webbrowser, "open", lambda target: opened.append(target) or True)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert opened == ["https://hol.org/guard/oauth/device"]
    assert "device_code" in captured.out
    assert "browser_opened" in captured.out
    assert "ABCD-EFGH" in captured.out
    assert "verification_uri" in captured.out
    assert "guardPairSecret" not in captured.out
    assert "guardPairRequest" not in captured.out
    assert not hasattr(guard_commands, "_run_guard_connect_flow")


def test_connect_default_device_flow_respects_wait_timeout_seconds(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    args = _ConnectArgs()
    args.guard_home = str(guard_home)
    args.wait_timeout_seconds = 7

    def fake_device_flow(
        *,
        store: GuardStore,
        connect_url: str,
        wait_timeout_seconds: int = 180,
        announce_copy=None,
        open_browser=None,
        ci_safe: bool = False,
        machine_label: str | None = None,
    ) -> dict[str, object]:
        del store, announce_copy, open_browser, ci_safe, machine_label
        assert connect_url == "https://hol.org/guard/connect"
        assert wait_timeout_seconds == 7
        return {
            "status": "connected",
            "connect_mode": "device_code",
            "browser_opened": False,
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
        }

    monkeypatch.setattr(guard_commands, "_run_guard_device_connect_flow", fake_device_flow)
    monkeypatch.setattr(guard_commands.webbrowser, "open", lambda _target: True)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "device_code" in captured.out


def test_connect_default_non_json_announces_device_copy_on_stderr(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    args = _ConnectArgs()
    args.guard_home = str(guard_home)
    args.json = False

    def fake_device_flow(
        *,
        store: GuardStore,
        connect_url: str,
        wait_timeout_seconds: int = 180,
        announce_copy=None,
        open_browser=None,
        ci_safe: bool = False,
        machine_label: str | None = None,
    ) -> dict[str, object]:
        del store, connect_url, open_browser, ci_safe, machine_label
        assert announce_copy is not None
        announce_copy(
            {
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://hol.org/guard/oauth/device",
                "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH",
            }
        )
        return {
            "status": "connected",
            "connect_mode": "device_code",
            "browser_opened": False,
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
        }

    monkeypatch.setattr(guard_commands, "_run_guard_device_connect_flow", fake_device_flow)
    monkeypatch.setattr(guard_commands.webbrowser, "open", lambda _target: True)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "HOL Guard headless approval" in captured.err
    assert "HOL Guard headless approval" not in captured.out


def test_loopback_callback_listener_uses_random_high_port_and_loopback_path() -> None:
    assert hasattr(connect_flow, "start_guard_loopback_callback_listener")

    listener = connect_flow.start_guard_loopback_callback_listener(expected_state="state-123")
    try:
        parsed = urllib.parse.urlparse(listener.redirect_uri)
        assert parsed.hostname in {"127.0.0.1", "::1"}
        assert parsed.path == "/oauth/callback"
        assert parsed.port is not None
        assert 49152 <= parsed.port <= 65535
    finally:
        listener.close()


def test_loopback_callback_listener_rejects_state_mismatch() -> None:
    listener = connect_flow.start_guard_loopback_callback_listener(expected_state="state-123")
    try:
        wrong_state_url = f"{listener.redirect_uri}?code=code-123&state=wrong-state"
        try:
            urllib.request.urlopen(wrong_state_url, timeout=5)
        except urllib.error.HTTPError as error:
            assert error.code == 400
        else:
            raise AssertionError("state mismatch must be rejected")

        try:
            listener.wait_for_callback(timeout_seconds=0.05)
        except TimeoutError as error:
            assert "timed out" in str(error)
        else:
            raise AssertionError("mismatched callback must not be accepted")
    finally:
        listener.close()


def test_loopback_callback_listener_rejects_raw_runtime_credentials_without_code() -> None:
    listener = connect_flow.start_guard_loopback_callback_listener(expected_state="state-123")
    try:
        legacy_query_url = (
            f"{listener.redirect_uri}?state=state-123"
            "&token=guard_live_secret"
            "&pairing_secret=pair-secret"
            "&sync_token=sync-secret"
        )
        response_body = ""
        try:
            urllib.request.urlopen(legacy_query_url, timeout=5)
        except urllib.error.HTTPError as error:
            assert error.code == 400
            response_body = error.read().decode("utf-8")
        else:
            raise AssertionError("raw runtime credentials must not satisfy OAuth callback")

        assert "authorization code" in response_body
        assert "guard_live_secret" not in response_body
        assert "pair-secret" not in response_body
        assert "sync-secret" not in response_body

        try:
            listener.wait_for_callback(timeout_seconds=0.05)
        except TimeoutError as error:
            assert "timed out" in str(error)
        else:
            raise AssertionError("legacy runtime credentials must not be accepted as callback state")
    finally:
        listener.close()


def test_loopback_callback_listener_surfaces_oauth_denial_without_timeout() -> None:
    listener = connect_flow.start_guard_loopback_callback_listener(expected_state="state-123")
    try:
        denied_url = f"{listener.redirect_uri}?state=state-123&error=access_denied&error_description=User+denied+access"
        with urllib.request.urlopen(denied_url, timeout=5) as response:
            assert response.status == 200

        try:
            listener.wait_for_callback(timeout_seconds=0.05)
        except RuntimeError as error:
            assert "User denied access" in str(error)
        else:
            raise AssertionError("denied callback must surface a runtime error")
    finally:
        listener.close()


def test_exchange_authorization_code_posts_pkce_and_dpop_binding() -> None:
    assert hasattr(connect_flow, "exchange_guard_authorization_code")

    dpop = generate_dpop_key_pair()
    captured: dict[str, object] = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            token = _fake_access_token(
                grant_id="grant-123",
                machine_id="machine-123",
                workspace_id="workspace-123",
            )
            return json.dumps(
                {
                    "access_token": token,
                    "refresh_token": "refresh-123",
                    "expires_in": 3600,
                    "scope": "guard:runtime.sync guard:offline_access",
                    "token_type": "Bearer",
                }
            ).encode("utf-8")

    def fake_urlopen(request: urllib.request.Request, timeout: int):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["headers"] = dict(request.header_items())
        captured["body"] = request.data.decode("utf-8") if request.data else ""
        return _Response()

    result = connect_flow.exchange_guard_authorization_code(
        token_endpoint="https://hol.org/api/guard/oauth/token",
        client_id="guard-local-daemon",
        code="auth-code-123",
        redirect_uri="http://127.0.0.1:61234/oauth/callback",
        code_verifier="verifier-123",
        dpop_key_material=dpop,
        urlopen=fake_urlopen,
        now=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )

    parsed = urllib.parse.parse_qs(str(captured["body"]))
    headers = {str(key).lower(): str(value) for key, value in dict(captured["headers"]).items()}

    assert captured["url"] == "https://hol.org/api/guard/oauth/token"
    assert captured["timeout"] == 20
    assert parsed["grant_type"] == ["authorization_code"]
    assert parsed["client_id"] == ["guard-local-daemon"]
    assert parsed["code"] == ["auth-code-123"]
    assert parsed["redirect_uri"] == ["http://127.0.0.1:61234/oauth/callback"]
    assert parsed["code_verifier"] == ["verifier-123"]
    assert "dpop" in headers
    assert result.refresh_token == "refresh-123"
    assert result.grant_id == "grant-123"
    assert result.machine_id == "machine-123"
    assert result.workspace_id == "workspace-123"


def test_browser_connect_persists_local_oauth_credentials(tmp_path: Path) -> None:
    assert hasattr(connect_flow, "run_guard_browser_connect_command")
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_device_label("Desk Mac", "2026-06-01T00:00:00+00:00")
    opened: list[str] = []
    dpop = generate_dpop_key_pair()

    class _FakeSession:
        authorize_url = "https://hol.org/api/guard/oauth/authorize?client_id=guard-local-daemon"
        redirect_uri = "http://127.0.0.1:61234/oauth/callback"
        pkce_verifier = "verifier-123"
        state = "state-123"
        dpop_key_material = dpop
        closed = False

        def wait_for_callback(self, timeout_seconds: float):
            assert timeout_seconds == 30
            return connect_flow.GuardOAuthLoopbackCallback(code="auth-code-123", state="state-123")

        def close(self) -> None:
            self.closed = True

    session = _FakeSession()

    def fake_open(url: str) -> bool:
        opened.append(url)
        return True

    def fake_exchange(**kwargs):
        assert kwargs["token_endpoint"] == "https://hol.org/api/guard/oauth/token"
        assert kwargs["client_id"] == "guard-local-daemon"
        assert kwargs["code"] == "auth-code-123"
        assert kwargs["redirect_uri"] == "http://127.0.0.1:61234/oauth/callback"
        assert kwargs["code_verifier"] == "verifier-123"
        return connect_flow.GuardOAuthTokenExchangeResult(
            access_token=_fake_access_token(
                grant_id="grant-123",
                machine_id="machine-123",
                workspace_id="workspace-123",
            ),
            refresh_token="refresh-123",
            expires_in=3600,
            scope="guard:runtime.sync guard:offline_access",
            token_type="Bearer",
            grant_id="grant-123",
            machine_id="machine-123",
            workspace_id="workspace-123",
        )

    payload = connect_flow.run_guard_browser_connect_command(
        store=store,
        connect_url="https://hol.org/guard/connect",
        start_browser_session=lambda **_: session,
        open_browser=fake_open,
        exchange_authorization_code=fake_exchange,
        now="2026-06-01T12:00:00+00:00",
        wait_timeout_seconds=30,
    )

    credentials = store.get_oauth_local_credentials()

    assert opened == ["https://hol.org/api/guard/oauth/authorize?client_id=guard-local-daemon"]
    assert session.closed is True
    assert payload["status"] == "connected"
    assert payload["connect_mode"] == "browser_oauth"
    assert payload["grant_id"] == "grant-123"
    assert payload["machine_id"] == "machine-123"
    assert credentials is not None
    assert credentials["grant_id"] == "grant-123"
    assert credentials["machine_id"] == "machine-123"
    assert credentials["workspace_id"] == "workspace-123"
    assert credentials["refresh_token"] == "refresh-123"


def test_legacy_pairing_helpers_are_not_exported() -> None:
    assert not hasattr(connect_flow, "run_guard_connect_command")
    assert not hasattr(connect_flow, "build_guard_connect_browser_url")


def test_daemon_rejects_legacy_pairing_request_endpoint(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        initialize_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/initialize",
            data=json.dumps(
                {
                    "client_name": "hol-guard-cli",
                    "surface": "cli",
                    "supported_protocol_versions": ["1.1"],
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(initialize_request, timeout=5) as response:
            initialize_payload = json.loads(response.read().decode("utf-8"))

        results: dict[str, tuple[int, dict[str, object]]] = {}
        for path, method in (
            ("/v1/connect/requests", "POST"),
            ("/v1/connect/complete", "POST"),
            ("/v1/connect/result", "POST"),
            ("/v1/connect/state?request_id=connect-legacy", "GET"),
        ):
            legacy_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}{path}",
                data=json.dumps(
                    {
                        "sync_url": "https://hol.org/api/guard/receipts/sync",
                        "allowed_origin": "https://hol.org",
                    }
                ).encode("utf-8")
                if method == "POST"
                else None,
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": initialize_payload["auth_token"],
                },
                method=method,
            )
            try:
                urllib.request.urlopen(legacy_request, timeout=5)
            except urllib.error.HTTPError as error:
                results[path] = (error.code, json.loads(error.read().decode("utf-8")))
            else:
                raise AssertionError(f"legacy pairing endpoint must be disabled: {path}")
    finally:
        daemon.stop()

    assert set(results) == {
        "/v1/connect/requests",
        "/v1/connect/complete",
        "/v1/connect/result",
        "/v1/connect/state?request_id=connect-legacy",
    }
    for status, payload in results.values():
        assert status == 410
        assert payload["error"] == "legacy_pairing_disabled"


def test_connect_headless_reports_device_authorization_network_error(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    args = _HeadlessConnectArgs()
    args.guard_home = str(guard_home)

    def failing_headless_flow(
        *,
        store: GuardStore,
        connect_url: str,
        wait_timeout_seconds: int = 180,
        announce_copy=None,
        ci_safe: bool = False,
        machine_label: str | None = None,
    ) -> dict[str, object]:
        del ci_safe, machine_label
        del announce_copy
        raise urllib.error.URLError("network unavailable")

    monkeypatch.setattr(guard_commands, "_run_guard_device_connect_flow", failing_headless_flow)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Guard authorization failed" in captured.err
    assert "Traceback" not in captured.err


def test_connect_headless_reports_malformed_device_authorization_response(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    args = _HeadlessConnectArgs()
    args.guard_home = str(guard_home)

    def failing_headless_flow(
        *,
        store: GuardStore,
        connect_url: str,
        wait_timeout_seconds: int = 180,
        announce_copy=None,
        ci_safe: bool = False,
        machine_label: str | None = None,
    ) -> dict[str, object]:
        del ci_safe, machine_label
        del announce_copy
        raise json.JSONDecodeError("invalid json", "not-json", 0)

    monkeypatch.setattr(guard_commands, "_run_guard_device_connect_flow", failing_headless_flow)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Guard authorization failed" in captured.err
    assert "Traceback" not in captured.err


def test_connect_browser_reports_loopback_timeout_without_traceback(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)

    def failing_browser_flow(
        *,
        store: GuardStore,
        connect_url: str,
        wait_timeout_seconds: float,
    ) -> dict[str, object]:
        raise TimeoutError("Guard OAuth browser callback timed out.")

    monkeypatch.setattr(guard_commands, "_run_guard_browser_connect_flow", failing_browser_flow)

    payload, exit_code = guard_commands._build_guard_device_connect_payload(
        store=store,
        connect_url="https://hol.org/guard/connect",
        use_browser_oauth=True,
        wait_timeout_seconds=30,
    )
    captured = capsys.readouterr()

    assert payload is None
    assert exit_code == 1
    assert "Guard authorization failed" in captured.err
    assert "timed out" in captured.err
    assert "Traceback" not in captured.err
    assert store.get_sync_credentials() is None
    assert store.get_oauth_local_credentials() is None
