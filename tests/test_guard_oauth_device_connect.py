import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

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


def test_device_authorization_request_uses_oauth_scopes_without_token_material() -> None:
    assert hasattr(connect_flow, "build_device_authorization_request_body")
    encoded = connect_flow.build_device_authorization_request_body(
        machine_id="machine-123",
        machine_label="Michaels MacBook",
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
    assert parsed["requested_runtime_id"] == ["hol-guard"]
    assert parsed["requested_runtime_label"] == ["HOL Guard CLI"]
    assert "token" not in encoded
    assert "secret" not in encoded


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
    assert payload["next_action"]["target"] == "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH"
    assert "device-secret-value" not in rendered
    assert "device_code" not in rendered


def test_headless_connect_requests_device_code_without_persisting_secrets(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_device_label("CI Runner", "2026-05-31T00:00:00Z")
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

    payload = connect_flow.run_guard_device_connect_command(
        store=store,
        connect_url="https://hol.org/guard/connect",
        request_device_authorization=fake_request,
    )
    rendered = json.dumps(payload, sort_keys=True)

    assert requests
    assert requests[0][0] == "https://hol.org/api/guard/oauth/device/authorize"
    assert "requested_machine_label=CI+Runner" in requests[0][1]
    assert payload["user_code"] == "ABCD-EFGH"
    assert "device-secret-value" not in rendered
    assert store.get_sync_credentials() is None


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

    connect_flow.run_guard_device_connect_command(
        store=store,
        connect_url="https://staging.hol.org/guard/connect",
        request_device_authorization=fake_request,
    )
    parsed = urllib.parse.parse_qs(requests[0][1])

    assert requests[0][0] == "https://staging.hol.org/api/guard/oauth/device/authorize"
    assert parsed["client_id"] == ["guard-local-daemon-staging"]


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


def test_connect_headless_emits_device_code_payload_without_pairing_secret(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    args = _HeadlessConnectArgs()
    args.guard_home = str(guard_home)

    def fake_headless_flow(*, store: GuardStore, connect_url: str) -> dict[str, object]:
        return {
            "status": "waiting_for_approval",
            "connect_mode": "device_code",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/oauth/device",
            "next_action": {
                "command": "open",
                "target": "https://hol.org/guard/oauth/device?user_code=ABCD-EFGH",
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


def test_connect_default_uses_browser_oauth_without_pairing_secret(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    args = _ConnectArgs()
    args.guard_home = str(guard_home)
    args.wait_timeout_seconds = 5

    def fake_browser_flow(*, store: GuardStore, connect_url: str, wait_timeout_seconds: int) -> dict[str, object]:
        assert wait_timeout_seconds == 5
        return {
            "status": "connected",
            "connect_mode": "browser_oauth",
            "authorize_url": "https://hol.org/api/guard/oauth/authorize?client_id=guard-local-daemon",
            "redirect_uri": "http://127.0.0.1:61234/oauth/callback",
        }

    monkeypatch.setattr(guard_commands, "_run_guard_browser_connect_flow", fake_browser_flow)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "browser_oauth" in captured.out
    assert '"authorize_url": "*****"' in captured.out
    assert "ABCD-EFGH" not in captured.out
    assert "verification_uri" not in captured.out
    assert "guardPairSecret" not in captured.out
    assert "guardPairRequest" not in captured.out
    assert not hasattr(guard_commands, "_run_guard_connect_flow")


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

    def failing_headless_flow(*, store: GuardStore, connect_url: str) -> dict[str, object]:
        raise urllib.error.URLError("network unavailable")

    monkeypatch.setattr(guard_commands, "_run_guard_device_connect_flow", failing_headless_flow)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Guard Device Code authorization failed" in captured.err
    assert "Traceback" not in captured.err


def test_connect_headless_reports_malformed_device_authorization_response(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    args = _HeadlessConnectArgs()
    args.guard_home = str(guard_home)

    def failing_headless_flow(*, store: GuardStore, connect_url: str) -> dict[str, object]:
        raise json.JSONDecodeError("invalid json", "not-json", 0)

    monkeypatch.setattr(guard_commands, "_run_guard_device_connect_flow", failing_headless_flow)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Guard Device Code authorization failed" in captured.err
    assert "Traceback" not in captured.err
