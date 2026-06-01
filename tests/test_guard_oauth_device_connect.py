import json
import urllib.error
import urllib.parse
from pathlib import Path

from codex_plugin_scanner.guard.cli import commands as guard_commands
from codex_plugin_scanner.guard.cli import connect_flow
from codex_plugin_scanner.guard.cli.commands import run_guard_command
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


def test_connect_default_uses_device_code_without_pairing_secret(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    args = _ConnectArgs()
    args.guard_home = str(guard_home)
    opened_urls: list[str] = []

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

    def fake_open(url: str) -> bool:
        opened_urls.append(url)
        return True

    monkeypatch.setattr(guard_commands, "_run_guard_device_connect_flow", fake_headless_flow)
    monkeypatch.setattr(guard_commands.webbrowser, "open", fake_open)

    exit_code = run_guard_command(args)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert opened_urls == ["https://hol.org/guard/oauth/device?user_code=ABCD-EFGH"]
    assert "ABCD-EFGH" in captured.out
    assert "guardPairSecret" not in captured.out
    assert "guardPairRequest" not in captured.out
    assert not hasattr(guard_commands, "_run_guard_connect_flow")


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
