from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import (
    commands_dispatch_trust,
    commands_support_service,
    extension_controls_commands,
)
from codex_plugin_scanner.guard.cli import product as product_module
from codex_plugin_scanner.guard.cli.product import build_guard_status_payload
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon import manager
from codex_plugin_scanner.guard.daemon.client import GuardDaemonRequestError
from codex_plugin_scanner.guard.daemon.discovery import authenticate_daemon_state, ensure_daemon_discovery_key
from codex_plugin_scanner.guard.daemon.runtime_peer import load_guard_daemon_endpoint
from codex_plugin_scanner.guard.store import GuardStore

_DESKTOP_CORE_VERSION = "3.0.86"


@contextmanager
def _signed_desktop_daemon(
    guard_home: Path,
    *,
    state_guard_home: Path | None = None,
    details_guard_home: Path | None = None,
    state_token: str = "desktop-token",
    package_version: str = _DESKTOP_CORE_VERSION,
    compatibility_version: object = manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
    source_root: str | None = None,
) -> Iterator[tuple[str, str]]:
    token = "desktop-token"
    guard_home.mkdir(parents=True, exist_ok=True)
    if source_root is None:
        managed_source = (
            guard_home.parent / "org.hol.guard.desktop" / "core" / "versions" / _DESKTOP_CORE_VERSION / "hol-guard"
        )
        managed_source.parent.mkdir(parents=True, exist_ok=True)
        managed_source.write_text("synthetic desktop core", encoding="utf-8")
        source_root = str(managed_source)
    discovery_key = ensure_daemon_discovery_key(guard_home)
    details_home = (details_guard_home or guard_home).resolve()
    state_home = (state_guard_home or guard_home).resolve()

    class _HealthHandler(BaseHTTPRequestHandler):
        def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path != "/v1/healthz/details":
                self._write_json({"error": "not_found"}, status=404)
                return
            if self.headers.get("X-Guard-Token") != token:
                self._write_json({"error": "unauthorized"}, status=401)
                return
            self._write_json({**state, "ok": True, "guard_home": str(details_home)})

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _HealthHandler)
    server.daemon_threads = True
    state: dict[str, object] = {
        "guard_home": str(state_home),
        "host": "127.0.0.1",
        "port": server.server_port,
        "compatibility_version": compatibility_version,
        "package_version": package_version,
        "runtime_fingerprint": "d" * 64,
        "pid": os.getpid(),
        "started_at": "2026-09-05T00:00:00+00:00",
        "state_id": "desktop-state",
        "source_root": source_root,
        "auth_token_id": hashlib.sha256(state_token.encode("utf-8")).hexdigest(),
    }
    auth_path = manager._auth_token_path(guard_home)
    auth_path.write_text(token, encoding="utf-8")
    state_path = manager._state_path(guard_home)
    state_path.write_text(
        json.dumps(authenticate_daemon_state(state, discovery_key=discovery_key)),
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(auth_path, 0o600)
        os.chmod(state_path, 0o600)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", token
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_client_reuses_verified_desktop_owner_for_mismatched_cli_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(manager, "__version__", "3.0.88")
    with _signed_desktop_daemon(guard_home) as (daemon_url, token):
        assert manager.load_guard_daemon_url(guard_home) is None
        client = extension_controls_commands._client(guard_home)

    assert client.daemon_url == daemon_url
    assert client.auth_token == token


def test_endpoint_rejects_incompatible_desktop_protocol(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    with _signed_desktop_daemon(guard_home, compatibility_version="not-current"):
        assert load_guard_daemon_endpoint(guard_home) is None


def test_trust_doctor_uses_verified_desktop_endpoint_without_fresh_locator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(manager, "__version__", "3.0.88")
    monkeypatch.setattr(commands_dispatch_trust, "read_approval_center_locator", lambda _home: None)

    with _signed_desktop_daemon(guard_home) as (daemon_url, _token):
        payload = commands_dispatch_trust._approval_center_status_payload(guard_home)

    assert payload["active"] is True
    assert payload["daemon_url"] == daemon_url
    assert payload["snapshot_fresh"] is False


def test_daemon_status_uses_verified_desktop_endpoint_after_running_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(manager, "__version__", "3.0.88")
    monkeypatch.setattr(commands_support_service, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        commands_support_service,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )

    with _signed_desktop_daemon(guard_home) as (daemon_url, _token):
        result = commands_support_service._handle_daemon_status(guard_home, as_json=True)

    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert output["running"] is True
    assert output["version"] == _DESKTOP_CORE_VERSION
    assert output["url"] == daemon_url


def test_client_keeps_strict_current_runtime_path_before_desktop_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        extension_controls_commands,
        "load_guard_daemon_endpoint",
        lambda _home: ("http://127.0.0.1:8235", "current-token"),
    )

    client = extension_controls_commands._client(tmp_path / "guard-home")

    assert client.daemon_url == "http://127.0.0.1:8235"
    assert client.auth_token == "current-token"


def test_client_rejects_desktop_owner_for_mismatched_home(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    with (
        _signed_desktop_daemon(guard_home, state_guard_home=tmp_path / "other-home"),
        pytest.raises(GuardDaemonRequestError, match="not running"),
    ):
        extension_controls_commands._client(guard_home)


def test_client_rejects_desktop_owner_for_mismatched_health_home(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    with (
        _signed_desktop_daemon(guard_home, details_guard_home=tmp_path / "other-home"),
        pytest.raises(GuardDaemonRequestError, match="not running"),
    ):
        extension_controls_commands._client(guard_home)


def test_client_rejects_desktop_owner_with_mismatched_auth_token(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    with (
        _signed_desktop_daemon(guard_home, state_token="wrong-token"),
        pytest.raises(GuardDaemonRequestError, match="not running"),
    ):
        extension_controls_commands._client(guard_home)


def test_client_rejects_arbitrary_daemon_identity_even_when_authenticated_shape_is_present(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    with (
        _signed_desktop_daemon(guard_home, source_root="/opt/hol-guard/lib/python"),
        pytest.raises(GuardDaemonRequestError, match="not running"),
    ):
        extension_controls_commands._client(guard_home)


def test_product_status_uses_verified_desktop_endpoint_for_mismatched_cli_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace_dir.mkdir()
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=workspace_dir)
    observed_homes: list[Path] = []

    def verified_desktop_endpoint(home: Path) -> str:
        observed_homes.append(home)
        return "http://127.0.0.1:8234"

    monkeypatch.setattr(product_module, "detect_all", lambda _context: ())
    monkeypatch.setattr(product_module, "load_guard_daemon_endpoint_url", verified_desktop_endpoint)

    payload = build_guard_status_payload(context, store, config)

    assert observed_homes == [guard_home]
    assert payload["approval_center_url"] == "http://127.0.0.1:8234"
    assert payload["runtime_status"] == "active"


def test_trust_doctor_keeps_desktop_owned_peer_without_restart_advice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(commands_dispatch_trust, "__version__", "3.0.88")
    monkeypatch.setattr(commands_dispatch_trust, "read_approval_center_locator", lambda _home: None)

    with _signed_desktop_daemon(guard_home) as (_daemon_url, _token):
        payload = commands_dispatch_trust._approval_center_status_payload(guard_home)

    assert payload["active"] is True
    assert payload["desktop_owned"] is True
    assert payload["desktop_update_pending"] is True
    assert payload["restart_required"] is False
    assert "HOL Guard Desktop" in payload["detail"]
    assert "Restart it" not in payload["detail"]


def test_trust_doctor_still_directs_cli_owned_daemons_to_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(commands_dispatch_trust, "__version__", "3.0.88")
    monkeypatch.setattr(commands_dispatch_trust, "read_approval_center_locator", lambda _home: None)
    monkeypatch.setattr(commands_dispatch_trust, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:8234")
    monkeypatch.setattr(
        commands_dispatch_trust,
        "_load_state",
        lambda _home: {
            "package_version": "3.0.86",
            "source_root": str(guard_home / "pipx" / "venvs" / "hol-guard" / "lib"),
        },
    )

    payload = commands_dispatch_trust._approval_center_status_payload(guard_home)

    assert payload["active"] is True
    assert payload["desktop_owned"] is False
    assert payload["desktop_update_pending"] is False
    assert payload["restart_required"] is True
    assert "Restart it" in payload["detail"]


def test_trust_doctor_recommends_desktop_update_for_owned_peer_skew(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    managed_source = tmp_path / "org.hol.guard.desktop" / "core" / "versions" / _DESKTOP_CORE_VERSION / "hol-guard"
    managed_source.parent.mkdir(parents=True, exist_ok=True)
    managed_source.write_text("synthetic desktop core", encoding="utf-8")
    monkeypatch.setattr(commands_dispatch_trust, "__version__", "3.0.88")
    monkeypatch.setattr(commands_dispatch_trust, "read_approval_center_locator", lambda _home: None)
    monkeypatch.setattr(commands_dispatch_trust, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:8234")
    monkeypatch.setattr(
        commands_dispatch_trust,
        "load_guard_daemon_endpoint_url",
        lambda _home: "http://127.0.0.1:8234",
    )
    monkeypatch.setattr(
        commands_dispatch_trust,
        "_load_state",
        lambda _home: {
            "pid": 4321,
            "port": 8234,
            "package_version": _DESKTOP_CORE_VERSION,
            "source_root": str(managed_source),
            "started_at": "2026-09-05T00:00:00+00:00",
        },
    )

    payload = commands_dispatch_trust.build_trust_doctor_payload(store)

    assert payload["approval_center"]["active"] is True
    assert payload["approval_center"]["restart_required"] is False
    assert payload["approval_center"]["desktop_owned"] is True
    actions = " ".join(payload["recommended_actions"])
    assert "HOL Guard Desktop" in actions
    assert "daemon repair" not in actions
