"""Focused tests for the Guard connect runtime flow."""

from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from codex_plugin_scanner.guard.cli.connect_flow import (
    _start_guard_runtime_session,
    run_guard_connect_command,
)
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.client import GuardDaemonTransportError
from codex_plugin_scanner.guard.store import GuardStore


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    home_dir.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)
    (home_dir / ".codex").mkdir(parents=True, exist_ok=True)
    (workspace_dir / ".codex").mkdir(parents=True, exist_ok=True)
    (home_dir / ".codex" / "config.toml").write_text('approval_policy = "never"\n', encoding="utf-8")
    (workspace_dir / ".codex" / "config.toml").write_text("", encoding="utf-8")


def test_guard_daemon_exposes_canonical_connect_state_endpoint(tmp_path) -> None:
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

        create_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/connect/requests",
            data=json.dumps(
                {
                    "sync_url": "https://hol.org/registry/api/v1",
                    "allowed_origin": "https://hol.org",
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Guard-Token": initialize_payload["auth_token"],
            },
            method="POST",
        )
        with urllib.request.urlopen(create_request, timeout=5) as response:
            created_payload = json.loads(response.read().decode("utf-8"))

        state_request = urllib.request.Request(
            (
                f"http://127.0.0.1:{daemon.port}/v1/connect/state"
                f"?request_id={created_payload['request_id']}"
                f"&pairing_secret={created_payload['pairing_secret']}"
            ),
            headers={"Origin": "https://hol.org"},
            method="GET",
        )
        with urllib.request.urlopen(state_request, timeout=5) as response:
            state_payload = json.loads(response.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert state_payload["state"]["version"] == "guard-connect-state.v1"
    assert state_payload["state"]["status"] == "waiting"
    assert state_payload["state"]["milestone"] == "waiting_for_browser"


def test_guard_connect_preserves_pairing_when_first_sync_fails(
    tmp_path,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    store = GuardStore(home_dir)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.ensure_guard_daemon",
        lambda guard_home: f"http://127.0.0.1:{daemon.port}",
    )

    def open_browser(url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        fragment = urllib.parse.parse_qs(parsed.fragment)
        request_id = query["guardPairRequest"][-1]
        daemon_url = query["guardDaemon"][-1]
        pairing_secret = fragment["guardPairSecret"][-1]

        def complete_pairing() -> None:
            request = urllib.request.Request(
                f"{daemon_url}/v1/connect/complete",
                data=urllib.parse.urlencode(
                    {
                        "request_id": request_id,
                        "pairing_secret": pairing_secret,
                        "token": "session-token-123",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://hol.org",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5):
                pass

        threading.Thread(target=complete_pairing, daemon=True).start()
        return True

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_receipts",
        lambda current_store: (_ for _ in ()).throw(RuntimeError("sync_unreachable")),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_runtime_session",
        lambda current_store, *, session: {
            "synced_at": "2026-04-15T00:00:01Z",
            "runtime_session_id": str(session.get("session_id") or session.get("sessionId")),
            "runtime_session_synced_at": "2026-04-15T00:00:01Z",
            "runtime_sessions_visible": 1,
        },
    )

    try:
        payload = run_guard_connect_command(
            guard_home=home_dir,
            store=store,
            sync_url="https://hol.org/registry/api/v1",
            connect_url="https://hol.org/guard/connect",
            opener=open_browser,
            wait_timeout_seconds=5,
        )
    finally:
        daemon.stop()

    assert payload["connected"] is False
    assert payload["status"] == "retry_required"
    assert payload["milestone"] == "first_sync_failed"
    assert payload["reason"] == "sync_unreachable"
    assert payload["sync_message"] == "sync_unreachable"
    assert payload["request_id"].startswith("connect-")
    assert "guardPairRequest=" in str(payload["connect_url"])
    assert "guardPairSecret=" in str(payload["connect_url"])
    assert payload["sync"]["synced_at"] is None
    assert payload["proof"]["first_synced_at"] is None


def test_guard_connect_prefers_paid_plan_sync_note_over_runtime_sync_timeout(
    tmp_path,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    store = GuardStore(home_dir)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.ensure_guard_daemon",
        lambda guard_home: f"http://127.0.0.1:{daemon.port}",
    )

    def open_browser(url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        fragment = urllib.parse.parse_qs(parsed.fragment)
        request_id = query["guardPairRequest"][-1]
        daemon_url = query["guardDaemon"][-1]
        pairing_secret = fragment["guardPairSecret"][-1]

        def complete_pairing() -> None:
            request = urllib.request.Request(
                f"{daemon_url}/v1/connect/complete",
                data=urllib.parse.urlencode(
                    {
                        "request_id": request_id,
                        "pairing_secret": pairing_secret,
                        "token": "session-token-123",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://hol.org",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5):
                pass

        threading.Thread(target=complete_pairing, daemon=True).start()
        return True

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_runtime_session",
        lambda current_store, *, session: (_ for _ in ()).throw(RuntimeError("timed out")),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_receipts",
        lambda current_store: (_ for _ in ()).throw(
            RuntimeError("Guard Cloud sync requires a paid Guard plan"),
        ),
    )

    try:
        payload = run_guard_connect_command(
            guard_home=home_dir,
            store=store,
            sync_url="https://hol.org/registry/api/v1",
            connect_url="https://hol.org/guard/connect",
            opener=open_browser,
            wait_timeout_seconds=5,
        )
    finally:
        daemon.stop()

    assert payload["connected"] is False
    assert payload["status"] == "retry_required"
    assert payload["milestone"] == "first_sync_failed"
    assert payload["reason"] == "Guard Cloud sync requires a paid Guard plan"
    assert payload["sync_message"] == "Guard Cloud sync requires a paid Guard plan"


def test_guard_connect_preserves_http_402_payment_required_sync_note(
    tmp_path,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    store = GuardStore(home_dir)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.ensure_guard_daemon",
        lambda guard_home: f"http://127.0.0.1:{daemon.port}",
    )

    def open_browser(url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        fragment = urllib.parse.parse_qs(parsed.fragment)
        request_id = query["guardPairRequest"][-1]
        daemon_url = query["guardDaemon"][-1]
        pairing_secret = fragment["guardPairSecret"][-1]

        def complete_pairing() -> None:
            request = urllib.request.Request(
                f"{daemon_url}/v1/connect/complete",
                data=urllib.parse.urlencode(
                    {
                        "request_id": request_id,
                        "pairing_secret": pairing_secret,
                        "token": "session-token-123",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://hol.org",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5):
                pass

        threading.Thread(target=complete_pairing, daemon=True).start()
        return True

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_runtime_session",
        lambda current_store, *, session: (_ for _ in ()).throw(RuntimeError("timed out")),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_receipts",
        lambda current_store: (_ for _ in ()).throw(
            RuntimeError("HTTP Error 402: Payment Required"),
        ),
    )

    try:
        payload = run_guard_connect_command(
            guard_home=home_dir,
            store=store,
            sync_url="https://hol.org/registry/api/v1",
            connect_url="https://hol.org/guard/connect",
            opener=open_browser,
            wait_timeout_seconds=5,
        )
    finally:
        daemon.stop()

    assert payload["connected"] is False
    assert payload["status"] == "retry_required"
    assert payload["milestone"] == "first_sync_failed"
    assert payload["reason"] == "HTTP Error 402: Payment Required"
    assert payload["sync_message"] == "HTTP Error 402: Payment Required"


def test_guard_connect_keeps_pairing_when_runtime_sync_fails(
    tmp_path,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    store = GuardStore(home_dir)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.ensure_guard_daemon",
        lambda guard_home: f"http://127.0.0.1:{daemon.port}",
    )

    def open_browser(url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        fragment = urllib.parse.parse_qs(parsed.fragment)
        request_id = query["guardPairRequest"][-1]
        daemon_url = query["guardDaemon"][-1]
        pairing_secret = fragment["guardPairSecret"][-1]

        def complete_pairing() -> None:
            request = urllib.request.Request(
                f"{daemon_url}/v1/connect/complete",
                data=urllib.parse.urlencode(
                    {
                        "request_id": request_id,
                        "pairing_secret": pairing_secret,
                        "token": "session-token-123",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://hol.org",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5):
                pass

        threading.Thread(target=complete_pairing, daemon=True).start()
        return True

    sync_receipts_calls: list[bool] = []

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_runtime_session",
        lambda current_store, *, session: (_ for _ in ()).throw(RuntimeError("runtime_sync_unreachable")),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_receipts",
        lambda current_store: (
            sync_receipts_calls.append(True)
            or {
                "synced_at": "2026-04-15T00:00:02Z",
                "receipts_stored": 0,
                "inventory_tracked": 0,
            }
        ),
    )

    try:
        payload = run_guard_connect_command(
            guard_home=home_dir,
            store=store,
            sync_url="https://hol.org/registry/api/v1",
            connect_url="https://hol.org/guard/connect",
            opener=open_browser,
            wait_timeout_seconds=5,
        )
    finally:
        daemon.stop()

    assert payload["connected"] is True
    assert payload["status"] == "connected"
    assert payload["milestone"] == "first_sync_pending"
    assert payload["reason"] == "runtime_sync_unreachable"
    assert payload["sync_message"] == "runtime_sync_unreachable"
    assert payload["sync"]["runtime_session_sync_pending"] is True
    assert payload["sync"]["runtime_session_sync_reason"] == "runtime_sync_unreachable"
    assert payload["sync"]["runtime_session_synced_at"] is None
    assert payload["sync"]["runtime_sessions_visible"] == 0
    assert payload["sync"]["runtime_session_id"]
    assert payload["sync"]["synced_at"] is None
    assert payload["proof"]["first_synced_at"] is None
    assert sync_receipts_calls == [True]


def test_guard_store_backfills_missing_connect_state_on_pairing_completion(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    created_request = store.create_guard_connect_request(
        sync_url="https://hol.org/registry/api/v1",
        allowed_origin="https://hol.org",
        now="2026-04-15T00:00:00+00:00",
    )

    with store._connect() as connection:
        connection.execute(
            "delete from guard_connect_states where request_id = ?",
            (created_request["request_id"],),
        )

    completed_request = store.complete_guard_connect_request(
        request_id=str(created_request["request_id"]),
        pairing_secret=str(created_request["pairing_secret"]),
        token="session-token-123",
        now="2026-04-15T00:00:01+00:00",
    )
    completed_state = store.get_guard_connect_state(
        str(created_request["request_id"]),
        now="2026-04-15T00:00:01+00:00",
    )

    assert completed_request["status"] == "completed"
    assert completed_state is not None
    assert completed_state["status"] == "connected"
    assert completed_state["milestone"] == "first_sync_pending"
    assert completed_state["proof"]["pairing_completed_at"] == "2026-04-15T00:00:01+00:00"


def test_guard_store_keeps_first_sync_pending_state_after_request_expiry(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    created_request = store.create_guard_connect_request(
        sync_url="https://hol.org/registry/api/v1",
        allowed_origin="https://hol.org",
        now="2026-04-15T00:00:00+00:00",
        lifetime_seconds=60,
    )
    store.complete_guard_connect_request(
        request_id=str(created_request["request_id"]),
        pairing_secret=str(created_request["pairing_secret"]),
        token="session-token-123",
        now="2026-04-15T00:00:30+00:00",
    )

    pending_state = store.get_guard_connect_state(
        str(created_request["request_id"]),
        now="2026-04-15T00:05:00+00:00",
    )

    assert pending_state is not None
    assert pending_state["status"] == "connected"
    assert pending_state["milestone"] == "first_sync_pending"
    assert pending_state["reason"] == "waiting_for_first_sync"


def test_start_guard_runtime_session_falls_back_when_daemon_start_fails() -> None:
    class FailingDaemonClient:
        def start_session(self, **kwargs: object) -> dict[str, object]:
            raise GuardDaemonTransportError("daemon_unavailable")

    runtime_session = _start_guard_runtime_session(FailingDaemonClient())

    assert runtime_session["session_id"].startswith("guard-session-")
    assert runtime_session["client_name"] == "hol-guard"
    assert runtime_session["surface"] == "cli"


def test_guard_connect_recovers_from_legacy_daemon_state_without_auth_token(
    tmp_path,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    store = GuardStore(home_dir)

    ensure_calls: list[Path] = []
    clear_calls: list[Path] = []
    load_attempts = {"count": 0}

    class _DaemonClient:
        daemon_url = "http://127.0.0.1:9999"

        def create_connect_request(self, *, sync_url: str, allowed_origin: str) -> dict[str, object]:
            return {
                "request_id": "connect-legacy-recovery",
                "pairing_secret": "pairing-secret",
                "expires_at": "2026-04-16T00:05:00+00:00",
            }

    def _ensure_guard_daemon(path: Path) -> str:
        ensure_calls.append(path)
        return "http://127.0.0.1:9999"

    def _clear_guard_daemon_state(path: Path) -> None:
        clear_calls.append(path)

    def _load_guard_surface_daemon_client(path: Path) -> _DaemonClient:
        load_attempts["count"] += 1
        if load_attempts["count"] == 1:
            raise RuntimeError("Guard daemon state is incomplete.")
        return _DaemonClient()

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.ensure_guard_daemon",
        _ensure_guard_daemon,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.clear_guard_daemon_state",
        _clear_guard_daemon_state,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.load_guard_surface_daemon_client",
        _load_guard_surface_daemon_client,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.wait_for_connect_transition",
        lambda **kwargs: None,
    )

    payload = run_guard_connect_command(
        guard_home=home_dir,
        store=store,
        sync_url="https://hol.org/api/guard/receipts/sync",
        connect_url="https://hol.org/guard/connect",
        opener=lambda url: True,
        wait_timeout_seconds=5,
    )

    assert payload["status"] == "waiting"
    assert payload["milestone"] == "waiting_for_browser"
    assert load_attempts["count"] == 2
    assert len(clear_calls) == 1
    assert len(ensure_calls) >= 2


def test_guard_connect_recovers_when_browser_pairing_completed_before_cli_sync(
    tmp_path,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    store = GuardStore(home_dir)

    class _DaemonClient:
        daemon_url = "http://127.0.0.1:9999"

        def create_connect_request(self, *, sync_url: str, allowed_origin: str) -> dict[str, object]:
            return {
                "request_id": "connect-recovered",
                "pairing_secret": "pairing-secret",
                "expires_at": "2026-04-16T00:05:00+00:00",
            }

        def report_connect_result(
            self,
            *,
            request_id: str,
            status: str,
            milestone: str,
            reason: str | None = None,
            sync: dict[str, object] | None = None,
        ) -> dict[str, object]:
            return {
                "request_id": request_id,
                "status": status,
                "milestone": milestone,
                "reason": reason,
                "completed_at": "2026-04-16T00:00:30+00:00",
                "expires_at": "2026-04-16T00:05:00+00:00",
                "proof": sync or {},
            }

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.ensure_guard_daemon",
        lambda guard_home: "http://127.0.0.1:9999",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.load_guard_surface_daemon_client",
        lambda guard_home: _DaemonClient(),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.wait_for_connect_transition",
        lambda **kwargs: {
            "request_id": "connect-recovered",
            "status": "retry_required",
            "milestone": "first_sync_failed",
            "reason": "timed out",
            "completed_at": "2026-04-16T00:00:30+00:00",
            "expires_at": "2026-04-16T00:05:00+00:00",
            "proof": {},
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_runtime_session",
        lambda current_store, *, session: {
            "runtime_session_id": str(session.get("sessionId")),
            "runtime_session_synced_at": "2026-04-16T00:00:31Z",
            "runtime_sessions_visible": 1,
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.sync_receipts",
        lambda current_store: {
            "synced_at": "2026-04-16T00:00:32Z",
            "receipts_stored": 0,
            "inventory_tracked": 0,
        },
    )

    payload = run_guard_connect_command(
        guard_home=home_dir,
        store=store,
        sync_url="https://hol.org/api/guard/receipts/sync",
        connect_url="https://hol.org/guard/connect",
        opener=lambda url: True,
        wait_timeout_seconds=5,
    )

    assert payload["connected"] is True
    assert payload["status"] == "connected"
    assert payload["milestone"] == "first_sync_succeeded"


def test_guard_connect_registers_runtime_session_before_first_sync(
    tmp_path,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    observed_requests: list[tuple[str, dict[str, object]]] = []

    class SyncHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            content_length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            observed_requests.append((self.path, payload))
            if self.path == "/api/guard/runtime/sessions/sync":
                response = {
                    "generatedAt": "2026-04-16T00:00:02.000Z",
                    "items": [payload["session"]],
                }
            elif self.path == "/api/guard/receipts/sync":
                response = {
                    "syncedAt": "2026-04-16T00:00:03.000Z",
                    "receiptsStored": len(payload.get("receipts", [])),
                    "advisories": [],
                    "policy": {},
                    "alertPreferences": {},
                    "teamPolicyPack": {},
                    "exceptions": [],
                }
            else:
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, message_format: str, *args: object) -> None:
            return

    sync_server = ThreadingHTTPServer(("127.0.0.1", 0), SyncHandler)
    sync_thread = threading.Thread(target=sync_server.serve_forever, daemon=True)
    sync_thread.start()

    store = GuardStore(home_dir)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.connect_flow.ensure_guard_daemon",
        lambda guard_home: f"http://127.0.0.1:{daemon.port}",
    )

    def open_browser(url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        fragment = urllib.parse.parse_qs(parsed.fragment)
        request_id = query["guardPairRequest"][-1]
        daemon_url = query["guardDaemon"][-1]
        pairing_secret = fragment["guardPairSecret"][-1]

        def complete_pairing() -> None:
            request = urllib.request.Request(
                f"{daemon_url}/v1/connect/complete",
                data=urllib.parse.urlencode(
                    {
                        "request_id": request_id,
                        "pairing_secret": pairing_secret,
                        "token": "session-token-123",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"http://127.0.0.1:{sync_server.server_port}",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5):
                pass

        threading.Thread(target=complete_pairing, daemon=True).start()
        return True

    try:
        payload = run_guard_connect_command(
            guard_home=home_dir,
            store=store,
            sync_url=f"http://127.0.0.1:{sync_server.server_port}/api/guard/receipts/sync",
            connect_url=f"http://127.0.0.1:{sync_server.server_port}/guard/connect",
            opener=open_browser,
            wait_timeout_seconds=5,
        )
    finally:
        daemon.stop()
        sync_server.shutdown()
        sync_server.server_close()

    assert payload["connected"] is True
    assert [path for path, _payload in observed_requests] == [
        "/api/guard/runtime/sessions/sync",
        "/api/guard/receipts/sync",
    ]
    runtime_session = observed_requests[0][1]["session"]
    assert isinstance(runtime_session, dict)
    assert runtime_session["clientName"] == "hol-guard"
    assert runtime_session["surface"] == "cli"
