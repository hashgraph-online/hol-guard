"""Focused tests for the Guard connect runtime flow."""

from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
from pathlib import Path

from codex_plugin_scanner.guard.cli.connect_flow import run_guard_connect_command
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
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


def test_guard_connect_returns_retry_required_when_first_sync_fails(
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
    assert payload["request_id"].startswith("connect-")


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
    assert completed_state["status"] == "waiting"
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
    assert pending_state["status"] == "waiting"
    assert pending_state["milestone"] == "first_sync_pending"
    assert pending_state["reason"] == "waiting_for_first_sync"
