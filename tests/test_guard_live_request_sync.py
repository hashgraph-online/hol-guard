"""Behavioral coverage for durable live-request cloud sync."""

from __future__ import annotations

from json import dumps as json_dumps
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import live_request_sync as live_request_sync_module
from codex_plugin_scanner.guard.runtime.live_request_sync import (
    LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
    _build_live_request_event,
    _resolve_sync_url,
    start_cloud_sync_sync_worker,
    stop_cloud_sync_sync_worker,
)


class Store:
    """Minimal GuardStore stand-in for event and worker contracts."""

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self._payloads: dict[str, object] = {}

    def get_sync_payload(self, key: str) -> object | None:
        return self._payloads.get(key)

    def set_sync_payload(self, key: str, payload: object, now: str) -> None:
        self._payloads[key] = payload

    def get_cloud_sync_profile(self) -> dict[str, str]:
        return {
            "auth_mode": "oauth",
            "sync_url": "https://hol.test/api/guard/receipts/sync",
            "workspace_id": "workspace-1",
        }

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object]:
        return {
            "grant_id": "grant-1",
            "machine_id": "machine-1",
            "runtime_id": "runtime-1",
            "workspace_id": "workspace-1",
        }

    def get_or_create_installation_id(self) -> str:
        return "22222222-2222-4222-8222-222222222222"

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object]:
        return {"operation_id": request_id, "metadata": {"workspace_path": "/workspace/repo"}}


class TestIndependentWorker:
    """start_cloud_sync_sync_worker creates a thread; stop_cloud_sync_sync_worker signals it."""

    def test_worker_owns_live_review_sync(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = Store(tmp_path)
        calls: list[tuple[str, dict[str, object]]] = []

        class StopAfterOneIteration:
            def is_set(self) -> bool:
                return False

            def wait(self, _timeout: float) -> bool:
                return True

        monkeypatch.setattr(
            live_request_sync_module,
            "_resolve_live_request_sync_auth_context",
            lambda _store: {"access_token": "token-1", "workspace_id": "workspace-1"},
        )
        monkeypatch.setattr(
            live_request_sync_module,
            "sync_live_requests_once",
            lambda _store, auth: calls.append(("live", auth)) or {"synced": 0},
        )

        live_request_sync_module._cloud_sync_sync_loop(
            store,
            StopAfterOneIteration(),
            poll_interval=1,
            error_backoff=1,
        )

        assert calls == [
            ("live", {"access_token": "token-1", "workspace_id": "workspace-1"}),
        ]

    def test_start_worker_creates_thread(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)

        class FakeThread:
            def __init__(self, *args: object, **kwargs: object) -> None:
                self.started = False

            def is_alive(self) -> bool:
                return True

            def start(self) -> None:
                self.started = True

        created_thread = FakeThread()

        def fake_thread(*args: object, **kwargs: object) -> FakeThread:
            return created_thread

        monkeypatch.setattr("codex_plugin_scanner.guard.runtime.live_request_sync.threading.Thread", fake_thread)
        worker = start_cloud_sync_sync_worker(store)
        assert worker is not None
        assert worker.thread is created_thread
        assert created_thread.started is True

    def test_stop_worker_signals_stop_event(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)

        class FakeThread:
            def __init__(self) -> None:
                self.started = False
                self.joined = False
                self.join_timeout: float | None = -1

            def is_alive(self) -> bool:
                return not self.joined

            def start(self) -> None:
                self.started = True

            def join(self, timeout: float | None = None) -> None:
                self.join_timeout = timeout
                self.joined = True

        class FakeEvent:
            def __init__(self, stopped: bool = False) -> None:
                self.stopped = stopped

            def is_set(self) -> bool:
                return self.stopped

            def set(self) -> None:
                self.stopped = True

        created_thread = FakeThread()
        created_event = FakeEvent(False)

        def fake_thread(*args: object, **kwargs: object) -> FakeThread:
            return created_thread

        monkeypatch.setattr(
            "codex_plugin_scanner.guard.runtime.live_request_sync.threading.Thread",
            fake_thread,
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.runtime.live_request_sync.threading.Event",
            lambda: created_event,
        )

        worker = start_cloud_sync_sync_worker(store)
        assert worker is not None
        assert created_event.is_set() is False

        new_worker = stop_cloud_sync_sync_worker(worker)
        assert new_worker is None  # dead worker returns None
        assert created_event.is_set() is True
        assert created_thread.join_timeout == 1.0

    def test_start_worker_skips_alive_existing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)

        class FakeThread:
            def is_alive(self) -> bool:
                return True

            def start(self) -> None:
                pass

        class FakeEvent:
            def is_set(self) -> bool:
                return False

        existing = type("Worker", (), {"thread": FakeThread(), "stop_event": FakeEvent()})()
        monkeypatch.delenv("GUARD_LIVE_REQUEST_POLL_INTERVAL", raising=False)

        new_worker = start_cloud_sync_sync_worker(store, existing=existing)  # type: ignore[arg-type]
        assert new_worker is existing

    def test_start_worker_returns_none_when_opted_out(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """GUARD_LIVE_REQUEST_ENABLED=0 disables the worker."""
        store = Store(tmp_path)
        monkeypatch.setenv("GUARD_LIVE_REQUEST_ENABLED", "0")
        monkeypatch.delenv("GUARD_LIVE_REQUEST_POLL_INTERVAL", raising=False)
        assert start_cloud_sync_sync_worker(store) is None

    def test_start_worker_returns_none_without_cloud_profile(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = Store(tmp_path)
        monkeypatch.setattr(store, "get_cloud_sync_profile", lambda: {})

        assert start_cloud_sync_sync_worker(store) is None

    def test_start_worker_with_existing_stopped_thread(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Existing worker with stopped thread → replaced with new worker."""
        store = Store(tmp_path)

        class FakeThread:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                self.started = False

            def is_alive(self) -> bool:
                return False

            def start(self) -> None:
                self.started = True

        class FakeEvent:
            def is_set(self) -> bool:
                return True

        existing = type("Worker", (), {"thread": FakeThread(), "stop_event": FakeEvent()})()
        monkeypatch.delenv("GUARD_LIVE_REQUEST_POLL_INTERVAL", raising=False)
        monkeypatch.setattr(live_request_sync_module.threading, "Thread", FakeThread)

        new_worker = start_cloud_sync_sync_worker(store, existing=existing)  # type: ignore[arg-type]
        assert new_worker is not existing

    def test_stop_worker_none_noop(self, tmp_path: Path) -> None:
        assert stop_cloud_sync_sync_worker(None) is None


# ---------------------------------------------------------------------------
# Contract: live_request_sync_status before dedicated cloud sync
# ---------------------------------------------------------------------------


class TestSyncStatus:
    """live_request_sync_status returns the current status dict."""

    def test_status_returns_protocol_version(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.store import GuardStore

        store = GuardStore(tmp_path)
        from codex_plugin_scanner.guard.runtime.live_request_sync import live_request_sync_status

        status = live_request_sync_status(store)
        assert isinstance(status, dict)
        assert status["protocolVersion"] == LIVE_REQUEST_SYNC_PROTOCOL_VERSION


class TestRedactionLevelNone:
    """Redaction level 'none' emits the actual scrubbed command for display/raw.

    Live request with a real command + secret: raw_command and display_command
    carry the secret-scrubbed text; display_provenance is 'raw'; redacted_command
    is None.
    """

    def test_redaction_none_uses_scrubbed_command(self, tmp_path: Path) -> None:
        """raw_command and display_command contain the command with secrets removed."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-redact-1",
            "status": "pending",
            "action_identity": "test-action",
            "trigger_summary": "Run deployment",
            "risk_headline": "Admin privilege escalation",
            "harness": "guard-review",
            "raw_command_text": 'curl -H "Bearer tokensecret123" https://api.example.com/deploy',
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
            "expires_at": "2026-07-10T01:00:00+00:00",
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        # The command must not contain the raw secret token
        assert "tokensecret123" not in event["rawCommand"]
        assert "tokensecret123" not in event["displayCommand"]
        # But the command shape is preserved (curl, Bearer, URL present)
        assert "curl" in event["rawCommand"]
        assert "https://api.example.com/deploy" in event["rawCommand"]
        # display_provenance must signal raw source
        assert event["displayProvenance"] == "raw"
        # redacted_command must be None for 'none' level
        assert event["redactedCommand"] is None

    def test_redaction_none_enforces_portal_utf16_field_limits(
        self,
        tmp_path: Path,
    ) -> None:
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-bounded-1",
            "status": "pending",
            "action_identity": "test-action",
            "trigger_summary": "😀" * 400,
            "risk_headline": "😀" * 400,
            "harness": "guard-review",
            "raw_command_text": ("😀" * 40_000) + " --dangerous-suffix",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )

        assert event is not None
        raw_command = event["rawCommand"]
        display_summary = event["displaySummary"]
        assert isinstance(raw_command, str)
        assert isinstance(display_summary, str)
        assert len(raw_command.encode("utf-16-le")) // 2 <= 65_536
        assert " … [truncated] … " in raw_command
        assert raw_command.endswith(" --dangerous-suffix")
        assert len(display_summary.encode("utf-16-le")) // 2 <= 512

    def test_redaction_none_hides_bearer_prefix(self, tmp_path: Path) -> None:
        """Bearer token is scrubbed to 'Bearer *****' — prefix retained."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-bearer-1",
            "status": "pending",
            "action_identity": "api-call",
            "trigger_summary": "Fetch data",
            "harness": "guard-review",
            "raw_command_text": 'curl -H "Bearer abcdef123456" https://example.com',
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert "Bearer *****" in event["rawCommand"]
        assert "Bearer abcdef" not in event["rawCommand"]

    def test_redaction_none_no_secret_in_any_field(self, tmp_path: Path) -> None:
        """A secret-bearing command must not leak the raw secret anywhere in the event."""
        store = Store(tmp_path)
        secret = "sk-" + ("x" * 24)
        item: dict[str, object] = {
            "request_id": "req-secret-1",
            "status": "pending",
            "action_identity": "openai-chat",
            "trigger_summary": "Generate text",
            "risk_summary": "Model API call",
            "harness": "guard-review",
            "raw_command_text": f'echo "{secret}" > ~/.env',
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        # The raw secret value must not appear in any field
        event_text = json_dumps(event)
        assert secret not in event_text

    def test_redaction_none_scrubs_generic_token_assignments(self, tmp_path: Path) -> None:
        """Mandatory cloud scrubbing still applies when user redaction is disabled."""
        store = Store(tmp_path)
        secret = "generic-" + ("x" * 24)
        item: dict[str, object] = {
            "request_id": "req-secret-2",
            "status": "pending",
            "action_identity": "deploy",
            "trigger_summary": "Deploy service",
            "harness": "guard-review",
            "raw_command_text": f"deploy --api-key {secret}",
            "action_envelope_json": {
                "action_type": "shell_command",
                "command": f"deploy --api-key {secret}",
                "args": ["--api-key", secret],
                "parameters": {"accessToken": secret, "region": "us-east-1"},
            },
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert secret not in json_dumps(event)
        assert "[redacted]" in event["rawCommand"]
        request_payload = event["requestPayload"]
        assert isinstance(request_payload, dict)
        action_envelope = request_payload["actionEnvelope"]
        assert isinstance(action_envelope, dict)
        assert action_envelope["args"] == ["--api-key", "[redacted]"]
        assert action_envelope["parameters"] == {
            "accessToken": "[redacted]",
            "region": "us-east-1",
        }


class TestRedactionLevelPartial:
    """Redaction level 'partial' emits a redacted command without secret leakage.

    raw_command is None; redacted_command carries the secret-stripped text;
    display_provenance is 'redacted'; the secret value must not appear.
    """

    def test_redaction_partial_has_redacted_command_not_raw(self, tmp_path: Path) -> None:
        """redacted_command carries the scrubbed text; raw_command is None."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-partial-1",
            "status": "pending",
            "action_identity": "deploy-staging",
            "trigger_summary": "Push to staging",
            "harness": "guard-review",
            "raw_command_text": "API_KEY=supersecretkey123 && ./deploy.sh",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="partial",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        # raw_command must be None for partial
        assert event["rawCommand"] is None
        # redacted_command must carry the scrubbed text
        assert event["redactedCommand"] is not None
        assert isinstance(event["redactedCommand"], str)
        # The original secret value must not appear
        assert "supersecretkey123" not in event["redactedCommand"]
        assert event["redactedCommand"] == "[redacted]"

    def test_redaction_partial_display_command_is_redacted(self, tmp_path: Path) -> None:
        """display_command mirrors redacted_command (not raw secret)."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-partial-2",
            "status": "pending",
            "action_identity": "db-migrate",
            "trigger_summary": "Migrate database",
            "harness": "guard-review",
            "raw_command_text": "postgres://user:p@ssw0rd@db.example.com:5432/mydb",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="partial",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert event["displayCommand"] == event["redactedCommand"]
        # connection-string pattern should have redacted the URL
        assert "postgres://" not in event["displayCommand"]
        assert "p@ssw0rd" not in event["displayCommand"]

    def test_redaction_partial_display_provenance_is_redacted(self, tmp_path: Path) -> None:
        """Provenance is 'redacted' — not 'raw' or 'withheld'."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-partial-3",
            "status": "pending",
            "action_identity": "test-action",
            "trigger_summary": "Run test",
            "harness": "guard-review",
            "raw_command_text": "echo hello",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="partial",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert event["displayProvenance"] == "redacted"

    def test_redaction_full_scrubs_secret_like_fallback_metadata(self, tmp_path: Path) -> None:
        """Full redaction scrubs fallback metadata when no command is available."""
        store = Store(tmp_path)
        sensitive_identity = "api_key=" + ("x" * 24)
        item: dict[str, object] = {
            "request_id": "req-full-2",
            "status": "pending",
            "action_identity": sensitive_identity,
            "trigger_summary": "Write config",
            "harness": "my-harness",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="full",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert sensitive_identity not in event["displayCommand"]
        assert event["displayCommand"] == "my-harness: [redacted]"
        assert event["redactedCommand"] is None
        assert event["displayProvenance"] == "withheld"

    def test_redaction_full_marks_scrubbed_command_as_redacted(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        sensitive = "api_key=" + ("x" * 24)
        item: dict[str, object] = {
            "request_id": "req-full-command",
            "status": "pending",
            "raw_command_text": f"curl '{sensitive}' https://api.example.com",
            "action_identity": "curl",
            "harness": "my-harness",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }

        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="full",
            store=store,
            event_sequence=1,
        )

        assert event is not None
        assert event["displayProvenance"] == "redacted"
        assert sensitive not in event["displayCommand"]
        assert "curl" in event["displayCommand"]


class TestPendingRequestAgeConnectivity:
    """Pending local requests remain live/actionable regardless age or connectivity.

    Age alone must not make a pending request historical; disconnected daemon
    must not suppress the command text.
    """

    def test_pending_request_ignores_legacy_expiration_timestamp(self, tmp_path: Path) -> None:
        """A pending request with a past expires_at emits no product expiration."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-age-1",
            "status": "pending",
            "action_identity": "deploy-critical-fix",
            "trigger_summary": "Hotfix for production",
            "harness": "guard-review",
            "raw_command_text": "./run-hotfix.sh --force",
            "created_at": "2026-07-01T00:00:00+00:00",
            "last_seen_at": "2026-07-01T00:00:00+00:00",
            "expires_at": "2026-07-01T01:00:00+00:00",  # already expired
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert event["eventType"] == "request_created"
        assert event["rawCommand"] is not None
        assert "./run-hotfix.sh --force" in event["rawCommand"]
        assert "localExpiresAt" not in event

    def test_disconnected_daemon_still_emits_command_text(self, tmp_path: Path) -> None:
        """No oauth context (disconnected) must not suppress command emission."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-disconn-1",
            "status": "pending",
            "action_identity": "review-pr",
            "trigger_summary": "Review pending pull request",
            "harness": "guard-review",
            "raw_command_text": "gh pr review 42 --approve",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
            "expires_at": "2026-07-10T12:00:00+00:00",
        }
        # oauth=None simulates disconnected daemon (no cloud auth available)
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert event["reviewClaim"] is None  # no oauth = no claim, but event still emitted
        # Command text must still be present
        assert "gh pr review 42 --approve" in event["rawCommand"]
        assert event["displayProvenance"] == "raw"

    def test_pending_status_keeps_lifecycle_live_not_historical(self, tmp_path: Path) -> None:
        """status='pending' must yield request_created, never historical status."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-live-1",
            "status": "pending",
            "action_identity": "install-package",
            "trigger_summary": "Add dependency",
            "harness": "guard-review",
            "raw_command_text": "npm install lodash@latest",
            "created_at": "2026-07-05T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
            "expires_at": "2026-07-06T00:00:00+00:00",
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        # Must be 'request_created', NOT 'request_expired'
        assert event["eventType"] == "request_created"
        assert event["eventType"] != "request_expired"

    def test_legacy_expired_status_reopens_as_live(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-legacy-expired-1",
            "status": "expired",
            "action_identity": "deploy-critical-fix",
            "trigger_summary": "Hotfix for production",
            "harness": "guard-review",
            "raw_command_text": "./run-hotfix.sh --force",
            "created_at": "2026-07-01T00:00:00+00:00",
            "last_seen_at": "2026-07-01T00:00:00+00:00",
            "resolved_at": "2026-07-01T01:00:00+00:00",
        }

        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )

        assert event is not None
        assert event["eventType"] == "request_created"
        assert event["requestPayload"]["status"] == "pending"


# ---------------------------------------------------------------------------
# Contract: _resolve_sync_url derives live-request endpoint from receipt sync URL
# ---------------------------------------------------------------------------


class TestResolveSyncUrl:
    """_resolve_sync_url replaces the entire path, preserving scheme and host."""

    def test_full_receipt_path_replaced_not_appended(self) -> None:
        """A receipt-sync URL must derive /api/guard/live-requests/sync, not
        append to the existing receipt path.  This is the contract that caused
        the production 404 — the old code appended instead of replacing."""
        auth_context: dict[str, object] = {
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        }
        result = _resolve_sync_url(auth_context, "/api/guard/live-requests/sync")
        assert result == "https://hol.org/api/guard/live-requests/sync"

    def test_https_origin_with_explicit_port_preserved(self) -> None:
        """An HTTPS origin carrying an explicit port keeps that port when the
        path is replaced."""
        auth_context: dict[str, object] = {
            "sync_url": "https://hol.org:8443/api/guard/receipts/sync",
        }
        result = _resolve_sync_url(auth_context, "/api/guard/live-requests/sync")
        assert result == "https://hol.org:8443/api/guard/live-requests/sync"

    def test_query_string_preserved_when_path_replaced(self) -> None:
        """Replacing the sync URL path preserves query-bound routing."""
        auth_context: dict[str, object] = {
            "sync_url": "https://hol.org/api/guard/receipts/sync?route=tenant-a",
        }
        result = _resolve_sync_url(auth_context, "/api/guard/live-requests/sync")
        assert result == "https://hol.org/api/guard/live-requests/sync?route=tenant-a"
