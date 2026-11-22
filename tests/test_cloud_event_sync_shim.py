"""The Python side of the native ``cloud-event-sync`` command."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime, native_runtime
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.cloud_bundle_sync import (
    CLOUD_EVENT_SYNC_COMMAND,
    CLOUD_EVENT_SYNC_FEATURE,
    cloud_event_sync,
)
from codex_plugin_scanner.guard.store import GuardStore

# These tests answer the native command themselves, so they never take the
# conftest's empty-queue double for Guard events.
pytestmark = pytest.mark.native_guard_events


def _status(tmp_path: Path, features: tuple[str, ...]) -> SimpleNamespace:
    return SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "hol-guard-runtime"),
        capabilities=SimpleNamespace(features=features),
    )


def _answer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, response: object) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status(tmp_path, (CLOUD_EVENT_SYNC_FEATURE,)))

    def run(argv: tuple[str, ...], **options: object) -> SimpleNamespace:
        assert argv[1:] == (CLOUD_EVENT_SYNC_COMMAND, "--stdin")
        sent.append(json.loads(str(options["input_text"])))
        return SimpleNamespace(
            returncode=0,
            timed_out=False,
            output_limit_exceeded=False,
            containment_failed=False,
            stdout=json.dumps(response),
        )

    monkeypatch.setattr(codex_hook_launch_runtime, "run_isolated_hook_process", run)
    # The session payload also reads package shim coverage from the runtime;
    # that read has its own tests and would hit this stub.
    monkeypatch.setattr(runner, "_cloud_package_manager_coverage", lambda *_args, **_kwargs: {})
    return sent


def test_runtime_without_the_command_asks_for_an_update(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status(tmp_path, ()))
    with pytest.raises(RuntimeError, match="event sync needs a newer"):
        cloud_event_sync(tmp_path, "guard_events")


def test_guard_events_returns_the_native_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary = {"synced_at": "2026-11-19T00:00:00+00:00", "events": 1, "accepted": 1}
    sent = _answer(monkeypatch, tmp_path, {"ok": True, "result": summary})
    store = GuardStore(tmp_path / "guard-home")

    assert runner.sync_guard_events(store, auth_context={"sync_url": "https://hol.org/api"}) == summary
    assert sent[0]["action"] == "guard_events"
    assert sent[0]["guardHome"] == str(store.guard_home)
    assert sent[0]["authContext"] == {"sync_url": "https://hol.org/api"}


def test_pain_signals_returns_the_uploaded_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _answer(monkeypatch, tmp_path, {"ok": True, "result": 3})
    store = GuardStore(tmp_path / "guard-home")

    assert runner.sync_pain_signals(store, auth_context={}) == 3
    assert sent[0]["action"] == "pain_signals"
    assert "authContext" not in sent[0] or sent[0]["authContext"] is None


def test_pain_signals_count_must_be_an_integer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, tmp_path, {"ok": True, "result": True})
    assert runner.sync_pain_signals(GuardStore(tmp_path / "guard-home")) == 0


def test_untrusted_endpoint_keeps_its_error_class(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(
        monkeypatch,
        tmp_path,
        {"ok": False, "outcome": "endpoint_untrusted", "error": "Guard Cloud sync endpoint is not trusted."},
    )
    with pytest.raises(runner.GuardSyncEndpointUntrustedError, match="not trusted"):
        runner.sync_guard_events(GuardStore(tmp_path / "guard-home"))


def test_a_plan_restriction_is_not_retryable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(
        monkeypatch,
        tmp_path,
        {"ok": False, "outcome": "not_available", "error": "Upgrade to sync events.", "retryable": False},
    )
    with pytest.raises(runner.GuardSyncNotAvailableError) as error:
        runner.sync_guard_events(GuardStore(tmp_path / "guard-home"))
    assert error.value.retryable is False


_SESSION = {"session_id": "session-live", "created_at": "2026-11-19T00:00:00.000Z"}
_AUTH = {"sync_url": "https://hol.org/api/guard/receipts/sync", "token": "demo"}


@pytest.mark.native_runtime_session
def test_runtime_session_posts_through_the_native_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    response = {"syncedAt": "2026-11-19T00:00:05+00:00", "items": [{"sessionId": "session-live"}]}
    sent = _answer(monkeypatch, tmp_path, {"ok": True, "result": {"status": "synced", "response": response}})
    store = GuardStore(tmp_path / "guard-home")
    # Queueing the session event writes through the native store, which this
    # stubbed runtime does not offer; the queue has its own tests.
    monkeypatch.setattr(store, "add_guard_event_v1", lambda *_args, **_kwargs: None)
    # The summary row is written through the native store too.
    written: dict[str, object] = {}
    monkeypatch.setattr(store, "set_sync_payload", lambda key, payload, _now: written.__setitem__(key, payload))

    summary = runner.sync_runtime_session(store, session=dict(_SESSION), auth_context=dict(_AUTH))

    assert written["runtime_session_summary"] == summary
    assert sent[0]["action"] == "runtime_session"
    assert sent[0]["session"]["sessionId"] == "session-live"
    assert summary["runtime_session_id"] == "session-live"
    assert summary["runtime_session_synced_at"] == "2026-11-19T00:00:05+00:00"


@pytest.mark.native_runtime_session
def test_a_skipped_runtime_session_returns_the_native_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    skipped = {
        "runtime_session_id": "session-live",
        "runtime_session_sync_skipped": True,
        "runtime_session_sync_reason": "runtime_session_endpoint_unavailable",
    }
    _answer(monkeypatch, tmp_path, {"ok": True, "result": {"status": "skipped", "summary": skipped}})

    summary = runner.sync_runtime_session(
        GuardStore(tmp_path / "guard-home"), session=dict(_SESSION), auth_context=dict(_AUTH)
    )

    assert summary == skipped


@pytest.mark.native_runtime_session
def test_runtime_session_answer_needs_a_response(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, tmp_path, {"ok": True, "result": {"status": "synced"}})
    with pytest.raises(RuntimeError, match="Invalid sync response"):
        runner.sync_runtime_session(
            GuardStore(tmp_path / "guard-home"), session=dict(_SESSION), auth_context=dict(_AUTH)
        )
