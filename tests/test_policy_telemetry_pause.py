"""Intentional optional-upload pauses stay distinct from failed delivery."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.runtime.optional_telemetry_sync import sync_nonessential_telemetry
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_receipt_runner_preference_integration import (
    _cursor,
    _invoke,
    _ordinary_auth,
    _ready,
    _rows,
    _settings,
    _Transport,
)
from tests.test_receipt_runner_preference_integration import _local_runtime as _local_runtime


@pytest.mark.parametrize("entrypoint", ["receipts", "proof"])
@pytest.mark.parametrize("local_telemetry,remote_telemetry", [(False, True), (True, False), (False, False)])
def test_saved_telemetry_pause_preserves_real_receipt_progress_and_reports_paused(
    tmp_path: Path,
    _local_runtime: Callable[[_Transport], None],
    entrypoint: str,
    local_telemetry: bool,
    remote_telemetry: bool,
) -> None:
    store, _ = _ready(tmp_path, telemetry=remote_telemetry)
    _settings(store, telemetry=local_telemetry)
    rows = _rows(store, 2)
    transport = _Transport(telemetry=remote_telemetry)
    _local_runtime(transport)

    summary = _invoke(store, entrypoint, auth_context=_ordinary_auth(store))

    assert isinstance(summary, dict)
    assert summary["telemetry_status"] == "paused"
    assert summary["guard_events_upload_status"] == "paused"
    assert summary["guard_events_upload_reason"] == "optional_upload_paused"
    assert summary["pain_signals_uploaded"] == 0
    assert transport.sent_ids() == [row["receipt_id"] for row in rows]
    assert _cursor(store) == rows[-1]["receipt_rowid"]
    expected_kinds = ["session", "receipts"] if entrypoint == "proof" else ["receipts"]
    assert [call["kind"] for call in transport.calls] == expected_kinds
    persisted = store.get_sync_payload("sync_summary")
    assert isinstance(persisted, dict)
    assert persisted["telemetry_status"] == "paused"


def test_paused_events_do_not_hide_an_independent_upload_failure(tmp_path: Path) -> None:
    def failed_pain_upload() -> int:
        raise OSError("synthetic upload outage")

    summary = sync_nonessential_telemetry(
        GuardStore(tmp_path),
        pain_signals=failed_pain_upload,
        guard_events=lambda: {"sync_skipped": True, "sync_reason": "optional_upload_paused", "accepted": 3},
        authorization_errors=(),
    )

    assert summary["telemetry_status"] == "degraded"
    assert summary["pain_signals_upload_status"] == "degraded"
    assert summary["pain_signals_upload_reason"] == "telemetry_transport_error"
    assert summary["guard_events_upload_status"] == "paused"
    assert summary["guard_events_upload_reason"] == "optional_upload_paused"
    events = summary["guard_events_v1"]
    assert isinstance(events, dict)
    assert events["accepted"] == 3


@pytest.mark.parametrize("event_status", ["failed", "degraded", "unknown", {"invalid": True}, ["paused"]])
def test_failure_or_unknown_status_cannot_be_masked_by_pause_reason(tmp_path: Path, event_status: object) -> None:
    summary = sync_nonessential_telemetry(
        GuardStore(tmp_path),
        pain_signals=lambda: 0,
        guard_events=lambda: {
            "status": event_status,
            "sync_skipped": True,
            "sync_reason": "optional_upload_paused",
        },
        authorization_errors=(),
    )

    assert summary["telemetry_status"] == "degraded"
    assert summary["guard_events_upload_status"] == "degraded"
    assert summary["guard_events_upload_reason"] == "telemetry_upload_failed"


def test_sync_display_describes_intentional_pause(capsys: pytest.CaptureFixture[str]) -> None:
    emit_guard_payload("sync", {"telemetry_status": "paused", "pain_signals_uploaded": 0}, False)
    output = " ".join(capsys.readouterr().out.split())
    assert "Telemetry uploads paused" in output
    assert "uploads delayed" not in output
