from __future__ import annotations

import argparse
import io
import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

from codex_plugin_scanner.guard.cli import commands_dispatch_desktop as desktop
from codex_plugin_scanner.guard.cli import product


def test_status_reads_current_operations_without_starting_or_minting_session(monkeypatch, tmp_path):
    session = Mock(side_effect=AssertionError("status must not launch or mint a session"))
    monkeypatch.setattr(desktop, "build_desktop_dashboard_session_url", session)
    state = {"runtime_status": "active", "managed_harnesses": 1, "cloud_state": "paired_active",
             "pending_approvals": 1, "harnesses": []}
    monkeypatch.setattr(product, "build_guard_status_payload", lambda *a, **kw: dict(state))
    store = Mock()
    store.list_approval_requests.return_value = []
    store.oldest_approval_request_created_at.return_value = None
    store.count_approval_requests.return_value = 0
    store.list_receipts.return_value = []
    store.receipt_summary_between.return_value = {}
    store.get_sync_payload.return_value = None
    context = SimpleNamespace(guard_home=tmp_path, home_dir=tmp_path)
    output = io.StringIO()
    result = desktop._run_guard_desktop_command(
        argparse.Namespace(desktop_command="status"), context=context,
        store=store, config=Mock(), output_stream=output,
    )
    assert result == 0
    first = json.loads(output.getvalue())
    assert first["daemon"]["running"] is True
    assert first["approvals"]["pending"] == 1
    assert "sessionUrl" not in first["dashboard"]
    assert datetime.fromisoformat(first["observedAt"].replace("Z", "+00:00")).tzinfo is not None
    state.update(runtime_status="offline", cloud_state="local_only", pending_approvals=0)
    output = io.StringIO()
    assert desktop._run_guard_desktop_command(
        argparse.Namespace(desktop_command="status"), context=context,
        store=store, config=Mock(), output_stream=output,
    ) == 0
    current = json.loads(output.getvalue())
    assert current["daemon"]["running"] is False
    assert current["approvals"]["pending"] == 0
    assert current["cloud"]["status"] == "not_connected"
    session.assert_not_called()


def test_missing_cloud_observation_is_unknown_not_disconnected():
    payload = desktop.build_desktop_bootstrap_payload(
        status_payload={}, pending_requests=[], approval_history=[], receipts=[], core_version="3.0.0",
    )
    assert payload["cloud"]["status"] == "unknown"
