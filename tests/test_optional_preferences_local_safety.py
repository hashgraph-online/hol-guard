"""Optional content preferences preserve real signed local enforcement authority."""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import workspace_preference_authority as authority
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.runtime.receipt_upload import optional_upload_settings
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_managed_source_support import PERMISSION, managed_store
from tests.test_oauth_connection_authority import _inputs
from tests.test_receipt_runner_preference_integration import (
    _cursor,
    _invoke,
    _Response,
    _rows,
    _settings,
    _Transport,
)
from tests.test_receipt_runner_preference_integration import _local_runtime as _local_runtime
from tests.test_workspace_preference_authority import NOW, WORKSPACE, _accept, _wire


class _ConsentTransport(_Transport):
    def __call__(self, request: urllib.request.Request, *args: Any, **kwargs: Any) -> _Response:
        assert isinstance(request.data, bytes)
        body = json.loads(request.data)
        if isinstance(body, dict) and set(body) == {"events"}:
            assert isinstance(body["events"], list) and body["events"]
            self.calls.append({"kind": "events", "body": body})
            return _Response(
                {
                    "syncedAt": NOW,
                    "statuses": [{"eventId": event["eventId"], "status": "accepted"} for event in body["events"]],
                }
            )
        return super().__call__(request, *args, **kwargs)


def _snapshot(store: GuardStore) -> ExtensionControlRuntimeSnapshot:
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        store.read_extension_control_authority_for_registry(REGISTRY)
    )
    assert snapshot.authority_failure is None
    return snapshot


def _assert_local_decisions(store: GuardStore, snapshot: ExtensionControlRuntimeSnapshot) -> None:
    states = {
        layer.kind: control.state
        for layer in snapshot.layers
        for control in layer.controls
        if control.target.target_id == PERMISSION
    }
    assert states[ControlLayerKind.LOCAL_ADMIN] is ControlState.ENABLED
    assert states[ControlLayerKind.SIGNED_CLOUD] is ControlState.DISABLED

    managed = evaluate_command(
        "git push --force origin main",
        cwd=store.guard_home,
        home_dir=store.guard_home,
        extension_control_snapshot=snapshot,
    )
    assert managed.minimum_action == "block"
    assert managed.decision_plane.action == "block"
    assert managed.control_resolution.blocked and not managed.control_resolution.failures
    assert any(factor.reason_code == "control.disabled-permission" for factor in managed.control_resolution.factors)

    intrinsic = evaluate_command(
        "rm -rf ./BUILD",
        cwd=store.guard_home,
        home_dir=store.guard_home,
        extension_control_snapshot=snapshot,
    )
    assert intrinsic.decision_plane.action == "block"
    assert not intrinsic.control_resolution.blocked
    assert not intrinsic.control_resolution.failures

    harmless = evaluate_command(
        "git status",
        cwd=store.guard_home,
        home_dir=store.guard_home,
        extension_control_snapshot=snapshot,
    )
    assert harmless.minimum_action == "allow"
    assert harmless.decision_plane.action == "review"
    assert not harmless.control_resolution.blocked


@pytest.mark.parametrize("preference_source", ["device", "workspace"])
@pytest.mark.parametrize("sync", [False, True])
@pytest.mark.parametrize("telemetry", [False, True])
@pytest.mark.parametrize("redaction", ["none", "partial", "full"])
def test_optional_preferences_preserve_signed_floor_and_local_decisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _local_runtime: Callable[[_Transport], None],
    preference_source: str,
    sync: bool,
    telemetry: bool,
    redaction: str,
) -> None:
    # Real signed managed activation, SQLite authority, and local approval-bound
    # settings. Fixture terminal confirmation and secret storage are controlled;
    # this is source-runtime execution, not an installed native or MFA claim.
    store = managed_store(tmp_path, monkeypatch, workspace_id=WORKSPACE)
    connection_inputs: dict[str, Any] = {**_inputs(), "workspace_id": WORKSPACE}
    store.set_oauth_local_credentials(**connection_inputs)
    before = _snapshot(store)
    _assert_local_decisions(store, before)
    bundle_before = store.get_sync_payload("policy_bundle")
    decisions_before = store.list_policy_decisions()

    device = preference_source == "device"
    _settings(
        store,
        sync=sync if device else True,
        telemetry=telemetry if device else True,
        redaction=redaction if device else "none",
    )
    wire = _wire(
        sync=True if device else sync,
        telemetry=True if device else telemetry,
        redaction="none" if device else redaction,
    )
    _accept(store, wire)
    state = authority.capture_workspace_preference_state(store)
    assert state.confirmed
    assert optional_upload_settings(store, state) == (sync, redaction)
    assert optional_upload_settings(store, state, telemetry=True) == (sync and telemetry, redaction)
    config_before = load_guard_config(store.guard_home)
    rows = _rows(store, 2)
    receipts_before = store.list_receipts(limit=10)
    transport = _ConsentTransport()

    def respond(body: dict[str, Any], _number: int) -> _Response:
        return _Response(
            {
                "syncedAt": NOW,
                "workspacePreferences": wire,
                "receiptSyncAccepted": sync,
                "receiptsStored": len(body["receipts"]),
            }
        )

    # Only HTTP delivery is controlled; real receipt selection, last-moment
    # consent checks, request serialization, and cursor completion execute.
    transport.receipt_handler = respond
    _local_runtime(transport)
    summary = _invoke(store)
    assert isinstance(summary, dict)
    assert transport.sent_ids() == ([row["receipt_id"] for row in rows] if sync else [])
    assert _cursor(store) == (rows[-1]["receipt_rowid"] if sync else None)
    if not sync or not telemetry:
        assert summary["telemetry_status"] == "paused"
        assert [call["kind"] for call in transport.calls] == ["receipts"]
    else:
        assert summary["telemetry_status"] == "success"
        assert [call["kind"] for call in transport.calls] == ["receipts", "events"]
        assert store.list_guard_events_v1(uploaded=False, limit=200) == []
    assert store.list_receipts(limit=10) == receipts_before

    after = _snapshot(store)
    assert after == before
    assert store.get_sync_payload("policy_bundle") == bundle_before
    assert store.list_policy_decisions() == decisions_before
    assert load_guard_config(store.guard_home) == config_before
    _assert_local_decisions(store, after)
