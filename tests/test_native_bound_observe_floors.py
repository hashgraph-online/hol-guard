"""Acknowledged command authority retains the native result in Observe mode.

The store, signature, source capture, configuration and worker adapter are real.
The resident ACK and already-decoded native result are explicit transport seams;
native producer and installed HTTP acceptance require separate execution.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from types import MethodType, SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    NativeCommandControlMutationRequiredError,
    require_command_control_mutation_lease,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from tests.native_managed_source_support import managed_store
from tests.native_policy_snapshot_test_fixtures import _ack, _status
from tests.test_canonical_policy_row_authority import _NOW


@pytest.mark.parametrize(
    ("action", "reason"),
    [
        ("block", "native_command_permission_disabled"),
        ("block", "native_destructive_command"),
        ("warn", "native_policy_warning"),
        ("allow", "native_exact_safe_command"),
    ],
)
def test_signed_managed_observe_delivers_the_acknowledged_native_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str, reason: str
) -> None:
    home = tmp_path / "guard-home"
    home.mkdir()
    (home / "config.toml").write_text('mode="observe"\nprotection_posture="watch"\n', encoding="utf-8")
    store = managed_store(tmp_path, monkeypatch, scoped=False)
    status = _status()
    status.capabilities.features += tuple(SCOPED_PUBLISH_FEATURES)
    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=lambda: status,
        client_request=lambda **values: _ack(values["payload"]),
        wall_clock=lambda: datetime.fromisoformat(_NOW.replace("Z", "+00:00")).timestamp(),
    )
    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        snapshot = publisher.current_snapshot()
        binding = publisher.current_snapshot_binding()
        assert snapshot is not None and binding is not None
        assert snapshot["version"] == 3 and binding["mode"] == "observe"
        assert binding["command_extensions_bound"] is True
        assert publisher.requires_policy_authority and not publisher.requires_scoped_authority
        controls = snapshot["command_extensions"]
        assert isinstance(controls, dict)
        assert controls["health"] == "protected" and controls["managed_revision"] == 1
        expected = "allow" if action in {"allow", "warn"} else "deny"
        native_result = {
            "authority": "rust",
            "decision": expected,
            "minimum_action": action,
            "policy_action": action,
            "reason_code": reason,
            "reason": "Synthetic bounded native result.",
            "explicitly_benign": action == "allow",
        }
        receipt = {"authority": "rust", "decision": expected, "policy_action": action}

        def native_edge(**_kwargs: object) -> dict[str, object]:
            with pytest.raises(NativeCommandControlMutationRequiredError):
                require_command_control_mutation_lease(home)
            return {
                "schema": "guard-hook-edge-result.v2",
                "authority": "rust",
                "event_name": "PreToolUse",
                "harness": "claude-code",
                "result": native_result,
                "receipt": receipt,
            }

        host: Any = SimpleNamespace(
            store=store,
            policy_snapshot_publisher=publisher,
            _native_policy_snapshot=lambda *_args, **_kwargs: binding,
            _review_raw_hook_native=native_edge,
            _record_native_decision_receipt=lambda value: value,
            metrics=SimpleNamespace(record_route=lambda _route: None),
            activity_writer=None,
        )
        host._review_native_edge_with_snapshot = MethodType(HookWorker._review_native_edge_with_snapshot, host)
        response = HookWorker._review_native_edge(
            host,
            payload={"tool_name": "Bash", "tool_input": {"command": "git push --force"}},
            harness="claude-code",
            event_name="PreToolUse",
            default_harness="claude-code",
            home_dir=tmp_path,
            guard_home=home,
            workspace=tmp_path,
            deadline=None,
        )
        output = response["hookSpecificOutput"]
        assert isinstance(output, dict)
        assert output["permissionDecision"] == expected
        assert response["policy_action"] == action
        assert native_result["minimum_action"] == action
        assert receipt["decision"] == expected
        assert "approval_request_id" not in response
        assert response.get("approval_reuse_status") != "accepted"
        assert store.list_approval_requests(status="pending") == []
        require_command_control_mutation_lease(home)
    finally:
        publisher.close()
