"""A local allow stays pending until the native snapshot that authorizes it is current."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.native_policy_snapshot import (
    _PUBLISHER_LOCK,
    _PUBLISHERS,
    _publisher_key,
)
from codex_plugin_scanner.guard.store import GuardStore


def test_artifact_allow_waits_for_native_publication_before_resolution(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="local-native-publication",
        harness="codex",
        artifact_id="codex:project:tool-action:local-native-publication",
        artifact_name="Read configuration",
        artifact_type="tool_action_request",
        artifact_hash="hash-local-native-publication",
        publisher=None,
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("file_path",),
        source_scope="project",
        config_path="/workspace/release-gate-project/.guard/config.toml",
        workspace="/workspace/release-gate-project",
        launch_target="Read .npmrc",
        action_envelope_json={"action_type": "tool", "tool_name": "Read"},
        decision_v2_json={"action": "ask", "approval_scopes": ["artifact"]},
        review_command="hol-guard approvals approve local-native-publication",
        approval_url="http://127.0.0.1:5474/approvals/local-native-publication",
    )
    store.add_approval_request(request, "2026-10-05T00:00:00+00:00")
    observed: dict[str, object] = {}

    class _Publisher:
        closed = False

        def has_served_snapshot(self) -> bool:
            return True

        def is_ready(self) -> bool:
            return False

        def request_publish(self) -> None:
            return None

        def wait_until_ready(self, deadline_monotonic: float) -> bool:
            del deadline_monotonic
            current = store.get_approval_request(request.request_id)
            observed["status_while_waiting"] = current["status"] if current is not None else None
            return True

    key = _publisher_key(Path(store.guard_home))
    publisher = _Publisher()
    with _PUBLISHER_LOCK:
        _PUBLISHERS.setdefault(key, set()).add(publisher)
    try:
        result = apply_approval_resolution(
            store=store,
            request_id=request.request_id,
            action="allow",
            scope="artifact",
            workspace=request.workspace,
            reason="Local release-gate reviewer",
            now="2026-10-05T00:00:01+00:00",
            return_queue_result=True,
        )
    finally:
        with _PUBLISHER_LOCK:
            publishers = _PUBLISHERS.get(key)
            if publishers is not None:
                publishers.discard(publisher)
                if not publishers:
                    _PUBLISHERS.pop(key, None)

    assert result["resolved"] is True
    assert observed["status_while_waiting"] == "pending"
    stored = store.get_approval_request(request.request_id)
    assert stored is not None and stored["status"] == "resolved"


def test_unacknowledged_native_publication_keeps_the_approval_pending(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="local-native-publication-late",
        harness="codex",
        artifact_id="codex:project:tool-action:local-native-publication-late",
        artifact_name="Read configuration",
        artifact_type="tool_action_request",
        artifact_hash="hash-local-native-publication-late",
        publisher=None,
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("file_path",),
        source_scope="project",
        config_path="/workspace/release-gate-project/.guard/config.toml",
        workspace="/workspace/release-gate-project",
        launch_target="Read .npmrc",
        action_envelope_json={"action_type": "tool", "tool_name": "Read"},
        decision_v2_json={"action": "ask", "approval_scopes": ["artifact"]},
        review_command="hol-guard approvals approve local-native-publication-late",
        approval_url="http://127.0.0.1:5474/approvals/local-native-publication-late",
    )
    store.add_approval_request(request, "2026-10-05T00:00:00+00:00")

    class _Publisher:
        closed = False

        def has_served_snapshot(self) -> bool:
            return True

        def is_ready(self) -> bool:
            return False

        def request_publish(self) -> None:
            return None

        def wait_until_ready(self, deadline_monotonic: float) -> bool:
            del deadline_monotonic
            return False

    key = _publisher_key(Path(store.guard_home))
    publisher = _Publisher()
    with _PUBLISHER_LOCK:
        _PUBLISHERS.setdefault(key, set()).add(publisher)
    try:
        try:
            apply_approval_resolution(
                store=store,
                request_id=request.request_id,
                action="allow",
                scope="artifact",
                workspace=request.workspace,
                reason="Local release-gate reviewer",
                now="2026-10-05T00:00:01+00:00",
                return_queue_result=True,
            )
        except ValueError as error:
            assert str(error) == "native_policy_snapshot_unacknowledged"
        else:
            raise AssertionError("an unacknowledged snapshot must not resolve the approval")
    finally:
        with _PUBLISHER_LOCK:
            publishers = _PUBLISHERS.get(key)
            if publishers is not None:
                publishers.discard(publisher)
                if not publishers:
                    _PUBLISHERS.pop(key, None)

    stored = store.get_approval_request(request.request_id)
    assert stored is not None and stored["status"] == "pending"


def test_one_publisher_cannot_hide_another_publication_failure(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot import await_registered_native_policy_publication

    class _Publisher:
        def __init__(self, ready: bool) -> None:
            self.closed = False
            self.ready = ready

        def has_served_snapshot(self) -> bool:
            return True

        def request_publish(self) -> None:
            return None

        def wait_until_ready(self, deadline_monotonic: float) -> bool:
            del deadline_monotonic
            return self.ready

    home = tmp_path / "guard-home"
    ready = _Publisher(True)
    late = _Publisher(False)
    key = _publisher_key(home)
    with _PUBLISHER_LOCK:
        _PUBLISHERS[key] = {ready, late}
    try:
        assert await_registered_native_policy_publication(home, timeout_seconds=1.0) is False
    finally:
        with _PUBLISHER_LOCK:
            _PUBLISHERS.pop(key, None)
