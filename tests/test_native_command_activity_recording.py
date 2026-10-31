"""Native decisions reach activity storage without retrospective policy evaluation."""

import hashlib
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_hook_evidence_writer import NativeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_pretool_edge_fixtures import canonical_receipt_bytes


def _writer(store: GuardStore) -> NativeHookEvidenceWriter:
    """The writer these tests record through, held by the resident.

    Every test that builds one takes ``native_hook_force`` first, so the
    caller-pinned runtime is the authority behind the handoff.
    """

    return NativeHookEvidenceWriter(store=store)


def _valid_native_receipt() -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": "request-1",
        "request_digest": "a" * 64,
        "harness": "codex",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": None,
        "rule_digest": None,
        "runtime_identity": None,
        "decision": "deny",
        "model_output_action": "not_applicable",
        "policy_action": "review",
        "observed_policy_action": None,
        "reason_code": "native_network_review",
        "workspace_bound": False,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 100,
    }
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    return receipt


def test_native_receipt_link_records_the_edge_receipt() -> None:
    from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin

    host = SimpleNamespace(_last_native_decision_receipt=None)
    # The edge checked the receipt before it answered; only a non-mapping is refused here.
    assert HookWorkerNativeMixin._record_native_decision_receipt(host, ["not", "a", "receipt"]) is None
    assert host._last_native_decision_receipt is None
    receipt = _valid_native_receipt()
    result = HookWorkerNativeMixin._record_native_decision_receipt(host, receipt)
    assert result == receipt
    assert host._last_native_decision_receipt == receipt
    assert HookWorkerNativeMixin._record_native_decision_receipt(host, None) is None


class _ReceiptWriter:
    """Records receipt submissions; every other evidence call is accepted."""

    def __init__(self) -> None:
        self.receipts: list[object] = []

    def submit_native_decision_receipt(self, *, receipt: object) -> bool:
        self.receipts.append(receipt)
        return True

    def __getattr__(self, _name: str) -> object:
        return lambda *_args, **_kwargs: True


@pytest.mark.parametrize("recorded", [True, False, None])
def test_the_daemon_submits_the_receipt_only_when_the_edge_did_not_queue_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorded: bool | None
) -> None:
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('mode = "observe"\nprotection_posture = "watch"\n', encoding="utf-8")
    receipt = _valid_native_receipt()
    asked: dict[str, object] = {}

    def edge(*_args: object, **kwargs: object) -> dict[str, object]:
        asked.update(kwargs)
        answer: dict[str, object] = {
            "event_name": "PreToolUse",
            "harness": "codex",
            "result": {
                "authority": "rust",
                "decision": "deny",
                "minimum_action": "block",
                "policy_action": "block",
                "reason_code": "native_destructive_command",
                "reason": "HOL Guard blocked a destructive command before execution.",
                "explicitly_benign": False,
            },
            "harness_response": {"decision": "allow", "policy_action": "warn"},
            "receipt": receipt,
        }
        if recorded is not None:
            answer["receipt_recorded"] = recorded
        return answer

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native", edge)
    writer = _ReceiptWriter()
    worker = HookWorker(store=GuardStore(guard_home), activity_writer=writer)  # pyright: ignore[reportArgumentType]
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda _workspace, **_kwargs: {"mode": "observe"})
    try:
        worker.review_http_payload(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "rm -rf /"}},
            params={},
            default_harness="codex",
            home_dir=tmp_path / "home",
            guard_home=guard_home,
            workspace=tmp_path / "workspace",
        )
    finally:
        worker.close()
    # A daemon with a writer always asks the edge to queue the receipt.
    assert asked["record_receipt"] is True
    assert writer.receipts == ([] if recorded else [receipt])


@pytest.mark.parametrize("recorded", [True, False, None])
def test_the_daemon_records_a_post_tool_activity_only_when_the_edge_did_not_queue_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorded: bool | None
) -> None:
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('mode = "observe"\nprotection_posture = "watch"\n', encoding="utf-8")

    def edge(*_args: object, **_kwargs: object) -> dict[str, object]:
        answer: dict[str, object] = {
            "event_name": "PostToolUse",
            "harness": "codex",
            "result": {
                "authority": "rust",
                "decision": "allow",
                "minimum_action": "allow",
                "policy_action": "allow",
                "reason_code": "native_post_tool_observed",
                "reason": "HOL Guard recorded the completed tool call.",
                "explicitly_benign": False,
            },
            "harness_response": {"decision": "allow", "policy_action": "allow"},
            "receipt": _valid_native_receipt(),
            "receipt_recorded": True,
        }
        if recorded is not None:
            answer["activity_recorded"] = recorded
        return answer

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native", edge)
    worker = HookWorker(store=GuardStore(guard_home), activity_writer=_ReceiptWriter())  # pyright: ignore[reportArgumentType]
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda _workspace, **_kwargs: {"mode": "observe"})
    activities: list[object] = []
    monkeypatch.setattr(worker, "_record_post_tool_activity", lambda **kwargs: activities.append(kwargs["harness"]))
    try:
        worker.review_http_payload(
            payload={"hook_event_name": "PostToolUse", "tool_input": {"command": "pwd"}},
            params={},
            default_harness="codex",
            home_dir=tmp_path / "home",
            guard_home=guard_home,
            workspace=tmp_path / "workspace",
        )
    finally:
        worker.close()
    # An edge that queued the activity behind its receipt says so; the daemon
    # records it otherwise, including for an older resident that never says.
    assert activities == ([] if recorded else ["codex"])


@pytest.mark.parametrize("recorded", [True, False, None])
def test_the_daemon_records_a_pre_tool_activity_only_when_the_edge_did_not_queue_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorded: bool | None
) -> None:
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('mode = "observe"\nprotection_posture = "watch"\n', encoding="utf-8")

    def edge(*_args: object, **_kwargs: object) -> dict[str, object]:
        # Watch returns a recorded-only block as the edge rendered it.
        answer: dict[str, object] = {
            "event_name": "PreToolUse",
            "harness": "codex",
            "result": {
                "authority": "rust",
                "decision": "deny",
                "minimum_action": "block",
                "policy_action": "block",
                "reason_code": "native_destructive_command",
                "reason": "HOL Guard blocked a destructive command before execution.",
                "explicitly_benign": False,
            },
            "harness_response": {"decision": "allow", "policy_action": "warn"},
            "receipt": _valid_native_receipt(),
            "receipt_recorded": True,
        }
        if recorded is not None:
            answer["activity_recorded"] = recorded
        return answer

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native", edge)
    # Evidence is submitted behind the answer; run it in line to observe it.
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker_native.run_hook_evidence", lambda _host, act: act()
    )
    activities: list[object] = []
    writer = _ReceiptWriter()
    writer.submit_command_activity = lambda **kwargs: activities.append(kwargs["policy_action"]) or True  # pyright: ignore[reportAttributeAccessIssue]
    worker = HookWorker(store=GuardStore(guard_home), activity_writer=writer)  # pyright: ignore[reportArgumentType]
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda _workspace, **_kwargs: {"mode": "observe"})
    try:
        response = worker.review_http_payload(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "rm -rf /"}},
            params={},
            default_harness="codex",
            home_dir=tmp_path / "home",
            guard_home=guard_home,
            workspace=tmp_path / "workspace",
        )
    finally:
        worker.close()
    assert response["policy_action"] == "warn"
    # An edge that queued the activity behind its receipt says so; the daemon
    # records it otherwise, including for an older resident that never says.
    assert activities == ([] if recorded else ["warn"])


@pytest.mark.parametrize(
    ("harness", "id_field", "input_field"),
    [
        ("codex", "tool_call_id", "tool_input"),
        ("grok", "toolUseId", "toolInput"),
        ("zcode", "tool_use_id", "tool_input"),
    ],
)
def test_native_pre_and_post_keep_authoritative_decision(
    native_hook_force: Path,
    tmp_path: Path,
    harness: str,
    id_field: str,
    input_field: str,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = _writer(store)
    payload = {id_field: "call_test_0123456789abcdef", input_field: {"command": "echo example"}}
    try:
        assert writer.submit_command_activity(
            harness=harness,
            event="PreToolUse",
            payload=payload,
            succeeded=True,
            policy_action="warn",
        )
        assert writer.submit_command_activity(
            harness=harness,
            event="PostToolUse",
            payload=payload,
            succeeded=True,
        )
        assert writer.submit_command_activity(
            harness=harness,
            event="PreToolUse",
            payload=payload,
            succeeded=True,
            policy_action="warn",
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        rows = connection.execute(
            "SELECT policy_action, execution_status, parse_confidence, decision_reason_code FROM command_activity"
        ).fetchall()
    assert rows == [("warn", "confirmed_success", None, "policy")]
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        preview = connection.execute("select invocation_preview from command_activity_invocation").fetchone()
    assert preview == ("echo example",)
    journal_path = store.guard_home / "runtime-hook-evidence.jsonl"
    if journal_path.exists():
        assert "echo example" not in journal_path.read_text(encoding="utf-8")
    sidecar_path = store.guard_home / "runtime-hook-evidence.preview.jsonl"
    if sidecar_path.exists():
        assert "echo example" not in sidecar_path.read_text(encoding="utf-8")
    assert writer.stats()["failures"] == 0


def test_approved_retry_preserves_prevented_attempt(native_hook_force: Path, tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = _writer(store)
    payload = {"toolUseId": "call_test_0123456789abcdef", "toolInput": {"command": "echo example"}}
    try:
        for action in ("review", "review", "allow"):
            assert writer.submit_command_activity(
                harness="grok",
                event="PreToolUse",
                payload=payload,
                succeeded=True,
                policy_action=action,
                prompted=action == "review",
                approval_reuse_status="accepted" if action == "allow" else "not-applicable",
            )
        assert writer.submit_command_activity(
            harness="grok",
            event="PostToolUse",
            payload=payload,
            succeeded=True,
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        rows = connection.execute(
            "SELECT policy_action, execution_status FROM command_activity ORDER BY policy_action"
        ).fetchall()
    assert rows == [("allow", "confirmed_success"), ("review", "prevented")]
    assert writer.stats()["failures"] == 0


def test_pre_without_decision_never_becomes_execution(native_hook_force: Path, tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = _writer(store)
    try:
        assert not writer.submit_command_activity(
            harness="grok",
            event="PreToolUse",
            payload={"command": "echo example"},
            succeeded=True,
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    assert store.count_command_activities() == 0


def test_incompatible_approval_metadata_is_not_queued(native_hook_force: Path, tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = _writer(store)
    try:
        assert not writer.submit_command_activity(
            harness="grok",
            event="PreToolUse",
            payload={"command": "echo example"},
            succeeded=True,
            policy_action="allow",
            prompted=True,
            approval_reuse_status="accepted",
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    assert writer.stats()["failures"] == 0
    assert store.count_command_activities() == 0


@pytest.mark.parametrize("action", ["review", "block", "warn", "allow"])
def test_native_restrictive_decisions_keep_receipt_and_prompt(
    native_hook_force: Path, tmp_path: Path, action: str
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = _writer(store)
    try:
        assert writer.submit_command_activity(
            harness="grok",
            event="PreToolUse",
            payload={"command": "echo example"},
            succeeded=False,
            policy_action=action,
            receipt_id="native-receipt-example",
            prompted=action == "review",
            approval_reuse_status="accepted" if action == "allow" else "not-applicable",
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        row = connection.execute(
            "SELECT policy_action, receipt_id, prompted, approval_reuse_status FROM command_activity"
        ).fetchone()
    assert row == (
        action,
        "native-receipt-example",
        int(action == "review"),
        "accepted" if action == "allow" else "not-applicable",
    )
    assert writer.stats()["failures"] == 0
