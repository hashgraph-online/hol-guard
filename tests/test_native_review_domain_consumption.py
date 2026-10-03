"""Policy-bound native reviews retain a single-use retry after approval."""

from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.daemon.hook_native_review_approval import pause_native_pre_tool_for_approval
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_native_review_approvals import consume_native_review_approval
from tests.test_native_command_observations import _edge, _observations, _receipt, _rehash
from tests.test_native_review_policy_binding import _resign_identity


@pytest.fixture(autouse=True)
def questionnaire_mode(tmp_path: Path) -> None:
    update_guard_settings(tmp_path / "guard-home", {"blocked_request_mode": "ask"})


def _review_fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    observations = _observations()
    observations["observations"] = []
    observations["binding"]["observation_count"] = 0
    _rehash(observations)
    result = _edge(observations)["result"]
    result.update(
        schema="guard-pre-tool-result.v1",
        version=1,
        authority="rust",
        minimum_action="review",
        action={"action_type": "command"},
        reason="This file read requires approval.",
    )
    return result, _receipt(observations)


def _pause(store: GuardStore, root: Path, result: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    return pause_native_pre_tool_for_approval(
        store,
        harness="claude-code",
        payload={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "cat .env"}},
        native_result=result,
        native_receipt=receipt,
        workspace=root,
        guard_home=root / "guard-home",
        home_dir=root / "home",
    )


def _approve(store: GuardStore, response: dict[str, Any]) -> str:
    request_id = response["approval_request_id"]
    assert isinstance(request_id, str)
    assert store.resolve_harness_native_approval_request(
        request_id,
        reason="verified harness Accept",
        resolved_at=datetime.now(timezone.utc).isoformat(),
        expected_harness="claude-code",
    )
    return request_id


def test_policy_bound_review_approval_retries_once_without_requeue(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    result, receipt = _review_fixture()
    first = _pause(store, tmp_path, result, receipt)
    request_id = _approve(store, first)
    row = store.get_approval_request(request_id)
    assert row is not None
    assert len(row["artifact_hash"].split(":")) == 7

    retry = _pause(store, tmp_path, result, receipt)
    assert retry.get("approval_reuse_status") == "accepted"
    assert "approval_request_id" not in retry
    assert _pause(store, tmp_path, result, receipt).get("approval_request_id") != request_id


@pytest.mark.parametrize("field", ["policy_digest", "rule_digest", "runtime_identity", "control_revision"])
def test_changed_policy_domain_does_not_consume_original_approval(tmp_path: Path, field: str) -> None:
    store = GuardStore(tmp_path / "guard-home")
    result, receipt = _review_fixture()
    request_id = _approve(store, _pause(store, tmp_path, result, receipt))
    changed_result, changed_receipt = copy.deepcopy(result), copy.deepcopy(receipt)
    if field == "control_revision":
        changed_result["command_extensions"]["binding"][field] += 1
        changed_receipt["command_extensions"][field] += 1
    else:
        changed_receipt[field] = "e" * 64
    _resign_identity(changed_receipt)
    changed = _pause(store, tmp_path, changed_result, changed_receipt)
    assert changed.get("approval_reuse_status") != "accepted"
    assert changed["approval_request_id"] != request_id
    assert _pause(store, tmp_path, result, receipt).get("approval_reuse_status") == "accepted"


def test_policy_bound_review_has_only_one_concurrent_consumer(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    result, receipt = _review_fixture()
    request_id = _approve(store, _pause(store, tmp_path, result, receipt))
    row = store.get_approval_request(request_id)
    assert row is not None
    barrier = Barrier(2)

    def consume() -> bool:
        barrier.wait(timeout=10)
        return store.consume_native_review_approval(
            harness="claude-code",
            artifact_id=row["artifact_id"],
            artifact_name=row["artifact_name"],
            artifact_hash=row["artifact_hash"],
            launch_target=row["launch_target"],
            workspace=str(tmp_path),
            now=datetime.now(timezone.utc).isoformat(),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(lambda _: consume(), range(2))) == [False, True]


@pytest.mark.parametrize(
    "suffix",
    [
        ":",
        ":" + "a" * 63,
        ":" + "a" * 65,
        ":" + "g" * 64,
        ":" + "A" * 64,
        ":" + "a" * 64 + ":extra",
        ":" + "a" * 64 + "\n",
    ],
)
def test_malformed_policy_domain_is_rejected_before_database_access(suffix: str) -> None:
    binding = f"native-review-v4:{'a' * 64}:deny:review:review:native_sensitive_access_review"
    with sqlite3.connect(":memory:") as connection:
        statements: list[str] = []
        connection.set_trace_callback(statements.append)
        assert not consume_native_review_approval(
            connection,
            harness="claude-code",
            artifact_id="claude-code:native-pretool:Bash",
            artifact_name="Bash",
            artifact_hash=binding + suffix,
            launch_target="cat .env",
            workspace=None,
            now=datetime.now(timezone.utc).isoformat(),
        )
        assert not statements


def test_policy_domain_cannot_be_stripped_or_substituted(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    result, receipt = _review_fixture()
    request_id = _approve(store, _pause(store, tmp_path, result, receipt))
    row = store.get_approval_request(request_id)
    assert row is not None
    base, domain = row["artifact_hash"].rsplit(":", 1)
    other_domain = ("a" if domain[0] != "a" else "b") + domain[1:]
    for identity in (base, base + ":" + other_domain):
        assert not store.consume_native_review_approval(
            harness="claude-code",
            artifact_id=row["artifact_id"],
            artifact_name=row["artifact_name"],
            artifact_hash=identity,
            launch_target=row["launch_target"],
            workspace=str(tmp_path),
            now=datetime.now(timezone.utc).isoformat(),
        )
    assert _pause(store, tmp_path, result, receipt).get("approval_reuse_status") == "accepted"
