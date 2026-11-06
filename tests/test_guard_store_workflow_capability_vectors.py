"""Parity of the native workflow-capability store with the original Python store.

The vectors were recorded from the original Python mixins (never from Rust).
Every recorded scenario is replayed through the real `GuardStore` and the
resident, and each step's outcome, control blob writes and database changes
must equal the recording. The protocol tests cover the plan/commit boundary.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_guard_store import NativeGuardStoreUnavailable
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workflow_capabilities import WorkflowCapabilityError
from tests.workflow_capability_vector_replay import DATA_DIR, SCENARIOS, replay

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

RECORDED = {
    scenario["name"]: scenario
    for scenario in json.loads((DATA_DIR / "workflow_capability_vectors.json").read_text(encoding="utf-8"))["scenarios"]
}


def test_every_recorded_scenario_has_a_replay_source() -> None:
    assert set(RECORDED) == set(SCENARIOS)


@pytest.mark.parametrize("name", sorted(RECORDED))
def test_scenario_replays_to_the_recorded_outcomes(name: str) -> None:
    for index, (expected, actual) in enumerate(replay(name, RECORDED[name])):
        for key in sorted(expected):
            assert actual.get(key) == expected[key], f"step {index} {key}"


class FakeControl:
    def __init__(self, blob: str | None = None) -> None:
        self.blob = blob
        self.writes: list[str] = []

    def load(self) -> str | None:
        return self.blob

    def store(self, encoded: str) -> bool:
        self.writes.append(encoded)
        self.blob = encoded
        return True


def _unavailable(reason: str) -> NativeGuardStoreUnavailable:
    error = NativeGuardStoreUnavailable(reason)
    error.reason = reason
    return error


def _plan(writes: list[str], post: list[str], *, commit: bool = True) -> dict[str, object]:
    return {"ok": True, "result": None, "writes": writes, "post_writes": post, "commit": commit}


def _store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, control: FakeControl) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"k" * 32, "key-id"))
    monkeypatch.setattr(store, "_load_workflow_capability_control", control.load)
    monkeypatch.setattr(store, "_store_workflow_capability_control", control.store)
    return store


def test_commit_replays_the_plan_and_persists_the_finalize_write_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = FakeControl()
    store = _store(tmp_path, monkeypatch, control)
    calls: list[tuple[str, dict[str, object]]] = []

    def native(method: str, args: Mapping[str, object]) -> Any:
        calls.append((method, dict(args)))
        if method == "workflow_capability_plan":
            return _plan(["pending"], ["final"])
        return {"result": True, "post_writes": ["final"]}

    monkeypatch.setattr(store, "_native_store_call", native)
    assert store.revoke_workflow_capability("wc-1", reason_code="operator_revoked") is True
    assert [method for method, _ in calls] == ["workflow_capability_plan", "workflow_capability_commit"]
    assert calls[1][1]["plan_writes"] == ["pending"]
    assert calls[1][1]["plan_post_writes"] == ["final"]
    assert control.writes == ["pending", "final"]


def test_stale_plan_restores_the_control_blob_and_retries_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = FakeControl("original")
    store = _store(tmp_path, monkeypatch, control)
    methods: list[str] = []

    def native(method: str, args: Mapping[str, object]) -> Any:
        methods.append(method)
        if method == "workflow_capability_plan":
            return _plan(["pending"], [])
        raise _unavailable("native_guard_store_capability_plan_stale")

    monkeypatch.setattr(store, "_native_store_call", native)
    with pytest.raises(WorkflowCapabilityError, match="capability_plan_stale"):
        store.revoke_workflow_capability("wc-1", reason_code="operator_revoked")
    assert methods == ["workflow_capability_plan", "workflow_capability_commit"] * 3
    assert control.blob == "original"


def test_stale_first_issue_restores_the_bootstrap_control_not_the_pending_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = FakeControl()
    store = _store(tmp_path, monkeypatch, control)
    attempts = 0

    def native(method: str, args: Mapping[str, object]) -> Any:
        nonlocal attempts
        if method == "workflow_capability_plan":
            # A retry must start from the unpended control, never a pending one.
            assert control.blob in (None, "bootstrap")
            return _plan(["bootstrap", "pending"], ["final"])
        attempts += 1
        if attempts == 1:
            raise _unavailable("native_guard_store_capability_plan_stale")
        return {"result": True, "post_writes": ["final"]}

    monkeypatch.setattr(store, "_native_store_call", native)
    assert store.revoke_workflow_capability("wc-1", reason_code="operator_revoked") is True
    assert control.writes[-1] == "final"
    assert control.writes[:3] == ["bootstrap", "pending", "bootstrap"]


def test_other_native_failures_are_not_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, monkeypatch, FakeControl())
    methods: list[str] = []

    def native(method: str, args: Mapping[str, object]) -> Any:
        methods.append(method)
        if method == "workflow_capability_plan":
            return _plan([], [])
        raise _unavailable("native_guard_store_unavailable")

    monkeypatch.setattr(store, "_native_store_call", native)
    with pytest.raises(NativeGuardStoreUnavailable):
        store.revoke_workflow_capability("wc-1", reason_code="operator_revoked")
    assert methods == ["workflow_capability_plan", "workflow_capability_commit"]


def test_unchanged_plan_skips_the_write_transaction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, monkeypatch, FakeControl())
    methods: list[str] = []

    def native(method: str, args: Mapping[str, object]) -> Any:
        methods.append(method)
        return _plan([], [], commit=False)

    monkeypatch.setattr(store, "_native_store_call", native)
    assert store.lookup_workflow_capability("wc-1") is None
    assert methods == ["workflow_capability_plan"]
