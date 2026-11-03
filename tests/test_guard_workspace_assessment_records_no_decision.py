from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_supply_chain_eval as transport
from codex_plugin_scanner.guard import supply_chain_workspace_audit as audit
from codex_plugin_scanner.guard import workspace_assessment_runner as runner
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_workspace_assessment_runner import AUDIT, SCANNED, T0, queued_run, snapshots
from tests.test_native_supply_chain_eval import _Artifact, _bind, _store

# Every GuardStore write that records an enforcement outcome: receipts, decision
# receipts, evidence, approvals and the events the Cloud sync sends on.
RECORDING_METHODS = (
    "add_receipt",
    "add_evidence",
    "record_tool_call_evidence",
    "record_native_decision_receipt",
    "record_local_once_approval",
    "add_approval_request",
    "queue_native_review",
    "add_event",
    "add_guard_event_v1",
)


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    for name in RECORDING_METHODS:
        assert callable(getattr(GuardStore, name))
        monkeypatch.setattr(GuardStore, name, lambda self, *args, _name=name, **kwargs: calls.append(_name))
    return calls


def test_a_blocking_finding_is_reported_without_recording_a_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorded: list[str]
) -> None:
    # A background assessment reports what it found. A package the audit would
    # block on install is a finding, not a blocked action: no receipt, approval
    # request or event comes out of the run.
    store, claimed = queued_run(tmp_path)
    snapshots(monkeypatch, runner, SCANNED)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert assessments.finish(store, claimed, outcome, now_ms=T0 + 1)
    [finding] = outcome.findings
    assert (finding["package_name"], finding["decision"]) == ("minimist", "block")
    assert recorded == []


def test_the_assessment_audit_asks_for_no_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The audit above is canned, so this pins the real call: the shared audit
    # writes a supply-chain evidence row for every package it would block, and
    # that row would list a package nobody tried to install as a blocked request.
    asked: dict[str, object] = {}

    def build(**kwargs: object) -> tuple[dict[str, object], int]:
        asked.update(kwargs)
        return AUDIT, 0

    monkeypatch.setattr(audit, "build_workspace_audit_payload", build)
    assert runner._local_audit(None, None, tmp_path) == AUDIT
    assert asked["record_evidence"] is False
    assert asked["allow_cloud_audit"] is False


def test_the_workspace_audit_passes_the_evidence_choice_to_the_evaluator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: dict[str, object] = {}

    def evaluate(**kwargs: object) -> SimpleNamespace:
        asked.update(kwargs)
        return SimpleNamespace(to_dict=lambda: {"decision": "block"})

    scanned = SimpleNamespace(inventory_digest="digest", scan_targets=())
    monkeypatch.setattr(audit, "native_workspace_inventory", lambda *args, **kwargs: scanned)
    monkeypatch.setattr(audit, "build_package_request_artifact", lambda *args, **kwargs: _Artifact())
    monkeypatch.setattr(audit._lsc, "evaluate_package_request_artifact", evaluate)
    evaluation = audit._workspace_local_evaluation(
        store=SimpleNamespace(guard_home=tmp_path),
        workspace_dir=tmp_path,
        sbom_paths=(),
        before_workspace_dir=None,
        manifest_paths=("package.json",),
        lockfile_paths=("package-lock.json",),
        command_name="workspace-assessment",
        inventory_digest="digest",
        now="2026-05-19T00:00:00Z",
        record_evidence=False,
    )
    assert evaluation == {"decision": "block"}
    assert asked["record_evidence"] is False


def _block_one_package(reply: dict[str, object]) -> None:
    reply["payload"].update(
        decision="block",
        policy_action="block",
        packages=[{"name": "minimist", "resolvedVersion": "0.0.8", "decision": "block"}],
        evidence_ids=["evidence-1"],
    )


@pytest.mark.parametrize("record_evidence", [True, False])
def test_a_blocked_evaluation_writes_evidence_only_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, record_evidence: bool
) -> None:
    _bind(monkeypatch, mutate=_block_one_package)
    persisted: list[object] = []
    monkeypatch.setattr(transport, "_persist_evidence", lambda **kwargs: persisted.append(kwargs["evaluation"]))
    result = transport.evaluate_package_request_native(
        artifact=_Artifact(),
        store=_store(tmp_path),
        workspace_dir=tmp_path,
        now="2026-05-19T00:00:00Z",
        record_evidence=record_evidence,
    )
    assert result.decision == "block"
    assert persisted == ([result] if record_evidence else [])
