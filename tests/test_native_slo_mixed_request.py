"""Real evidence admission for diagnostic requests; no runtime timing claims."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.runtime.command_activity_correlation import derive_proven_request_correlation
from codex_plugin_scanner.guard.runtime.command_activity_privacy import InstallationCorrelationKey
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_adapter import payload
from scripts.native_slo_mixed_request import fixture_request, request_attempt
from scripts.native_slo_mixed_witness import ReceiptWitness
from tests.test_native_decision_receipt import _receipt


def test_fixture_ids_admit_real_command_evidence_for_both_harnesses_and_all_attempt_kinds(tmp_path: Path) -> None:
    writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path))
    key = InstallationCorrelationKey(key_id="fixture-test", material=b"fixture-test-material" * 2)
    identities: set[str] = set()
    try:
        for harness, field in (("claude-code", "tool_use_id"), ("codex", "tool_call_id")):
            for kind in ("load", "policy", "recovery"):
                for event in ("PreToolUse", "PostToolUse"):
                    attempt = f"mixed-{kind}-0"
                    request = fixture_request(harness, event, attempt=attempt)
                    identity = request[field]
                    assert isinstance(identity, str) and identity not in identities
                    identities.add(identity)
                    assert request_attempt(request) == attempt
                    assert {k: v for k, v in request.items() if k not in {field, "native_slo_attempt"}} == payload(
                        event
                    )
                    assert derive_proven_request_correlation(harness=harness, event=event, payload=request, key=key)
                    assert writer.submit_command_activity(
                        harness=harness,
                        event=event,
                        payload=request,
                        succeeded=True,
                        policy_action="allow" if event == "PreToolUse" else None,
                    )
        assert writer.stop(timeout_seconds=5)
        stats = writer.stats()
        assert stats["accepted"] == stats["processed"] == len(identities) == 12
        assert stats["dropped"] == stats["failures"] == 0
    finally:
        writer.stop(timeout_seconds=2)


@pytest.mark.parametrize("attempt", ("mixed-load-1", "mixed-policy-0"))
def test_diagnostic_labels_do_not_satisfy_native_correlation_admission(tmp_path: Path, attempt: str) -> None:
    writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path))
    try:
        assert not writer.submit_command_activity(
            harness="claude-code",
            event="PreToolUse",
            payload={**payload("PreToolUse"), "tool_use_id": attempt},
            succeeded=True,
            policy_action="allow",
        )
        assert writer.stop(timeout_seconds=3)
        stats = writer.stats()
        assert stats["dropped"] == 1
        assert stats["accepted"] == stats["processed"] == stats["failures"] == 0
    finally:
        writer.stop(timeout_seconds=2)


@pytest.mark.parametrize("harness,field", (("claude-code", "tool_use_id"), ("codex", "tool_call_id")))
def test_receipt_join_keeps_diagnostic_label_without_retaining_opaque_native_id(
    tmp_path: Path, harness: str, field: str
) -> None:
    store = GuardStore(tmp_path)
    writer = RuntimeHookEvidenceWriter(store=store)
    request = fixture_request(harness, "PostToolUse", attempt="mixed-load-0")
    receipt = _receipt(harness=harness)
    edge = {"receipt": receipt}
    forwarded = []

    def review(**kwargs: object) -> object:
        forwarded.append(kwargs["payload"])
        return edge

    worker = SimpleNamespace(_review_raw_hook_native=review)
    session = SimpleNamespace(
        store=store,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=writer)),
    )
    witness = ReceiptWitness(session, maximum=1).__enter__()
    try:
        assert worker._review_raw_hook_native(payload=request) is edge
        assert forwarded == [request] and forwarded[0] is request
        assert writer.submit_native_decision_receipt(receipt)
        assert writer.submit_command_activity(harness=harness, event="PostToolUse", payload=request, succeeded=True)
        assert writer.stop(timeout_seconds=3)
        witness.reconcile(verify_all=True)
        row = witness.row("mixed-load-0")
        assert row is not None and row["committed"] and row["commit_binding_valid"]
        assert witness.report()["writer_admitted"] == 1
        assert writer.stats()["dropped"] == 0
        assert request[field] not in json.dumps(witness.page(0, 128))
    finally:
        writer.stop(timeout_seconds=2)
        witness.close()


def test_repeated_attempt_labels_receive_independent_opaque_native_ids() -> None:
    first = fixture_request("claude-code", "PreToolUse", attempt="mixed-policy-0")
    second = fixture_request("claude-code", "PreToolUse", attempt="mixed-policy-0")
    assert first["tool_use_id"] != second["tool_use_id"]
    assert request_attempt(first) == request_attempt(second) == "mixed-policy-0"


@pytest.mark.parametrize("invalid", (None, 1, "private-path", "mixed-load-1000000", "mixed-policy-0\n"))
def test_invalid_diagnostic_attempt_cannot_be_replaced_by_native_id(invalid: object) -> None:
    assert request_attempt({"native_slo_attempt": invalid, "tool_use_id": "mixed-load-0"}) is None
    assert request_attempt({"tool_use_id": "mixed-load-0"}) is None


@pytest.mark.parametrize("value", (None, [], {}, {"tool_use_id": "mixed-load-0"}, {"tool_call_id": "mixed-load-0"}))
def test_diagnostic_attempt_requires_its_explicit_field(value: object) -> None:
    assert request_attempt(value) is None


@pytest.mark.parametrize("harness,attempt", (("unknown", "mixed-load-0"), ("codex", "outside-fixture")))
def test_fixture_request_rejects_undeclared_scope(harness: str, attempt: str) -> None:
    with pytest.raises(ValueError, match="declared scope"):
        fixture_request(harness, "PreToolUse", attempt=attempt)
