"""Policy ACK ordering and explicit installed-baseline compatibility checks."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import config, native_policy_snapshot_acked
from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal
from codex_plugin_scanner.guard.store import GuardStore
from scripts import native_slo_mixed_server
from scripts.native_slo_mixed_receipt_reader import InstalledReceiptReader
from scripts.native_slo_mixed_server import MixedScenarioFixture
from scripts.native_slo_mixed_witness import ReceiptWitness
from tests.test_native_decision_receipt import _receipt


def test_legacy_readback_requires_the_explicit_pinned_baseline_profile(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    receipt = _receipt(request_id="legacy")
    store.record_native_decision_receipt(receipt)

    # This owner models the older installed API and schema without importing
    # current store migrations on each connection.
    class LegacyOwner:
        @contextmanager
        def _connect(self):
            with sqlite3.connect(store.path) as connection:
                connection.row_factory = sqlite3.Row
                yield connection

    legacy = LegacyOwner()
    with pytest.raises(RuntimeError, match="binding-aware"):
        InstalledReceiptReader(legacy)
    with pytest.raises(RuntimeError, match="pinned legacy"):
        InstalledReceiptReader(legacy, profile="baseline_2e672d2")
    with legacy._connect() as connection:
        connection.execute("alter table native_hook_decision_receipts drop column command_extensions_json")
    reader = InstalledReceiptReader(legacy, profile="baseline_2e672d2")
    assert reader.read(receipt["decision_id"]) == receipt
    with legacy._connect() as connection:
        connection.execute("update native_hook_decision_receipts set policy_generation = 999")
    assert reader.read(receipt["decision_id"]) is None


def test_candidate_invalid_receipt_or_getter_failure_never_uses_legacy(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    receipt = _receipt()
    store.record_native_decision_receipt(receipt)

    def failed(_identity: str) -> None:
        raise OSError("readback unavailable")

    reader = InstalledReceiptReader(SimpleNamespace(get_native_decision_receipt=failed))
    with pytest.raises(OSError):
        reader.read(receipt["decision_id"])
    reader = InstalledReceiptReader(SimpleNamespace(get_native_decision_receipt=lambda _identity: None))
    assert reader.read(receipt["decision_id"]) is None


def test_legacy_journal_without_directory_helper_reports_unavailable_not_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path)

    class LegacyOwner:
        @contextmanager
        def _connect(self):
            with sqlite3.connect(store.path) as connection:
                connection.row_factory = sqlite3.Row
                yield connection

    legacy = LegacyOwner()
    with legacy._connect() as connection:
        connection.execute("alter table native_hook_decision_receipts drop column command_extensions_json")
    worker = SimpleNamespace(_review_raw_hook_native=lambda **_kwargs: None)
    writer = SimpleNamespace(submit_native_decision_receipt=lambda *_args, **_kwargs: True)
    session = SimpleNamespace(
        store=legacy,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=writer)),
    )
    monkeypatch.delattr(journal, "fsync_directory")
    witness = ReceiptWitness(session, maximum=1, receipt_profile="baseline_2e672d2").__enter__()
    try:
        result = witness.report()
        assert result["journal_instrumentation_installed"] is True
        assert result["journal_io"]["journal_directory_sync_attempts"] is None
        assert result["sqlite_fsync_calls"] is None
        assert result["full_persistence_metric_coverage"] is False
    finally:
        witness.close()


def _fixture(tmp_path: Path) -> tuple[MixedScenarioFixture, dict[str, object]]:
    store = GuardStore(tmp_path)
    binding = {"generation": 2, "policy_digest": "b" * 64, "runtime_identity": "c" * 64}
    snapshot = {
        **binding,
        "mode": "enforce",
        "effective_policy": {"default_action": "block", "subprocess_action": "block"},
    }
    publisher = SimpleNamespace(current_snapshot=lambda: snapshot, current_snapshot_binding=lambda: binding)
    worker = SimpleNamespace(
        policy_snapshot_publisher=publisher, prepare_workspace_policy=lambda *_args, **_kwargs: binding
    )
    session = SimpleNamespace(
        store=store,
        guard_home=tmp_path,
        workspace=tmp_path,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)),
    )
    fixture = MixedScenarioFixture(session)
    fixture.witness = ReceiptWitness(session, maximum=4)
    return fixture, binding


def test_ack_requires_disk_mac_verified_binding_generation_and_effective_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture, binding = _fixture(tmp_path)
    monkeypatch.setattr(native_policy_snapshot_acked, "acked_snapshot_binding_for_store", lambda _store: binding)
    assert fixture._ack("block", previous_generation=1) == binding
    monkeypatch.setattr(native_slo_mixed_server, "MAX_READINESS_P95_MS", 1)
    with pytest.raises(RuntimeError, match="acknowledgment"):
        fixture._ack("block", previous_generation=2)
    with pytest.raises(RuntimeError, match="acknowledgment"):
        fixture._ack("allow", previous_generation=1)
    monkeypatch.setattr(
        native_policy_snapshot_acked,
        "acked_snapshot_binding_for_store",
        lambda _store: {**binding, "policy_digest": "e" * 64},
    )
    with pytest.raises(RuntimeError, match="acknowledgment"):
        fixture._ack("block", previous_generation=1)


def test_failed_ack_retains_successful_public_mutation_without_approval_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture, _binding = _fixture(tmp_path)
    calls: list[object] = []

    def update(home: Path, value: object, **kwargs: object) -> None:
        calls.append((home, value, kwargs))

    def ack(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("not acknowledged")

    monkeypatch.setattr(config, "update_guard_settings", update)
    monkeypatch.setattr(fixture, "_ack", ack)
    result = fixture.dispatch("mixed_policy", {"action": "block", "index": 0})
    assert calls == [(tmp_path, {"default_action": "block", "subprocess_action": "block"}, {})]
    assert result["status"] == "failed"
    assert result["mutation_returned"] is True
    assert result["acknowledged"] is False
    assert "first_enforcing_receipt" not in result
