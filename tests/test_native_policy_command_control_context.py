"""V3 command authority preserves complete source verification and refusal."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, require_approval_decision
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_context import CapturedV3PublicationInputs
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_managed_source_support import PERMISSION, managed_store
from tests.native_policy_snapshot_test_fixtures import _status
from tests.test_canonical_policy_row_authority import _NOW
from tests.test_guard_extension_control_authority import _PASSWORD, MemorySecretStore, _commit, _store

_TIME = datetime.fromisoformat(_NOW.replace("Z", "+00:00")).timestamp()


@pytest.fixture(autouse=True)
def _local_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _publisher(store: GuardStore, *, features: tuple[str, ...] = ()) -> NativePolicySnapshotPublisher:
    status = _status()
    status.capabilities.features += features
    return NativePolicySnapshotPublisher(store=store, status_provider=lambda: status, wall_clock=lambda: _TIME)


def test_real_signed_controls_and_defaults_use_exact_bound_v3_without_scoped_support(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = managed_store(tmp_path, monkeypatch, scoped=False)
    publisher = _publisher(store)
    try:
        context = publisher._publication_context()
        assert context is not None and len(context) == 7
        captured, binding = context[5], context[6]
        assert isinstance(captured, CapturedV3PublicationInputs)
        assert captured.defaults is not None and captured.defaults["defaultAction"] == "warn"
        assert captured.source_identity is not None
        complete = read_native_policy_authority_inputs(store, now=_TIME)
        assert complete.authority.rows == () and complete.authority.command_expressions == ()
        assert complete.authority.managed is not None
        assert complete.authority.managed.controls[0].target_id == PERMISSION
        assert complete.authority.managed.controls[0].state == "disabled"
        assert captured.input_digest == complete.input_digest
        source = next(value for value in complete.sources if value["kind"] == "managed-controls")
        assert binding["effective_digest"] == source["effective_digest"]
        assert binding["revision"] == source["revision"] == 1
        assert binding["managed_revision"] == source["managed_revision"] == 1
        assert not publisher._scoped_publication_enabled
        layers = binding["layers"]
        assert isinstance(layers, list)
        assert [layer["kind"] for layer in layers] == ["local-admin", "signed-cloud"]
        assert layers[0]["controls"][0]["state"] == "enabled"
        assert layers[1]["controls"][0]["state"] == "disabled"
    finally:
        publisher.close()


@pytest.mark.parametrize("features", [(), tuple(SCOPED_PUBLISH_FEATURES)])
def test_a_stale_authenticated_command_binding_cannot_authorize_new_control_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, features: tuple[str, ...]
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    publisher = _publisher(store, features=features)
    try:
        previous = publisher._compiled_command_extensions()
        _commit(store)
        monkeypatch.setattr(publisher, "_compiled_command_extensions", lambda: previous)
        with pytest.raises(NativePolicySnapshotError, match="native_command_control_binding_changed"):
            publisher._publication_context()
        assert not publisher.is_ready()
    finally:
        publisher.close()


@pytest.mark.parametrize("targeted", [False, True])
def test_command_control_support_cannot_erase_signed_rule_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, targeted: bool
) -> None:
    store = managed_store(tmp_path, monkeypatch, targeted=targeted)
    publisher = _publisher(store)
    try:
        with pytest.raises(NativePolicySnapshotError, match="semantics_unsupported"):
            publisher._publication_context()
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_local_tamper_can_publish_only_an_exact_native_command_block(tmp_path: Path) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _commit(store)
    publisher = _publisher(store)
    try:
        publisher._compiled_command_extensions()
        with store._connect() as connection:
            connection.execute("update extension_control_authority_snapshot set snapshot_mac = 'invalid'")
        with pytest.raises(NativePolicySnapshotError, match="native_policy_authority_managed_unavailable"):
            read_native_policy_authority_inputs(store, now=_TIME)
        context = publisher._publication_context()
        assert context is not None and isinstance(context[5], CapturedV3PublicationInputs)
        assert context[6]["health"] == "tampered"
        assert context[6]["layers"] == []
        assert not publisher._scoped_publication_enabled
    finally:
        publisher.close()


@pytest.mark.parametrize("features", [(), tuple(SCOPED_PUBLISH_FEATURES)])
def test_a_command_block_cannot_hide_separate_local_scoped_authority(tmp_path: Path, features: tuple[str, ...]) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _commit(store)
    grant = require_approval_decision(
        store.guard_home,
        action="block",
        scope="global",
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        now=_NOW,
    )
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="global", action="block", source="local"),
        _NOW,
        approval_gate_grant=grant,
    )
    publisher = _publisher(store, features=features)
    try:
        publisher._compiled_command_extensions()
        with store._connect() as connection:
            connection.execute("update extension_control_authority_snapshot set snapshot_mac = 'invalid'")
        with pytest.raises(NativePolicySnapshotError, match="native_policy_authority_scoped_consumer_required"):
            publisher._publication_context()
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_broken_managed_source_cannot_be_acknowledged_as_a_local_command_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = managed_store(tmp_path, monkeypatch, scoped=False)
    publisher = _publisher(store)
    try:
        publisher._compiled_command_extensions()
        with store._connect() as connection:
            connection.execute("update extension_control_authority_snapshot set snapshot_mac = 'invalid'")
        with pytest.raises(NativePolicySnapshotError):
            publisher._publication_context()
        assert not publisher.is_ready()
    finally:
        publisher.close()
