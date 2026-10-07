"""Actual Rust source codecs and approval gate, isolated local installation.

No actor/provider credentials, custody, external dispatch or business acceptance.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_business_source_store as owner
from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, require_high_risk, update_settings
from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.policy_document_authority import policy_import_approval_binding
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_business_document_compile import document


def _grant(store, candidate, *, initialize=True):
    password = "synthetic-source-installation-password"
    if initialize:
        update_settings(
            store.guard_home,
            {
                "enabled": True,
                "new_password": password,
                "confirm_password": password,
                "cooldown_seconds": 0,
            },
        )
    grant = require_high_risk(
        store.guard_home,
        purpose="policy_import",
        **policy_import_approval_binding(candidate, "replace"),
        approval_gate_input=ApprovalGateInput(password=password, use_cooldown=False),
    )
    assert grant is not None
    return grant


def _install(store, candidate, grant, *, commit=True):
    with (
        owner.approved_business_source_mutation(
            store, candidate, mode="replace", now=grant.issued_at, approval_gate_grant=grant
        ) as mutation,
        store._connect() as connection,
    ):
        connection.execute("begin immediate")
        mutation.stage_on_connection(connection, now=grant.issued_at)
        if commit:
            connection.commit()
        else:
            connection.rollback()
    return mutation


def _key(store):
    material = store._policy_integrity_secret_material(create=False)
    assert material[0] is not None
    return derive_native_policy_verifier_key(material[0])


def test_old_current_fence_consumer_cannot_receive_installation_key(tmp_path, native_mcp_probe, monkeypatch):
    from types import SimpleNamespace

    store = GuardStore(tmp_path / "old-fence-home")
    native_mcp_probe(store.guard_home)
    monkeypatch.setattr(
        owner,
        "_consumer",
        lambda *args, **kwargs: SimpleNamespace(
            capabilities=SimpleNamespace(features=("native-business-source-current-fence-v1",))
        ),
    )
    monkeypatch.setattr(
        store, "_policy_integrity_secret_material", lambda **kwargs: pytest.fail("key crossed old fence")
    )
    with (
        pytest.raises(NativePolicySnapshotError, match="native_business_source_current_fence_unavailable"),
        owner.approved_business_source_mutation(
            store,
            document(),
            mode="replace",
            now="2026-10-06T00:00:00Z",
            approval_gate_grant=None,
        ),
    ):
        pytest.fail("old fence admitted installation")
    assert not (store.guard_home / "native-runtime" / owner.ANCHOR_FILE_NAME).exists()


def test_exact_approved_source_database_and_retained_marker_agree(tmp_path: Path, native_mcp_probe):
    store = GuardStore(tmp_path / "source-home")
    native_mcp_probe(store.guard_home)
    candidate = document(0)
    grant = _grant(store, candidate)
    installed = _install(store, candidate, grant)
    observed = owner.read_installed_business_source(store, _key(store))
    assert observed == installed.source
    assert json.loads(observed.record_bytes)["source_document"] == candidate.to_mapping()
    next_candidate = document(1)
    newer = _install(store, next_candidate, _grant(store, next_candidate, initialize=False))
    assert newer.source.mutation_revision == 2
    assert owner.read_installed_business_source(store, _key(store)) == newer.source


def test_sql_rollback_leaves_closed_marker_and_no_source_admission(tmp_path: Path, native_mcp_probe):
    store = GuardStore(tmp_path / "rollback-home")
    native_mcp_probe(store.guard_home)
    candidate = document()
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_transaction_not_committed"):
        _install(store, candidate, _grant(store, candidate), commit=False)
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_installation_incoherent"):
        owner.read_installed_business_source(store, _key(store))
    marker = json.loads((store.guard_home / "native-runtime" / owner.ANCHOR_FILE_NAME).read_bytes())
    assert marker["phase"] == "closed"


@pytest.mark.parametrize("missing", [owner.SOURCE_FILE_NAME, owner.ANCHOR_FILE_NAME, "both-and-snapshot"])
def test_independent_retention_refuses_primary_source_state_loss(tmp_path: Path, native_mcp_probe, missing: str):
    store = GuardStore(tmp_path / "loss-home")
    native_mcp_probe(store.guard_home)
    candidate = document()
    _install(store, candidate, _grant(store, candidate))
    state = store.guard_home / "native-runtime"
    if missing == "both-and-snapshot":
        (state / owner.SOURCE_FILE_NAME).unlink()
        (state / owner.ANCHOR_FILE_NAME).unlink()
        with store._connect() as connection:
            connection.execute("delete from sync_state where state_key = ?", (owner.INSTALLATION_STATE_KEY,))
            connection.commit()
    else:
        (state / missing).unlink()
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_installation_incoherent"):
        owner.read_installed_business_source(store, _key(store))
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_installation_incoherent"):
        _install(store, document(2), _grant(store, document(2), initialize=False))


def test_native_floor_refuses_approved_document_revision_rollback(tmp_path: Path, native_mcp_probe):
    store = GuardStore(tmp_path / "floor-home")
    native_mcp_probe(store.guard_home)
    installed = _install(store, document(2), _grant(store, document(2)))
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_codec_refused"):
        _install(store, document(1), _grant(store, document(1), initialize=False))
    assert owner.read_installed_business_source(store, _key(store)) == installed.source


def test_expired_approval_cannot_open_committed_marker_after_sql_commit(tmp_path: Path, native_mcp_probe, monkeypatch):
    from codex_plugin_scanner.guard.approval_gate import ApprovalGateError

    store = GuardStore(tmp_path / "expiry-home")
    native_mcp_probe(store.guard_home)
    candidate = document()
    grant = _grant(store, candidate)
    require = owner._require_approved
    checks = []

    def expire_at_commit(current_store, binding, current_grant, now):
        checks.append(now)
        if len(checks) == 4:
            now = (datetime.fromisoformat(grant.issued_at.replace("Z", "+00:00")) + timedelta(seconds=31)).isoformat()
        return require(current_store, binding, current_grant, now)

    monkeypatch.setattr(owner, "_require_approved", expire_at_commit)
    with pytest.raises(ApprovalGateError):
        _install(store, candidate, grant)
    assert len(checks) == 4
    marker = json.loads((store.guard_home / "native-runtime" / owner.ANCHOR_FILE_NAME).read_bytes())
    assert marker["phase"] == "closed"
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_installation_incoherent"):
        owner.read_installed_business_source(store, _key(store))
    monkeypatch.setattr(owner, "_require_approved", require)
    from codex_plugin_scanner.guard.native_business_source_recovery import recover_committed_business_source

    recovered = recover_committed_business_source(
        store, candidate, approval_gate_grant=_grant(store, candidate, initialize=False)
    )
    assert owner.read_installed_business_source(store, _key(store)) == recovered
