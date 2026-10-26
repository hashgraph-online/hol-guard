"""Recovery denial metadata commits with the source witness, never grants authority."""

import pytest

from codex_plugin_scanner.guard import native_business_source_store as owner
from codex_plugin_scanner.guard.mcp.policy_recovery_state import request_recovery_recorded, stage_request_recovery
from codex_plugin_scanner.guard.native_business_source_recovery import recover_committed_business_source
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from tests.guard_mcp_policy_test_support import env_flags as env_flags
from tests.guard_mcp_policy_test_support import store as store
from tests.test_business_policy_document_import import _stage
from tests.test_native_business_document_compile import document
from tests.test_native_business_source_store import _grant, _install, _key


@pytest.mark.parametrize("failure", ["sql", "final-approval"])
def test_recovery_marker_is_atomic_and_closed_installation_can_retry(
    store, env_flags, native_mcp_probe, monkeypatch, failure
):
    native_mcp_probe(store.guard_home)
    candidate = document()
    request_id = _stage(store, candidate, monkeypatch)["requestId"]
    with pytest.raises(NativePolicySnapshotError):
        _install(store, candidate, _grant(store, candidate), commit=False)
    prior = owner._database_witness(store)
    grant = _grant(store, candidate, initialize=False)
    require = owner._require_approved
    checks = []

    def record(connection, digest, now):
        stage_request_recovery(connection, request_id, digest, now)
        if failure == "sql":
            raise RuntimeError("synthetic_sql_failure")

    def require_until_final(*args):
        checks.append(1)
        if failure == "final-approval" and len(checks) == 4:
            raise NativePolicySnapshotError("synthetic_final_approval_expired")
        return require(*args)

    with monkeypatch.context() as patch:
        patch.setattr(owner, "_require_approved", require_until_final)
        with pytest.raises((RuntimeError, NativePolicySnapshotError), match="synthetic_"):
            recover_committed_business_source(
                store, candidate, approval_gate_grant=grant, stage_request_recovery=record
            )
    assert request_recovery_recorded(store, request_id) is (failure == "final-approval")
    if failure == "sql":
        assert owner._database_witness(store) == prior
    else:
        assert owner._database_witness(store) is not None
    with pytest.raises(NativePolicySnapshotError):
        owner.read_installed_business_source(store, _key(store))
    source = recover_committed_business_source(
        store,
        candidate,
        approval_gate_grant=_grant(store, candidate, initialize=False),
        stage_request_recovery=lambda connection, digest, now: stage_request_recovery(
            connection, request_id, digest, now
        ),
    )
    assert request_recovery_recorded(store, request_id) is True
    assert owner.read_installed_business_source(store, _key(store)) == source
