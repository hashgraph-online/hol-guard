"""Real native approval and authenticated interrupted-installation recovery."""

import io
import json
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_business_source_store as owner
from codex_plugin_scanner.guard.native_business_source_recovery import recover_committed_business_source
from codex_plugin_scanner.guard.native_business_source_retention import write_retained_business_source_anchor
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_business_document_compile import document
from tests.test_native_business_source_store import _grant, _install, _key


def _interrupt(store, candidate, grant, monkeypatch):
    require = owner._require_approved
    checks = []

    def refuse_final(*args):
        checks.append(1)
        if len(checks) == 4:
            raise NativePolicySnapshotError("synthetic_interruption")
        return require(*args)

    with monkeypatch.context() as patch:
        patch.setattr(owner, "_require_approved", refuse_final)
        with pytest.raises(NativePolicySnapshotError, match="synthetic_interruption"):
            _install(store, candidate, grant)


@pytest.mark.parametrize("retained_committed", [False, True])
def test_recovery_finishes_only_exact_committed_source(tmp_path, native_mcp_probe, monkeypatch, retained_committed):
    store = GuardStore(tmp_path / "recovery-home")
    native_mcp_probe(store.guard_home)
    candidate = document()
    _interrupt(store, candidate, _grant(store, candidate), monkeypatch)
    if retained_committed:
        from codex_plugin_scanner.guard.native_business_source_anchor_bridge import build_business_source_anchor
        from codex_plugin_scanner.guard.native_business_source_bridge import verify_business_source_record

        record = (store.guard_home / "native-runtime" / owner.SOURCE_FILE_NAME).read_bytes()
        source = verify_business_source_record(record, _key(store))
        committed = build_business_source_anchor(source, _key(store), "committed")
        write_retained_business_source_anchor(store, committed.anchor_bytes)
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_approval_required"):
        recover_committed_business_source(store, candidate, approval_gate_grant=None)
    changed = document(2)
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_recovery_identity_mismatch"):
        recover_committed_business_source(store, changed, approval_gate_grant=_grant(store, changed, initialize=False))
    recovered = recover_committed_business_source(
        store, candidate, approval_gate_grant=_grant(store, candidate, initialize=False)
    )
    assert owner.read_installed_business_source(store, _key(store)) == recovered


def test_fresh_approval_recovery_finishes_rolled_back_prepared_transaction(tmp_path, native_mcp_probe):
    store = GuardStore(tmp_path / "rollback-home")
    native_mcp_probe(store.guard_home)
    candidate = document()
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_transaction_not_committed"):
        _install(store, candidate, _grant(store, candidate), commit=False)
    recovered = recover_committed_business_source(
        store, candidate, approval_gate_grant=_grant(store, candidate, initialize=False)
    )
    assert owner.read_installed_business_source(store, _key(store)) == recovered


def test_cli_exposes_freshly_approved_recovery(tmp_path, native_mcp_probe, monkeypatch):
    from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput
    from codex_plugin_scanner.guard.cli import commands_dispatch_policy_document as command
    from codex_plugin_scanner.guard.policy_document_io import write_private_policy_text

    store = GuardStore(tmp_path / "cli-recovery-home")
    native_mcp_probe(store.guard_home)
    candidate = document()
    _interrupt(store, candidate, _grant(store, candidate), monkeypatch)
    path = tmp_path / "exact-source.yaml"
    write_private_policy_text(path, json.dumps(candidate.to_mapping()))
    monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
    monkeypatch.setattr(
        command,
        "prompt_for_approval_gate",
        lambda *args, **kwargs: ApprovalGateInput(
            password="synthetic-source-installation-password", use_cooldown=False
        ),
    )
    output = io.StringIO()
    assert (
        command._run_guard_policy_document_command(
            SimpleNamespace(policy_command="recover-business-source", file=str(path), json=True),
            store=store,
            output_stream=output,
        )
        == 0
    ), output.getvalue()
    source = owner.read_installed_business_source(store, _key(store))
    assert json.loads(output.getvalue())["digest"] == source.source_digest
    assert "synthetic-source-installation-password" not in output.getvalue()
