"""Real native source/factor checks at interrupted installation boundaries."""

import pytest

from codex_plugin_scanner.guard import native_business_source_retention as retention
from codex_plugin_scanner.guard import native_business_source_store as owner
from codex_plugin_scanner.guard.native_business_source_recovery import recover_committed_business_source
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_business_document_compile import document
from tests.test_native_business_source_store import _grant, _install, _key


@pytest.mark.parametrize("replacement", [False, True])
@pytest.mark.parametrize("boundary", ["before-close", "before-retention", "before-source", "rollback"])
def test_fresh_exact_approval_resumes_each_precommit_boundary(
    tmp_path, native_mcp_probe, monkeypatch, replacement, boundary
):
    store = GuardStore(tmp_path / "interrupted-home")
    native_mcp_probe(store.guard_home)
    if replacement:
        _install(store, document(1), _grant(store, document(1)))
    candidate = document(2)
    grant = _grant(store, candidate, initialize=not replacement)
    write = owner._write_private
    retain = owner.write_retained_business_source_anchor

    def interrupted_write(current_store, name, *args):
        if (boundary == "before-close" and name == owner.ANCHOR_FILE_NAME) or (
            boundary == "before-source" and name == owner.SOURCE_FILE_NAME
        ):
            raise NativePolicySnapshotError("synthetic_interruption")
        return write(current_store, name, *args)

    def interrupted_retention(*args):
        if boundary == "before-retention":
            raise NativePolicySnapshotError("synthetic_interruption")
        return retain(*args)

    with monkeypatch.context() as patch:
        patch.setattr(owner, "_write_private", interrupted_write)
        patch.setattr(owner, "write_retained_business_source_anchor", interrupted_retention)
        with pytest.raises(NativePolicySnapshotError):
            _install(store, candidate, grant, commit=boundary != "rollback")
    with pytest.raises(NativePolicySnapshotError):
        _install(store, document(3), _grant(store, document(3), initialize=False))
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_recovery_identity_mismatch"):
        recover_committed_business_source(
            store, document(3), approval_gate_grant=_grant(store, document(3), initialize=False)
        )
    recovered = recover_committed_business_source(
        store, candidate, approval_gate_grant=_grant(store, candidate, initialize=False)
    )
    assert owner.read_installed_business_source(store, _key(store)) == recovered
    assert recovered.mutation_revision == (2 if replacement else 1)


class Copy:
    def __init__(self, value):
        self.value = value
        self.fail = False

    def get_secret(self, reference):
        return self.value

    def set_secret(self, reference, value):
        if self.fail:
            raise OSError("synthetic_copy_failure")
        self.value = value


def test_prepared_only_state_without_key_cannot_be_treated_as_legacy(tmp_path, monkeypatch):
    import time

    from codex_plugin_scanner.guard.business_policy_document_import import refuse_legacy_import_over_business_source

    store = GuardStore(tmp_path / "missing-prepared-key-home")
    owner._write_private(
        store,
        owner.PREPARED_SOURCE_FILE_NAME,
        b"synthetic-prepared-record",
        owner.MAX_RECORD_BYTES,
        time.monotonic() + 5,
    )
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda **kwargs: None)
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_installation_key_unavailable"):
        refuse_legacy_import_over_business_source(store)


def test_recovery_final_approval_failure_keeps_committed_sql_closed(tmp_path, native_mcp_probe, monkeypatch):
    store = GuardStore(tmp_path / "final-approval-home")
    native_mcp_probe(store.guard_home)
    candidate = document()
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_transaction_not_committed"):
        _install(store, candidate, _grant(store, candidate), commit=False)
    grant = _grant(store, candidate, initialize=False)
    require = owner._require_approved
    checks = []

    def refuse_final(*args):
        checks.append(1)
        if len(checks) == 4:
            raise NativePolicySnapshotError("synthetic_final_approval_expired")
        return require(*args)

    with monkeypatch.context() as patch:
        patch.setattr(owner, "_require_approved", refuse_final)
        with pytest.raises(NativePolicySnapshotError, match="synthetic_final_approval_expired"):
            recover_committed_business_source(store, candidate, approval_gate_grant=grant)
    assert owner._database_witness(store) is not None
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_installation_incoherent"):
        owner.read_installed_business_source(store, _key(store))
    recovered = recover_committed_business_source(
        store, candidate, approval_gate_grant=_grant(store, candidate, initialize=False)
    )
    assert owner.read_installed_business_source(store, _key(store)) == recovered


@pytest.mark.parametrize("loss", ["all-anchors", "one-copy", "older-anchors"])
def test_existing_sql_floor_prevents_recovery_of_older_prepared_source(tmp_path, native_mcp_probe, monkeypatch, loss):
    import time

    store = GuardStore(tmp_path / "newer-sql-home")
    native_mcp_probe(store.guard_home)
    old = _install(store, document(1), _grant(store, document(1)))
    old_marker = retention.read_retained_business_source_anchor(store)
    _install(store, document(2), _grant(store, document(2), initialize=False))
    copies = (Copy(old_marker.decode()), Copy(old_marker.decode()))
    monkeypatch.setattr(retention, "_copies", lambda current_store: copies)
    owner._write_private(
        store, owner.PREPARED_SOURCE_FILE_NAME, old.source.record_bytes, owner.MAX_RECORD_BYTES, time.monotonic() + 5
    )
    state = store.guard_home / "native-runtime"
    if loss == "all-anchors":
        (state / owner.ANCHOR_FILE_NAME).unlink()
        copies[0].value = copies[1].value = None
    elif loss == "one-copy":
        copies[1].value = None
    else:
        owner._write_private(store, owner.ANCHOR_FILE_NAME, old_marker, owner.MAX_ANCHOR_BYTES, time.monotonic() + 5)
    witness = owner._database_witness(store)
    values = tuple(copy.value for copy in copies)
    with pytest.raises(NativePolicySnapshotError):
        recover_committed_business_source(
            store, document(1), approval_gate_grant=_grant(store, document(1), initialize=False)
        )
    assert owner._database_witness(store) == witness
    assert tuple(copy.value for copy in copies) == values


def test_split_retained_write_is_repaired_only_with_fresh_exact_approval(tmp_path, native_mcp_probe, monkeypatch):
    store = GuardStore(tmp_path / "split-home")
    native_mcp_probe(store.guard_home)
    _install(store, document(1), _grant(store, document(1)))
    old = retention.read_retained_business_source_anchor(store).decode()
    copies = (Copy(old), Copy(old))
    monkeypatch.setattr(retention, "_copies", lambda current_store: copies)
    candidate = document(2)
    grant = _grant(store, candidate, initialize=False)
    copies[1].fail = True
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_retention_unavailable"):
        _install(store, candidate, grant)
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_retention_conflict"):
        owner.read_installed_business_source(store, _key(store))
    copies[1].fail = False
    with pytest.raises(NativePolicySnapshotError, match="native_business_source_approval_required"):
        recover_committed_business_source(store, candidate, approval_gate_grant=None)
    recovered = recover_committed_business_source(
        store, candidate, approval_gate_grant=_grant(store, candidate, initialize=False)
    )
    assert copies[0].value == copies[1].value
    assert owner.read_installed_business_source(store, _key(store)) == recovered


@pytest.mark.parametrize("bad_copy", ["newer", "malformed", "unavailable"])
def test_recovery_never_overwrites_newer_invalid_or_unavailable_retention(
    tmp_path, native_mcp_probe, monkeypatch, bad_copy
):
    from codex_plugin_scanner.guard.native_business_document_compile import compile_business_policy_document
    from codex_plugin_scanner.guard.native_business_source_anchor_bridge import build_business_source_anchor
    from codex_plugin_scanner.guard.native_business_source_bridge import build_business_source_record

    store = GuardStore(tmp_path / "refused-repair-home")
    native_mcp_probe(store.guard_home)
    _install(store, document(1), _grant(store, document(1)))
    old = retention.read_retained_business_source_anchor(store).decode()
    copies = (Copy(old), Copy(old))
    monkeypatch.setattr(retention, "_copies", lambda current_store: copies)
    candidate = document(2)
    copies[1].fail = True
    with pytest.raises(NativePolicySnapshotError):
        _install(store, candidate, _grant(store, candidate, initialize=False))
    copies[1].fail = False
    if bad_copy == "newer":
        newer = build_business_source_record(compile_business_policy_document(document(3)), _key(store), 3)
        copies[0].value = build_business_source_anchor(newer, _key(store), "committed").anchor_bytes.decode()
    elif bad_copy == "malformed":
        copies[0].value = "private-malformed-copy-marker"
    else:

        def unavailable(reference):
            raise OSError("private-unavailable-copy-marker")

        monkeypatch.setattr(copies[0], "get_secret", unavailable)
    state = store.guard_home / "native-runtime"
    before = (state / owner.ANCHOR_FILE_NAME).read_bytes()
    values = tuple(copy.value for copy in copies)
    with pytest.raises(NativePolicySnapshotError):
        recover_committed_business_source(
            store, candidate, approval_gate_grant=_grant(store, candidate, initialize=False)
        )
    assert (state / owner.ANCHOR_FILE_NAME).read_bytes() == before
    assert tuple(copy.value for copy in copies) == values
