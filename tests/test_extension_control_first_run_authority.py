"""Only empty authority may enter the ordinary first-run policy path."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import (
    ExtensionControlEnrollment,
    consume_extension_control_enrollment_proof,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)
from codex_plugin_scanner.guard.runtime.sensitive_read_controls import sensitive_read_control_is_terminal
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_managed_source_support import managed_store
from tests.test_guard_extension_control_authority import MemorySecretStore, _commit, _enrollment_proof, _store
from tests.test_native_sensitive_read_sources import produce_sensitive_read

_HISTORY = (
    "extension_control_authority_transition",
    "extension_control_authority_proof",
    "extension_control_catalog_manifest",
    "extension_control_authority_recovery_archive",
)
_MANAGED = ("managed_controls_active", "managed_controls_revision", "managed_controls_last_good")


@pytest.fixture(autouse=True)
def _local_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _read_terminal(store: GuardStore) -> tuple[AuthorityHealth, bool]:
    view = store.read_extension_control_authority_for_registry(REGISTRY)
    workspace = store.guard_home / "workspace"
    workspace.mkdir(exist_ok=True)
    source: dict[str, object] = {
        "harness": "codex",
        "source": {"home_dir": str(workspace), "cwd": str(workspace), "guard_home": str(store.guard_home)},
        "payload": {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(workspace / ".npmrc")},
        },
    }
    with use_extension_control_snapshot(ExtensionControlRuntimeSnapshot.from_authority_view(view)):
        artifact = produce_sensitive_read(source)
    return view.health, sensitive_read_control_is_terminal(artifact.metadata)


def _delete_snapshot(store: GuardStore) -> None:
    with store._connect() as connection:
        connection.execute("delete from extension_control_authority_snapshot")


def test_passive_first_run_does_not_create_extension_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    unrelated_secrets = MemorySecretStore()
    store._policy_integrity_secret_store = unrelated_secrets
    key, key_id = store._policy_integrity_secret_material(create=True)
    assert key is not None and key_id is not None
    assert unrelated_secrets.values
    assert store._key_ref() not in unrelated_secrets.values
    secrets = MemorySecretStore()
    store._extension_control_authority_secret_store = secrets
    for _ in range(2):
        assert _read_terminal(store) == (AuthorityHealth.UNENROLLED, False)
        assert secrets.values == {}
    with store._connect() as connection:
        assert connection.execute("select count(*) from extension_control_schema_migration").fetchone()[0] == 1


@pytest.mark.parametrize(
    "parts", [("snapshot",), ("anchor",), ("snapshot", "anchor"), ("snapshot", "key"), ("snapshot", "anchor", "key")]
)
def test_lost_enrollment_never_becomes_first_run(tmp_path: Path, parts: tuple[str, ...]) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    assert _read_terminal(store) == (AuthorityHealth.PROTECTED, False)
    if "snapshot" in parts:
        _delete_snapshot(store)
    for part in ("key", "anchor"):
        if part in parts:
            secrets.delete_secret(getattr(store, "_" + part + "_ref")())
    assert _read_terminal(store) == (AuthorityHealth.TAMPERED, True)


@pytest.mark.parametrize("history", _HISTORY)
def test_each_persisted_authority_history_disqualifies_first_run(tmp_path: Path, history: str) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _commit(store)
    store.read_extension_control_authority_for_registry(REGISTRY)
    if history == "extension_control_authority_recovery_archive":
        with store._connect() as connection:
            connection.execute("update extension_control_authority_snapshot set snapshot_mac = 'invalid'")
        store.recover_extension_control_authority(catalog_digest=REGISTRY.catalog_digest)
    with store._connect() as connection:
        assert connection.execute("select count(*) from " + history).fetchone()[0] > 0
        connection.execute("delete from extension_control_authority_snapshot")
        for other in _HISTORY:
            if other != history:
                connection.execute("delete from " + other)
    secrets.values.clear()
    assert _read_terminal(store) == (AuthorityHealth.TAMPERED, True)


@pytest.mark.parametrize("retained", _MANAGED)
def test_managed_residue_disqualifies_first_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retained: str) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=True, lockdown=True)
    if retained != "managed_controls_active":
        store.clear_policy_bundle_authority("2026-09-19T00:00:00Z", policy_bundle_last_error={})
        # Withdrawal with its protected snapshot is still ordinary supported authority.
        view = store.read_extension_control_authority_for_registry(REGISTRY)
        assert view.health is AuthorityHealth.PROTECTED
        assert view.managed_revision > 0
    with store._connect() as connection:
        assert connection.execute("select 1 from sync_state where state_key = ?", (retained,)).fetchone() is not None
        connection.execute("delete from extension_control_authority_snapshot")
        for table in _HISTORY:
            connection.execute("delete from " + table)
        for state in _MANAGED:
            if state != retained:
                connection.execute("delete from sync_state where state_key = ?", (state,))
    store._secret_store().delete_secret(store._key_ref())
    store._secret_store().delete_secret(store._anchor_ref())
    assert _read_terminal(store) == (AuthorityHealth.TAMPERED, True)


@pytest.mark.parametrize("after_write", [False, True])
def test_interrupted_first_enrollment_requires_recovery_only_after_key_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets, enroll=False)
    proof = _enrollment_proof(store)
    original_set = secrets.set_secret

    def interrupted_set(secret_id: str, value: str) -> None:
        if secret_id == store._key_ref():
            if after_write:
                original_set(secret_id, value)
            raise RuntimeError("controlled first-enrollment interruption")
        original_set(secret_id, value)

    with monkeypatch.context() as interruption:
        interruption.setattr(secrets, "set_secret", interrupted_set)
        with pytest.raises(RuntimeError, match="controlled first-enrollment interruption"):
            store.enroll_extension_control_authority(
                catalog_digest=REGISTRY.catalog_digest, actor_id="local-admin", nonce="enrollment-nonce", proof=proof
            )
    assert _read_terminal(store) == (
        (AuthorityHealth.TAMPERED, True) if after_write else (AuthorityHealth.UNENROLLED, False)
    )
    if after_write:
        recovered = store.recover_extension_control_authority(catalog_digest=REGISTRY.catalog_digest)
        assert recovered.health is AuthorityHealth.PROTECTED
        assert _read_terminal(store) == (AuthorityHealth.PROTECTED, False)


def test_residual_authority_cannot_consume_another_first_enrollment_proof(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority_for_registry(REGISTRY)
    _delete_snapshot(store)
    secrets.delete_secret(store._anchor_ref())
    proof = _enrollment_proof(store, nonce="another-enrollment")
    before = dict(secrets.values)
    with pytest.raises(ExtensionControlAuthorityError, match="already enrolled"):
        store.enroll_extension_control_authority(
            catalog_digest=REGISTRY.catalog_digest, actor_id="local-admin", nonce="another-enrollment", proof=proof
        )
    assert secrets.values == before
    # The refused enrollment leaves no new snapshot; only trusted recovery may replace it.
    with store._connect() as connection:
        assert connection.execute("select count(*) from extension_control_authority_snapshot").fetchone()[0] == 0
    enrollment = ExtensionControlEnrollment(
        catalog_digest=REGISTRY.catalog_digest, actor_id="local-admin", nonce="another-enrollment"
    )
    consume_extension_control_enrollment_proof(store.guard_home, proof, enrollment)
    with pytest.raises(ApprovalGateError):
        consume_extension_control_enrollment_proof(store.guard_home, proof, enrollment)


@pytest.mark.parametrize("raw_anchor", ["", "unverifiable-anchor"])
def test_unverified_anchor_presence_never_grants_first_run(tmp_path: Path, raw_anchor: str) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets, enroll=False)
    secrets.set_secret(store._anchor_ref(), raw_anchor)
    assert _read_terminal(store) == (AuthorityHealth.TAMPERED, True)
    assert secrets.values == {store._anchor_ref(): raw_anchor}


def test_unavailable_secret_source_is_not_first_run(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets, enroll=False)
    secrets.available = False
    assert _read_terminal(store) == (AuthorityHealth.DEGRADED_UNACKNOWLEDGED, True)
