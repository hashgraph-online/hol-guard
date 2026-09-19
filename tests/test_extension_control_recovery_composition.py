"""Recovery succeeds only after the complete authority is authenticated."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.cli import extension_controls_commands as cli
from codex_plugin_scanner.guard.daemon import extension_control_api as api_module
from codex_plugin_scanner.guard.daemon.client import GuardDaemonRequestError, GuardSurfaceDaemonClient
from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
from codex_plugin_scanner.guard.daemon.extension_control_errors import ExtensionControlApiError
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore
from tests.native_managed_source_support import managed_store
from tests.test_guard_extension_control_authority import _PASSWORD, _enroll


def _local_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GuardStore:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    store._extension_control_authority_secret_store = EncryptedFileSecretStore(store.guard_home)
    update_settings(
        store.guard_home,
        {"enabled": True, "new_password": _PASSWORD, "confirm_password": _PASSWORD, "cooldown_seconds": 0},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    _enroll(store)
    assert store.read_extension_control_authority_for_registry(REGISTRY).health is AuthorityHealth.PROTECTED
    return store


def _key_recovery_before(store: GuardStore) -> dict[str, object]:
    key = store._authority_key(required=True)
    assert isinstance(key, bytes)
    with store._connect() as connection:
        snapshot = connection.execute("select * from extension_control_authority_snapshot").fetchone()
        assert snapshot is not None
        transitions = connection.execute(
            "select * from extension_control_authority_transition order by revision"
        ).fetchall()
        proofs = connection.execute(
            "select * from extension_control_authority_proof order by transition_revision, proof_id_hash"
        ).fetchall()
    return {
        "key_digest": hashlib.sha256(key).hexdigest(),
        "snapshot": dict(snapshot),
        "transitions": [dict(row) for row in transitions],
        "proofs": [dict(row) for row in proofs],
    }


def _observe_real_key_recovery(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch, *, via_cli: bool = False
) -> list[str]:
    module = cli if via_cli else api_module
    consume = module.consume_extension_control_grant
    recover = store.recover_extension_control_authority
    events: list[str] = []

    def consume_then_record(*args, **kwargs):
        consume(*args, **kwargs)
        events.append("consumed")

    def recover_after_consumption(*args, **kwargs):
        assert events == ["consumed"], "Recovery requires a consumed real approval grant."
        result = recover(*args, **kwargs)
        events.append("recovered")
        return result

    monkeypatch.setattr(module, "consume_extension_control_grant", consume_then_record)
    monkeypatch.setattr(store, "recover_extension_control_authority", recover_after_consumption)
    return events


def _assert_complete_key_recovery(
    store: GuardStore, before: dict[str, object], events: list[str], *, verify_key_change: bool = True
) -> None:
    assert events == ["consumed", "recovered"]
    current = store.read_extension_control_authority_for_registry(REGISTRY)
    assert current.health is AuthorityHealth.PROTECTED
    assert current.revision == 0 and current.managed_revision == 0 and current.layers == ()
    if verify_key_change:
        key = store._authority_key(required=True)
        assert isinstance(key, bytes)
        assert hashlib.sha256(key).hexdigest() != before["key_digest"]
    with store._connect() as connection:
        archives = connection.execute("select * from extension_control_authority_recovery_archive").fetchall()
    assert len(archives) == 1
    archive = archives[0]
    assert archive["reason"] == "authentication-key-missing"
    assert json.loads(archive["snapshot_row_json"]) == before["snapshot"]
    assert json.loads(archive["transition_rows_json"]) == before["transitions"]
    assert json.loads(archive["proof_rows_json"]) == before["proofs"]


def _damage(store: GuardStore, kind: str) -> None:
    if kind == "key":
        store._secret_store().delete_secret(store._key_ref())
    elif kind == "local":
        with store._connect() as connection:
            connection.execute("update extension_control_authority_snapshot set snapshot_mac = 'invalid'")
    elif kind == "catalog":
        with store._connect() as connection:
            connection.execute("update extension_control_catalog_manifest set record_mac = 'invalid'")
    else:
        raise AssertionError(kind)


def _service(store: GuardStore) -> tuple[ExtensionControlApiService, ExtensionControlRuntime]:
    runtime = ExtensionControlRuntime(store.read_extension_control_authority_for_registry(REGISTRY))
    return ExtensionControlApiService(store=store, registry=REGISTRY, runtime=runtime), runtime


def test_api_never_installs_local_success_over_invalid_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _local_store(tmp_path, monkeypatch)
    _damage(store, "catalog")
    service, runtime = _service(store)
    assert runtime.current().health is AuthorityHealth.TAMPERED

    with pytest.raises(ExtensionControlApiError) as denied:
        service.recover_authority({"approval_password": _PASSWORD, "session_nonce": "synthetic-recovery"})

    assert denied.value.status == 503
    assert denied.value.code == "authority_recovery_incomplete"
    assert store.read_extension_control_authority_for_registry(REGISTRY).health is AuthorityHealth.TAMPERED
    assert runtime.current().health is AuthorityHealth.TAMPERED
    assert service.effective()["health"] == AuthorityHealth.TAMPERED.value


def test_api_missing_key_recovery_requires_approval_and_rebuilds_authenticated_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _local_store(tmp_path, monkeypatch)
    key_before = _key_recovery_before(store)
    key_events = _observe_real_key_recovery(store, monkeypatch)
    old_key = store._secret_store().get_secret(store._key_ref())
    assert old_key is not None
    _damage(store, "key")
    service, runtime = _service(store)
    assert runtime.current().health is AuthorityHealth.TAMPERED
    with pytest.raises(ExtensionControlApiError) as denied:
        service.recover_authority({"session_nonce": "synthetic-unapproved"})
    assert denied.value.status == 403
    assert store._secret_store().get_secret(store._key_ref()) is None
    assert runtime.current().health is AuthorityHealth.TAMPERED

    # Explicit approved key recovery retires records authenticated by the lost
    # key and rebuilds the trusted built-in catalog under the new key epoch.
    response = service.recover_authority({"approval_password": _PASSWORD, "session_nonce": "synthetic-recovery"})
    new_key = store._secret_store().get_secret(store._key_ref())
    assert new_key is not None and new_key != old_key
    assert response["health"] == AuthorityHealth.PROTECTED.value
    assert runtime.current().health is AuthorityHealth.PROTECTED
    assert store.read_extension_control_authority_for_registry(REGISTRY).health is AuthorityHealth.PROTECTED
    _assert_complete_key_recovery(store, key_before, key_events, verify_key_change=False)
    store._secret_store().set_secret(store._key_ref(), old_key)
    assert store.read_extension_control_authority_for_registry(REGISTRY).health in {
        AuthorityHealth.TAMPERED,
        AuthorityHealth.DEGRADED_UNACKNOWLEDGED,
    }


@pytest.mark.parametrize("lockdown", [False, True])
def test_api_recovery_keeps_real_signed_managed_restrictions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lockdown: bool
) -> None:
    # This existing signed-admission fixture uses its explicit in-memory secret store.
    store = managed_store(tmp_path, monkeypatch, cloud=True, lockdown=lockdown)
    before = store.read_extension_control_authority_for_registry(REGISTRY)
    managed = tuple(layer for layer in before.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
    assert before.health is AuthorityHealth.PROTECTED
    assert before.managed_revision > 0 and managed
    _damage(store, "local")
    service, runtime = _service(store)
    assert runtime.current().health is AuthorityHealth.TAMPERED

    response = service.recover_authority({"approval_password": _PASSWORD, "session_nonce": "synthetic-recovery"})

    composed = store.read_extension_control_authority_for_registry(REGISTRY)
    assert response["health"] == AuthorityHealth.PROTECTED.value
    assert composed.health is AuthorityHealth.PROTECTED
    assert composed.managed_revision == before.managed_revision
    assert tuple(layer for layer in composed.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD) == managed
    assert runtime.current().managed_revision == composed.managed_revision
    assert runtime.current().layers == composed.layers
    assert response["global_lockdown"] is lockdown


def test_api_local_recovery_still_requires_real_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _local_store(tmp_path, monkeypatch)
    _damage(store, "local")
    service, runtime = _service(store)
    with pytest.raises(ExtensionControlApiError) as denied:
        service.recover_authority({"session_nonce": "synthetic-recovery"})
    assert denied.value.status == 403
    assert denied.value.code == "approval_gate_required"
    assert runtime.current().health is AuthorityHealth.TAMPERED
    assert store.read_extension_control_authority_for_registry(REGISTRY).health is AuthorityHealth.TAMPERED

    response = service.recover_authority({"approval_password": _PASSWORD, "session_nonce": "synthetic-approved"})
    assert response["health"] == AuthorityHealth.PROTECTED.value
    assert runtime.current().layers == store.read_extension_control_authority_for_registry(REGISTRY).layers


@pytest.mark.parametrize("damage", ["key", "catalog", "local"])
def test_cli_success_follows_complete_persisted_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], damage: str
) -> None:
    store = _local_store(tmp_path, monkeypatch)
    key_before = _key_recovery_before(store) if damage == "key" else None
    key_events = _observe_real_key_recovery(store, monkeypatch, via_cli=True) if damage == "key" else []
    _damage(store, damage)
    monkeypatch.setattr(cli, "GuardStore", lambda _guard_home: store)
    monkeypatch.setattr(
        cli, "prompt_for_approval_gate", lambda *_args, **_kwargs: ApprovalGateInput(password=_PASSWORD)
    )

    def no_daemon(_guard_home: Path) -> None:
        raise GuardDaemonRequestError("Guard daemon is not running")

    monkeypatch.setattr(cli, "_client", no_daemon)
    output = io.StringIO()
    result = cli.run_extension_controls_command(
        argparse.Namespace(controls_command="recover-authority"),
        guard_home=store.guard_home,
        output_stream=output,
    )
    composed = store.read_extension_control_authority_for_registry(REGISTRY)
    if damage == "key":
        assert key_before is not None
        _assert_complete_key_recovery(store, key_before, key_events)
    if damage in {"local", "key"}:
        assert result == 0
        assert json.loads(output.getvalue())["health"] == composed.health.value == AuthorityHealth.PROTECTED.value
        assert capsys.readouterr().err == ""
    else:
        assert result == 4
        assert composed.health is AuthorityHealth.TAMPERED
        assert output.getvalue() == ""
        assert capsys.readouterr().err.strip() == "Error: Extension-control authority recovery is incomplete."


@pytest.mark.parametrize("damage", ["key", "local", "catalog"])
def test_authenticated_http_recovery_reports_complete_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    store = _local_store(tmp_path, monkeypatch)
    key_before = _key_recovery_before(store) if damage == "key" else None
    key_events = _observe_real_key_recovery(store, monkeypatch) if damage == "key" else []
    _damage(store, damage)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = load_guard_daemon_auth_token(store.guard_home)
        assert token is not None
        client = GuardSurfaceDaemonClient(f"http://127.0.0.1:{daemon.port}", token)
        payload: dict[str, object] = {"approval_password": _PASSWORD, "session_nonce": "synthetic-http-recovery"}
        if damage == "catalog":
            with pytest.raises(GuardDaemonRequestError) as denied:
                client.recover_extension_control_authority(payload)
            assert denied.value.status == 503
            assert denied.value.code == "authority_recovery_incomplete"
            assert client.effective_extension_controls()["health"] == AuthorityHealth.TAMPERED.value
        else:
            response = client.recover_extension_control_authority(payload)
            if damage == "key":
                assert key_before is not None
                _assert_complete_key_recovery(store, key_before, key_events)
            assert response["health"] == AuthorityHealth.PROTECTED.value
            assert client.effective_extension_controls()["health"] == AuthorityHealth.PROTECTED.value
    finally:
        daemon.stop()
