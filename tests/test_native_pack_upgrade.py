"""Isolated installed-package bridge and legacy-to-native startup migration."""

from __future__ import annotations

import hashlib
import json
import subprocess

import pytest

from codex_plugin_scanner.guard.catalog_delivery import (
    installed_bundle,
    lifecycle,
    lifecycle_store,
    preparation_authority,
)
from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import MANIFEST, descriptor
from codex_plugin_scanner.guard.extension_builder import native_source_compiler as transport
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from tests.extension_builder_support import use_installed_native_source_compiler
from tests.guard_extension_control_authority_fixtures import MemorySecretStore, _commit, _store
from tests.guard_extension_control_authority_fixtures import (
    _allow_local_terminal_confirmation as _allow_local_terminal_confirmation,
)
from tests.native_activation_support import BINARY, native, seed
from tests.test_installed_command_pack_bundle import root
from tests.test_native_command_control_binding_publisher import (
    _pinned_integrity_material_and_resident_key as _pinned_integrity_material_and_resident_key,
)


@pytest.fixture
def release(tmp_path, monkeypatch):
    """Real factory, executable verification and production subprocess bridge."""
    package = tmp_path / "package"
    native_dir = package / "_native"
    native_dir.mkdir(parents=True)
    raw = BINARY.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    engine = json.loads(subprocess.check_output([str(BINARY), "compiler-info"]))["implementation_digest"]
    executable = native_dir / "hol-guard-runtime"
    executable.write_bytes(raw)
    executable.chmod(0o700)
    bundle = package / "guard/contracts/data/extensions/command-pack-bundle"
    bundle.mkdir(parents=True)
    use_installed_native_source_compiler(monkeypatch, native_dir)
    monkeypatch.setattr(installed_bundle, "_package", lambda: package)
    original_version = transport.metadata.version
    current = {"version": "3.50.0a1"}
    monkeypatch.setattr(
        transport.metadata,
        "version",
        lambda name: current["version"] if name == "hol-guard" else original_version(name),
    )

    def install(version="3.50.0a1", source="a" * 40):
        current["version"] = version
        data = root()
        data["source_sha"] = source
        data["policy"]["transport"]["location"]["tag"] = f"extension-data-{source}-0.0-000000"
        data["engine"] = data["policy"]["root"]["engine"] = engine
        data = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        (bundle / MANIFEST).write_bytes(data)
        common = dict(
            protocol_version=1,
            package_version=version,
            source_sha=source,
            target="test",
            platform_tag="test",
            command_pack_bundle=descriptor(data, source_sha=source, engine=engine),
        )
        runtime = dict(common, schema="hol-guard-native-runtime.v1", runtime_size=len(raw), runtime_sha256=digest)
        compiler = dict(
            common,
            schema="hol-guard-native-source-compiler.v2",
            compiler_size=len(raw),
            compiler_sha256=digest,
            executable="hol-guard-runtime",
            implementation_digest=engine,
            base_program_digest=transport._packaged_program_digest(),
        )
        for name, value in [("runtime-manifest.json", runtime), ("source-compiler-manifest.json", compiler)]:
            (native_dir / name).write_text(json.dumps(value))
        return installed_bundle.load_installed_bundle()

    authority = install()
    monkeypatch.setattr(
        preparation_authority, "load_installed_bundle", lambda: installed_bundle.load_installed_bundle()
    )
    return authority, install


def legacy_store(tmp_path, monkeypatch, *, revisions=1):
    # The frozen released v4 schema implementation creates the disk fixture.
    from pathlib import Path

    from codex_plugin_scanner.guard import store_extension_control_authority_commit as commits

    namespace = {"__package__": "codex_plugin_scanner.guard"}
    frozen = Path(__file__).parent / "fixtures/extension-control-schema-v5.py.txt"
    exec(compile(frozen.read_text(), str(frozen), "exec"), namespace)
    with monkeypatch.context() as legacy:
        legacy.setattr(preparation_authority, "load_installed_bundle", lambda: None)
        legacy.setattr(
            commits, "ensure_extension_control_authority_schema", namespace["ensure_extension_control_authority_schema"]
        )
        store = _store(tmp_path, MemorySecretStore())
        # Each control commit is one authority revision, so a caller that needs
        # the migration to walk a chain asks for more than the first one.
        for revision in range(revisions):
            _commit(store, revision=revision, key=f"change-{revision + 1}")
    # Pin disposable protected IO while retaining the real control key/anchor.
    seed(store)
    store._policy_integrity_secret_store.values.clear()
    return store


def database(store):
    with store._connect() as connection:
        return tuple(connection.iterdump())


def test_legacy_fixture_startup_migrates_once_without_touching_controls_or_allows(tmp_path, monkeypatch, release):
    store = legacy_store(tmp_path, monkeypatch)
    from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, require_approval_decision
    from codex_plugin_scanner.guard.models import PolicyDecision
    from tests.guard_extension_control_authority_fixtures import _PASSWORD
    from tests.managed_controls_activation_support import activate_managed_bundle, managed_bundle

    assert activate_managed_bundle(store, managed_bundle())
    grant = require_approval_decision(
        store.guard_home, action="allow", scope="artifact", approval_gate_input=ApprovalGateInput(password=_PASSWORD)
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id="fixture:exact-command",
            artifact_hash="a" * 64,
        ),
        "2026-10-18T12:00:00Z",
        approval_gate_grant=grant,
    )
    assert store.list_policy_decisions()
    before = database(store)
    authority_secrets = dict(store._secret_store().values)
    store.migrate_installed_command_pack_authority()
    record, floor = lifecycle_store.inspect(store)
    assert floor["installed"]["version"] == "3.50.0a1"
    assert database(store) == before
    assert store._secret_store().values == authority_secrets
    store.migrate_installed_command_pack_authority()
    assert lifecycle_store.inspect(store)[0] == record
    assert database(store) == before


@pytest.mark.parametrize("loss", ["missing", "corrupt", "rollback-db", "lost-db"])
def test_migrated_floor_loss_never_reenrolls_from_legacy_rows(tmp_path, monkeypatch, release, loss):
    import sqlite3

    store = legacy_store(tmp_path, monkeypatch)
    with sqlite3.connect(tmp_path / "legacy-backup.db") as backup, store._connect() as connection:
        connection.backup(backup)
    store.migrate_installed_command_pack_authority()
    reference = store._build_scoped_secret_ref(lifecycle_store.PREFIX)
    backend = store._policy_integrity_secret_store
    if loss == "corrupt":
        backend.set_secret(reference, "corrupt")
    else:
        backend.delete_secret(reference)
    if loss in {"rollback-db", "lost-db"}:
        with store._connect() as connection:
            tables = [
                row[0]
                for row in connection.execute(
                    "select name from sqlite_master where type='table' and name like 'extension_control_authority_%'"
                )
            ]
            for table in tables:
                connection.execute(f'delete from "{table}"')
        if loss == "rollback-db":
            with sqlite3.connect(tmp_path / "legacy-backup.db") as backup, store._connect() as connection:
                backup.backup(connection)
    with pytest.raises(ValueError, match="pack_lifecycle"):
        store.migrate_installed_command_pack_authority()
    assert backend.get_secret(reference) in {None, "corrupt"}


def test_fresh_install_and_retained_floor_after_sqlite_loss(tmp_path, monkeypatch, release):
    with monkeypatch.context() as fresh:
        fresh.setattr(preparation_authority, "load_installed_bundle", lambda: None)
        store = _store(tmp_path, MemorySecretStore(), enroll=False)
    seed(store)
    store._policy_integrity_secret_store.values.clear()
    store.migrate_installed_command_pack_authority()
    # An install with no legacy controls still gets a floor, derived from the
    # verified installed release. Without one every later pack-lifecycle read
    # fails and nothing else ever creates it.
    enrolled = lifecycle_store.read(store)
    assert enrolled is not None
    from tests.guard_extension_control_authority_fixtures import _enroll

    # Enrolling the authority afterwards must not be refused by the floor that
    # startup already wrote, and must leave that floor exactly as it is.
    _enroll(store)
    retained = lifecycle_store.inspect(store)[0]
    assert retained == enrolled
    with store._connect() as connection:
        connection.execute("delete from extension_control_authority_snapshot")
    store.migrate_installed_command_pack_authority()
    assert lifecycle_store.inspect(store)[0] == retained


@pytest.mark.parametrize("tamper", ["anchor-mac", "snapshot-mac", "anchor-missing", "snapshot-missing"])
def test_legacy_database_rows_cannot_authorize_migration_without_exact_protected_anchor(
    tmp_path, monkeypatch, release, tamper
):
    store = legacy_store(tmp_path, monkeypatch)
    backend = store._secret_store()
    if tamper == "anchor-missing":
        backend.delete_secret(store._anchor_ref())
    elif tamper == "anchor-mac":
        value = json.loads(backend.get_secret(store._anchor_ref()))
        value["mac"] = "0" * 64
        backend.set_secret(store._anchor_ref(), json.dumps(value))
    else:
        with store._connect() as connection:
            if tamper == "snapshot-missing":
                connection.execute("delete from extension_control_authority_snapshot")
            else:
                connection.execute("update extension_control_authority_snapshot set snapshot_mac=?", ("0" * 64,))
    before = database(store)
    with pytest.raises(ValueError, match="pack_lifecycle"):
        store.migrate_installed_command_pack_authority()
    assert lifecycle_store.read(store) is None and lifecycle_store._stamp(store) is None
    assert database(store) == before


def test_packaged_alpha_offline_upgrade_keeps_remote_floor_and_rejects_replays(tmp_path, monkeypatch, release):
    authority, install = release
    store = legacy_store(tmp_path, monkeypatch)
    store.migrate_installed_command_pack_authority()
    before, floor = lifecycle_store.inspect(store)
    remote = {**floor["installed"], "profile": "remote", "version": "100.7"}
    record = native("transition", key=_key(store).hex(), floor=before, candidate=remote)["record"]
    with hold_command_control_authority_lock(store.guard_home):
        lifecycle_store.commit(store, before, record)
    for version, source in [("3.50.0b1", "a" * 40), ("3.50.0rc1", "b" * 40), ("3.50.0", "c" * 40)]:
        authority = install(version, source)
        identity = lifecycle.installed_identity(authority)
        before, _ = lifecycle_store.inspect(store)
        plan = lifecycle.invoke(
            "plan",
            key=_key(store).hex(),
            floor=before,
            installed=identity,
            selected=[],
            retained=[],
            active=None,
            active_engine=None,
            registry=[],
        )
        assert plan["profile"] == "installed" and "lineage_source" not in plan
        with hold_command_control_authority_lock(store.guard_home):
            lifecycle_store.commit(store, before, plan["admission_floor"])
        _, floor = lifecycle_store.inspect(store)
        assert floor["remote"] == remote and floor["source"] == "a" * 40
    for candidate in [{**identity, "version": "3.50.0a1"}, {**remote, "version": "100.6"}]:
        with pytest.raises(ValueError, match="version_rollback"):
            lifecycle.invoke("transition", key=_key(store).hex(), floor=plan["admission_floor"], candidate=candidate)


def test_history_past_the_request_bound_migrates_through_a_spilled_chain(tmp_path, monkeypatch, release):
    """One authority transition per policy save eventually outgrows a request.

    The native walk reads the chain in order, so the daemon hands it a file
    rather than inlining every predecessor. Forcing the threshold down proves
    the spilled transport carries a real chain end to end.
    """
    from pathlib import Path

    store = legacy_store(tmp_path, monkeypatch, revisions=4)
    with store._connect() as connection:
        # Three predecessors under the head: a real chain for the walk to read.
        assert len(lifecycle_store.legacy_evidence(store, connection)["legacy_history"]) == 3
    monkeypatch.setattr(lifecycle_store, "LEGACY_HISTORY_INLINE_BYTES", -1)
    requested: dict = {}
    invoke = lifecycle.invoke

    def record(kind, **fields):
        if kind == "migrate":
            requested.update(fields)
        return invoke(kind, **fields)

    monkeypatch.setattr(lifecycle, "invoke", record)
    store.migrate_installed_command_pack_authority()
    assert requested["legacy_history"] == []
    # The chain travelled beside the request, and nothing is left behind.
    assert not Path(requested["legacy_history_path"]).exists()
    assert lifecycle_store.read(store) is not None
