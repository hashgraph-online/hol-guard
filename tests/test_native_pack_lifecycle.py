"""Compiled native lifecycle policy and real protected-store adapter regressions."""

from __future__ import annotations

import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import lifecycle, lifecycle_store
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from tests.extension_builder_support import use_installed_native_source_compiler
from tests.native_activation_support import BINARY, native, seed
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.test_extension_pack_preparation import delivery as delivery

PRODUCTION_INVOKE = lifecycle.invoke


@pytest.fixture
def protected(tmp_path):
    store = SimpleNamespace(guard_home=tmp_path)
    seed(store)
    return store


def advance(store, candidate, ancestry=None):
    before, _ = lifecycle_store.inspect(store)
    return native("transition", key=_key(store).hex(), floor=before, candidate=candidate, ancestry=ancestry)["record"]


def test_remote_high_water_survives_installed_upgrade_and_cross_engine(protected):
    before, f = lifecycle_store.inspect(protected)
    remote = {**f["installed"], "profile": "remote", "version": "100.2", "root": "2" * 64}
    after = advance(protected, remote)
    with hold_command_control_authority_lock(protected.guard_home):
        lifecycle_store.commit(protected, before, after)
    before, f = lifecycle_store.inspect(protected)
    installed = {**f["installed"], "version": "3.16.4", "root": "3" * 64, "engine": "4" * 64}
    plan = native(
        "plan",
        key=_key(protected).hex(),
        floor=before,
        selected=[],
        retained=[],
        active=[],
        active_engine=f["installed"]["engine"],
        registry=[],
        installed=installed,
    )
    assert plan["profile"] == "installed"
    with hold_command_control_authority_lock(protected.guard_home):
        lifecycle_store.commit(protected, before, plan["admission_floor"])
    _, f = lifecycle_store.inspect(protected)
    assert f["remote"] == remote and f["installed"] == installed
    assert advance(protected, remote) == plan["admission_floor"]
    with pytest.raises(ValueError, match="version_rollback"):
        advance(protected, {**remote, "version": "99.9"})
    for field, value in [("root", "9" * 64), ("source", "b" * 40), ("engine", "9" * 64)]:
        with pytest.raises(ValueError, match="version_reused"):
            advance(protected, {**installed, field: value})


def test_source_rollback_rejected_and_exact_compare_identity_required(protected):
    before, floor = lifecycle_store.inspect(protected)
    candidate = {**floor["installed"], "profile": "remote", "version": "100.1", "source": "b" * 40, "root": "3" * 64}
    with pytest.raises(ValueError, match="ancestry_required"):
        advance(protected, candidate, [floor["source"], candidate["source"]])
    evidence = dict(
        status="ahead",
        base_commit={"sha": floor["source"]},
        merge_base_commit={"sha": floor["source"]},
        head_commit={"sha": candidate["source"]},
        ahead_by=1,
        behind_by=0,
    )
    after = advance(protected, candidate, evidence)
    with hold_command_control_authority_lock(protected.guard_home):
        lifecycle_store.commit(protected, before, after)
    with pytest.raises(ValueError, match="ancestry_required"):
        advance(protected, {**candidate, "version": "100.2", "source": floor["source"]}, evidence)


def test_older_known_installed_source_does_not_replace_remote_floor(protected):
    _, floor = lifecycle_store.inspect(protected)
    installed = floor["installed"]
    remote = {**installed, "profile": "remote", "version": "100.1", "source": "b" * 40, "root": "3" * 64}
    record = seed(protected, source=remote["source"], installed=installed, remote=remote)
    result = native(
        "plan",
        key=_key(protected).hex(),
        floor=record,
        selected=[],
        retained=[],
        active=[],
        active_engine=installed["engine"],
        registry=[],
        installed=installed,
    )
    assert result["profile"] == "committed-subset"
    assert native("read", key=_key(protected).hex(), floor=result["admission_floor"])["remote"] == remote


@pytest.mark.parametrize("loss", ["missing", "corrupt", "mac", "invalid-schema"])
def test_db_loss_never_recreates_or_lowers_protected_state(protected, loss):
    before, floor = lifecycle_store.inspect(protected)
    protected._connect = lambda: pytest.fail("lifecycle floors must not depend on SQLite")
    assert lifecycle_store.inspect(protected)[0] == before
    candidate = {**floor["installed"], "version": "3.16.1"}
    with pytest.raises(ValueError, match="version_rollback"):
        advance(protected, candidate)
    backend = protected._policy_integrity_secret_store
    reference = protected._build_scoped_secret_ref(lifecycle_store.PREFIX)
    if loss == "missing":
        backend.delete_secret(reference)
    elif loss == "corrupt":
        backend.set_secret(reference, "invalid")
    elif loss == "mac":
        backend.set_secret(reference, before.replace("3.16.2", "3.16.1"))
    else:
        backend.set_secret(reference, '{"floor":{"schema":"unsupported"},"mac":"00"}')
    with pytest.raises(ValueError, match="pack_lifecycle"):
        lifecycle_store.inspect(protected)
    assert backend.get_secret(reference) != before


def test_floor_race_and_readback_fail_without_lowering(protected, monkeypatch):
    before, f = lifecycle_store.inspect(protected)
    first = advance(protected, {**f["installed"], "version": "3.16.4"})
    second = advance(protected, {**f["installed"], "version": "3.16.5"})
    with hold_command_control_authority_lock(protected.guard_home):
        lifecycle_store.commit(protected, before, second)
        with pytest.raises(ValueError, match="floor_conflict"):
            lifecycle_store.commit(protected, before, first)
        monkeypatch.setattr(protected._policy_integrity_secret_store, "set_secret", lambda *args: None)
        with pytest.raises(ValueError, match="write_mismatch"):
            lifecycle_store.write(protected, first)
    assert lifecycle_store.inspect(protected)[0] == second


def test_arbitrary_installed_identity_cannot_enroll(protected):
    _, f = lifecycle_store.inspect(protected)
    with pytest.raises(ValueError, match="release_missing"):
        native("enroll", key=_key(protected).hex(), installed=f["installed"])


def test_native_feature_unavailable_is_explicit_without_policy_fallback(monkeypatch):
    from codex_plugin_scanner.guard.extension_builder import native_source_compiler as transport

    def unavailable(*args):
        raise transport.NativeSourceCompilerError("feature unavailable")

    monkeypatch.setattr(transport, "_verify_manifest", unavailable)
    with pytest.raises(ValueError, match="native_pack_lifecycle_unavailable"):
        PRODUCTION_INVOKE("selection", layers=[], owners={})


def test_profile_freshness_and_candidate_lifetime_are_native():
    assert native("admission", profile="remote", now=1500, issued_at=1000, expires_at=2000) == {
        "current": True,
        "lifetime": 300.0,
    }
    assert native("admission", profile="remote", now=1999, issued_at=1000, expires_at=2000)["lifetime"] == 1
    assert not native("admission", profile="remote", now=2000, issued_at=1000, expires_at=2000)["current"]
    assert native("admission", profile="committed-subset", now=10000, issued_at=1000, expires_at=2000)["current"]


def test_sqlite_loss_recovery_retains_native_publication_floor(delivery, tmp_path):
    import sqlite3

    from codex_plugin_scanner.guard.catalog_delivery import activation_store, activation_transition, preparation

    database = tmp_path / "activation.db"

    def connect():
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        return connection

    store = SimpleNamespace(guard_home=tmp_path, _connect=connect)
    seed(store)
    directory = activation_store.prepare_directory_for_store(store)

    def prepared():
        return preparation.prepare(delivery.verified(), [], directory, engine="1" * 64, now=1500, fetch=delivery.fetch)

    draft = activation_transition.stage(None, prepared(), verifier_key=_key(store), store=store, now=1500)
    with hold_command_control_authority_lock(tmp_path), connect() as connection:
        activation_store.write_in_transaction(
            store, connection, draft, verifier_key=_key(store), recorded_at="unit", now=1500
        )
    protected, floor = lifecycle_store.inspect(store)
    assert floor["remote"]["version"] == "12.1"
    database.unlink()  # Only this test's disposable SQLite file is removed.
    assert activation_store.read(store) is None
    assert lifecycle_store.inspect(store)[0] == protected
    delivery.value["publication_id"] = "11.9"
    with pytest.raises(ValueError, match="version_rollback"):
        activation_transition.stage(None, prepared(), verifier_key=_key(store), store=store, now=1500)
    delivery.value["publication_id"] = "12.1"
    recovered = activation_transition.stage(None, prepared(), verifier_key=_key(store), store=store, now=1500)
    with hold_command_control_authority_lock(tmp_path), connect() as connection:
        activation_store.write_in_transaction(
            store, connection, recovered, verifier_key=_key(store), recorded_at="recovered", now=1500
        )
    assert activation_store.read(store).record()["publication_id"] == "12.1"
    assert lifecycle_store.inspect(store)[0] == protected


def test_db_loss_and_missing_release_cannot_fall_back_to_legacy_controls(protected, monkeypatch):
    import sqlite3

    from codex_plugin_scanner.guard.daemon import extension_control_prepared as candidates

    protected._connect = lambda: sqlite3.connect(":memory:")
    monkeypatch.setattr(candidates, "load_installed_bundle", lambda: None)
    with pytest.raises(ValueError, match="pack_authority_unavailable"):
        candidates.prepare_candidate(protected, None, None, ())


def test_production_packaged_bridge_and_native_release_binding(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.catalog_delivery import installed_bundle
    from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import MANIFEST, descriptor
    from codex_plugin_scanner.guard.extension_builder import native_source_compiler as transport
    from tests.test_installed_command_pack_bundle import root

    raw = BINARY.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    info = json.loads(subprocess.check_output([str(BINARY), "compiler-info"]))
    engine = info["implementation_digest"]
    data = root()
    data["engine"] = data["policy"]["root"]["engine"] = engine
    data = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    native_dir = tmp_path / "_native"
    native_dir.mkdir()
    (native_dir / "hol-guard-runtime").write_bytes(raw)
    (native_dir / "hol-guard-runtime").chmod(0o700)
    bundle_dir = tmp_path / "guard/contracts/data/extensions/command-pack-bundle"
    bundle_dir.mkdir(parents=True)
    (bundle_dir / MANIFEST).write_bytes(data)
    common = dict(
        protocol_version=1,
        package_version=transport.metadata.version("hol-guard"),
        source_sha="a" * 40,
        target="test",
        platform_tag="test",
        command_pack_bundle=descriptor(data, source_sha="a" * 40, engine=engine),
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
    use_installed_native_source_compiler(monkeypatch, native_dir)
    monkeypatch.setattr(installed_bundle, "_package", lambda: tmp_path)
    monkeypatch.setattr(lifecycle, "invoke", PRODUCTION_INVOKE)
    authority = installed_bundle.load_installed_bundle()
    identity = lifecycle.installed_identity(authority)
    assert identity["engine"] == engine and identity["version"] == common["package_version"]
    store = SimpleNamespace(guard_home=tmp_path)
    seed(store)
    store._policy_integrity_secret_store.values.clear()
    with hold_command_control_authority_lock(tmp_path):
        lifecycle_store.enroll_installed(store, authority)
        with pytest.raises(ValueError, match="already_enrolled"):
            lifecycle_store.enroll_installed(store, authority)
    assert lifecycle_store.inspect(store)[1]["installed"] == identity
    evidence = lifecycle.release_evidence(authority)
    evidence["compiler_manifest"]["implementation_digest"] = "9" * 64
    with pytest.raises(ValueError, match="binding_invalid"):
        PRODUCTION_INVOKE("installed", **evidence)
