"""Production timer/factory/native readiness with isolated synthetic transport IO."""

from __future__ import annotations

import copy
import json
import threading
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_catalog_read
from codex_plugin_scanner.guard.catalog_delivery import (
    activation_store,
    activation_transition,
    active_security,
    current_refresh,
    discovery,
    lifecycle_store,
    preparation,
    preparation_authority,
)
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from tests.current_publication_support import ADDED, setup


@pytest.fixture
def publication(tmp_path, monkeypatch, native_hook_force):
    for field, value in dict(
        _home=None, _worker=None, _handle=None, _retry_after=0.0, _refresh_worker=None, _refresh_after=0.0
    ).items():
        monkeypatch.setattr(discovery, field, value)
    monkeypatch.setattr(discovery, "_cached", None)
    state = setup(tmp_path, monkeypatch)
    real_current = current_refresh.refresh

    def capture(store):
        try:
            return real_current(store)
        except Exception as error:
            state.last_error = repr(error)
            raise

    monkeypatch.setattr(current_refresh, "refresh", capture)
    real_refresh = discovery._refresh
    monkeypatch.setattr(discovery, "_refresh", lambda home, store: real_refresh(home, store or state.store))
    monkeypatch.setattr(preparation_authority, "load_installed_bundle", lambda: state.installed)
    yield state
    for field in ("_worker", "_refresh_worker"):
        worker = getattr(discovery, field)
        if worker is not None:
            worker.join(60)
            assert not worker.is_alive()
    close_native_residents(guard_home=state.home)


def workers():
    for field in ("_worker", "_refresh_worker"):
        worker = getattr(discovery, field)
        if worker is not None:
            worker.join(60)
            assert not worker.is_alive()


def periodic(state):
    from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer

    class Stop:
        calls = 0

        def wait(self, seconds):
            self.calls += 1
            return self.calls > 1

    server = SimpleNamespace(
        store=state.store,
        refresh_extension_control_runtime=lambda: None,
        extension_control_api=SimpleNamespace(expire_prepared_cache_leases=lambda: None),
    )
    daemon = SimpleNamespace(_shutdown_started=Stop(), _server=server, _extension_control_refresh_interval_seconds=0.1)
    discovery._refresh_after = 0
    GuardDaemonServer._refresh_extension_control_loop(daemon)
    workers()


def read(state, query=""):
    result = native_catalog_read.native_catalog_read(
        guard_home=state.home,
        route="index",
        query=query,
        if_none_match=None,
        expected_catalog_digest="b" * 64,
        timeout_seconds=60,
    )
    assert result.status == 200, result
    return json.loads(result.body)


def commit_initial(state):
    store = state.store
    prepared = preparation.prepare(
        state.installed, [], activation_store.prepare_directory_for_store(store), engine=state.engine
    )
    draft = activation_transition.stage(None, prepared, verifier_key=_key(store), store=store)
    with store._extension_control_authority_lock(), store._connect() as connection:
        activation_store.write_in_transaction(store, connection, draft, verifier_key=_key(store), recorded_at="fixture")
    return activation_store.read(store)


def test_periodic_publisher_advances_complete_readiness_and_enable_without_package_update(publication):
    state = publication
    # Initial installed metadata is immediately independent of publisher outage.
    state.offline = True
    with pytest.raises(ValueError, match="preparing"):
        discovery.installed_discovery(state.home)
    workers()
    initial = discovery.installed_discovery(state.home)
    assert initial.authority == state.installed.digest
    assert read(state)["total_count"] == state.initial_count
    active = commit_initial(state)
    before = (
        active.record_digest,
        active.metadata.program_digest,
        active.metadata.catalog_digest,
        active.metadata.trust_digest,
        lifecycle_store.read(state.store),
        active_security.scope_identity(state.store),
    )
    state.offline = False
    periodic(state)
    current = discovery.installed_discovery(state.home)
    assert current.authority != initial.authority, getattr(state, "last_error", None)
    assert any("/compare/" in url for url in state.calls)
    assert read(state)["total_count"] == state.initial_count + 1
    result = read(state, "q=AgenticJobs&limit=1")
    assert result["total_count"] == 1 and result["items"][0]["extension_id"] == ADDED
    assert result["items"][0]["catalog_defaults"]["enabled"] is False
    # Cloud consumers use this same fixed complete-view accessor; no separate
    # caller-supplied Root/preparation command can select a partial collection.
    assert discovery.require_handle(discovery.installed_discovery(state.home), state.home) is current
    active = activation_store.read(state.store)
    assert (
        active.record_digest,
        active.metadata.program_digest,
        active.metadata.catalog_digest,
        active.metadata.trust_digest,
        lifecycle_store.read(state.store),
        active_security.scope_identity(state.store),
    ) == before
    # Existing automatic enable preparation retries unavailable installed data
    # with the authenticated current publisher, then stages native policy IR.
    from codex_plugin_scanner.guard.daemon import extension_control_prepared as candidates
    from codex_plugin_scanner.guard.runtime.extension_control_contract import (
        ControlLayerKind,
        ControlState,
        ControlTarget,
        ControlTargetKind,
        ExtensionControl,
        ExtensionControlLayer,
    )
    from codex_plugin_scanner.guard.runtime.extension_control_proof import ExtensionControlMutation
    from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog

    registry = GeneratedCommandCatalog.from_prepared_packs(active)
    layer = ExtensionControlLayer(
        schema_version="1.0.0",
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=registry.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(target=ControlTarget(ControlTargetKind.EXTENSION, ADDED), state=ControlState.ENABLED),
        ),
    )
    mutation = ExtensionControlMutation(
        previous_revision=0,
        catalog_digest=registry.catalog_digest,
        layers=(layer,),
        actor_id="fixture",
        idempotency_key="enable",
        nonce="enable",
    )
    staged = candidates.prepare_candidate(state.store, registry, mutation, (layer,))
    from codex_plugin_scanner.guard.catalog_delivery.activation_record import open_record

    opened = open_record(
        staged.draft.data,
        staged.draft.digest,
        staged.draft.mac,
        key=_key(state.store),
        directory=staged.draft.directory,
    )
    assert ADDED in opened.selected
    assert any("/pack-" in url for url in state.calls)
    state.offline = True
    with pytest.raises(preparation.UnavailablePackError, match="pack_policy_unavailable"):
        preparation.prepare(state.installed, [ADDED], state.home / "uncached", engine=state.engine)


def test_invalid_incomplete_outage_and_restart_retain_complete_view(publication, monkeypatch):
    state = publication
    periodic(state)
    previous = discovery.installed_discovery(state.home)
    assert read(state)["total_count"] == state.initial_count + 1
    valid = copy.deepcopy(state.root)
    state.corrupt = True
    periodic(state)
    assert discovery.installed_discovery(state.home) is previous
    state.corrupt = False
    for field, value in [("publication_id", "99.9"), ("engine", "f" * 64), ("expires_at", 1), ("authority_epoch", 0)]:
        state.root = {**valid, field: value}
        if field == "engine":
            state.root = copy.deepcopy(state.root)
            state.root["policy"]["root"]["engine"] = value
        periodic(state)
        assert discovery.installed_discovery(state.home) is previous
    # Same publication ID with different authenticated content is substitution.
    state.root = {**valid, "issued_at": valid["issued_at"] - 1}
    periodic(state)
    assert discovery.installed_discovery(state.home) is previous
    # Clear transfers and fail new metadata IO: accepted cursor advances, the
    # complete view does not. A later outage cannot select an older Root.
    state.root = {**valid, "publication_id": "100.2"}
    state.root = copy.deepcopy(state.root)
    state.root["policy"]["transport"]["sha256"] = "f" * 64
    state.root["policy"]["transport"]["location"]["member"] = "object-" + "f" * 64 + ".json"
    state.missing = True
    periodic(state)
    assert discovery.installed_discovery(state.home) is previous
    state.offline = True
    # Same resident restart path: no registered handles survive. The protected
    # cursor selects cached, factory-reverified authority without network.
    close_native_residents(guard_home=state.home)
    discovery._cached = None
    periodic(state)
    restored = discovery.installed_discovery(state.home)
    assert restored.authority == previous.authority
    assert read(state)["total_count"] == state.initial_count + 1
    cache = state.home / "command-packs/current-publication"
    assert len(list(cache.glob("*.root"))) == 2
    reference = state.store._build_scoped_secret_ref(current_refresh.PREFIX)
    state.store._policy_integrity_secret_store.delete_secret(reference)
    with pytest.raises(ValueError, match="protected_cursor_missing"):
        current_refresh.refresh(state.store)


def test_security_timer_does_not_wait_for_browsing_refresh(publication, monkeypatch):
    state = publication
    entered, release, observed = threading.Event(), threading.Event(), threading.Event()

    def slow(store):
        entered.set()
        assert release.wait(10)
        raise OSError("incomplete metadata")

    monkeypatch.setattr(current_refresh, "refresh", slow)
    monkeypatch.setattr(active_security, "observe", lambda store: observed.set())
    # Call the real timer but inspect before joining its metadata worker.
    thread = threading.Thread(target=periodic, args=(state,))
    thread.start()
    try:
        assert entered.wait(5) and observed.wait(5)
    finally:
        release.set()
        thread.join(15)
    assert not thread.is_alive()
