"""The served catalog and the effective controls must name one catalog.

The dashboard reads the catalog from the control API and the effective controls
from the runtime snapshot, and refuses to render when the two name different
catalogs. Nothing the operator can do from the page resolves that, so the daemon
has to keep the two bindings together on its own.
"""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHttpServer
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntime,
    ExtensionControlRuntimeSnapshot,
)
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from codex_plugin_scanner.guard.store import GuardStore

_REVISION = 7


def _delivered_registry() -> GeneratedCommandCatalog:
    """A catalog distinct from the core registry, standing in for delivered packs."""

    registry = GeneratedCommandCatalog(tuple(BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[:4]))
    assert registry.catalog_digest != BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    return registry


def _protected(catalog_digest: str, *, revision: int = _REVISION) -> ExtensionControlAuthorityView:
    return ExtensionControlAuthorityView(
        health=AuthorityHealth.PROTECTED,
        revision=revision,
        catalog_digest=catalog_digest,
        layers=(),
    )


def test_refresh_rebinds_the_control_api_to_the_registry_the_authority_was_read_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pack activation found after startup must move both bindings together.

    Durable authority does not change when a pack activation lands, so the
    re-read comes back at the revision already installed. The daemon still has
    to install it, because it is the same authority projected onto another
    catalog, and then serve that catalog from the control API.
    """

    store = GuardStore(tmp_path / "guard-home")
    core = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    delivered = _delivered_registry()
    runtime = ExtensionControlRuntime(_protected(core.catalog_digest))
    api = ExtensionControlApiService(store=store, registry=core, runtime=runtime)
    server = cast(
        _GuardDaemonHttpServer,
        cast(
            object,
            SimpleNamespace(
                store=store,
                extension_control_runtime=runtime,
                extension_control_api=api,
                _installed_authority_pending=False,
                # Startup read the core registry through the ordinary path,
                # because the activation was not committed yet. That path never
                # sets the recovery flag.
                _extension_control_on_core_registry=False,
            ),
        ),
    )

    from codex_plugin_scanner.guard.catalog_delivery import projection

    monkeypatch.setattr(projection, "capture", lambda _store: (None, delivered, "delivered-digest"))
    monkeypatch.setattr(projection, "require_current", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        store,
        "read_extension_control_authority_for_registry",
        lambda registry, *, read_only=False, **_kwargs: _protected(registry.catalog_digest),
    )

    snapshot = _GuardDaemonHttpServer.refresh_extension_control_runtime(server)

    assert snapshot.catalog_digest == delivered.catalog_digest
    assert api.catalog_digest == delivered.catalog_digest
    assert api.catalog()["catalog_digest"] == delivered.catalog_digest
    assert api.effective()["catalog_digest"] == delivered.catalog_digest


def test_a_protected_revision_admits_the_same_revision_read_for_another_catalog() -> None:
    core = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    delivered = _delivered_registry()
    runtime = ExtensionControlRuntime(_protected(core.catalog_digest))
    other_catalog = _protected(delivered.catalog_digest)

    installed = runtime.refresh(other_catalog)

    assert installed.catalog_digest == delivered.catalog_digest
    assert (
        installed.effective_digest
        == ExtensionControlRuntimeSnapshot.from_authority_view(other_catalog).effective_digest
    )
    # The revision floor still rejects an authority that moves backwards.
    with pytest.raises(ValueError, match="cannot move backwards"):
        runtime.refresh(_protected(delivered.catalog_digest, revision=_REVISION - 1))


def test_the_refresh_route_recaptures_the_activation_rather_than_its_own_registry() -> None:
    """The dashboard's repair request must be able to move the catalog binding.

    The service's own refresh re-reads durable authority for the registry it is
    already bound to, so a page that posts here to resolve two disagreeing
    catalog digests has to reach the daemon-wide refresh instead.
    """

    from codex_plugin_scanner.guard.daemon.server_control_routes_post import _ControlPostRoutes

    calls: list[str] = []
    daemon = SimpleNamespace(
        refresh_extension_control_runtime=lambda: calls.append("daemon"),
        extension_control_api=SimpleNamespace(
            effective=lambda *, reread=True: {"health": "protected", "reread": reread},
            refresh=lambda: calls.append("service"),
        ),
    )
    written: list[dict[str, object]] = []
    handler = cast(
        _ControlPostRoutes,
        cast(
            object,
            SimpleNamespace(
                _daemon_server=lambda: daemon,
                _write_json=lambda payload, **_kwargs: written.append(payload),
            ),
        ),
    )

    _ControlPostRoutes._dispatch_control_post(
        handler,
        SimpleNamespace(path="/v1/extension-controls/refresh"),
        ["v1", "extension-controls", "refresh"],
        {},
        SimpleNamespace(route_class="extension_control"),
    )

    assert calls == ["daemon"]
    # The daemon refresh above already re-read durable authority under the
    # lease, so the payload must not take it a second time.
    assert written == [{"health": "protected", "reread": False}]


def test_the_refresh_route_still_answers_when_the_daemon_refresh_fails() -> None:
    """A repair that cannot run must not drop the request.

    This endpoint exists because the page has no other way forward, so a
    refresh that raises has to leave the page with the controls the runtime
    holds and a recorded reason, not a dropped connection it cannot retry
    against.
    """

    from codex_plugin_scanner.guard.daemon import background_diagnostics
    from codex_plugin_scanner.guard.daemon.server_control_routes_post import _ControlPostRoutes

    def unavailable() -> None:
        raise ValueError("native command control authority is unavailable")

    daemon = SimpleNamespace(
        refresh_extension_control_runtime=unavailable,
        extension_control_api=SimpleNamespace(effective=lambda *, reread=True: {"health": "protected"}),
    )
    written: list[dict[str, object]] = []
    handler = cast(
        _ControlPostRoutes,
        cast(
            object,
            SimpleNamespace(
                _daemon_server=lambda: daemon,
                _write_json=lambda payload, **_kwargs: written.append(payload),
            ),
        ),
    )
    recorded: list[tuple[str, str]] = []

    def sink(event: str, detail: str) -> None:
        recorded.append((event, detail))

    background_diagnostics.install_sink(sink)
    try:
        _ControlPostRoutes._dispatch_control_post(
            handler,
            SimpleNamespace(path="/v1/extension-controls/refresh"),
            ["v1", "extension-controls", "refresh"],
            {},
            SimpleNamespace(route_class="extension_control"),
        )
    finally:
        background_diagnostics.release_sink(sink)

    assert written == [{"health": "protected"}]
    assert recorded == [
        (
            "extension_control_refresh_failed",
            "error=ValueError detail=native command control authority is unavailable",
        )
    ]


def test_two_catalogs_at_one_revision_cannot_replace_each_other_by_alternating() -> None:
    """The replacement floor is per catalog, so alternating must not clear it.

    One floor digest for the whole runtime is cleared by every read for another
    catalog, and this daemon reads for another catalog whenever an activation
    lands. A replayed authority could then be installed at a revision already
    served simply by interleaving the two catalogs.
    """

    core = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    delivered = _delivered_registry()
    runtime = ExtensionControlRuntime(_protected(core.catalog_digest))
    runtime.refresh(_protected(delivered.catalog_digest))

    replayed = ExtensionControlAuthorityView(
        health=AuthorityHealth.PROTECTED,
        revision=_REVISION,
        catalog_digest=core.catalog_digest,
        layers=(
            ExtensionControlLayer(
                schema_version=CONTROL_SCHEMA_VERSION,
                kind=ControlLayerKind.LOCAL_ADMIN,
                catalog_digest=core.catalog_digest,
                global_lockdown=True,
                controls=(),
            ),
        ),
    )
    assert (
        ExtensionControlRuntimeSnapshot.from_authority_view(replayed).effective_digest
        != runtime.current().effective_digest
    )

    with pytest.raises(ValueError, match="cannot be replaced"):
        runtime.refresh(replayed)


def test_the_floor_map_is_bounded_and_still_refuses_an_older_revision() -> None:
    """A churn of activations must not grow the floor map without end."""

    from codex_plugin_scanner.guard.runtime import extension_control_runtime as module

    core = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    runtime = ExtensionControlRuntime(_protected(core.catalog_digest))
    for index in range(module._MAX_PROTECTED_FLOORS + 4):
        runtime.refresh(_protected(f"{index:064x}", revision=_REVISION + index))

    assert len(runtime._protected_floors) == module._MAX_PROTECTED_FLOORS
    # The evicted catalogs are still behind the revision floor, which is global.
    with pytest.raises(ValueError, match="cannot move backwards"):
        runtime.refresh(_protected(core.catalog_digest, revision=_REVISION))


def test_a_read_that_loses_the_race_serves_what_the_writer_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A polled read must not roll the runtime back under a concurrent apply.

    The live re-read runs without the apply lock, so an apply or a daemon
    refresh can install a newer snapshot while it is in flight. Installing the
    older view anyway would publish controls the daemon has already replaced,
    and the rebind that follows a refresh would then refuse to move the catalog
    binding because the snapshot it installed is no longer current.
    """

    store = GuardStore(tmp_path / "guard-home")
    core = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    runtime = ExtensionControlRuntime(_protected(core.catalog_digest))
    api = ExtensionControlApiService(store=store, registry=core, runtime=runtime)

    def read_then_lose_the_race(registry, *, read_only=False, **_kwargs):
        # Stands in for an apply committing while this read is in flight.
        runtime.refresh(_protected(registry.catalog_digest, revision=_REVISION + 2))
        return _protected(registry.catalog_digest, revision=_REVISION + 1)

    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", read_then_lose_the_race)

    assert api.effective()["revision"] == _REVISION + 2
    installed = runtime.current()
    assert installed.revision == _REVISION + 2
    # The snapshot the writer installed is still current, so its rebind holds.
    assert api.rebind_registry(core, installed=installed) is True


def test_an_apply_that_reads_a_newer_view_does_not_wait_on_its_own_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The apply path re-reads authority while it holds the apply lock.

    The lock is not reentrant. When the durable view is newer than the runtime,
    installing it must not try to take the lock the apply already holds, or the
    apply waits on itself and the daemon stops answering extension mutations.
    """

    store = GuardStore(tmp_path / "guard-home")
    core = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    runtime = ExtensionControlRuntime(_protected(core.catalog_digest))
    api = ExtensionControlApiService(store=store, registry=core, runtime=runtime)
    monkeypatch.setattr(
        store,
        "read_extension_control_authority_for_registry",
        lambda registry, *, read_only=False, **_kwargs: _protected(registry.catalog_digest, revision=_REVISION + 1),
    )
    result: list[ExtensionControlRuntimeSnapshot] = []

    def read_under_the_apply_lock() -> None:
        with api._apply_lock:
            result.append(api._live_snapshot(read_only=True, apply_locked=True))

    worker = threading.Thread(target=read_under_the_apply_lock, daemon=True)
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert [snapshot.revision for snapshot in result] == [_REVISION + 1]
