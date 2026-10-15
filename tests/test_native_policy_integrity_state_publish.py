"""The daemon publishes the policy-integrity state the store holds now.

The resident accepts a saved decision only while the published state equals
the stored row, and refuses an MCP relay binding without the exact-action
state. A fresh home has no row, and a policy write advances the generation
after refreshing it, so the publisher refreshes the row before binding it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_direct_lane_saved as saved
from codex_plugin_scanner.guard import native_policy_snapshot_publisher as publisher_api
from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane import (
    DIRECT_HOOK_SAVED_DECISION_FEATURE,
    direct_lane_integrity_key,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import (
    NativePolicySnapshotError,
    NativePolicySnapshotPublisher,
)
from codex_plugin_scanner.guard.store import GuardStore

FEATURES = (DIRECT_HOOK_SAVED_DECISION_FEATURE,)


@pytest.fixture(autouse=True)
def _daemon(monkeypatch: pytest.MonkeyPatch, install_fake_system_keyring) -> None:
    install_fake_system_keyring()
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(saved, "current_extension_control_binding_digest", lambda: "e" * 64)
    monkeypatch.setattr(saved, "os", SimpleNamespace(environ={"HOME": "/home/dev", "PATH": "/usr/bin"}))


def _daemon_store(guard_home: Path) -> GuardStore:
    # As `daemon serve` opens it: never primed, never the system keyring.
    return GuardStore(guard_home, source="default", prime_policy_integrity=False, allow_system_keyring=False)


def _stored(store: GuardStore) -> object:
    with store._connect() as connection:
        return store._load_policy_integrity_state(connection)


def _published(store: GuardStore) -> dict[str, object]:
    saved.refresh_integrity_state(store)
    bound = saved.with_saved_decision_state({}, store=store, features=FEATURES)
    assert bound is not None
    return bound


def test_a_fresh_home_binds_the_state_its_store_writes(tmp_path: Path) -> None:
    store = _daemon_store(tmp_path / "guard-home")
    assert _stored(store) is None
    assert saved.with_saved_decision_state({}, store=store, features=FEATURES) == {}

    bound = _published(store)

    assert bound["exact_action_control_digest"] == "e" * 64
    assert bound["policy_integrity_state"] == _stored(store)
    assert _published(store) == bound
    # Without a key the state is degraded and no integrity key binds, so the
    # resident defers any saved row rather than deciding it
    # (mcp_relay_decide_saved_tests::an_unpublished_or_moved_integrity_state_defers).
    state = bound["policy_integrity_state"]
    assert isinstance(state, dict)
    assert state["mode"] == "degraded"
    assert state["degraded_reasons"]
    assert state["generation"] is None
    assert direct_lane_integrity_key(store, FEATURES) is None


def test_a_key_the_context_mints_reaches_the_first_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Startup provisioning failed, so the publication context mints the key.
    # That moves the state without a database write; the first binding must
    # still carry the keyed state rather than the degraded one before it.
    store = _daemon_store(tmp_path / "guard-home")
    assert direct_lane_integrity_key(store, FEATURES) is None
    publisher = NativePolicySnapshotPublisher(store=store)
    contexts: list[object] = []
    bindings: list[object] = []

    def context(*, workspaces: object = None) -> tuple[object, ...]:
        material = store._policy_integrity_secret_material(create=True)
        contexts.append(material)
        return (SimpleNamespace(), SimpleNamespace(features=FEATURES), material[0], {}, {}, None)

    def publish(**kwargs: object) -> None:
        bindings.append(kwargs["direct_lane"])
        raise NativePolicySnapshotError("captured")

    monkeypatch.setattr(publisher, "_publication_context", context)
    monkeypatch.setattr(publisher_api, "_publish_snapshot_v3", publish)
    try:
        publisher._publish_once()
    finally:
        publisher.close()

    assert len(contexts) == 2
    assert len(bindings) == 1
    binding = bindings[0]
    assert isinstance(binding, dict)
    state = binding["policy_integrity_state"]
    assert state == _stored(store)
    assert isinstance(state, dict) and state["key_id"] is not None


def _save_decision(store: GuardStore) -> int:
    """Save one local decision from another store; return the generation it signed."""

    writer = GuardStore(store.guard_home, prime_policy_integrity=False)
    writer.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id="codex:project:workspace-skill",
            artifact_hash="hash-123",
            reason="reviewed",
            source="local",
        ),
        "2026-06-14T00:00:00Z",
    )
    with sqlite3.connect(store.path) as connection:
        (signed_generation,) = connection.execute("select integrity_generation from policy_decisions").fetchone()
    return int(signed_generation)


def test_a_policy_write_republishes_the_state_it_leaves(tmp_path: Path) -> None:
    store = _daemon_store(tmp_path / "guard-home")
    before = _published(store)["policy_integrity_state"]
    signed_generation = _save_decision(store)

    after = _published(store)["policy_integrity_state"]

    # The resident refuses the earlier binding, whose state no longer matches
    # the row, and verifies rows against the generation it now carries.
    assert isinstance(after, dict)
    assert after != before
    assert after == _stored(store)
    assert after["mode"] == "protected"
    assert after["generation"] == signed_generation


_REFRESH = saved.refresh_integrity_state


class _Lane(saved.NativePolicySnapshotSavedStateMixin):
    """The publisher surface the reconcile recheck uses."""

    def __init__(self, store: GuardStore) -> None:
        self.store = store
        self.guard_home = Path(store.guard_home)
        self._direct_lane_ack_target: tuple[int, str] | None = (1, "ack")
        self.rebinds = 0
        self._bind_relay_and_saved_state(_published(store), FEATURES)

    def _bind_mcp_relay_view(self, binding: object, features: object) -> None:
        return None

    def _rebind_direct_lane(self) -> None:
        # The republish binds the state the store holds.
        self.rebinds += 1
        self._bind_relay_and_saved_state(
            saved.with_saved_decision_state({}, store=self.store, features=FEATURES), FEATURES
        )


def _counted_refreshes(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    calls: list[object] = []

    def refresh(store: object) -> None:
        calls.append(store)
        _REFRESH(store)

    monkeypatch.setattr(saved, "refresh_integrity_state", refresh)
    return calls


def test_a_saved_decision_rebinds_the_lane_from_the_reconcile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A saved decision leaves the effective policy unchanged, so it queues no
    # republish; only this recheck carries the state it leaves to the lane.
    store = _daemon_store(tmp_path / "guard-home")
    lane = _Lane(store)
    lane._recheck_direct_lane_saved_state()
    assert lane.rebinds == 0

    signed_generation = _save_decision(store)
    lane._recheck_direct_lane_saved_state()
    assert lane.rebinds == 1
    stored = _stored(store)
    assert isinstance(stored, dict)
    assert stored["mode"] == "protected"
    assert stored["generation"] == signed_generation
    assert lane._direct_lane_integrity_state == stored

    # A refresh that wrote the row costs one more refresh, which writes
    # nothing; after that an unchanged database refreshes nothing.
    refreshes = _counted_refreshes(monkeypatch)
    lane._recheck_direct_lane_saved_state()
    lane._recheck_direct_lane_saved_state()
    assert len(refreshes) <= 1
    settled = len(refreshes)
    lane._recheck_direct_lane_saved_state()
    assert (lane.rebinds, len(refreshes)) == (1, settled)

    # A closed lane has nothing to rebind.
    lane._direct_lane_ack_target = None
    _save_decision(store)
    lane._recheck_direct_lane_saved_state()
    assert (lane.rebinds, len(refreshes)) == (1, settled)


def test_a_write_after_the_refresh_is_refreshed_on_the_next_reconcile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _daemon_store(tmp_path / "guard-home")
    lane = _Lane(store)
    lane._recheck_direct_lane_saved_state()
    late: list[int] = []

    def refresh_then_write(target: object) -> None:
        _REFRESH(target)
        if not late:
            late.append(_save_decision(store))

    monkeypatch.setattr(saved, "refresh_integrity_state", refresh_then_write)
    first = _save_decision(store)
    lane._recheck_direct_lane_saved_state()
    assert lane.rebinds == 1
    assert late and late[0] != first
    bound = lane._direct_lane_integrity_state
    assert isinstance(bound, dict) and bound["generation"] == first

    # The second write landed after the refresh: the next reconcile refreshes
    # again and binds the generation it signed.
    lane._recheck_direct_lane_saved_state()
    assert lane.rebinds == 2
    stored = _stored(store)
    assert isinstance(stored, dict) and stored["generation"] == late[0]
    assert lane._direct_lane_integrity_state == stored


@pytest.mark.parametrize("error", [OSError("gone"), sqlite3.OperationalError("locked"), RuntimeError("resident")])
def test_a_refresh_that_fails_leaves_the_row_alone(error: Exception) -> None:
    class _Failing:
        def _connect(self):
            raise error

        def _refresh_policy_integrity_state(self, connection: object, *, now: str, create_key: bool) -> None:
            raise AssertionError("never reached")

        def _load_policy_integrity_state(self, connection: object) -> None:
            raise AssertionError("never reached")

    assert saved.refresh_integrity_state(_Failing()) is False
    assert saved.refresh_integrity_state(object()) is False
