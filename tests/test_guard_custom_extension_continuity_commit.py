from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import custom_extension_continuity
from codex_plugin_scanner.guard.runtime.custom_extension_continuity import (
    CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY,
    CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY,
    CUSTOM_EXTENSION_CONTINUITY_STATE_KEY,
    CustomExtensionContinuityError,
    apply_verified_custom_extension_continuity,
    prepare_verified_custom_extension_continuity,
    record_local_custom_extension_mutation,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_custom_extension_continuity import _local_cli_observation_snapshot
from tests.test_guard_custom_extension_continuity import _NOW, _bundle, _fake_plan, _identity, _observe, _state_write

_V2_CAPABILITY = "custom-extension-continuity.v2"
_STATE = _state_write({"items": {}}, [])
_REMOVALS = {"stores": ["removals"], "payload": {"removed": {}}, "item_order": None}


def _store(tmp_path: Path) -> tuple[GuardStore, UnlistedCliIdentity]:
    store = GuardStore(tmp_path / "guard-home")
    identity = _identity()
    _observe(store, identity)
    return store, identity


def test_native_writes_choose_which_sync_records_are_stored(tmp_path: Path, monkeypatch) -> None:
    store, identity = _store(tmp_path)
    state = {"items": {"b": {"n": 1}, "a": {"n": 2}}}
    _fake_plan(
        monkeypatch,
        writes=[_state_write(state, ["b", "a"], "state", "last_good"), _REMOVALS],
    )

    mutation, returned = prepare_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)

    assert mutation is not None
    assert set(mutation.sync_payloads) == {
        CUSTOM_EXTENSION_CONTINUITY_STATE_KEY,
        CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY,
        CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY,
    }
    assert list(mutation.sync_payloads[CUSTOM_EXTENSION_CONTINUITY_STATE_KEY]["items"]) == ["b", "a"]
    assert mutation.sync_payloads[CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY] == returned
    assert mutation.sync_payloads[CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY] == {"removed": {}}


def test_native_write_set_is_what_the_store_applies(tmp_path: Path, monkeypatch) -> None:
    store, identity = _store(tmp_path)
    _fake_plan(monkeypatch, writes=[_state_write({"items": {}}, [], "state", "last_good")])

    _ = apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)

    assert store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY) == {"items": {}}
    assert store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY) == {"items": {}}
    assert store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY) is None


@pytest.mark.parametrize(
    ("requirements", "protected", "capability"),
    [
        ({"protected_authority": False, "capability": None}, False, None),
        ({"protected_authority": True, "capability": _V2_CAPABILITY}, True, _V2_CAPABILITY),
    ],
)
def test_native_requirements_set_the_mutation_gates(
    tmp_path: Path, monkeypatch, requirements: dict[str, object], protected: bool, capability: str | None
) -> None:
    store, identity = _store(tmp_path)
    _fake_plan(monkeypatch, requirements=requirements)

    mutation, _state = prepare_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)

    assert mutation is not None
    assert mutation.requires_protected_extension_authority is protected
    assert mutation.required_negotiated_capability == capability


@pytest.mark.parametrize(
    "writes",
    [
        "state",
        [],
        [_REMOVALS],
        [{"stores": ["state"], "payload": {"items": {}}}],
        [{**_STATE, "extra": True}],
        [{**_STATE, "stores": []}],
        [{**_STATE, "stores": "state"}],
        [{**_STATE, "stores": ["bogus"]}],
        [{**_STATE, "stores": ["state", "state"]}],
        [{**_STATE, "stores": [1]}],
        [{**_STATE, "payload": []}],
        [{**_STATE, "item_order": None}],
        [_STATE, _STATE],
        [_STATE, _state_write({"items": {}}, [], "last_good", "state")],
        [_STATE, {**_REMOVALS, "item_order": []}],
        [{**_STATE, "stores": ["state", "removals"]}],
        [{**_STATE, "stores": ["removals", "last_good"]}],
        [{**_REMOVALS, "stores": ["removals", "state"]}],
        ["not-a-write"],
    ],
)
def test_malformed_native_writes_apply_nothing(tmp_path: Path, monkeypatch, writes: object) -> None:
    store, identity = _store(tmp_path)
    before = store.read_local_cli_revision()
    _fake_plan(monkeypatch, writes=writes)

    with pytest.raises(CustomExtensionContinuityError, match="malformed"):
        _ = apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)

    assert store.read_local_cli_revision() == before
    assert store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY) is None


@pytest.mark.parametrize(
    "requirements",
    [
        None,
        {},
        {"protected_authority": False},
        {"protected_authority": "yes", "capability": None},
        {"protected_authority": 1, "capability": None},
        {"protected_authority": True, "capability": 2},
        {"protected_authority": True, "capability": None, "extra": True},
    ],
)
def test_malformed_native_requirements_apply_nothing(tmp_path: Path, monkeypatch, requirements: object) -> None:
    store, identity = _store(tmp_path)
    _fake_plan(monkeypatch, requirements=requirements)

    with pytest.raises(CustomExtensionContinuityError, match="malformed"):
        _ = apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)

    assert store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY) is None


def _local_commit(monkeypatch, **overrides: object) -> None:
    answer: dict[str, object] = {
        "writes": [_REMOVALS],
        "event": ["receipt", {}],
        "observation_precondition": {},
        **overrides,
    }
    monkeypatch.setattr(
        custom_extension_continuity,
        "native_context_digest",
        lambda *_args, **_kwargs: {"status": "ok", "custom_extension_continuity": answer},
    )


@pytest.mark.parametrize(
    "writes",
    [
        [],
        [_STATE],
        [{**_REMOVALS, "stores": ["last_good"]}],
        [{**_REMOVALS, "stores": ["removals", "last_good"]}],
        [{**_REMOVALS, "item_order": []}],
        [{**_STATE, "stores": ["state", "removals"]}],
        [{**_REMOVALS, "stores": ["removals", "state"]}],
        [_STATE, _STATE, _REMOVALS],
    ],
)
def test_malformed_native_local_writes_apply_nothing(tmp_path: Path, monkeypatch, writes: object) -> None:
    store, identity = _store(tmp_path)
    before = store.read_local_cli_revision()
    _local_commit(monkeypatch, writes=writes)

    with pytest.raises(CustomExtensionContinuityError, match="malformed"):
        _ = record_local_custom_extension_mutation(
            store, identity=identity, state="unset", expected_revision=before, command_states={}, now=_NOW
        )

    assert store.read_local_cli_revision() == before
    assert store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY) is None


def test_native_local_writes_keep_state_and_tombstone(tmp_path: Path, monkeypatch) -> None:
    store, identity = _store(tmp_path)
    before = store.read_local_cli_revision()
    with store._connect() as connection:
        observed = _local_cli_observation_snapshot(connection, identity.cli_id)
    _local_commit(
        monkeypatch,
        writes=[_state_write({"items": {}}, []), _REMOVALS],
        observation_precondition=observed,
    )

    _ = record_local_custom_extension_mutation(
        store, identity=identity, state="unset", expected_revision=before, command_states={}, now=_NOW
    )

    assert store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY) == {"items": {}}
    assert store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY) == {"removed": {}}
