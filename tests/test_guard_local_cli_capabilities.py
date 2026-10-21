"""Local CLI grant capabilities: schema, authority writes and read side."""

from __future__ import annotations

import ast
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.native_local_cli_grant import _decode_payload
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.sqlite_recovery import salvage_local_cli_state
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_local_cli_schema import (
    _V12_CHECKSUM,
    LOCAL_CLI_SCHEMA_VERSION,
    ensure_local_cli_schema,
)

_SRC = Path(__file__).resolve().parents[1] / "src" / "codex_plugin_scanner" / "guard"
_PASSWORD = "synthetic-capability-test-password"
_SEEN = "2026-10-01T12:00:00Z"
_ALL_OFF = {"loopback-network": "off", "state-dir-read": "off", "state-dir-write": "off"}


def _identity(identity_hash: str = "a" * 64) -> UnlistedCliIdentity:
    return UnlistedCliIdentity(
        cli_id="local-cli.lanectl-12345678",
        name="lanectl",
        kind="executable",
        identity_hash=identity_hash,
        example_label="lanectl",
    )


def _service(tmp_path: Path, monkeypatch, *, surface: str = "cli") -> tuple[GuardStore, LocalCliApiService]:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.local_cli_api.Path.home", staticmethod(lambda: home))
    store = GuardStore(home)
    store.record_local_cli_observation(_identity(), seen_at=_SEEN, surface=surface)
    update_settings(
        store.guard_home,
        {"enabled": True, "new_password": _PASSWORD, "confirm_password": _PASSWORD, "cooldown_seconds": 0},
    )
    return store, LocalCliApiService(store=store)


def _payload(store: GuardStore, state: str, capabilities: object, *, identity_hash: str = "a" * 64) -> dict:
    identity = _identity(identity_hash)
    payload: dict[str, object] = {
        "cli_id": identity.cli_id,
        "identity_hash": identity.identity_hash,
        "name": identity.name,
        "kind": identity.kind,
        "state": state,
        "previous_revision": store.read_local_cli_revision(),
        "session_nonce": "synthetic-capability-nonce",
    }
    if capabilities is not None:
        payload["capabilities"] = capabilities
    return payload


def _apply(service: LocalCliApiService, payload: dict) -> dict:
    return service.apply({**payload, "approval_password": _PASSWORD})


def test_v12_store_gains_capability_table_on_migration(tmp_path: Path) -> None:
    with sqlite3.connect(tmp_path / "guard.db") as connection:
        ensure_local_cli_schema(connection)
        connection.execute("drop table local_cli_grant_capability")
        connection.execute(
            "update local_cli_schema_migration set version = 12, checksum = ? where singleton = 1", (_V12_CHECKSUM,)
        )
        ensure_local_cli_schema(connection)
        version = connection.execute("select version from local_cli_schema_migration").fetchone()[0]
        assert version == LOCAL_CLI_SCHEMA_VERSION == 14
        columns = [row[1] for row in connection.execute("pragma table_info(local_cli_grant_capability)")]
        assert columns == ["cli_id", "capability", "state", "revision", "updated_at"]
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("insert into local_cli_grant_capability values ('x', 'raw-network', 'on', 1, 't')")


def test_apply_with_proof_persists_capabilities_and_lists_them(tmp_path: Path, monkeypatch) -> None:
    store, service = _service(tmp_path, monkeypatch)
    choices = {"state-dir-read": "on", "loopback-network": "on", "state-dir-write": "off"}
    preview = service.preview(_payload(store, "allowed", choices))
    assert preview["capabilities"] == choices
    with pytest.raises(LocalCliApiError):
        service.apply(_payload(store, "allowed", choices))
    assert store.read_local_cli_capabilities(_identity().cli_id) == _ALL_OFF
    result = _apply(service, _payload(store, "allowed", choices))
    expected = {"loopback-network": "on", "state-dir-read": "on", "state-dir-write": "off"}
    assert result["capabilities"] == expected
    listed = [item for item in service.list_items()["items"] if item["cli_id"] == _identity().cli_id]
    assert listed[0]["capabilities"] == expected
    # Turning one off keeps the rest; omitting the field leaves them untouched.
    _apply(service, _payload(store, "allowed", {"loopback-network": "off"}))
    _apply(service, _payload(store, "allowed", None))
    assert store.read_local_cli_capabilities(_identity().cli_id)["state-dir-read"] == "on"
    assert store.read_local_cli_capabilities(_identity().cli_id)["loopback-network"] == "off"


@pytest.mark.parametrize(
    "capabilities",
    [
        {"raw-network": "on"},
        {"state-dir-read": "yes"},
        {"state-dir-read": ["on"]},
        {"state-dir-read": {"on": True}},
        {"state-dir-read": None},
        {"state-dir-read": 1},
        ["state-dir-read"],
        "state-dir-read",
    ],
)
def test_unknown_or_malformed_capabilities_are_refused(tmp_path: Path, monkeypatch, capabilities) -> None:
    store, service = _service(tmp_path, monkeypatch)
    for call in (service.preview, lambda body: _apply(service, body)):
        with pytest.raises(LocalCliApiError) as error:
            call(_payload(store, "allowed", capabilities))
        assert error.value.code == "invalid_capabilities"
    assert store.read_local_cli_revision() == 0


@pytest.mark.parametrize("state", ["blocked", "unset"])
def test_capability_on_requires_allowed_grant(tmp_path: Path, monkeypatch, state: str) -> None:
    store, service = _service(tmp_path, monkeypatch)
    with pytest.raises(LocalCliApiError) as error:
        _apply(service, _payload(store, state, {"state-dir-read": "on"}))
    assert error.value.code == "capabilities_require_allowed_grant"
    assert store.read_local_cli_revision() == 0


def test_capabilities_are_only_for_cli_surface(tmp_path: Path, monkeypatch) -> None:
    store, service = _service(tmp_path, monkeypatch, surface="package-scripts")
    with pytest.raises(LocalCliApiError) as error:
        _apply(service, _payload(store, "allowed", {"state-dir-read": "off"}))
    assert error.value.code == "capabilities_require_cli_surface"
    assert service.list_items()["items"][0]["capabilities"] == {}


def test_block_unset_and_identity_change_clear_capabilities(tmp_path: Path, monkeypatch) -> None:
    store, service = _service(tmp_path, monkeypatch)
    _apply(service, _payload(store, "allowed", {"state-dir-write": "on"}))
    _apply(service, _payload(store, "blocked", None))
    assert store.read_local_cli_capabilities(_identity().cli_id) == _ALL_OFF
    _apply(service, _payload(store, "allowed", {"state-dir-write": "on"}))
    _apply(service, _payload(store, "unset", None))
    assert store.read_local_cli_capabilities(_identity().cli_id) == _ALL_OFF
    _apply(service, _payload(store, "allowed", {"state-dir-write": "on"}))
    _apply(service, _payload(store, "allowed", None, identity_hash="b" * 64))
    assert store.read_local_cli_capabilities(_identity().cli_id) == _ALL_OFF


def test_allow_block_allow_does_not_bring_capabilities_back(tmp_path: Path, monkeypatch) -> None:
    store, service = _service(tmp_path, monkeypatch)
    _apply(service, _payload(store, "allowed", {"loopback-network": "on"}))
    _apply(service, _payload(store, "blocked", None))
    _apply(service, _payload(store, "allowed", None))
    assert store.read_local_cli_capabilities(_identity().cli_id) == _ALL_OFF
    # A row that survived a block some other way (a salvage) is dropped on re-allow.
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            "insert into local_cli_grant_capability values (?, 'state-dir-read', 'on', 1, 't')",
            (_identity().cli_id,),
        )
        connection.execute("update local_cli_grant set state = 'blocked'")
    _apply(service, _payload(store, "allowed", None))
    assert store.read_local_cli_capabilities(_identity().cli_id) == _ALL_OFF


def test_salvage_copies_capabilities_only_with_an_allowed_grant(tmp_path: Path, monkeypatch) -> None:
    store, service = _service(tmp_path, monkeypatch)
    _apply(service, _payload(store, "allowed", {"loopback-network": "on"}))
    source = store.guard_home / "guard.db"
    with sqlite3.connect(source) as connection:
        connection.execute(
            "insert into local_cli_grant_capability values ('local-cli.gone-1', 'state-dir-read', 'on', 1, 't')"
        )
    destination = tmp_path / "fresh.db"
    with sqlite3.connect(destination) as connection:
        ensure_local_cli_schema(connection)
    assert salvage_local_cli_state(source=source, destination=destination)
    with sqlite3.connect(destination) as connection:
        rows = connection.execute("select cli_id, capability from local_cli_grant_capability").fetchall()
    assert rows == [(_identity().cli_id, "loopback-network")]


def test_salvage_drops_capabilities_without_a_restored_cli_observation(tmp_path: Path, monkeypatch) -> None:
    store, service = _service(tmp_path, monkeypatch)
    _apply(service, _payload(store, "allowed", {"loopback-network": "on"}))
    source = store.guard_home / "guard.db"
    with sqlite3.connect(source) as connection:
        connection.execute("delete from local_cli_observation")
    destination = tmp_path / "fresh.db"
    with sqlite3.connect(destination) as connection:
        ensure_local_cli_schema(connection)
    assert salvage_local_cli_state(source=source, destination=destination)
    with sqlite3.connect(destination) as connection:
        assert connection.execute("select count(*) from local_cli_grant").fetchone()[0] == 1
        assert connection.execute("select count(*) from local_cli_grant_capability").fetchone()[0] == 0


_BASE = {"state": "allowed", "cli_id": "local-cli.lanectl-12345678", "identity_hash": "c" * 64}


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({}, ()),
        ({"capabilities": []}, ()),
        ({"capabilities": ["loopback-network", "state-dir-read"]}, ("loopback-network", "state-dir-read")),
        ({"capabilities": ["state-dir-read", "loopback-network"]}, None),
        ({"capabilities": ["state-dir-read", "state-dir-read"]}, None),
        ({"capabilities": ["raw-network"]}, None),
        ({"capabilities": "state-dir-read"}, None),
        ({"state": "blocked", "capabilities": ["state-dir-read"]}, None),
        ({"other": []}, None),
    ],
)
def test_native_answer_decodes_capabilities(extra: dict, expected) -> None:
    decoded = _decode_payload({**_BASE, **extra})
    assert (None if decoded is None else decoded.capabilities) == expected


def _calls(name: str) -> set[str]:
    found: set[str] = set()
    for path in _SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                if called == name or any(keyword.arg == name for keyword in node.keywords):
                    found.add(path.relative_to(_SRC).as_posix())
    return found


def test_only_the_authority_apply_writes_capabilities() -> None:
    """R1.3: no path but preview, one-use proof and apply reaches the table."""

    writers = set()
    for path in [*_SRC.rglob("*.py"), *(_SRC.parents[2] / "rust" / "crates").rglob("*.rs")]:
        if path.name.endswith("_tests.rs") or "/tests/" in path.as_posix():
            continue
        text = path.read_text(encoding="utf-8").lower()
        for verb in ("insert into", "insert or", "update", "replace into"):
            if f"{verb} local_cli_grant_capability" in text:
                writers.add(path.name)
    assert writers == {"store_local_cli_capabilities.py"}
    assert _calls("write_local_cli_capabilities") == {"store_custom_extension_continuity.py"}
    # The store forwards its own parameter; only the local mutation recorder sets it.
    assert _calls("capability_updates") == {
        "runtime/custom_extension_continuity.py",
        "store_custom_extension_continuity.py",
    }
    callers = _calls("record_local_custom_extension_mutation") - {"runtime/custom_extension_continuity.py"}
    with_capabilities = {path for path in callers if "capabilities=" in (_SRC / path).read_text(encoding="utf-8")}
    assert with_capabilities == {"daemon/local_cli_api.py"}
