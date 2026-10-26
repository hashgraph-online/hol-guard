"""A granted CLI's blocked loopback connection suggests local network access, and turns nothing on."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore

_PASSWORD = "synthetic-capability-test-password"
_SEEN = "2026-10-01T12:00:00Z"
_IDENTITY = UnlistedCliIdentity(
    cli_id="local-cli.lanectl-12345678",
    name="lanectl",
    kind="executable",
    identity_hash="a" * 64,
    example_label="lanectl",
)


def _service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[GuardStore, LocalCliApiService]:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.local_cli_api.Path.home", staticmethod(lambda: home))
    store = GuardStore(home)
    store.record_local_cli_observation(_IDENTITY, seen_at=_SEEN, surface="cli")
    update_settings(
        store.guard_home,
        {"enabled": True, "new_password": _PASSWORD, "confirm_password": _PASSWORD, "cooldown_seconds": 0},
    )
    return store, LocalCliApiService(store=store)


def _apply(store: GuardStore, service: LocalCliApiService, state: str, capabilities: dict | None = None) -> None:
    payload: dict[str, object] = {
        "cli_id": _IDENTITY.cli_id,
        "identity_hash": _IDENTITY.identity_hash,
        "name": _IDENTITY.name,
        "kind": _IDENTITY.kind,
        "state": state,
        "previous_revision": store.read_local_cli_revision(),
        "session_nonce": "synthetic-capability-nonce",
        "approval_password": _PASSWORD,
    }
    if capabilities is not None:
        payload["capabilities"] = capabilities
    service.apply(payload)


def _listed(service: LocalCliApiService) -> dict[str, object]:
    return next(item for item in service.list_items()["items"] if item["cli_id"] == _IDENTITY.cli_id)


def _note(store: GuardStore, *, identity_hash: str = "a" * 64) -> int:
    return store.note_local_cli_capability_cause(
        cli_id=_IDENTITY.cli_id, identity_hash=identity_hash, cause="connect_loopback"
    )


def test_a_blocked_loopback_connection_suggests_local_network_access(tmp_path: Path, monkeypatch) -> None:
    store, service = _service(tmp_path, monkeypatch)
    _apply(store, service, "allowed")
    assert "suggested_capability" not in _listed(service)

    assert _note(store) == 1

    listed = _listed(service)
    assert listed["suggested_capability"] == "loopback-network"
    assert listed["capabilities"]["loopback-network"] == "off"


def test_the_suggestion_ends_once_local_network_access_is_on(tmp_path: Path, monkeypatch) -> None:
    store, service = _service(tmp_path, monkeypatch)
    _apply(store, service, "allowed")
    _note(store)

    _apply(store, service, "allowed", {"loopback-network": "on"})

    assert "suggested_capability" not in _listed(service)


@pytest.mark.parametrize("state", ["unset", "blocked"])
def test_only_an_allowed_grant_gets_a_suggestion(tmp_path: Path, monkeypatch, state: str) -> None:
    store, service = _service(tmp_path, monkeypatch)
    if state != "unset":
        _apply(store, service, state)
    _note(store)

    assert "suggested_capability" not in _listed(service)


def test_a_cause_for_another_binary_changes_nothing(tmp_path: Path, monkeypatch) -> None:
    store, service = _service(tmp_path, monkeypatch)
    _apply(store, service, "allowed")

    assert _note(store, identity_hash="b" * 64) == 0
    assert "suggested_capability" not in _listed(service)


def _cause(store: GuardStore) -> str | None:
    with store._connect() as connection:
        (cause,) = connection.execute(
            "select first_blocked_cause from local_cli_observation where cli_id = ?", (_IDENTITY.cli_id,)
        ).fetchone()
    return cause


def test_the_newest_capability_cause_wins(tmp_path: Path, monkeypatch) -> None:
    store, _ = _service(tmp_path, monkeypatch)
    for cause in ("write_home_state", "connect_loopback"):
        store.note_local_cli_capability_cause(
            cli_id=_IDENTITY.cli_id, identity_hash=_IDENTITY.identity_hash, cause=cause
        )
    assert _cause(store) == "connect_loopback"


def test_turning_the_capability_on_clears_its_cause(tmp_path: Path, monkeypatch) -> None:
    store, service = _service(tmp_path, monkeypatch)
    _apply(store, service, "allowed")
    _note(store)

    _apply(store, service, "allowed", {"state-dir-read": "on"})
    assert _cause(store) == "connect_loopback"

    _apply(store, service, "allowed", {"loopback-network": "on"})
    assert _cause(store) is None


def test_a_changed_binary_drops_the_old_cause(tmp_path: Path, monkeypatch) -> None:
    store, _ = _service(tmp_path, monkeypatch)
    _note(store)
    changed = UnlistedCliIdentity(
        cli_id=_IDENTITY.cli_id,
        name=_IDENTITY.name,
        kind=_IDENTITY.kind,
        identity_hash="b" * 64,
        example_label=_IDENTITY.example_label,
    )

    store.record_local_cli_observation(changed, seen_at=_SEEN, surface="cli")

    assert _cause(store) is None


def test_an_unknown_cause_is_refused(tmp_path: Path, monkeypatch) -> None:
    store, _ = _service(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="invalid_first_blocked_cause"):
        store.note_local_cli_capability_cause(
            cli_id=_IDENTITY.cli_id, identity_hash=_IDENTITY.identity_hash, cause="exec_outside_roots"
        )


class _NotingStore:
    def __init__(self) -> None:
        self.noted: list[dict[str, str]] = []

    def note_local_cli_capability_cause(self, **cause: str) -> int:
        self.noted.append(cause)
        return 1


@pytest.mark.parametrize(
    ("capabilities", "output", "noted"),
    [
        ((), b"Error: connect EPERM 127.0.0.1:8080", True),
        (("loopback-network",), b"Error: connect EPERM 127.0.0.1:8080", False),
        ((), b"Error: connect EPERM 203.0.113.7:443", False),
        ((), b"Error: EPERM: operation not permitted, mkdir '/opt/lanectl/cache'", False),
    ],
)
def test_the_python_sink_remembers_only_a_granted_loopback_denial(
    capabilities: tuple[str, ...], output: bytes, noted: bool
) -> None:
    from codex_plugin_scanner.guard.local_cli_hook import ContainedGrant
    from codex_plugin_scanner.guard.runtime.contained_denial_note import denial_note
    from codex_plugin_scanner.guard.runtime.restricted_workspace_grant_lookup import grant_store, granted_denial_note

    store = _NotingStore()
    grant = ContainedGrant(
        cli_id=_IDENTITY.cli_id, identity_hash=_IDENTITY.identity_hash, name="lanectl", capabilities=capabilities
    )
    with grant_store(store):  # type: ignore[arg-type]
        note = granted_denial_note(grant)
        assert note([output]) == denial_note([output])

    expected = [{"cli_id": _IDENTITY.cli_id, "identity_hash": _IDENTITY.identity_hash, "cause": "connect_loopback"}]
    assert store.noted == (expected if noted else [])


def test_the_python_sink_without_a_grant_keeps_the_plain_note() -> None:
    from codex_plugin_scanner.guard.runtime.contained_denial_note import denial_note
    from codex_plugin_scanner.guard.runtime.restricted_workspace_grant_lookup import granted_denial_note

    assert granted_denial_note(None) is denial_note
