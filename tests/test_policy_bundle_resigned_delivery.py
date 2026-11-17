"""A re-signed copy of the active policy bundle leaves the native fence open.

Cloud signs the bundle it serves on every sync, and RSA-PSS signatures are
randomised, so each sync delivers the same bundle with a new signature. Each
delivery used to close the native command-control fence once per activation
attempt, twice per sync. Every native reader then republished an identical
policy snapshot, and hooks that arrived meanwhile failed closed: about one
hook in twenty-five on a long-lived install.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy_activation_noop import activation_changes_enforcement
from tests.test_policy_bundle_activation_atomicity import _activate_bundle, _signed_bundle

_FIRST_SYNC = "2026-07-18T00:00:00Z"
_NEXT_SYNC = "2026-07-18T00:00:45Z"


@pytest.fixture
def fence_closures(monkeypatch: pytest.MonkeyPatch) -> list[None]:
    closures: list[None] = []
    close = GuardStore._invalidate_native_extension_control_policy

    def counted(self: GuardStore, **kwargs: bool) -> None:
        closures.append(None)
        close(self, **kwargs)

    monkeypatch.setattr(GuardStore, "_invalidate_native_extension_control_policy", counted)
    return closures


def _stored(store: GuardStore, state_key: str) -> dict[str, object]:
    payload = store.get_sync_payload(state_key)
    assert isinstance(payload, dict)
    return payload


def test_a_resigned_bundle_is_stored_without_closing_the_fence(tmp_path: Path, fence_closures: list[None]) -> None:
    store = GuardStore(tmp_path)
    first = _signed_bundle(rollout_state="enforcing")
    assert _activate_bundle(store, first, _FIRST_SYNC) is not None
    assert len(fence_closures) == 1
    rows = store.list_policy_decisions()

    resigned = _signed_bundle(rollout_state="enforcing")
    assert resigned["bundleHash"] == first["bundleHash"]
    assert resigned["verifier"] != first["verifier"]
    fence_closures.clear()

    assert _activate_bundle(store, resigned, _NEXT_SYNC) is not None

    assert fence_closures == []
    # The delivery is still written: Guard keeps the signature it was served.
    assert _stored(store, "policy_bundle")["verifier"] == resigned["verifier"]
    assert _stored(store, "policy_bundle_last_good")["verifier"] == resigned["verifier"]
    assert [row["action"] for row in store.list_policy_decisions()] == [row["action"] for row in rows]


def test_a_changed_bundle_closes_the_fence_once(tmp_path: Path, fence_closures: list[None]) -> None:
    store = GuardStore(tmp_path)
    assert _activate_bundle(store, _signed_bundle(rollout_state="enforcing"), _FIRST_SYNC) is not None
    fence_closures.clear()

    changed = _signed_bundle(
        rollout_state="enforcing",
        bundle_version="policy-2026-07-19.enforcing",
        issued_at="2026-07-02T00:00:00Z",
    )
    assert _activate_bundle(store, changed, _NEXT_SYNC) is not None

    # Once, not once per resident-verdict attempt.
    assert len(fence_closures) == 1
    assert _stored(store, "policy_bundle")["bundleVersion"] == "policy-2026-07-19.enforcing"


def _state(rows: list[tuple[object, ...]], payloads: dict[str, str]) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute("create table sync_state (state_key text primary key, payload_json text, updated_at text)")
    connection.execute(
        "create table policy_decisions (harness, scope, artifact_id, artifact_hash, workspace, publisher, action, "
        "reason, owner, source, expires_at, updated_at, integrity_version, integrity_generation, payload_hash, "
        "payload_mac, integrity_key_id, signed_at)"
    )
    connection.executemany("insert into sync_state values (?, ?, 'then')", payloads.items())
    connection.executemany(f"insert into policy_decisions values ({', '.join('?' * 18)})", rows)
    return connection


def _row(*, action: str = "block", updated_at: str = "then", source: str = "policy-bundle") -> tuple[object, ...]:
    return ("codex", "global", "a", None, None, None, action, "r", None, source, None, updated_at, *([None] * 6))


def _bundle(signature: str, *, version: str = "v1") -> str:
    return json.dumps({"bundleVersion": version, "verifier": {"keyId": "k", "signature": signature}})


def test_only_the_signature_ack_and_write_time_are_ignored() -> None:
    stored = {"policy_bundle": _bundle("old"), "policy_bundle_ack": "{}", "cloud_exceptions": "[]"}
    connection = _state([_row(), _row(source="local")], stored)

    same = {**stored, "policy_bundle": _bundle("new"), "policy_bundle_ack": '{"seq": 2}'}
    assert not activation_changes_enforcement(connection, payloads=same, rows=[_row(updated_at="now")])

    for payloads, rows in (
        ({**same, "policy_bundle": _bundle("new", version="v2")}, [_row()]),
        ({**same, "cloud_exceptions": '[{"id": 1}]'}, [_row()]),
        ({**same, "policy_bundle_keyring": "{}"}, [_row()]),
        (same, [_row(action="allow")]),
        (same, [_row(), _row()]),
        (same, []),
    ):
        assert activation_changes_enforcement(connection, payloads=payloads, rows=rows)
