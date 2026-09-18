"""Inventory write optimization preserves first-seen and approval transitions."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.store import GuardStore


def _artifact() -> GuardArtifact:
    return GuardArtifact(
        artifact_id="fixture",
        harness="gemini",
        name="fixture",
        artifact_type="skill",
        source_scope="global",
        config_path="fixture/SKILL.md",
    )


def test_first_seen_and_approval_survive_updates_removal_and_reappearance(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    artifact = _artifact()
    store.record_inventory_artifact(
        artifact=artifact,
        artifact_hash="initial",
        policy_action="allow",
        changed=False,
        now="2026-09-17T00:00:00Z",
        approved=True,
    )
    store.record_inventory_artifact(
        artifact=artifact,
        artifact_hash="changed",
        policy_action="block",
        changed=True,
        now="2026-09-17T00:01:00Z",
        approved=False,
    )
    changed = store.list_inventory()[0]
    assert changed["first_seen_at"] == "2026-09-17T00:00:00Z"
    assert changed["last_changed_at"] == "2026-09-17T00:01:00Z"
    assert changed["last_approved_at"] is None
    store.mark_inventory_removed(
        harness="gemini",
        artifact_id="fixture",
        policy_action="block",
        artifact_hash="removed",
        now="2026-09-17T00:02:00Z",
    )
    store.record_inventory_artifact(
        artifact=artifact,
        artifact_hash="returned",
        policy_action="warn",
        changed=False,
        now="2026-09-17T00:03:00Z",
        approved=True,
    )
    returned = store.list_inventory()[0]
    assert returned["first_seen_at"] == "2026-09-17T00:00:00Z"
    assert returned["last_changed_at"] == "2026-09-17T00:02:00Z"
    assert returned["last_approved_at"] == "2026-09-17T00:03:00Z"
    assert returned["removed_at"] is None and returned["present"] is True
    assert returned["last_policy_action"] == "warn"
    store.record_inventory_artifact(
        artifact=replace(artifact, harness="hermes"),
        artifact_hash="independent",
        policy_action="allow",
        changed=False,
        now="2026-09-17T00:04:00Z",
        approved=True,
    )
    assert store.list_inventory("hermes")[0]["first_seen_at"] == "2026-09-17T00:04:00Z"


def test_failed_upsert_does_not_partially_change_existing_inventory(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    artifact = _artifact()
    store.record_inventory_artifact(
        artifact=artifact,
        artifact_hash="initial",
        policy_action="allow",
        changed=False,
        now="2026-09-17T00:00:00Z",
        approved=True,
    )
    before = store.list_inventory()
    with store._connect() as connection:
        connection.execute("""create trigger reject_fixture_update before update on artifact_inventory
            when NEW.artifact_hash = 'reject' begin select raise(ABORT, 'fixture rejection'); end""")
    with pytest.raises(sqlite3.IntegrityError, match="fixture rejection"):
        store.record_inventory_artifact(
            artifact=artifact,
            artifact_hash="reject",
            policy_action="block",
            changed=True,
            now="2026-09-17T00:01:00Z",
            approved=False,
        )
    assert store.list_inventory() == before
