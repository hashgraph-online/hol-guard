import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import (
    NativePolicySnapshotPublisher,
    local_cli_publication_status,
)
from codex_plugin_scanner.guard.runtime.composio_discovery import ComposioActionSchema
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _status


def _publisher(store: GuardStore, monkeypatch: pytest.MonkeyPatch, client):
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"m" * 32, "fixture"))
    return NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=client)


def _mutate(store: GuardStore) -> int:
    identity = UnlistedCliIdentity(
        cli_id="local-cli.mcp-fixture",
        name="Fixture",
        kind="executable",
        identity_hash="a" * 64,
        example_label="fixture-mcp",
    )
    store.record_local_cli_observation(identity, seen_at="2026-09-27T12:00:00Z", surface="mcp")
    return store.upsert_local_cli_grant(
        identity=identity,
        state="blocked",
        expected_revision=store.read_local_cli_revision(),
        updated_at="2026-09-27T12:00:00Z",
    )


def test_publication_status_requires_ack_for_exact_local_revision(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    assert local_cli_publication_status(store.guard_home, 0)["state"] == "unavailable"
    publisher = _publisher(store, monkeypatch, lambda **kwargs: _ack(kwargs["payload"]))
    try:
        assert local_cli_publication_status(store.guard_home, 0)["state"] == "pending"
        publisher._publish_once()
        receipt = local_cli_publication_status(store.guard_home, 0)
        assert receipt["state"] == "acknowledged"
        assert receipt["generation"] == publisher.current_snapshot()["generation"]
        revision = _mutate(store)
        assert local_cli_publication_status(store.guard_home, revision)["state"] != "acknowledged"
        publisher.request_publish()
        assert publisher.local_cli_publication_receipt(0) is None
        publisher._publish_once()
        assert local_cli_publication_status(store.guard_home, revision)["state"] == "acknowledged"
    finally:
        publisher.close()


def test_local_revision_changed_during_native_ack_keeps_barrier_closed(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")

    def client(**kwargs):
        _mutate(store)
        return _ack(kwargs["payload"])

    publisher = _publisher(store, monkeypatch, client)
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.last_error == "native_local_cli_revision_changed"
        assert local_cli_publication_status(store.guard_home, store.read_local_cli_revision())["state"] == "failed"
    finally:
        publisher.close()


def test_provider_schema_changed_during_ack_keeps_barrier_closed(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    source = observed_mcp_tool("codex", "mcp__codex_apps__composio__composio_search_tools")
    assert source is not None
    store.record_composio_discovery(
        source,
        (ComposioActionSchema("slack", "SLACK_SEARCH_MESSAGES", "Search", {"type": "object"}, True),),
        seen_at="2026-09-27T12:00:00Z",
    )

    def client(**kwargs):
        policy = json.loads(kwargs["payload"])["request"]["snapshot"]["effective_policy"]
        assert policy["mcp_provider_catalog_hash"] == store.read_mcp_provider_authority_hash()
        store.record_composio_discovery(
            source,
            (
                ComposioActionSchema(
                    "slack", "SLACK_SEARCH_MESSAGES", "Search", {"type": "object", "required": ["query"]}, True
                ),
            ),
            seen_at="2026-09-27T12:01:00Z",
        )
        return _ack(kwargs["payload"])

    publisher = _publisher(store, monkeypatch, client)
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.last_error == "native_provider_catalog_changed"
    finally:
        publisher.close()
