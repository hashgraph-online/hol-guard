"""A fresh complete empty capture supplies its own empty Cloud projection."""

from __future__ import annotations

import json
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot_publisher_context as context_module
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_policy_snapshot_reservation_capture import _make_publisher
from tests.test_native_policy_source_selection import _insert_untrusted_row


def test_complete_empty_publication_has_fresh_captures_without_secondary_cloud_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "home")
    captures: list[str] = []
    original = context_module.compiled_scoped_policy

    def capture(publisher: NativePolicySnapshotPublisher, *, command_extensions: Mapping[str, object] | None = None):
        config, inputs = original(publisher, command_extensions=command_extensions)
        assert inputs.sources == [] and inputs.defaults is None
        captures.append(inputs.input_digest)
        return config, inputs

    def secondary_read(*args: object, **kwargs: object):
        pytest.fail("The complete empty capture already proves the absence of Cloud authority")

    monkeypatch.setattr(context_module, "compiled_scoped_policy", capture)
    monkeypatch.setattr(context_module, "read_native_cloud_policy_inputs", secondary_read)
    calls: list[dict[str, object]] = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        assert len(calls) == 1
        assert len(captures) >= 2 and len(set(captures)) == 1
        assert publisher.current_snapshot_binding() is not None


@pytest.mark.parametrize("boundary", ["capture", "ack"])
@pytest.mark.parametrize("source", ["unsigned-row", "unsigned-cloud", "orphan-memory"])
def test_source_arrival_cannot_ack_an_earlier_empty_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str, source: str
) -> None:
    store = GuardStore(tmp_path / "home")
    writes: list[str] = []
    calls: list[dict[str, object]] = []
    original = context_module.compiled_scoped_policy

    def mutate() -> None:
        assert not writes
        writes.append(source)
        if source == "unsigned-row":
            _insert_untrusted_row(store)
            return
        key = "policy_bundle" if source == "unsigned-cloud" else "guard_review_memory_policy_version"
        with store._connect() as connection:
            connection.execute(
                "insert into sync_state(state_key, payload_json, updated_at) values(?,?,?)",
                (key, json.dumps({"version": "untrusted"}), "2026-09-19T00:00:00Z"),
            )

    def capture(publisher: NativePolicySnapshotPublisher, *, command_extensions: Mapping[str, object] | None = None):
        result = original(publisher, command_extensions=command_extensions)
        if boundary == "capture" and not writes:
            mutate()
        return result

    def during_ack(snapshot: object) -> str:
        del snapshot
        if boundary == "ack":
            mutate()
        return "accepted"

    monkeypatch.setattr(context_module, "compiled_scoped_policy", capture)
    with closing(_make_publisher(store, calls, during=during_ack, scoped=False)) as publisher:
        publisher._publish_once()
        assert writes == [source]
        assert len(calls) == (1 if boundary == "ack" else 0)
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
        assert publisher.current_snapshot_binding() is None
        assert publisher.last_error is not None
