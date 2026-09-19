"""Controlled resident transport with the real source publisher and ACK commit.

Component tests use this fixture to meet the native application prerequisite.
Installed native execution and hook readiness remain separate acceptance proofs.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_policy_bundle_sync
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _status
from tests.test_native_policy_snapshot_v4_publication import _ack


def controlled_policy_publisher(store: GuardStore, *, reply: str = "accepted") -> NativePolicySnapshotPublisher:
    status = _status()
    status.capabilities.features += tuple(SCOPED_PUBLISH_FEATURES)

    def client(**kwargs: Any) -> bytes:
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        directory = store.guard_home / "native-runtime" / "resident-v3-synthetic"
        directory.mkdir(parents=True, exist_ok=True)
        generation = directory / "generation-00000000000000000003.json"
        if not generation.exists():
            generation.write_text("{}")
        if reply == "timeout":
            raise TimeoutError("synthetic resident timeout")
        acknowledgement = _ack(snapshot)
        if reply == "different-source":
            acknowledgement["source_input_digest"] = "c" * 64
        return json.dumps(acknowledgement).encode()

    return NativePolicySnapshotPublisher(store=store, status_provider=lambda: status, client_request=client)


@pytest.fixture
def native_policy_consumer(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # Ordinary unit tests explicitly default to the Python rollback oracle.
    # These sync tests instead exercise real native source acceptance with a
    # controlled transport; canonical rollout remains each test's own choice.
    for name in (
        "HOL_GUARD_NATIVE",
        "HOL_GUARD_NATIVE_BINARY",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "HOL_GUARD_PYTHON_ORACLE",
        "HOL_GUARD_TEST_MODE",
    ):
        monkeypatch.delenv(name, raising=False)
    publishers: dict[Path, NativePolicySnapshotPublisher] = {}

    def publisher_for(store: GuardStore) -> NativePolicySnapshotPublisher:
        publisher = publishers.get(store.guard_home)
        if publisher is None:
            publisher = controlled_policy_publisher(store)
            publishers[store.guard_home] = publisher
        return publisher

    monkeypatch.setattr(native_policy_bundle_sync, "get_native_policy_snapshot_publisher", publisher_for)
    try:
        yield
    finally:
        for publisher in publishers.values():
            publisher.close()
