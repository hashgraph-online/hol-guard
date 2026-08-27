from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_queue
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    enable_exact_cloud_review,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import connected_exact_review_store
from tests.guard_review_signing_helpers import review_trusted_keyring_payload


def no_generic_operations(_store: GuardStore) -> tuple[str, ...]:
    return ()


@pytest.fixture
def exact_review_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GuardStore:
    store = connected_exact_review_store(tmp_path)
    _ = enable_exact_cloud_review(store)
    monkeypatch.setattr(command_queue, "command_capability_operations", no_generic_operations)
    return store


def test_exact_review_lease_waits_for_workspace_keyring(exact_review_store: GuardStore) -> None:
    now = datetime.now(timezone.utc).isoformat()
    exact_review_store.set_sync_payload("guard_review_verification_keyring", [], now)

    assert command_queue.lease_ready_operations(exact_review_store) == ()

    exact_review_store.set_sync_payload(
        "guard_review_verification_keyring",
        review_trusted_keyring_payload(workspace_id="workspace-1"),
        now,
    )

    assert command_queue.lease_ready_operations(exact_review_store) == (EXACT_CLOUD_REVIEW_OPERATION,)


def test_exact_review_lease_rejects_other_workspace_keyring(exact_review_store: GuardStore) -> None:
    exact_review_store.set_sync_payload(
        "guard_review_verification_keyring",
        review_trusted_keyring_payload(workspace_id="workspace-2"),
        datetime.now(timezone.utc).isoformat(),
    )

    assert command_queue.lease_ready_operations(exact_review_store) == ()


def test_generic_queue_operations_continue_before_review_key_sync(
    exact_review_store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def generic_operations(_store: GuardStore) -> tuple[str, ...]:
        return ("guard.packageShims.status",)

    exact_review_store.set_sync_payload(
        "guard_review_verification_keyring",
        [],
        datetime.now(timezone.utc).isoformat(),
    )
    monkeypatch.setattr(command_queue, "command_capability_operations", generic_operations)

    assert command_queue.lease_ready_operations(exact_review_store) == ("guard.packageShims.status",)
