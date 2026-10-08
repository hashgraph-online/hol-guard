from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.cloud_review_settings import cloud_review_settings_status
from codex_plugin_scanner.guard.runtime.cloud_review_event_delivery import _normalize_response
from tests.guard_exact_cloud_review_support import connected_exact_review_store


@pytest.mark.parametrize(
    "changed_field", [None, "legacy", "oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id"]
)
def test_last_delivery_belongs_to_the_current_connection(tmp_path: Path, changed_field: str | None) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    delivered_at = "2026-08-24T12:00:00+00:00"
    delivery_binding = {key: value for key, value in binding.items() if key != "oauth_source"}
    state: dict[str, object] = {"last_delivery_at": delivered_at}
    if changed_field != "legacy":
        if changed_field is not None:
            delivery_binding[changed_field] += "-different"
        state["last_delivery_binding"] = delivery_binding
    store.set_sync_payload("guard_cloud_review_sync_state", state, delivered_at)

    status = cloud_review_settings_status(store)

    assert status["connected"] is True
    assert status["last_synced_at"] == (delivered_at if changed_field is None else None)
    assert status["enabled"] is False
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None


def test_continuation_delivery_is_part_of_cloud_review_activity() -> None:
    result = _normalize_response(
        {
            "protocolVersion": 2,
            "acknowledgedThrough": 1,
            "accepted": 1,
            "rejected": 0,
            "results": [{"eventId": "continuation-event", "status": "accepted"}],
        },
        events=[{"eventId": "continuation-event", "eventType": "review.continuation.result", "localStreamSequence": 1}],
        sequences=[1],
    )

    assert result["delivered"] == 1
