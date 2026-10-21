from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import add_review_request, review_request


def _resolve(
    store: GuardStore,
    request_id: str,
    expected_request: Mapping[str, object] | object,
    *,
    action: str = "allow",
) -> dict[str, object]:
    return store.resolve_native_workspace_review_request(
        request_id,
        resolution_action=action,
        expected_request=cast(Mapping[str, object], expected_request),
        resolved_at="2026-09-27T00:00:00+00:00",
        native_replayed=False,
    )


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("deny", "native_workspace_review_decision_invalid"),
        ("allow_once", "native_workspace_review_decision_invalid"),
    ],
)
def test_native_store_rejects_invalid_resolution_actions(
    tmp_path: Path,
    action: str,
    expected: str,
) -> None:
    result = _resolve(GuardStore(tmp_path / action), "missing", {}, action=action)
    assert result == {"resolved": False, "error": expected}


def test_native_store_rejects_invalid_expected_snapshots(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "invalid-snapshot")
    assert _resolve(store, "missing", object()) == {
        "resolved": False,
        "error": "native_workspace_review_request_invalid",
    }


def test_native_store_distinguishes_missing_stale_resolved_and_nonpending_rows(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "states")
    assert _resolve(store, "missing", {}) == {
        "resolved": False,
        "error": "native_workspace_review_request_missing",
    }

    stale_request = review_request("stale")
    add_review_request(store, stale_request)
    current = store.get_approval_request("stale")
    assert isinstance(current, dict)
    stale_expected = {**current, "launch_target": "different command"}
    assert _resolve(store, "stale", stale_expected) == {
        "resolved": False,
        "error": "native_workspace_review_request_stale",
    }

    resolved_request = review_request("resolved")
    add_review_request(store, resolved_request)
    current = store.get_approval_request("resolved")
    assert isinstance(current, dict)
    first = _resolve(store, "resolved", current)
    assert first["resolved"] is True
    replay = _resolve(store, "resolved", current)
    assert replay["resolved"] is True
    assert replay["replayed"] is True
    assert _resolve(store, "resolved", current, action="block") == {
        "resolved": False,
        "error": "native_workspace_review_request_resolved",
    }

    nonpending_request = review_request("nonpending")
    add_review_request(store, nonpending_request)
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set status = 'cancelled' where request_id = ?",
            ("nonpending",),
        )
    current = store.get_approval_request("nonpending")
    assert isinstance(current, dict)
    assert _resolve(store, "nonpending", current) == {
        "resolved": False,
        "error": "native_workspace_review_request_not_pending",
    }


def test_native_store_enforces_terminal_policy_before_persisting(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "terminal")
    request = review_request("terminal")
    add_review_request(store, request)
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set policy_action = 'block' where request_id = ?",
            ("terminal",),
        )
    current = store.get_approval_request("terminal")
    assert isinstance(current, dict)
    result = _resolve(store, "terminal", current)
    assert result == {
        "resolved": False,
        "error": "native_workspace_review_request_invalid",
    }
