"""Display projections must not become exact-approval authority."""

from __future__ import annotations

from copy import deepcopy

import pytest

from codex_plugin_scanner.guard.store_exact_cloud_review import _changed_request_fields


def test_explanation_is_excluded_from_exact_request_comparison() -> None:
    persisted = {"request_id": "one", "action_identity": "identity", "status": "pending"}
    decorated = {**persisted, "action_explanation": {"renderer_version": "1.0.0"}}
    assert _changed_request_fields(persisted, decorated) == []
    changed_copy = {**decorated, "action_explanation": {"renderer_version": "2.0.0"}}
    assert _changed_request_fields(decorated, changed_copy) == []


@pytest.mark.parametrize(
    "field",
    ["action_identity", "action_envelope_json", "policy_action", "allowed_scopes", "status", "raw_command_text"],
)
def test_explanation_cannot_hide_a_changed_persisted_approval_input(field: str) -> None:
    original = {field: "before", "action_explanation": {"action_identity": "unchanged"}}
    changed = deepcopy(original)
    changed[field] = "after"
    assert _changed_request_fields(original, changed) == [field]


def test_unknown_request_fields_still_participate_in_exact_comparison() -> None:
    assert _changed_request_fields({}, {"future_authority_field": "new"}) == ["future_authority_field"]
