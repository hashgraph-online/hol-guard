"""Native reviews whose approval cannot match a retry say so in the scope contract."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract

RESTRICTION = "retry_cannot_reuse_approval"
BOUND_HASH = "native-review-v4:" + "a" * 64 + ":deny:review:review:native_sensitive_access_review"


def _request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "request_id": "11111111111111111111111111111111",
        "harness": "omp",
        "artifact_id": "omp:native-pretool:bash",
        "artifact_name": "bash",
        "artifact_type": "tool_call",
        "artifact_hash": "11111111111111111111111111111111",
        "policy_action": "review",
    }
    request.update(overrides)
    return request


def test_unbound_native_pre_tool_review_is_marked_not_reusable() -> None:
    assert RESTRICTION in request_scope_contract(_request()).restrictions


def test_bound_native_pre_tool_review_keeps_normal_restrictions() -> None:
    contract = request_scope_contract(_request(artifact_hash=BOUND_HASH))
    assert RESTRICTION not in contract.restrictions
    assert "reusable_allow_is_action_bound" in contract.restrictions


@pytest.mark.parametrize("artifact_id", ["omp:mcp:server", "codex:skill:demo", "omp:file:AGENTS.md"])
def test_non_native_pre_tool_requests_are_not_marked(artifact_id: str) -> None:
    assert RESTRICTION not in request_scope_contract(_request(artifact_id=artifact_id)).restrictions


def test_restriction_is_part_of_the_scope_contract_digest() -> None:
    marked = request_scope_contract(_request())
    bound = request_scope_contract(_request(artifact_hash=BOUND_HASH))
    assert marked.digest != bound.digest
    assert RESTRICTION in marked.to_dict()["scope_restrictions"]
