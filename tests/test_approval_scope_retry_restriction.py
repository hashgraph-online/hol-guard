"""Native reviews whose approval cannot match a retry say so in the scope contract."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.approval_scope_support import (
    RETRY_CANNOT_REUSE_APPROVAL,
    ApprovalScopeContract,
    _contract_from_native,
    request_scope_contract,
)

# The Python constant must name the restriction the resident actually emits.
RESTRICTION = RETRY_CANNOT_REUSE_APPROVAL
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
    contract = request_scope_contract(_request())
    assert RESTRICTION in contract.restrictions
    assert contract.allow_scopes == ()
    assert contract.block_scopes == ("artifact",)
    assert not contract.can_run_once
    assert not contract.can_persist_exact_version
    assert contract.to_dict()["execution_approval"] == {
        "schema": "guard.execution-approval.v1",
        "can_record_decision": True,
        "can_run_once": False,
        "can_persist_exact_version": False,
        "delivery_reason": "execution_binding_unavailable",
    }


def test_bound_native_pre_tool_review_keeps_normal_restrictions() -> None:
    contract = request_scope_contract(_request(artifact_hash=BOUND_HASH))
    assert RESTRICTION not in contract.restrictions
    assert "reusable_allow_is_action_bound" in contract.restrictions
    assert contract.can_run_once


def test_script_without_delivery_owner_cannot_borrow_a_bound_retry(native_context_digest) -> None:
    from codex_plugin_scanner.guard.runtime.approval_context import build_approval_context_token

    token = build_approval_context_token(
        identity={"command": "cat notes.txt"},
        content={},
        capabilities={},
        policy={},
        sandbox={},
    )
    assert isinstance(token, str)
    envelope = {"exact_context_token": token}
    request = _request(
        artifact_hash=BOUND_HASH,
        raw_command_text="cat notes.txt",
        action_envelope_json=envelope,
    )
    eligible = request_scope_contract(request)
    assert eligible.can_run_once and eligible.can_persist_exact_version
    envelope["once_only_reason"] = "script_execution_binding_unavailable"
    contract = request_scope_contract(request)
    assert RESTRICTION in contract.restrictions
    assert not contract.can_run_once
    assert not contract.can_persist_exact_version
    assert contract.allow_scopes == ()


@pytest.mark.parametrize("artifact_id", ["omp:mcp:server", "codex:skill:demo", "omp:file:AGENTS.md"])
def test_non_native_pre_tool_requests_are_not_marked(artifact_id: str) -> None:
    assert RESTRICTION not in request_scope_contract(_request(artifact_id=artifact_id)).restrictions


def test_restriction_is_part_of_the_scope_contract_digest() -> None:
    marked = request_scope_contract(_request())
    bound = request_scope_contract(_request(artifact_hash=BOUND_HASH))
    assert marked.digest != bound.digest
    restrictions = marked.to_dict()["scope_restrictions"]
    assert isinstance(restrictions, list) and RESTRICTION in restrictions


def test_contradictory_or_unknown_capability_projection_is_rejected() -> None:
    contract = ApprovalScopeContract(
        allow_scopes=(),
        block_scopes=("artifact",),
        recommended_allow_scope=None,
        recommended_block_scope="artifact",
        restrictions=(RESTRICTION,),
        digest="a" * 64,
    )
    payload = contract.to_dict()
    assert _contract_from_native(payload) == contract
    execution = payload["execution_approval"]
    assert isinstance(execution, dict)
    payload["execution_approval"] = {**execution, "can_run_once": 0}
    assert _contract_from_native(payload) is None
    payload["execution_approval"] = {
        "schema": "guard.execution-approval.v1",
        "can_record_decision": True,
        "can_run_once": True,
        "can_persist_exact_version": False,
        "delivery_reason": None,
    }
    assert _contract_from_native(payload) is None
    payload["execution_approval"] = {"schema": "guard.execution-approval.v999"}
    assert _contract_from_native(payload) is None
    # A legacy resident still carries the authoritative restriction; absence
    # of the additive projection cannot turn it into executable once consent.
    del payload["execution_approval"]
    parsed = _contract_from_native(payload)
    assert parsed is not None and not parsed.can_run_once
