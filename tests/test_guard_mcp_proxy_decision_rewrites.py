"""The proxy's decision rewrites keep the enforced action the resident named.

Three proxy paths replace a tool decision after the resident has routed it: the
saved-allow gate, the observe-mode override and the package forward. Each one
changes ``action``, so each must also carry the ``policy_action`` the resident
derived for the rewritten decision. Receipts and scanner evidence read that
field, so a stale value would record an action the call never enforced.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

from codex_plugin_scanner.guard.mcp_tool_calls import (
    ToolCallDecision,
    resolve_tool_call_policy_action,
)
from codex_plugin_scanner.guard.proxy.runtime_mcp import (
    RuntimeMcpGuardProxy,
    _tool_decision_after_runtime_allow,
)

# The gate reads the store only when the caller has no verdict to present, and
# every case here supplies one.
NO_PROXY = cast(RuntimeMcpGuardProxy, cast(object, None))

PENDING = ToolCallDecision(
    action="allow",
    source="policy",
    signals=(),
    summary="",
    policy_action="allow",
    pending_approval_reuse_decision={"status": "accepted"},
)


def test_the_saved_allow_gate_carries_its_own_enforced_action() -> None:
    gate: dict[str, Any] = {
        "disable": True,
        "action": "review",
        "policy_action": "require-reapproval",
        "source": "tool-catalog-state",
        "summary": "catalog incomplete",
        "approval_reuse_status": "rejected",
        "approval_reuse_reason_code": "approval_reuse_tool_catalog_incomplete",
    }

    gated = RuntimeMcpGuardProxy._apply_saved_allow_gate(NO_PROXY, PENDING, gate)

    assert gated.action == "review"
    assert resolve_tool_call_policy_action(gated) == "require-reapproval"
    assert gated.pending_approval_reuse_decision is None


def test_a_gate_that_stays_open_leaves_the_decision_alone() -> None:
    assert RuntimeMcpGuardProxy._apply_saved_allow_gate(NO_PROXY, PENDING, {"disable": False}) is PENDING


def test_the_observe_override_carries_its_own_enforced_action() -> None:
    override: dict[str, Any] = {
        "action": "review",
        "policy_action": "require-reapproval",
        "source": "observe-current-policy",
    }

    overridden = RuntimeMcpGuardProxy._apply_decision_override(PENDING, override)

    assert overridden.action == "review"
    assert resolve_tool_call_policy_action(overridden) == "require-reapproval"
    assert overridden.pending_approval_reuse_decision is None


def test_no_override_leaves_the_decision_alone() -> None:
    assert RuntimeMcpGuardProxy._apply_decision_override(PENDING, None) is PENDING


def test_the_package_forward_carries_the_resident_s_enforced_action() -> None:
    stale = replace(PENDING, action="review", policy_action="require-reapproval")

    forwarded = _tool_decision_after_runtime_allow(stale, source="native-approved", policy_action="allow")

    assert forwarded.action == "allow"
    assert forwarded.source == "native-approved"
    assert resolve_tool_call_policy_action(forwarded) == "allow"
    assert forwarded.pending_approval_reuse_decision is None
