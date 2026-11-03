"""The approval resolution gate asks the resident and never decides locally."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import approval_resolution
from codex_plugin_scanner.guard import native_approval_resolution_eligibility as eligibility
from codex_plugin_scanner.guard.native_approval_resolution_eligibility import (
    ApprovalResolutionEligibilityUnavailableError,
)


def test_a_block_reason_is_whatever_the_resident_answered(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[dict[str, object]]] = []

    def fake(requests, *, guard_home=None):  # type: ignore[no-untyped-def]
        captured.append([dict(request) for request in requests])
        return ["terminal_policy_action_not_resolvable"]

    monkeypatch.setattr(approval_resolution, "native_approval_resolution_block_reasons", fake)
    request = {"policy_action": "block", "decision_contract_error": None}
    assert approval_resolution.approval_resolution_block_reason(request) == "terminal_policy_action_not_resolvable"
    assert captured == [[request]]


def test_a_batch_keeps_the_callers_order(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(requests, *, guard_home=None):  # type: ignore[no-untyped-def]
        return [None, "authoritative_decision_inconsistent", None]

    monkeypatch.setattr(approval_resolution, "native_approval_resolution_block_reasons", fake)
    assert approval_resolution.approval_resolution_block_reasons(
        [{"policy_action": "review"}, {"policy_action": "nonsense"}, {"policy_action": "warn"}]
    ) == [None, "authoritative_decision_inconsistent", None]


def test_a_refusal_raises_at_the_mutation_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        approval_resolution,
        "native_approval_resolution_block_reasons",
        lambda requests, *, guard_home=None: ["terminal_policy_action_not_resolvable"],
    )
    with pytest.raises(ValueError, match="terminal_policy_action_not_resolvable"):
        approval_resolution.require_resolvable_approval_request({"policy_action": "block"})


def test_a_resolvable_row_passes_the_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        approval_resolution,
        "native_approval_resolution_block_reasons",
        lambda requests, *, guard_home=None: [None],
    )
    approval_resolution.require_resolvable_approval_request({"policy_action": "review"})


def test_an_unavailable_resident_never_reads_as_resolvable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(requests, *, guard_home=None):  # type: ignore[no-untyped-def]
        raise ApprovalResolutionEligibilityUnavailableError

    monkeypatch.setattr(approval_resolution, "native_approval_resolution_block_reasons", unavailable)
    with pytest.raises(ApprovalResolutionEligibilityUnavailableError):
        approval_resolution.require_resolvable_approval_request({"policy_action": "review"})
    with pytest.raises(ApprovalResolutionEligibilityUnavailableError):
        approval_resolution.approval_resolution_block_reason({"policy_action": "block"})


def test_an_empty_batch_asks_the_resident_nothing() -> None:
    assert approval_resolution.approval_resolution_block_reasons([]) == []


def test_a_sweep_wider_than_the_contract_cap_is_asked_in_batches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The resident refuses an over-long request, so the adapter never sends one."""

    batch_sizes: list[int] = []

    def fake_request(**kwargs):  # type: ignore[no-untyped-def]
        batch_sizes.append(len(kwargs["request"]["items"]))
        return kwargs["request"]

    def fake_payload(response, wire, home):  # type: ignore[no-untyped-def]
        return {"reasons": [item["policy_action"] for item in wire["items"]]}

    monkeypatch.setattr(eligibility, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(eligibility, "_resident_request", fake_request)
    monkeypatch.setattr(eligibility, "_payload", fake_payload)

    rows = [{"policy_action": f"row-{index}"} for index in range(2500)]
    answers = eligibility.native_approval_resolution_block_reasons(rows)

    assert batch_sizes == [1024, 1024, 452]
    assert answers == [f"row-{index}" for index in range(2500)]
