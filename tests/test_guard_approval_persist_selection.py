"""The persistence half of the resident's one-ask selection, translated for its callers."""

from __future__ import annotations

from typing import Any

import pytest

from codex_plugin_scanner.guard import native_approval_scope_select as adapter
from codex_plugin_scanner.guard.approval_scope_selection import resolve_request_scope_selection
from codex_plugin_scanner.guard.approval_scope_support import (
    ApprovalScopeContract,
    IneligibleApprovalScopeError,
    StaleApprovalScopeContractError,
)
from codex_plugin_scanner.guard.native_approval_scope import ApprovalScopeUnavailableError

_REQUEST: dict[str, object] = {
    "artifact_id": "pkg:npm/left-pad",
    "artifact_type": "package_request",
    "artifact_hash": "sha256:left-pad",
    "policy_action": "review",
}


def _contract(*, persistable: bool = True) -> dict[str, object]:
    return ApprovalScopeContract(
        allow_scopes=("artifact",),
        block_scopes=("artifact",),
        recommended_allow_scope="artifact",
        recommended_block_scope="artifact",
        restrictions=("reusable_allow_is_action_bound",),
        digest="a" * 64,
        exact_action_persistence_eligible=persistable,
    ).to_dict() | {"exact_context_token": "token-1"}


def _answer(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def answer(_item: object, **kwargs: Any) -> dict[str, object]:
        calls.append(kwargs)
        return payload

    monkeypatch.setattr(adapter, "native_approval_scope_selection", answer)
    return calls


def _selected(persist_policy: bool | None, *, warning: str | None = None) -> dict[str, object]:
    return {
        "outcome": "selected",
        "requested_scope": "artifact",
        "applied_scope": "artifact",
        "warning": warning,
        "persist_policy": persist_policy,
        "contract": _contract(),
    }


def _resolve(**overrides: Any) -> bool | None:
    return _select(**overrides).persist_policy


def _select(**overrides: Any) -> Any:
    arguments: dict[str, Any] = {
        "action": "allow",
        "requested_scope": "artifact",
        "persist_policy": True,
        "ask_persistence": True,
        "contract_version": None,
        "contract_digest": None,
    }
    arguments.update(overrides)
    return resolve_request_scope_selection(_REQUEST, **arguments)


def test_the_resident_decides_whether_the_decision_is_remembered(monkeypatch: pytest.MonkeyPatch) -> None:
    for selected in (True, None):
        calls = _answer(monkeypatch, _selected(selected))
        assert _resolve(persist_policy=True) is selected
        # Nothing about the request is decided here, so everything the contract
        # is derived from reaches the resident in the same ask as the scope.
        assert calls[0]["action"] == "allow"
        assert calls[0]["requested_scope"] == "artifact"
        assert calls[0]["persist_policy"] is True


def test_the_one_ask_hands_back_the_contract_and_exact_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, _selected(True))
    selection = _select()
    assert selection.applied_scope == "artifact"
    assert selection.contract is not None
    assert selection.contract.digest == "a" * 64
    assert selection.exact_token == "token-1"


def test_a_selection_that_asks_nothing_about_persistence_sends_no_question(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.native_approval_scope_select import PERSIST_NOT_ASKED

    calls = _answer(monkeypatch, _selected(None))
    _select(ask_persistence=False)
    assert calls[0]["persist_policy"] is PERSIST_NOT_ASKED


def test_an_answer_that_skips_the_persistence_question_saves_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = _selected(True)
    del answer["persist_policy"]
    _answer(monkeypatch, answer)
    with pytest.raises(ApprovalScopeUnavailableError):
        _select()


@pytest.mark.parametrize(
    ("action", "reason"),
    [
        ("allow", "saved_allow_scope_ineligible"),
        ("block", "saved_block_scope_ineligible"),
        ("allow", "execution_binding_unavailable"),
    ],
)
def test_a_refused_resolution_names_what_the_request_offers(
    monkeypatch: pytest.MonkeyPatch, action: str, reason: str
) -> None:
    _answer(
        monkeypatch,
        {
            "outcome": "refused",
            "reason": reason,
            "applied_scope": "artifact",
            "contract": _contract(persistable=False),
        },
    )
    with pytest.raises(IneligibleApprovalScopeError) as raised:
        _resolve(action=action)
    assert str(raised.value) == reason
    assert raised.value.action == action
    assert raised.value.requested_scope == "artifact"
    assert raised.value.contract.digest == "a" * 64


def test_a_superseded_contract_is_reported_as_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, {"outcome": "refused", "reason": "stale_scope_contract", "contract": _contract()})
    with pytest.raises(StaleApprovalScopeContractError):
        _resolve(contract_version="guard.approval-scopes.v1", contract_digest="b" * 64)


def test_an_answer_this_module_cannot_read_saves_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    for payload in (
        {"outcome": "deferred", "contract": _contract()},
        _selected(True) | {"persist_policy": "yes"},
        _selected(True) | {"contract": None},
        # A refusal with no contract leaves the caller nothing to report.
        {
            "outcome": "refused",
            "reason": "execution_binding_unavailable",
            "applied_scope": "artifact",
            "contract": None,
        },
        {"outcome": "refused", "reason": "something_new", "contract": _contract()},
    ):
        _answer(monkeypatch, payload)
        with pytest.raises(ApprovalScopeUnavailableError):
            _resolve()
