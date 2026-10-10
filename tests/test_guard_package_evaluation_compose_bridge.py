"""Reply validation and fail-closed behavior of the package compose bridge."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from codex_plugin_scanner.guard import local_supply_chain as lsc
from codex_plugin_scanner.guard import native_package_evaluation_compose as compose
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import SupplyChainUserCopy


@dataclass(frozen=True)
class _Evaluation:
    policy_action: str = "review"
    decision: str = "ask"
    reasons: tuple[dict[str, object], ...] = ()
    packages: tuple[dict[str, object], ...] = ({"name": "demo"},)
    risk_summary: str = ""
    user_copy: Any = field(default_factory=lambda: SupplyChainUserCopy("t", "s", None, None, "h"))
    record_monitor_evidence: bool = True


_COPY = {"title": "t", "summary": "s", "next_step": None, "dashboard_url": None, "harness_message": "h"}


def _full(action: str, decision: str) -> dict[str, object]:
    return {
        "decision": decision,
        "policy_action": action,
        "reasons": [{"code": "x"}],
        "risk_summary": "r",
        "user_copy": dict(_COPY),
        "record_monitor_evidence": False,
    }


def _reply(monkeypatch: pytest.MonkeyPatch, patch: object) -> None:
    def fake(**kwargs: Any) -> dict[str, object]:
        request = kwargs["request"]
        return {
            "schema": compose._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + compose._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": {"patch": patch},
        }

    monkeypatch.setattr(compose, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(compose, "_resident_request", fake)


FACTS: dict[str, dict[str, object]] = {
    "saved_block": {"approval_reuse": {"action": "block"}, "clear_command": "c"},
    "saved_allow": {"approval_reuse": {"action": "allow"}, "variant": "reused"},
    "external_archive_override": {"variant": "mcp_unbound"},
    "current_policy_action": {"current_action": "block"},
    "rejected_reuse": {"approval_reuse": {"action": "block"}},
}
BLOCKS = ("saved_block", "external_archive_override", "current_policy_action", "rejected_reuse")


@pytest.mark.parametrize("kind", sorted(FACTS))
def test_empty_patch_is_rejected_for_verdict_kinds(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    _reply(monkeypatch, {})
    with pytest.raises(compose.NativePackageEvaluationComposeError):
        compose.compose_package_evaluation(kind, _Evaluation(), **FACTS[kind])


@pytest.mark.parametrize("kind", BLOCKS)
def test_partial_and_wrong_action_patches_are_rejected(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    for patch in (
        {"policy_action": "block"},  # missing decision / copy
        _full("allow", "allow"),  # verdict contradicts the request
        _full("bogus", "block"),
        {**_full("block", "block"), "decision": "nope"},
        {**_full("block", "block"), "user_copy": {**_COPY, "title": 3}},
        {**_full("block", "block"), "user_copy": {**_COPY, "next_step": 5}},
    ):
        _reply(monkeypatch, patch)
        with pytest.raises(compose.NativePackageEvaluationComposeError):
            compose.compose_package_evaluation(kind, _Evaluation(), **FACTS[kind])


def test_valid_block_patch_is_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    _reply(monkeypatch, _full("block", "block"))
    result = compose.compose_package_evaluation("saved_block", _Evaluation(), **FACTS["saved_block"])
    assert (result.policy_action, result.decision) == ("block", "block")


@pytest.mark.parametrize("kind", ["saved_block", "external_archive_override", "rejected_reuse"])
def test_blocking_compose_fails_closed(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    monkeypatch.setattr(compose, "ensure_resident_prerequisite", lambda _home: False)
    result = lsc.compose_blocking_package_evaluation(kind, _Evaluation(policy_action="allow"), **FACTS[kind])
    assert result.policy_action == "block"
    assert result.reasons[0]["code"] == "native_package_evaluation_unavailable"
    assert all(item["decision"] == "block" for item in result.packages)


def test_archive_override_variants_never_allow_when_resident_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compose, "ensure_resident_prerequisite", lambda _home: False)
    for variant in ("launch_unbound", "mcp_unbound", "binding_unavailable", "shim_delegated"):
        result = lsc.package_external_archive_override(_Evaluation(policy_action="allow"), variant=variant)
        assert result.policy_action == "block"


def test_allow_paths_still_raise_when_resident_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compose, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(compose.NativePackageEvaluationComposeError):
        lsc.compose_package_evaluation("saved_allow", _Evaluation(), **FACTS["saved_allow"])


def test_identity_current_policy_rewrite_skips_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("resident must not be consulted")

    monkeypatch.setattr(compose, "ensure_resident_prerequisite", boom)
    evaluation = _Evaluation(policy_action="review")
    assert lsc._package_evaluation_with_current_policy_action(evaluation, current_action="review") is evaluation
