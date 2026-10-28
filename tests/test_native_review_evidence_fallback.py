"""One resident ask answers a review's policy binding, retry binding and token."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_exact_action as exact


def _evidence(
    tmp_path: Path, command: str = "make build", result: Mapping[str, object] | None = None
) -> tuple[bool, str | None, str | None, str | None]:
    return exact.native_review_evidence(
        harness="codex",
        payload={"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(tmp_path)},
        native_result=result or {"reason": "review"},
        native_receipt=None,
        workspace=tmp_path,
        home_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
    )


def _resident(monkeypatch: pytest.MonkeyPatch, reply: dict[str, Any] | Exception) -> list[dict[str, Any]]:
    asked: list[dict[str, Any]] = []

    def decide(query: Mapping[str, object], _guard_home: Path | None, *_args: object, **kwargs: Any) -> dict[str, Any]:
        asked.append({"query": dict(query), **kwargs})
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(exact, "_decide", decide)
    return asked


def test_one_hook_review_ask_carries_the_whole_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _resident(
        monkeypatch,
        {"kind": "hook_review", "policy_binding_valid": True, "binding": "b", "token": "t", "once_only_reason": None},
    )

    assert _evidence(tmp_path, "echo " + "x" * 1_000_000) == (True, "b", "t", None)
    [ask] = asked
    assert ask["query"]["kind"] == "hook_review"
    assert ask["query"]["payload"]["tool_input"]["command"].endswith("x")
    # The hook bridges cap a payload at 1 MB; the ask must not refuse one.
    assert ask["max_request_bytes"] >= 4 * 1024 * 1024


def test_the_resident_decides_the_policy_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(
        monkeypatch,
        {
            "kind": "hook_review",
            "policy_binding_valid": False,
            "binding": None,
            "token": None,
            "once_only_reason": exact.UNPROVEN_LAUNCH,
        },
    )

    assert _evidence(tmp_path) == (False, None, None, exact.UNPROVEN_LAUNCH)


def test_an_answer_with_neither_token_nor_reason_stays_once_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _resident(
        monkeypatch,
        {"kind": "hook_review", "policy_binding_valid": True, "binding": "b", "token": None, "once_only_reason": None},
    )

    assert _evidence(tmp_path) == (True, "b", None, exact.UNPROVEN_LAUNCH)


def test_a_failed_ask_binds_nothing_and_still_checks_the_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked = _resident(monkeypatch, exact.NativeExactActionError("native_exact_action_unavailable"))

    # A verdict that claims no extension policy needs no receipt.
    assert _evidence(tmp_path) == (True, None, None, exact.UNPROVEN_LAUNCH)
    # One that claims extension policy without a receipt cannot be offered.
    claimed = {"reason": "review", "command_extensions": {"uncertainty_count": 0}}
    assert _evidence(tmp_path, result=claimed) == (False, None, None, exact.UNPROVEN_LAUNCH)
    assert [ask["query"]["kind"] for ask in asked] == ["hook_review", "hook_review"]


def _pause(
    review: Any,
    tmp_path: Path,
    native_result: Mapping[str, object],
    local_cli_rule: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return review.pause_native_pre_tool_for_approval(
        object(),
        harness="codex",
        payload={"tool_name": "Bash", "tool_input": {"command": "make build"}, "cwd": str(tmp_path)},
        native_result=native_result,
        native_receipt=None,
        workspace=tmp_path,
        guard_home=tmp_path / "guard-home",
        local_cli_rule=local_cli_rule,
    )


_REVIEW = {"decision": "deny", "minimum_action": "review", "policy_action": "review"}


def test_a_review_whose_policy_binding_fails_is_denied_before_any_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval as review

    monkeypatch.setattr(review, "native_review_evidence", lambda **_k: pytest.fail("no ask before the binding holds"))
    monkeypatch.setattr(review, "render_pre_tool", lambda _harness, verdict, **_k: dict(verdict))

    # The verdict claims extension policy and no receipt proves it.
    custom = {"blocked": True, "harness_response": {"decision": "deny", "source": "custom"}}
    response = _pause(review, tmp_path, {**_REVIEW, "command_extensions": {"uncertainty_count": 0}}, custom)

    assert response["reason_code"] == "native_review_policy_binding_invalid"
    assert response["policy_action"] == "block"


def test_a_matching_custom_grant_settles_without_the_evidence_ask(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval as review

    granted = {"decision": "allow"}
    monkeypatch.setattr(review, "native_review_evidence", lambda **_k: pytest.fail("a custom grant needs no evidence"))

    assert _pause(review, tmp_path, _REVIEW, local_cli_rule={"blocked": True, "harness_response": granted}) is granted


def test_a_binding_the_resident_rejects_is_denied_before_any_saved_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval as review

    monkeypatch.setattr(review, "native_review_evidence", lambda **_k: (False, "binding", "token", None))
    monkeypatch.setattr(
        review, "native_saved_decision_response", lambda *_a, **_k: pytest.fail("no saved decision without a binding")
    )
    monkeypatch.setattr(review, "render_pre_tool", lambda _harness, verdict, **_k: dict(verdict))

    response = _pause(review, tmp_path, _REVIEW)

    assert response["reason_code"] == "native_review_policy_binding_invalid"
    assert response["policy_action"] == "block"
