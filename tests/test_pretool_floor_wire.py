"""The PreToolUse floor, asked of the resident through ``HookDecide``.

The resident decides whether its pre-tool review floors a PreToolUse verdict,
and at which action. These pin the transport: the query it sends, the reply it
accepts, and that anything else is a ``NativeHookDecisionError`` the hook
answers with the host outage response.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_pretool_floor as floor_module
from codex_plugin_scanner.guard import native_pretool as pretool
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError

_REVIEW = {"minimum_action": "review", "reason_code": "native_destructive_review"}


def _resident_answering(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any], asked: list[Any]) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(
            features={"resident-protocol-v2", floor_module.HOOK_DECISION_PRETOOL_FLOOR_FEATURE}
        ),
    )
    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)

    def transport(*, request: dict[str, Any], required_feature: str, **_kwargs: object) -> dict[str, Any]:
        asked.append((required_feature, request["query"]))
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }

    monkeypatch.setattr(floor_module, "_resident_request", transport)


@pytest.mark.parametrize("floor", ["review", "sandbox-required", "require-reapproval", "block", None])
def test_a_bound_floor_is_decoded_behind_its_capability(monkeypatch: pytest.MonkeyPatch, floor: str | None) -> None:
    asked: list[Any] = []
    _resident_answering(monkeypatch, {"kind": "pretool_floor", "floor": floor}, asked)
    review = {**_REVIEW, "decision": "deny", "reason": "ignored", "command_model": {}}
    assert floor_module.native_pretool_floor(review, guard_home=None) == floor
    # Only the two facts the floor depends on are sent.
    assert asked == [
        (
            floor_module.HOOK_DECISION_PRETOOL_FLOOR_FEATURE,
            {"kind": "pretool_floor", "inputs": _REVIEW},
        )
    ]


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "pretool_floor"},
        {"kind": "pretool_floor", "floor": "deny"},
        {"kind": "pretool_floor", "floor": 1},
        {"kind": "pretool_floor", "floor": "review", "extra": True},
        {"kind": "hook_route", "floor": "review"},
    ],
)
def test_a_malformed_floor_is_an_outage_not_a_floor(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]) -> None:
    _resident_answering(monkeypatch, payload, [])
    with pytest.raises(NativeHookDecisionError):
        floor_module.native_pretool_floor(_REVIEW, guard_home=None)


@pytest.mark.parametrize(
    "review",
    [
        {"minimum_action": "deny", "reason_code": "r"},
        {"minimum_action": "review", "reason_code": ""},
        {"minimum_action": "review"},
        {"reason_code": "r"},
    ],
)
def test_a_malformed_review_is_never_sent(monkeypatch: pytest.MonkeyPatch, review: dict[str, Any]) -> None:
    asked: list[Any] = []
    _resident_answering(monkeypatch, {"kind": "pretool_floor", "floor": "block"}, asked)
    with pytest.raises(NativeHookDecisionError):
        floor_module.native_pretool_floor(review, guard_home=None)
    assert asked == []


def _legacy_review(command: str, action: str) -> dict[str, Any]:
    return {
        "decision": "deny",
        "minimum_action": action,
        "policy_action": action,
        "reason_code": "native_reason",
        "reason": "A reason.",
        "explicitly_benign": False,
        "command_model": {"normalized_text": command},
    }


@pytest.mark.parametrize("action", ["sandbox-required", "require-reapproval"])
def test_only_the_floor_path_admits_containment_and_reapproval(action: str) -> None:
    # The resident's pre-tool review answers these for contained Git reads and
    # privileged wrappers. The floor path routes them; the old floor rejected
    # them as a failed review and collapsed the verdict to a block.
    review = _legacy_review("git status", action)
    assert pretool._decode_pre_tool(review, command="git status", full_lattice=True) == review
    assert pretool._decode_pre_tool(review, command="git status") is None


def test_a_review_floor_keeps_allow_once_and_always_allow(native_approval_reuse_runtime: Path) -> None:
    # A review floor stays the review tier, whose card offers Allow once and
    # Always allow; the resident never raises it to a terminal action.
    home = native_approval_reuse_runtime
    assert floor_module.native_pretool_floor(_REVIEW, guard_home=home) == "review"
    reapproval = {"minimum_action": "require-reapproval", "reason_code": "native_privileged_wrapper_reapproval"}
    assert floor_module.native_pretool_floor(reapproval, guard_home=home) == "require-reapproval"


def test_the_resident_floor_matches_the_retired_python_floor(native_approval_reuse_runtime: Path) -> None:
    home = native_approval_reuse_runtime
    cases = {
        ("allow", "native_exact_safe_command"): "allow",
        ("block", "native_destructive_command"): "block",
        # The contextual git-helper review is settled from the hook's own facts.
        ("review", "native_git_helper_context_review"): None,
        # The retired floor turned this into a block; it keeps its sandbox-required tier.
        ("sandbox-required", "native_git_readonly_containment_required"): "sandbox-required",
    }
    for (action, reason_code), expected in cases.items():
        review = {"minimum_action": action, "reason_code": reason_code}
        assert floor_module.native_pretool_floor(review, guard_home=home) == expected, review
