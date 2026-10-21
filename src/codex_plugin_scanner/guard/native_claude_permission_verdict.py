"""Claude Code's permission-dialog verdict, answered by the native runtime.

The CLI hook peeks the session's pending Guard notice and sends it with
whether a runtime artifact was found. The resident picks the verdict: no
decision, the Guard approval question, a review that defers to Claude's
dialog, or a deny. When the verdict rests on the artifact's policy the
resident asks for it by name, and only then is it gathered. A reply that is
not a bound, strictly decoded ``ok`` with a consistent verdict raises
``NativeHookDecisionError`` and the caller answers with the host outage
response, so a verdict is never guessed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .native_hook_decision import _INVALID, NativeHookDecisionError, _decide, _shape

HOOK_DECISION_CLAUDE_PERMISSION_VERDICT_FEATURE = "hook-decision-claude-permission-verdict-v1"
ARTIFACT_POLICY_FACT = "artifact_policy"

_OPT_STR = (str, type(None))
_VERDICT_FIELDS: Mapping[str, Any] = {
    "verdict": str,
    "policy_action": _OPT_STR,
    "offers_approval": bool,
    "reason": _OPT_STR,
    "reason_from_artifact": bool,
    "artifact_action": _OPT_STR,
}
# The action each verdict renders, and whether it offers a way to approve.
_VERDICT_SHAPES: Mapping[str, tuple[frozenset[str | None], bool]] = {
    "passthrough": (frozenset({None}), False),
    "guard_question": (frozenset({"block"}), True),
    "review": (frozenset({"require-reapproval"}), True),
    "deny": (frozenset({"block", "sandbox-required"}), False),
}
# The artifact actions each verdict may rest on.
_ARTIFACT_ACTIONS: Mapping[str, frozenset[str]] = {
    "review": frozenset({"review", "require-reapproval"}),
    "deny": frozenset({"block", "sandbox-required"}),
}


@dataclass(frozen=True)
class ClaudePermissionVerdict:
    """The resident's verdict for one Claude permission dialog."""

    verdict: str
    policy_action: str | None
    offers_approval: bool
    reason: str | None
    reason_from_artifact: bool
    artifact_action: str | None


def _verdict(value: object, *, artifact_policy_sent: bool) -> ClaudePermissionVerdict:
    fields = _shape(value, _VERDICT_FIELDS)
    answer = ClaudePermissionVerdict(**fields)
    shape = _VERDICT_SHAPES.get(answer.verdict)
    if shape is None or answer.policy_action not in shape[0] or answer.offers_approval is not shape[1]:
        raise NativeHookDecisionError(_INVALID)
    if (answer.verdict == "passthrough") != (answer.reason is None):
        raise NativeHookDecisionError(_INVALID)
    if answer.reason_from_artifact != (answer.artifact_action is not None):
        raise NativeHookDecisionError(_INVALID)
    if answer.reason_from_artifact and (
        not artifact_policy_sent
        or answer.artifact_action not in _ARTIFACT_ACTIONS.get(answer.verdict, frozenset())
        or (answer.verdict == "deny" and answer.artifact_action != answer.policy_action)
    ):
        raise NativeHookDecisionError(_INVALID)
    return answer


def native_claude_permission_verdict(
    *,
    notice: Mapping[str, object] | None,
    runtime_artifact_present: bool,
    artifact_policy: Callable[[], Mapping[str, object]],
    guard_home: Path | None = None,
) -> ClaudePermissionVerdict:
    """The verdict for this dialog; ``artifact_policy`` runs only if asked for.

    ``artifact_policy`` returns ``config_action`` and ``package_action`` (the
    package evaluation's action, ``None`` for any other artifact).
    """

    gathered: Mapping[str, object] | None = None

    def validate(payload: dict[str, Any]) -> None:
        if set(payload) != {"kind", "needs_facts", "verdict"}:
            raise NativeHookDecisionError(_INVALID)
        needs, verdict = payload["needs_facts"], payload["verdict"]
        if needs == [ARTIFACT_POLICY_FACT] and gathered is None and runtime_artifact_present and verdict is None:
            return
        if needs != [] or verdict is None:
            raise NativeHookDecisionError(_INVALID)
        _verdict(verdict, artifact_policy_sent=gathered is not None)

    for _ in range(2):
        payload = _decide(
            {
                "kind": "claude_permission_verdict",
                "inputs": {
                    "notice": None if notice is None else dict(notice),
                    "runtime_artifact_present": runtime_artifact_present,
                    "artifact_policy": None if gathered is None else dict(gathered),
                },
            },
            guard_home,
            validate,
            HOOK_DECISION_CLAUDE_PERMISSION_VERDICT_FEATURE,
        )
        if payload["verdict"] is not None:
            return _verdict(payload["verdict"], artifact_policy_sent=gathered is not None)
        gathered = dict(artifact_policy())
    raise NativeHookDecisionError(_INVALID)


__all__ = [
    "ARTIFACT_POLICY_FACT",
    "HOOK_DECISION_CLAUDE_PERMISSION_VERDICT_FEATURE",
    "ClaudePermissionVerdict",
    "native_claude_permission_verdict",
]
