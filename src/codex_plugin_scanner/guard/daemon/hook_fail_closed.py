"""Hook responses the daemon renders itself.

Rust renders every real hook response. This module keeps only the fixed,
deny-only payloads used when the resident cannot render one. It never computes
an allow and never mirrors Rust decision logic. Which envelope each harness and
event gets is declared once in ``guard/contracts/hook-fail-closed-envelopes.v1.json``,
and a Rust test holds every envelope there to the deny shape the Rust renderer
gives the same harness; this module only fills in the reason. When the
resident already reached a blocking verdict, that deny carries the verdict's
own reason and reason code, so a render that misses its deadline still tells
the user why.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from ..approval_link_output import native_review_reason
from ..native_hook_render import (
    native_render_pre_tool,
    native_render_pre_tool_review,
    native_render_recording_only_pre_tool,
)

ENVELOPES_CONTRACT_PATH: Final = (
    Path(__file__).resolve().parent.parent / "contracts" / "hook-fail-closed-envelopes.v1.json"
)
_ENVELOPES_SCHEMA: Final = "hol-guard.hook-fail-closed-envelopes.v1"
_ENVELOPE_KINDS: Final = ("pre_tool", "permission", "prompt", "lifecycle", "unmanaged")


def _load_contract() -> dict[str, Any]:
    document = json.loads(ENVELOPES_CONTRACT_PATH.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema") != _ENVELOPES_SCHEMA:
        raise ValueError("hook_fail_closed_envelopes_contract_invalid: schema")
    envelopes = document.get("envelopes")
    if not isinstance(envelopes, dict) or any(
        not isinstance(envelopes.get(kind), dict) or not isinstance(envelopes[kind].get("*"), dict)
        for kind in _ENVELOPE_KINDS
    ):
        raise ValueError("hook_fail_closed_envelopes_contract_invalid: envelopes")
    for key in ("defaults", "events", "event_prefixes"):
        if not isinstance(document.get(key), dict):
            raise ValueError(f"hook_fail_closed_envelopes_contract_invalid: {key}")
    for key in ("events", "event_prefixes"):
        if any(kind not in _ENVELOPE_KINDS for kind in document[key].values()):
            raise ValueError(f"hook_fail_closed_envelopes_contract_invalid: {key}")
    return document


_CONTRACT: Final = _load_contract()
_DEFAULTS: Final = _CONTRACT["defaults"]
_EVENT_KINDS: Final = _CONTRACT["events"]
_EVENT_PREFIX_KINDS: Final = _CONTRACT["event_prefixes"]
_ENVELOPES: Final = _CONTRACT["envelopes"]

RENDER_UNAVAILABLE_REASON_CODE: Final = str(_DEFAULTS["reason_code"])
RENDER_UNAVAILABLE_REASON: Final = str(_DEFAULTS["reason"])
PROMPT_UNAVAILABLE_REASON: Final = str(_DEFAULTS["prompt_reason"])
PROMPT_UNAVAILABLE_REASON_CODE = "native_prompt_unavailable"
_REVIEW_DEFAULT_REASON = "HOL Guard requires review before this action can execute."


def canonical_harness(harness: str) -> str:
    return harness.strip().lower().replace("_", "-")


def _fill(template: object, values: Mapping[str, str]) -> object:
    """Copy a contract envelope, replacing whole-string placeholders only."""

    if isinstance(template, str):
        return values.get(template, template)
    if isinstance(template, dict):
        return {key: _fill(value, values) for key, value in template.items()}
    if isinstance(template, list):
        return [_fill(item, values) for item in template]
    return template


def _envelope(kind: str, harness: str, **values: str) -> dict[str, object]:
    table = _ENVELOPES[kind]
    template = table.get(canonical_harness(harness), table["*"])
    filled = _fill(template, {f"${name}": value for name, value in values.items()})
    assert isinstance(filled, dict)
    return filled


def fail_closed_pre_tool(
    harness: str,
    *,
    reason: str = RENDER_UNAVAILABLE_REASON,
    reason_code: str = RENDER_UNAVAILABLE_REASON_CODE,
) -> dict[str, object]:
    """A fixed PreToolUse deny in the harness envelope."""

    return _envelope("pre_tool", harness, reason=reason, reason_code=reason_code)


_ALLOW_FLOORS = ("allow", "warn")


def _verdict_text(verdict: Mapping[str, object], key: str) -> str | None:
    value = verdict.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _verdict_deny(harness: str, verdict: Mapping[str, object], *, reason: str | None = None) -> dict[str, object]:
    """Fixed deny for a verdict the resident reached but could not render.

    A blocking verdict keeps its own reason and reason code. An allow keeps the
    generic unavailable code, because the action is denied here only because
    its rendered allow never arrived. A verdict counts as an allow only on the
    terms the renderer uses: an allow decision over an allow or warn floor.
    """

    if verdict.get("decision") == "allow" and verdict.get("minimum_action") in _ALLOW_FLOORS:
        return fail_closed_pre_tool(harness, reason=reason or RENDER_UNAVAILABLE_REASON)
    return fail_closed_pre_tool(
        harness,
        reason=reason or _verdict_text(verdict, "reason") or RENDER_UNAVAILABLE_REASON,
        reason_code=_verdict_text(verdict, "reason_code") or RENDER_UNAVAILABLE_REASON_CODE,
    )


def _deadline_kwargs(deadline: float | None) -> dict[str, float]:
    return {} if deadline is None else {"deadline": deadline}


def render_pre_tool(
    harness: str, verdict: Mapping[str, object], *, guard_home: Path | None = None, deadline: float | None = None
) -> dict[str, object]:
    """Resident-rendered PreToolUse response, or a fixed deny when it cannot render."""

    rendered = native_render_pre_tool(harness, verdict, guard_home=guard_home, **_deadline_kwargs(deadline))
    return rendered or _verdict_deny(harness, verdict)


def render_accepted_allow(
    harness: str, allowed: Mapping[str, object], *, guard_home: Path | None = None, deadline: float | None = None
) -> dict[str, object]:
    """Render an allow that rests on a saved or local approval.

    Only a reply the resident actually rendered is marked as an accepted reuse.
    When the resident cannot render, the fixed deny carries no reuse status, so
    the activity record never says an approval was accepted for a blocked action.
    """

    rendered = native_render_pre_tool(harness, allowed, guard_home=guard_home, **_deadline_kwargs(deadline))
    if rendered is None:
        return fail_closed_pre_tool(harness)
    rendered["approval_reuse_status"] = "accepted"
    return rendered


def render_pre_tool_review(
    harness: str,
    verdict: Mapping[str, object],
    *,
    approval: Mapping[str, object] | None,
    guard_home: Path | None = None,
    deadline: float | None = None,
) -> dict[str, object]:
    """Resident-rendered paused review, or a fixed deny when it cannot render.

    The fixed deny keeps the signed approval link in its reason, so a review that
    is already queued still tells the user where to approve it.
    """

    linked_reason = None
    raw_url = approval.get("approval_url") if approval is not None else None
    if isinstance(raw_url, str) and raw_url.strip():
        linked_reason = native_review_reason(
            canonical_harness(harness),
            str(verdict.get("reason") or _REVIEW_DEFAULT_REASON),
            raw_url.strip(),
            guard_home=guard_home,
        )
    rendered = native_render_pre_tool_review(
        harness,
        verdict,
        approval=approval,
        linked_reason=linked_reason,
        guard_home=guard_home,
        **_deadline_kwargs(deadline),
    )
    return rendered or _verdict_deny(harness, verdict, reason=linked_reason)


def render_recording_only_pre_tool(
    harness: str,
    *,
    reason_code: str,
    reason: str,
    guard_home: Path | None = None,
    deadline: float | None = None,
    fallback: dict[str, object] | None = None,
) -> dict[str, object]:
    """Resident-rendered Watch continue, or a fixed deny when it cannot render."""

    rendered = native_render_recording_only_pre_tool(
        harness,
        reason_code=reason_code,
        reason=reason,
        guard_home=guard_home,
        **_deadline_kwargs(deadline),
    )
    return rendered or fallback or fail_closed_pre_tool(harness)


def _event_kind(event_name: str) -> str:
    compact = event_name.strip().lower().replace("_", "").replace("-", "")
    kind = _EVENT_KINDS.get(compact)
    if kind is not None:
        return str(kind)
    for prefix, prefix_kind in _EVENT_PREFIX_KINDS.items():
        if compact.startswith(prefix):
            return str(prefix_kind)
    return "lifecycle"


def fail_closed_response(
    harness: str,
    event_name: str,
    *,
    reason: str = RENDER_UNAVAILABLE_REASON,
    reason_code: str = RENDER_UNAVAILABLE_REASON_CODE,
    prompt_reason: str | None = None,
) -> dict[str, object]:
    """Fixed response when the resident cannot answer a hook.

    Prompt, permission and tool events get a constant deny in the harness
    envelope. Other events observe activity that already happened, so they get
    a constant payload that carries no verdict. Nothing here reads the payload
    or the posture, and nothing here ever authorizes an action.
    """

    kind = _event_kind(event_name)
    if kind == "prompt":
        reason = prompt_reason or PROMPT_UNAVAILABLE_REASON
    return _envelope(kind, harness, reason=reason, reason_code=reason_code, event_name=event_name)


def unmanaged_passthrough(harness: str) -> dict[str, object]:
    """Constant reply for a hook that belongs to an app Guard does not manage."""

    return _envelope("unmanaged", harness)
