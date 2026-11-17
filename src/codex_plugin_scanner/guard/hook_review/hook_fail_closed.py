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
import re
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any, Final

from ..blocked_request_mode import BLOCKED_REASON, safe_alternative_reason
from ..native_hook_decision import NativeHookDecisionError, native_review_response
from ..native_hook_render import native_render_pre_tool, native_render_recording_only_pre_tool

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


def _verdict_deny(harness: str, verdict: Mapping[str, object]) -> dict[str, object]:
    """Fixed deny for a verdict the resident reached but could not render.

    A blocking verdict keeps its own reason and reason code. An allow keeps the
    generic unavailable code, because the action is denied here only because
    its rendered allow never arrived. A verdict counts as an allow only on the
    terms the renderer uses: an allow decision over an allow or warn floor.
    """

    if verdict.get("decision") == "allow" and verdict.get("minimum_action") in _ALLOW_FLOORS:
        return fail_closed_pre_tool(harness, reason=RENDER_UNAVAILABLE_REASON)
    return fail_closed_pre_tool(
        harness,
        reason=_verdict_text(verdict, "reason") or RENDER_UNAVAILABLE_REASON,
        reason_code=_verdict_text(verdict, "reason_code") or RENDER_UNAVAILABLE_REASON_CODE,
    )


def _without_raw_url(reason: str, url: str) -> str:
    """``reason`` without ``url`` and without the separator that introduced it.

    ``native_review_link::without_raw_url`` in Rust, which the resident uses for
    the same text: removing the URL from "...approve it here: {url}." would
    otherwise leave the agent reading "...approve it here: .".
    """

    joined = re.sub(r":\s*\.(?=\s|$)", ".", reason.replace(url, "").strip()).rstrip()
    if joined.endswith("."):
        joined = joined[:-1].rstrip(" \t\r\n:;,") + "."
    return joined.rstrip(" :;,")


def _without_approval_url(verdict: Mapping[str, object], url: object) -> Mapping[str, object]:
    """``verdict`` with a raw approval URL removed from its reason.

    A fixed deny carries no signed link, so a URL the resident never reproduced
    or signed is not left in the text the agent reads. Only the literal URL is
    removed; the reason is otherwise the resident's own.
    """

    reason = _verdict_text(verdict, "reason")
    if not isinstance(url, str) or not url or reason is None or url not in reason:
        return verdict
    return {**verdict, "reason": _without_raw_url(reason, url) or RENDER_UNAVAILABLE_REASON}


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
    guard_home: Path,
    deadline: float | None = None,
) -> dict[str, object]:
    """Resident-rendered paused review with its signed approval link, or a fixed deny.

    The fixed deny carries no link: the review is still queued in the approval inbox.
    """

    inputs = {
        "harness": harness,
        "verdict": dict(verdict),
        # The resident reads only the link and the request id; the stored row can be large.
        "approval": None
        if approval is None
        else {key: approval[key] for key in ("approval_url", "request_id") if isinstance(approval.get(key), str)},
        "guard_home": str(guard_home),
    }
    with suppress(NativeHookDecisionError):
        return native_review_response("paused_review", inputs, guard_home=guard_home, deadline=deadline)
    approval_url = None if approval is None else approval.get("approval_url")
    return _verdict_deny(harness, _without_approval_url(verdict, approval_url))


def _silent_block_reason(inputs: Mapping[str, Any]) -> str:
    """The agent text for a silent block the resident could not compose.

    The native reason alone says what Guard stopped, not what the agent should do
    instead, and it still offers an inbox approval that may not be able to release
    this row. So the fallback builds the text from the same shared formatter the
    resident reads, ``hook_decision_review_response::respond``: the connector setup
    copy once the review reached the inbox, otherwise the safe-alternative reason
    whose wait note matches what approving this row can actually do. The resident's
    read-only wait hint is left out, because the resident is what is unavailable here.
    """

    result = inputs["result"]
    queued = bool(inputs.get("queued"))
    setup_reason = inputs.get("setup_reason")
    if queued and isinstance(setup_reason, str) and setup_reason:
        return setup_reason
    reason = result.get("reason")
    reason_code = result.get("reason_code")
    return safe_alternative_reason(
        reason if isinstance(reason, str) and reason else BLOCKED_REASON,
        reason_code=reason_code if isinstance(reason_code, str) and reason_code else "unknown",
        approval_queued=queued,
        retry_reuses_approval=bool(inputs.get("retry_reuses_approval")),
        exact_action_allowable=bool(inputs.get("exact_action_allowable")),
    )


def render_silent_review_block(
    harness: str, inputs: Mapping[str, Any], *, guard_home: Path, deadline: float | None = None
) -> dict[str, object]:
    """Resident-composed silent review block, or the fixed deny ``render_pre_tool`` gives it.

    The fixed deny keeps the never-prompted mode and the resume handle a bound retry watches.
    """

    with suppress(NativeHookDecisionError):
        return native_review_response("silent_review_block", inputs, guard_home=guard_home, deadline=deadline)
    blocked = {
        **inputs["result"],
        "decision": "deny",
        "minimum_action": "block",
        "policy_action": "block",
        "reason": _silent_block_reason(inputs),
    }
    response = _verdict_deny(harness, _without_approval_url(blocked, inputs.get("approval_url")))
    response.update(prompted=False, blocked_request_mode="safe-alternative")
    request_id = inputs.get("request_id")
    if inputs.get("retry_reuses_approval") and isinstance(request_id, str) and request_id:
        response["approval_resume"] = {"request_id": request_id, "poll_path": f"/v1/requests/{request_id}"}
    return response


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
