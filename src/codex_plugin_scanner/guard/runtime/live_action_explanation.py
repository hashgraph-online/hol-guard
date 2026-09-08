"""Attach Core-owned Everyday explanations to persisted approval projections."""

from __future__ import annotations

from collections.abc import Mapping

from .action_explanation_projection import project_action_explanation


def build_live_action_explanation(
    payload: Mapping[str, object] | None,
    *,
    list_projection: bool = False,
) -> dict[str, object] | None:
    """Build an explanation from persisted identity and typed action facts only."""

    if not isinstance(payload, Mapping):
        return None
    action_identity = payload.get("action_identity")
    action_envelope = payload.get("action_envelope_json")
    if not isinstance(action_identity, str) or not action_identity.strip():
        return None
    if not isinstance(action_envelope, Mapping):
        return None

    raw_command_text = payload.get("raw_command_text")
    envelope_command = action_envelope.get("command")
    retained = bool(
        (isinstance(raw_command_text, str) and raw_command_text.strip())
        or (isinstance(envelope_command, str) and envelope_command.strip())
    )
    harness = payload.get("harness")
    actor_label = harness.strip() if isinstance(harness, str) and harness.strip() else "The protected app"
    explanation = project_action_explanation(
        action_envelope,
        action_identity=action_identity,
        actor_label=actor_label,
        exact_details_authorized=False,
        retained=retained,
    )
    if explanation is None:
        return None
    return explanation.list_projection() if list_projection else explanation.to_dict()


def attach_live_action_explanation(
    payload: Mapping[str, object],
    *,
    list_projection: bool = False,
    source_payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return a copy of a live payload with an explanation or explicit null."""

    result = dict(payload)
    result["action_explanation"] = build_live_action_explanation(
        source_payload if source_payload is not None else payload,
        list_projection=list_projection,
    )
    return result
