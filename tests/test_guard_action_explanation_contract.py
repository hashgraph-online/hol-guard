from __future__ import annotations

from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.action_explanation_contract import (
    EverydayExplanation,
    ExplanationRedaction,
    GuardActionExplanationV1,
    TechnicalExplanation,
    explanation_identity_matches,
    parse_action_explanation,
)


def _explanation() -> GuardActionExplanationV1:
    return GuardActionExplanationV1(
        action_identity="action:1",
        canonical_identity="command:v1:abc",
        kind="unknown_action",
        confidence="limited",
        everyday=EverydayExplanation(
            headline_message_id="action.unknown.headline",
            headline="Run an action Guard could not fully explain",
            summary_message_id="action.unknown.summary",
            summary="Guard could not confirm every effect.",
            impact_message_id=None,
            impact=None,
            why_guard_intervened_message_id=None,
            why_guard_intervened=None,
            recommendation_message_id="action.unknown.stop",
            recommendation="Stop it unless you expected this action.",
            actor_label="Codex",
        ),
        technical=TechnicalExplanation(
            available=False,
            unavailable_reason="Exact details were not retained.",
            action_type="unknown",
        ),
        redaction=ExplanationRedaction(level="redacted", omitted_fields=("technical.command",)),
        uncertainty_reasons=("unsupported_action",),
    )


def test_round_trip_and_identity_binding() -> None:
    original = _explanation()
    parsed = parse_action_explanation(original.to_dict())
    assert parsed == original
    assert explanation_identity_matches(parsed, action_identity="action:1", canonical_identity="command:v1:abc")
    assert not explanation_identity_matches(parsed, action_identity="action:2")


def test_cloud_projection_is_strict_subset() -> None:
    payload = _explanation().cloud_safe_projection()
    technical = cast(dict[str, object], payload["technical"])
    redaction = cast(dict[str, object], payload["redaction"])
    assert technical["available"] is False
    assert technical["action_type"] == _explanation().technical.action_type
    assert technical["command_display"] is None
    assert redaction["level"] == "redacted"


def test_canonical_identity_must_be_present_when_expected() -> None:
    payload = _explanation().to_dict()
    payload["canonical_identity"] = None
    parsed = parse_action_explanation(payload)
    assert not explanation_identity_matches(parsed, action_identity="action:1", canonical_identity="command:v1:abc")


def test_segment_arguments_are_normalized_to_tuples() -> None:
    payload = _explanation().to_dict()
    technical = cast(dict[str, object], payload["technical"])
    technical["segments"] = [
        {
            "executable": "git",
            "arguments_display": ["status"],
            "execution_context": "workspace",
            "pipeline_index": 0,
        }
    ]
    parsed = parse_action_explanation(payload)
    assert parsed.technical.segments[0].arguments_display == ("status",)


def test_schema_invalid_nested_payload_is_rejected() -> None:
    payload = _explanation().to_dict()
    everyday = cast(dict[str, object], payload["everyday"])
    del everyday["headline"]
    with pytest.raises(ValueError, match="Invalid"):
        parse_action_explanation(payload)


def test_non_json_payload_is_rejected() -> None:
    payload = _explanation().to_dict()
    payload["action_identity"] = object()
    with pytest.raises(ValueError, match="non-JSON"):
        parse_action_explanation(payload)


def test_unknown_top_level_field_rejected() -> None:
    payload = _explanation().to_dict()
    payload["surprise"] = True
    with pytest.raises(ValueError, match="Unknown"):
        parse_action_explanation(payload)


def test_cloud_projection_removes_everyday_identity_and_sensitive_details() -> None:
    original = _explanation()
    payload = original.cloud_safe_projection()
    serialized = __import__("json").dumps(payload, sort_keys=True)
    everyday = cast(dict[str, object], payload["everyday"])
    technical = cast(dict[str, object], payload["technical"])
    assert payload["action_identity"] != original.action_identity
    assert str(payload["action_identity"]).startswith("action:sha256:")
    assert payload["canonical_identity"] is None
    assert everyday["actor_label"] == "Guard"
    assert everyday["targets"] == []
    assert everyday["consequences"] == []
    assert technical["action_id"] is None
    assert technical["reason_codes"] == []
    assert "Codex" not in serialized
    assert "command:v1:abc" not in serialized
    parse_action_explanation(payload)
