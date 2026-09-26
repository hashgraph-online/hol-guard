"""Redacted native-review presentation, never authorization or retry identity."""

from collections.abc import Mapping
from pathlib import Path

from .actions import (
    GuardActionEnvelope,
    _normalize_action_payload,
    action_envelope_harnesses,
    normalize_harness_payload,
)

_REGISTERED_HARNESSES = frozenset(action_envelope_harnesses())


def normalize_native_review_payload(
    harness: str, payload: Mapping[str, object], *, workspace: Path | None
) -> GuardActionEnvelope:
    """Use shared classification and redaction even for unregistered native harnesses."""
    normalized_harness = harness.strip().lower()
    if normalized_harness in _REGISTERED_HARNESSES:
        return normalize_harness_payload(normalized_harness, "PreToolUse", payload, workspace=workspace)
    return _normalize_action_payload(
        payload, harness=normalized_harness, default_event_name="PreToolUse", workspace=workspace, home_dir=None
    )
