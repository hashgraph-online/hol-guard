"""Focused transformations for human-facing ``guard protect`` output."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..approval_hook_copy import (
    _SIGNED_APPROVAL_LINK_UNAVAILABLE,
    authenticated_approval_review_url,
    is_loopback_approval_url,
)

_EPHEMERAL_SIGNED_APPROVAL_PLACEHOLDER = "__HOL_GUARD_EPHEMERAL_SIGNED_APPROVAL_URL__"


def _protect_payload_for_human_output(payload: dict[str, object], *, guard_home: Path) -> dict[str, object]:
    """Sign only the package approval copy used by human output."""

    supply_chain_evaluation = payload.get("supply_chain_evaluation")
    if not isinstance(supply_chain_evaluation, dict):
        return payload
    user_copy = supply_chain_evaluation.get("user_copy")
    if not isinstance(user_copy, dict):
        return payload
    review_url = user_copy.get("dashboard_url")
    harness_message = user_copy.get("harness_message")
    if not isinstance(review_url, str) or not review_url or not isinstance(harness_message, str):
        return payload
    browser_url = authenticated_approval_review_url(review_url, guard_home=guard_home)
    output_user_copy = dict(user_copy)
    if browser_url is None:
        output_user_copy["dashboard_url"] = None
        output_user_copy["harness_message"] = _SIGNED_APPROVAL_LINK_UNAVAILABLE
    elif is_loopback_approval_url(review_url):
        output_user_copy["dashboard_url"] = browser_url
        output_user_copy["harness_message"] = harness_message.replace(
            review_url,
            _EPHEMERAL_SIGNED_APPROVAL_PLACEHOLDER,
        )
    else:
        return payload
    output_evaluation = dict(supply_chain_evaluation)
    output_evaluation["user_copy"] = output_user_copy
    output_payload = dict(payload)
    output_payload["supply_chain_evaluation"] = output_evaluation
    if browser_url is not None and is_loopback_approval_url(review_url):
        output_payload["_ephemeral_signed_approval"] = True
        output_payload["_ephemeral_signed_approval_url"] = browser_url
        output_payload["_ephemeral_signed_approval_placeholder"] = _EPHEMERAL_SIGNED_APPROVAL_PLACEHOLDER
    return output_payload


def _restore_ephemeral_signed_approval_output(
    source_payload: dict[str, object],
    redacted_payload: dict[str, object],
    *,
    command: str,
) -> None:
    """Restore the deliberately user-facing signed approval copy after redaction."""

    if command != "protect" or source_payload.get("_ephemeral_signed_approval") is not True:
        return
    signed_url = source_payload.get("_ephemeral_signed_approval_url")
    if not isinstance(signed_url, str) or not signed_url:
        return
    source_evaluation = source_payload.get("supply_chain_evaluation")
    redacted_evaluation = redacted_payload.get("supply_chain_evaluation")
    if not isinstance(source_evaluation, dict) or not isinstance(redacted_evaluation, dict):
        return
    source_user_copy = source_evaluation.get("user_copy")
    redacted_user_copy = redacted_evaluation.get("user_copy")
    if not isinstance(source_user_copy, dict) or not isinstance(redacted_user_copy, dict):
        return
    placeholder = source_payload.get("_ephemeral_signed_approval_placeholder")
    redacted_message = redacted_user_copy.get("harness_message")
    if isinstance(placeholder, str) and isinstance(redacted_message, str):
        redacted_user_copy["harness_message"] = redacted_message.replace(placeholder, signed_url)
    redacted_user_copy["dashboard_url"] = signed_url
    redacted_payload["_ephemeral_signed_approval_url"] = signed_url


def _protect_harness_message_for_render(
    payload: Mapping[str, object],
    harness_message: str,
) -> tuple[str, str | None]:
    """Replace signed URLs in the panel copy while returning the link to print below it."""

    signed_approval_url = payload.get("_ephemeral_signed_approval_url")
    if not isinstance(signed_approval_url, str) or not signed_approval_url:
        return harness_message, None
    return harness_message.replace(signed_approval_url, "[approval link below]"), signed_approval_url


__all__ = [
    "_EPHEMERAL_SIGNED_APPROVAL_PLACEHOLDER",
    "_protect_harness_message_for_render",
    "_protect_payload_for_human_output",
    "_restore_ephemeral_signed_approval_output",
]
