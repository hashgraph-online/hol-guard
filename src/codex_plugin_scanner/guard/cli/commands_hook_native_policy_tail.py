"""The tail of the artifact hook's policy stack, answered by the resident.

Three decisions the hook made around ``policy_stack`` live in the resident:
whether the native command floor is skipped (an artifact fact), whether local
tool-grant evidence is gathered (a ``policy_stack`` field) and what the settled
verdict's ``policy_composition`` trace and receipt ``approval_source`` are.
This module gathers what the resident asked for, reads its answers and treats
a malformed or missing one as no answer: it raises, and the hook pipeline
turns that into the host outage response.  Nothing here decides a fallback.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..native_hook_artifact_compose import NativeHookComposeError, native_hook_compose

_INVALID = "native_hook_artifact_compose_payload_invalid"
_COMPOSITION_KEYS = frozenset(
    {
        "current_config_action",
        "current_action_override",
        "trusted_cli_override",
        "untrusted_hook_payload_hint",
        "package_action",
        "data_flow_action",
        "scanner_action",
        "current_composed_action",
        "saved_policy_action",
        "approval_reuse_source",
        "trusted_request_override",
        "trusted_request_override_reason",
        "authoritative_action",
    }
)
_APPROVAL_SOURCES = frozenset({"inline", "approval_center", "policy"})


@dataclass(frozen=True)
class SettledPolicyComposition:
    """The resident's record of how the settled verdict was composed."""

    policy_composition: dict[str, object]
    evidence: dict[str, object]
    approval_source: str


def local_eligibility_required(stack: Mapping[str, object], *, raw_command: str | None) -> bool:
    """Whether the resident asked for local tool-grant evidence on this request.

    The evidence names the raw command, so a request for it without one is a
    malformed answer rather than something to default.
    """

    required = stack.get("local_eligibility_required")
    if not isinstance(required, bool) or (required and raw_command is None):
        raise NativeHookComposeError(_INVALID)
    return required


def settled_policy_composition(
    *,
    guard_home: Path,
    current_config_action: str,
    current_action_override: str | None,
    trusted_cli_action: str | None,
    untrusted_payload_action: str | None,
    package_policy_action: str | None,
    data_flow_action: str | None,
    scanner_action: str | None,
    current_composed_action: str,
    saved_policy_action: str | None,
    approval_reuse_source: str | None,
    trusted_request_override: bool,
    trusted_request_override_reason: str | None,
    authoritative_action: str,
    claude_native_approval_observed: bool,
    user_override_present: bool,
) -> SettledPolicyComposition:
    """Ask the resident for the settled verdict's composition trace and source."""

    answer = native_hook_compose(
        "policy_composition",
        {
            "current_config_action": current_config_action,
            "current_action_override": current_action_override,
            "trusted_cli_action": trusted_cli_action,
            "untrusted_payload_action": untrusted_payload_action,
            "package_policy_action": package_policy_action,
            "data_flow_action": data_flow_action,
            "scanner_action": scanner_action,
            "current_composed_action": current_composed_action,
            "saved_policy_action": saved_policy_action,
            "approval_reuse_source": approval_reuse_source,
            "trusted_request_override": trusted_request_override,
            "trusted_request_override_reason": trusted_request_override_reason,
            "authoritative_action": authoritative_action,
            "claude_native_approval_observed": claude_native_approval_observed,
            "user_override_present": user_override_present,
        },
        guard_home=guard_home,
    )
    composition = cast("dict[str, object]", answer["policy_composition"])
    evidence = cast("dict[str, object]", answer["evidence"])
    source = answer["approval_source"]
    if (
        set(composition) != _COMPOSITION_KEYS
        or set(evidence) != {"source", *_COMPOSITION_KEYS}
        or evidence["source"] != "policy_composition"
        or source not in _APPROVAL_SOURCES
    ):
        raise NativeHookComposeError(_INVALID)
    return SettledPolicyComposition(composition, evidence, cast("str", source))
