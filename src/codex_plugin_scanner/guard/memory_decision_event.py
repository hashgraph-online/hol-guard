"""``GuardMemoryDecisionEventV1`` — durable local-to-cloud decision event.

A memory decision event records one concrete human choice (approve, block, or
keep-asking dismissal) so HOL Guard Cloud can build a Suggested Memory candidate
from *repeated* choices. This is the missing first-class pipeline: previously
local approvals lived only in local SQLite and never reached Cloud as decision
evidence, so Suggested Memory had nothing durable to read.

Contract version: ``guard.memory-decision.v1``. Events are enqueued into the
existing ``guard_cloud_events`` outbox and synced via the existing platform
event transport — no new outbox table or auth path.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, cast

_LOGGER = logging.getLogger(__name__)

MEMORY_DECISION_EVENT_CONTRACT_VERSION = "guard.memory-decision.v1"

MemoryDecisionAction = Literal["approved", "blocked", "dismissed_keep_asking"]
MemoryDecisionSource = Literal[
    "local_approval_center",
    "cloud_review",
    "headless_remote",
]
MemoryRedactionState = Literal["disabled", "enabled", "withheld"]

# Request fields the resident reads; only string values travel.
_REQUEST_TEXT_FIELDS = (
    "request_id",
    "review_command",
    "raw_command_text",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "harness",
    "launch_target",
    "queue_group_id",
    "action_identity",
    "resolution_reason",
    "reason",
    "risk_summary",
    "risk_headline",
    "project_id",
    "projectId",
    "workspace_path",
    "workspacePath",
)


@dataclass(frozen=True, slots=True)
class GuardMemoryDecisionEventV1:
    """One human decision that may later contribute to a memory candidate."""

    event_id: str
    event_schema_version: str
    owner_user_id: str | None
    workspace_id: str | None
    device_id: str | None
    machine_id: str | None
    machine_installation_id: str | None
    harness_id: str | None
    project_id: str | None
    request_id: str
    queue_group_id: str | None
    action_identity: str | None
    decision_action: MemoryDecisionAction
    decision_scope: str
    decision_source: MemoryDecisionSource
    decision_reason: str | None
    occurred_at: str
    command_display: str
    command_raw: str | None
    redaction_state: MemoryRedactionState
    artifact_type: str | None
    artifact_id: str | None
    artifact_name: str | None
    risk_summary: str | None
    risk_signals: tuple[str, ...] = ()
    source_receipt_id: str | None = None
    source_receipt_hash: str | None = None
    memory_pattern_fingerprint: str | None = None
    memory_pattern_kind: str | None = None
    memory_pattern_components: dict[str, str] = field(default_factory=dict)

    def to_payload(self) -> dict[str, object]:
        payload = asdict(self)
        payload["event_schema_version"] = self.event_schema_version
        payload["risk_signals"] = list(self.risk_signals)
        payload["memory_pattern_components"] = dict(self.memory_pattern_components)
        return payload


def build_memory_decision_event(
    *,
    request: Mapping[str, object],
    action: str,
    scope: str,
    resolved_at: str,
    owner_user_id: str | None = None,
    workspace_id: str | None = None,
    device_id: str | None = None,
    machine_id: str | None = None,
    machine_installation_id: str | None = None,
    source: MemoryDecisionSource = "local_approval_center",
    redaction_enabled: bool = False,
    source_receipt_id: str | None = None,
    source_receipt_hash: str | None = None,
) -> GuardMemoryDecisionEventV1 | None:
    """Build a decision event from a resolved approval request mapping.

    The resident's ``memory_decision_event`` kind picks the redaction state,
    the display text and the memory fingerprint. Returns ``None`` when the
    request has no id or the action is not a decision, and also when the
    resident cannot answer: callers treat ``None`` as "this decision does not
    contribute to memory" and skip the outbox write.
    """
    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority(
            "memory_decision_event",
            {
                "request": _request_fields(request),
                "action": action,
                "resolved_at": resolved_at,
                "redaction_enabled": bool(redaction_enabled),
            },
        )
        fields = answer["event"]
        if fields is None:
            return None
        pattern = fields.pop("memory_pattern")
        risk_signals = tuple(fields.pop("risk_signals"))
        return GuardMemoryDecisionEventV1(
            **fields,
            risk_signals=risk_signals,
            event_schema_version=MEMORY_DECISION_EVENT_CONTRACT_VERSION,
            owner_user_id=owner_user_id,
            workspace_id=workspace_id,
            device_id=device_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
            decision_scope=scope,
            decision_source=source,
            occurred_at=resolved_at,
            source_receipt_id=source_receipt_id,
            source_receipt_hash=source_receipt_hash,
            memory_pattern_fingerprint=pattern["fingerprint"] if pattern else None,
            memory_pattern_kind=pattern["kind"] if pattern else None,
            memory_pattern_components=dict(pattern["components"]) if pattern else {},
        )
    except (NativeRunnerAuthorityError, AttributeError, KeyError, TypeError) as error:
        # The Cloud event is evidence, not authority: without the resident no
        # event is built rather than one rebuilt in Python.
        _LOGGER.warning("memory decision event %s was not built: %s", request.get("request_id"), error)
        return None


def event_to_cloud_payload(event: GuardMemoryDecisionEventV1) -> dict[str, object]:
    """Wrap a decision event as the ``payload`` of a GuardEventV1 envelope."""
    payload = event.to_payload()
    payload["contractVersion"] = MEMORY_DECISION_EVENT_CONTRACT_VERSION
    return payload


def is_approval_wrapper(value: str) -> bool:
    return value.strip().startswith("hol-guard approvals approve ")


def _request_fields(request: Mapping[str, object]) -> dict[str, Any]:
    fields: dict[str, Any] = {key: value for key in _REQUEST_TEXT_FIELDS if isinstance(value := request.get(key), str)}
    envelope = request.get("action_envelope_json")
    if isinstance(envelope, str):
        fields["action_envelope_json"] = envelope
    elif isinstance(envelope, Mapping):
        fields["action_envelope_json"] = dict(cast(Mapping[str, object], envelope))
    signals = request.get("risk_signals")
    if isinstance(signals, (list, tuple)):
        fields["risk_signals"] = [str(item) for item in signals]
    return fields
