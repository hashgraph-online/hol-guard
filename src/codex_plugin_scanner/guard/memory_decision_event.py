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

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Literal

from .memory_pattern_fingerprint import (
    build_memory_pattern_fingerprint,
)

MEMORY_DECISION_EVENT_CONTRACT_VERSION = "guard.memory-decision.v1"

MemoryDecisionAction = Literal["approved", "blocked", "dismissed_keep_asking"]
MemoryDecisionSource = Literal[
    "local_approval_center",
    "cloud_review",
    "headless_remote",
]
MemoryRedactionState = Literal["disabled", "enabled", "withheld"]


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


def resolve_redaction_state(
    *,
    raw_command: str | None,
    redaction_enabled: bool,
) -> MemoryRedactionState:
    """Pick the safest redaction state for the command evidence."""
    if not raw_command:
        return "withheld"
    return "enabled" if redaction_enabled else "disabled"


def resolve_command_display(
    *,
    review_command: str | None,
    raw_command: str | None,
    redaction_state: MemoryRedactionState,
    action_envelope: Mapping[str, object] | None = None,
    artifact_name: str | None = None,
    artifact_id: str | None = None,
    launch_target: str | None = None,
) -> str:
    """Return the human-facing command text honoring the redaction policy."""
    if raw_command and redaction_state in {"disabled", "enabled"}:
        return raw_command
    envelope_display = _display_from_action_envelope(action_envelope)
    if envelope_display is not None:
        return envelope_display
    for candidate in (launch_target, artifact_name, artifact_id, review_command):
        value = _string_or_none(candidate)
        if value is not None and not _is_approval_wrapper(value) and not _is_generic_fragment(value):
            return value
    if redaction_state == "enabled":
        return "Command redacted"
    if redaction_state == "withheld":
        return "Command withheld"
    return "Command unavailable"


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

    Returns ``None`` when the request lacks the minimum signal (request id,
    command, or artifact) to anchor a future memory candidate. Callers treat
    ``None`` as "this decision does not contribute to memory" and skip the
    outbox write rather than emitting a useless event.
    """
    request_id = _string_or_none(request.get("request_id"))
    if not request_id:
        return None

    review_command = _string_or_none(request.get("review_command"))
    raw_command = _string_or_none(request.get("raw_command_text"))
    artifact_id = _string_or_none(request.get("artifact_id"))
    artifact_name = _string_or_none(request.get("artifact_name"))
    artifact_type = _string_or_none(request.get("artifact_type"))
    harness = _string_or_none(request.get("harness"))
    action_envelope = _mapping_or_none(request.get("action_envelope_json"))

    redaction_state = resolve_redaction_state(
        raw_command=raw_command,
        redaction_enabled=redaction_enabled,
    )
    command_display = resolve_command_display(
        review_command=review_command,
        raw_command=raw_command,
        redaction_state=redaction_state,
        action_envelope=action_envelope,
        artifact_name=artifact_name,
        artifact_id=artifact_id,
        launch_target=_string_or_none(request.get("launch_target")),
    )

    # Build the fingerprint from the real command when redaction permits it.
    # When raw_command is withheld, do NOT fall back to review_command: that
    # field commonly holds the approval wrapper ("hol-guard approvals approve
    # <id>") which would produce an over-broad, useless command fingerprint.
    # Fall back to artifact identity only.
    fingerprint_command = raw_command if redaction_state != "withheld" else None
    pattern = build_memory_pattern_fingerprint(
        command=fingerprint_command,
        artifact_type=artifact_type,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        harness=harness,
    )

    decision_action = _normalize_decision_action(action)
    if decision_action is None:
        return None

    return GuardMemoryDecisionEventV1(
        event_id=_event_id(request_id, decision_action, resolved_at),
        event_schema_version=MEMORY_DECISION_EVENT_CONTRACT_VERSION,
        owner_user_id=owner_user_id,
        workspace_id=workspace_id,
        device_id=device_id,
        machine_id=machine_id,
        machine_installation_id=machine_installation_id,
        harness_id=harness,
        project_id=_project_identity(request),
        request_id=request_id,
        queue_group_id=_string_or_none(request.get("queue_group_id")),
        action_identity=_string_or_none(request.get("action_identity")),
        decision_action=decision_action,
        decision_scope=scope,
        decision_source=source,
        decision_reason=_string_or_none(request.get("resolution_reason")) or _string_or_none(request.get("reason")),
        occurred_at=resolved_at,
        command_display=command_display,
        command_raw=raw_command if redaction_state == "disabled" else None,
        redaction_state=redaction_state,
        artifact_type=artifact_type,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        risk_summary=_string_or_none(request.get("risk_summary")) or _string_or_none(request.get("risk_headline")),
        risk_signals=_risk_signals(request),
        source_receipt_id=source_receipt_id,
        source_receipt_hash=source_receipt_hash,
        memory_pattern_fingerprint=pattern.fingerprint if pattern else None,
        memory_pattern_kind=pattern.kind if pattern else None,
        memory_pattern_components=dict(pattern.components) if pattern else {},
    )


def event_to_cloud_payload(event: GuardMemoryDecisionEventV1) -> dict[str, object]:
    """Wrap a decision event as the ``payload`` of a GuardEventV1 envelope."""
    payload = event.to_payload()
    payload["contractVersion"] = MEMORY_DECISION_EVENT_CONTRACT_VERSION
    return payload


def _normalize_decision_action(action: str) -> MemoryDecisionAction | None:
    normalized = action.strip().lower()
    if normalized in {"approve", "approved", "allow", "allowed"}:
        return "approved"
    if normalized in {"block", "blocked", "deny", "denied", "reject", "rejected"}:
        return "blocked"
    if normalized in {"dismiss", "dismissed", "keep_asking", "keep-asking"}:
        return "dismissed_keep_asking"
    return None


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _mapping_or_none(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, Mapping) else None


def _project_identity(request: Mapping[str, object]) -> str | None:
    for key in ("project_id", "projectId", "workspace_path", "workspacePath"):
        value = _string_or_none(request.get(key))
        if value is not None:
            return value
    return None


def _display_from_action_envelope(envelope: Mapping[str, object] | None) -> str | None:
    if envelope is None:
        return None
    action_type = _string_or_none(envelope.get("action_type") or envelope.get("actionType"))
    if action_type in {"file_read", "file_read_request", "file_write", "file_write_request"}:
        path = _first_string_from_sequence(envelope.get("target_paths") or envelope.get("targetPaths"))
        if path is None:
            path = _string_or_none(envelope.get("path") or envelope.get("file_path") or envelope.get("filePath"))
        if path is not None:
            verb = "Read" if "read" in action_type else "Write"
            return f"{verb} {path}"
    if action_type == "mcp_tool":
        server = _string_or_none(envelope.get("mcp_server") or envelope.get("mcpServer"))
        tool = _string_or_none(envelope.get("mcp_tool") or envelope.get("mcpTool") or envelope.get("tool_name"))
        if server and tool:
            return f"mcp {server}.{tool}"
        if tool and not _is_generic_fragment(tool):
            return f"mcp {tool}"
    package_manager = _string_or_none(envelope.get("package_manager") or envelope.get("packageManager"))
    package_name = _string_or_none(envelope.get("package_name") or envelope.get("packageName"))
    if package_manager and package_name:
        return f"{package_manager} install {package_name}"
    url = _string_or_none(
        envelope.get("url") or envelope.get("uri") or envelope.get("endpoint") or envelope.get("host")
    )
    method = _string_or_none(envelope.get("method"))
    if url and method:
        return f"{method.upper()} {url}"
    if url:
        return url
    tool_name = _string_or_none(envelope.get("tool_name") or envelope.get("toolName"))
    if tool_name and not _is_generic_fragment(tool_name):
        return tool_name
    return None


def _first_string_from_sequence(value: object) -> str | None:
    if isinstance(value, str):
        return _string_or_none(value)
    if isinstance(value, (list, tuple)):
        for item in value:
            candidate = _string_or_none(item)
            if candidate is not None:
                return candidate
    return None


def _is_approval_wrapper(value: str) -> bool:
    return value.strip().startswith("hol-guard approvals approve ")


def _is_generic_fragment(value: str) -> bool:
    return value.strip().lower() in {"bash", "rg", "cat", "tool", "mcp", "skill"}


def _risk_signals(request: Mapping[str, object]) -> tuple[str, ...]:
    raw = request.get("risk_signals")
    if isinstance(raw, (list, tuple)):
        return tuple(str(item).strip() for item in raw if str(item).strip())
    return ()


def _event_id(request_id: str, action: MemoryDecisionAction, occurred_at: str) -> str:
    import hashlib

    digest = hashlib.sha256(f"memory_decision:{request_id}:{action}:{occurred_at}".encode()).hexdigest()
    return f"guard-memory-decision-{digest[:32]}"
