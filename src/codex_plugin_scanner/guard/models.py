"""Shared Guard data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

GuardAction = Literal["allow", "warn", "review", "block", "sandbox-required", "require-reapproval"]
GuardMode = Literal["observe", "prompt", "enforce"]
DecisionScope = Literal["global", "harness", "workspace", "artifact", "publisher"]
GUARD_ACTION_VALUES: tuple[GuardAction, ...] = (
    "allow",
    "warn",
    "review",
    "block",
    "sandbox-required",
    "require-reapproval",
)
DECISION_SCOPE_VALUES: tuple[DecisionScope, ...] = ("global", "harness", "workspace", "artifact", "publisher")

SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _redact_url(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.query:
        return value
    redacted_pairs = []
    for key, item in parse_qsl(parsed.query, keep_blank_values=True):
        if any(token in key.lower() for token in ("key", "token", "auth", "secret")):
            redacted_pairs.append((key, "*****"))
            continue
        redacted_pairs.append((key, item))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(redacted_pairs), parsed.fragment))


def _redact_arg(value: str) -> str:
    lower_value = value.lower()
    if "authorization:" in lower_value or "api-key:" in lower_value or "bearer " in lower_value:
        prefix, _, _ = value.partition(":")
        return f"{prefix}: *****"
    if any(token in lower_value for token in ("apikey=", "api_key=", "api-key=", "token=", "secret=")):
        key, _, _ = value.partition("=")
        return f"{key}=*****"
    return value


def _redact_metadata(value: object, key: str | None = None) -> object:
    if key is not None and any(
        token in key.lower() for token in ("key", "token", "auth", "secret", "password", "credential")
    ):
        return "*****"
    if isinstance(value, dict):
        return {item_key: _redact_metadata(item_value, item_key) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_redact_metadata(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class GuardArtifact:
    """A local harness artifact that Guard can reason about."""

    artifact_id: str
    name: str
    harness: str
    artifact_type: str
    source_scope: str
    config_path: str
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    transport: str | None = None
    publisher: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["args"] = [_redact_arg(value) for value in self.args]
        payload["url"] = _redact_url(self.url)
        payload["metadata"] = _redact_metadata(payload.get("metadata", {}))
        return payload


@dataclass(frozen=True, slots=True)
class HarnessDetection:
    """Artifacts and installation state discovered for one harness."""

    harness: str
    installed: bool
    command_available: bool
    config_paths: tuple[str, ...]
    artifacts: tuple[GuardArtifact, ...]
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "harness": self.harness,
            "installed": self.installed,
            "command_available": self.command_available,
            "config_paths": list(self.config_paths),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Persisted policy decision."""

    harness: str
    scope: DecisionScope
    action: GuardAction
    artifact_id: str | None = None
    artifact_hash: str | None = None
    workspace: str | None = None
    publisher: str | None = None
    reason: str | None = None
    owner: str | None = None
    source: str = "local"
    expires_at: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


CloudExceptionEffect = Literal["allow"]
CloudExceptionScope = Literal["artifact", "publisher", "harness", "workspace", "global"]
CloudExceptionAckStatus = Literal["pending", "synced", "failed", "offline"]
CloudExceptionProvenance = Literal["receipt-sync", "policy-bundle"]


@dataclass(frozen=True, slots=True)
class CloudException:
    """Governed Cloud risk acceptance synced from Guard Cloud."""

    id: str
    effect: CloudExceptionEffect
    scope: CloudExceptionScope
    harness: str | None
    owner: str
    approver: str | None
    expiry: str
    source_receipt_id: str | None
    bundle_hash: str | None
    ack_status: CloudExceptionAckStatus | None
    last_used_at: str | None
    rejection_reason: str | None
    provenance: CloudExceptionProvenance = "receipt-sync"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GuardReceipt:
    """Runtime receipt recorded after a Guard evaluation."""

    receipt_id: str
    timestamp: str
    harness: str
    artifact_id: str
    artifact_hash: str
    policy_decision: GuardAction
    capabilities_summary: str
    changed_capabilities: tuple[str, ...]
    provenance_summary: str
    user_override: str | None = None
    artifact_name: str | None = None
    source_scope: str | None = None
    diff_summary: str | None = None
    approval_source: str | None = None
    approval_request_id: str | None = None
    scanner_evidence: tuple[dict[str, object], ...] = ()
    browser_intent: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["changed_capabilities"] = list(self.changed_capabilities)
        payload["scanner_evidence"] = [dict(item) for item in self.scanner_evidence]
        return payload


@dataclass(frozen=True, slots=True)
class GuardApprovalRequest:
    """Pending approval request surfaced through the local approval center."""

    request_id: str
    harness: str
    artifact_id: str
    artifact_name: str
    artifact_hash: str
    policy_action: GuardAction
    recommended_scope: DecisionScope
    changed_fields: tuple[str, ...]
    source_scope: str
    config_path: str
    review_command: str
    approval_url: str
    workspace: str | None = None
    artifact_type: str = "artifact"
    launch_target: str | None = None
    transport: str | None = None
    publisher: str | None = None
    risk_summary: str | None = None
    risk_signals: tuple[str, ...] = ()
    artifact_label: str | None = None
    source_label: str | None = None
    trigger_summary: str | None = None
    why_now: str | None = None
    launch_summary: str | None = None
    risk_headline: str | None = None
    action_envelope_json: dict[str, object] | None = None
    decision_v2_json: dict[str, object] | None = None
    fallback_cli_command: str | None = None
    action_identity: str | None = None
    queue_group_id: str | None = None
    dedupe_count: int = 1
    last_seen_at: str | None = None
    scanner_evidence: tuple[dict[str, object], ...] = ()
    browser_intent: dict[str, object] | None = None
    raw_command_text: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["changed_fields"] = list(self.changed_fields)
        payload["risk_signals"] = list(self.risk_signals)
        payload["scanner_evidence"] = [dict(item) for item in self.scanner_evidence]
        return payload


@dataclass(frozen=True, slots=True)
class GuardRuntimeState:
    """Current local Guard runtime session exposed to thin clients."""

    session_id: str
    daemon_host: str
    daemon_port: int
    started_at: str
    last_heartbeat_at: str

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["approval_center_url"] = f"http://{self.daemon_host}:{self.daemon_port}"
        return payload


@dataclass(frozen=True, slots=True)
class SyncedPolicyRule:
    """A compiled policy rule from a synced cloud policy bundle.

    Maps to the ``rules`` array in ``guard-policy-bundle.v1``.  Each rule
    carries an action and a scope that the local evaluator matches against
    the incoming artifact's harness, device, and type.
    """

    rule_id: str
    action: str
    reason: str
    agents: tuple[str, ...] = ()
    devices: tuple[str, ...] = ()
    harnesses: tuple[str, ...] = ()
    locations: tuple[str, ...] = ()
    artifact_types: tuple[str, ...] = ()

    def matches(
        self,
        *,
        harness: str,
        artifact_type: str,
        device_id: str | None = None,
    ) -> bool:
        """Return ``True`` when every non-empty scope dimension matches."""
        if self.harnesses and harness not in self.harnesses:
            return False
        if self.artifact_types:
            matcher = _ARTIFACT_TYPE_TO_MATCHER.get(artifact_type, artifact_type)
            if matcher not in self.artifact_types and artifact_type not in self.artifact_types:
                return False
        if self.devices and device_id is not None and device_id not in self.devices:
            return False
        # Empty scope dimensions mean "matches all" (wildcard)
        return True


_ARTIFACT_TYPE_TO_MATCHER: dict[str, str] = {
    "shell": "tool-action",
    "tool-action": "tool-action",
    "tool_action_request": "mcp",
    "prompt_request": "mcp",
    "file-read": "file-read",
    "file_read_request": "file-read",
    "package-request": "package-request",
    "package_request": "package-request",
}
