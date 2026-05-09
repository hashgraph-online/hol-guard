"""GuardInsight model and action-type-specific generators (L246-L252)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .models import SEVERITY_RANK
from .runtime.actions import GuardActionEnvelope
from .runtime.signals import RiskSignalV2


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _max_severity(signals: tuple[RiskSignalV2, ...]) -> str:
    best = "info"
    for sig in signals:
        sev = str(sig.severity or "info").lower()
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(best, 0):
            best = sev
    return best


def _detector_ids(signals: tuple[RiskSignalV2, ...]) -> tuple[str, ...]:
    return tuple(sig.detector for sig in signals if sig.detector)


def _first_reason(signals: tuple[RiskSignalV2, ...]) -> str:
    for sig in signals:
        if sig.plain_reason:
            return sig.plain_reason
    return "Risk signals detected."


@dataclass(frozen=True, slots=True)
class GuardInsight:
    """Human-readable insight generated from a detected risk event.

    Captures what happened, why it was risky, the source/sink/app context,
    which detectors fired, and a user-facing recommendation.
    """

    insight_id: str
    action_id: str
    action_type: str
    harness: str
    what_happened: str
    why_risky: str
    source: str | None
    sink: str | None
    app: str
    scanner_evidence: tuple[str, ...] = field(default_factory=tuple)
    recommendation: str = ""
    severity: str = "low"
    created_at: str = field(default_factory=_now_iso)


def insight_from_prompt_block(
    action: GuardActionEnvelope,
    signals: tuple[RiskSignalV2, ...],
) -> GuardInsight | None:
    """L247: Generate a GuardInsight for a blocked prompt action."""
    if not signals:
        return None
    excerpt = action.prompt_excerpt or (action.prompt_text or "")[:80]
    return GuardInsight(
        insight_id=str(uuid.uuid4()),
        action_id=action.action_id,
        action_type="prompt",
        harness=action.harness,
        what_happened=f"AI submitted a prompt that triggered a risk signal. Excerpt: {excerpt!r}",
        why_risky=_first_reason(signals),
        source=action.harness,
        sink=None,
        app=action.harness,
        scanner_evidence=_detector_ids(signals),
        recommendation=(
            "Review the prompt text for injection attempts or data exfiltration patterns. "
            "Allow only if you trust the source and intent."
        ),
        severity=_max_severity(signals),
    )


def insight_from_bash_command(
    action: GuardActionEnvelope,
    signals: tuple[RiskSignalV2, ...],
) -> GuardInsight | None:
    """L248: Generate a GuardInsight for a blocked bash/shell command."""
    if not signals:
        return None
    cmd = (action.command or "")[:120]
    return GuardInsight(
        insight_id=str(uuid.uuid4()),
        action_id=action.action_id,
        action_type="shell_command",
        harness=action.harness,
        what_happened=f"AI attempted to run a shell command: {cmd!r}",
        why_risky=_first_reason(signals),
        source=action.tool_name or "bash",
        sink=None,
        app=action.harness,
        scanner_evidence=_detector_ids(signals),
        recommendation=(
            "Inspect the full command before allowing. Pipe-to-shell and network-fetch patterns "
            "are common supply-chain attack vectors."
        ),
        severity=_max_severity(signals),
    )


def insight_from_mcp_tool_call(
    action: GuardActionEnvelope,
    signals: tuple[RiskSignalV2, ...],
) -> GuardInsight | None:
    """L249: Generate a GuardInsight for a blocked MCP tool call."""
    if not signals:
        return None
    tool = action.mcp_tool or action.tool_name or "unknown"
    server = action.mcp_server or "unknown"
    return GuardInsight(
        insight_id=str(uuid.uuid4()),
        action_id=action.action_id,
        action_type="mcp_tool",
        harness=action.harness,
        what_happened=f"AI invoked MCP tool {tool!r} on server {server!r}",
        why_risky=_first_reason(signals),
        source=server,
        sink=None,
        app=action.harness,
        scanner_evidence=_detector_ids(signals),
        recommendation=(
            f"Verify that the MCP tool {tool!r} is from a trusted source and that "
            "the server configuration has not been tampered with."
        ),
        severity=_max_severity(signals),
    )


def insight_from_skill_scan(
    *,
    action_id: str,
    harness: str,
    skill_name: str,
    signals: tuple[RiskSignalV2, ...],
) -> GuardInsight | None:
    """L250: Generate a GuardInsight for a flagged skill scan result."""
    if not signals:
        return None
    return GuardInsight(
        insight_id=str(uuid.uuid4()),
        action_id=action_id,
        action_type="skill_scan",
        harness=harness,
        what_happened=f"Skill scan flagged {skill_name!r} as potentially dangerous",
        why_risky=_first_reason(signals),
        source=skill_name,
        sink=None,
        app=harness,
        scanner_evidence=_detector_ids(signals),
        recommendation=(
            f"Review the skill definition for {skill_name!r}. "
            "Remove or isolate the skill if you did not install it intentionally."
        ),
        severity=_max_severity(signals),
    )


def insight_from_package_script(
    action: GuardActionEnvelope,
    signals: tuple[RiskSignalV2, ...],
) -> GuardInsight | None:
    """L251: Generate a GuardInsight for a blocked package/script action."""
    if not signals:
        return None
    pkg = action.package_name or action.script_name or (action.command or "")[:60]
    mgr = action.package_manager or "unknown"
    return GuardInsight(
        insight_id=str(uuid.uuid4()),
        action_id=action.action_id,
        action_type=action.action_type,
        harness=action.harness,
        what_happened=f"AI tried to run a {mgr} package or script: {pkg!r}",
        why_risky=_first_reason(signals),
        source=mgr,
        sink=pkg,
        app=action.harness,
        scanner_evidence=_detector_ids(signals),
        recommendation=(
            f"Verify that {pkg!r} is a legitimate package and that it does not "
            "run post-install scripts that modify system state or phone home."
        ),
        severity=_max_severity(signals),
    )


def insight_from_encoded_payload(
    action: GuardActionEnvelope,
    signals: tuple[RiskSignalV2, ...],
) -> GuardInsight | None:
    """L252: Generate a GuardInsight for an encoded/obfuscated payload."""
    if not signals:
        return None
    cmd = (action.command or action.prompt_text or "")[:80]
    return GuardInsight(
        insight_id=str(uuid.uuid4()),
        action_id=action.action_id,
        action_type=action.action_type,
        harness=action.harness,
        what_happened=f"AI submitted a payload containing encoded or obfuscated content: {cmd!r}",
        why_risky="Encoded payloads can hide malicious commands from static analysis and bypass security controls.",
        source=action.tool_name or action.harness,
        sink=None,
        app=action.harness,
        scanner_evidence=_detector_ids(signals),
        recommendation=(
            "Decode the payload manually and inspect the plaintext before allowing. "
            "Legitimate commands do not need encoding."
        ),
        severity=_max_severity(signals),
    )
