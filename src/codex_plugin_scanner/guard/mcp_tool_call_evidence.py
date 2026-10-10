"""Receipt display evidence for MCP tool calls (observability only).

Verdicts are final before this runs, so a native evidence failure degrades the
evidence (no command text, no ``runtimeAction``) and never drops a receipt,
event, or already-executed tool result. Python never recomputes the evidence.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path

from .models import GuardArtifact
from .native_mcp_runtime_evidence import NativeMcpRuntimeEvidenceError, argument_entries, native_receipt_evidence
from .native_mcp_tool_evidence import NativeMcpToolEvidenceError
from .runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall

_LOGGER = logging.getLogger(__name__)


def receipt_evidence_for_mcp_tool_call(
    artifact: GuardArtifact,
    *,
    arguments: object,
    risk_categories: tuple[str, ...],
    guard_home: Path,
) -> tuple[str | None, dict[str, object]]:
    """Return ``(raw_command_text, scanner_evidence)`` using one resident round trip."""
    evidence: dict[str, object] = {}
    enriched = artifact
    if not isinstance(artifact.metadata.get("mcpSkillFirewall"), dict):
        # build_tool_call_artifact already enriched; only recompute when absent.
        try:
            enriched = enrich_artifact_with_mcp_skill_firewall(artifact)
        except NativeMcpToolEvidenceError:
            _LOGGER.warning("native MCP firewall evidence unavailable; recording receipt without it", exc_info=True)
            evidence["firewallEvidence"] = "native_unavailable"
    firewall = enriched.metadata.get("mcpSkillFirewall")
    if isinstance(firewall, dict):
        evidence["mcpSkillFirewall"] = firewall
    description = enriched.metadata.get("tool_description")
    try:
        raw_command_text, runtime_action = native_receipt_evidence(
            artifact_name=artifact.name,
            tool_description=description if isinstance(description, str) else None,
            arguments=argument_entries(arguments, mapping_type=Mapping),
            risk_categories=risk_categories,
            guard_home=guard_home,
        )
    except NativeMcpRuntimeEvidenceError:
        _LOGGER.warning("native MCP runtime evidence unavailable; recording receipt without it", exc_info=True)
        evidence["runtimeEvidence"] = "native_unavailable"
        return None, evidence
    if runtime_action is not None:
        evidence["runtimeAction"] = runtime_action
    return raw_command_text, evidence
