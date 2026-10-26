"""Safe, non-content evidence derived from primary skill documents.

The native runtime reads the document. It decides whether the path is a
primary skill document at all, refuses a symlinked component, holds the
read under a ceiling, hashes the bytes and reports the document's shape and
any network capability its prose documents. Python sends the path exactly as
it holds it, with its own working directory and the safe roots alongside, and
presents the answer. Nothing here opens the file or re-derives a verdict.

When no bound answer arrives the evidence stays explicitly unavailable.
"""

from __future__ import annotations

from pathlib import Path

from .native_skill_directory_identity import native_skill_document_evidence

MAX_SKILL_DOCUMENT_BYTES = 256 * 1024
_ANALYSIS_VERSION = "1"
_CAPABILITY_INFERENCE_VERSION = "1"


def enrich_skill_document_metadata(
    config_path: object,
    metadata: dict[str, object],
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> dict[str, object]:
    """Add bounded evidence for a primary SKILL.md without retaining its content."""

    enriched = dict(metadata)
    enriched.pop("skillDocumentEvidence", None)
    enriched.pop("contentEvidence", None)
    enriched.pop("documentedCapabilities", None)
    evidence, documented_capabilities = _analyze_skill_document(
        config_path,
        safe_roots=(home_dir, workspace_dir),
    )
    enriched["contentEvidence"] = evidence
    if documented_capabilities:
        enriched["documentedCapabilities"] = documented_capabilities
    return enriched


def _analyze_skill_document(
    config_path: object,
    *,
    safe_roots: tuple[Path | None, ...],
) -> tuple[dict[str, object], list[dict[str, str]]]:
    evidence: dict[str, object] = {
        "analysisVersion": _ANALYSIS_VERSION,
        "readabilityStatus": "unavailable",
        "evidenceAuthority": "device_claim",
        "affectsV4Score": False,
    }
    answer = native_skill_document_evidence(config_path, safe_roots=safe_roots)
    if answer is None:
        return evidence, []
    capability = answer.pop("documentedNetworkCapability", None)
    evidence.update(answer)
    if not isinstance(capability, str):
        return evidence, []
    return evidence, [_network_capability(capability)]


def _network_capability(evidence_code: str) -> dict[str, str]:
    return {
        "capability": "network_egress",
        "source": "skill_documentation",
        "confidence": "high",
        "evidenceCode": evidence_code,
        "inferenceVersion": _CAPABILITY_INFERENCE_VERSION,
    }


__all__ = ["MAX_SKILL_DOCUMENT_BYTES", "enrich_skill_document_metadata"]
