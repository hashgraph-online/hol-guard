"""Consumer-mode Guard contract generation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from ...models import SEVERITY_ORDER, Severity
from ...scanner import scan_plugin


def _artifact_hash(payload: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _install_recommendation(
    highest_severity: Severity,
    score: int,
    finding_titles: list[str],
) -> tuple[str, str]:
    if highest_severity in {Severity.CRITICAL, Severity.HIGH} or score < 60:
        reason = "Install-time scan found severe findings that need review before you trust this artifact."
        return ("block", reason)
    if finding_titles:
        reason = "Install-time scan found non-blocking findings that should be reviewed before install."
        return ("review", reason)
    return ("allow", "Install-time scan found no blocking issues in the local artifact.")


def build_consumer_mode_contract(target: Path, intended_harness: str | None = None) -> dict[str, object]:
    """Build the stable consumer-mode payload for a local artifact."""

    scan_result = scan_plugin(target)
    summary_payload = {
        "path": str(target),
        "score": scan_result.score,
        "grade": scan_result.grade,
        "ecosystems": list(scan_result.ecosystems),
        "packages": [asdict(package) for package in scan_result.packages],
    }
    artifact_hash = _artifact_hash(summary_payload)
    finding_titles = [finding.title for finding in scan_result.findings[:10]]
    highest_severity = max(
        (finding.severity for finding in scan_result.findings),
        key=lambda severity: SEVERITY_ORDER[severity],
        default=Severity.INFO,
    )
    recommendation, recommendation_reason = _install_recommendation(
        highest_severity=highest_severity,
        score=scan_result.score,
        finding_titles=finding_titles,
    )
    trust_score = None
    if scan_result.trust_report is not None:
        trust_score = scan_result.trust_report.total
    abom_entry = {
        "artifact_id": f"preflight:{target.name}",
        "artifact_name": target.name,
        "artifact_type": scan_result.scope,
        "path": str(target),
        "ecosystems": list(scan_result.ecosystems),
        "packages": [asdict(package) for package in scan_result.packages],
    }
    return {
        "schema_version": "guard-consumer.v2",
        "generated_at": scan_result.timestamp,
        "install_target": {
            "path": str(target),
            "intended_harness": intended_harness,
        },
        "artifact_snapshot": {
            "path": str(target),
            "artifact_hash": artifact_hash,
            "score": scan_result.score,
            "grade": scan_result.grade,
        },
        "capability_manifest": {
            "ecosystems": list(scan_result.ecosystems),
            "packages": [asdict(package) for package in scan_result.packages],
            "category_names": [category.name for category in scan_result.categories],
        },
        "artifact_diff": {
            "changed": False,
            "changed_fields": [],
        },
        "provenance_record": {
            "scope": scan_result.scope,
            "plugin_dir": scan_result.plugin_dir,
            "trust_score": trust_score,
        },
        "trust_evidence_bundle": {
            "findings": finding_titles,
            "severity_counts": scan_result.severity_counts,
            "integrations": [asdict(integration) for integration in scan_result.integrations],
        },
        "policy_recommendation": {
            "action": recommendation,
            "reason": recommendation_reason,
        },
        "install_verdict": {
            "action": recommendation,
            "reason": recommendation_reason,
            "can_install": recommendation == "allow",
        },
        "abom_entry": abom_entry,
        "threat_intelligence": {
            "verdict_source": "local-scan",
            "highest_severity": highest_severity.value,
            "finding_count": len(scan_result.findings),
        },
    }
