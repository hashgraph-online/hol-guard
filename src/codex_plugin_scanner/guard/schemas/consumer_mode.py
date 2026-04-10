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


def build_consumer_mode_contract(target: Path) -> dict[str, object]:
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
    recommendation = "allow"
    if highest_severity in {Severity.CRITICAL, Severity.HIGH} or scan_result.score < 60:
        recommendation = "block"
    elif scan_result.findings:
        recommendation = "review"
    return {
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
            "trust_score": scan_result.trust_report.total if scan_result.trust_report is not None else None,
        },
        "trust_evidence_bundle": {
            "findings": finding_titles,
            "severity_counts": scan_result.severity_counts,
            "integrations": [asdict(integration) for integration in scan_result.integrations],
        },
        "policy_recommendation": {
            "action": recommendation,
            "reason": "Consumer-mode recommendation based on severity findings and aggregate score.",
        },
    }
