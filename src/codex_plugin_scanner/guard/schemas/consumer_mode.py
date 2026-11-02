"""Consumer-mode Guard contract generation.

The scanner runs here; the native runtime owns the ``guard-consumer.v2``
contract built from its result (the ``consumer_mode_contract`` kind).
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from ...models import ScanOptions, ScanResult
from ...scanner import scan_plugin
from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

_UNAVAILABLE_MESSAGE = "Guard could not build the install-time scan contract. Check that the Guard daemon is running."
_CONTRACT_KEYS = (
    "schema_version",
    "generated_at",
    "install_target",
    "artifact_snapshot",
    "capability_manifest",
    "artifact_diff",
    "provenance_record",
    "trust_evidence_bundle",
    "policy_recommendation",
    "install_verdict",
    "abom_entry",
    "threat_intelligence",
    "cisco_evidence",
)
_OPTIONAL_CONTRACT_KEYS = frozenset({"cisco_evidence"})


def _scan_args(scan_result: ScanResult) -> dict[str, object]:
    trust_report = scan_result.trust_report
    return {
        "score": scan_result.score,
        "grade": scan_result.grade,
        "timestamp": scan_result.timestamp,
        "plugin_dir": scan_result.plugin_dir,
        "scope": scan_result.scope,
        "ecosystems": list(scan_result.ecosystems),
        "packages": [asdict(package) for package in scan_result.packages],
        "category_names": [category.name for category in scan_result.categories],
        "findings": [{"title": finding.title, "severity": finding.severity.value} for finding in scan_result.findings],
        "severity_counts": scan_result.severity_counts,
        "integrations": [asdict(integration) for integration in scan_result.integrations],
        "trust_total": None if trust_report is None else trust_report.total,
    }


def build_consumer_mode_contract(
    target: Path,
    intended_harness: str | None = None,
    options: ScanOptions | None = None,
) -> dict[str, object]:
    """Build the stable consumer-mode payload for a local artifact."""

    scan_result = scan_plugin(target, options=options)
    try:
        answer = native_runner_authority(
            "consumer_mode_contract",
            {
                "target": str(target),
                "target_name": target.name,
                "intended_harness": intended_harness,
                "scan": _scan_args(scan_result),
            },
        )
    except NativeRunnerAuthorityError as error:
        raise RuntimeError(_UNAVAILABLE_MESSAGE) from error
    contract = answer.get("contract")
    if not isinstance(contract, dict) or not _complete(contract):
        raise RuntimeError(_UNAVAILABLE_MESSAGE)
    return {key: contract[key] for key in _CONTRACT_KEYS if key in contract}


def _complete(contract: dict[str, object]) -> bool:
    """A contract without every required key, or without a verdict action, is refused."""

    if any(key not in contract for key in _CONTRACT_KEYS if key not in _OPTIONAL_CONTRACT_KEYS):
        return False
    verdict = contract["install_verdict"]
    return isinstance(verdict, dict) and isinstance(verdict.get("action"), str)
