"""Package-request evaluation DTOs and the evidence rows they imply.

The resident decides every package verdict and reads every stored evaluation
back into the view a caller shows. This module only holds the typed shape that
view arrives in and writes the evidence rows it implies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..models import GuardAction, GuardArtifact
from ..stable_digest import stable_digest_hex
from ..store import GuardStore
from ..store_evidence import EvidenceRecord
from .restricted_archive_download import RestrictedArchiveDownload
from .supply_chain_package_identity import PackageIdentityError, canonical_package_identity


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


@dataclass(frozen=True, slots=True)
class SupplyChainUserCopy:
    title: str
    summary: str
    next_step: str | None
    dashboard_url: str | None
    harness_message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "summary": self.summary,
            "next_step": self.next_step,
            "dashboard_url": self.dashboard_url,
            "harness_message": self.harness_message,
        }


@dataclass(frozen=True, slots=True)
class PackageRequestEvaluation:
    decision: str
    policy_action: GuardAction
    enforcement: str
    entitlement_state: str
    cache_status: str
    package_intent_hash: str
    policy_version: str
    bundle_version: str | None
    workspace_fingerprint: str | None
    reasons: tuple[dict[str, object], ...]
    packages: tuple[dict[str, object], ...]
    risk_summary: str
    user_copy: SupplyChainUserCopy
    matched_rule_id: str | None = None
    exception_id: str | None = None
    refresh_required: bool = False
    record_monitor_evidence: bool = False
    evidence_ids: tuple[str, ...] = ()
    external_archive_downloads: tuple[RestrictedArchiveDownload, ...] = ()
    external_archive_source_hashes: tuple[str, ...] = ()

    def to_cache_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "policy_action": self.policy_action,
            "enforcement": self.enforcement,
            "entitlement_state": self.entitlement_state,
            "cache_status": self.cache_status,
            "workspace_fingerprint": self.workspace_fingerprint,
            "reasons": list(self.reasons),
            "packages": list(self.packages),
            "matched_rule_id": self.matched_rule_id,
            "exception_id": self.exception_id,
            "risk_summary": self.risk_summary,
            "record_monitor_evidence": self.record_monitor_evidence,
            "external_archive_source_hashes": list(self.external_archive_source_hashes),
            "user_copy": self.user_copy.to_dict(),
        }

    def to_dict(self) -> dict[str, object]:
        payload = self.to_cache_dict()
        payload["package_intent_hash"] = self.package_intent_hash
        payload["policy_version"] = self.policy_version
        payload["bundle_version"] = self.bundle_version
        payload["workspace_fingerprint"] = self.workspace_fingerprint
        payload["refresh_required"] = self.refresh_required
        payload["evidence_ids"] = list(self.evidence_ids)
        if self.external_archive_downloads:
            payload["external_archive_inspection"] = [
                {
                    "sha256": download.sha256,
                    "size": download.size,
                    "source_url_hash": stable_digest_hex(download.source_url.encode("utf-8")),
                    "final_url_hash": stable_digest_hex(download.final_url.encode("utf-8")),
                }
                for download in self.external_archive_downloads
            ]
        return payload


def strip_review_evidence_tail(message: str) -> str:
    stripped = message.strip()
    lower_stripped = stripped.lower()
    for suffix in ("Review evidence: .", "Review evidence:.", "Review evidence:"):
        if lower_stripped.endswith(suffix.lower()):
            return stripped[: -len(suffix)].rstrip()
    return stripped


def _persist_evidence(
    *, store: GuardStore, artifact: GuardArtifact, evaluation: PackageRequestEvaluation, now: str
) -> None:
    if evaluation.decision == "allow":
        return
    if evaluation.decision == "monitor" and not evaluation.record_monitor_evidence:
        return
    for package in evaluation.packages:
        if not _should_record_package(package, evaluation.decision):
            continue
        evidence_id = _evidence_id(evaluation.package_intent_hash, package)
        store.add_evidence(
            EvidenceRecord(
                evidence_id=evidence_id,
                action_id=artifact.artifact_id,
                request_id=evaluation.package_intent_hash,
                harness=artifact.harness,
                workspace=artifact.source_scope,
                signal_id=str(package.get("decision") or evaluation.decision),
                category="supply-chain",
                severity=_reason_severity(package),
                confidence=1.0 if evaluation.decision in {"block", "ask"} else 0.6,
                summary=evaluation.risk_summary,
                details={
                    "agent_app": _optional_string(artifact.metadata.get("agent_app")) or artifact.harness,
                    "command_shape": _optional_string(artifact.metadata.get("redacted_command")),
                    "decision": evaluation.decision,
                    "enforcement": evaluation.enforcement,
                    "exception_id": evaluation.exception_id,
                    "harness": artifact.harness,
                    "matched_rule_id": evaluation.matched_rule_id,
                    "package": package,
                    "package_manager": _optional_string(artifact.metadata.get("package_manager")),
                    "repo_fingerprint": evaluation.workspace_fingerprint,
                    "reasons": package.get("reasons", []),
                    "workspace_fingerprint": evaluation.workspace_fingerprint,
                },
                action_identity=evaluation.exception_id or evaluation.matched_rule_id,
                created_at=now,
            )
        )


def _reason_severity(package: dict[str, object]) -> str:
    reasons = package.get("reasons")
    if isinstance(reasons, (tuple, list)):
        for item in reasons:
            if isinstance(item, dict):
                severity = _optional_string(item.get("severity"))
                if severity is not None:
                    return severity
    return "unknown"


def _should_record_package(package: dict[str, object], decision: str) -> bool:
    package_decision = str(package.get("decision") or decision)
    return package_decision in {"block", "ask", "warn"} or decision == "monitor"


def _evidence_id(package_intent_hash: str, package: dict[str, object]) -> str:
    decision = str(package.get("decision") or "monitor")
    dependency_path = _optional_string(package.get("dependencyPath")) or "direct"
    identity_payload = {
        "decision": decision,
        "dependency_path": dependency_path,
        "package_identity": _result_package_identity(package),
        "package_intent_hash": package_intent_hash,
    }
    encoded = json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"evidence-{stable_digest_hex(encoded, length=16)}"


def _result_package_identity(package: dict[str, object]) -> tuple[str, str, str, str, str, str]:
    ecosystem = _optional_string(package.get("ecosystem"))
    name = _optional_string(package.get("name")) or "package"
    namespace = _optional_string(package.get("namespace"))
    version = _optional_string(package.get("resolvedVersion")) or _optional_string(package.get("requestedVersion"))
    if ecosystem is not None:
        try:
            identity = canonical_package_identity(
                ecosystem=ecosystem,
                namespace=namespace,
                name=name,
                version=version or "*",
            )
            return (
                "canonical",
                identity.ecosystem,
                identity.namespace or "",
                identity.name,
                identity.version,
                "",
            )
        except PackageIdentityError:
            pass
    opaque_sha256 = stable_digest_hex(
        json.dumps(package, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    )
    return ("opaque", ecosystem or "", namespace or "", name, version or "", opaque_sha256)
