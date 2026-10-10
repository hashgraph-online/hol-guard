"""Package-request evaluation DTOs hydrated from the resident's answer.

The resident decides every package verdict. This module only holds the typed
shape Python callers read, hydrates it from the resident's payload and writes
the evidence rows that payload implies.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, replace

from ..action_lattice import normalize_guard_action_result
from ..models import GuardAction, GuardArtifact
from ..stable_digest import stable_digest_hex
from ..store import GuardStore
from ..store_evidence import EvidenceRecord
from .restricted_archive_download import RestrictedArchiveDownload
from .supply_chain_package_identity import PackageIdentityError, canonical_package_identity
from .supply_chain_support import ecosystem_support_metadata


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


_CLOUD_INBOX_URL_RE = re.compile(r"https?://[^\s]+/guard/inbox/?", re.IGNORECASE)


_LOCAL_REVIEW_INSTRUCTION = "Review this request in HOL Guard, then retry."


_LOCAL_REVIEW_INSTRUCTION_RE = re.compile(re.escape(_LOCAL_REVIEW_INSTRUCTION), re.IGNORECASE)


_LOCAL_APPROVAL_INSTRUCTION_RE = re.compile(
    r"\s*Open HOL Guard to approve or keep this blocked:\s*https?://\S+"
    r"(?:\s+After you choose,\s+retry the same .*? action\.)?",
    re.IGNORECASE,
)


_LOCAL_APPROVAL_REQUEST_URL_RE = re.compile(r"https?://[^\s]+/requests(?:/[^\s]*)?", re.IGNORECASE)


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

    @classmethod
    def from_cache_dict(
        cls,
        payload: dict[str, object],
        *,
        package_intent_hash: str,
        policy_version: str,
        bundle_version: str | None,
        workspace_fingerprint: str | None,
    ) -> PackageRequestEvaluation:
        user_copy = payload.get("user_copy")
        user_copy_map = user_copy if isinstance(user_copy, dict) else {}
        cached_packages = tuple(_with_support_metadata(item) for item in _dict_items(payload.get("packages")))
        policy_action_normalization = normalize_guard_action_result(
            payload.get("policy_action"),
            unknown_action="require-reapproval",
        )
        policy_action = policy_action_normalization.action
        cached_reasons = _dict_items(payload.get("reasons"))
        if not policy_action_normalization.recognized:
            normalization_reason: dict[str, object] = {
                "code": policy_action_normalization.reason_code,
                "message": "Cached package policy action was missing or unknown; Guard requires review.",
                "original_action": policy_action_normalization.original_action,
                "normalized_action": policy_action,
            }
            cached_reasons = (
                *cached_reasons,
                normalization_reason,
            )
        normalized_user_copy = _normalize_package_user_copy(
            SupplyChainUserCopy(
                title=str(user_copy_map.get("title") or "Monitoring this package"),
                summary=str(user_copy_map.get("summary") or "HOL Guard recorded this package request."),
                next_step=_optional_string(user_copy_map.get("next_step")),
                dashboard_url=_optional_string(user_copy_map.get("dashboard_url")),
                harness_message=str(user_copy_map.get("harness_message") or payload.get("risk_summary") or ""),
            ),
            policy_action=policy_action,
        )
        raw_external_archive_source_hashes = payload.get("external_archive_source_hashes")
        external_archive_source_hashes = (
            tuple(
                item
                for item in raw_external_archive_source_hashes
                if isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item)
            )
            if isinstance(raw_external_archive_source_hashes, (list, tuple))
            else ()
        )
        return cls(
            decision=str(payload.get("decision") or "monitor"),
            policy_action=policy_action,
            enforcement=str(payload.get("enforcement") or "offline_cached"),
            entitlement_state=str(payload.get("entitlement_state") or "premium"),
            cache_status=str(payload.get("cache_status") or "hit"),
            package_intent_hash=package_intent_hash,
            policy_version=policy_version,
            bundle_version=bundle_version,
            workspace_fingerprint=workspace_fingerprint,
            reasons=cached_reasons,
            packages=cached_packages,
            risk_summary=str(payload.get("risk_summary") or "HOL Guard recorded this package request."),
            user_copy=normalized_user_copy,
            matched_rule_id=_optional_string(payload.get("matched_rule_id")),
            exception_id=_optional_string(payload.get("exception_id")),
            refresh_required=bool(payload.get("refresh_required")),
            record_monitor_evidence=bool(payload.get("record_monitor_evidence")),
            external_archive_source_hashes=external_archive_source_hashes,
        )


def _normalize_package_user_copy(user_copy: SupplyChainUserCopy, *, policy_action: GuardAction) -> SupplyChainUserCopy:
    dashboard_url = user_copy.dashboard_url
    if _looks_like_cloud_inbox_url(dashboard_url):
        dashboard_url = None
    harness_message = _CLOUD_INBOX_URL_RE.sub("", user_copy.harness_message or "").strip()
    harness_message = " ".join(harness_message.split())
    harness_message = _strip_review_evidence_tail(harness_message)
    terminal_action = policy_action in {"sandbox-required", "block"}
    if terminal_action:
        dashboard_url = None
        harness_message = _LOCAL_APPROVAL_INSTRUCTION_RE.sub("", harness_message)
        harness_message = _LOCAL_APPROVAL_REQUEST_URL_RE.sub("", harness_message)
        harness_message = _LOCAL_REVIEW_INSTRUCTION_RE.sub("", harness_message)
        harness_message = " ".join(harness_message.split()).strip()
    needs_local_review = policy_action in {"review", "require-reapproval"}
    if needs_local_review and _LOCAL_REVIEW_INSTRUCTION.lower() not in harness_message.lower():
        harness_message = f"{harness_message} {_LOCAL_REVIEW_INSTRUCTION}".strip()
    return replace(user_copy, dashboard_url=dashboard_url, harness_message=harness_message)


def _strip_review_evidence_tail(message: str) -> str:
    stripped = message.strip()
    lower_stripped = stripped.lower()
    for suffix in ("Review evidence: .", "Review evidence:.", "Review evidence:"):
        if lower_stripped.endswith(suffix.lower()):
            return stripped[: -len(suffix)].rstrip()
    return stripped


def _looks_like_cloud_inbox_url(url: str | None) -> bool:
    if url is None or not url.strip():
        return False
    parsed = urllib.parse.urlparse(url.strip())
    return parsed.path.rstrip("/") == "/guard/inbox"


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


def _with_support_metadata(package: dict[str, object]) -> dict[str, object]:
    metadata = ecosystem_support_metadata(_optional_string(package.get("ecosystem")) or "unsupported")
    enriched = dict(package)
    enriched["supportLevel"] = metadata["support_level"]
    enriched["supportLabel"] = metadata["support_label"]
    return enriched


def _dict_items(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, dict))


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
