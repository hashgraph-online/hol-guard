"""Local package-request evaluation for HOL Guard supply-chain protection."""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..models import GuardArtifact
from ..store import GuardStore
from ..store_evidence import EvidenceRecord
from .package_manifest_diff import _DeadlineExceededError, _dependency_map_for_path
from .runner import (
    _guard_sync_headers,
    _normalized_receipts_sync_url,
    _urlopen_json_with_timeout_retry,
)
from .supply_chain_bundle import evaluate_cached_supply_chain_bundle, load_supply_chain_bundle_response
from .supply_chain_bundle_models import (
    SupplyChainBundlePackage,
    SupplyChainBundlePolicyRule,
    SupplyChainBundleResponse,
)

_DECISION_RANK = {"allow": 0, "monitor": 1, "warn": 2, "ask": 3, "block": 4}
_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_TIMEOUT_SECONDS = 1
_RETRY_TIMEOUT_SECONDS = 1
_CLOUD_DASHBOARD_URL = "https://hol.org/guard/inbox"


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
    policy_action: str
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
        return cls(
            decision=str(payload.get("decision") or "monitor"),
            policy_action=str(payload.get("policy_action") or "allow"),
            enforcement=str(payload.get("enforcement") or "offline_cached"),
            entitlement_state=str(payload.get("entitlement_state") or "premium"),
            cache_status=str(payload.get("cache_status") or "hit"),
            package_intent_hash=package_intent_hash,
            policy_version=policy_version,
            bundle_version=bundle_version,
            workspace_fingerprint=workspace_fingerprint,
            reasons=tuple(item for item in payload.get("reasons", []) if isinstance(item, dict)),
            packages=tuple(item for item in payload.get("packages", []) if isinstance(item, dict)),
            risk_summary=str(payload.get("risk_summary") or "HOL Guard recorded this package request."),
            user_copy=SupplyChainUserCopy(
                title=str(user_copy_map.get("title") or "Monitoring this package"),
                summary=str(user_copy_map.get("summary") or "HOL Guard recorded this package request."),
                next_step=_optional_string(user_copy_map.get("next_step")),
                dashboard_url=_optional_string(user_copy_map.get("dashboard_url")),
                harness_message=str(user_copy_map.get("harness_message") or payload.get("risk_summary") or ""),
            ),
            matched_rule_id=_optional_string(payload.get("matched_rule_id")),
            exception_id=_optional_string(payload.get("exception_id")),
            refresh_required=bool(payload.get("refresh_required")),
            record_monitor_evidence=bool(payload.get("record_monitor_evidence")),
        )


def evaluate_package_request_artifact(
    *,
    artifact: GuardArtifact,
    store: GuardStore,
    workspace_dir: Path | None,
    now: str | None = None,
) -> PackageRequestEvaluation:
    now_value = now or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    targets = _targets_from_artifact(artifact)
    package_intent_hash = artifact.artifact_id.rsplit(":", 1)[-1]
    workspace_id = store.get_cloud_workspace_id()
    bundle_payload = store.get_cached_supply_chain_bundle(workspace_id) if workspace_id is not None else None
    bundle_response = load_supply_chain_bundle_response(bundle_payload) if isinstance(bundle_payload, dict) else None
    bundle_meta = _bundle_meta(bundle_payload) if isinstance(bundle_payload, dict) else None
    workspace_fingerprint = (
        _workspace_fingerprint(workspace_id, workspace_dir=workspace_dir, artifact=artifact, bundle_meta=bundle_meta)
        if workspace_id is not None
        else None
    )
    if workspace_id is not None and bundle_meta is not None:
        cached = store.get_cached_supply_chain_evaluation(
            workspace_id=workspace_id,
            package_intent_hash=package_intent_hash,
            feed_snapshot_hash=bundle_meta["feed_snapshot_hash"],
            policy_hash=bundle_meta["policy_hash"],
            scoring_version=bundle_meta["scoring_version"],
            bundle_version=bundle_meta["bundle_version"],
        )
        if isinstance(cached, dict):
            cached_workspace_fingerprint = _optional_string(cached.get("workspace_fingerprint"))
            if cached_workspace_fingerprint == workspace_fingerprint:
                cached_result = PackageRequestEvaluation.from_cache_dict(
                    cached,
                    package_intent_hash=package_intent_hash,
                    policy_version=bundle_meta["policy_hash"],
                    bundle_version=bundle_meta["bundle_version"],
                    workspace_fingerprint=workspace_fingerprint,
                )
                _persist_evidence(store=store, artifact=artifact, evaluation=cached_result, now=now_value)
                return cached_result
    bundle_evaluation = (
        _evaluate_with_bundle(
            artifact=artifact,
            targets=targets,
            bundle_response=bundle_response,
            workspace_dir=workspace_dir,
            workspace_id=workspace_id,
        )
        if bundle_response is not None
        else None
    )
    if bundle_evaluation is not None and bundle_meta is not None and bundle_evaluation.decision != "monitor":
        result = _finalize_evaluation(
            bundle_evaluation, package_intent_hash=package_intent_hash, workspace_fingerprint=workspace_fingerprint
        )
        store.cache_supply_chain_evaluation(
            workspace_id=workspace_id or bundle_payload["bundle"]["workspaceId"],
            package_intent_hash=package_intent_hash,
            feed_snapshot_hash=bundle_meta["feed_snapshot_hash"],
            policy_hash=bundle_meta["policy_hash"],
            scoring_version=bundle_meta["scoring_version"],
            bundle_version=bundle_meta["bundle_version"],
            decision=result.to_cache_dict(),
            now=now_value,
        )
        _persist_evidence(store=store, artifact=artifact, evaluation=result, now=now_value)
        if result.refresh_required:
            store.add_event("supply_chain_bundle_refresh_requested", {"artifact_id": artifact.artifact_id}, now_value)
        return result
    if bundle_evaluation is not None and bundle_evaluation.refresh_required:
        fallback = _finalize_evaluation(
            bundle_evaluation,
            package_intent_hash=package_intent_hash,
            workspace_fingerprint=workspace_fingerprint,
        )
        _persist_evidence(store=store, artifact=artifact, evaluation=fallback, now=now_value)
        store.add_event("supply_chain_bundle_refresh_requested", {"artifact_id": artifact.artifact_id}, now_value)
        return fallback
    cloud_result, cloud_fallback_reason = _evaluate_with_cloud(
        artifact=artifact,
        targets=targets,
        workspace_dir=workspace_dir,
        workspace_id=workspace_id,
        workspace_fingerprint=workspace_fingerprint,
        bundle_meta=bundle_meta,
        store=store,
    )
    if cloud_result is not None:
        upgraded = cloud_result
        if cloud_result.enforcement == "upgrade_required":
            heuristic = _heuristic_result(artifact=artifact, targets=targets)
            if heuristic is not None and _decision_rank(heuristic.decision) > _decision_rank(cloud_result.decision):
                upgraded = _finalize_evaluation(
                    _EvaluationDraft(
                        decision=heuristic.decision,
                        enforcement="free_local",
                        entitlement_state="free",
                        cache_status="upgrade-gated",
                        packages=heuristic.packages,
                        reasons=heuristic.reasons,
                        matched_rule_id=heuristic.matched_rule_id,
                        exception_id=heuristic.exception_id,
                        refresh_required=False,
                        record_monitor_evidence=heuristic.record_monitor_evidence,
                        bundle_version=None,
                        policy_version=bundle_meta["policy_hash"] if bundle_meta is not None else "local:none",
                    ),
                    package_intent_hash=package_intent_hash,
                    workspace_fingerprint=workspace_fingerprint,
                )
        _persist_evidence(store=store, artifact=artifact, evaluation=upgraded, now=now_value)
        return upgraded
    if bundle_evaluation is not None:
        fallback = _finalize_evaluation(
            bundle_evaluation, package_intent_hash=package_intent_hash, workspace_fingerprint=workspace_fingerprint
        )
        if cloud_fallback_reason is not None:
            fallback = _with_additional_reason(fallback, cloud_fallback_reason)
        _persist_evidence(store=store, artifact=artifact, evaluation=fallback, now=now_value)
        if fallback.refresh_required:
            store.add_event("supply_chain_bundle_refresh_requested", {"artifact_id": artifact.artifact_id}, now_value)
        return fallback
    heuristic = _heuristic_result(artifact=artifact, targets=targets)
    if heuristic is None:
        heuristic = _EvaluationDraft(
            decision="monitor",
            enforcement="free_local" if workspace_id is None else "local_fallback",
            entitlement_state="free" if workspace_id is None else "premium",
            cache_status="miss",
            packages=tuple(_unknown_package_result(target) for target in targets),
            reasons=(
                {
                    "code": "no_cached_match",
                    "message": "Guard recorded this package request and will keep watching for new intelligence.",
                    "severity": "unknown",
                    "source": "guard-local",
                },
            ),
            matched_rule_id=None,
            exception_id=None,
            refresh_required=False,
            record_monitor_evidence=True,
            bundle_version=None,
            policy_version=bundle_meta["policy_hash"] if bundle_meta is not None else "local:none",
        )
    result = _finalize_evaluation(
        heuristic, package_intent_hash=package_intent_hash, workspace_fingerprint=workspace_fingerprint
    )
    if cloud_fallback_reason is not None:
        result = _with_additional_reason(result, cloud_fallback_reason)
    _persist_evidence(store=store, artifact=artifact, evaluation=result, now=now_value)
    return result


@dataclass(frozen=True, slots=True)
class _EvaluationDraft:
    decision: str
    enforcement: str
    entitlement_state: str
    cache_status: str
    packages: tuple[dict[str, object], ...]
    reasons: tuple[dict[str, object], ...]
    matched_rule_id: str | None
    exception_id: str | None
    refresh_required: bool
    record_monitor_evidence: bool
    bundle_version: str | None
    policy_version: str


def _finalize_evaluation(
    draft: _EvaluationDraft,
    *,
    package_intent_hash: str,
    workspace_fingerprint: str | None,
) -> PackageRequestEvaluation:
    primary_package = draft.packages[0] if draft.packages else {}
    package_display = _package_display_name(primary_package)
    requested_version = _optional_string(primary_package.get("requestedVersion")) or _optional_string(
        primary_package.get("resolvedVersion")
    )
    package_ref = f"{package_display}@{requested_version}" if requested_version else package_display
    prefix = {
        "block": "HOL Guard blocked",
        "ask": "HOL Guard paused",
        "warn": "HOL Guard found risk signals for",
    }.get(draft.decision, "HOL Guard recorded")
    risk_summary = {
        "block": f"{prefix} `{package_ref}` before install.",
        "ask": f"{prefix} `{package_ref}` for review before install.",
        "warn": f"{prefix} `{package_ref}` before install.",
        "monitor": f"{prefix} `{package_ref}` for continued monitoring.",
        "allow": f"{prefix} `{package_ref}` as trusted by policy.",
    }[draft.decision]
    reason_message = _optional_string(draft.reasons[0].get("message")) if draft.reasons else None
    fix_command = _fix_command(primary_package)
    title = {
        "block": "Critical install blocked",
        "ask": "Review required",
        "warn": "Proceed with caution",
        "monitor": "Monitoring this package",
        "allow": "Allowed by policy",
    }[draft.decision]
    summary = (
        reason_message
        or {
            "block": f"{package_display} needs a safer version before you continue.",
            "ask": f"{package_display} needs a human review before Guard allows it.",
            "warn": f"Guard found risk signals for {package_display}. Proceed with caution.",
            "monitor": "Guard recorded the package intent and will keep watching for new intelligence.",
            "allow": "Guard matched a scoped allow rule for this package request.",
        }[draft.decision]
    )
    if len(draft.packages) > 1:
        others = ", ".join(_package_display_name(item) for item in draft.packages[1:3])
        if others:
            summary = f"{summary} Also flagged: {others}."
    harness_parts = [risk_summary]
    if reason_message:
        harness_parts.append(f"Reason: {reason_message}.")
    if fix_command:
        harness_parts.append(f"Fix: install `{fix_command}` or choose a team exception.")
    harness_parts.append(f"Review evidence: {_CLOUD_DASHBOARD_URL}.")
    user_copy = SupplyChainUserCopy(
        title=title,
        summary=summary,
        next_step=fix_command,
        dashboard_url=_CLOUD_DASHBOARD_URL,
        harness_message=" ".join(part.strip() for part in harness_parts if part.strip()),
    )
    return PackageRequestEvaluation(
        decision=draft.decision,
        policy_action={
            "allow": "allow",
            "monitor": "allow",
            "warn": "warn",
            "ask": "require-reapproval",
            "block": "block",
        }[draft.decision],
        enforcement=draft.enforcement,
        entitlement_state=draft.entitlement_state,
        cache_status=draft.cache_status,
        package_intent_hash=package_intent_hash,
        policy_version=draft.policy_version,
        bundle_version=draft.bundle_version,
        workspace_fingerprint=workspace_fingerprint,
        reasons=draft.reasons,
        packages=draft.packages,
        risk_summary=risk_summary,
        user_copy=user_copy,
        matched_rule_id=draft.matched_rule_id,
        exception_id=draft.exception_id,
        refresh_required=draft.refresh_required,
        record_monitor_evidence=draft.record_monitor_evidence,
        evidence_ids=tuple(
            _evidence_id(package_intent_hash, item)
            for item in draft.packages
            if _should_record_package(item, draft.decision)
        ),
    )


def _evaluate_with_cloud(
    *,
    artifact: GuardArtifact,
    targets: tuple[dict[str, object], ...],
    workspace_dir: Path | None,
    workspace_id: str | None,
    workspace_fingerprint: str | None,
    bundle_meta: dict[str, str] | None,
    store: GuardStore,
) -> tuple[PackageRequestEvaluation | None, dict[str, object] | None]:
    if workspace_id is None or workspace_fingerprint is None:
        return None, None
    sync_credentials = store.get_sync_credentials()
    if sync_credentials is None:
        return None, None
    request_payload = _build_request_payload(
        artifact=artifact,
        targets=targets,
        workspace_dir=workspace_dir,
        workspace_fingerprint=workspace_fingerprint,
        policy_version=bundle_meta["policy_hash"] if bundle_meta is not None else "local:none",
    )
    request = urllib.request.Request(
        _normalized_supply_chain_evaluate_url(sync_credentials["sync_url"], workspace_id),
        data=json.dumps(request_payload).encode("utf-8"),
        headers=_guard_sync_headers(sync_credentials["token"]),
        method="POST",
    )
    try:
        response_payload = _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_TIMEOUT_SECONDS,
            retry_timeout_seconds=_RETRY_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as error:
        return None, _cloud_fallback_reason(
            code="cloud_http_error",
            message=(f"Guard cloud evaluation returned HTTP {error.code}, so Guard fell back to local intelligence."),
        )
    except OSError:
        return None, _cloud_fallback_reason(
            code="cloud_timeout",
            message="Guard cloud evaluation timed out, so Guard fell back to local intelligence.",
        )
    except ValueError:
        return None, _cloud_fallback_reason(
            code="cloud_invalid_response",
            message="Guard cloud evaluation returned an invalid response, so Guard fell back locally.",
        )
    if not isinstance(response_payload, dict):
        return None, _cloud_fallback_reason(
            code="cloud_invalid_response",
            message="Guard cloud evaluation returned an invalid response, so Guard fell back locally.",
        )
    if not isinstance(response_payload.get("packages"), list):
        return None, _cloud_fallback_reason(
            code="cloud_invalid_response",
            message="Guard cloud evaluation returned an invalid package payload, so Guard fell back locally.",
        )
    packages = tuple(
        _package_from_cloud_result(item) for item in response_payload["packages"] if isinstance(item, dict)
    )
    reasons = tuple(item for item in response_payload.get("reasons", []) if isinstance(item, dict))
    normalized_decision = _normalize_bundle_action(str(response_payload.get("decision") or "monitor"))
    draft = _EvaluationDraft(
        decision=normalized_decision,
        enforcement=str(response_payload.get("enforcement") or "premium_cloud"),
        entitlement_state=str(response_payload.get("entitlementState") or "premium"),
        cache_status=str(response_payload.get("cacheStatus") or "miss"),
        packages=packages,
        reasons=reasons,
        matched_rule_id=None,
        exception_id=None,
        refresh_required=False,
        record_monitor_evidence=normalized_decision == "monitor",
        bundle_version=bundle_meta["bundle_version"] if bundle_meta is not None else None,
        policy_version=str(
            response_payload.get("policyVersion")
            or (bundle_meta["policy_hash"] if bundle_meta is not None else "local:none")
        ),
    )
    evaluation = _finalize_evaluation(
        draft,
        package_intent_hash=artifact.artifact_id.rsplit(":", 1)[-1],
        workspace_fingerprint=workspace_fingerprint,
    )
    copy_payload = response_payload.get("copy")
    if isinstance(copy_payload, dict):
        title = _optional_string(copy_payload.get("title"))
        summary = _optional_string(copy_payload.get("summary"))
        if title is not None or summary is not None:
            updated_summary = summary or evaluation.user_copy.summary
            harness_parts = [evaluation.risk_summary, updated_summary]
            if evaluation.user_copy.next_step:
                harness_parts.append(f"Fix: run `{evaluation.user_copy.next_step}`.")
            harness_parts.append(f"Review evidence: {_CLOUD_DASHBOARD_URL}.")
            evaluation = replace(
                evaluation,
                user_copy=SupplyChainUserCopy(
                    title=title or evaluation.user_copy.title,
                    summary=updated_summary,
                    next_step=evaluation.user_copy.next_step,
                    dashboard_url=evaluation.user_copy.dashboard_url,
                    harness_message=" ".join(harness_parts),
                ),
            )
    return evaluation, None


def _evaluate_with_bundle(
    *,
    artifact: GuardArtifact,
    targets: tuple[dict[str, object], ...],
    bundle_response,
    workspace_dir: Path | None,
    workspace_id: str | None,
) -> _EvaluationDraft | None:
    bundle_meta = _bundle_meta(bundle_response.to_dict())
    refresh_required = False
    packages: list[dict[str, object]] = []
    for target in targets:
        exact_version = _exact_version(_optional_string(target.get("version")) or _optional_string(target.get("range")))
        package_match = (
            _bundle_package(
                bundle_response,
                package_name=str(target["normalized_name"]),
                package_version=exact_version,
            )
            if exact_version is not None
            else None
        )
        matched_rule = _matching_policy_rule(
            bundle_response.bundle.policy_rules,
            target=target,
            harness=artifact.harness,
            package_severity=package_match.normalized_severity if package_match is not None else None,
        )
        if matched_rule is not None:
            decision = _normalize_bundle_action(matched_rule.action)
            package = _policy_package_result(target, decision=decision, rule_id=matched_rule.rule_id)
            packages.append(package)
            continue
        if exact_version is None:
            continue
        offline = evaluate_cached_supply_chain_bundle(
            bundle_response,
            package_name=str(target["normalized_name"]),
            package_version=exact_version,
        )
        if package_match is None:
            continue
        refresh_required = refresh_required or offline.stale
        package = _bundle_package_result(
            target=target,
            package=package_match,
            decision=_normalize_bundle_action(offline.action),
            reason=offline.reason,
            stale=offline.stale,
        )
        packages.append(package)
    packages.extend(
        _transitive_lockfile_results(bundle_response=bundle_response, artifact=artifact, workspace_dir=workspace_dir)
    )
    if not packages:
        return None
    packages.sort(key=lambda item: _decision_rank(str(item.get("decision") or "monitor")), reverse=True)
    decision = str(packages[0].get("decision") or "monitor")
    winning_rule_id = _optional_string(packages[0].get("ruleId"))
    return _EvaluationDraft(
        decision=decision,
        enforcement="policy_override" if winning_rule_id is not None else "offline_cached",
        entitlement_state="premium" if workspace_id is not None else "free",
        cache_status="stale" if refresh_required else "miss",
        packages=tuple(packages),
        reasons=tuple(
            reason for package in packages for reason in package.get("reasons", []) if isinstance(reason, dict)
        ),
        matched_rule_id=winning_rule_id,
        exception_id=winning_rule_id if decision == "allow" else None,
        refresh_required=refresh_required,
        record_monitor_evidence=decision == "monitor",
        bundle_version=bundle_meta["bundle_version"],
        policy_version=bundle_meta["policy_hash"],
    )


def _heuristic_result(*, artifact: GuardArtifact, targets: tuple[dict[str, object], ...]) -> _EvaluationDraft | None:
    packages: list[dict[str, object]] = []
    for target in targets:
        source_url = _optional_string(target.get("source_url"))
        if source_url is not None and source_url.lower().startswith("http://"):
            packages.append(
                {
                    "decision": "block",
                    "ecosystem": target["ecosystem"],
                    "name": target["name"],
                    "namespace": target["namespace"],
                    "requestedVersion": _optional_string(target.get("range"))
                    or _optional_string(target.get("version")),
                    "resolvedVersion": _optional_string(target.get("version")),
                    "recommendedFixVersion": None,
                    "riskScore": None,
                    "dependencyPath": None,
                    "reasons": (
                        {
                            "code": "insecure_source_url",
                            "message": f"Insecure HTTP package source: {source_url}",
                            "severity": "high",
                            "source": "guard-local",
                        },
                    ),
                }
            )
    if not packages:
        return None
    return _EvaluationDraft(
        decision="block",
        enforcement="free_local",
        entitlement_state="free",
        cache_status="miss",
        packages=tuple(packages),
        reasons=tuple(reason for package in packages for reason in package["reasons"]),
        matched_rule_id=None,
        exception_id=None,
        refresh_required=False,
        record_monitor_evidence=False,
        bundle_version=None,
        policy_version="local:none",
    )


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
                    "decision": evaluation.decision,
                    "enforcement": evaluation.enforcement,
                    "exception_id": evaluation.exception_id,
                    "matched_rule_id": evaluation.matched_rule_id,
                    "package": package,
                    "reasons": package.get("reasons", []),
                },
                action_identity=evaluation.exception_id or evaluation.matched_rule_id,
                created_at=now,
            )
        )


def _targets_from_artifact(artifact: GuardArtifact) -> tuple[dict[str, object], ...]:
    raw_targets = artifact.metadata.get("targets")
    if not isinstance(raw_targets, list):
        return ()
    parsed: list[dict[str, object]] = []
    for item in raw_targets:
        if not isinstance(item, dict):
            continue
        package_name = _optional_string(item.get("package_name"))
        if package_name is None:
            continue
        namespace, name = _split_namespace_name(package_name)
        requested = _optional_string(item.get("requested_specifier"))
        exact_version = _exact_version(requested)
        raw_spec = _optional_string(item.get("raw_spec")) or package_name
        source_url = _optional_string(item.get("source_url"))
        if source_url is None:
            source_url = _source_url_from_specifier(requested)
        if source_url is None:
            source_url = _source_url_from_raw_spec(raw_spec)
        parsed.append(
            {
                "ecosystem": str(item.get("ecosystem") or "npm"),
                "package_name": package_name,
                "normalized_name": package_name.lower(),
                "namespace": namespace,
                "name": name,
                "raw_spec": raw_spec,
                "version": exact_version,
                "range": requested if exact_version is None else None,
                "source_url": source_url,
            }
        )
    return tuple(parsed)


def _bundle_meta(bundle_payload: dict[str, object]) -> dict[str, str]:
    bundle = bundle_payload["bundle"]
    assert isinstance(bundle, dict)
    return {
        "bundle_version": str(bundle["bundleVersion"]),
        "feed_snapshot_hash": str(bundle["feedSnapshotHash"]),
        "policy_hash": str(bundle["policyHash"]),
        "scoring_version": str(bundle["scoringVersion"]),
    }


def _workspace_fingerprint(
    workspace_id: str,
    *,
    workspace_dir: Path | None,
    artifact: GuardArtifact,
    bundle_meta: dict[str, str] | None,
) -> str:
    manifest_hashes = _hash_paths(workspace_dir, artifact.metadata.get("manifest_paths"))
    lockfile_hashes = _hash_paths(workspace_dir, artifact.metadata.get("lockfile_paths"))
    return _stable_hash(
        {
            "workspace_id": workspace_id,
            "workspace_name": workspace_dir.name if workspace_dir is not None else None,
            "manifest_hashes": manifest_hashes,
            "lockfile_hashes": lockfile_hashes,
            "bundle_policy_hash": bundle_meta["policy_hash"] if bundle_meta is not None else None,
        }
    )


def _build_request_payload(
    *,
    artifact: GuardArtifact,
    targets: tuple[dict[str, object], ...],
    workspace_dir: Path | None,
    workspace_fingerprint: str,
    policy_version: str,
) -> dict[str, object]:
    lockfile_context = _lockfile_context(workspace_dir, artifact)
    return {
        "commandShape": {
            "argCount": len(str(artifact.metadata.get("redacted_command") or "").split()),
            "flags": [item for item in artifact.metadata.get("flags", []) if isinstance(item, str)],
            "packageManager": str(artifact.metadata.get("package_manager") or "unknown"),
            "redacted": True,
            "verb": str(artifact.metadata.get("intent_kind") or "install"),
        },
        "harness": artifact.harness,
        "lockfileContext": lockfile_context,
        "packages": [
            {
                "direct": True,
                "ecosystem": str(target["ecosystem"]),
                "name": str(target["name"]),
                "namespace": target["namespace"],
                **({"version": str(target["version"])} if target.get("version") else {}),
                **({"range": str(target["range"])} if target.get("range") else {}),
            }
            for target in targets
        ],
        "policyVersion": policy_version,
        "workspaceFingerprint": workspace_fingerprint,
    }


def _lockfile_context(workspace_dir: Path | None, artifact: GuardArtifact) -> dict[str, object] | None:
    if workspace_dir is None:
        return None
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list) or not lockfile_paths:
        return None
    lockfile_path = workspace_dir / str(lockfile_paths[0])
    if not lockfile_path.exists():
        return None
    try:
        lockfile_text = lockfile_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    dependencies = _safe_dependency_map_for_path(
        str(lockfile_path.name), lockfile_text, deadline=time.monotonic() + 0.2
    )
    manifest_hashes = _hash_paths(workspace_dir, artifact.metadata.get("manifest_paths"))
    return {
        "dependencyCount": len(dependencies),
        "fileName": lockfile_path.name,
        "lockfileHash": hashlib.sha256(lockfile_text.encode("utf-8")).hexdigest(),
        "manifestHash": manifest_hashes[0] if manifest_hashes else None,
        "repository": workspace_dir.name,
    }


def _transitive_lockfile_results(
    *, bundle_response, artifact: GuardArtifact, workspace_dir: Path | None
) -> list[dict[str, object]]:
    if workspace_dir is None:
        return []
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list):
        return []
    results: list[dict[str, object]] = []
    for relative_path in lockfile_paths:
        lockfile_path = workspace_dir / str(relative_path)
        if not lockfile_path.exists():
            continue
        try:
            lockfile_text = lockfile_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        dependency_map = _safe_dependency_map_for_path(
            str(lockfile_path.name),
            lockfile_text,
            deadline=time.monotonic() + 0.2,
        )
        for dependency_path, version in dependency_map.items():
            if "node_modules/" not in dependency_path:
                continue
            package_name = dependency_path.rsplit("node_modules/", 1)[-1]
            offline = evaluate_cached_supply_chain_bundle(
                bundle_response, package_name=package_name, package_version=version
            )
            if _normalize_bundle_action(offline.action) not in {"ask", "block", "warn"}:
                continue
            package_match = _bundle_package(bundle_response, package_name=package_name, package_version=version)
            if package_match is None:
                continue
            results.append(
                {
                    "decision": _normalize_bundle_action(offline.action),
                    "ecosystem": package_match.ecosystem,
                    "name": package_match.name,
                    "namespace": package_match.namespace,
                    "requestedVersion": version,
                    "resolvedVersion": version,
                    "recommendedFixVersion": package_match.recommended_fix_version,
                    "riskScore": package_match.risk_score,
                    "dependencyPath": dependency_path,
                    "reasons": (
                        {
                            "code": "transitive_lockfile_match",
                            "message": (
                                f"Existing lockfile already includes vulnerable dependency path {dependency_path}."
                            ),
                            "severity": package_match.normalized_severity,
                            "source": "lockfile",
                        },
                    ),
                }
            )
    return results


def _bundle_package_result(
    *,
    target: dict[str, object],
    package: SupplyChainBundlePackage,
    decision: str,
    reason: str,
    stale: bool,
) -> dict[str, object]:
    severity = package.normalized_severity if stale is False else "unknown"
    return {
        "decision": decision,
        "ecosystem": package.ecosystem,
        "name": package.name,
        "namespace": package.namespace,
        "requestedVersion": _optional_string(target.get("version")) or _optional_string(target.get("range")),
        "resolvedVersion": package.version,
        "recommendedFixVersion": package.recommended_fix_version,
        "riskScore": package.risk_score,
        "dependencyPath": None,
        "reasons": (
            {
                "advisoryId": package.related_advisory_ids[0] if package.related_advisory_ids else None,
                "code": reason,
                "message": _bundle_reason_message(package, reason=reason, stale=stale),
                "severity": severity,
                "source": "bundle",
            },
        ),
    }


def _policy_package_result(target: dict[str, object], *, decision: str, rule_id: str) -> dict[str, object]:
    return {
        "decision": decision,
        "ecosystem": target["ecosystem"],
        "name": target["name"],
        "namespace": target["namespace"],
        "requestedVersion": _optional_string(target.get("version")) or _optional_string(target.get("range")),
        "resolvedVersion": _optional_string(target.get("version")),
        "recommendedFixVersion": None,
        "riskScore": None,
        "dependencyPath": None,
        "ruleId": rule_id,
        "reasons": (
            {
                "code": "policy_override",
                "message": f"Local synced policy rule {rule_id} matched this package request.",
                "severity": "low",
                "source": "policy",
            },
        ),
    }


def _package_from_cloud_result(item: dict[str, object]) -> dict[str, object]:
    return {
        "decision": _normalize_bundle_action(str(item.get("decision") or "monitor")),
        "ecosystem": str(item.get("ecosystem") or "npm"),
        "name": str(item.get("name") or "unknown"),
        "namespace": _optional_string(item.get("namespace")),
        "requestedVersion": _optional_string(item.get("requestedVersion")),
        "resolvedVersion": _optional_string(item.get("resolvedVersion")),
        "recommendedFixVersion": _optional_string(item.get("recommendedFixVersion")),
        "riskScore": item.get("riskScore"),
        "dependencyPath": None,
        "reasons": tuple(reason for reason in item.get("reasons", []) if isinstance(reason, dict)),
    }


def _unknown_package_result(target: dict[str, object]) -> dict[str, object]:
    return {
        "decision": "monitor",
        "ecosystem": target["ecosystem"],
        "name": target["name"],
        "namespace": target["namespace"],
        "requestedVersion": _optional_string(target.get("range")) or _optional_string(target.get("version")),
        "resolvedVersion": _optional_string(target.get("version")),
        "recommendedFixVersion": None,
        "riskScore": None,
        "dependencyPath": None,
        "reasons": (
            {
                "code": "no_cached_match",
                "message": "Guard recorded this package request and will keep watching for new intelligence.",
                "severity": "unknown",
                "source": "guard-local",
            },
        ),
    }


def _source_url_from_specifier(specifier: str | None) -> str | None:
    if specifier is None:
        return None
    if "://" in specifier or specifier.startswith("git+"):
        return specifier
    return None


def _source_url_from_raw_spec(raw_spec: str) -> str | None:
    if raw_spec.startswith("@") and "@" in raw_spec[1:]:
        candidate = raw_spec.rsplit("@", 1)[-1]
    elif (
        "@" in raw_spec
        and not raw_spec.startswith("http://")
        and not raw_spec.startswith("https://")
        and not raw_spec.startswith("git+")
    ):
        candidate = raw_spec.split("@", 1)[1]
    else:
        candidate = raw_spec
    if "://" in candidate or candidate.startswith("git+"):
        return candidate
    return None


def _safe_dependency_map_for_path(path: str, text: str, *, deadline: float) -> dict[str, str]:
    try:
        return _dependency_map_for_path(path, text, deadline=deadline)
    except (
        _DeadlineExceededError,
        ET.ParseError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return {}


def _matching_policy_rule(
    rules: tuple[SupplyChainBundlePolicyRule, ...],
    *,
    target: dict[str, object],
    harness: str,
    package_severity: str | None,
) -> SupplyChainBundlePolicyRule | None:
    current_time = datetime.now(timezone.utc).timestamp()
    sorted_rules = sorted(
        rules, key=lambda item: (item.priority if item.priority is not None else 10_000, item.rule_id)
    )
    for rule in sorted_rules:
        if rule.enabled is False:
            continue
        if rule.expires_at is not None:
            try:
                if datetime.fromisoformat(rule.expires_at.replace("Z", "+00:00")).timestamp() <= current_time:
                    continue
            except ValueError:
                pass
        if rule.harness_selector is not None and rule.harness_selector != harness:
            continue
        if rule.ecosystem_selector is not None and rule.ecosystem_selector != target["ecosystem"]:
            continue
        if rule.package_selector is not None:
            selector = rule.package_selector.strip().lower()
            candidates = {
                str(target["normalized_name"]),
                str(target["name"]).lower(),
                f"{target['namespace']}/{target['name']}".lower()
                if target["namespace"] is not None
                else str(target["name"]).lower(),
                f"pkg:{target['ecosystem']}/{target['normalized_name']}",
            }
            if selector not in candidates:
                continue
        if rule.version_range_selector is not None and not _selector_matches_version(
            rule.version_range_selector, target
        ):
            continue
        if rule.severity_threshold is not None:
            if package_severity is None:
                continue
            if _severity_rank_value(package_severity) < _severity_rank_value(rule.severity_threshold):
                continue
        return rule
    return None


def _selector_matches_version(selector: str, target: dict[str, object]) -> bool:
    version = _optional_string(target.get("version"))
    requested_range = _optional_string(target.get("range"))
    if requested_range is not None and requested_range == selector:
        return True
    if version is None:
        return False
    if selector in {version, f"={version}", f"=={version}"}:
        return True
    try:
        return Version(version) in SpecifierSet(selector)
    except (InvalidSpecifier, InvalidVersion):
        return False


def _bundle_package(
    bundle_response: SupplyChainBundleResponse,
    *,
    package_name: str,
    package_version: str,
) -> SupplyChainBundlePackage | None:
    normalized = package_name.lower()
    for item in bundle_response.bundle.packages:
        full_name = f"{item.namespace}/{item.name}".lower() if item.namespace is not None else item.name.lower()
        if normalized not in {item.name.lower(), full_name}:
            continue
        if item.version == package_version:
            return item
    return None


def _severity_rank_value(value: str) -> int:
    return _SEVERITY_RANK.get(value.strip().lower(), _SEVERITY_RANK["unknown"])


def _normalize_bundle_action(value: str) -> str:
    if value == "review":
        return "ask"
    if value in _DECISION_RANK:
        return value
    return "monitor"


def _normalized_supply_chain_evaluate_url(sync_url: str, workspace_id: str) -> str:
    parsed = urllib.parse.urlsplit(_normalized_receipts_sync_url(sync_url))
    if parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        next_path = "/api/guard/supply-chain/evaluate"
    elif parsed.path.rstrip("/") == "/guard/receipts/sync":
        next_path = "/guard/supply-chain/evaluate"
    else:
        next_path = parsed.path.rstrip("/") + "/supply-chain/evaluate"
    query_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != "workspaceId"
    ]
    query_pairs.append(("workspaceId", workspace_id))
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            next_path,
            urllib.parse.urlencode(query_pairs),
            "",
        )
    )


def _hash_paths(workspace_dir: Path | None, raw_paths: object) -> list[str]:
    if workspace_dir is None or not isinstance(raw_paths, list):
        return []
    hashes: list[str] = []
    for item in raw_paths:
        path = workspace_dir / str(item)
        if not path.exists():
            continue
        hashes.append(hashlib.sha256(path.read_bytes()).hexdigest())
    return hashes


def _stable_hash(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _split_namespace_name(value: str) -> tuple[str | None, str]:
    if value.startswith("@") and "/" in value:
        namespace, name = value.split("/", 1)
        return namespace, name
    return None, value


def _exact_version(value: str | None) -> str | None:
    if value is None:
        return None
    if "://" in value or value.startswith("git+"):
        return None
    if value.startswith(("^", "~", "<", ">", "!", "*")):
        return None
    if any(token in value for token in ("||", " - ", ",")):
        return None
    return value


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _decision_rank(value: str) -> int:
    return _DECISION_RANK.get(value, 1)


def _fix_command(package: dict[str, object]) -> str | None:
    package_name = _package_display_name(package)
    fix_version = _optional_string(package.get("recommendedFixVersion"))
    ecosystem = _optional_string(package.get("ecosystem")) or "npm"
    if not fix_version:
        return None
    if ecosystem == "pypi":
        return f"pip install {package_name}=={fix_version}"
    return f"npm install {package_name}@{fix_version}"


def _package_display_name(package: dict[str, object]) -> str:
    namespace = _optional_string(package.get("namespace"))
    name = _optional_string(package.get("name")) or "package"
    return f"{namespace}/{name}" if namespace is not None else name


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
    package_name = _package_display_name(package)
    decision = str(package.get("decision") or "monitor")
    resolved_version = _optional_string(package.get("resolvedVersion")) or _optional_string(
        package.get("requestedVersion")
    )
    dependency_path = _optional_string(package.get("dependencyPath")) or "direct"
    identity = f"{package_intent_hash}:{package_name}:{resolved_version}:{dependency_path}:{decision}"
    return f"evidence-{hashlib.sha256(identity.encode()).hexdigest()[:16]}"


def _with_additional_reason(
    evaluation: PackageRequestEvaluation, reason: dict[str, object]
) -> PackageRequestEvaluation:
    updated_reasons = (*evaluation.reasons, reason)
    updated_packages = []
    for package in evaluation.packages:
        package_reasons = package.get("reasons")
        if isinstance(package_reasons, (tuple, list)):
            updated_package = dict(package)
            updated_package["reasons"] = (
                *tuple(item for item in package_reasons if isinstance(item, dict)),
                reason,
            )
            updated_packages.append(updated_package)
            continue
        updated_package = dict(package)
        updated_package["reasons"] = (reason,)
        updated_packages.append(updated_package)
    return replace(evaluation, reasons=updated_reasons, packages=tuple(updated_packages))


def _cloud_fallback_reason(*, code: str, message: str) -> dict[str, object]:
    return {
        "code": code,
        "message": message,
        "severity": "unknown",
        "source": "guard-cloud",
    }


def _bundle_reason_message(
    package: SupplyChainBundlePackage,
    *,
    reason: str,
    stale: bool,
) -> str:
    package_label = f"{package.name}@{package.version}"
    if stale:
        return f"Cached bundle is stale, so Guard kept {package_label} in monitor mode."
    if reason == "known_malware_or_kev":
        return f"Cached bundle flagged {package_label} from advisory intelligence."
    return f"Cached bundle matched {package_label}."
