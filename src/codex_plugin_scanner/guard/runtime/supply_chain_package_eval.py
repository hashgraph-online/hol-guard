"""Local package-request evaluation for HOL Guard supply-chain protection."""

from __future__ import annotations

import hashlib
import io
import json
import posixpath
import re
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..config import load_guard_config, resolve_risk_action
from ..models import GuardArtifact
from ..store import GuardStore
from ..store_evidence import EvidenceRecord
from .js_semver import highest_js_version_for_selector, version_matches_js_selector
from .package_intent_common import split_python_extras
from .package_manifest_diff import (
    _DeadlineExceededError,
    _dependency_map_for_path,
    parse_manifest_dependencies,
)
from .runner import (
    GuardSyncNotConfiguredError,
    _guard_sync_headers,
    _normalized_receipts_sync_url,
    _resolve_guard_sync_auth_context,
    _urlopen_json_with_timeout_retry,
)
from .supply_chain import detect_supply_chain_risk
from .supply_chain_bundle import (
    SupplyChainBundleExpiredError,
    SupplyChainBundleMalformedError,
    check_supply_chain_bundle_freshness,
    evaluate_cached_supply_chain_bundle,
    load_supply_chain_bundle_response,
)
from .supply_chain_bundle_models import (
    SupplyChainBundlePackage,
    SupplyChainBundlePolicyRule,
    SupplyChainBundleResponse,
)
from .supply_chain_bundle_runtime import _is_high_confidence_block
from .supply_chain_support import ecosystem_support_metadata

_DECISION_RANK = {"allow": 0, "monitor": 1, "warn": 2, "ask": 3, "block": 4}
_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_TIMEOUT_SECONDS = 1
_RETRY_TIMEOUT_SECONDS = 1
_CLOUD_INBOX_URL_RE = re.compile(r"https?://[^\s]+/guard/inbox/?", re.IGNORECASE)
_LOCAL_REVIEW_INSTRUCTION = "Review this request in HOL Guard, then retry."
_LOCKFILE_PARSE_BUDGET_SECONDS = 0.2
_TRANSITIVE_BLOCK_CONFIDENCE_THRESHOLD = 900
_NPM_REGISTRY_METADATA_BASE_URL = "https://registry.npmjs.org"
_PYPI_REGISTRY_METADATA_BASE_URL = "https://pypi.org/pypi"
_TARBALL_SCAN_TIMEOUT_SECONDS = 2
_TARBALL_SCAN_MAX_BYTES = 6 * 1024 * 1024
_TARBALL_SCAN_MAX_FILES = 500
_TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES = 256 * 1024


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
        cached_packages = tuple(
            _with_support_metadata(item) for item in payload.get("packages", []) if isinstance(item, dict)
        )
        policy_action = str(payload.get("policy_action") or "allow")
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
            reasons=tuple(item for item in payload.get("reasons", []) if isinstance(item, dict)),
            packages=cached_packages,
            risk_summary=str(payload.get("risk_summary") or "HOL Guard recorded this package request."),
            user_copy=normalized_user_copy,
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
    now_timestamp = _parse_evaluation_timestamp(now_value)
    targets = _targets_from_artifact(artifact)
    package_intent_hash = artifact.artifact_id.rsplit(":", 1)[-1]
    workspace_id = store.get_cloud_workspace_id()
    bundle_payload = store.get_cached_supply_chain_bundle(workspace_id) if workspace_id is not None else None
    bundle_response: SupplyChainBundleResponse | None = None
    bundle_meta: dict[str, str] | None = None
    if isinstance(bundle_payload, dict):
        try:
            bundle_response = load_supply_chain_bundle_response(bundle_payload)
            bundle_meta = _bundle_meta(bundle_payload)
        except (AssertionError, KeyError, SupplyChainBundleMalformedError, TypeError, ValueError):
            bundle_response = None
            bundle_meta = None
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
            now_timestamp=now_timestamp,
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
            store.add_event(
                "supply_chain_bundle_refresh_requested",
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "reason": "feed_stale",
                },
                now_value,
            )
        return result
    if bundle_evaluation is not None and bundle_evaluation.refresh_required:
        fallback = _finalize_evaluation(
            bundle_evaluation,
            package_intent_hash=package_intent_hash,
            workspace_fingerprint=workspace_fingerprint,
        )
        _persist_evidence(store=store, artifact=artifact, evaluation=fallback, now=now_value)
        store.add_event(
            "supply_chain_bundle_refresh_requested",
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "reason": "feed_stale",
            },
            now_value,
        )
        return fallback
    if not _artifact_has_package_material(artifact, targets):
        no_material_result = _empty_package_material_result(
            artifact=artifact,
            workspace_id=workspace_id,
            bundle_meta=bundle_meta,
            package_intent_hash=package_intent_hash,
            workspace_fingerprint=workspace_fingerprint,
        )
        _persist_evidence(store=store, artifact=artifact, evaluation=no_material_result, now=now_value)
        return no_material_result
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
            heuristic = _heuristic_result(artifact=artifact, targets=targets, workspace_dir=workspace_dir)
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
            store.add_event(
                "supply_chain_bundle_refresh_requested",
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "reason": "feed_stale",
                },
                now_value,
            )
        return fallback
    heuristic = _heuristic_result(artifact=artifact, targets=targets, workspace_dir=workspace_dir)
    if heuristic is None:
        fallback_packages = _fallback_monitor_packages(targets=targets, artifact=artifact, workspace_dir=workspace_dir)
        has_bun_binary_fallback = any(
            reason["code"] == "bun_lockfile_binary_fallback"
            for package in fallback_packages
            for reason in package["reasons"]
        )
        heuristic = _EvaluationDraft(
            decision="monitor",
            enforcement="free_local" if workspace_id is None else "local_fallback",
            entitlement_state="free" if workspace_id is None else "premium",
            cache_status="miss",
            packages=fallback_packages,
            reasons=(
                {
                    "code": "bun_lockfile_binary_fallback" if has_bun_binary_fallback else "no_cached_match",
                    "message": (
                        "Guard could not parse bun.lockb because Bun stores it as a binary "
                        "lockfile, so this request fell back to manifest-only monitoring."
                        if has_bun_binary_fallback
                        else "Guard recorded this package request and will keep watching for new intelligence."
                    ),
                    "severity": "low" if has_bun_binary_fallback else "unknown",
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


def _artifact_has_package_material(artifact: GuardArtifact, targets: tuple[dict[str, object], ...]) -> bool:
    if targets:
        return True
    return _has_non_empty_string_item(artifact.metadata.get("manifest_paths")) or _has_non_empty_string_item(
        artifact.metadata.get("lockfile_paths")
    )


def _has_non_empty_string_item(value: object) -> bool:
    if not isinstance(value, (list, tuple)):
        return False
    return any(isinstance(item, str) and item for item in value)


def _empty_package_material_result(
    *,
    artifact: GuardArtifact,
    workspace_id: str | None,
    bundle_meta: dict[str, str] | None,
    package_intent_hash: str,
    workspace_fingerprint: str | None,
) -> PackageRequestEvaluation:
    draft = _EvaluationDraft(
        decision="monitor",
        enforcement="free_local" if workspace_id is None else "local_fallback",
        entitlement_state="free" if workspace_id is None else "premium",
        cache_status="empty",
        packages=(),
        reasons=(
            {
                "code": "no_package_material",
                "message": "Guard found no package targets, manifests, or lockfiles to evaluate for this request.",
                "severity": "unknown",
                "source": "guard-local",
            },
        ),
        matched_rule_id=None,
        exception_id=None,
        refresh_required=False,
        record_monitor_evidence=False,
        bundle_version=bundle_meta.get("bundle_version") if bundle_meta is not None else None,
        policy_version=bundle_meta.get("policy_hash", "local:none") if bundle_meta is not None else "local:none",
    )
    return _finalize_evaluation(
        draft,
        package_intent_hash=package_intent_hash,
        workspace_fingerprint=workspace_fingerprint,
    )


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
    packages = tuple(_with_support_metadata(item) for item in draft.packages)
    primary_package = packages[0] if packages else {}
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
    reason_code = _optional_string(draft.reasons[0].get("code")) if draft.reasons else None
    source_risk_summaries = {
        "insecure_source_url": "from insecure HTTP source before install.",
        "external_tarball_source": "from external tarball source before install.",
        "git_dependency_source": "from git dependency source before install.",
    }
    if reason_code in source_risk_summaries and reason_message is not None:
        risk_summary = f"{prefix} `{package_ref}` {source_risk_summaries[reason_code]}"
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
    user_copy = _normalize_package_user_copy(
        SupplyChainUserCopy(
            title=title,
            summary=summary,
            next_step=fix_command,
            dashboard_url=None,
            harness_message=" ".join(part.strip() for part in harness_parts if part.strip()),
        ),
        policy_action={
            "allow": "allow",
            "monitor": "allow",
            "warn": "warn",
            "ask": "require-reapproval",
            "block": "block",
        }[draft.decision],
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
        packages=packages,
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
    try:
        auth_context = _resolve_guard_sync_auth_context(store)
    except GuardSyncNotConfiguredError:
        return None, None
    evaluate_url = _normalized_supply_chain_evaluate_url(auth_context["sync_url"], workspace_id)
    request_payload = _build_request_payload(
        artifact=artifact,
        targets=targets,
        workspace_dir=workspace_dir,
        workspace_fingerprint=workspace_fingerprint,
        policy_version=bundle_meta["policy_hash"] if bundle_meta is not None else "local:none",
    )
    request = urllib.request.Request(
        evaluate_url,
        data=json.dumps(request_payload).encode("utf-8"),
        headers=_guard_sync_headers(auth_context, request_url=evaluate_url, method="POST"),
        method="POST",
    )
    fail_closed_decision = _cloud_fail_closed_decision(store=store, workspace_dir=workspace_dir)
    try:
        response_payload = _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_TIMEOUT_SECONDS,
            retry_timeout_seconds=_RETRY_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as error:
        fail_closed = _cloud_http_fail_closed_evaluation(
            status_code=error.code,
            artifact=artifact,
            targets=targets,
            workspace_dir=workspace_dir,
            workspace_fingerprint=workspace_fingerprint,
            bundle_meta=bundle_meta,
            fail_closed_decision=fail_closed_decision,
        )
        if fail_closed is not None:
            return fail_closed, None
        return None, _cloud_fallback_reason(
            code="cloud_http_error",
            message=(f"Guard cloud evaluation returned HTTP {error.code}, so Guard fell back to local intelligence."),
        )
    except OSError:
        if fail_closed_decision == "block":
            return (
                _cloud_fail_closed_evaluation(
                    code="cloud_validation_error",
                    message="Guard cloud evaluation timed out, so strict mode blocked this package request.",
                    artifact=artifact,
                    targets=targets,
                    workspace_dir=workspace_dir,
                    workspace_fingerprint=workspace_fingerprint,
                    bundle_meta=bundle_meta,
                    fail_closed_decision=fail_closed_decision,
                ),
                None,
            )
        return None, _cloud_fallback_reason(
            code="cloud_timeout",
            message="Guard cloud evaluation timed out, so Guard fell back to local intelligence.",
        )
    except (RuntimeError, ValueError):
        return (
            _cloud_fail_closed_evaluation(
                code="cloud_validation_error",
                message="Guard cloud evaluation returned an invalid response, so this package request needs review.",
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=fail_closed_decision,
            ),
            None,
        )
    if not isinstance(response_payload, dict):
        return (
            _cloud_fail_closed_evaluation(
                code="cloud_validation_error",
                message="Guard cloud evaluation returned an invalid response, so this package request needs review.",
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=fail_closed_decision,
            ),
            None,
        )
    if not isinstance(response_payload.get("packages"), list):
        return (
            _cloud_fail_closed_evaluation(
                code="cloud_validation_error",
                message=(
                    "Guard cloud evaluation returned an invalid package payload, so this package request needs review."
                ),
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=fail_closed_decision,
            ),
            None,
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
            evaluation = replace(
                evaluation,
                user_copy=_normalize_package_user_copy(
                    SupplyChainUserCopy(
                        title=title or evaluation.user_copy.title,
                        summary=updated_summary,
                        next_step=evaluation.user_copy.next_step,
                        dashboard_url=evaluation.user_copy.dashboard_url,
                        harness_message=" ".join(harness_parts),
                    ),
                    policy_action=evaluation.policy_action,
                ),
            )
    return evaluation, None


def _normalize_package_user_copy(user_copy: SupplyChainUserCopy, *, policy_action: str) -> SupplyChainUserCopy:
    dashboard_url = user_copy.dashboard_url
    if _looks_like_cloud_inbox_url(dashboard_url):
        dashboard_url = None
    harness_message = _CLOUD_INBOX_URL_RE.sub("", user_copy.harness_message or "").strip()
    harness_message = " ".join(harness_message.split())
    harness_message = _strip_review_evidence_tail(harness_message)
    needs_local_review = policy_action in {"require-reapproval", "block"}
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


def _cloud_http_fail_closed_evaluation(
    *,
    status_code: int,
    artifact: GuardArtifact,
    targets: tuple[dict[str, object], ...],
    workspace_dir: Path | None,
    workspace_fingerprint: str | None,
    bundle_meta: dict[str, str] | None,
    fail_closed_decision: str,
) -> PackageRequestEvaluation | None:
    if status_code in {401, 403}:
        return _cloud_fail_closed_evaluation(
            code="cloud_auth_error",
            message="Guard cloud evaluation was not authorized, so this package request needs review.",
            artifact=artifact,
            targets=targets,
            workspace_dir=workspace_dir,
            workspace_fingerprint=workspace_fingerprint,
            bundle_meta=bundle_meta,
            fail_closed_decision=fail_closed_decision,
        )
    if status_code in {400, 404}:
        return _cloud_fail_closed_evaluation(
            code="cloud_validation_error",
            message="Guard cloud evaluation could not validate this request, so it needs review.",
            artifact=artifact,
            targets=targets,
            workspace_dir=workspace_dir,
            workspace_fingerprint=workspace_fingerprint,
            bundle_meta=bundle_meta,
            fail_closed_decision=fail_closed_decision,
        )
    return None


def _cloud_fail_closed_evaluation(
    *,
    code: str,
    message: str,
    artifact: GuardArtifact,
    targets: tuple[dict[str, object], ...],
    workspace_dir: Path | None,
    workspace_fingerprint: str | None,
    bundle_meta: dict[str, str] | None,
    fail_closed_decision: str,
) -> PackageRequestEvaluation:
    reason = _cloud_fallback_reason(code=code, message=message)
    decision = "block" if fail_closed_decision == "block" else "ask"
    severity = "critical" if decision == "block" else "high"
    packages = tuple(
        _heuristic_package_result(
            target=target,
            decision=decision,
            code=code,
            message=message,
            severity=severity,
        )
        for target in targets
    )
    if not packages:
        packages = tuple(
            {
                **package,
                "decision": decision,
                "reasons": (reason,),
            }
            for package in _fallback_monitor_packages(targets=targets, artifact=artifact, workspace_dir=workspace_dir)
        )
    draft = _EvaluationDraft(
        decision=decision,
        enforcement="premium_cloud",
        entitlement_state="premium",
        cache_status="cloud-error",
        packages=packages,
        reasons=(reason,),
        matched_rule_id=None,
        exception_id=None,
        refresh_required=False,
        record_monitor_evidence=False,
        bundle_version=bundle_meta.get("bundle_version") if bundle_meta is not None else None,
        policy_version=bundle_meta.get("policy_hash", "local:none") if bundle_meta is not None else "local:none",
    )
    return _finalize_evaluation(
        draft,
        package_intent_hash=artifact.artifact_id.rsplit(":", 1)[-1],
        workspace_fingerprint=workspace_fingerprint,
    )


def _cloud_fail_closed_decision(*, store: GuardStore, workspace_dir: Path | None) -> str:
    config = load_guard_config(store.guard_home, workspace=workspace_dir)
    cloud_action = resolve_risk_action(config, "cloud_advisory", harness=None)
    if config.security_level in {"strict", "paranoid"}:
        return "block"
    if cloud_action == "block":
        return "block"
    return "ask"


def _evaluate_with_bundle(
    *,
    artifact: GuardArtifact,
    targets: tuple[dict[str, object], ...],
    bundle_response,
    workspace_dir: Path | None,
    workspace_id: str | None,
    now_timestamp: float | None,
) -> _EvaluationDraft | None:
    bundle_meta = _bundle_meta(bundle_response.to_dict())
    refresh_required = False
    packages: list[dict[str, object]] = []
    lockfile_versions = _lockfile_dependency_versions(workspace_dir, artifact, targets)
    for target in targets:
        resolved_version = _resolved_target_version(
            target=target,
            lockfile_versions=lockfile_versions,
        )
        package_match = (
            _bundle_package(
                bundle_response,
                package_name=str(target["normalized_name"]),
                package_version=resolved_version,
                ecosystem=_optional_string(target.get("ecosystem")) or "npm",
            )
            if resolved_version is not None
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
        confusion_result = _dependency_confusion_policy_package_result(
            bundle_response.bundle.policy_rules,
            target=target,
        )
        if confusion_result is not None:
            packages.append(confusion_result)
            continue
        if resolved_version is None:
            continue
        offline = evaluate_cached_supply_chain_bundle(
            bundle_response,
            package_name=str(target["normalized_name"]),
            package_version=resolved_version,
            ecosystem=_optional_string(target.get("ecosystem")) or "npm",
            now=now_timestamp,
        )
        if package_match is None:
            safe_allow = _recommended_fix_allow_package_result(
                target=target,
                resolved_version=resolved_version,
                bundle_response=bundle_response,
            )
            if safe_allow is not None:
                packages.append(safe_allow)
            continue
        refresh_required = refresh_required or offline.stale
        package = _bundle_package_result(
            target=target,
            bundle_response=bundle_response,
            package=package_match,
            decision=_normalize_bundle_action(offline.action),
            reason=offline.reason,
            stale=offline.stale,
            resolved_version=resolved_version,
        )
        packages.append(package)
    direct_identities = {
        (
            _optional_string(package.get("namespace")),
            str(package.get("name") or ""),
            _optional_string(package.get("resolvedVersion")),
        )
        for package in packages
    }
    packages.extend(
        package
        for package in _transitive_lockfile_results(
            bundle_response=bundle_response,
            artifact=artifact,
            workspace_dir=workspace_dir,
            now_timestamp=now_timestamp,
        )
        if (
            _optional_string(package.get("namespace")),
            str(package.get("name") or ""),
            _optional_string(package.get("resolvedVersion")),
        )
        not in direct_identities
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


def _primary_bundle_advisory_id(
    bundle_response: SupplyChainBundleResponse,
    package: SupplyChainBundlePackage,
) -> str | None:
    if not package.related_advisory_ids:
        return None
    advisory_lookup: dict[str, str] = {}
    for advisory in bundle_response.bundle.advisories:
        advisory_lookup[advisory.advisory_id] = advisory.advisory_id
        for alias in advisory.aliases:
            advisory_lookup.setdefault(alias, advisory.advisory_id)
    for advisory_id in package.related_advisory_ids:
        canonical_id = advisory_lookup.get(advisory_id)
        if canonical_id is not None:
            return canonical_id
    return package.related_advisory_ids[0]


def _heuristic_result(
    *,
    artifact: GuardArtifact,
    targets: tuple[dict[str, object], ...],
    workspace_dir: Path | None,
) -> _EvaluationDraft | None:
    packages: list[dict[str, object]] = []
    for target in targets:
        lockfile_parse_warning = _lockfile_parse_warning_result(
            target=target,
            artifact=artifact,
            workspace_dir=workspace_dir,
        )
        package_result: dict[str, object] | None = None
        local_package_result = _local_package_manifest_result(
            target=target,
            artifact=artifact,
            workspace_dir=workspace_dir,
        )
        if local_package_result is not None:
            package_result = local_package_result
        if package_result is None:
            local_python_result = _local_python_build_result(target=target, workspace_dir=workspace_dir)
            if local_python_result is not None:
                package_result = local_python_result
        ecosystem = _optional_string(target.get("ecosystem")) or "npm"
        if package_result is None and ecosystem == "system":
            package_result = _system_package_monitor_result(target)
        if package_result is None and ecosystem == "unsupported":
            package_result = _unsupported_ecosystem_result(target)
        if package_result is None:
            go_replace_result = _go_replace_result(target=target, artifact=artifact, workspace_dir=workspace_dir)
            if go_replace_result is not None:
                package_result = go_replace_result
        if package_result is None:
            local_source_result = _local_source_dependency_result(target)
            if local_source_result is not None:
                package_result = local_source_result
        source_url = _optional_string(target.get("source_url"))
        if package_result is None and source_url is not None and source_url.lower().startswith("http://"):
            package_result = _heuristic_package_result(
                target=target,
                decision="block",
                code="insecure_source_url",
                message="Package source uses insecure HTTP transport.",
                severity="high",
            )
        if package_result is None and source_url is not None and _is_git_source_url(source_url):
            package_result = _heuristic_package_result(
                target=target,
                decision="ask",
                code="git_dependency_source",
                message="Git package source requires review before install.",
                severity="high",
            )
        if package_result is None and source_url is not None and _is_external_https_tarball_source(source_url):
            package_result = _external_tarball_dependency_result(target)
        if package_result is None:
            if lockfile_parse_warning is not None:
                packages.append(lockfile_parse_warning)
            continue
        if lockfile_parse_warning is not None:
            package_result = _with_package_reason(package_result, lockfile_parse_warning["reasons"][0])
        packages.append(package_result)
    if not packages:
        return None
    packages.sort(key=lambda item: _decision_rank(str(item.get("decision") or "monitor")), reverse=True)
    decision = str(packages[0].get("decision") or "monitor")
    return _EvaluationDraft(
        decision=decision,
        enforcement="free_local",
        entitlement_state="free",
        cache_status="miss",
        packages=tuple(packages),
        reasons=tuple(reason for package in packages for reason in package["reasons"]),
        matched_rule_id=None,
        exception_id=None,
        refresh_required=False,
        record_monitor_evidence=decision == "monitor",
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


def _targets_from_artifact(artifact: GuardArtifact) -> tuple[dict[str, object], ...]:
    raw_targets = artifact.metadata.get("targets")
    if not isinstance(raw_targets, list):
        return ()
    parsed: list[dict[str, object]] = []
    package_manager = str(artifact.metadata.get("package_manager") or "npm")
    redacted_command = _optional_string(artifact.metadata.get("redacted_command"))
    for item in raw_targets:
        if not isinstance(item, dict):
            continue
        ecosystem = str(item.get("ecosystem") or "npm")
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
                "ecosystem": ecosystem,
                "package_name": package_name,
                "normalized_name": _normalize_package_name(ecosystem, package_name),
                "namespace": namespace,
                "name": name,
                "raw_spec": raw_spec,
                "version": exact_version,
                "range": requested if exact_version is None else None,
                "source_url": source_url,
                "alias": _optional_string(item.get("alias")),
                "dependency_group": _optional_string(item.get("dependency_group")),
                "extras": tuple(item.get("extras")) if isinstance(item.get("extras"), list) else (),
                "editable": bool(item.get("editable")),
                "package_manager": package_manager,
                "redacted_command": redacted_command,
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
                "dependencyPath": None,
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
    except (OSError, UnicodeDecodeError):
        return None
    dependencies = _safe_dependency_map_for_path(
        str(lockfile_path.name), lockfile_text, deadline=time.monotonic() + _LOCKFILE_PARSE_BUDGET_SECONDS
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
    *,
    bundle_response: SupplyChainBundleResponse,
    artifact: GuardArtifact,
    workspace_dir: Path | None,
    now_timestamp: float | None = None,
) -> list[dict[str, object]]:
    if workspace_dir is None:
        return []
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list):
        return []
    results: list[dict[str, object]] = []
    bundle_stale = _is_bundle_stale(bundle_response, now_timestamp=now_timestamp)
    bundle_index = _bundle_package_index(bundle_response)
    direct_target_names_by_ecosystem: dict[str, set[str]] = {}
    all_direct_target_names: set[str] = set()
    direct_targets = _targets_from_artifact(artifact)
    for target in direct_targets:
        ecosystem = _optional_string(target.get("ecosystem")) or "npm"
        candidate_names = {str(target["normalized_name"]), *_target_candidate_names(target)}
        direct_target_names_by_ecosystem.setdefault(ecosystem, set()).update(candidate_names)
        all_direct_target_names.update(candidate_names)
    for relative_path in lockfile_paths:
        lockfile_path = workspace_dir / str(relative_path)
        if not lockfile_path.exists():
            continue
        lockfile_ecosystem = _lockfile_ecosystem(lockfile_path.name)
        direct_target_names = (
            direct_target_names_by_ecosystem.get(lockfile_ecosystem, all_direct_target_names)
            if lockfile_ecosystem is not None
            else all_direct_target_names
        )
        try:
            lockfile_text = lockfile_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        dependency_entries: list[tuple[str, str, str, bool]] = []
        parse_deadline = time.monotonic() + _LOCKFILE_PARSE_BUDGET_SECONDS
        try:
            if lockfile_path.name == "package-lock.json":
                dependency_entries = [
                    (
                        dependency_path,
                        package_name,
                        version,
                        dependency_path in direct_target_names,
                    )
                    for dependency_path, package_name, version, _direct in _package_lock_entries(
                        lockfile_text, deadline=parse_deadline
                    )
                ]
            else:
                dependency_map = _safe_dependency_map_for_path(
                    str(lockfile_path.name),
                    lockfile_text,
                    deadline=parse_deadline,
                )
                for dependency_path, version in dependency_map.items():
                    normalized_dependency_path = dependency_path.strip("/")
                    if not normalized_dependency_path:
                        continue
                    package_name = _dependency_package_name(normalized_dependency_path)
                    if package_name is None:
                        continue
                    dependency_entries.append(
                        (
                            dependency_path,
                            package_name,
                            version,
                            normalized_dependency_path in direct_target_names,
                        )
                    )
        except _DeadlineExceededError:
            timeout_warning = _transitive_lockfile_timeout_warning(
                targets=direct_targets,
                lockfile_name=lockfile_path.name,
            )
            if timeout_warning is not None:
                results.append(timeout_warning)
            continue
        for dependency_path, package_name, version, direct in dependency_entries:
            if direct:
                continue
            package_match = _bundle_package_from_index(
                bundle_index,
                package_name=package_name,
                package_version=version,
                ecosystem=lockfile_ecosystem,
            )
            if package_match is None:
                continue
            decision = _transitive_lockfile_decision(package=package_match, stale=bundle_stale)
            if decision not in {"ask", "block", "warn"}:
                continue
            downgraded_low_confidence = (
                decision == "warn" and _normalize_bundle_action(package_match.default_action) == "block"
            )
            results.append(
                {
                    "decision": decision,
                    "ecosystem": package_match.ecosystem,
                    "name": package_match.name,
                    "namespace": package_match.namespace,
                    "requestedVersion": version,
                    "resolvedVersion": version,
                    "recommendedFixVersion": package_match.recommended_fix_version,
                    "riskScore": package_match.risk_score,
                    "direct": False,
                    "dependencyPath": dependency_path,
                    "packageManager": str(artifact.metadata.get("package_manager") or "npm"),
                    "redactedCommand": _optional_string(artifact.metadata.get("redacted_command")),
                    "reasons": (
                        {
                            "code": "transitive_low_confidence_match"
                            if downgraded_low_confidence
                            else "transitive_lockfile_match",
                            "message": (
                                (
                                    "Existing lockfile includes transitive dependency path "
                                    f"{dependency_path} with lower-confidence risk signals."
                                )
                                if downgraded_low_confidence
                                else f"Existing lockfile already includes vulnerable dependency path {dependency_path}."
                            ),
                            "severity": package_match.normalized_severity,
                            "source": "lockfile",
                        },
                    ),
                }
            )
    return results


def _transitive_lockfile_decision(*, package: SupplyChainBundlePackage, stale: bool) -> str:
    decision = _normalize_bundle_action(package.default_action if package.default_action != "allow" else "monitor")
    if stale and not _is_high_confidence_block(package):
        return "warn" if decision in {"block", "ask", "warn"} else "monitor"
    if decision != "block":
        return decision
    if _is_high_confidence_block(package):
        return "block"
    if package.confidence >= _TRANSITIVE_BLOCK_CONFIDENCE_THRESHOLD:
        return "block"
    return "warn"


def _is_bundle_stale(bundle_response: SupplyChainBundleResponse, *, now_timestamp: float | None) -> bool:
    try:
        check_supply_chain_bundle_freshness(bundle_response.bundle, now=now_timestamp)
    except SupplyChainBundleExpiredError:
        return True
    return False


def _bundle_package_index(
    bundle_response: SupplyChainBundleResponse,
) -> dict[tuple[str, str, str], SupplyChainBundlePackage]:
    index: dict[tuple[str, str, str], SupplyChainBundlePackage] = {}
    for package in bundle_response.bundle.packages:
        normalized_name = _normalize_package_name(package.ecosystem, package.name)
        index[(package.ecosystem, normalized_name, package.version)] = package
        if package.namespace is not None:
            qualified_name = _normalize_package_name(package.ecosystem, f"{package.namespace}/{package.name}")
            index[(package.ecosystem, qualified_name, package.version)] = package
    return index


def _bundle_package_from_index(
    index: dict[tuple[str, str, str], SupplyChainBundlePackage],
    *,
    package_name: str,
    package_version: str,
    ecosystem: str | None = None,
) -> SupplyChainBundlePackage | None:
    if ecosystem is None:
        return None
    normalized_name = _normalize_package_name(ecosystem, package_name)
    return index.get((ecosystem, normalized_name, package_version))


def _transitive_lockfile_timeout_warning(
    *,
    targets: tuple[dict[str, object], ...],
    lockfile_name: str,
) -> dict[str, object] | None:
    if not targets:
        return None
    return _heuristic_package_result(
        target=targets[0],
        decision="warn",
        code="transitive_lockfile_timeout",
        message=(
            f"Guard only partially scanned {lockfile_name} before the resolver deadline; "
            "transitive dependency results may be incomplete."
        ),
        severity="unknown",
    )


def _parse_evaluation_timestamp(now_value: str) -> float | None:
    try:
        return datetime.fromisoformat(now_value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _lockfile_ecosystem(lockfile_name: str) -> str | None:
    lower_name = lockfile_name.lower()
    if lower_name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"}:
        return "npm"
    if lower_name in {"poetry.lock", "uv.lock", "pipfile.lock"}:
        return "pypi"
    if lower_name == "cargo.lock":
        return "cargo"
    if lower_name == "composer.lock":
        return "packagist"
    if lower_name == "gemfile.lock":
        return "rubygems"
    if lower_name == "go.sum":
        return "go"
    if lower_name == "gradle.lockfile":
        return "maven"
    return None


def _bundle_package_result(
    *,
    target: dict[str, object],
    bundle_response: SupplyChainBundleResponse,
    package: SupplyChainBundlePackage,
    decision: str,
    reason: str,
    stale: bool,
    resolved_version: str,
) -> dict[str, object]:
    severity = package.normalized_severity if stale is False else "unknown"
    return {
        "decision": decision,
        "ecosystem": package.ecosystem,
        "name": package.name,
        "namespace": package.namespace,
        "requestedVersion": _optional_string(target.get("range")) or _optional_string(target.get("version")),
        "resolvedVersion": resolved_version,
        "recommendedFixVersion": package.recommended_fix_version,
        "riskScore": package.risk_score,
        "direct": True,
        "dependencyPath": None,
        "packageManager": _optional_string(target.get("package_manager")) or "npm",
        "redactedCommand": _optional_string(target.get("redacted_command")),
        "alias": _optional_string(target.get("alias")),
        "reasons": (
            {
                "advisoryId": _primary_bundle_advisory_id(bundle_response, package),
                "code": reason,
                "message": _bundle_reason_message(package, decision=decision, reason=reason, stale=stale),
                "severity": severity,
                "source": "bundle",
            },
        ),
    }


def _system_package_monitor_result(target: dict[str, object]) -> dict[str, object]:
    command = _optional_string(target.get("redacted_command")) or ""
    signals = detect_supply_chain_risk(command)
    if signals:
        strongest = sorted(signals, key=lambda item: _severity_rank_value(item.severity), reverse=True)[0]
        return _heuristic_package_result(
            target=target,
            decision="warn",
            code="system_package_manager_generic_risk",
            message=strongest.plain_reason,
            severity=strongest.severity,
        )
    return _heuristic_package_result(
        target=target,
        decision="warn",
        code="system_package_manager_monitor_only",
        message=(
            "Guard treats system package managers as monitor-only coverage today and will not "
            "pretend advisory blocking."
        ),
        severity="low",
    )


def _unsupported_ecosystem_result(target: dict[str, object]) -> dict[str, object]:
    command = _optional_string(target.get("redacted_command")) or ""
    signals = detect_supply_chain_risk(command)
    if signals:
        strongest = sorted(signals, key=lambda item: _severity_rank_value(item.severity), reverse=True)[0]
        decision = "block" if strongest.severity in {"critical", "high"} else "warn"
        return _heuristic_package_result(
            target=target,
            decision=decision,
            code="unsupported_ecosystem_generic_risk",
            message=strongest.plain_reason,
            severity=strongest.severity,
        )
    return _heuristic_package_result(
        target=target,
        decision="monitor",
        code="unsupported_ecosystem_monitor_only",
        message="Guard recorded this unsupported package-manager request and applied generic risk detection only.",
        severity="low",
    )


def _local_source_dependency_result(target: dict[str, object]) -> dict[str, object] | None:
    source_url = _optional_string(target.get("source_url"))
    if source_url is None or not source_url.startswith("file:"):
        return None
    return _heuristic_package_result(
        target=target,
        decision="ask",
        code="local_path_dependency_source",
        message="Local path dependency requires review before install.",
        severity="medium",
    )


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
        "direct": True,
        "dependencyPath": None,
        "packageManager": _optional_string(target.get("package_manager")) or "npm",
        "redactedCommand": _optional_string(target.get("redacted_command")),
        "alias": _optional_string(target.get("alias")),
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
    dependency_path = _optional_string(item.get("dependencyPath"))
    direct_value = item.get("direct")
    direct = direct_value if isinstance(direct_value, bool) else dependency_path is None
    return {
        "decision": _normalize_bundle_action(str(item.get("decision") or "monitor")),
        "ecosystem": str(item.get("ecosystem") or "npm"),
        "name": str(item.get("name") or "unknown"),
        "namespace": _optional_string(item.get("namespace")),
        "requestedVersion": _optional_string(item.get("requestedVersion")),
        "resolvedVersion": _optional_string(item.get("resolvedVersion")),
        "recommendedFixVersion": _optional_string(item.get("recommendedFixVersion")),
        "riskScore": item.get("riskScore"),
        "direct": direct,
        "dependencyPath": dependency_path,
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
        "direct": True,
        "dependencyPath": None,
        "packageManager": _optional_string(target.get("package_manager")) or "npm",
        "redactedCommand": _optional_string(target.get("redacted_command")),
        "alias": _optional_string(target.get("alias")),
        "reasons": (
            {
                "code": "no_cached_match",
                "message": "Guard recorded this package request and will keep watching for new intelligence.",
                "severity": "unknown",
                "source": "guard-local",
            },
        ),
    }


def _fallback_monitor_packages(
    *,
    targets: tuple[dict[str, object], ...],
    artifact: GuardArtifact,
    workspace_dir: Path | None,
) -> tuple[dict[str, object], ...]:
    bun_fallback_packages = _bun_lockfile_binary_fallback_packages(
        targets=targets,
        artifact=artifact,
        workspace_dir=workspace_dir,
    )
    if bun_fallback_packages:
        return tuple(bun_fallback_packages)
    return tuple(_unknown_package_result(target) for target in targets)


def _bun_lockfile_binary_fallback_packages(
    *,
    targets: tuple[dict[str, object], ...],
    artifact: GuardArtifact,
    workspace_dir: Path | None,
) -> list[dict[str, object]]:
    if workspace_dir is None:
        return []
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list):
        return []
    bun_lock_path = next(
        (
            workspace_dir / str(relative_path)
            for relative_path in lockfile_paths
            if Path(str(relative_path)).name == "bun.lockb" and (workspace_dir / str(relative_path)).exists()
        ),
        None,
    )
    if bun_lock_path is None:
        return []
    message = (
        "Guard detected bun.lockb but Bun stores it as a binary lockfile, so this request fell back to "
        "manifest-only monitoring."
    )
    if targets:
        return [
            _heuristic_package_result(
                target=target,
                decision="monitor",
                code="bun_lockfile_binary_fallback",
                message=message,
                severity="low",
            )
            for target in targets
        ]
    return [
        _heuristic_package_result(
            target={"ecosystem": "npm", "name": "workspace", "namespace": None, "package_manager": "bun"},
            decision="monitor",
            code="bun_lockfile_binary_fallback",
            message=message,
            severity="low",
        )
    ]


def _local_package_manifest_result(
    *,
    target: dict[str, object],
    artifact: GuardArtifact,
    workspace_dir: Path | None,
) -> dict[str, object] | None:
    manifest_path = _local_package_manifest_path(target, workspace_dir)
    if manifest_path is None:
        return None
    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    signals = tuple(
        signal
        for signal in detect_supply_chain_risk(manifest_text)
        if signal.signal_id.startswith("supply-chain.postinstall")
        or signal.signal_id.endswith("install-lifecycle-exec")
    )
    if not signals:
        return None
    manifest_target = dict(target)
    manifest_package_name = _manifest_package_name(manifest_text)
    if manifest_package_name is not None:
        namespace, name = _split_namespace_name(manifest_package_name)
        manifest_target["namespace"] = namespace
        manifest_target["name"] = name
    if _artifact_has_flag(artifact, "--ignore-scripts"):
        return _heuristic_package_result(
            target=manifest_target,
            decision="allow",
            code="ignore_scripts_applied",
            message="`--ignore-scripts` disables lifecycle hooks for this local package install.",
            severity="low",
        )
    strongest_signal = sorted(signals, key=lambda item: _severity_rank_value(item.severity), reverse=True)[0]
    return _heuristic_package_result(
        target=manifest_target,
        decision="block",
        code="install_script_risk",
        message=strongest_signal.plain_reason,
        severity=strongest_signal.severity,
    )


def _local_package_manifest_path(target: dict[str, object], workspace_dir: Path | None) -> Path | None:
    if workspace_dir is None:
        return None
    raw_spec = _optional_string(target.get("raw_spec"))
    source_url = _optional_string(target.get("source_url"))
    if source_url is not None and source_url.startswith("file:"):
        raw_spec = source_url.partition("file:")[2]
    if raw_spec is None or raw_spec.startswith(("http://", "https://", "git+", "github:", "gitlab:", "bitbucket:")):
        return None
    if raw_spec.startswith("file:"):
        raw_spec = raw_spec.partition("file:")[2]
    candidate_path = Path(raw_spec)
    disk_path = candidate_path if candidate_path.is_absolute() else workspace_dir / candidate_path
    if disk_path.is_dir():
        manifest_path = disk_path / "package.json"
        return manifest_path if manifest_path.exists() else None
    if disk_path.name == "package.json" and disk_path.exists():
        return disk_path
    return None


def _local_python_build_result(target: dict[str, object], workspace_dir: Path | None) -> dict[str, object] | None:
    if workspace_dir is None or (_optional_string(target.get("ecosystem")) or "npm") != "pypi":
        return None
    project_path = _local_python_project_path(target, workspace_dir)
    if project_path is None:
        return None
    setup_py_path = project_path / "setup.py"
    if setup_py_path.exists():
        try:
            setup_py_text = setup_py_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            setup_py_text = ""
        if _python_setup_script_looks_suspicious(setup_py_text):
            return _heuristic_package_result(
                target=target,
                decision="block",
                code="setup_py_exec_risk",
                message="Local setup.py executes commands or network behavior during packaging.",
                severity="high",
            )
    pyproject_path = project_path / "pyproject.toml"
    if pyproject_path.exists():
        try:
            pyproject_text = pyproject_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            pyproject_text = ""
        if "[build-system]" in pyproject_text and "build-backend" in pyproject_text:
            if _python_setup_script_looks_suspicious(pyproject_text):
                return _heuristic_package_result(
                    target=target,
                    decision="block",
                    code="build_backend_exec_risk",
                    message="Local pyproject build backend references execution or network bootstrap behavior.",
                    severity="high",
                )
            return _heuristic_package_result(
                target=target,
                decision="ask",
                code="local_build_backend_risk",
                message="Editable local Python installs can invoke pyproject build backend hooks from this workspace.",
                severity="medium",
            )
    return None


def _looks_like_explicit_local_python_path(raw_spec: str) -> bool:
    normalized, _extras = split_python_extras(_local_python_path_text(raw_spec))
    return (
        normalized == "."
        or normalized == "~"
        or normalized.startswith(("./", "../", "/", "~/", ".\\", "..\\", "~\\", "\\\\", "//"))
        or "/" in normalized
        or "\\" in normalized
        or bool(re.match(r"^[A-Za-z]:[\\\\/]", normalized))
    )


def _local_python_path_text(raw_spec: str) -> str:
    path_text = raw_spec.partition("file:")[2] if raw_spec.startswith("file:") else raw_spec
    normalized_path, _extras = split_python_extras(path_text)
    return normalized_path or path_text


def _local_python_project_path(target: dict[str, object], workspace_dir: Path) -> Path | None:
    raw_spec = _optional_string(target.get("raw_spec"))
    source_url = _optional_string(target.get("source_url"))
    editable = bool(target.get("editable"))
    if source_url is not None and source_url.startswith("file:"):
        raw_spec = source_url.partition("file:")[2]
    if raw_spec is None:
        return workspace_dir if editable else None
    if raw_spec.startswith(("http://", "https://", "git+", "github:", "gitlab:", "bitbucket:")):
        return None
    if not _looks_like_explicit_local_python_path(raw_spec):
        workspace_has_python_project = (workspace_dir / "pyproject.toml").exists() or (
            workspace_dir / "setup.py"
        ).exists()
        return workspace_dir if editable and workspace_has_python_project else None
    path_text = _local_python_path_text(raw_spec)
    try:
        candidate_path = Path(path_text).expanduser()
    except RuntimeError:
        candidate_path = Path(path_text)
    disk_path = candidate_path if candidate_path.is_absolute() else workspace_dir / candidate_path
    if disk_path.is_dir():
        if (disk_path / "pyproject.toml").exists() or (disk_path / "setup.py").exists():
            return disk_path
        return None
    parent = disk_path.parent
    if disk_path.name in {"pyproject.toml", "setup.py"} and disk_path.exists():
        return parent
    workspace_has_python_project = (workspace_dir / "pyproject.toml").exists() or (workspace_dir / "setup.py").exists()
    return workspace_dir if editable and workspace_has_python_project else None


def _python_setup_script_looks_suspicious(content: str) -> bool:
    return bool(
        re.search(
            r"\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output)|requests\.(?:get|post)|urllib\.request\.)",
            content,
        )
        or re.search(r"\b(?:curl|wget)\b", content)
    )


def _manifest_package_name(manifest_text: str) -> str | None:
    try:
        payload = json.loads(manifest_text or "{}")
    except json.JSONDecodeError:
        return None
    package_name = payload.get("name")
    return package_name.strip() if isinstance(package_name, str) and package_name.strip() else None


def _artifact_has_flag(artifact: GuardArtifact, flag: str) -> bool:
    raw_flags = artifact.metadata.get("flags")
    return isinstance(raw_flags, list) and flag in raw_flags


def _dependency_confusion_policy_package_result(
    rules: tuple[SupplyChainBundlePolicyRule, ...],
    *,
    target: dict[str, object],
) -> dict[str, object] | None:
    if (_optional_string(target.get("ecosystem")) or "npm") != "npm" or _optional_string(
        target.get("namespace")
    ) is not None:
        return None
    current_time = datetime.now(timezone.utc).timestamp()
    target_name = str(target["name"]).lower()
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
        if rule.ecosystem_selector is not None and rule.ecosystem_selector != "npm":
            continue
        selector = (rule.package_selector or "").strip().lower()
        if not selector or not _dependency_confusion_selector_matches(selector, target_name):
            continue
        decision = _normalize_bundle_action(rule.action)
        if decision not in {"block", "ask", "warn"}:
            decision = "warn"
        return {
            "decision": decision,
            "ecosystem": target["ecosystem"],
            "name": target["name"],
            "namespace": target["namespace"],
            "requestedVersion": _optional_string(target.get("range")) or _optional_string(target.get("version")),
            "resolvedVersion": _optional_string(target.get("version")),
            "recommendedFixVersion": None,
            "riskScore": None,
            "direct": True,
            "dependencyPath": None,
            "packageManager": _optional_string(target.get("package_manager")) or "npm",
            "redactedCommand": _optional_string(target.get("redacted_command")),
            "alias": _optional_string(target.get("alias")),
            "ruleId": rule.rule_id,
            "reasons": (
                {
                    "code": "dependency_confusion_risk",
                    "message": (
                        f"Policy reserves internal package selector {rule.package_selector}; "
                        f"installing public package {target_name} may cause dependency confusion."
                    ),
                    "severity": "high",
                    "source": "policy",
                },
            ),
        }
    return None


def _dependency_confusion_selector_matches(selector: str, target_name: str) -> bool:
    if not selector.startswith("@") or "/" not in selector:
        return False
    selector = selector.split("/", 1)[1]
    if selector in {"", "*"}:
        return False
    if selector.endswith("*"):
        return target_name.startswith(selector[:-1])
    return target_name == selector


def _heuristic_package_result(
    *,
    target: dict[str, object],
    decision: str,
    code: str,
    message: str,
    severity: str,
) -> dict[str, object]:
    return {
        "decision": decision,
        "ecosystem": target["ecosystem"],
        "name": target["name"],
        "namespace": target["namespace"],
        "requestedVersion": _optional_string(target.get("range")) or _optional_string(target.get("version")),
        "resolvedVersion": _optional_string(target.get("version")),
        "recommendedFixVersion": None,
        "riskScore": None,
        "direct": True,
        "dependencyPath": None,
        "packageManager": _optional_string(target.get("package_manager")) or "npm",
        "redactedCommand": _optional_string(target.get("redacted_command")),
        "alias": _optional_string(target.get("alias")),
        "reasons": (
            {
                "code": code,
                "message": message,
                "severity": severity,
                "source": "guard-local",
            },
        ),
    }


def _go_replace_result(
    *,
    target: dict[str, object],
    artifact: GuardArtifact,
    workspace_dir: Path | None,
) -> dict[str, object] | None:
    if workspace_dir is None or (_optional_string(target.get("ecosystem")) or "npm") != "go":
        return None
    manifest_paths = artifact.metadata.get("manifest_paths")
    if not isinstance(manifest_paths, list):
        return None
    go_mod_path = next((workspace_dir / str(path) for path in manifest_paths if Path(str(path)).name == "go.mod"), None)
    if go_mod_path is None or not go_mod_path.exists():
        return None
    try:
        go_mod_text = go_mod_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    replacements = _go_mod_replace_map(go_mod_text)
    for candidate in _target_candidate_names(target):
        replacement = replacements.get(candidate)
        if replacement is None:
            continue
        if replacement.startswith(("file:", "./", "../", "/", "~", ".\\", "..\\")):
            return _heuristic_package_result(
                target=target,
                decision="ask",
                code="go_replace_local_source",
                message="Go replace directive reroutes this module to a local path.",
                severity="medium",
            )
        if _exact_version(replacement) is None:
            return _heuristic_package_result(
                target=target,
                decision="ask",
                code="go_replace_mutable_source",
                message="Go replace directive reroutes this module away from proxy-pinned version resolution.",
                severity="medium",
            )
    return None


def _go_mod_replace_map(text: str) -> dict[str, str]:
    replacements: dict[str, str] = {}
    in_replace_block = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("replace ("):
            in_replace_block = True
            continue
        if in_replace_block and line == ")":
            in_replace_block = False
            continue
        if line.startswith("replace "):
            line = line.removeprefix("replace ").strip()
        elif not in_replace_block:
            continue
        if "=>" not in line:
            continue
        original, _, replacement = line.partition("=>")
        normalized_original = original.strip().split()[0]
        normalized_replacement = replacement.strip().split()[0]
        if normalized_original and normalized_replacement:
            replacements[_normalize_package_name("go", normalized_original)] = normalized_replacement
    return replacements


def _is_git_source_url(source_url: str) -> bool:
    normalized = source_url.lower()
    if normalized.startswith(("git+", "github:", "gitlab:", "bitbucket:")):
        return True
    parsed = urllib.parse.urlsplit(source_url)
    if (
        parsed.scheme.lower() in {"http", "https"}
        and parsed.hostname is not None
        and parsed.hostname.lower() in {"github.com", "gitlab.com", "bitbucket.org"}
    ):
        path_parts = [part for part in parsed.path.split("/") if part]
        return len(path_parts) >= 2
    return (
        "/" in source_url
        and not normalized.startswith(("http://", "https://"))
        and ":" not in source_url
        and not source_url.startswith(("@", "./", "../", "/"))
    )


def _is_external_https_tarball_source(source_url: str) -> bool:
    parsed = urllib.parse.urlsplit(source_url)
    normalized_path = parsed.path.lower()
    hostname = parsed.hostname.lower() if parsed.hostname is not None else ""
    return (
        parsed.scheme.lower() == "https"
        and normalized_path.endswith((".tgz", ".tar.gz", ".tar"))
        and hostname != "registry.npmjs.org"
    )


def _external_tarball_dependency_result(target: dict[str, object]) -> dict[str, object]:
    source_url = _optional_string(target.get("source_url"))
    if source_url is None:
        return _heuristic_package_result(
            target=target,
            decision="ask",
            code="external_tarball_source",
            message="External tarball source requires review before install.",
            severity="medium",
        )
    scan = _scan_external_tarball(source_url)
    if scan is None:
        return _heuristic_package_result(
            target=target,
            decision="ask",
            code="external_tarball_source",
            message="External tarball source requires review before install.",
            severity="medium",
        )
    return _heuristic_package_result(
        target=target,
        decision=scan["decision"],
        code=scan["code"],
        message=scan["message"],
        severity=scan["severity"],
    )


def _scan_external_tarball(source_url: str) -> dict[str, str] | None:
    archive_bytes = _download_external_tarball(source_url)
    if archive_bytes is None:
        return None
    if len(archive_bytes) > _TARBALL_SCAN_MAX_BYTES:
        return {
            "decision": "block",
            "code": "tarball_size_limit",
            "message": "External tarball exceeded Guard scan size limits.",
            "severity": "high",
        }
    return _scan_tarball_archive_bytes(archive_bytes)


def _download_external_tarball(source_url: str) -> bytes | None:
    request = urllib.request.Request(source_url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=_TARBALL_SCAN_TIMEOUT_SECONDS) as response:
            payload = response.read(_TARBALL_SCAN_MAX_BYTES + 1)
    except OSError:
        return None
    return payload


def _scan_tarball_archive_bytes(archive_bytes: bytes) -> dict[str, str] | None:
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
            member_count = 0
            for member in archive:
                if member_count >= _TARBALL_SCAN_MAX_FILES:
                    return {
                        "decision": "block",
                        "code": "tarball_file_count_limit",
                        "message": "External tarball exceeded Guard file-count limits.",
                        "severity": "high",
                    }
                member_count += 1
                if _tarball_member_is_unsafe(member):
                    return {
                        "decision": "block",
                        "code": "tarball_zip_slip",
                        "message": "External tarball contains unsafe archive paths.",
                        "severity": "high",
                    }
                if not member.isfile():
                    continue
                if not member.name.endswith("package.json"):
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                package_json = extracted.read(_TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES + 1)
                if len(package_json) > _TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES:
                    return {
                        "decision": "block",
                        "code": "tarball_package_json_limit",
                        "message": "External tarball package manifest exceeded Guard scan limits.",
                        "severity": "high",
                    }
                install_script_risk = _package_json_install_script_risk(package_json)
                if install_script_risk is not None:
                    return {
                        "decision": "block",
                        "code": install_script_risk["code"],
                        "message": install_script_risk["message"],
                        "severity": "high",
                    }
    except (tarfile.TarError, OSError, UnicodeDecodeError, ValueError):
        return None
    return None


def _tarball_member_is_unsafe(member: tarfile.TarInfo) -> bool:
    normalized_name = posixpath.normpath(member.name)
    if member.name.startswith(("/", "\\")):
        return True
    if normalized_name in {"..", "."} or normalized_name.startswith("../"):
        return True
    if ":" in normalized_name.split("/", 1)[0]:
        return True
    if member.issym() or member.islnk():
        link_target = posixpath.normpath(member.linkname or "")
        if link_target.startswith("/") or link_target.startswith("../") or link_target == "..":
            return True
    return False


def _package_json_install_script_risk(payload: bytes) -> dict[str, str] | None:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    scripts = parsed.get("scripts")
    if not isinstance(scripts, dict):
        return None
    for key in ("preinstall", "install", "postinstall", "prepare"):
        value = scripts.get(key)
        if isinstance(value, str) and value.strip():
            normalized = value.lower()
            touches_credentials = bool(
                re.search(
                    r"\b(?:npm_token|node_auth_token|_authtoken|pypi_token)\b|\.npmrc|\.pypirc",
                    normalized,
                )
            )
            exfiltrates = bool(
                re.search(
                    r"\b(?:curl|wget|axios|urllib)\b|\bhttps?\.request\b|\bfetch\s*\(|\brequests\.",
                    normalized,
                )
            )
            if touches_credentials and exfiltrates:
                return {
                    "code": "credential_theft_install_script",
                    "message": (
                        "External tarball install script attempts to read local package-manager credentials "
                        "and exfiltrate them."
                    ),
                }
            return {
                "code": "tarball_install_script",
                "message": "External tarball declares install-time scripts and was blocked.",
            }
    return None


def _lockfile_dependency_versions(
    workspace_dir: Path | None,
    artifact: GuardArtifact,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    if workspace_dir is None:
        return {}
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list):
        return {}
    versions: dict[tuple[str, str | None], str] = {}
    python_manifest_names = _manifest_direct_dependency_names(
        workspace_dir,
        artifact,
        ecosystem="pypi",
    )
    for relative_path in lockfile_paths:
        lockfile_path = workspace_dir / str(relative_path)
        if not lockfile_path.exists():
            continue
        try:
            lockfile_text = lockfile_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if lockfile_path.name == "package-lock.json":
            versions.update(_package_lock_target_versions(lockfile_text, targets))
            continue
        if lockfile_path.name == "pnpm-lock.yaml":
            versions.update(_pnpm_lock_target_versions(lockfile_text, targets))
            continue
        if lockfile_path.name == "yarn.lock":
            versions.update(_yarn_lock_target_versions(lockfile_text, targets))
            continue
        if lockfile_path.name == "bun.lock":
            versions.update(_bun_lock_target_versions(lockfile_text, targets))
            continue
        if lockfile_path.name == "Cargo.lock":
            versions.update(_cargo_lock_target_versions(lockfile_text, targets))
            continue
        if lockfile_path.name == "composer.lock":
            versions.update(_composer_lock_target_versions(lockfile_text, targets))
            continue
        if lockfile_path.name == "Gemfile.lock":
            versions.update(_gemfile_lock_target_versions(lockfile_text, targets))
            continue
        if lockfile_path.name == "poetry.lock":
            versions.update(_poetry_lock_target_versions(lockfile_text, targets, python_manifest_names))
            continue
        if lockfile_path.name == "uv.lock":
            versions.update(_uv_lock_target_versions(lockfile_text, targets, python_manifest_names))
            continue
        if lockfile_path.name == "Pipfile.lock":
            versions.update(_pipfile_lock_target_versions(lockfile_text, targets, python_manifest_names))
    manifest_versions = _manifest_dependency_versions(workspace_dir, artifact, targets)
    for target_key, version in manifest_versions.items():
        versions.setdefault(target_key, version)
    return versions


def _manifest_direct_dependency_names(
    workspace_dir: Path | None,
    artifact: GuardArtifact,
    *,
    ecosystem: str,
) -> set[str]:
    if workspace_dir is None:
        return set()
    manifest_paths = artifact.metadata.get("manifest_paths")
    if not isinstance(manifest_paths, list):
        return set()
    package_manager = str(artifact.metadata.get("package_manager") or "npm")
    direct_names: set[str] = set()
    for relative_path in manifest_paths:
        manifest_path = workspace_dir / str(relative_path)
        if not manifest_path.exists():
            continue
        try:
            manifest_text = manifest_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        dependency_map = _artifact_manifest_dependency_map(
            package_manager=package_manager,
            relative_path=str(relative_path),
            manifest_text=manifest_text,
        )
        for package_name in dependency_map:
            direct_names.add(_normalize_package_name(ecosystem, package_name))
    return direct_names


def _manifest_dependency_versions(
    workspace_dir: Path | None,
    artifact: GuardArtifact,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    if workspace_dir is None:
        return {}
    manifest_paths = artifact.metadata.get("manifest_paths")
    if not isinstance(manifest_paths, list):
        return {}
    package_manager = str(artifact.metadata.get("package_manager") or "npm")
    keyed_targets = {target_key: target for target in targets if (target_key := _lockfile_target_key(target))}
    versions: dict[tuple[str, str | None], str] = {}
    for relative_path in manifest_paths:
        manifest_path = workspace_dir / str(relative_path)
        if not manifest_path.exists():
            continue
        try:
            manifest_text = manifest_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        dependency_map = _artifact_manifest_dependency_map(
            package_manager=package_manager,
            relative_path=str(relative_path),
            manifest_text=manifest_text,
        )
        if not dependency_map:
            continue
        for target_key, target in keyed_targets.items():
            if target_key in versions:
                continue
            ecosystem = _optional_string(target.get("ecosystem")) or "npm"
            normalized_dependencies = {
                _normalize_package_name(ecosystem, package_name): specifier
                for package_name, specifier in dependency_map.items()
            }
            for candidate in _target_candidate_names(target):
                specifier = normalized_dependencies.get(_normalize_package_name(ecosystem, candidate))
                exact_version = _manifest_exact_version(ecosystem, specifier)
                if exact_version is not None:
                    versions[target_key] = exact_version
                    break
    return versions


def _artifact_manifest_dependency_map(
    *,
    package_manager: str,
    relative_path: str,
    manifest_text: str,
) -> dict[str, str]:
    dependency_map = parse_manifest_dependencies(path=relative_path, text=manifest_text)
    if dependency_map or package_manager != "pip":
        return dependency_map
    return parse_manifest_dependencies(path="requirements.txt", text=manifest_text)


def _package_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    try:
        entries = _package_lock_entries(text, deadline=time.monotonic() + _LOCKFILE_PARSE_BUDGET_SECONDS)
    except _DeadlineExceededError:
        return {}
    versions: dict[tuple[str, str | None], str] = {}
    for target in targets:
        target_key = _lockfile_target_key(target)
        candidate_paths = set(_package_lock_candidate_names(target))
        normalized_name = str(target["normalized_name"])
        for dependency_path, package_name, version, direct in entries:
            if not direct:
                continue
            if dependency_path in candidate_paths or package_name == normalized_name:
                versions[target_key] = version
                break
    return versions


def _package_lock_entries(text: str, *, deadline: float | None = None) -> list[tuple[str, str, str, bool]]:
    payload = json.loads(text or "{}")
    entries: list[tuple[str, str, str, bool]] = []
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for package_path, value in packages.items():
            if deadline is not None and time.monotonic() > deadline:
                break
            if not isinstance(package_path, str) or not package_path.startswith("node_modules/"):
                continue
            version = value.get("version") if isinstance(value, dict) else None
            if not isinstance(version, str):
                continue
            dependency_path = package_path.removeprefix("node_modules/")
            package_name = _optional_string(value.get("name")) if isinstance(value, dict) else None
            entries.append(
                (
                    dependency_path,
                    package_name or dependency_path.rsplit("node_modules/", 1)[-1],
                    version,
                    "node_modules/" not in dependency_path,
                )
            )
        return entries
    legacy_dependencies = payload.get("dependencies")
    if isinstance(legacy_dependencies, dict):
        _walk_package_lock_entries(legacy_dependencies, entries, prefix=None, deadline=deadline)
    return entries


def _walk_package_lock_entries(
    payload: dict[str, object],
    entries: list[tuple[str, str, str, bool]],
    *,
    prefix: str | None,
    deadline: float | None,
) -> None:
    for package_name, value in payload.items():
        if deadline is not None and time.monotonic() > deadline:
            return
        if not isinstance(package_name, str) or not isinstance(value, dict):
            continue
        version = value.get("version")
        dependency_path = package_name if prefix is None else f"{prefix}/node_modules/{package_name}"
        if isinstance(version, str):
            entries.append(
                (
                    dependency_path,
                    _optional_string(value.get("name")) or package_name,
                    version,
                    prefix is None,
                )
            )
        nested_dependencies = value.get("dependencies")
        if isinstance(nested_dependencies, dict):
            _walk_package_lock_entries(nested_dependencies, entries, prefix=dependency_path, deadline=deadline)


def _package_lock_candidate_names(target: dict[str, object]) -> tuple[str, ...]:
    alias = _optional_string(target.get("alias"))
    namespace = _optional_string(target.get("namespace"))
    name = str(target["name"])
    candidates: list[str] = []
    if alias is not None:
        candidates.append(alias)
    qualified_name = f"{namespace}/{name}" if namespace is not None else name
    if qualified_name not in candidates:
        candidates.append(qualified_name)
    return tuple(candidates)


def _cargo_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    direct_versions, _error = _safe_dependency_map_result_for_path("Cargo.lock", text, deadline=time.monotonic() + 0.2)
    return _target_versions_from_direct_map(targets, direct_versions)


def _composer_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    direct_versions, _error = _safe_dependency_map_result_for_path(
        "composer.lock",
        text,
        deadline=time.monotonic() + 0.2,
    )
    return _target_versions_from_direct_map(targets, direct_versions)


def _gemfile_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    direct_versions, _error = _safe_dependency_map_result_for_path(
        "Gemfile.lock",
        text,
        deadline=time.monotonic() + 0.2,
    )
    return _target_versions_from_direct_map(targets, direct_versions)


def _pnpm_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    direct_versions: dict[str, str] = {}
    section: str | None = None
    importer: str | None = None
    dependency_block: str | None = None
    dependency_name: str | None = None
    top_level_dependency_sections = {"dependencies", "devDependencies", "optionalDependencies"}
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0:
            section = stripped.removesuffix(":")
            importer = None
            dependency_block = None
            dependency_name = None
            continue
        if section in top_level_dependency_sections:
            if indent == 2 and ":" in stripped:
                raw_name, _, raw_value = stripped.partition(":")
                dependency_name = raw_name.strip().strip('"').strip("'")
                direct_value = raw_value.strip().strip('"').strip("'")
                exact_version = _direct_lockfile_version(direct_value)
                if exact_version is not None:
                    direct_versions[dependency_name] = exact_version
                    dependency_name = None
                continue
            if dependency_name is not None and indent >= 4 and stripped.startswith("version:"):
                exact_version = _direct_lockfile_version(stripped.partition(":")[2].strip().strip('"').strip("'"))
                if exact_version is not None:
                    direct_versions[dependency_name] = exact_version
                dependency_name = None
            continue
        if section != "importers":
            continue
        if indent == 2 and stripped.endswith(":"):
            importer = stripped[:-1].strip('"').strip("'")
            dependency_block = None
            dependency_name = None
            continue
        if importer not in {".", "default"}:
            continue
        if indent == 4 and stripped.endswith(":"):
            block_name = stripped.removesuffix(":")
            dependency_block = block_name if "dependencies" in block_name.lower() else None
            dependency_name = None
            continue
        if dependency_block is None:
            continue
        if indent == 6 and ":" in stripped:
            raw_name, _, raw_value = stripped.partition(":")
            dependency_name = raw_name.strip().strip('"').strip("'")
            direct_value = raw_value.strip().strip('"').strip("'")
            exact_version = _direct_lockfile_version(direct_value)
            if exact_version is not None:
                direct_versions[dependency_name] = exact_version
                dependency_name = None
            continue
        if dependency_name is not None and indent >= 8 and stripped.startswith("version:"):
            exact_version = _direct_lockfile_version(stripped.partition(":")[2].strip().strip('"').strip("'"))
            if exact_version is not None:
                direct_versions[dependency_name] = exact_version
            dependency_name = None
    return _target_versions_from_direct_map(targets, direct_versions)


def _yarn_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    versions: dict[tuple[str, str | None], str] = {}
    current_selectors: tuple[str, ...] = ()
    target_selectors = {_lockfile_target_key(target): set(_expected_yarn_selectors(target)) for target in targets}
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw_line.startswith((" ", "\t")):
            current_selectors = tuple(
                selector
                for selector in (part.strip().strip('"').strip("'") for part in stripped.removesuffix(":").split(","))
                if selector and selector != "__metadata"
            )
            continue
        if not current_selectors:
            continue
        version_match = re.match(r'^version\s+"([^"]+)"$', stripped) or re.match(
            r'^version:\s*"?([^"\s]+)"?$',
            stripped,
        )
        if version_match is None:
            continue
        version = version_match.group(1)
        selector_set = set(current_selectors)
        for target_key, expected_selectors in target_selectors.items():
            if target_key in versions or not expected_selectors:
                continue
            if selector_set & expected_selectors:
                versions[target_key] = version
    return versions


def _expected_yarn_selectors(target: dict[str, object]) -> tuple[str, ...]:
    requested = _optional_string(target.get("version")) or _optional_string(target.get("range"))
    if requested is None:
        return ()
    normalized_name = str(target["normalized_name"])
    alias = _optional_string(target.get("alias"))
    selectors = [f"{normalized_name}@{requested}", f"{normalized_name}@npm:{requested}"]
    if alias is not None:
        selectors.append(f"{alias}@npm:{normalized_name}@{requested}")
    return tuple(dict.fromkeys(selectors))


def _bun_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    try:
        payload = tomllib.loads(text or "")
    except tomllib.TOMLDecodeError:
        return {}
    packages = payload.get("package")
    if not isinstance(packages, list):
        return {}
    versions_by_name: dict[str, list[str]] = {}
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = _optional_string(entry.get("name"))
        version = _optional_string(entry.get("version"))
        if name is None or version is None:
            continue
        versions_by_name.setdefault(name, []).append(version)
    versions: dict[tuple[str, str | None], str] = {}
    for target in targets:
        target_key = _lockfile_target_key(target)
        requested = _optional_string(target.get("range"))
        candidates = versions_by_name.get(str(target["normalized_name"]), [])
        if len(candidates) == 1:
            versions[target_key] = candidates[0]
            continue
        if requested is None:
            continue
        matching_versions = [value for value in candidates if version_matches_js_selector(value, requested)]
        if len(matching_versions) == 1:
            versions[target_key] = matching_versions[0]
    return versions


def _poetry_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
    direct_manifest_names: set[str],
) -> dict[tuple[str, str | None], str]:
    return _target_versions_from_direct_map(
        targets,
        _poetry_lock_direct_versions(text, direct_manifest_names),
    )


def _poetry_lock_direct_versions(text: str, direct_manifest_names: set[str]) -> dict[str, str]:
    try:
        payload = tomllib.loads(text or "")
    except tomllib.TOMLDecodeError:
        return {}
    packages = payload.get("package")
    direct_versions: dict[str, str] = {}
    if not isinstance(packages, list):
        return direct_versions
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = _optional_string(package.get("name"))
        version = _optional_string(package.get("version"))
        normalized_name = _normalize_package_name("pypi", name) if name is not None else None
        if normalized_name is None or version is None or normalized_name not in direct_manifest_names:
            continue
        direct_versions[normalized_name] = version
    return direct_versions


def _uv_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
    direct_manifest_names: set[str],
) -> dict[tuple[str, str | None], str]:
    return _target_versions_from_direct_map(
        targets,
        _uv_lock_direct_versions(text, direct_manifest_names),
    )


def _uv_lock_direct_versions(text: str, direct_manifest_names: set[str]) -> dict[str, str]:
    try:
        payload = tomllib.loads(text or "")
    except tomllib.TOMLDecodeError:
        return {}
    packages = payload.get("package")
    direct_versions: dict[str, str] = {}
    if not isinstance(packages, list):
        return direct_versions
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = _optional_string(package.get("name"))
        version = _optional_string(package.get("version"))
        normalized_name = _normalize_package_name("pypi", name) if name is not None else None
        if normalized_name is None or version is None or normalized_name not in direct_manifest_names:
            continue
        direct_versions[normalized_name] = version
    return direct_versions


def _pipfile_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
    direct_manifest_names: set[str],
) -> dict[tuple[str, str | None], str]:
    return _target_versions_from_direct_map(
        targets,
        _pipfile_lock_direct_versions(text, direct_manifest_names),
    )


def _pipfile_lock_direct_versions(text: str, direct_manifest_names: set[str]) -> dict[str, str]:
    try:
        payload = json.loads(text or "{}")
    except json.JSONDecodeError:
        return {}
    direct_versions: dict[str, str] = {}
    for section in ("default", "develop"):
        values = payload.get(section)
        if not isinstance(values, dict):
            continue
        for package_name, package_value in values.items():
            if not isinstance(package_name, str) or not isinstance(package_value, dict):
                continue
            exact_version = _python_lockfile_version(package_value.get("version"))
            normalized_name = _normalize_package_name("pypi", package_name)
            if exact_version is not None and normalized_name in direct_manifest_names:
                direct_versions[normalized_name] = exact_version
    return direct_versions


def _target_versions_from_direct_map(
    targets: tuple[dict[str, object], ...],
    direct_versions: dict[str, str],
) -> dict[tuple[str, str | None], str]:
    versions: dict[tuple[str, str | None], str] = {}
    for target in targets:
        target_key = _lockfile_target_key(target)
        for candidate in _target_candidate_names(target):
            version = direct_versions.get(candidate)
            if version is not None:
                versions[target_key] = version
                break
    return versions


def _direct_lockfile_version(value: str) -> str | None:
    normalized = value.split("(", 1)[0].strip()
    if normalized.startswith("npm:"):
        normalized = normalized.partition("npm:")[2]
    if "@" in normalized and not normalized.startswith("@"):
        candidate = normalized.rsplit("@", 1)[-1]
        if _exact_version(candidate) is not None:
            return candidate
    if _exact_version(normalized) is not None:
        return normalized
    return None


def _lockfile_target_key(target: dict[str, object]) -> tuple[str, str | None]:
    return str(target["normalized_name"]), _optional_string(target.get("alias"))


def _dependency_package_name(dependency_path: str) -> str | None:
    normalized_dependency_path = dependency_path.strip("/").lower()
    if not normalized_dependency_path:
        return None
    if "node_modules/" in normalized_dependency_path:
        return normalized_dependency_path.rsplit("node_modules/", 1)[-1]
    if "/" not in normalized_dependency_path or normalized_dependency_path.startswith("@"):
        return normalized_dependency_path
    return None


def _resolved_target_version(
    *,
    target: dict[str, object],
    lockfile_versions: dict[tuple[str, str | None], str],
) -> str | None:
    exact_version = _optional_string(target.get("version"))
    if exact_version is not None:
        return exact_version
    lockfile_version = lockfile_versions.get(_lockfile_target_key(target))
    if lockfile_version is not None:
        return lockfile_version
    requested_range = _optional_string(target.get("range"))
    if requested_range is None:
        return None
    exact_version = _exact_version(requested_range)
    if exact_version is not None:
        return exact_version
    registry_version = _registry_resolved_target_version(target=target, requested_range=requested_range)
    if registry_version is not None:
        return registry_version
    return None


def _registry_resolved_target_version(*, target: dict[str, object], requested_range: str) -> str | None:
    ecosystem = _optional_string(target.get("ecosystem")) or "npm"
    if _optional_string(target.get("source_url")) is not None:
        return None
    package_name = _registry_package_name(target)
    if package_name is None:
        return None
    if ecosystem == "npm":
        return _npm_registry_resolved_version(package_name=package_name, requested_range=requested_range)
    if ecosystem == "pypi":
        normalized_name = _normalize_package_name("pypi", package_name)
        return _pypi_registry_resolved_version(package_name=normalized_name, requested_range=requested_range)
    return None


def _registry_package_name(target: dict[str, object]) -> str | None:
    package_name = _optional_string(target.get("name"))
    if package_name is None:
        return None
    namespace = _optional_string(target.get("namespace"))
    return f"{namespace}/{package_name}" if namespace is not None else package_name


def _npm_registry_resolved_version(*, package_name: str, requested_range: str) -> str | None:
    metadata_url = f"{_NPM_REGISTRY_METADATA_BASE_URL.rstrip('/')}/{urllib.parse.quote(package_name, safe='')}"
    request = urllib.request.Request(
        metadata_url,
        headers={
            "Accept": "application/vnd.npm.install-v1+json",
            "User-Agent": "hol-guard-local",
        },
    )
    try:
        payload = _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_TIMEOUT_SECONDS,
            retry_timeout_seconds=_RETRY_TIMEOUT_SECONDS,
        )
    except (OSError, RuntimeError, ValueError):
        return None
    versions_payload = payload.get("versions")
    if not isinstance(versions_payload, dict):
        return None
    versions = [version for version in versions_payload if isinstance(version, str)]
    if not versions:
        return None
    return highest_js_version_for_selector(versions, requested_range)


def _pypi_registry_resolved_version(*, package_name: str, requested_range: str) -> str | None:
    metadata_url = f"{_PYPI_REGISTRY_METADATA_BASE_URL.rstrip('/')}/{urllib.parse.quote(package_name, safe='')}/json"
    request = urllib.request.Request(
        metadata_url,
        headers={
            "Accept": "application/json",
            "User-Agent": "hol-guard-local",
        },
    )
    try:
        payload = _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_TIMEOUT_SECONDS,
            retry_timeout_seconds=_RETRY_TIMEOUT_SECONDS,
        )
    except (OSError, RuntimeError, ValueError):
        return None
    releases_payload = payload.get("releases")
    if not isinstance(releases_payload, dict):
        return None
    normalized_range = _normalized_pypi_requested_range(requested_range)
    if normalized_range is None:
        return None
    try:
        specifier = SpecifierSet(normalized_range)
    except InvalidSpecifier:
        return None
    matching_versions: list[Version] = []
    for release in releases_payload:
        if not isinstance(release, str):
            continue
        try:
            parsed_version = Version(release)
        except InvalidVersion:
            continue
        if parsed_version in specifier:
            matching_versions.append(parsed_version)
    if not matching_versions:
        return None
    matching_versions.sort()
    return str(matching_versions[-1])


def _normalized_pypi_requested_range(requested_range: str) -> str | None:
    normalized = requested_range.strip()
    if not normalized:
        return None
    if normalized.startswith("~="):
        return normalized
    if normalized.startswith("^"):
        return _pypi_caret_specifier(normalized[1:])
    if normalized.startswith("~"):
        return _pypi_tilde_specifier(normalized[1:])
    return normalized


def _pypi_caret_specifier(value: str) -> str | None:
    base = _optional_string(value)
    if base is None:
        return None
    try:
        parsed_version = Version(base)
    except InvalidVersion:
        return None
    release = parsed_version.release
    major = release[0] if len(release) >= 1 else 0
    minor = release[1] if len(release) >= 2 else 0
    patch = release[2] if len(release) >= 3 else 0
    if major > 0:
        upper_bound = f"{major + 1}"
    elif minor > 0:
        upper_bound = f"0.{minor + 1}"
    else:
        upper_bound = f"0.0.{patch + 1}"
    return f">={base},<{upper_bound}"


def _pypi_tilde_specifier(value: str) -> str | None:
    base = _optional_string(value)
    if base is None:
        return None
    try:
        parsed_version = Version(base)
    except InvalidVersion:
        return None
    release = parsed_version.release
    major = release[0] if len(release) >= 1 else 0
    upper_bound = f"{major}.{release[1] + 1}" if len(release) >= 2 else f"{major + 1}"
    return f">={base},<{upper_bound}"


def _bundle_package_versions(bundle_response: SupplyChainBundleResponse, target: dict[str, object]) -> list[str]:
    return [item.version for item in bundle_response.bundle.packages if _bundle_package_name_matches(item, target)]


def _bundle_package_name_matches(package: SupplyChainBundlePackage, target: dict[str, object]) -> bool:
    target_ecosystem = _optional_string(target.get("ecosystem"))
    if target_ecosystem is not None and package.ecosystem != target_ecosystem:
        return False
    full_name = (
        _normalize_package_name(package.ecosystem, f"{package.namespace}/{package.name}")
        if package.namespace is not None
        else _normalize_package_name(package.ecosystem, package.name)
    )
    target_name = str(target["normalized_name"])
    target_namespace = _optional_string(target.get("namespace"))
    if target_namespace is not None:
        return target_name == full_name
    if package.namespace is not None:
        return False
    return target_name == _normalize_package_name(package.ecosystem, package.name)


def _recommended_fix_allow_package_result(
    *,
    target: dict[str, object],
    resolved_version: str,
    bundle_response: SupplyChainBundleResponse,
) -> dict[str, object] | None:
    for package in bundle_response.bundle.packages:
        if not _bundle_package_name_matches(package, target):
            continue
        if package.version == resolved_version:
            continue
        if package.recommended_fix_version != resolved_version:
            continue
        return {
            "decision": "allow",
            "ecosystem": package.ecosystem,
            "name": target["name"],
            "namespace": target["namespace"],
            "requestedVersion": _optional_string(target.get("range")) or resolved_version,
            "resolvedVersion": resolved_version,
            "recommendedFixVersion": None,
            "riskScore": None,
            "direct": True,
            "dependencyPath": None,
            "packageManager": _optional_string(target.get("package_manager")) or "npm",
            "redactedCommand": _optional_string(target.get("redacted_command")),
            "alias": _optional_string(target.get("alias")),
            "reasons": (
                {
                    "code": "recommended_fix_version",
                    "message": (
                        f"Requested version {resolved_version} matches Guard's recommended fix for "
                        f"{_package_display_name(target)}."
                    ),
                    "severity": "low",
                    "source": "bundle",
                },
            ),
        }
    return None


def _source_url_from_specifier(specifier: str | None) -> str | None:
    if specifier is None:
        return None
    if "://" in specifier or specifier.startswith(("git+", "github:", "gitlab:", "bitbucket:", "file:")):
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
    if "://" in candidate or candidate.startswith(("git+", "github:", "gitlab:", "bitbucket:", "file:")):
        return candidate
    return None


def _safe_dependency_map_for_path(path: str, text: str, *, deadline: float) -> dict[str, str]:
    dependency_map, _error = _safe_dependency_map_result_for_path(path, text, deadline=deadline)
    return dependency_map


def _safe_dependency_map_result_for_path(
    path: str,
    text: str,
    *,
    deadline: float,
) -> tuple[dict[str, str], str | None]:
    try:
        return _dependency_map_for_path(path, text, deadline=deadline), None
    except (
        _DeadlineExceededError,
        ET.ParseError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return {}, "parse_error"


def _lockfile_parse_warning_result(
    *,
    target: dict[str, object],
    artifact: GuardArtifact,
    workspace_dir: Path | None,
) -> dict[str, object] | None:
    if workspace_dir is None:
        return None
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list):
        return None
    target_ecosystem = _optional_string(target.get("ecosystem")) or "npm"
    for relative_path in lockfile_paths:
        lockfile_path = workspace_dir / str(relative_path)
        if not lockfile_path.exists():
            continue
        lockfile_ecosystem = _lockfile_ecosystem(lockfile_path.name)
        if lockfile_ecosystem is not None and lockfile_ecosystem != target_ecosystem:
            continue
        try:
            lockfile_text = lockfile_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        _dependency_map, error = _safe_dependency_map_result_for_path(
            lockfile_path.name,
            lockfile_text,
            deadline=time.monotonic() + 0.2,
        )
        if error is None:
            continue
        return _heuristic_package_result(
            target=target,
            decision="ask",
            code="lockfile_parse_error",
            message=(
                "Guard could not parse the existing lockfile, so this range-based package request needs review. "
                "Repair the lockfile, then retry."
            ),
            severity="high",
        )
    return None


def _manifest_exact_version(ecosystem: str, value: str | None) -> str | None:
    if ecosystem == "pypi":
        return _python_lockfile_version(value)
    if ecosystem == "cargo":
        normalized = _optional_string(value)
        if normalized is None:
            return None
        if normalized.startswith("="):
            return _exact_version(normalized.lstrip("="))
        return None
    return _exact_version(value)


def _with_support_metadata(package: dict[str, object]) -> dict[str, object]:
    metadata = ecosystem_support_metadata(_optional_string(package.get("ecosystem")) or "unsupported")
    enriched = dict(package)
    enriched["supportLevel"] = metadata["support_level"]
    enriched["supportLabel"] = metadata["support_label"]
    return enriched


def _with_package_reason(package: dict[str, object], reason: dict[str, object]) -> dict[str, object]:
    package_reasons = package.get("reasons")
    updated = dict(package)
    if isinstance(package_reasons, (tuple, list)):
        updated["reasons"] = (*tuple(item for item in package_reasons if isinstance(item, dict)), reason)
    else:
        updated["reasons"] = (reason,)
    return updated


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
    ecosystem = _optional_string(target.get("ecosystem")) or "npm"
    if version is None:
        return False
    if selector in {version, f"={version}", f"=={version}"}:
        return True
    if ecosystem == "npm" and version_matches_js_selector(version, selector):
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
    ecosystem: str | None = None,
) -> SupplyChainBundlePackage | None:
    normalized = _normalize_package_name(ecosystem, package_name) if ecosystem is not None else None
    for item in bundle_response.bundle.packages:
        if ecosystem is not None and item.ecosystem != ecosystem:
            continue
        target_name = normalized or _normalize_package_name(item.ecosystem, package_name)
        full_name = (
            _normalize_package_name(item.ecosystem, f"{item.namespace}/{item.name}")
            if item.namespace is not None
            else _normalize_package_name(item.ecosystem, item.name)
        )
        normalized_item_name = _normalize_package_name(item.ecosystem, item.name)
        if target_name not in {normalized_item_name, full_name}:
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
        try:
            hashes.append(hashlib.sha256(path.read_bytes()).hexdigest())
        except OSError:
            continue
    return hashes


def _stable_hash(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _split_namespace_name(value: str) -> tuple[str | None, str]:
    if value.startswith("@") and "/" in value:
        namespace, name = value.split("/", 1)
        return namespace, name
    return None, value


def _exact_version(value: str | None) -> str | None:
    normalized = _optional_string(value)
    if normalized is None:
        return None
    if "://" in normalized or normalized.startswith(("git+", "github:", "gitlab:", "bitbucket:", "file:")):
        return None
    if normalized.startswith(("^", "~", "<", ">", "!", "*")):
        return None
    if any(token in normalized for token in ("||", " - ", ",")):
        return None
    return normalized


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _decision_rank(value: str) -> int:
    return _DECISION_RANK.get(value, 1)


def _fix_command(package: dict[str, object]) -> str | None:
    package_name = _package_install_target(package)
    fix_version = _optional_string(package.get("recommendedFixVersion"))
    ecosystem = _optional_string(package.get("ecosystem")) or "npm"
    package_manager = _optional_string(package.get("packageManager")) or "npm"
    if not fix_version:
        return None
    if ecosystem == "pypi":
        if package_manager == "uv":
            if _uses_uv_pip_install(package):
                return f"uv pip install {package_name}=={fix_version}"
            return f"uv add {package_name}=={fix_version}"
        if package_manager == "poetry":
            return f"poetry add {package_name}@{fix_version}"
        if package_manager == "pipenv":
            return f"pipenv install {package_name}=={fix_version}"
        return f"pip install {package_name}=={fix_version}"
    if package_manager == "pnpm":
        return f"pnpm add {package_name}@{fix_version}"
    if package_manager == "yarn":
        return f"yarn add {package_name}@{fix_version}"
    if package_manager == "bun":
        return f"bun add {package_name}@{fix_version}"
    return f"npm install {package_name}@{fix_version}"


def _uses_uv_pip_install(package: dict[str, object]) -> bool:
    command = (_optional_string(package.get("redactedCommand")) or "").split()
    return len(command) >= 3 and tuple(command[:3]) == ("uv", "pip", "install")


def _package_install_target(package: dict[str, object]) -> str:
    alias = _optional_string(package.get("alias"))
    package_name = _package_display_name({**package, "alias": None})
    ecosystem = _optional_string(package.get("ecosystem")) or "npm"
    if alias is not None and ecosystem == "npm":
        return f"{alias}@npm:{package_name}"
    return alias if alias is not None else package_name


def _package_display_name(package: dict[str, object]) -> str:
    alias = _optional_string(package.get("alias"))
    if alias is not None:
        return alias
    namespace = _optional_string(package.get("namespace"))
    name = _optional_string(package.get("name")) or "package"
    return f"{namespace}/{name}" if namespace is not None else name


def _normalize_package_name(ecosystem: str, package_name: str) -> str:
    normalized = package_name.strip().lower()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", normalized)
    return normalized


def _target_candidate_names(target: dict[str, object]) -> tuple[str, ...]:
    alias = _optional_string(target.get("alias"))
    namespace = _optional_string(target.get("namespace"))
    ecosystem = _optional_string(target.get("ecosystem")) or "npm"
    name = str(target["name"])
    candidates: list[str] = []
    if alias is not None:
        candidates.append(alias)
    qualified_name = f"{namespace}/{name}" if namespace is not None else name
    candidates.append(qualified_name)
    normalized_name = _normalize_package_name(ecosystem, qualified_name)
    if normalized_name not in candidates:
        candidates.append(normalized_name)
    raw_package_name = _optional_string(target.get("package_name"))
    if raw_package_name is not None and raw_package_name not in candidates:
        candidates.append(raw_package_name)
        raw_normalized = _normalize_package_name(ecosystem, raw_package_name)
        if raw_normalized not in candidates:
            candidates.append(raw_normalized)
    return tuple(candidates)


def _python_lockfile_version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().strip('"').strip("'")
    if ";" in normalized:
        normalized = normalized.split(";", 1)[0].strip()
    if normalized.startswith(("==", "===")):
        normalized = normalized.lstrip("=")
    if not normalized:
        return None
    try:
        Version(normalized)
    except InvalidVersion:
        return None
    return normalized


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
    decision: str,
    reason: str,
    stale: bool,
) -> str:
    package_label = f"{package.name}@{package.version}"
    if stale:
        if decision == "block":
            return f"Cached bundle is stale, but Guard still blocked {package_label} from advisory intelligence."
        if decision == "ask":
            return f"Cached bundle is stale, so Guard still requires approval for {package_label}."
        if decision == "warn":
            return f"Cached bundle is stale, so Guard still warns on {package_label}."
        return f"Cached bundle is stale, so Guard kept {package_label} in monitor mode."
    if reason == "known_malware_or_kev":
        return f"Cached bundle flagged {package_label} from advisory intelligence."
    if reason == "maintainer_compromise":
        return f"Cached bundle flagged {package_label} for probable maintainer compromise."
    return f"Cached bundle matched {package_label}."
