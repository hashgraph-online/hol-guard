"""Local package-request evaluation for HOL Guard supply-chain protection."""

from __future__ import annotations

import hashlib  # noqa: F401
import importlib
import json  # noqa: F401
import re
import sys
import time  # noqa: F401
import urllib.error
import urllib.parse
import urllib.request  # noqa: F401
from collections.abc import Callable, Mapping  # noqa: F401
from contextvars import ContextVar
from dataclasses import dataclass, replace  # noqa: F401
from datetime import datetime, timezone  # noqa: F401
from pathlib import Path  # noqa: F401
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tomllib
else:  # pragma: no cover - runtime compatibility
    tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")

from packaging.specifiers import InvalidSpecifier, SpecifierSet  # noqa: F401
from packaging.version import InvalidVersion, Version  # noqa: F401

from ..action_lattice import normalize_guard_action_result
from ..config import load_guard_config, resolve_risk_action  # noqa: F401
from ..models import GuardAction, GuardArtifact  # noqa: F401
from ..package_firewall_entitlement import resolve_package_firewall_entitlement  # noqa: F401
from ..stable_digest import stable_digest_hex
from ..store import GuardStore  # noqa: F401
from ..store_evidence import EvidenceRecord  # noqa: F401
from ..text import ensure_terminal_punctuation as _ensure_terminal_punctuation  # noqa: F401
from .js_semver import highest_js_version_for_selector, version_matches_js_selector  # noqa: F401
from .lockfile_evaluation_support import (
    collect_lockfile_parse_results,  # noqa: F401
    incomplete_lockfile_fallback_target,  # noqa: F401
    incomplete_lockfile_metadata,  # noqa: F401
    package_has_incomplete_lockfile,  # noqa: F401
    parse_lockfile_with_budget,  # noqa: F401
)
from .lockfile_parse_result import (
    LOCKFILE_PARSER_VERSION,  # noqa: F401
    LockfileParseResult,
    incomplete_lockfile_result,  # noqa: F401
    parse_lockfile_text,  # noqa: F401
)
from .manifest_dependency_targets import evaluation_targets as _manifest_evaluation_targets  # noqa: F401
from .npm_policy_range import (
    bind_resolved_npm_policy_result,  # noqa: F401
    policy_selector_matches_target,  # noqa: F401
    target_for_resolved_npm_policy_match,  # noqa: F401
)
from .npm_source_spec import NpmSourceSpec, parse_npm_source_spec  # noqa: F401
from .offline_archive_inspection import inspect_archive_offline  # noqa: F401
from .package_intent_common import split_python_extras  # noqa: F401
from .package_lock_versions import direct_lockfile_version as _direct_lockfile_version  # noqa: F401
from .package_lock_versions import exact_lockfile_version as _exact_version  # noqa: F401
from .package_manifest_diff import (
    _DeadlineExceededError,  # noqa: F401
    _dependency_map_for_path,  # noqa: F401
    parse_manifest_dependencies,  # noqa: F401
)
from .restricted_archive_download import (
    RestrictedArchiveDownload,
    RestrictedArchiveDownloadResult,
    RestrictedArchiveFailure,  # noqa: F401
    canonical_external_https_archive_source,  # noqa: F401
    download_restricted_archive,
    is_external_https_archive_source,  # noqa: F401
)
from .runner import (
    GuardSyncAuthorizationExpiredError,  # noqa: F401
    GuardSyncEndpointUntrustedError,  # noqa: F401
    GuardSyncNotConfiguredError,  # noqa: F401
    _guard_sync_request,  # noqa: F401
    _is_timeout_error,  # noqa: F401
    _normalized_receipts_sync_url,  # noqa: F401
    _resolve_guard_sync_auth_context,  # noqa: F401
    _urlopen_json_with_timeout_retry,  # noqa: F401
    _validate_guard_sync_url,  # noqa: F401
)
from .supply_chain import detect_supply_chain_risk  # noqa: F401
from .supply_chain_bundle import (
    SupplyChainBundleExpiredError,  # noqa: F401
    SupplyChainBundleMalformedError,  # noqa: F401
    check_supply_chain_bundle_freshness,  # noqa: F401
    evaluate_cached_supply_chain_bundle,  # noqa: F401
    load_supply_chain_bundle_response,  # noqa: F401
)
from .supply_chain_bundle_models import (
    SupplyChainBundlePackage,  # noqa: F401
    SupplyChainBundlePolicyRule,  # noqa: F401
    SupplyChainBundleResponse,  # noqa: F401
)
from .supply_chain_bundle_runtime import _is_high_confidence_block  # noqa: F401
from .supply_chain_package_identity import (
    CanonicalPackageIdentity,  # noqa: F401
    PackageIdentityError,  # noqa: F401
    canonical_package_identity,  # noqa: F401
    normalize_ecosystem,  # noqa: F401
    normalize_qualified_package_name,  # noqa: F401
    parse_package_identity,  # noqa: F401
)
from .supply_chain_support import ecosystem_support_metadata  # noqa: F401
from .workspace_path_guard import (
    WorkspaceInputSnapshotError,  # noqa: F401
    path_exists_within_workspace,  # noqa: F401
    read_bytes_within_workspace,  # noqa: F401
    read_text_within_workspace,  # noqa: F401
    resolve_path_within_workspace,  # noqa: F401
    workspace_input_snapshot,  # noqa: F401
)

_DECISION_RANK = {"allow": 0, "monitor": 1, "warn": 2, "ask": 3, "block": 4}
_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_TIMEOUT_SECONDS = 1
_RETRY_TIMEOUT_SECONDS = 1
_CLOUD_INBOX_URL_RE = re.compile(r"https?://[^\s]+/guard/inbox/?", re.IGNORECASE)
_LOCAL_REVIEW_INSTRUCTION = "Review this request in HOL Guard, then retry."
_LOCAL_REVIEW_INSTRUCTION_RE = re.compile(re.escape(_LOCAL_REVIEW_INSTRUCTION), re.IGNORECASE)
_LOCAL_APPROVAL_INSTRUCTION_RE = re.compile(
    r"\s*Open HOL Guard to approve or keep this blocked:\s*https?://\S+"
    r"(?:\s+After you choose,\s+retry the same .*? action\.)?",
    re.IGNORECASE,
)
_LOCAL_APPROVAL_REQUEST_URL_RE = re.compile(r"https?://[^\s]+/requests(?:/[^\s]*)?", re.IGNORECASE)
_NAMED_SOURCE_SEPARATOR_RE = re.compile(
    r"@(?=(?:https?|git\+|github|gitlab|bitbucket|file):)",
    re.IGNORECASE,
)
_LOCKFILE_PARSE_BUDGET_SECONDS = 0.5
_LOCKFILE_PARSE_BUDGET_PER_MIB_SECONDS = 0.75
_LOCKFILE_PARSE_MAX_BUDGET_SECONDS = 1.5
_LOCKFILE_PARSE_CACHE: ContextVar[dict[tuple[str, bytes], LockfileParseResult] | None] = ContextVar(
    "lockfile_parse_cache",
    default=None,
)
_TRANSITIVE_BLOCK_CONFIDENCE_THRESHOLD = 900
_NPM_REGISTRY_METADATA_BASE_URL = "https://registry.npmjs.org"
_PYPI_REGISTRY_METADATA_BASE_URL = "https://pypi.org/pypi"
_TARBALL_SCAN_TIMEOUT_SECONDS = 2
_TARBALL_SCAN_MAX_BYTES = 6 * 1024 * 1024
_TARBALL_SCAN_MAX_FILES = 500
_TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES = 256 * 1024
_EXTERNAL_ARCHIVE_MAX_TARGETS = 4
_EXTERNAL_ARCHIVE_MAX_AGGREGATE_BYTES = 12 * 1024 * 1024
_EXTERNAL_ARCHIVE_REQUEST_TIMEOUT_SECONDS = 8.0
_CLOUD_VALIDATION_ERROR_CACHE_TTL_SECONDS = 15 * 60
_REGISTRY_DEFAULT_RANGES = {
    "npm": "latest",
    "pypi": ">=0",
}
_DIST_TAG_RANGE_ECOSYSTEMS = {"npm"}
_DECISION_TO_GUARD_ACTION: dict[str, GuardAction] = {
    "allow": "allow",
    "monitor": "allow",
    "warn": "warn",
    "ask": "require-reapproval",
    "block": "block",
}


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


# Reexports retain the original declaration and initialization order.
# isort: off
from .package_eval_dispatch import evaluate_package_request_artifact  # noqa: E402, F401
from .package_eval_uncached import _evaluate_package_request_artifact_uncached  # noqa: E402, F401
from .package_eval_dispatch import _artifact_has_package_material, _has_non_empty_string_item  # noqa: E402, F401
from .package_eval_dispatch import _empty_package_material_result  # noqa: E402, F401
from .package_eval_dispatch import _cached_supply_chain_eval_is_reusable  # noqa: E402, F401
from .package_eval_dispatch import _cached_eval_has_reason_code  # noqa: E402, F401
from .package_eval_dispatch import _cache_reusable_cloud_validation_error  # noqa: E402, F401
from .package_eval_dispatch import _cached_cloud_validation_error_requires_uncached_retry  # noqa: E402, F401
from .package_eval_dispatch import _cached_cloud_validation_error_has_saved_policy  # noqa: E402, F401
from .package_eval_dispatch import _evaluation_has_reason_code  # noqa: E402, F401


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
    external_archive_downloads: tuple[RestrictedArchiveDownload, ...] = ()
    external_archive_source_hashes: tuple[str, ...] = ()


from .package_eval_finalize import _finalize_evaluation  # noqa: E402, F401
from .package_eval_cloud import _evaluate_with_cloud  # noqa: E402, F401
from .package_eval_cloud_failures import _normalize_package_user_copy, _strip_review_evidence_tail  # noqa: E402, F401
from .package_eval_cloud_failures import _looks_like_cloud_inbox_url  # noqa: E402, F401
from .package_eval_cloud_failures import _cloud_http_fail_closed_evaluation  # noqa: E402, F401
from .package_eval_cloud_failures import _cloud_fail_closed_evaluation  # noqa: E402, F401
from .package_eval_cloud_failures import _with_cloud_auth_reconnect_copy  # noqa: E402, F401
from .package_eval_cloud_failures import _cloud_fallback_requires_reconnect_copy  # noqa: E402, F401
from .package_eval_cloud_failures import _cloud_fail_closed_decision  # noqa: E402, F401
from .package_eval_cloud_failures import _unidentified_packages_fail_closed  # noqa: E402, F401
from .package_eval_cloud_failures import _unidentified_package_decision  # noqa: E402, F401
from .package_eval_bundle import _evaluate_with_bundle, _primary_bundle_advisory_id  # noqa: E402, F401
from .package_eval_bundle import _bundle_advisory_aliases  # noqa: E402, F401
from .package_eval_heuristics import _heuristic_result  # noqa: E402, F401
from .package_eval_evidence import _persist_evidence  # noqa: E402, F401
from .package_eval_targets import _evaluation_targets, _cloud_evaluation_targets  # noqa: E402, F401
from .package_eval_targets import _targets_from_artifact, _private_package_targets_match_public  # noqa: E402, F401
from .package_eval_targets import _public_package_targets_are_self_consistent  # noqa: E402, F401
from .package_eval_bundle import _bundle_meta  # noqa: E402, F401
from .package_eval_lockfile_status import _lockfile_parse_results, _parse_lockfile_text_result  # noqa: E402, F401
from .package_eval_lockfile_status import _lockfile_parse_budget_seconds  # noqa: E402, F401
from .package_eval_lockfile_status import _first_incomplete_lockfile_result  # noqa: E402, F401
from .package_eval_lockfile_status import _finalize_incomplete_lockfile_evaluation  # noqa: E402, F401
from .package_eval_lockfile_status import _incomplete_lockfile_package_result  # noqa: E402, F401
from .package_eval_evidence import _workspace_fingerprint, _build_request_payload  # noqa: E402, F401
from .package_eval_lockfile_status import _lockfile_context  # noqa: E402, F401
from .package_eval_transitive import _transitive_lockfile_results, _transitive_lockfile_decision  # noqa: E402, F401
from .package_eval_transitive import _is_bundle_stale, _bundle_package_index  # noqa: E402, F401
from .package_eval_transitive import _bundle_package_from_index, _parse_evaluation_timestamp  # noqa: E402, F401
from .package_eval_transitive import _lockfile_ecosystem  # noqa: E402, F401
from .package_eval_results import _bundle_package_result, _system_package_monitor_result  # noqa: E402, F401
from .package_eval_results import _homebrew_package_monitor_result, _unsupported_ecosystem_result  # noqa: E402, F401
from .package_eval_results import _local_source_dependency_result, _policy_package_result  # noqa: E402, F401
from .package_eval_results import _package_from_cloud_result, _package_target_result  # noqa: E402, F401
from .package_eval_results import _unknown_package_result, _fallback_package_results  # noqa: E402, F401
from .package_eval_results import _bun_lockfile_binary_fallback_packages  # noqa: E402, F401
from .package_eval_local_sources import _local_package_manifest_result, _local_package_manifest_path  # noqa: E402, F401
from .package_eval_local_sources import _local_python_build_result  # noqa: E402, F401
from .package_eval_local_sources import _looks_like_explicit_local_python_path  # noqa: E402, F401
from .package_eval_local_sources import _local_python_path_text, _local_python_project_path  # noqa: E402, F401
from .package_eval_local_sources import _python_setup_script_looks_suspicious  # noqa: E402, F401
from .package_eval_local_sources import _manifest_package_name, _artifact_has_flag  # noqa: E402, F401
from .package_eval_local_sources import _dependency_confusion_policy_package_result  # noqa: E402, F401
from .package_eval_local_sources import _dependency_confusion_selector_matches  # noqa: E402, F401
from .package_eval_local_sources import _heuristic_package_result, _go_replace_result  # noqa: E402, F401
from .package_eval_local_sources import _go_mod_replace_map, _is_git_source_url  # noqa: E402, F401
from .package_eval_archives import _is_external_https_tarball_source  # noqa: E402, F401
from .package_eval_archives import _target_is_external_https_archive  # noqa: E402, F401
from .package_eval_archives import _target_requires_npm_source_review  # noqa: E402, F401
from .package_eval_archives import _external_tarball_dependency_result, _scan_external_tarball  # noqa: E402, F401
from .package_eval_archives import _external_archive_request_timeout_result  # noqa: E402, F401


def _download_external_tarball(
    source_url: str,
    *,
    timeout_seconds: float = _TARBALL_SCAN_TIMEOUT_SECONDS,
) -> RestrictedArchiveDownloadResult:
    return download_restricted_archive(
        source_url,
        max_bytes=_TARBALL_SCAN_MAX_BYTES,
        timeout_seconds=timeout_seconds,
    )


from .package_eval_lockfile_versions import _lockfile_dependency_versions  # noqa: E402, F401
from .package_eval_lockfile_versions import _manifest_direct_dependency_names  # noqa: E402, F401
from .package_eval_lockfile_versions import _manifest_dependency_versions  # noqa: E402, F401
from .package_eval_lockfile_versions import _artifact_manifest_dependency_map  # noqa: E402, F401
from .package_eval_lockfile_versions import _package_lock_target_versions  # noqa: E402, F401
from .package_eval_lockfile_versions import _package_lock_target_versions_from_entries  # noqa: E402, F401
from .package_eval_lockfile_versions import _package_lock_entries, _walk_package_lock_entries  # noqa: E402, F401
from .package_eval_lockfile_versions import _package_lock_candidate_names  # noqa: E402, F401
from .package_eval_other_lockfiles import _cargo_lock_target_versions  # noqa: E402, F401
from .package_eval_other_lockfiles import _composer_lock_target_versions  # noqa: E402, F401
from .package_eval_other_lockfiles import _gemfile_lock_target_versions, _pnpm_lock_target_versions  # noqa: E402, F401
from .package_eval_other_lockfiles import _yarn_lock_target_versions  # noqa: E402, F401
from .package_eval_other_lockfiles import _yarn_lock_target_versions_from_entries  # noqa: E402, F401
from .package_eval_other_lockfiles import _expected_yarn_selectors, _bun_lock_target_versions  # noqa: E402, F401
from .package_eval_other_lockfiles import _poetry_lock_target_versions, _toml_lock_direct_versions  # noqa: E402, F401


_poetry_lock_direct_versions = _toml_lock_direct_versions
_uv_lock_direct_versions = _toml_lock_direct_versions


from .package_eval_other_lockfiles import _uv_lock_target_versions, _pipfile_lock_target_versions  # noqa: E402, F401
from .package_eval_other_lockfiles import _pipfile_lock_direct_versions  # noqa: E402, F401
from .package_eval_other_lockfiles import _target_versions_from_direct_map, _lockfile_target_key  # noqa: E402, F401
from .package_eval_other_lockfiles import _dependency_package_name  # noqa: E402, F401
from .package_eval_registry import _resolved_target_version, _registry_resolved_target_version  # noqa: E402, F401
from .package_eval_registry import _registry_package_name, _npm_registry_resolved_version  # noqa: E402, F401
from .package_eval_registry import _pypi_registry_resolved_version, _normalized_pypi_requested_range  # noqa: E402, F401
from .package_eval_registry import _pypi_caret_specifier, _pypi_tilde_specifier  # noqa: E402, F401
from .package_eval_bundle import _bundle_package_versions, _bundle_packages_for_target  # noqa: E402, F401
from .package_eval_bundle import _bundle_package_name_matches  # noqa: E402, F401
from .package_eval_results import _recommended_fix_allow_package_result  # noqa: E402, F401
from .package_eval_archives import _source_url_from_specifier, _source_url_from_raw_spec  # noqa: E402, F401
from .package_eval_lockfile_status import _safe_dependency_map_for_path  # noqa: E402, F401
from .package_eval_lockfile_status import _safe_dependency_map_result_for_path  # noqa: E402, F401
from .package_eval_lockfile_status import _lockfile_parse_warning_result  # noqa: E402, F401
from .package_eval_registry import _manifest_exact_version  # noqa: E402, F401
from .package_eval_values import _with_support_metadata, _with_package_reason  # noqa: E402, F401
from .package_eval_bundle import _matching_policy_rule, _bundle_package, _severity_rank_value  # noqa: E402, F401
from .package_eval_bundle import _normalize_bundle_action  # noqa: E402, F401
from .package_eval_values import _normalized_supply_chain_evaluate_url  # noqa: E402, F401
from .package_eval_evidence import _hash_paths, _stable_hash  # noqa: E402, F401
from .package_eval_values import _dict_items, _first_dict_item, _string_tuple  # noqa: E402, F401
from .package_eval_registry import _split_namespace_name, _npm_source_spec, _default_registry_range  # noqa: E402, F401
from .package_eval_registry import _requested_specifier_is_range  # noqa: E402, F401
from .package_eval_values import _optional_string, _decision_rank, _fix_command  # noqa: E402, F401
from .package_eval_values import _uses_uv_pip_install, _package_install_target  # noqa: E402, F401
from .package_eval_values import _package_display_name, _normalize_package_name  # noqa: E402, F401
from .package_eval_registry import _target_candidate_names, _python_lockfile_version  # noqa: E402, F401
from .package_eval_values import _reason_severity, _should_record_package  # noqa: E402, F401
from .package_eval_evidence import _evidence_id, _result_package_identity  # noqa: E402, F401
from .package_eval_values import _with_additional_reason  # noqa: E402, F401
from .package_eval_cloud_fallback import _cloud_result_should_defer_to_bundle  # noqa: E402, F401
from .package_eval_cloud_fallback import _cloud_fallback_reason  # noqa: E402, F401
from .package_eval_bundle import _emergency_deny_bundle_message, _bundle_reason_message  # noqa: E402, F401
from .package_eval_bundle import _bundle_package_label  # noqa: E402, F401
# isort: on
