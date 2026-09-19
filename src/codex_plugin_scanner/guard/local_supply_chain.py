"""Shared local supply-chain posture and CLI helpers."""

from __future__ import annotations

import hashlib  # noqa: F401
import importlib
import inspect  # noqa: F401
import json  # noqa: F401
import os  # noqa: F401
import shlex  # noqa: F401
import socket  # noqa: F401
import stat  # noqa: F401
import subprocess  # noqa: F401
import threading
import time  # noqa: F401
import urllib.error
import urllib.parse
import urllib.request  # noqa: F401
from collections.abc import Callable, Mapping, Sequence  # noqa: F401
from contextlib import suppress  # noqa: F401
from dataclasses import dataclass, field, replace  # noqa: F401
from datetime import datetime, timedelta, timezone  # noqa: F401
from pathlib import Path
from typing import Any, Literal, TypeGuard, cast  # noqa: F401
from uuid import uuid4  # noqa: F401

from codex_plugin_scanner.path_support import resolve_path_within_allowed_roots, resolves_within_root  # noqa: F401

from .action_lattice import most_restrictive_guard_action, normalize_guard_action  # noqa: F401
from .adapters.base import HarnessContext  # noqa: F401
from .advisory_model import ProtectTargetIdentity, advisory_matches_target, build_package_url  # noqa: F401
from .approval_scope_support import package_request_runtime_workspace_scope  # noqa: F401
from .cloud_audit_request import build_cloud_workspace_audit_request  # noqa: F401
from .config import GuardConfig, resolve_risk_action  # noqa: F401
from .mdm.network import managed_urlopen  # noqa: F401
from .models import GuardAction, GuardArtifact
from .package_execution_context import PackageExecutionContext, build_package_execution_context  # noqa: F401
from .redaction import redact_local_path, redact_text  # noqa: F401
from .runtime.approval_context import (
    approval_context_tokens_validation_reason,  # noqa: F401
    build_approval_context_token,  # noqa: F401
    build_runtime_launch_identity,  # noqa: F401
    parse_approval_context_token,  # noqa: F401
    resolved_runtime_launch_argv,  # noqa: F401
    runtime_launch_identity_is_reusable,  # noqa: F401
)
from .runtime.approval_context import (
    saved_allow_context_validation_reason as package_saved_allow_validation_reason,  # noqa: F401
)
from .runtime.approval_reuse import (
    APPROVAL_REUSE_CLAIM_FAILED,  # noqa: F401
    APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,  # noqa: F401
    ApprovalReuseDecision,  # noqa: F401
    ApprovalReuseValidationFailure,  # noqa: F401
    evaluate_approval_reuse,  # noqa: F401
)
from .runtime.lockfile_parse_result import LOCKFILE_PARSER_VERSION  # noqa: F401
from .runtime.package_execution_policy import is_execution_permitted  # noqa: F401
from .runtime.package_intent_common import (
    PackageIntent,
    PackageIntentTarget,  # noqa: F401
    build_package_request_artifact,  # noqa: F401
    composer_target,  # noqa: F401
    coordinate_target,  # noqa: F401
    existing_relative_paths,  # noqa: F401
    js_target,  # noqa: F401
    python_target,  # noqa: F401
    redact_package_request_token,  # noqa: F401
    version_target,  # noqa: F401
)
from .runtime.package_manifest_diff import parse_manifest_dependencies, parse_manifest_dependency_changes  # noqa: F401
from .runtime.package_protect_projection import (
    LOCAL_SUPPLY_CHAIN_HARNESS as _LOCAL_SUPPLY_CHAIN_HARNESS,  # noqa: F401
)
from .runtime.package_protect_projection import (
    PackageProtectProjection as _PackageProtectProjection,  # noqa: F401
)
from .runtime.package_protect_projection import (
    PackageProtectVerdictContext,  # noqa: F401
)
from .runtime.package_protect_projection import (
    build_package_guard_receipt as _build_guard_receipt,  # noqa: F401
)
from .runtime.package_protect_projection import (
    protect_target_payload as _protect_target_payload,  # noqa: F401
)
from .runtime.package_protect_projection import (
    resolve_local_supply_chain_harness as _resolve_local_supply_chain_harness,
)
from .runtime.restricted_archive_download import RestrictedArchiveDownload  # noqa: F401
from .runtime.supply_chain_support import ecosystem_support_matrix  # noqa: F401
from .runtime.workspace_path_guard import (
    read_bytes_within_workspace,  # noqa: F401
    read_text_within_workspace,  # noqa: F401
    resolve_path_within_workspace,  # noqa: F401
)
from .shims import package_shim_dashboard_status, package_shim_supported_managers  # noqa: F401
from .stable_digest import stable_digest_hex  # noqa: F401
from .store import GuardStore  # noqa: F401

# Preserve the original dependency import order before loading function owners.
# Imports marked F401 remain live facade dependencies for these owners.
# isort: split
from . import local_supply_chain_advisories as _advisories
from . import local_supply_chain_archive_binding as _archive_binding
from . import local_supply_chain_audit_discovery as _audit_discovery
from . import local_supply_chain_audit_evaluation as _audit_evaluation
from . import local_supply_chain_audit_receipts as _audit_receipts
from . import local_supply_chain_cloud_audit as _cloud_audit
from . import local_supply_chain_cloud_requests as _cloud_requests
from . import local_supply_chain_cloud_sync as _cloud_sync
from . import local_supply_chain_inventory as _inventory
from . import local_supply_chain_policy_evaluation as _policy_evaluation
from . import local_supply_chain_policy_identity as _policy_identity
from . import local_supply_chain_posture as _posture
from . import local_supply_chain_protect_authority as _protect_authority
from . import local_supply_chain_protect_execution as _protect_execution
from . import local_supply_chain_protect_projection as _protect_projection
from . import local_supply_chain_stored_policy as _stored_policy
from . import local_supply_chain_values as _values

_MANIFEST_CANDIDATES = (
    "package.json",
    "requirements.txt",
    "constraints.txt",
    "pyproject.toml",
    "Pipfile",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
)
_LOCKFILE_CANDIDATES = (
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "gradle.lockfile",
    "composer.lock",
    "Gemfile.lock",
)
_WORKSPACE_AUDIT_DISCOVERY_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        "dist",
        "build",
        ".next",
        "target",
        ".guard",
        ".worktrees",
        "worktrees",
    }
)
_WORKSPACE_AUDIT_DISCOVERY_MAX_DEPTH = 3
_MANIFEST_CANDIDATE_SET = frozenset(_MANIFEST_CANDIDATES)
_LOCKFILE_CANDIDATE_SET = frozenset(_LOCKFILE_CANDIDATES)
_INFORMATIONAL_REASON_CODES = frozenset({"unknown_package", "no_cached_match"})
_PACKAGE_MANAGER_BY_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "pip",
    "cargo": "cargo",
    "go": "go",
    "maven": "maven",
    "packagist": "composer",
    "rubygems": "bundle",
    "docker": "docker",
    "system": "system",
    "unsupported": "unsupported",
}
_ECOSYSTEM_BY_MANIFEST = {
    "package.json": "npm",
    "requirements.txt": "pypi",
    "constraints.txt": "pypi",
    "pyproject.toml": "pypi",
    "Pipfile": "pypi",
    "Cargo.toml": "cargo",
    "go.mod": "go",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "composer.json": "packagist",
    "Gemfile": "rubygems",
}
_DEFAULT_BUNDLE_REFRESH_INTERVAL_SECONDS = 15 * 60
_STALE_REFRESH_GRACE_SECONDS = 5 * 60
_CLOUD_AUDIT_TIMEOUT_SECONDS = 20
_CLOUD_AUDIT_PAGE_SIZE = 500
_CLOUD_AUDIT_MAX_PAGES = 100
_CLOUD_AUDIT_JOB_PAGE_SIZE = 1
_CLOUD_AUDIT_JOB_POLL_INTERVAL_SECONDS = 0.5
_CLOUD_AUDIT_JOB_POLL_TIMEOUT_SECONDS = 20
_CLOUD_AUDIT_SYNC_PAGE_SIZE = 25
_MAX_SBOM_BYTES = 10 * 1024 * 1024
_ECOSYSTEM_BY_LOCKFILE = {
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "npm",
    "yarn.lock": "npm",
    "bun.lock": "npm",
    "bun.lockb": "npm",
    "poetry.lock": "pypi",
    "uv.lock": "pypi",
    "Pipfile.lock": "pypi",
    "Cargo.lock": "cargo",
    "go.sum": "go",
    "gradle.lockfile": "maven",
    "composer.lock": "packagist",
    "Gemfile.lock": "rubygems",
}
_ECOSYSTEM_BY_PURL = {
    "cargo": "cargo",
    "composer": "packagist",
    "gem": "rubygems",
    "golang": "go",
    "maven": "maven",
    "npm": "npm",
    "pypi": "pypi",
}
_SEVERITY_RANK = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS = 300.0
_PACKAGE_FIREWALL_REFRESH_STATE_FILE = "package-firewall-refresh.json"
_PACKAGE_FIREWALL_REFRESH_LOCK = threading.Lock()
_AUDIT_SENSITIVE_BASENAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.test",
        ".envrc",
    }
)
_KNOWN_UNSUPPORTED_LOCKFILE_BASENAMES = frozenset({"bun.lockb"})


def _runtime_runner_module():
    return importlib.import_module(".runtime.runner", __package__)


_LAZY_RUNTIME_RUNNER_EXPORTS = frozenset(
    {
        "GuardSyncAuthorizationExpiredError",
        "GuardSyncNotAvailableError",
        "GuardSyncNotConfiguredError",
    }
)


def __getattr__(name: str) -> Any:
    if name in _LAZY_RUNTIME_RUNNER_EXPORTS:
        return getattr(_runtime_runner_module(), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _package_firewall_entitlement_module():
    return importlib.import_module(".package_firewall_entitlement", __package__)


def _package_intent_parser_module():
    return importlib.import_module(".runtime.package_intent_parser", __package__)


def _supply_chain_package_eval_module():
    return importlib.import_module(".runtime.supply_chain_package_eval", __package__)


sync_local_guard_cloud_proof = _posture.sync_local_guard_cloud_proof
sync_supply_chain_bundle = _posture.sync_supply_chain_bundle
_resolve_guard_sync_auth_context = _posture._resolve_guard_sync_auth_context
evaluate_package_request_artifact = _posture.evaluate_package_request_artifact
_is_package_request_evaluation = _posture._is_package_request_evaluation
_package_firewall_refresh_state_path = _posture._package_firewall_refresh_state_path
_read_package_firewall_refresh_state = _posture._read_package_firewall_refresh_state
_write_package_firewall_refresh_state = _posture._write_package_firewall_refresh_state
build_local_supply_chain_posture = _posture.build_local_supply_chain_posture
build_supply_chain_status_payload = _posture.build_supply_chain_status_payload
_call_sync_with_optional_auth_context = _posture._call_sync_with_optional_auth_context
resolve_package_firewall_entitlement_with_refresh = _posture.resolve_package_firewall_entitlement_with_refresh
_is_audit_sensitive_basename = _audit_discovery._is_audit_sensitive_basename
_read_workspace_audit_text = _audit_discovery._read_workspace_audit_text
_workspace_has_project_markers = _audit_discovery._workspace_has_project_markers
managed_install_audit_workspace_dirs = _audit_discovery.managed_install_audit_workspace_dirs
_managed_workspace_audit_candidates = _audit_discovery._managed_workspace_audit_candidates
resolve_supply_chain_audit_workspace_dir = _audit_discovery.resolve_supply_chain_audit_workspace_dir
_audit_lockfile_warnings = _audit_discovery._audit_lockfile_warnings
_package_advisory_ids = _advisories._package_advisory_ids
_cached_supply_chain_bundle_payload = _advisories._cached_supply_chain_bundle_payload
_resolve_advisory_aliases_from_bundle = _advisories._resolve_advisory_aliases_from_bundle
_enrich_package_with_advisory_aliases = _advisories._enrich_package_with_advisory_aliases
_enrich_evaluation_packages_with_advisory_aliases = _advisories._enrich_evaluation_packages_with_advisory_aliases
_package_reason_codes = _advisories._package_reason_codes
_is_actionable_package_finding = _advisories._is_actionable_package_finding
_audit_package_inventory_for_receipt = _audit_receipts._audit_package_inventory_for_receipt
_audit_package_findings_for_receipt = _audit_receipts._audit_package_findings_for_receipt
workspace_audit_path_hashes = _audit_receipts.workspace_audit_path_hashes
_resolve_empty_audit_outcome = _audit_receipts._resolve_empty_audit_outcome
_incomplete_audit_receipt_metadata = _audit_receipts._incomplete_audit_receipt_metadata
audit_receipt_metadata = _audit_receipts.audit_receipt_metadata
build_workspace_scan_payload = _audit_evaluation.build_workspace_scan_payload
build_workspace_audit_payload = _audit_evaluation.build_workspace_audit_payload
_workspace_local_evaluation = _audit_evaluation._workspace_local_evaluation
build_supply_chain_explain_payload = _audit_evaluation.build_supply_chain_explain_payload


@dataclass(frozen=True, slots=True)
class _PackageProtectAuthority:
    intent: PackageIntent
    artifact: GuardArtifact
    evaluation: Any
    current_action: GuardAction
    execution_context: PackageExecutionContext
    artifact_hash: str
    launch_identity: dict[str, object]
    launch_cwd: Path
    launch_environment: Mapping[str, str]
    additional_current_action: object | None
    additional_policy_context: dict[str, object] | None
    observe_mode: bool
    invoking_harness: str = field(default_factory=_resolve_local_supply_chain_harness)


_PackageApprovalClaimDisposition = Literal["consumed", "retained"]


@dataclass(frozen=True, slots=True)
class _StoredPackagePolicyResolution:
    evaluation: Any
    approval_reuse_decision: Mapping[str, object] | None = None
    claim_disposition: _PackageApprovalClaimDisposition | None = None


_external_archive_downloads = _archive_binding._external_archive_downloads
_cleanup_external_archive_downloads = _archive_binding._cleanup_external_archive_downloads
_package_evaluation_requires_external_archive_binding = (
    _archive_binding._package_evaluation_requires_external_archive_binding
)
_verified_external_archive_replacements = _archive_binding._verified_external_archive_replacements
_bound_external_archive_launch_command = _archive_binding._bound_external_archive_launch_command
_package_manager_launch_environment = _archive_binding._package_manager_launch_environment
_build_package_protect_authority = _protect_authority._build_package_protect_authority
_final_package_protect_authority = _protect_authority._final_package_protect_authority
_package_execution_policy_action = _protect_authority._package_execution_policy_action
_package_protect_verdict_context = _protect_authority._package_protect_verdict_context
_apply_package_protect_projection = _protect_projection._apply_package_protect_projection
_install_time_event_payload = _protect_projection._install_time_event_payload
_package_protect_denied_after_final_boundary = _protect_projection._package_protect_denied_after_final_boundary
build_package_protect_payload = _protect_execution.build_package_protect_payload
apply_stored_package_policy_override = _stored_policy.apply_stored_package_policy_override
_apply_stored_package_policy_override = _stored_policy._apply_stored_package_policy_override
_resolve_stored_package_policy_override = _stored_policy._resolve_stored_package_policy_override
_is_fresh_artifact_approval = _stored_policy._is_fresh_artifact_approval
_is_durable_exact_artifact_approval = _stored_policy._is_durable_exact_artifact_approval
_is_legacy_package_local_approval = _stored_policy._is_legacy_package_local_approval
_package_evaluation_with_current_policy_action = _policy_evaluation._package_evaluation_with_current_policy_action
_package_evaluation_with_rejected_reuse = _policy_evaluation._package_evaluation_with_rejected_reuse
_approval_reuse_reason_message = _policy_evaluation._approval_reuse_reason_message
_package_decision_for_action = _policy_evaluation._package_decision_for_action
_package_policy_workspace_candidates = _policy_evaluation._package_policy_workspace_candidates
_stored_package_policy_is_stale_policy_bundle_family = (
    _policy_evaluation._stored_package_policy_is_stale_policy_bundle_family
)
_stored_package_policy_evaluation_requires_review = _policy_evaluation._stored_package_policy_evaluation_requires_review
_saved_package_policy_clear_command = _policy_evaluation._saved_package_policy_clear_command
recompute_package_protect_artifact_hash = _policy_identity.recompute_package_protect_artifact_hash
_package_target_identities = _policy_identity._package_target_identities
_package_matched_cached_advisory_ids = _policy_identity._package_matched_cached_advisory_ids
_package_feed_snapshot_hash = _policy_identity._package_feed_snapshot_hash
_package_policy_gate_context = _policy_identity._package_policy_gate_context
_package_config_policy_context = _policy_identity._package_config_policy_context
compose_current_package_policy_action = _policy_identity.compose_current_package_policy_action
_package_current_policy_context = _policy_identity._package_current_policy_context
_package_request_artifact_hash = _policy_identity._package_request_artifact_hash
_package_launch_approval_identity = _policy_identity._package_launch_approval_identity
_package_approval_identity = _policy_identity._package_approval_identity
package_request_policy_hash = _policy_identity.package_request_policy_hash
_evaluation_uses_saved_package_approval = _policy_evaluation._evaluation_uses_saved_package_approval
_package_approval_reuse_evidence = _policy_evaluation._package_approval_reuse_evidence
_package_policy_override_evaluation = _policy_evaluation._package_policy_override_evaluation
redacted_command_tokens = _protect_projection.redacted_command_tokens
_build_command_execution_payload = _protect_projection._build_command_execution_payload
_coerce_command_output = _protect_projection._coerce_command_output
_coerce_command_error_output = _protect_projection._coerce_command_error_output
_build_package_manager_protection = _posture._build_package_manager_protection
_workspace_scan_intent = _audit_evaluation._workspace_scan_intent
_discover_workspace_audit_paths = _audit_discovery._discover_workspace_audit_paths
_workspace_files = _audit_discovery._workspace_files
_targets_from_workspace_manifests = _inventory._targets_from_workspace_manifests
_workspace_audit_inventory = _inventory._workspace_audit_inventory
_workspace_diff_audit_inventory = _inventory._workspace_diff_audit_inventory
_workspace_inventory_from_paths = _inventory._workspace_inventory_from_paths
_merge_inventory_item = _inventory._merge_inventory_item
_inventory_key = _inventory._inventory_key
_split_namespace_name = _inventory._split_namespace_name
_target_from_inventory_item = _inventory._target_from_inventory_item
_resolve_sbom_paths = _inventory._resolve_sbom_paths
_inventory_from_sbom_text = _inventory._inventory_from_sbom_text
_read_sbom_text = _inventory._read_sbom_text
_inventory_from_cyclonedx = _inventory._inventory_from_cyclonedx
_inventory_from_spdx = _inventory._inventory_from_spdx
_inventory_item_from_sbom_component = _inventory._inventory_item_from_sbom_component
_inventory_from_purl = _inventory._inventory_from_purl
_should_use_cloud_workspace_audit = _cloud_audit._should_use_cloud_workspace_audit
_run_cloud_workspace_audit = _cloud_audit._run_cloud_workspace_audit
_codebase_label_from_remote = _cloud_audit._codebase_label_from_remote
_read_git_origin_codebase = _cloud_audit._read_git_origin_codebase
_safe_machine_name = _cloud_audit._safe_machine_name
_redacted_workspace_folder_path = _cloud_audit._redacted_workspace_folder_path
_build_workspace_context_payload = _cloud_audit._build_workspace_context_payload
_build_cloud_audit_payload = _cloud_audit._build_cloud_audit_payload
_execute_cloud_workspace_audit_request = _cloud_requests._execute_cloud_workspace_audit_request
_normalized_supply_chain_batch_job_url = _cloud_requests._normalized_supply_chain_batch_job_url
_enqueue_cloud_workspace_audit_job = _cloud_requests._enqueue_cloud_workspace_audit_job
_poll_cloud_workspace_audit_job = _cloud_requests._poll_cloud_workspace_audit_job
_workspace_audit_lockfile_context = _cloud_sync._workspace_audit_lockfile_context
_workspace_audit_fingerprint = _cloud_sync._workspace_audit_fingerprint
_hash_existing_paths = _cloud_sync._hash_existing_paths
_normalize_cloud_audit_response = _cloud_sync._normalize_cloud_audit_response
_ci_gate_result = _cloud_sync._ci_gate_result
_package_severity_rank = _cloud_sync._package_severity_rank
_inventory_summary = _cloud_sync._inventory_summary
_normalized_supply_chain_batch_url = _cloud_requests._normalized_supply_chain_batch_url
sync_managed_workspace_audits = _cloud_sync.sync_managed_workspace_audits
sync_supply_chain_cloud_state = _cloud_sync.sync_supply_chain_cloud_state
_target_from_manifest_dependency = _audit_discovery._target_from_manifest_dependency
_target_for_package_spec = _audit_discovery._target_for_package_spec
_package_manager_for_scan = _audit_discovery._package_manager_for_scan
_evaluation_exit_code = _protect_projection._evaluation_exit_code
_package_execution_exit_code = _protect_projection._package_execution_exit_code
_protect_action_for_policy_action = _protect_projection._protect_action_for_policy_action
_evaluation_risk_signals = _protect_projection._evaluation_risk_signals
_matched_advisories = _protect_projection._matched_advisories
_redact_command_token = _protect_projection._redact_command_token
_posture_status = _posture._posture_status
_posture_detail = _posture._posture_detail
_posture_health_status = _posture._posture_health_status
_resolve_next_refresh_at = _posture._resolve_next_refresh_at
_dict_payload = _values._dict_payload
_dict_items = _values._dict_items
_string_items = _values._string_items
_string_value = _values._string_value
_int_value = _values._int_value
_parse_timestamp = _values._parse_timestamp
