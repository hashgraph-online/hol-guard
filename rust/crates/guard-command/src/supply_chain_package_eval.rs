//! Rust port of `runtime/supply_chain_package_eval.py` — local package-request
//! evaluation for HOL Guard supply-chain protection.
//!
//! TODO(deps): several Python dependencies are not yet ported to this crate.
//! They are modeled as injected seams (`SupplyChainEvalDeps`) or small local
//! ports kept byte-parity where cheap:
//!   - `supply_chain_support.ecosystem_support_metadata` — local port.
//!   - `text.ensure_terminal_punctuation` — local port.
//!   - `workspace_path_guard.{read_bytes_within_workspace,read_text_within_workspace,
//!     resolve_path_within_workspace}` — `resolve_path_within_workspace` reused
//!     from `package_intent_common`; the read wrappers are local ports.
//!   - `stable_digest.stable_digest_hex` — reused from `local_supply_chain`.
//!   - `action_lattice.normalize_guard_action_result` — reused.
//!   - `config.{load_guard_config,resolve_risk_action}` — `resolve_risk_action`
//!     reused; `load_guard_config` is a seam.
//!   - `native_archive_inspection.inspect_archive_native` — seam.
//!   - `package_firewall_entitlement.resolve_package_firewall_entitlement` — seam.
//!   - `store.GuardStore` — `local_supply_chain::SupplyChainStore` seam.
//!   - `store_evidence.EvidenceRecord` — `Value`-dict seam.
//!   - `js_semver.{highest_js_version_for_selector,version_matches_js_selector}` —
//!     seam (per-package policy resolution; not yet ported).
//!   - `lockfile_evaluation_support.*` / `lockfile_parse_result.*` — seam via
//!     `LockfileEvaluationApi`.
//!   - `manifest_dependency_targets.evaluation_targets` — seam.
//!   - `npm_policy_range.*` — seam via `NpmPolicyRangeApi`.
//!   - `npm_source_spec.NpmSourceSpec`/`parse_npm_source_spec` — reused from
//!     `npm_source_spec` module.
//!   - `restricted_archive_download.*` — `RestrictedArchiveDownload` seam +
//!     `ExternalArchiveDownloadApi` for the network path.
//!   - `supply_chain_bundle*.*` — `SupplyChainBundleResponse`/`…Package` seams +
//!     `SupplyChainBundleApi` for freshness/cached evaluation.
//!   - `supply_chain_package_identity.*` — local port (pure logic).
//!   - `subprocess` (bundled pip audit fallback) — `// TODO(deps): subprocess`
//!     fail-closed stub.
//!   - `urllib.request.urlopen` (cloud validation) — `CloudValidationApi` seam.
//!   - `importlib.metadata` (bundled pip detection) — `PipAuditShims` seam.
//!   - `guard_sync`/`resolved_receipt`/`evidence_store` — seams on the store or
//!     via `SupplyChainRuntimeApi`.
//!
//! serde_json::Map is a BTreeMap, so all emitted JSON maps are key-sorted by
//! construction — matching Python `dict` literal order only where byte-parity
//! requires `write_spaced_sorted_json`/`serde_json::to_string` compact paths.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};
use serde_json::{json, Map, Value};

use crate::action_lattice::{normalize_guard_action_result, UNKNOWN_GUARD_ACTION_REASON};
use crate::effect_decision::GuardAction;
use crate::local_supply_chain::{
    resolve_risk_action, stable_digest_hex, stable_digest_hex_len, GuardConfig, SupplyChainStore,
};
use crate::npm_source_spec::{parse_npm_source_spec, NpmSourceSpec};
use crate::package_intent_common::{
    resolve_path_within_workspace, split_python_extras, GuardArtifact,
};

#[path = "supply_chain_package_eval/contracts.rs"]
mod contracts;
use contracts::{
    decision_rank_map, decision_to_guard_action, dict_items, dist_tag_range_ecosystems,
    ensure_terminal_punctuation, json_obj, optional_string, registry_default_ranges,
    severity_rank_map, string_tuple, value_str, CLOUD_INBOX_URL_RE,
    EXTERNAL_ARCHIVE_MAX_AGGREGATE_BYTES, EXTERNAL_ARCHIVE_MAX_TARGETS,
    EXTERNAL_ARCHIVE_REQUEST_TIMEOUT_SECONDS, LOCAL_APPROVAL_INSTRUCTION_RE,
    LOCAL_APPROVAL_REQUEST_URL_RE, LOCAL_REVIEW_INSTRUCTION_RE, LOCKFILE_PARSE_BUDGET_SECONDS,
    NAMED_SOURCE_SEPARATOR_RE, RETRY_TIMEOUT_SECONDS, TARBALL_SCAN_MAX_BYTES,
    TARBALL_SCAN_MAX_FILES, TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES, TARBALL_SCAN_TIMEOUT_SECONDS,
    TIMEOUT_SECONDS,
};
#[path = "supply_chain_package_eval/result_models.rs"]
mod result_models;

pub use result_models::{PackageEvalResult, SupplyChainUserCopy};
#[path = "supply_chain_package_eval/service_contracts.rs"]
mod service_contracts;
pub use service_contracts::{
    EvalError, EvalResult, GuardSyncRequest, GuardSyncRunnerApi, LockfileDependencyEntry,
    LockfileParseApi, LockfileParseResult,
};
#[path = "supply_chain_package_eval/bundle_contracts.rs"]
mod bundle_contracts;
pub use bundle_contracts::{
    CanonicalPackageIdentity, JsSemverApi, ManifestDepsApi, PackageIdentityApi, RiskDetectApi,
    SpecifierSet, SupplyChainBundleApi, SupplyChainBundleResponse, Version,
};
#[path = "supply_chain_package_eval/runtime_contracts.rs"]
mod runtime_contracts;
pub use runtime_contracts::{
    ConfigLoaderApi, EntitlementRefreshApi, NativeArchiveApi, RestrictedArchiveApi,
    RestrictedArchiveDownload, RestrictedArchiveDownloadResult, RestrictedArchiveFailure,
    StoreExtrasApi, WorkspaceIoApi,
};
#[path = "supply_chain_package_eval/evaluation.rs"]
mod evaluation;
use evaluation::{
    artifact_has_flag, artifact_has_package_material, cache_reusable_cloud_validation_error,
    cached_eval_has_reason_code, cached_supply_chain_eval_is_reusable, decision_rank,
    decision_to_guard_action_variant, empty_package_material_result, normalize_package_name,
    parse_evaluation_timestamp, reason_severity, severity_rank_value,
};
pub use evaluation::{evaluate_package_request_artifact, EvaluationDraft, SupplyChainEvalDeps};
#[path = "supply_chain_package_eval/cache_retry.rs"]
mod cache_retry;

#[path = "supply_chain_package_eval/decisions.rs"]
mod decisions;

#[path = "supply_chain_package_eval/package_copy.rs"]
mod package_copy;
use package_copy::{
    evidence_id, fix_command, normalize_bundle_action, normalize_package_user_copy,
    package_display_name, result_package_identity, should_record_package, with_support_metadata,
};
#[path = "supply_chain_package_eval/finalization.rs"]
mod finalization;
use finalization::finalize_evaluation;
#[path = "supply_chain_package_eval/cloud_failures.rs"]
mod cloud_failures;
use cloud_failures::{
    cloud_fail_closed_decision, cloud_fail_closed_evaluation_full,
    cloud_fallback_requires_reconnect_copy, unidentified_package_decision,
    unidentified_packages_fail_closed,
};
#[path = "supply_chain_package_eval/bundle_evaluation.rs"]
mod bundle_evaluation;
use bundle_evaluation::evaluate_with_bundle;
#[path = "supply_chain_package_eval/advisory_aliases.rs"]
mod advisory_aliases;

#[path = "supply_chain_package_eval/heuristics.rs"]
mod heuristics;
use heuristics::heuristic_result;
#[path = "supply_chain_package_eval/evidence.rs"]
mod evidence;
use evidence::persist_evidence;
#[path = "supply_chain_package_eval/targets.rs"]
mod targets;
use targets::{cloud_evaluation_targets, evaluation_targets, sha256_hex};
#[path = "supply_chain_package_eval/target_integrity.rs"]
mod target_integrity;
use target_integrity::{
    bundle_meta, private_package_targets_match_public, public_package_targets_are_self_consistent,
};
#[path = "supply_chain_package_eval/lockfile_evidence.rs"]
mod lockfile_evidence;
use lockfile_evidence::{
    finalize_incomplete_lockfile_evaluation, first_incomplete_lockfile_result,
    lockfile_parse_results, parse_lockfile_text_result,
};
#[path = "supply_chain_package_eval/request_payload.rs"]
mod request_payload;
use request_payload::{build_request_payload, workspace_fingerprint};
#[path = "supply_chain_package_eval/package_resolution.rs"]
mod package_resolution;
use package_resolution::{
    bundle_package, bundle_package_label, exact_version, hash_paths, lockfile_target_key,
    npm_source_spec, optional_string_map, policy_rule_get_str, registry_resolved_target_version,
    resolved_target_version, split_namespace_name, stable_hash, value_to_plain_string,
};
#[path = "supply_chain_package_eval/bundle_policy.rs"]
mod bundle_policy;
use bundle_policy::{
    bind_resolved_npm_policy_result, dependency_confusion_policy_package_result,
    emergency_deny_bundle_message, matching_policy_rule, policy_package_result,
    target_for_resolved_npm_policy_match,
};
#[path = "supply_chain_package_eval/package_results.rs"]
mod package_results;
use package_results::{
    heuristic_package_result, lockfile_dependency_versions, package_target_result,
    target_is_external_https_archive, transitive_lockfile_results,
};
#[path = "supply_chain_package_eval/archive_dependencies.rs"]
mod archive_dependencies;
use archive_dependencies::external_tarball_dependency_result;
#[path = "supply_chain_package_eval/fallbacks.rs"]
mod fallbacks;
use fallbacks::{
    block_package_from_offline, bundle_package_result, cloud_fallback_reason,
    cloud_result_should_defer_to_bundle, incomplete_lockfile_fallback_target, lockfile_ecosystem,
    lockfile_parse_warning_result, python_lockfile_version, target_candidate_names,
};
#[path = "supply_chain_package_eval/version_selectors.rs"]
mod version_selectors;
use version_selectors::{direct_lockfile_version, target_versions_from_direct_map};
#[path = "supply_chain_package_eval/manifest_versions.rs"]
mod manifest_versions;
use manifest_versions::{
    manifest_exact_version, requested_specifier_is_range, with_package_reason,
};
#[path = "supply_chain_package_eval/lockfile_helpers.rs"]
mod lockfile_helpers;
use lockfile_helpers::{
    monotonic_seconds, normalized_supply_chain_evaluate_url, safe_dependency_map_result_for_path,
};
#[path = "supply_chain_package_eval/package_lock.rs"]
mod package_lock;

#[path = "supply_chain_package_eval/manifest_dependencies.rs"]
mod manifest_dependencies;

#[path = "supply_chain_package_eval/pnpm_lock.rs"]
mod pnpm_lock;

#[path = "supply_chain_package_eval/yarn_bun_lock.rs"]
mod yarn_bun_lock;

#[path = "supply_chain_package_eval/python_lock.rs"]
mod python_lock;

#[path = "supply_chain_package_eval/source_identity.rs"]
mod source_identity;
use source_identity::{is_git_source_url, FIRST_PARTY_PYPI_PACKAGES};
#[path = "supply_chain_package_eval/local_projects.rs"]
mod local_projects;
use local_projects::{
    local_python_project_path, manifest_package_name, own_package_name, py_partition,
    python_setup_script_looks_suspicious,
};
#[path = "supply_chain_package_eval/package_outcomes.rs"]
mod package_outcomes;
use package_outcomes::{
    homebrew_package_monitor_result, installed_release_reinstall_result,
    local_source_dependency_result, system_package_monitor_result, unknown_package_result,
    unsupported_ecosystem_result,
};
#[path = "supply_chain_package_eval/cloud_packages.rs"]
mod cloud_packages;
use cloud_packages::{
    bun_lockfile_binary_fallback_packages, command_uses_alternate_package_index,
    package_from_cloud_result,
};
#[path = "supply_chain_package_eval/local_manifests.rs"]
mod local_manifests;
use local_manifests::{local_package_manifest_result, local_python_build_result};
#[path = "supply_chain_package_eval/go_sources.rs"]
mod go_sources;
use go_sources::{go_replace_result, target_requires_npm_source_review};
#[path = "supply_chain_package_eval/archive_scanning.rs"]
mod archive_scanning;

#[path = "supply_chain_package_eval/fallback_packages.rs"]
mod fallback_packages;
use fallback_packages::{
    fallback_package_results, with_additional_reason_result, with_cloud_auth_reconnect_copy_result,
};
#[path = "supply_chain_package_eval/cloud_transport.rs"]
mod cloud_transport;
use cloud_transport::{
    cloud_http_fail_closed_evaluation_full, fetch_package_evaluation_response,
    resolve_guard_sync_context,
};
#[path = "supply_chain_package_eval/cloud_evaluation.rs"]
mod cloud_evaluation;
use cloud_evaluation::evaluate_with_cloud;
#[path = "supply_chain_package_eval/orchestration.rs"]
mod orchestration;
use orchestration::evaluate_package_request_artifact_uncached;
#[path = "supply_chain_package_eval/source_review.rs"]
mod source_review;
use source_review::evaluate_non_registry_sources;
#[path = "supply_chain_package_eval/draft_conversion.rs"]
mod draft_conversion;
use draft_conversion::evaluation_to_draft;

use contracts::LOCAL_REVIEW_INSTRUCTION;
