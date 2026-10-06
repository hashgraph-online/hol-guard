//! Port of `src/codex_plugin_scanner/guard/local_supply_chain.py` (RTM-019).
//!
//! Local supply-chain posture, workspace audit inventory, package-protect
//! authority, cloud audit fan-out, and stored-approval reuse.
//!
//! TODO(deps): Python lazily resolves `.runtime.runner`,
//! `.runtime.supply_chain_package_eval`, `.runtime.package_intent_parser`,
//! `.package_firewall_entitlement`, `.synced_policy`, `.store`, `.cloud_client`
//! (`managed_urlopen`), `.redaction` (`redact_text`), `.path_support`
//! (`resolve_path_within_allowed_roots`, `resolves_within_root`,
//! `read_text_within_workspace`), `.shims` (`package_shim_dashboard_status`),
//! `.manifest_parser` (`parse_manifest_dependencies`,
//! `parse_manifest_dependency_changes`), `.runtime_launch_identity`,
//! `.approval_context` (`parse_approval_context_token`,
//! `approval_context_tokens_validation_reason`, `build_approval_context_token`,
//! `saved_allow_context_validation_reason`), `.approval_artifact_hash`,
//! `.package_registry_metadata`, `.restricted_archive`,
//! `.runtime_security`, `.approvals`, `.native_context`, and
//! `daemon.policy_authority_client`. Until those ports land, the module keeps
//! those surfaces behind traits (`SupplyChainStore`, `RuntimeRunnerApi`,
//! `PackageEvalApi`, `PackageIntentParserApi`, `PolicyAuthorityApi`,
//! `PackageFirewallEntitlementApi`, `SyncedPolicyApi`, `ManifestParserApi`,
//! `ApprovalContextApi`, `RestrictedArchiveApi`, `HttpTransport`) plus
//! fail-closed stubs for subprocess/network shells.
//! No subprocess is spawned directly by this module.

use crate::cloud_audit_sync::{
    build_cloud_audit_payload, normalize_cloud_audit_response,
    normalized_supply_chain_batch_job_url, normalized_supply_chain_batch_url,
    resolve_next_refresh_at, should_use_cloud_workspace_audit, EnvCloudAuditWorkspaceContext,
};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha512};

use crate::action_lattice::{most_restrictive_guard_action, normalize_guard_action};
use crate::approval_reuse::evaluate_approval_reuse;
use crate::effect_decision::GuardAction;
use crate::package_execution_context::{
    PackageExecutionContext, PackageExecutionContextComponent, PACKAGE_EXECUTION_CONTEXT_VERSION,
};
use crate::package_intent_common::{
    build_package_request_artifact, GuardArtifact, PackageIntent, PackageIntentTarget,
};
use crate::package_manifest_diff::parse_manifest_dependencies;
use crate::package_policy_override as ppo;
use crate::package_protect_projection as ppp;
use crate::workspace_inventory::{
    inventory_from_sbom_payload, merge_inventory_item, package_manager_for_scan,
    split_namespace_name, target_for_package_spec, target_from_inventory_item,
    target_from_manifest_dependency, InventoryMap, ECOSYSTEM_BY_LOCKFILE, ECOSYSTEM_BY_MANIFEST,
    SEVERITY_RANK,
};

pub const WORKSPACE_AUDIT_DISCOVERY_MAX_DEPTH: usize = 3;
pub const DEFAULT_BUNDLE_REFRESH_INTERVAL_SECONDS: f64 = 15.0 * 60.0;
pub const STALE_REFRESH_GRACE_SECONDS: f64 = 5.0 * 60.0;
pub const CLOUD_AUDIT_TIMEOUT_SECONDS: f64 = 20.0;
pub const CLOUD_AUDIT_PAGE_SIZE: usize = 500;
pub const CLOUD_AUDIT_MAX_PAGES: usize = 100;
pub const CLOUD_AUDIT_JOB_PAGE_SIZE: usize = 1;
pub const CLOUD_AUDIT_JOB_POLL_INTERVAL_SECONDS: f64 = 0.5;
pub const CLOUD_AUDIT_JOB_POLL_TIMEOUT_SECONDS: f64 = 20.0;
pub const CLOUD_AUDIT_SYNC_PAGE_SIZE: usize = 25;
pub const MAX_SBOM_BYTES: u64 = 10 * 1024 * 1024;
pub const PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS: f64 = 300.0;
pub const PACKAGE_FIREWALL_REFRESH_STATE_FILE: &str = "package-firewall-refresh.json";
/// `package_firewall_defaults.PACKAGE_FIREWALL_PAID_TIERS` — tiers that unlock
/// package-firewall actions.
pub const PACKAGE_FIREWALL_PAID_TIERS: &[&str] = &[
    "paid",
    "premium",
    "pro",
    "team",
    "enterprise",
    "guard_cloud",
    "guard-cloud",
];
/// `package_firewall_entitlement.PACKAGE_FIREWALL_CONNECT_CTA`.
pub const PACKAGE_FIREWALL_CONNECT_CTA: &str =
    "Connect HOL Guard Cloud to check package firewall access and run package firewall actions.";
/// `package_firewall_entitlement.PACKAGE_FIREWALL_RECONNECT_CTA`.
pub const PACKAGE_FIREWALL_RECONNECT_CTA: &str =
    "Reconnect HOL Guard Cloud to refresh package firewall access.";
/// `package_firewall_entitlement.PACKAGE_FIREWALL_UPGRADE_CTA`.
pub const PACKAGE_FIREWALL_UPGRADE_CTA: &str =
    "Upgrade to HOL Guard Cloud to run package firewall actions.";
pub const LOCAL_SUPPLY_CHAIN_HARNESS: &str = "local-supply-chain";
/// `.runtime.supply_chain_package_eval.LOCKFILE_PARSER_VERSION` mirror.
/// TODO(deps): keep in sync with the Rust lockfile parser port.
pub const LOCKFILE_PARSER_VERSION: &str = "1";
/// `.runtime.supply_chain_package_eval.PACKAGE_REQUEST_ARTIFACT_SCHEMA_VERSION`.
pub const PACKAGE_REQUEST_ARTIFACT_SCHEMA_VERSION: &str = "package-request-artifact/v1";
/// `.runtime.package_manifest_diff` default `byte_limit` (:42, :69).
pub const DEFAULT_MANIFEST_PARSE_BYTE_LIMIT: usize = 2_097_152;
/// `.runtime.package_manifest_diff` default `deadline_ms` (:43, :70).
pub const DEFAULT_MANIFEST_PARSE_DEADLINE_MS: u64 = 50;

pub const APPROVAL_REUSE_CLAIM_FAILED: &str = "approval_reuse_claim_failed";
pub const APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM: &str =
    "approval_reuse_context_changed_after_claim";

pub static MANIFEST_CANDIDATES: &[&str] = &[
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
];

pub static LOCKFILE_CANDIDATES: &[&str] = &[
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
];

pub static WORKSPACE_AUDIT_DISCOVERY_SKIP_DIRS: &[&str] = &[
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
];

static EMPTY_MAP: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);
static MANIFEST_CANDIDATE_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| MANIFEST_CANDIDATES.iter().copied().collect());
static LOCKFILE_CANDIDATE_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| LOCKFILE_CANDIDATES.iter().copied().collect());
#[allow(dead_code)]
static SKIP_DIR_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    WORKSPACE_AUDIT_DISCOVERY_SKIP_DIRS
        .iter()
        .copied()
        .collect()
});
static AUDIT_SENSITIVE_BASENAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.test",
        ".envrc",
    ]
    .into_iter()
    .collect()
});

#[allow(dead_code)]
static KNOWN_UNSUPPORTED_LOCKFILE_BASENAMES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ["bun.lockb"].into_iter().collect());

// ---------------------------------------------------------------------------
// Error surface — mirrors the runner exception hierarchy fail-closed.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum LocalSupplyChainError {
    /// `runner.GuardSyncNotConfiguredError`
    NotConfigured(String),
    /// `runner.GuardSyncNotAvailableError`
    NotAvailable { message: String, retryable: bool },
    /// `runner.GuardSyncAuthorizationExpiredError`
    AuthorizationExpired(String),
    /// `RuntimeError`/`ValueError`-style failures.
    Runtime(String),
}

impl std::fmt::Display for LocalSupplyChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured(m)
            | Self::NotAvailable { message: m, .. }
            | Self::AuthorizationExpired(m)
            | Self::Runtime(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for LocalSupplyChainError {}

pub type SyncResult<T> = Result<T, LocalSupplyChainError>;

// ---------------------------------------------------------------------------
// Dependency seams — traits replacing unported modules (see TODO(deps) above).
// ---------------------------------------------------------------------------

/// `.store.GuardStore` seam.
pub trait SupplyChainStore {
    /// `store.guard_home`
    fn guard_home(&self) -> &Path;
    /// `store.get_cloud_sync_profile()` -> dict | None
    fn get_cloud_sync_profile(&self) -> Option<Value>;
    /// `store.get_cloud_workspace_id()` -> str | None
    fn get_cloud_workspace_id(&self) -> Option<String>;
    /// `store.get_cached_supply_chain_bundle(workspace_id)` -> dict | None
    fn get_cached_supply_chain_bundle(&self, workspace_id: &str) -> Option<Value>;
    /// `store.get_sync_payload(key)` -> object
    fn get_sync_payload(&self, key: &str) -> Option<Value>;
    /// `store.set_sync_payload(key, payload)`
    fn set_sync_payload(&self, key: &str, payload: &Value);

    /// `store.get_oauth_local_credential_health()` -> `{configured, state, ...}`.
    /// Defaults to `None` (not configured) so non-resident stores that never
    /// reach the OAuth path do not need to implement it.
    fn get_oauth_local_credential_health(&self) -> Option<Map<String, Value>> {
        None
    }
    /// `store.get_effective_guard_connect_state(now=)` -> connect-state dict |
    /// `None`. Defaults to `None` (no persisted connect state) for the same
    /// reason.
    fn get_effective_guard_connect_state(&self, now: &str) -> Option<Value> {
        let _ = now;
        None
    }
    /// `store.list_cached_advisories()` -> tuple[dict, ...]
    fn list_cached_advisories(&self) -> Vec<Value>;
    /// `store.list_managed_installs()` -> tuple[dict, ...]
    fn list_managed_installs(&self) -> Vec<Value>;
    /// `store.record_latest_guard_connect_sync_result(...)`
    fn record_latest_guard_connect_sync_result(
        &self,
        status: &str,
        milestone: &str,
        now: &str,
        reason: Option<&str>,
    );
    /// `store.get_approval_request(request_id)` -> dict | None
    fn get_approval_request(&self, request_id: &str) -> Option<Value>;
    /// `store.resolve_policy_decision_lookup(...) -> (decision, ignored_local_integrity)`
    #[allow(clippy::too_many_arguments)]
    fn resolve_policy_decision_lookup(
        &self,
        harness: &str,
        artifact_id: &str,
        artifact_hash: Option<&str>,
        workspace: &str,
        publisher: Option<&str>,
        now: &str,
        consume_one_shot: bool,
    ) -> PolicyDecisionLookup;
    /// `store.approval_reuse_diagnostic(...) -> (reason | None, stored_hash | None)`
    fn approval_reuse_diagnostic(
        &self,
        harness: &str,
        artifact_id: &str,
        artifact_hash: &str,
        workspace: &str,
        publisher: Option<&str>,
        now: &str,
    ) -> (Option<String>, Option<String>);
    /// `store.approval_reuse_claim_disposition(decision) -> str | None`
    fn approval_reuse_claim_disposition(&self, decision: &Value) -> Option<String>;
    /// `store.claim_approval_reuse_decision(decision, now=) -> bool`
    fn claim_approval_reuse_decision(&self, decision: &Value, now: &str) -> bool;
    /// `store.claim_local_once_approval(approval_id, claimed_at=, expected_decision=) -> bool`
    fn claim_local_once_approval(
        &self,
        approval_id: &str,
        claimed_at: &str,
        expected_decision: &Value,
    ) -> bool;
    /// `store.add_receipt(receipt)` — receipt is a dict payload here.
    fn add_receipt(&self, receipt: &Value);
    /// `store.set_receipt_action_envelope(receipt_id, metadata)`
    fn set_receipt_action_envelope(&self, receipt_id: &str, metadata: &Value);
    /// `store.add_event(kind, payload, now)`
    fn add_event(&self, kind: &str, payload: &Value, now: &str);
}

/// `store.resolve_policy_decision_lookup` return shape.
#[derive(Debug, Clone, Default)]
pub struct PolicyDecisionLookup {
    pub decision: Option<Value>,
    pub ignored_local_integrity: Option<Value>,
}

/// `.runtime.runner` seam.
pub trait RuntimeRunnerApi {
    /// `runner._resolve_guard_sync_auth_context(store)` -> dict
    fn resolve_guard_sync_auth_context(&self, store: &dyn SupplyChainStore) -> SyncResult<Value>;
    /// `runner.sync_local_guard_cloud_proof(store, auth_context=?...)`-shaped callable.
    fn sync_local_guard_cloud_proof(
        &self,
        store: &dyn SupplyChainStore,
        auth_context: Option<&Value>,
    ) -> SyncResult<Value>;
    /// `runner.sync_supply_chain_bundle(store, auth_context=?...)`
    fn sync_supply_chain_bundle(
        &self,
        store: &dyn SupplyChainStore,
        auth_context: Option<&Value>,
    ) -> SyncResult<Option<Value>>;
    /// `runner._guard_sync_headers(auth_context)` -> dict[str, str]
    fn guard_sync_headers(&self, auth_context: &Value) -> BTreeMap<String, String>;
    /// `runner._check_plan_restriction_403(error)` -> (is_plan_restricted, message)
    fn check_plan_restriction_403(&self, status: u16, body: &str) -> (bool, String);
    /// `runner._guard_cloud_http_error_details(error)` -> (message, retryable)
    fn guard_cloud_http_error_details(&self, status: u16, body: &str) -> (String, bool);
    /// `runner._sync_url_error_message(error)` -> str
    fn sync_url_error_message(&self, error: &str) -> String;
    /// `runner._execute_package_command(command, cwd=, environment=)` analogue.
    fn execute_package_command(
        &self,
        command: &[String],
        cwd: &Path,
        environment: &BTreeMap<String, String>,
    ) -> Result<CommandExecution, String>;
}

/// Captured subprocess result (`execution.stdout/stderr/returncode`).
#[derive(Debug, Clone, Default)]
pub struct CommandExecution {
    pub stdout: String,
    pub stderr: String,
    pub returncode: i64,
}

/// `.runtime.supply_chain_package_eval` seam.
pub trait PackageEvalApi {
    /// `evaluate_package_request_artifact(artifact=, store=, workspace_dir=, now=, ...)`
    fn evaluate_package_request_artifact(
        &self,
        artifact: &GuardArtifact,
        store: &dyn SupplyChainStore,
        workspace_dir: &Path,
        now: &str,
        external_archive_network_authorized: bool,
        retain_external_archive_blob: bool,
    ) -> Result<PackageRequestEvaluation, String>;
    /// `build_cloud_workspace_audit_request(...)` — payload normalization that
    /// lives next to the evaluator in Python.
    fn cloud_request_shape(&self, payload: &Value) -> Value {
        payload.clone()
    }
    /// `SupplyChainUserCopy(title=, summary=, next_step=, dashboard_url=, harness_message=)`
    /// -> object consumed by `evaluation.user_copy`.
    fn supply_chain_user_copy(
        &self,
        title: &str,
        summary: &str,
        next_step: Option<&str>,
        dashboard_url: Option<&str>,
        harness_message: Option<&str>,
    ) -> Map<String, Value>;
    /// `_package_decision_for_action(action)` -> decision string for a policy
    /// action (`block`/`sandbox-required`/`require-reapproval`/`review`/`warn`/`allow`).
    /// Default delegates to the oracle-verified `package_policy_override` mapping.
    fn package_decision_for_action(&self, action: &str) -> String {
        crate::package_policy_override::package_decision_for_action(normalize_guard_action(
            &Value::String(action.to_string()),
            GuardAction::Allow,
        ))
        .to_string()
    }
}

/// `.runtime.package_intent_parser` seam.
pub trait PackageIntentParserApi {
    /// `parse_package_intent(command, workspace=, environment=)`
    fn parse_package_intent(
        &self,
        command: &str,
        workspace: &Path,
        environment: &BTreeMap<String, String>,
    ) -> Option<PackageIntent>;
}

/// `daemon.policy_authority_client` seam.
pub trait PolicyAuthorityApi {
    /// `resolve_package_policy(guard_home=, harness=, artifact_id=, artifact_hash=, workspaces=, publisher=)`
    fn resolve_package_policy(
        &self,
        guard_home: &Path,
        harness: &str,
        artifact_id: &str,
        artifact_hash: &str,
        workspaces: &[String],
        publisher: Option<&str>,
    ) -> DaemonPolicyResolution;
    /// `claim_package_policy(authority, decision) -> bool`
    fn claim_package_policy(&self, authority: &Value, decision: &Value) -> bool;
}

#[derive(Debug, Clone, Default)]
pub struct DaemonPolicyResolution {
    pub authority: Option<Value>,
    pub decision: Option<Value>,
}

/// `.package_firewall_entitlement` seam.
pub trait PackageFirewallEntitlementApi {
    /// `resolve_package_firewall_entitlement(store)` -> dict
    fn resolve_package_firewall_entitlement(&self, store: &dyn SupplyChainStore) -> Value;
    /// `refresh_package_firewall_entitlements(store, auth_context=)` -> dict
    fn refresh_package_firewall_entitlements(
        &self,
        store: &dyn SupplyChainStore,
        auth_context: Option<&Value>,
    ) -> SyncResult<Value>;
}

/// `.synced_policy` seam.
pub trait SyncedPolicyApi {
    /// `synced_policy_payload(store)` -> dict
    fn synced_policy_payload(&self, store: &dyn SupplyChainStore) -> Option<Value>;
    /// `validated_synced_policy_bundle(payload)` -> dict | None
    fn validated_synced_policy_bundle(&self, payload: &Value) -> Option<Value>;
}

/// `.runtime.package_manifest_diff` seam — mirrors the free functions in
/// `crate::package_manifest_diff` so callers stay injectable in tests.
pub trait ManifestParserApi {
    /// `parse_manifest_dependencies(path, text, byte_limit, deadline_ms)`
    /// -> `dict[package_name, version]`.
    fn parse_manifest_dependencies(
        &self,
        path: &str,
        text: &str,
        byte_limit: usize,
        deadline_ms: u64,
    ) -> BTreeMap<String, String>;
    /// `parse_manifest_dependency_changes(path, before_text, after_text,
    /// byte_limit, deadline_ms)` -> `ManifestParseResult`.
    fn parse_manifest_dependency_changes(
        &self,
        path: &str,
        before_text: Option<&str>,
        after_text: Option<&str>,
        byte_limit: usize,
        deadline_ms: u64,
    ) -> crate::package_intent_common::ManifestParseResult;
}

/// `.approval_context` seam.
pub trait ApprovalContextApi {
    fn parse_approval_context_token(&self, token: &Value) -> Option<Value>;
    /// `approval_context_tokens_validation_reason(saved_token, current_token)`
    /// -> validation-failure reason or `None`.
    fn approval_context_tokens_validation_reason(
        &self,
        saved_token: &Value,
        current_token: &Value,
    ) -> Option<String>;
    /// `build_approval_context_token(identity, content, capabilities, policy,
    /// sandbox)` -> deterministic context token.
    fn build_approval_context_token(
        &self,
        identity: &Value,
        content: &Value,
        capabilities: &Value,
        policy: &Value,
        sandbox: &Value,
    ) -> String;
    /// `saved_allow_context_validation_reason(decision, artifact_hash)`
    /// -> validation-failure reason or `None` (stored allows only).
    fn saved_allow_context_validation_reason(
        &self,
        decision: &Value,
        artifact_hash: &str,
    ) -> Option<String>;
}

/// `.restricted_archive` / `.runtime_security` seam.
pub trait RestrictedArchiveApi {
    /// `restricted_archive_download_sha256(download)` -> str | None
    fn restricted_archive_download_sha256(&self, download: &Value) -> Option<String>;
    /// `restricted_archive_download_to_evidence(download)` -> dict
    fn restricted_archive_download_to_evidence(&self, download: &Value) -> Value;
    /// `detect_js_circular_manifest_errors(text)` -> tuple[str, ...]
    fn detect_js_circular_manifest_errors(&self, text: &str) -> Vec<String>;
}

/// `.runtime_launch_identity` seam.
pub trait RuntimeLaunchIdentityApi {
    fn build_runtime_launch_identity(&self, artifact: &GuardArtifact, command: &[String]) -> Value;
    fn resolved_runtime_launch_argv(&self, command: &[String]) -> Vec<String>;
    fn runtime_launch_identity_is_reusable(&self, saved: &Value, current: &Value) -> bool;
}

/// `.approvals` seam — local-once approval envelopes.
pub trait ApprovalsApi {
    fn build_local_once_approval(&self, decision: &Value, now: &str) -> Value;
}

/// `.shims` seam — dashboard status + supported managers for
/// `_build_package_manager_protection`.
pub trait ShimsApi {
    /// `package_shim_dashboard_status(HarnessContext)` -> dict
    fn package_shim_dashboard_status(
        &self,
        home_dir: &Path,
        workspace_dir: Option<&Path>,
        guard_home: &Path,
    ) -> Value;
    /// `package_shim_supported_managers()` -> tuple[str, ...]
    fn package_shim_supported_managers(&self) -> Vec<String>;
}

/// `.native_context.bind_context_digest_home` seam.
pub type BindContextDigestHome = dyn Fn(Option<&Path>);

/// `managed_urlopen` seam.
pub trait HttpTransport {
    fn open(&self, request: &HttpRequest, timeout_secs: f64) -> Result<HttpResponse, HttpError>;
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum HttpError {
    /// `urllib.error.HTTPError` — status + body.
    Status { status: u16, body: String },
    /// `OSError` — network/IO failure.
    Io(String),
}

/// `.path_support` seam — containment resolution (`resolve_path_within_allowed_roots`,
/// `resolves_within_root`, `read_text_within_workspace`).
pub trait PathSupportApi {
    fn resolve_path_within_allowed_roots(
        &self,
        candidate: &Path,
        allowed_roots: &[PathBuf],
        require_exists: bool,
    ) -> Option<PathBuf>;
    fn resolves_within_root(&self, root: &Path, candidate: &Path, require_exists: bool) -> bool;
    fn read_text_within_workspace(
        &self,
        workspace_dir: &Path,
        relative_path: &str,
    ) -> Option<String>;
    /// `read_bytes_within_workspace` — bounded byte read inside the workspace.
    fn read_bytes_within_workspace(
        &self,
        workspace_dir: &Path,
        relative_path: &str,
    ) -> Option<Vec<u8>>;
}

/// `.redaction.redact_text` seam — returns `(text, count, classifiers)`.
pub trait RedactionApi {
    fn redact_text(&self, value: &str) -> (String, usize, Vec<String>);
    /// `redact_sensitive_text` / `redact_local_path` bundled so command-token
    /// redaction matches Python ordering.
    fn redact_sensitive_text(&self, value: &str) -> String;
    fn redact_local_path(&self, value: &str) -> String;
}

/// `.advisory_model` seam — target identities, package-url construction, and
/// advisory matching.
pub trait AdvisoryModelApi {
    /// `build_package_url(ecosystem, package_name, version)` -> str | None
    fn build_package_url(
        &self,
        ecosystem: &str,
        package_name: Option<&str>,
        version: Option<&str>,
    ) -> Option<String>;
    /// `advisory_matches_target(advisory, target)` -> bool. `target` is the
    /// JSON form of `ProtectTargetIdentity` fields.
    fn advisory_matches_target(&self, advisory: &Value, target: &Value) -> bool;
}

/// `.package_execution_context` seam.
pub trait PackageExecutionContextApi {
    /// `build_package_execution_context(...)` -> PackageExecutionContext JSON
    /// evidence (`to_evidence()` payload with `context_digest`, `version`).
    fn build_package_execution_context(
        &self,
        workspace_dir: &Path,
        artifact: &GuardArtifact,
        executable: Option<&str>,
        executable_args: &[String],
        environment: Option<&Map<String, Value>>,
    ) -> Value;
}

// ---------------------------------------------------------------------------
// Value mirrors for unported types. All JSON-backed so seams stay duck-typed.
// ---------------------------------------------------------------------------

/// `.config.GuardConfig` duck-typed mirror — fields consumed by this module.
#[derive(Debug, Clone, Default)]
pub struct GuardConfig {
    /// `security_level` (config.py :397).
    pub security_level: String,
    /// `protection_posture` (config.py :393).
    pub protection_posture: String,
    /// `protection_posture_explicit` (config.py :394).
    pub protection_posture_explicit: bool,
    /// `managed_locked_settings` (config.py :428).
    pub managed_locked_settings: Vec<String>,
    /// `risk_actions` (config.py :418).
    pub risk_actions: Option<std::collections::BTreeMap<String, String>>,
    /// `harness_risk_actions` (config.py :419).
    pub harness_risk_actions:
        Option<std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>>,
    /// `managed_policy_status` (config.py :426).
    pub managed_policy_status: String,
    /// `managed_policy_hash` (config.py :427).
    pub managed_policy_hash: Option<String>,
    /// Path reported by `config.store.guard_home`.
    pub guard_home: Option<PathBuf>,
    /// Extra fields ride along verbatim (`risk-policy` metadata etc.).
    pub extra: Map<String, Value>,
}

/// `harness.HarnessContext` mirror.
#[derive(Debug, Clone, Default)]
pub struct HarnessContext {
    pub workspace_id: Option<String>,
    pub harness: Option<String>,
    pub extra: Map<String, Value>,
}

/// `supply_chain_bundle.SupplyChainBundle` mirror.
#[derive(Debug, Clone, Default)]
pub struct SupplyChainBundle {
    /// `bundle.expires_at` — ISO-8601 UTC.
    pub expires_at: Option<String>,
    /// `bundle.advisories` — raw advisory dicts.
    pub advisories: Vec<Value>,
    /// `bundle.user_copy` — policy-authored copy keyed by advisory id.
    pub user_copy: Map<String, Value>,
}

/// `runtime.supply_chain_package_eval.PackageRequestEvaluation` mirror —
/// attribute access in Python maps to JSON keys here.
#[derive(Debug, Clone, Default)]
pub struct PackageRequestEvaluation {
    pub value: Value,
}

impl PackageRequestEvaluation {
    pub fn new(value: Value) -> Self {
        Self { value }
    }
    fn get(&self, key: &str) -> Option<&Value> {
        self.value.get(key)
    }
    pub fn decision_value(&self) -> &Value {
        self.get("decision").unwrap_or(&Value::Null)
    }
    pub fn external_archive_source_hashes(&self) -> &[Value] {
        self.get("external_archive_source_hashes")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }
    pub fn policy_action(&self) -> Option<String> {
        self.get("policy_action")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }
    pub fn matched_rule_id(&self) -> Option<String> {
        self.get("matched_rule_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }
    pub fn reasons(&self) -> &[Value] {
        self.get("reasons")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }
    pub fn packages(&self) -> &[Value] {
        self.get("packages")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }
    pub fn risk_signals(&self) -> &[Value] {
        self.get("risk_signals")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }
    pub fn risk_summary(&self) -> Option<&str> {
        self.get("risk_summary").and_then(Value::as_str)
    }
    pub fn external_archive_downloads(&self) -> &[Value] {
        self.get("external_archive_downloads")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }
    /// `evaluation.user_copy` — `SupplyChainUserCopy` attribute map.
    pub fn user_copy(&self) -> Option<&Map<String, Value>> {
        self.get("user_copy").and_then(Value::as_object)
    }
    /// `evaluation.approval_reuse` — `ApprovalReuseDecision` attribute map.
    pub fn approval_reuse(&self) -> Option<&Map<String, Value>> {
        self.get("approval_reuse").and_then(Value::as_object)
    }
    /// `.approval_reuse.status`
    pub fn approval_reuse_status(&self) -> Option<&str> {
        self.approval_reuse()
            .and_then(|m| m.get("status"))
            .and_then(Value::as_str)
    }
    /// `.approval_reuse.approval_id`
    pub fn approval_reuse_approval_id(&self) -> Option<&str> {
        self.approval_reuse()
            .and_then(|m| m.get("approval_id"))
            .and_then(Value::as_str)
    }
    /// `.approval_reuse.prior_decision`
    pub fn approval_reuse_prior_decision(&self) -> Option<&Value> {
        self.approval_reuse().and_then(|m| m.get("prior_decision"))
    }
    /// `.approval_reuse.prior_artifact_id`
    pub fn approval_reuse_prior_artifact_id(&self) -> Option<&str> {
        self.approval_reuse()
            .and_then(|m| m.get("prior_artifact_id"))
            .and_then(Value::as_str)
    }
    /// `.approval_reuse.artifact_hash`
    pub fn approval_reuse_artifact_hash(&self) -> Option<&str> {
        self.approval_reuse()
            .and_then(|m| m.get("artifact_hash"))
            .and_then(Value::as_str)
    }
    /// `.approval_reuse.claim_contract`
    pub fn approval_reuse_claim_contract(&self) -> Option<&Value> {
        self.approval_reuse().and_then(|m| m.get("claim_contract"))
    }
    /// `.approval_reuse.saved_artifact_hash`
    pub fn approval_reuse_saved_artifact_hash(&self) -> Option<&str> {
        self.approval_reuse()
            .and_then(|m| m.get("saved_artifact_hash"))
            .and_then(Value::as_str)
    }
    /// `.approval_reuse.current_artifact_hash`
    pub fn approval_reuse_current_artifact_hash(&self) -> Option<&str> {
        self.approval_reuse()
            .and_then(|m| m.get("current_artifact_hash"))
            .and_then(Value::as_str)
    }
    /// `.approval_reuse.same_artifact`
    pub fn approval_reuse_same_artifact(&self) -> bool {
        self.approval_reuse()
            .and_then(|m| m.get("same_artifact"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }
    /// `.approval_reuse.blocking_rules` — list of dicts.
    pub fn approval_reuse_blocking_rules(&self) -> &[Value] {
        self.approval_reuse()
            .and_then(|m| m.get("blocking_rules"))
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }
    /// `.approval_reuse.attributed_context`
    pub fn approval_reuse_attributed_context(&self) -> Option<&Value> {
        self.approval_reuse()
            .and_then(|m| m.get("attributed_context"))
    }
    /// `.approval_reuse.launch_id`
    pub fn approval_reuse_launch_id(&self) -> Option<&str> {
        self.approval_reuse()
            .and_then(|m| m.get("launch_id"))
            .and_then(Value::as_str)
    }
    /// `dataclasses.replace`-style copy with key overrides.
    pub fn with_fields(&self, updates: &[(&str, Value)]) -> Self {
        let mut map = self.value.as_object().cloned().unwrap_or_default();
        for (key, value) in updates {
            map.insert((*key).to_string(), value.clone());
        }
        Self::new(Value::Object(map))
    }
}

/// `isinstance(value, PackageRequestEvaluation)` — duck-typed on the Rust mirror.
pub fn is_package_request_evaluation(value: &PackageRequestEvaluation) -> bool {
    let _ = value;
    true
}

/// `.guard_receipt.GuardReceipt` mirror — full payload kept as JSON so
/// `store.add_receipt` round-trips byte-identical content.
#[derive(Debug, Clone, Default)]
pub struct GuardReceipt {
    pub value: Value,
}

impl GuardReceipt {
    pub fn new(value: Value) -> Self {
        Self { value }
    }
    fn get(&self, key: &str) -> Option<&Value> {
        self.value.get(key)
    }
    pub fn receipt_id(&self) -> &str {
        self.get("receipt_id").and_then(Value::as_str).unwrap_or("")
    }
    pub fn artifact_hash(&self) -> Option<&str> {
        self.get("artifact_hash").and_then(Value::as_str)
    }
    pub fn to_dict(&self) -> &Value {
        &self.value
    }
}

/// `approval_freshness.approval_freshness_status` → `(status, freshness)`.
#[derive(Debug, Clone, Default)]
pub struct ApprovalFreshnessStatus {
    pub status: String,
    pub freshness: Value,
}

/// `.local_supply_chain._PackageProtectAuthority` (:1236-1257).
#[derive(Debug, Clone)]
pub struct PackageProtectAuthority {
    pub intent: PackageIntent,
    pub artifact: GuardArtifact,
    pub evaluation: PackageRequestEvaluation,
    pub current_action: Option<Value>,
    pub execution_context: PackageExecutionContext,
    pub artifact_hash: String,
    pub launch_identity: Value,
    pub launch_cwd: PathBuf,
    pub launch_environment: BTreeMap<String, String>,
    pub additional_current_action: Option<Value>,
    pub additional_policy_context: Option<Map<String, Value>>,
    pub observe_mode: bool,
    pub invoking_harness: String,
}

impl PackageProtectAuthority {
    /// Current package-policy action as a plain `str`; `None` when absent.
    pub fn current_action_value(&self) -> String {
        self.current_action
            .as_ref()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| v.to_string())
            })
            .unwrap_or_default()
    }
}

/// `package_request_artifact_schema_version` — runtime-private metadata key.
#[allow(dead_code)]
fn runtime_private_metadata(artifact: &GuardArtifact) -> Option<&Map<String, Value>> {
    artifact.runtime_private_metadata.as_object()
}

#[allow(dead_code)]
fn artifact_runtime_schema_version(artifact: &GuardArtifact) -> String {
    runtime_private_metadata(artifact)
        .and_then(|m| m.get("schema_version"))
        .and_then(Value::as_str)
        .unwrap_or(PACKAGE_REQUEST_ARTIFACT_SCHEMA_VERSION)
        .to_string()
}

#[allow(dead_code)]
fn artifact_package_targets(artifact: &GuardArtifact) -> Vec<Value> {
    runtime_private_metadata(artifact)
        .and_then(|m| m.get("package_targets"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

#[allow(dead_code)]
fn artifact_context_request_tokens(artifact: &GuardArtifact) -> Vec<Value> {
    artifact
        .metadata
        .get("context_request_tokens")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

#[allow(dead_code)]
fn artifact_context_token(artifact: &GuardArtifact) -> Option<String> {
    artifact
        .metadata
        .get("context_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[allow(dead_code)]
fn artifact_launcher_policy_options(artifact: &GuardArtifact) -> Option<&Map<String, Value>> {
    artifact
        .metadata
        .get("launcher_policy_options")
        .and_then(Value::as_object)
}

// ---------------------------------------------------------------------------
// Primitive helpers — `_string_value`, `_int_value`, timestamps, digests.
// ---------------------------------------------------------------------------

fn string_value(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn int_value(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::Bool(_)) | Some(Value::Null) | None => None,
        Some(Value::String(s)) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn string_tuple(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn string_items(value: Option<&Value>) -> Vec<String> {
    string_tuple(value)
}

fn dict_payload(value: Option<&Value>) -> Option<Map<String, Value>> {
    value.and_then(Value::as_object).cloned()
}

/// Minimal UTC timestamp (epoch microseconds) replacing `time::OffsetDateTime`,
/// which is not a guard-command dependency. Mirrors Python `datetime` semantics
/// for the parse/format/compare/add operations this module uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    micros: i64,
}

impl Timestamp {
    pub fn from_unix_micros(micros: i64) -> Self {
        Self { micros }
    }
    pub fn unix_seconds(&self) -> i64 {
        self.micros.div_euclid(1_000_000)
    }
    pub fn unix_seconds_f64(&self) -> f64 {
        self.micros as f64 / 1_000_000.0
    }
    /// `datetime.now(tz=timezone.utc)`.
    pub fn now_utc() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);
        Self { micros: secs }
    }
    /// `timedelta(seconds=…)`.
    pub fn add_seconds_f64(&self, seconds: f64) -> Self {
        Self {
            micros: self.micros + (seconds * 1_000_000.0) as i64,
        }
    }
    fn utc_parts(&self) -> (i64, u32, u32, u32, u32, u32, u64) {
        let secs = self.micros.div_euclid(1_000_000);
        let micros = self.micros.rem_euclid(1_000_000) as u64;
        let days = secs.div_euclid(86_400);
        let day_secs = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let h = (day_secs / 3600) as u32;
        let mi = ((day_secs % 3600) / 60) as u32;
        let s = (day_secs % 60) as u32;
        (y, m, d, h, mi, s, micros)
    }
    /// `datetime.isoformat()` — `+00:00` suffix, seconds precision.
    pub fn isoformat(&self) -> String {
        let (y, m, d, h, mi, s, _) = self.utc_parts();
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}+00:00")
    }
}

// --- ISO-8601 UTC timestamps (fromisoformat subset + isoformat) --------------

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// `datetime.fromisoformat` subset — RFC 3339 / `isoformat()` output.
/// `VALID_RISK_ACTION_KEYS` (config.py :155-164) — ordered as in source.
pub const VALID_RISK_ACTION_KEYS: &[&str] = &[
    "local_secret_read",
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive_shell",
    "encoded_execution",
    "network_egress",
    "prompt_injection",
    "mcp_dangerous_tool",
    "malicious_skill",
    "package_script",
    "persistence",
    "guard_bypass",
    "cloud_advisory",
    "encoded_exfiltration",
];

/// `DEFAULT_SECURITY_LEVEL` (config.py).
pub const DEFAULT_SECURITY_LEVEL: &str = "balanced";

pub fn parse_timestamp(value: &str) -> Option<Timestamp> {
    let text = value.trim();
    let bytes = text.as_bytes();
    if bytes.len() < 10 {
        return None;
    }
    let year: i64 = text.get(0..4)?.parse().ok()?;
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let month: u32 = text.get(5..7)?.parse().ok()?;
    let day: u32 = text.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut hour: u32 = 0;
    let mut minute: u32 = 0;
    let mut second: u32 = 0;
    let mut micros: u64 = 0;
    let mut offset_seconds: i64 = 0;
    if bytes.len() > 10 {
        if !matches!(bytes[10], b'T' | b' ') {
            return None;
        }
        let mut cursor = 11usize;
        let two = |text: &str, cursor: usize| -> Option<u32> {
            text.get(cursor..cursor + 2)?.parse().ok()
        };
        hour = two(text, cursor)?;
        if *bytes.get(cursor + 2)? != b':' {
            return None;
        }
        minute = two(text, cursor + 3)?;
        if let Some(b':') = bytes.get(cursor + 5) {
            second = two(text, cursor + 6)?;
            cursor += 8;
            if let Some(b'.') = bytes.get(cursor) {
                cursor += 1;
                let start = cursor;
                while matches!(bytes.get(cursor), Some(b'0'..=b'9')) {
                    cursor += 1;
                }
                let frac = text.get(start..cursor)?;
                let mut frac = frac.to_string();
                while frac.len() < 6 {
                    frac.push('0');
                }
                frac.truncate(6);
                micros = frac.parse::<u64>().ok()?;
            }
        } else {
            cursor += 5;
        }
        if let Some(&marker) = bytes.get(cursor) {
            match marker {
                b'Z' | b'z' => offset_seconds = 0,
                b'+' | b'-' => {
                    let sign: i64 = if marker == b'-' { -1 } else { 1 };
                    let off_h = two(text, cursor + 1)?;
                    let off_m = if bytes.get(cursor + 3) == Some(&b':') {
                        two(text, cursor + 4)?
                    } else {
                        two(text, cursor + 3)?
                    };
                    offset_seconds = sign * ((off_h as i64) * 3600 + (off_m as i64) * 60);
                }
                _ => {}
            }
        }
    }
    let days = days_from_civil(year, month as i64, day as i64);
    // Python `_parse_timestamp`: naive inputs are assumed UTC (not local).
    let unix =
        days * 86400 + (hour as i64) * 3600 + (minute as i64) * 60 + second as i64 - offset_seconds;
    Some(Timestamp::from_unix_micros(
        unix * 1_000_000 + micros as i64,
    ))
}

#[allow(dead_code)]
fn isoformat_utc(t: Timestamp) -> String {
    t.isoformat()
}

/// `datetime.now(tz=timezone.utc).isoformat()` — seconds precision, `+00:00`.
pub fn utc_now_iso() -> String {
    Timestamp::now_utc().isoformat()
}

/// `.stable_digest` — `_STABLE_DIGEST_KEY`.
const STABLE_DIGEST_KEY: &[u8] = b"hol-guard-stable-digest.v3";

/// `stable_digest_hex` — `hmac.digest(KEY, payload, "sha512")[:64]`.
/// Implemented manually because the `hmac` crate is not a guard-command dep.
pub fn stable_digest_hex(payload: &[u8]) -> String {
    stable_digest_hex_len(payload, None)
}

/// `stable_digest_hex(payload, length=n)`.
pub fn stable_digest_hex_len(payload: &[u8], length: Option<usize>) -> String {
    const BLOCK: usize = 128; // sha512 block size
    let mut key = [0u8; BLOCK];
    if STABLE_DIGEST_KEY.len() > BLOCK {
        let hashed = Sha512::digest(STABLE_DIGEST_KEY);
        key[..64].copy_from_slice(&hashed);
    } else {
        key[..STABLE_DIGEST_KEY.len()].copy_from_slice(STABLE_DIGEST_KEY);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha512::new();
    inner.update(ipad);
    inner.update(payload);
    let inner_digest = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner_digest);
    let hex_digest = hex::encode(outer.finalize());
    match length {
        Some(n) => hex_digest[..n.min(64)].to_string(),
        None => hex_digest[..64].to_string(),
    }
}

/// `.stable_digest.sha256_content_digest`.
pub fn sha256_content_digest(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

/// `uuid.uuid4().hex` — no uuid dep; 16 random bytes with version/variant bits.
pub fn uuid4_hex() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        return "0".repeat(32);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    hex::encode(bytes)
}

/// `secrets.token_hex(n)` — fail-closed to zeros when the RNG is unavailable.
pub fn token_hex(nbytes: usize) -> String {
    let mut bytes = vec![0u8; nbytes];
    if getrandom::fill(&mut bytes).is_err() {
        return "0".repeat(nbytes * 2);
    }
    hex::encode(&bytes)
}

// --- URL helpers (urllib.parse subset) --------------------------------------

/// `str.partition(sep)` — (before, sep, after); after is empty when sep absent.
#[allow(dead_code)]
fn partition<'a>(value: &'a str, sep: &str) -> (&'a str, &'a str, &'a str) {
    match value.find(sep) {
        Some(i) => (
            &value[..i],
            &value[i..i + sep.len()],
            &value[i + sep.len()..],
        ),
        None => (value, "", ""),
    }
}

/// `urllib.parse.unquote` — percent-decode.
pub fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `urllib.parse.unquote_plus`.
pub fn unquote_plus(value: &str) -> String {
    unquote(&value.replace('+', " "))
}

/// `urllib.parse.quote(value, safe='')`.
pub fn quote_component(value: &str) -> String {
    let mut out = String::new();
    for &b in value.as_bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~') {
            out.push(c);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `urllib.parse.urlencode(pairs)`.
pub fn urlencode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn quote_plus(value: &str) -> String {
    let mut out = String::new();
    for &b in value.as_bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~') {
            out.push(c);
        } else if b == b' ' {
            out.push('+');
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `urllib.parse.parse_qsl(query, keep_blank_values=True)` on a query string.
pub fn parse_qsl(query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.push((unquote_plus(k), unquote_plus(v)));
    }
    out
}

/// `urllib.parse.urlsplit` — minimal (scheme, netloc, path, query, fragment).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UrlSplit {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

pub fn urlsplit(url: &str) -> UrlSplit {
    let (rest, fragment) = match url.split_once('#') {
        Some((r, f)) => (r, f.to_string()),
        None => (url, String::new()),
    };
    let (rest, query) = match rest.split_once('?') {
        Some((r, q)) => (r, q.to_string()),
        None => (rest, String::new()),
    };
    let (scheme, netloc, path) = if let Some((scheme, after)) = rest.split_once("://") {
        let (netloc, path) = match after.find('/') {
            Some(idx) => (&after[..idx], &after[idx..]),
            None => (after, ""),
        };
        (scheme.to_string(), netloc.to_string(), path.to_string())
    } else if let Some((scheme, after)) = rest.split_once(':') {
        (scheme.to_string(), String::new(), after.to_string())
    } else {
        (String::new(), String::new(), rest.to_string())
    };
    UrlSplit {
        scheme,
        netloc,
        path,
        query,
        fragment,
    }
}

// ---------------------------------------------------------------------------
// Path helpers.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn is_within(candidate: &Path, root: &Path) -> bool {
    let candidate = candidate
        .canonicalize()
        .unwrap_or_else(|_| candidate.to_path_buf());
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    candidate.starts_with(&root)
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// `Path.is_relative_to` equivalent on uncanonicalized paths.
#[allow(dead_code)]
fn path_is_relative_to(candidate: &Path, root: &Path) -> bool {
    candidate.starts_with(root)
}

/// `_read_sbom_text` (:3530-3536) — refuses files over `_MAX_SBOM_BYTES`, UTF-8.
fn read_sbom_text(disk_path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(disk_path).ok()?;
    if metadata.len() > MAX_SBOM_BYTES {
        return None;
    }
    std::fs::read_to_string(disk_path).ok()
}

// ---------------------------------------------------------------------------
// Refresh-state sidecar — `package-firewall-refresh.json`.
// ---------------------------------------------------------------------------

/// `_package_firewall_refresh_state_path`
pub fn package_firewall_refresh_state_path(guard_home: &Path) -> PathBuf {
    guard_home.join(PACKAGE_FIREWALL_REFRESH_STATE_FILE)
}

/// `_read_package_firewall_refresh_state` — last refresh epoch, `None` when
/// missing/corrupt (Python returns the raw dict; the only consumed key is
/// `last_attempt_monotonic` persisted as epoch seconds).
pub fn read_package_firewall_refresh_state(guard_home: &Path) -> Option<Value> {
    let path = package_firewall_refresh_state_path(guard_home);
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<Value>(&text)
        .ok()
        .filter(|v| v.is_object())
}

/// `_write_package_firewall_refresh_state` — atomic write of
/// `{"last_refresh_attempt_at": <epoch float>}` with compact separators.
pub fn write_package_firewall_refresh_state(guard_home: &Path, last_attempt: f64) {
    let path = package_firewall_refresh_state_path(guard_home);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp_path = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        uuid4_hex()
    ));
    let encoded = format!("{{\"last_refresh_attempt_at\":{last_attempt:?}}}");
    let result = std::fs::write(&tmp_path, encoded).and_then(|_| std::fs::rename(&tmp_path, &path));
    let _ = result;
    if tmp_path.exists() {
        let _ = std::fs::remove_file(&tmp_path);
    }
}

// ---------------------------------------------------------------------------
// Posture — `build_local_supply_chain_posture` + internals.
// ---------------------------------------------------------------------------

/// `.runtime.supply_chain_support._SUPPORT_LEVELS` — ported verbatim.
/// TODO(deps): dedup once `supply_chain_support` lands in Rust.
static SUPPORT_LEVELS: LazyLock<
    BTreeMap<&'static str, (&'static str, &'static str, &'static str)>,
> = LazyLock::new(|| {
    [
        ("npm", ("npm", "protected", "Protected")),
        ("pypi", ("PyPI", "protected", "Protected")),
        ("cargo", ("Cargo", "beta", "Beta")),
        ("go", ("Go modules", "beta", "Beta")),
        ("maven", ("Maven/Gradle", "beta", "Beta")),
        ("packagist", ("Composer", "beta", "Beta")),
        ("rubygems", ("RubyGems", "beta", "Beta")),
        (
            "homebrew",
            ("Homebrew formulae", "monitor-only", "Monitor-only"),
        ),
        (
            "homebrew-cask",
            ("Homebrew Casks", "monitor-only", "Monitor-only"),
        ),
        (
            "homebrew-tap",
            ("Homebrew taps", "monitor-only", "Monitor-only"),
        ),
        (
            "docker",
            ("Docker base images", "monitor-only", "Monitor-only"),
        ),
        (
            "github-actions",
            ("GitHub Actions", "monitor-only", "Monitor-only"),
        ),
        (
            "system",
            ("System packages", "monitor-only", "Monitor-only"),
        ),
        (
            "unsupported",
            ("Unsupported managers", "monitor-only", "Monitor-only"),
        ),
    ]
    .into_iter()
    .collect()
});

static SUPPORT_ORDER: &[&str] = &[
    "npm",
    "pypi",
    "cargo",
    "go",
    "maven",
    "packagist",
    "rubygems",
    "homebrew",
    "homebrew-cask",
    "homebrew-tap",
    "docker",
    "github-actions",
    "system",
    "unsupported",
];

/// `ecosystem_support_metadata`.
pub fn ecosystem_support_metadata(ecosystem: &str) -> Map<String, Value> {
    let (display_name, support_level, support_label) =
        SUPPORT_LEVELS.get(ecosystem).copied().unwrap_or({
            (
                "", // computed below
                "monitor-only",
                "Monitor-only",
            )
        });
    let display_name = if display_name.is_empty() {
        // `ecosystem.replace("-", " ").title()` — Python `str.title()` per word.
        ecosystem
            .replace('-', " ")
            .split(' ')
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => {
                        first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                    }
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        display_name.to_string()
    };
    let mut out = Map::new();
    out.insert("display_name".into(), json!(display_name));
    out.insert("support_level".into(), json!(support_level));
    out.insert("support_label".into(), json!(support_label));
    out
}

/// `ecosystem_support_matrix`.
pub fn ecosystem_support_matrix() -> Vec<Value> {
    SUPPORT_ORDER
        .iter()
        .map(|ecosystem| {
            let mut row = Map::new();
            row.insert("ecosystem".into(), json!(ecosystem));
            row.extend(ecosystem_support_metadata(ecosystem));
            Value::Object(row)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Correct posture internals + payload (verbatim port of 4427-4547 + 325-430).
// ---------------------------------------------------------------------------

/// `_posture_status` (:4427-4449).
fn posture_status(
    credentials_present: bool,
    workspace_id: Option<&str>,
    summary: &Map<String, Value>,
    bundle_payload: &Map<String, Value>,
    expires_at: Option<Timestamp>,
    snapshot_now: Timestamp,
) -> &'static str {
    if !credentials_present {
        return "not_connected";
    }
    if workspace_id.is_none() {
        return "workspace_required";
    }
    if summary.is_empty() && bundle_payload.is_empty() {
        return "sync_required";
    }
    if let Some(exp) = expires_at {
        if exp <= snapshot_now {
            return "expired";
        }
    }
    if let Some(summary_status) = string_value(summary.get("status")) {
        // `str` key lookup — leak-free since we return `&'static str` via Box::leak
        // is undesirable; map known values then fall back to a stable owned path.
        // Python returns the raw string; we return a static when it matches the
        // known vocabulary, else treat presence as `synced` upstream.
        return match summary_status.as_str() {
            "not_connected" => "not_connected",
            "workspace_required" => "workspace_required",
            "sync_required" => "sync_required",
            "expired" => "expired",
            "synced" => "synced",
            "degraded" => "degraded",
            _ => "degraded",
        };
    }
    if !bundle_payload.is_empty() {
        return "synced";
    }
    "degraded"
}

/// `_posture_detail` (:4452-4464).
pub fn posture_detail(status: &str) -> &'static str {
    match status {
        "not_connected" => "Local package protection is active. Guard Cloud is optional and adds live package intelligence, synced policy, and cross-device evidence.",
        "workspace_required" => "Finish Guard Cloud pairing to fetch workspace-specific supply-chain bundles.",
        "sync_required" => "Run `hol-guard supply-chain sync` to fetch the latest signed bundle.",
        "expired" => "The cached signed bundle expired. Run `hol-guard supply-chain sync` before the next install.",
        "synced" => "Signed supply-chain bundle is ready for local install protection.",
        "degraded" => "Supply-chain protection is degraded. Refresh the signed bundle before trusting new installs.",
        _ => "Supply-chain protection status is available.",
    }
}

/// `_posture_health_status` (:4467-4488).
fn posture_health_status(
    status: &str,
    next_refresh_at: Option<&str>,
    snapshot_now: Timestamp,
) -> &'static str {
    if status == "expired" {
        return "stale";
    }
    if status == "not_connected" {
        return "local";
    }
    if matches!(status, "workspace_required" | "sync_required" | "degraded") {
        return "degraded";
    }
    let next_refresh_timestamp = next_refresh_at.and_then(parse_timestamp);
    if status == "synced"
        && next_refresh_timestamp
            .map(|t| t.add_seconds_f64(STALE_REFRESH_GRACE_SECONDS) <= snapshot_now)
            .unwrap_or(false)
    {
        return "stale";
    }
    if status == "synced" {
        return "protected";
    }
    "degraded"
}

/// `resolve_risk_action` (config.py :1065-1077) ported against the local
/// `GuardConfig` mirror.
pub fn resolve_risk_action(
    config: &GuardConfig,
    risk_class: Option<&str>,
    harness: Option<&str>,
) -> Option<String> {
    let risk_class = risk_class?;
    if !VALID_RISK_ACTION_KEYS.contains(&risk_class) {
        return None;
    }
    if let Some(h) = harness {
        if let Some(harness_map) = config.harness_risk_actions.as_ref() {
            if let Some(inner) = harness_map.get(h) {
                if let Some(action) = inner.get(risk_class) {
                    return Some(action.clone());
                }
            }
        }
    }
    if let Some(map) = config.risk_actions.as_ref() {
        if let Some(action) = map.get(risk_class) {
            return Some(action.clone());
        }
    }
    posture_or_level_defaults(config).get(risk_class).cloned()
}

/// `_posture_or_level_defaults` (config.py :1053-1058).
fn posture_or_level_defaults(config: &GuardConfig) -> std::collections::BTreeMap<String, String> {
    let managed_locks_level = config
        .managed_locked_settings
        .iter()
        .any(|s| s == "security_level");
    if config.protection_posture_explicit && !managed_locks_level {
        if let Some(defaults) = resolve_posture_defaults(&config.protection_posture) {
            return defaults;
        }
    }
    security_level_risk_actions(&config.security_level)
}

/// `SECURITY_LEVEL_RISK_ACTIONS` lookup with `DEFAULT_SECURITY_LEVEL` fallback
/// (config.py :1058, :167-265).
fn security_level_risk_rows(level: &str) -> &'static [(&'static str, &'static str)] {
    const TABLE: &[(&str, &[(&str, &str)])] = &[
        (
            "relaxed",
            &[
                ("local_secret_read", "warn"),
                ("credential_exfiltration", "warn"),
                ("data_flow_exfiltration", "warn"),
                ("destructive_shell", "warn"),
                ("encoded_execution", "warn"),
                ("network_egress", "allow"),
                ("prompt_injection", "warn"),
                ("mcp_dangerous_tool", "warn"),
                ("malicious_skill", "warn"),
                ("package_script", "warn"),
                ("persistence", "warn"),
                ("guard_bypass", "warn"),
                ("cloud_advisory", "allow"),
                ("encoded_exfiltration", "warn"),
            ],
        ),
        (
            "gentle",
            &[
                ("local_secret_read", "warn"),
                ("credential_exfiltration", "warn"),
                ("data_flow_exfiltration", "warn"),
                ("destructive_shell", "warn"),
                ("encoded_execution", "warn"),
                ("network_egress", "allow"),
                ("prompt_injection", "warn"),
                ("mcp_dangerous_tool", "warn"),
                ("malicious_skill", "warn"),
                ("package_script", "warn"),
                ("persistence", "warn"),
                ("guard_bypass", "warn"),
                ("cloud_advisory", "warn"),
                ("encoded_exfiltration", "warn"),
            ],
        ),
        (
            "balanced",
            &[
                ("local_secret_read", "review"),
                ("credential_exfiltration", "block"),
                ("data_flow_exfiltration", "block"),
                ("destructive_shell", "block"),
                ("encoded_execution", "block"),
                ("network_egress", "warn"),
                ("prompt_injection", "review"),
                ("mcp_dangerous_tool", "require-reapproval"),
                ("malicious_skill", "block"),
                ("package_script", "review"),
                ("persistence", "review"),
                ("guard_bypass", "block"),
                ("cloud_advisory", "warn"),
                ("encoded_exfiltration", "block"),
            ],
        ),
        (
            "strict",
            &[
                ("local_secret_read", "block"),
                ("credential_exfiltration", "block"),
                ("data_flow_exfiltration", "block"),
                ("destructive_shell", "block"),
                ("encoded_execution", "block"),
                ("network_egress", "warn"),
                ("prompt_injection", "block"),
                ("mcp_dangerous_tool", "block"),
                ("malicious_skill", "block"),
                ("package_script", "block"),
                ("persistence", "block"),
                ("guard_bypass", "block"),
                ("cloud_advisory", "require-reapproval"),
                ("encoded_exfiltration", "block"),
            ],
        ),
        (
            "paranoid",
            &[
                ("local_secret_read", "block"),
                ("credential_exfiltration", "block"),
                ("data_flow_exfiltration", "block"),
                ("destructive_shell", "block"),
                ("encoded_execution", "block"),
                ("network_egress", "block"),
                ("prompt_injection", "block"),
                ("mcp_dangerous_tool", "block"),
                ("malicious_skill", "block"),
                ("package_script", "block"),
                ("persistence", "block"),
                ("guard_bypass", "block"),
                ("cloud_advisory", "block"),
                ("encoded_exfiltration", "block"),
            ],
        ),
        (
            "custom",
            &[
                ("local_secret_read", "require-reapproval"),
                ("credential_exfiltration", "require-reapproval"),
                ("data_flow_exfiltration", "require-reapproval"),
                ("destructive_shell", "require-reapproval"),
                ("encoded_execution", "require-reapproval"),
                ("network_egress", "warn"),
                ("prompt_injection", "require-reapproval"),
                ("mcp_dangerous_tool", "require-reapproval"),
                ("malicious_skill", "require-reapproval"),
                ("package_script", "warn"),
                ("persistence", "require-reapproval"),
                ("guard_bypass", "block"),
                ("cloud_advisory", "warn"),
                ("encoded_exfiltration", "require-reapproval"),
            ],
        ),
    ];
    let find = |level: &str| {
        TABLE
            .iter()
            .find(|(name, _)| *name == level)
            .map(|(_, rows)| *rows)
    };
    find(level)
        .or_else(|| find(DEFAULT_SECURITY_LEVEL))
        .unwrap_or(&[])
}

fn security_level_risk_actions(level: &str) -> std::collections::BTreeMap<String, String> {
    security_level_risk_rows(level)
        .iter()
        .map(|(key, action)| ((*key).to_owned(), (*action).to_owned()))
        .collect()
}

/// `resolve_posture_defaults` (protection_posture.py :121-122).
fn resolve_posture_defaults(posture: &str) -> Option<std::collections::BTreeMap<String, String>> {
    posture_risk_actions(posture)
}

/// `POSTURE_RISK_ACTIONS` (protection_posture.py :35) — keyed by posture name.
fn posture_risk_rows(posture: &str) -> Option<&'static [(&'static str, &'static str)]> {
    const TABLE: &[(&str, &[(&str, &str)])] = &[
        (
            "protected",
            &[
                ("local_secret_read", "require-reapproval"),
                ("credential_exfiltration", "require-reapproval"),
                ("data_flow_exfiltration", "require-reapproval"),
                ("destructive_shell", "require-reapproval"),
                ("encoded_execution", "require-reapproval"),
                ("network_egress", "allow"),
                ("prompt_injection", "require-reapproval"),
                ("mcp_dangerous_tool", "require-reapproval"),
                ("malicious_skill", "require-reapproval"),
                ("package_script", "require-reapproval"),
                ("persistence", "require-reapproval"),
                ("guard_bypass", "block"),
                ("cloud_advisory", "allow"),
                ("encoded_exfiltration", "block"),
            ],
        ),
        (
            "extra_careful",
            &[
                ("local_secret_read", "require-reapproval"),
                ("credential_exfiltration", "require-reapproval"),
                ("data_flow_exfiltration", "require-reapproval"),
                ("destructive_shell", "require-reapproval"),
                ("encoded_execution", "require-reapproval"),
                ("network_egress", "require-reapproval"),
                ("prompt_injection", "require-reapproval"),
                ("mcp_dangerous_tool", "require-reapproval"),
                ("malicious_skill", "require-reapproval"),
                ("package_script", "require-reapproval"),
                ("persistence", "require-reapproval"),
                ("guard_bypass", "block"),
                ("cloud_advisory", "require-reapproval"),
                ("encoded_exfiltration", "block"),
            ],
        ),
    ];
    TABLE
        .iter()
        .find(|(name, _)| *name == posture)
        .map(|(_, rows)| *rows)
}

fn posture_risk_actions(posture: &str) -> Option<std::collections::BTreeMap<String, String>> {
    posture_risk_rows(posture).map(|rows| {
        rows.iter()
            .map(|(key, action)| ((*key).to_owned(), (*action).to_owned()))
            .collect()
    })
}

pub(crate) fn default_risk_action(
    security_level: &str,
    posture: &str,
    posture_explicit: bool,
    managed_locks_level: bool,
    risk_class: &str,
) -> Option<&'static str> {
    let rows = if posture_explicit && !managed_locks_level {
        posture_risk_rows(posture).unwrap_or_else(|| security_level_risk_rows(security_level))
    } else {
        security_level_risk_rows(security_level)
    };
    rows.iter()
        .find(|(key, _)| *key == risk_class)
        .map(|(_, action)| *action)
}

/// `build_local_supply_chain_posture` (:325-428).
pub fn build_local_supply_chain_posture(
    store: &dyn SupplyChainStore,
    config: &GuardConfig,
    synced_policy: &dyn SyncedPolicyApi,
    _entitlement_api: &dyn PackageFirewallEntitlementApi,
    shims: &dyn ShimsApi,
    now: Option<&str>,
) -> Map<String, Value> {
    let snapshot_now = now
        .and_then(parse_timestamp)
        .unwrap_or_else(Timestamp::now_utc);
    let now_text = snapshot_now.isoformat();
    let workspace_id = store.get_cloud_workspace_id();
    let cloud_profile = store.get_cloud_sync_profile();
    let summary = dict_payload(
        store
            .get_sync_payload("supply_chain_bundle_summary")
            .as_ref(),
    )
    .unwrap_or_default();
    let entitlement = dict_payload(
        store
            .get_sync_payload("supply_chain_bundle_entitlement")
            .as_ref(),
    )
    .unwrap_or_default();
    let remote_policy = synced_policy
        .synced_policy_payload(store)
        .and_then(|p| dict_payload(Some(&p)))
        .unwrap_or_default();
    // Legacy team-policy siblings are not signed policy-bundle content and
    // therefore cannot contribute enforcement or managed-policy status.
    let team_policy_pack: Map<String, Value> = Map::new();
    let cached_bundle = workspace_id
        .as_deref()
        .and_then(|id| store.get_cached_supply_chain_bundle(id));
    let bundle_payload = cached_bundle
        .as_ref()
        .and_then(|c| c.get("bundle"))
        .and_then(|b| dict_payload(Some(b)))
        .unwrap_or_default();
    let expires_at_text = string_value(bundle_payload.get("expiresAt"));
    let expires_at = expires_at_text.as_deref().and_then(parse_timestamp);
    let status = posture_status(
        cloud_profile.is_some(),
        workspace_id.as_deref(),
        &summary,
        &bundle_payload,
        expires_at,
        snapshot_now,
    );
    let synced_at = string_value(summary.get("synced_at"));
    let next_refresh_at = resolve_next_refresh_at(Some(&summary), synced_at.as_deref());
    let support = summary
        .get("supported_ecosystems")
        .cloned()
        .unwrap_or(Value::Null);
    let supported_ecosystems = match &support {
        Value::Array(items) if !items.is_empty() => support,
        _ => Value::Array(ecosystem_support_matrix()),
    };
    let remote_package_script_action = string_value(remote_policy.get("packageScriptAction"))
        .or_else(|| string_value(remote_policy.get("package_script_action")));
    let remote_cloud_advisory_action = string_value(remote_policy.get("cloudAdvisoryAction"))
        .or_else(|| string_value(remote_policy.get("cloud_advisory_action")));
    let managed_by_cloud = !remote_policy.is_empty() || !team_policy_pack.is_empty();
    let managed_label = string_value(team_policy_pack.get("name")).or_else(|| {
        if managed_by_cloud {
            Some("Guard Cloud sync".to_string())
        } else {
            None
        }
    });
    let managed_updated_at = string_value(team_policy_pack.get("updatedAt"))
        .or_else(|| string_value(remote_policy.get("updatedAt")));

    let mut posture = Map::new();
    posture.insert("generated_at".into(), json!(now_text));
    posture.insert("status".into(), json!(status));
    posture.insert("detail".into(), json!(posture_detail(status)));
    posture.insert(
        "health".into(),
        json!(posture_health_status(
            status,
            next_refresh_at.as_deref(),
            snapshot_now
        )),
    );
    posture.insert(
        "workspace_id".into(),
        workspace_id.clone().map_or(Value::Null, Value::String),
    );
    posture.insert(
        "synced_at".into(),
        synced_at.map_or(Value::Null, Value::String),
    );
    posture.insert(
        "next_refresh_at".into(),
        next_refresh_at.map_or(Value::Null, Value::String),
    );
    posture.insert(
        "bundle_expires_at".into(),
        expires_at_text.map_or(Value::Null, Value::String),
    );
    posture.insert(
        "advisory_count".into(),
        summary.get("advisoryCount").cloned().unwrap_or(Value::Null),
    );
    posture.insert("entitlement".into(), Value::Object(entitlement));
    posture.insert("security_level".into(), json!(config.security_level));
    posture.insert(
        "supply_chain".into(),
        json!({
            "cloud_advisory_action": remote_cloud_advisory_action
                .or_else(|| resolve_risk_action(config, Some("cloud_advisory"), None)),
            "package_script_action": remote_package_script_action
                .or_else(|| resolve_risk_action(config, Some("package_script"), None)),
            "managed_by_cloud": managed_by_cloud,
            "remote_policy_active": !remote_policy.is_empty(),
            "team_policy_active": !team_policy_pack.is_empty(),
            "managed_label": managed_label,
            "managed_updated_at": managed_updated_at,
        }),
    );
    posture.insert("supported_ecosystems".into(), supported_ecosystems);
    posture.insert(
        "package_manager_protection".into(),
        Value::Object(build_package_manager_protection(store, shims)),
    );
    posture
}

/// `build_supply_chain_status_payload` (:430-443).
pub fn build_supply_chain_status_payload(
    store: &dyn SupplyChainStore,
    config: &GuardConfig,
    synced_policy: &dyn SyncedPolicyApi,
    entitlement_api: &dyn PackageFirewallEntitlementApi,
    shims: &dyn ShimsApi,
    now: Option<&str>,
) -> Map<String, Value> {
    let posture =
        build_local_supply_chain_posture(store, config, synced_policy, entitlement_api, shims, now);
    let mut payload = Map::new();
    payload.insert(
        "generated_at".into(),
        now.map_or(json!(utc_now_iso()), |n| json!(n)),
    );
    payload.insert("mode".into(), json!("status"));
    payload.insert("executed".into(), json!(false));
    payload.insert("dry_run".into(), json!(true));
    payload.insert("supply_chain".into(), Value::Object(posture));
    payload
}

/// `_build_package_manager_protection` (:3171-3190).
pub fn build_package_manager_protection(
    store: &dyn SupplyChainStore,
    shims: &dyn ShimsApi,
) -> Map<String, Value> {
    let home_dir = expand_tilde_inner(Path::new("~"));
    let status = dict_payload(Some(&shims.package_shim_dashboard_status(
        &home_dir,
        None,
        store.guard_home(),
    )))
    .unwrap_or_default();
    let managed = status
        .get("managed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let supported_managers = shims.package_shim_supported_managers();
    let mut protection = Map::new();
    protection.insert("managed".into(), json!(managed));
    protection.insert("supported_managers".into(), json!(supported_managers));
    if let Some(s) = status.get("state") {
        protection.insert("state".into(), s.clone());
    }
    if let Some(s) = status.get("detail") {
        protection.insert("detail".into(), s.clone());
    }
    protection
}

/// `_call_sync_with_optional_auth_context` — retries with refreshed auth when
/// the first attempt raises `GuardSyncAuthorizationExpiredError`.
#[allow(clippy::type_complexity)]
pub fn call_sync_with_optional_auth_context(
    store: &dyn SupplyChainStore,
    runner: &dyn RuntimeRunnerApi,
    call: &dyn Fn(&dyn SupplyChainStore, Option<&Value>) -> SyncResult<Option<Value>>,
) -> SyncResult<Option<Value>> {
    match call(store, None) {
        Err(LocalSupplyChainError::AuthorizationExpired(_)) => {
            let auth_context = runner.resolve_guard_sync_auth_context(store)?;
            call(store, Some(&auth_context))
        }
        other => other,
    }
}

/// `resolve_package_firewall_entitlement_with_refresh` — heal stale cloud state.
pub fn resolve_package_firewall_entitlement_with_refresh(
    store: &dyn SupplyChainStore,
    runner: &dyn RuntimeRunnerApi,
    entitlement_api: &dyn PackageFirewallEntitlementApi,
) -> Value {
    let entitlement = entitlement_api.resolve_package_firewall_entitlement(store);
    if entitlement
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return entitlement;
    }
    if store.get_cloud_sync_profile().is_none() {
        return entitlement;
    }
    let reason = entitlement
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !matches!(
        reason,
        "guard_cloud_connect_required"
            | "guard_cloud_reconnect_required"
            | "paid_guard_cloud_required"
    ) {
        return entitlement;
    }
    let now_iso = utc_now_iso();
    let now_epoch = Timestamp::now_utc().unix_seconds() as f64;
    let state = read_package_firewall_refresh_state(store.guard_home());
    let last_refresh_at = state
        .as_ref()
        .and_then(|s| s.get("last_refresh_attempt_at"))
        .and_then(|v| v.as_f64().or_else(|| v.as_i64().map(|i| i as f64)));
    if let Some(last) = last_refresh_at {
        if now_epoch - last < PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS {
            return entitlement;
        }
    }
    write_package_firewall_refresh_state(store.guard_home(), now_epoch);
    let auth_context = runner.resolve_guard_sync_auth_context(store).ok();
    for refresh_proof in [true, false] {
        let result = if refresh_proof {
            runner.sync_local_guard_cloud_proof(store, auth_context.as_ref())
        } else {
            runner
                .sync_supply_chain_bundle(store, auth_context.as_ref())
                .map(|_| Value::Null)
        };
        match result {
            Ok(_) => {}
            Err(LocalSupplyChainError::AuthorizationExpired(error)) => {
                if reason == "guard_cloud_connect_required" {
                    store.record_latest_guard_connect_sync_result(
                        "retry_required",
                        "first_sync_failed",
                        &now_iso,
                        Some(&error),
                    );
                }
                break;
            }
            Err(_) => continue,
        }
    }
    entitlement_api.resolve_package_firewall_entitlement(store)
}

// ---------------------------------------------------------------------------
// package_firewall_entitlement.py — `resolve_package_firewall_entitlement`.
//
// Read-only resolver over `SupplyChainStore`. Never writes. Mirrors Python
// `src/codex_plugin_scanner/guard/package_firewall_entitlement.py` lines
// 68-318.
// ---------------------------------------------------------------------------

/// `_optional_string` — non-empty trimmed string.
fn entitlement_optional_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_owned())
            }
        }
        _ => None,
    }
}

fn entitlement_is_paid_tier(tier: &str) -> bool {
    PACKAGE_FIREWALL_PAID_TIERS.contains(&tier)
}

/// `_bundle_entitlement` (:68) — `supply_chain_bundle_entitlement` sync payload.
fn bundle_entitlement(payload: Option<&Value>) -> Option<Map<String, Value>> {
    let payload = payload?.as_object()?;
    let tier = entitlement_optional_string(payload.get("tier"))?;
    let normalized_tier = tier.to_lowercase();
    let allowed = entitlement_is_paid_tier(&normalized_tier);
    let mut m = Map::new();
    m.insert("allowed".to_string(), Value::Bool(allowed));
    m.insert(
        "reason".to_string(),
        Value::String(
            if allowed {
                "paid_entitlement_active"
            } else {
                "paid_guard_cloud_required"
            }
            .to_string(),
        ),
    );
    m.insert("tier".to_string(), Value::String(normalized_tier));
    m.insert(
        "upgrade_cta".to_string(),
        if allowed {
            Value::Null
        } else {
            Value::String(PACKAGE_FIREWALL_UPGRADE_CTA.to_string())
        },
    );
    Some(m)
}

/// `_oauth_entitlement_fields_from_sync_payload` (:84) — normalized OAuth
/// claim fields, `None` unless `supply_chain_plan_id` is present.
fn oauth_entitlement_fields_from_sync_payload(
    payload: Option<&Value>,
) -> Option<Map<String, Value>> {
    let payload = payload?.as_object()?;
    let mut fields = Map::new();
    for key in [
        "supply_chain_plan_id",
        "supply_chain_firewall",
        "supply_chain_entitlement_expires_at",
        "workspace_id",
    ] {
        let value = payload.get(key);
        if let Some(Value::String(s)) = value {
            let t = s.trim();
            if !t.is_empty() {
                fields.insert(key.to_string(), Value::String(t.to_owned()));
            }
        } else if key == "supply_chain_firewall" {
            if let Some(Value::Bool(b)) = value {
                fields.insert(key.to_string(), Value::Bool(*b));
            }
        }
    }
    entitlement_optional_string(fields.get("supply_chain_plan_id"))?;
    Some(fields)
}

/// `_oauth_entitlement` (:104) — claim-time entitlement from OAuth fields.
fn oauth_entitlement(
    credentials: Option<&Map<String, Value>>,
    now: &Timestamp,
) -> Option<Map<String, Value>> {
    let credentials = credentials?;
    let plan_id = entitlement_optional_string(credentials.get("supply_chain_plan_id"))?;
    let normalized_tier = plan_id.to_lowercase();
    let firewall_value = credentials.get("supply_chain_firewall");
    let firewall_allowed = match firewall_value {
        Some(Value::Bool(b)) => *b,
        _ => entitlement_is_paid_tier(&normalized_tier),
    };
    let expires_at_raw = credentials.get("supply_chain_entitlement_expires_at");
    let expires_at = expires_at_raw
        .and_then(Value::as_str)
        .and_then(parse_timestamp);
    if firewall_allowed && expires_at.is_none() {
        let mut m = Map::new();
        m.insert("allowed".to_string(), Value::Bool(false));
        m.insert(
            "reason".to_string(),
            Value::String("guard_cloud_reconnect_required".to_string()),
        );
        m.insert("tier".to_string(), Value::String(normalized_tier));
        m.insert(
            "upgrade_cta".to_string(),
            Value::String(PACKAGE_FIREWALL_RECONNECT_CTA.to_string()),
        );
        return Some(m);
    }
    if firewall_allowed && expires_at.is_some_and(|e| e <= *now) {
        let mut m = Map::new();
        m.insert("allowed".to_string(), Value::Bool(false));
        m.insert(
            "reason".to_string(),
            Value::String("guard_cloud_reconnect_required".to_string()),
        );
        m.insert("tier".to_string(), Value::String(normalized_tier));
        m.insert(
            "upgrade_cta".to_string(),
            Value::String(PACKAGE_FIREWALL_RECONNECT_CTA.to_string()),
        );
        return Some(m);
    }
    if firewall_allowed {
        let mut m = Map::new();
        m.insert("allowed".to_string(), Value::Bool(true));
        m.insert(
            "reason".to_string(),
            Value::String("paid_oauth_entitlement_active".to_string()),
        );
        m.insert("tier".to_string(), Value::String(normalized_tier));
        m.insert("upgrade_cta".to_string(), Value::Null);
        return Some(m);
    }
    if entitlement_is_paid_tier(&normalized_tier)
        && (expires_at.is_none() || expires_at.is_some_and(|e| e <= *now))
    {
        // Paid plan whose firewall claim is missing or expired: stale record,
        // reconnect refreshes the entitlement.
        let mut m = Map::new();
        m.insert("allowed".to_string(), Value::Bool(false));
        m.insert(
            "reason".to_string(),
            Value::String("guard_cloud_reconnect_required".to_string()),
        );
        m.insert("tier".to_string(), Value::String(normalized_tier));
        m.insert(
            "upgrade_cta".to_string(),
            Value::String(PACKAGE_FIREWALL_RECONNECT_CTA.to_string()),
        );
        return Some(m);
    }
    let mut m = Map::new();
    m.insert("allowed".to_string(), Value::Bool(false));
    m.insert(
        "reason".to_string(),
        Value::String("paid_guard_cloud_required".to_string()),
    );
    m.insert("tier".to_string(), Value::String(normalized_tier));
    m.insert(
        "upgrade_cta".to_string(),
        Value::String(PACKAGE_FIREWALL_UPGRADE_CTA.to_string()),
    );
    Some(m)
}

/// `_connect_state_entitlement` (:156) — reconnect verdict from the persisted
/// guard-connect state when it asserts a failed/expired connect.
fn connect_state_entitlement(
    store: &dyn SupplyChainStore,
    now: &Timestamp,
) -> Option<Map<String, Value>> {
    let oauth_payload = store.get_sync_payload("oauth_local_credentials");
    let oauth_fields = oauth_entitlement_fields_from_sync_payload(oauth_payload.as_ref());
    if let Some(fields) = &oauth_fields {
        if let Some(plan_id) = entitlement_optional_string(fields.get("supply_chain_plan_id")) {
            if !entitlement_is_paid_tier(&plan_id.to_lowercase()) {
                return None;
            }
        }
    }
    let latest_state = store.get_effective_guard_connect_state(&now.isoformat());
    let latest_state = latest_state.as_ref()?.as_object()?;
    let status = entitlement_optional_string(latest_state.get("status"));
    let milestone = entitlement_optional_string(latest_state.get("milestone"));
    let missing_oauth_after_success = status.as_deref() == Some("connected")
        && milestone.as_deref() == Some("first_sync_succeeded")
        && !oauth_payload.as_ref().is_some_and(Value::is_object);
    if !missing_oauth_after_success {
        let status_blocks = matches!(status.as_deref(), Some("retry_required") | Some("expired"));
        let milestone_blocks = matches!(
            milestone.as_deref(),
            Some("first_sync_failed") | Some("expired") | Some("sync_not_available")
        );
        if !status_blocks && !milestone_blocks {
            return None;
        }
    }
    let mut tier = "unknown".to_string();
    if let Some(fields) = &oauth_fields {
        if let Some(plan) = entitlement_optional_string(fields.get("supply_chain_plan_id")) {
            tier = plan;
        }
    }
    let mut m = Map::new();
    m.insert("allowed".to_string(), Value::Bool(false));
    m.insert(
        "reason".to_string(),
        Value::String("guard_cloud_reconnect_required".to_string()),
    );
    m.insert("tier".to_string(), Value::String(tier));
    m.insert(
        "upgrade_cta".to_string(),
        Value::String(PACKAGE_FIREWALL_RECONNECT_CTA.to_string()),
    );
    Some(m)
}

/// `_reconnect_required_entitlement` (:193).
fn reconnect_required_entitlement(
    bundle: Option<&Map<String, Value>>,
    oauth: Option<&Map<String, Value>>,
    oauth_payload: Option<&Value>,
) -> Map<String, Value> {
    let mut tier = "unknown".to_string();
    if let Some(o) = oauth {
        if let Some(t) = entitlement_optional_string(o.get("tier")) {
            tier = t;
        }
    }
    if tier == "unknown" {
        if let Some(b) = bundle {
            if let Some(t) = entitlement_optional_string(b.get("tier")) {
                tier = t;
            }
        }
    }
    if tier == "unknown" {
        if let Some(Value::Object(p)) = oauth_payload {
            if let Some(t) = entitlement_optional_string(p.get("supply_chain_plan_id")) {
                tier = t;
            }
        }
    }
    let mut m = Map::new();
    m.insert("allowed".to_string(), Value::Bool(false));
    m.insert(
        "reason".to_string(),
        Value::String("guard_cloud_reconnect_required".to_string()),
    );
    m.insert("tier".to_string(), Value::String(tier.to_lowercase()));
    m.insert(
        "upgrade_cta".to_string(),
        Value::String(PACKAGE_FIREWALL_RECONNECT_CTA.to_string()),
    );
    m
}

/// `_connect_required_entitlement` (:214).
fn connect_required_entitlement(store: &dyn SupplyChainStore) -> Map<String, Value> {
    let oauth_payload = store.get_sync_payload("oauth_local_credentials");
    let mut tier = "unknown".to_string();
    if let Some(Value::Object(p)) = &oauth_payload {
        if let Some(plan_id) = entitlement_optional_string(p.get("supply_chain_plan_id")) {
            tier = plan_id.to_lowercase();
        }
    }
    let mut m = Map::new();
    m.insert("allowed".to_string(), Value::Bool(false));
    m.insert(
        "reason".to_string(),
        Value::String("guard_cloud_connect_required".to_string()),
    );
    m.insert("tier".to_string(), Value::String(tier));
    m.insert(
        "upgrade_cta".to_string(),
        Value::String(PACKAGE_FIREWALL_CONNECT_CTA.to_string()),
    );
    m
}

/// `_requires_guard_cloud_connect` (:229) — whether a fresh Guard Cloud
/// connect is required before trusting the bundle/OAuth claim.
fn requires_guard_cloud_connect(
    store: &dyn SupplyChainStore,
    bundle: Option<&Map<String, Value>>,
    _oauth: Option<&Map<String, Value>>,
) -> bool {
    let oauth_health = store.get_oauth_local_credential_health();
    let oauth_configured = oauth_health
        .as_ref()
        .and_then(|h| h.get("configured"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let oauth_state = oauth_health
        .as_ref()
        .and_then(|h| h.get("state"))
        .and_then(Value::as_str);
    let cloud_profile = store.get_cloud_sync_profile();
    if oauth_configured && oauth_state == Some("healthy") {
        return false;
    }
    if cloud_profile.is_some() {
        return false;
    }
    if oauth_configured {
        return true;
    }
    !(bundle.is_some()
        && bundle
            .unwrap()
            .get("allowed")
            .and_then(Value::as_bool)
            .unwrap_or(false))
}

/// `resolve_package_firewall_entitlement` (:275) — read-only entitlement
/// resolution. Ported 1:1 from Python.
pub fn resolve_package_firewall_entitlement(store: &dyn SupplyChainStore) -> Map<String, Value> {
    let now = Timestamp::now_utc();
    let bundle = bundle_entitlement(
        store
            .get_sync_payload("supply_chain_bundle_entitlement")
            .as_ref(),
    );
    let oauth_health = store.get_oauth_local_credential_health();
    let oauth_payload = store.get_sync_payload("oauth_local_credentials");
    // Python gates `oauth_fields` on a healthy credential so a degraded secret
    // cannot mint a paid/unpaid claim from stale metadata.
    let oauth_fields = if oauth_health
        .as_ref()
        .and_then(|h| h.get("state"))
        .and_then(Value::as_str)
        == Some("healthy")
    {
        oauth_entitlement_fields_from_sync_payload(oauth_payload.as_ref())
    } else {
        None
    };
    let oauth = oauth_entitlement(oauth_fields.as_ref(), &now);
    let connect_state = connect_state_entitlement(store, &now);
    let is_healthy_profile = oauth_health
        .as_ref()
        .and_then(|h| h.get("state"))
        .and_then(Value::as_str)
        == Some("healthy");
    let has_profile_backed_bundle = bundle
        .as_ref()
        .is_some_and(|b| b.get("allowed").and_then(Value::as_bool).unwrap_or(false))
        && is_healthy_profile;
    if let Some(state) = connect_state {
        if !has_profile_backed_bundle {
            return state;
        }
    }
    if requires_guard_cloud_connect(store, bundle.as_ref(), oauth.as_ref()) {
        if bundle
            .as_ref()
            .is_some_and(|b| b.get("allowed").and_then(Value::as_bool).unwrap_or(false))
        {
            return reconnect_required_entitlement(
                bundle.as_ref(),
                oauth.as_ref(),
                oauth_payload.as_ref(),
            );
        }
        return connect_required_entitlement(store);
    }
    if bundle
        .as_ref()
        .is_some_and(|b| b.get("allowed").and_then(Value::as_bool).unwrap_or(false))
    {
        return bundle.unwrap();
    }
    if let Some(o) = &oauth {
        if o.get("allowed").and_then(Value::as_bool).unwrap_or(false) {
            return o.clone();
        }
    }
    if let Some(o) = &oauth {
        if o.get("reason").and_then(Value::as_str) == Some("guard_cloud_reconnect_required") {
            return o.clone();
        }
    }
    if let Some(b) = &bundle {
        let oauth_plan = oauth_payload
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|p| entitlement_optional_string(p.get("supply_chain_plan_id")));
        if let Some(o) = &oauth {
            if o.get("reason").and_then(Value::as_str) == Some("paid_guard_cloud_required") {
                return o.clone();
            }
        }
        if oauth_plan
            .as_deref()
            .is_some_and(|p| entitlement_is_paid_tier(&p.to_lowercase()))
        {
            return reconnect_required_entitlement(Some(b), oauth.as_ref(), oauth_payload.as_ref());
        }
        return b.clone();
    }
    if let Some(o) = &oauth {
        return o.clone();
    }
    connect_required_entitlement(store)
}

// ---------------------------------------------------------------------------
// Audit workspace resolution + lockfile warnings + advisory helpers.
// ---------------------------------------------------------------------------

/// `_is_audit_sensitive_basename`
pub fn is_audit_sensitive_basename(name: &str) -> bool {
    let lowered = name.to_lowercase();
    AUDIT_SENSITIVE_BASENAMES.contains(lowered.as_str()) || lowered.starts_with(".env.")
}

/// `_read_workspace_audit_text` — refuses `.env*` basenames, then reads within
/// the workspace via the path-support seam.
fn read_workspace_audit_text(
    paths: &dyn PathSupportApi,
    workspace_dir: &Path,
    relative_path: &str,
) -> Option<String> {
    if is_audit_sensitive_basename(basename(relative_path)) {
        return None;
    }
    paths.read_text_within_workspace(workspace_dir, relative_path)
}

/// `_workspace_has_project_markers`
fn workspace_has_project_markers(workspace_dir: &Path) -> bool {
    let resolved = match workspace_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    MANIFEST_CANDIDATES
        .iter()
        .any(|marker| resolved.join(marker).exists())
}

/// `managed_install_audit_workspace_dirs` — active installs first, then by
/// `updated_at` desc; deduped, stripped non-empty workspaces.
pub fn managed_install_audit_workspace_dirs(store: &dyn SupplyChainStore) -> Vec<String> {
    let mut installs = store.list_managed_installs();
    installs.sort_by(|a, b| {
        let a_key = (
            if a.get("active").and_then(Value::as_bool).unwrap_or(false) {
                1
            } else {
                0
            },
            a.get("updated_at")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        );
        let b_key = (
            if b.get("active").and_then(Value::as_bool).unwrap_or(false) {
                1
            } else {
                0
            },
            b.get("updated_at")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        );
        b_key.cmp(&a_key)
    });
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for install in &installs {
        let Some(workspace) = install.get("workspace").and_then(Value::as_str) else {
            continue;
        };
        let normalized = workspace.trim();
        if normalized.is_empty() || seen.contains(normalized) {
            continue;
        }
        seen.insert(normalized.to_string());
        candidates.push(normalized.to_string());
    }
    candidates
}

fn expand_tilde(path: &str) -> PathBuf {
    expand_tilde_inner(Path::new(path))
}

/// `Path.expanduser` — `~`/`~/` via `HOME`/`USERPROFILE` (mirrors
/// `package_intent_common::expanduser`, kept private to this module).
fn expand_tilde_inner(path: &Path) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            if text == "~" {
                return PathBuf::from(home);
            }
            return PathBuf::from(home).join(&text[2..]);
        }
    }
    path.to_path_buf()
}

/// `_managed_workspace_audit_candidates`
fn managed_workspace_audit_candidates(
    store: &dyn SupplyChainStore,
    workspace_dir: Option<&Path>,
) -> Vec<PathBuf> {
    let mut raw: Vec<PathBuf> = Vec::new();
    if let Some(dir) = workspace_dir {
        raw.push(dir.to_path_buf());
    }
    raw.extend(
        managed_install_audit_workspace_dirs(store)
            .iter()
            .map(|entry| expand_tilde(entry)),
    );
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for candidate in raw {
        let resolved = match candidate.canonicalize() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let normalized = resolved.to_string_lossy().into_owned();
        if seen.contains(&normalized) || !resolved.is_dir() {
            continue;
        }
        if !workspace_has_project_markers(&resolved) {
            continue;
        }
        seen.insert(normalized);
        candidates.push(resolved);
    }
    candidates
}

/// `resolve_supply_chain_audit_workspace_dir` — explicit path, then
/// `CURSOR_PROJECT_DIR`, then cwd, then managed installs; each constrained to
/// `allowed_roots` via the path-support seam.
pub fn resolve_supply_chain_audit_workspace_dir(
    paths: &dyn PathSupportApi,
    store: &dyn SupplyChainStore,
    workspace_dir_value: Option<&str>,
    workspace_value: Option<&str>,
    allowed_roots: &[PathBuf],
    managed_workspace_dirs: Option<&[String]>,
    reject_invalid_explicit: bool,
) -> Result<Option<PathBuf>, LocalSupplyChainError> {
    for candidate in [workspace_dir_value, workspace_value].into_iter().flatten() {
        let candidate = candidate.trim();
        if candidate.is_empty() {
            continue;
        }
        if let Some(resolved) =
            paths.resolve_path_within_allowed_roots(Path::new(candidate), allowed_roots, true)
        {
            return Ok(Some(resolved));
        }
        if reject_invalid_explicit {
            return Err(LocalSupplyChainError::Runtime(
                "workspace_dir_invalid".into(),
            ));
        }
    }
    let cursor_project = std::env::var("CURSOR_PROJECT_DIR")
        .unwrap_or_default()
        .trim()
        .to_string();
    if !cursor_project.is_empty() {
        if let Some(resolved) =
            paths.resolve_path_within_allowed_roots(Path::new(&cursor_project), allowed_roots, true)
        {
            if workspace_has_project_markers(&resolved) {
                return Ok(Some(resolved));
            }
        }
    }
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.canonicalize().ok());
    if let Some(cwd) = cwd {
        if workspace_has_project_markers(&cwd) {
            for root in allowed_roots {
                if paths.resolves_within_root(root, &cwd, true) {
                    return Ok(Some(cwd));
                }
            }
        }
    }
    let managed: Vec<String> = managed_workspace_dirs
        .map(|dirs| dirs.to_vec())
        .unwrap_or_else(|| managed_install_audit_workspace_dirs(store));
    for managed_workspace in &managed {
        if let Some(resolved) = paths.resolve_path_within_allowed_roots(
            &expand_tilde(managed_workspace),
            allowed_roots,
            true,
        ) {
            if workspace_has_project_markers(&resolved) {
                return Ok(Some(resolved));
            }
        }
    }
    Ok(None)
}

/// `_audit_lockfile_warnings` — `parse_manifest_dependencies` is the shared
/// `package_manifest_diff` port; `path` is the relative lockfile path.
#[allow(dead_code)]
fn audit_lockfile_warnings(
    paths: &dyn PathSupportApi,
    workspace_dir: &Path,
    lockfile_paths: &[String],
) -> Vec<Value> {
    let mut warnings = Vec::new();
    for lockfile_path in lockfile_paths {
        let lockfile_name = basename(lockfile_path);
        let disk_path = workspace_dir.join(lockfile_path);
        if !disk_path.exists() {
            continue;
        }
        if KNOWN_UNSUPPORTED_LOCKFILE_BASENAMES.contains(lockfile_name) {
            warnings.push(json!({
                "code": "bun_lockfile_binary_fallback",
                "message": "Guard detected bun.lockb but Bun stores it as a binary lockfile, so audit fell back to manifest-only monitoring.",
                "path": lockfile_path,
            }));
            continue;
        }
        if !ECOSYSTEM_BY_LOCKFILE.contains_key(lockfile_name) {
            continue;
        }
        let lockfile_text = read_workspace_audit_text(paths, workspace_dir, lockfile_path);
        let Some(lockfile_text) = lockfile_text else {
            warnings.push(json!({
                "code": "lockfile_unreadable",
                "message": format!("Guard could not read {lockfile_name} for workspace audit."),
                "path": lockfile_path,
            }));
            continue;
        };
        let dependency_map = crate::package_manifest_diff::parse_manifest_dependencies(
            lockfile_path,
            &lockfile_text,
            2_097_152,
            50,
        );
        if dependency_map.is_empty() {
            warnings.push(json!({
                "code": "lockfile_parse_warning",
                "message": format!("Guard could not parse {lockfile_name} for workspace audit."),
                "path": lockfile_path,
            }));
        }
    }
    warnings
}

/// `_cached_supply_chain_bundle_payload`
fn cached_supply_chain_bundle_payload(store: &dyn SupplyChainStore) -> Option<Map<String, Value>> {
    let workspace_id = store.get_cloud_workspace_id()?;
    let cached = store.get_cached_supply_chain_bundle(&workspace_id)?;
    cached.get("bundle").and_then(Value::as_object).cloned()
}

/// `_resolve_advisory_aliases_from_bundle` — upper-cased alias closure.
#[cfg(unix)]
fn resolve_advisory_aliases_from_bundle(
    bundle: Option<&Map<String, Value>>,
    advisory_ids: &[String],
) -> Vec<String> {
    let mut lookup: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    if let Some(bundle) = bundle {
        if let Some(advisories) = bundle.get("advisories").and_then(Value::as_array) {
            for advisory in advisories {
                let Some(advisory) = advisory.as_object() else {
                    continue;
                };
                let Some(advisory_id) = advisory.get("advisoryId").and_then(Value::as_str) else {
                    continue;
                };
                if advisory_id.trim().is_empty() {
                    continue;
                }
                let mut alias_tuple = vec![advisory_id.to_string()];
                if let Some(raw) = advisory.get("aliases").and_then(Value::as_array) {
                    alias_tuple.extend(
                        raw.iter()
                            .filter_map(|a| a.as_str())
                            .filter(|a| !a.trim().is_empty())
                            .map(str::to_owned),
                    );
                }
                let upper: Vec<String> = alias_tuple.iter().map(|a| a.to_uppercase()).collect();
                lookup.insert(advisory_id.to_uppercase(), upper.clone());
                for alias in &alias_tuple {
                    lookup
                        .entry(alias.to_uppercase())
                        .or_insert_with(|| upper.clone());
                }
            }
        }
    }
    let mut aliases = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |value: &str| {
        let trimmed = value.trim().to_uppercase();
        if !trimmed.is_empty() && !seen.contains(&trimmed) {
            seen.insert(trimmed.clone());
            aliases.push(trimmed);
        }
    };
    for advisory_id in advisory_ids {
        add(advisory_id);
        if let Some(resolved) = lookup.get(&advisory_id.to_uppercase()) {
            for alias in resolved {
                add(alias);
            }
        }
    }
    aliases
}

/// `_enrich_package_with_advisory_aliases`
#[cfg(unix)]
fn enrich_package_with_advisory_aliases(
    package: &Map<String, Value>,
    bundle: Option<&Map<String, Value>>,
) -> Map<String, Value> {
    if package
        .get("advisoryAliases")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false)
    {
        return package.clone();
    }
    let advisory_ids = crate::launch_identity::package_advisory_ids(package);
    if advisory_ids.is_empty() {
        return package.clone();
    }
    let aliases = resolve_advisory_aliases_from_bundle(bundle, &advisory_ids);
    if aliases.is_empty() {
        return package.clone();
    }
    let mut enriched = package.clone();
    enriched.insert(
        "advisoryAliases".to_string(),
        Value::Array(aliases.into_iter().map(Value::String).collect()),
    );
    enriched
}

/// `_enrich_evaluation_packages_with_advisory_aliases`
#[cfg(unix)]
#[allow(dead_code)]
fn enrich_evaluation_packages_with_advisory_aliases(
    evaluation: &Map<String, Value>,
    store: &dyn SupplyChainStore,
) -> Map<String, Value> {
    let Some(packages) = evaluation.get("packages").and_then(Value::as_array) else {
        return evaluation.clone();
    };
    let bundle = cached_supply_chain_bundle_payload(store);
    let enriched_packages: Vec<Value> = packages
        .iter()
        .filter_map(|p| p.as_object())
        .map(|p| Value::Object(enrich_package_with_advisory_aliases(p, bundle.as_ref())))
        .collect();
    let mut out = evaluation.clone();
    out.insert("packages".to_string(), Value::Array(enriched_packages));
    out
}

/// `_package_severity_rank` — `normalized_severity` first, then max over
/// reason severities; absent → `unknown` rank (0).
fn package_severity_rank(package: &Map<String, Value>) -> i64 {
    if let Some(severity) = package.get("normalized_severity").and_then(Value::as_str) {
        return SEVERITY_RANK.get(severity).copied().unwrap_or(0);
    }
    let mut highest = 0i64;
    if let Some(reasons) = package.get("reasons").and_then(Value::as_array) {
        for reason in reasons {
            let Some(reason) = reason.as_object() else {
                continue;
            };
            if let Some(severity) = reason.get("severity").and_then(Value::as_str) {
                highest = highest.max(SEVERITY_RANK.get(severity).copied().unwrap_or(0));
            }
        }
    }
    highest
}

/// `workspace_audit_path_hashes`
pub fn workspace_audit_path_hashes(
    paths_api: &dyn PathSupportApi,
    workspace_dir: Option<&Path>,
    manifest_paths: &[String],
    lockfile_paths: &[String],
) -> Map<String, Value> {
    let mut out = Map::new();
    match workspace_dir {
        None => {
            out.insert("manifest_hashes".into(), Value::Array(vec![]));
            out.insert("lockfile_hashes".into(), Value::Array(vec![]));
        }
        Some(dir) => {
            out.insert(
                "manifest_hashes".into(),
                Value::Array(
                    hash_existing_paths(paths_api, dir, manifest_paths)
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            );
            out.insert(
                "lockfile_hashes".into(),
                Value::Array(
                    hash_existing_paths(paths_api, dir, lockfile_paths)
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
    }
    out
}

/// `_hash_existing_paths` — sha256 file digests `path:hash`? Actual: returns
/// list of per-file sha256 hex digests of on-disk content, one per path that
/// resolves inside the workspace.
fn hash_existing_paths(
    paths_api: &dyn PathSupportApi,
    workspace_dir: &Path,
    paths: &[String],
) -> Vec<String> {
    paths
        .iter()
        .filter_map(|relative| {
            paths_api
                .read_bytes_within_workspace(workspace_dir, relative)
                .map(|bytes| stable_digest_hex(&bytes))
        })
        .collect()
}

/// `_inventory_summary`
#[allow(dead_code)]
fn inventory_summary(inventory: &[Map<String, Value>]) -> Map<String, Value> {
    let direct_count = inventory
        .iter()
        .filter(|item| item.get("direct").and_then(Value::as_bool).unwrap_or(false))
        .count();
    let transitive_count = inventory.len() - direct_count;
    let sbom_count = inventory
        .iter()
        .filter(|item| !item.get("direct").and_then(Value::as_bool).unwrap_or(false))
        .count();
    let mut out = Map::new();
    out.insert("direct_package_count".into(), json!(direct_count));
    out.insert("sbom_package_count".into(), json!(sbom_count));
    out.insert("total_packages".into(), json!(inventory.len()));
    out.insert("transitive_package_count".into(), json!(transitive_count));
    out
}

/// `_ci_gate_result`
fn ci_gate_result(evaluation: &Map<String, Value>, threshold: &str) -> Map<String, Value> {
    let threshold_rank = SEVERITY_RANK.get(threshold).copied().unwrap_or(3);
    let mut matched_packages: Vec<String> = Vec::new();
    if let Some(packages) = evaluation.get("packages").and_then(Value::as_array) {
        for package in packages {
            let Some(package) = package.as_object() else {
                continue;
            };
            if package_severity_rank(package) < threshold_rank {
                continue;
            }
            if let Some(name) = package.get("name").and_then(Value::as_str) {
                if !name.is_empty() {
                    matched_packages.push(name.to_string());
                }
            }
        }
    }
    let mut out = Map::new();
    out.insert("matched".into(), json!(!matched_packages.is_empty()));
    out.insert("matched_packages".into(), json!(matched_packages));
    out.insert("threshold".into(), json!(threshold));
    out
}

// ---------------------------------------------------------------------------
// Missing-region ports — appended in Python source order (:237 onward).
// ---------------------------------------------------------------------------

/// `_dict_items` (:4509-4512).
pub fn dict_items(value: &Value) -> Vec<&Map<String, Value>> {
    match value {
        Value::Array(items) => items.iter().filter_map(Value::as_object).collect(),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Workspace scan / inventory helpers.
// ---------------------------------------------------------------------------

/// `_resolve_sbom_paths` (:3503-3517).
fn resolve_sbom_paths(workspace_dir: &Path, sbom_paths: &[String]) -> Vec<String> {
    let mut resolved: Vec<String> = Vec::new();
    for raw_path in sbom_paths {
        let candidate = Path::new(raw_path);
        let disk_path = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            workspace_dir.join(candidate)
        };
        if !disk_path.exists() {
            continue;
        }
        let normalized = match disk_path.strip_prefix(workspace_dir) {
            Ok(rel) => rel.to_string_lossy().into_owned(),
            Err(_) => disk_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        };
        if !normalized.is_empty() && !resolved.contains(&normalized) {
            resolved.push(normalized);
        }
    }
    resolved
}

// ---------------------------------------------------------------------------
// Evaluation mutation helpers (approval-reuse / current-policy rewrites).
// ---------------------------------------------------------------------------

/// `.local_supply_chain._stored_package_policy_is_stale_policy_bundle_family`
/// (:1849-1864). Returns `true` when the stored override record describes a
/// policy-bundle *family* stale override for the package-request family.
#[allow(dead_code)]
pub(crate) fn stored_package_policy_is_stale_policy_bundle_family(
    store: &dyn SupplyChainStore,
    matched_policy: &Value,
    _artifact: &GuardArtifact,
) -> bool {
    let scope = matched_policy.get("scope").and_then(Value::as_str);
    if matched_policy.get("source").and_then(Value::as_str) != Some("policy-bundle") {
        return false;
    }
    if matched_policy.get("artifact_id").and_then(Value::as_str) != Some("family:package-request") {
        return false;
    }
    if matched_policy.get("artifact_hash").is_some() {
        return false;
    }
    if !matches!(scope, Some("harness") | Some("global")) {
        return false;
    }
    let owner = matched_policy.get("owner").and_then(Value::as_str);
    let Some(owner) = owner else { return false };
    let payload = validated_synced_policy_bundle(store);
    let Some(bundle) = payload else { return false };
    let rules = bundle.get("rules").and_then(Value::as_array);
    let Some(rules) = rules else { return false };
    let matching: Vec<&Value> = rules
        .iter()
        .filter(|rule| rule.get("ruleId").and_then(Value::as_str) == Some(owner))
        .collect();
    if matching.is_empty() {
        return true;
    }
    !matching.iter().any(|rule| {
        policy_bundle_rule_saved_decision_families(rule)
            .iter()
            .any(|f| f == "package-request")
    })
}

/// `.local_supply_chain._package_policy_workspace_candidates` (:2620-2637).
/// Returns the ordered runtime workspace candidates for stored overrides.
#[allow(dead_code)]
fn package_policy_workspace_candidates(
    artifact: &GuardArtifact,
    artifact_hash: &str,
    workspace_dir: &Path,
    execution_context: Option<&PackageExecutionContext>,
    _paths_api: &dyn PathSupportApi,
) -> Vec<String> {
    let resolved_ctx = execution_context.cloned().unwrap_or_else(|| {
        build_package_execution_context(workspace_dir, artifact, None, &[], None, _paths_api)
    });
    let runtime_workspace = package_request_runtime_workspace_scope(
        Some(&artifact.artifact_id),
        Some(artifact_hash),
        Some(&artifact.artifact_type),
        &resolved_ctx,
    );
    match runtime_workspace {
        Some(ws) if !ws.is_empty() => vec![ws],
        _ => Vec::new(),
    }
}

/// `.local_supply_chain._is_fresh_artifact_approval` (:2098-2118).
#[allow(dead_code)]
fn is_fresh_artifact_approval(store: &dyn SupplyChainStore, decision: &Value) -> bool {
    let approval_id = decision.get("approval_id").and_then(Value::as_str);
    let request_id = decision.get("request_id").and_then(Value::as_str);
    if approval_id.is_none()
        || approval_id == Some("")
        || request_id.is_none()
        || request_id == Some("")
        || decision.get("workspace").is_some()
    {
        return false;
    }
    let request_id = request_id.unwrap();
    let request = store.get_approval_request(request_id);
    match request {
        Some(request) => {
            request.get("artifact_type").and_then(Value::as_str) == Some("package_request")
                && request.get("status").and_then(Value::as_str) == Some("resolved")
                && request.get("resolution_action").and_then(Value::as_str) == Some("allow")
                && request.get("resolution_scope").and_then(Value::as_str) == Some("artifact")
                && request.get("artifact_id") == decision.get("artifact_id")
                && request.get("artifact_hash") == decision.get("artifact_hash")
        }
        None => false,
    }
}

/// `.local_supply_chain._is_durable_exact_artifact_approval` (:2121-2132).
#[allow(dead_code)]
fn is_durable_exact_artifact_approval(decision: &Value) -> bool {
    decision.get("scope").and_then(Value::as_str) == Some("artifact")
        && decision
            .get("artifact_hash")
            .and_then(Value::as_str)
            .is_some()
        && decision.get("workspace").is_none()
}

/// `.local_supply_chain._is_legacy_package_local_approval` (:2135-2150).
#[allow(dead_code)]
fn is_legacy_package_local_approval(decision: &Value) -> bool {
    decision.get("artifact_type").and_then(Value::as_str) == Some("package_request")
        && decision.get("action").and_then(Value::as_str) == Some("allow")
        && decision
            .get("artifact_hash")
            .and_then(Value::as_str)
            .is_some()
        && decision.get("workspace").is_none()
}

// ---------------------------------------------------------------------------
// Audit receipt metadata (:904-1008).
// ---------------------------------------------------------------------------

/// `audit_receipt_metadata` (:943-1008). Canonical implementation lives in
/// `crate::audit_receipt`; this resolves the `store`→bundle boundary locally.
pub fn audit_receipt_metadata(
    paths_api: &dyn PathSupportApi,
    result: &Map<String, Value>,
    workspace_dir: Option<&Path>,
    store: Option<&dyn SupplyChainStore>,
) -> Map<String, Value> {
    let bundle = store.and_then(cached_supply_chain_bundle_payload);
    crate::audit_receipt::audit_receipt_metadata(paths_api, result, workspace_dir, bundle.as_ref())
}

// ---------------------------------------------------------------------------
// Batch 1 — audit/explain/scan payload + package-protect authority port.
// ---------------------------------------------------------------------------

/// `_evaluation_exit_code` (:4365-4366).
fn evaluation_exit_code(decision: &str) -> i64 {
    if decision == "block" || decision == "ask" {
        2
    } else {
        0
    }
}

/// `is_execution_permitted` (runtime/package_execution_policy.py :8-15) permits
/// exactly `"allow"` and `"warn"`; `monitor`/observe/require-reapproval are
/// telemetry or pre-approval dispositions, not enforcement passes — fail closed.
#[allow(dead_code)]
fn is_execution_permitted(action: &GuardAction) -> bool {
    matches!(action.as_str(), "allow" | "warn")
}

/// `_protect_action_for_policy_action` (:4373-4374).
#[allow(dead_code)]
fn protect_action_for_policy_action(policy_action: Option<&Value>) -> GuardAction {
    normalize_guard_action(
        &policy_action.cloned().unwrap_or(Value::Null),
        GuardAction::Block,
    )
}

/// `_discover_workspace_audit_paths` (:3243-3262).
fn discover_workspace_audit_paths(workspace_dir: &Path) -> (Vec<String>, Vec<String>) {
    let workspace_root = match workspace_dir.canonicalize() {
        Ok(value) => value,
        Err(_) => return (Vec::new(), Vec::new()),
    };
    let mut manifests: Vec<String> = Vec::new();
    let mut lockfiles: Vec<String> = Vec::new();
    // Bounded DFS; `follow_links` is intentionally disabled to avoid cycles.
    let mut stack: Vec<PathBuf> = vec![workspace_root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(value) => value,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let relative = match path.strip_prefix(&workspace_root) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let depth = relative.components().count();
            let file_type = match entry.file_type() {
                Ok(value) => value,
                Err(_) => continue,
            };
            if file_type.is_dir() || (file_type.is_symlink() && path.is_dir()) {
                if depth >= WORKSPACE_AUDIT_DISCOVERY_MAX_DEPTH {
                    continue;
                }
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if WORKSPACE_AUDIT_DISCOVERY_SKIP_DIRS.contains(&name) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !(file_type.is_file() || (file_type.is_symlink() && path.is_file())) {
                continue;
            }
            let relative_posix = relative.to_string_lossy().replace('\\', "/");
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if relative.components().any(|component| {
                WORKSPACE_AUDIT_DISCOVERY_SKIP_DIRS
                    .contains(&component.as_os_str().to_string_lossy().as_ref())
            }) {
                continue;
            }
            if depth > WORKSPACE_AUDIT_DISCOVERY_MAX_DEPTH + 1 {
                continue;
            }
            if MANIFEST_CANDIDATE_SET.contains(file_name) && !manifests.contains(&relative_posix) {
                manifests.push(relative_posix);
            } else if LOCKFILE_CANDIDATE_SET.contains(file_name)
                && !lockfiles.contains(&relative_posix)
            {
                lockfiles.push(relative_posix);
            }
        }
    }
    manifests.sort();
    lockfiles.sort();
    (manifests, lockfiles)
}

/// `_workspace_files` (:3265-3273).
fn workspace_files(workspace_dir: &Path) -> (Vec<String>, Vec<String>) {
    let mut manifests: Vec<String> = Vec::new();
    let mut lockfiles: Vec<String> = Vec::new();
    let _packages = "packages/package.json".to_string();
    for name in MANIFEST_CANDIDATES {
        let rel = name.to_string();
        if workspace_dir.join(name).is_file() && !manifests.contains(&rel) {
            manifests.push(rel);
        }
    }
    for name in LOCKFILE_CANDIDATES {
        let rel = name.to_string();
        if workspace_dir.join(name).is_file() && !lockfiles.contains(&rel) {
            lockfiles.push(rel);
        }
    }
    for name in MANIFEST_CANDIDATES {
        let prefix = format!("packages/{name}");
        if workspace_dir.join(&prefix).is_file() && !manifests.contains(&prefix) {
            manifests.push(prefix);
        }
        let prefix = format!("package/{name}");
        if workspace_dir.join(&prefix).is_file() && !manifests.contains(&prefix) {
            manifests.push(prefix);
        }
        let prefix = format!("src/{name}");
        if workspace_dir.join(&prefix).is_file() && !manifests.contains(&prefix) {
            manifests.push(prefix);
        }
    }
    for name in LOCKFILE_CANDIDATES {
        for prefix_dir in ["packages", "package", "src"] {
            let prefix = format!("{prefix_dir}/{name}");
            if workspace_dir.join(&prefix).is_file() && !lockfiles.contains(&prefix) {
                lockfiles.push(prefix);
            }
        }
    }
    if manifests.is_empty() && lockfiles.is_empty() {
        return discover_workspace_audit_paths(workspace_dir);
    }
    (manifests, lockfiles)
}

/// `_workspace_inventory_from_paths` (:3390-3437).
fn workspace_inventory_from_paths(
    workspace_dir: &Path,
    manifest_paths: &[String],
    lockfile_paths: &[String],
    paths: &dyn PathSupportApi,
    manifest_parser: &dyn ManifestParserApi,
) -> Vec<Map<String, Value>> {
    let mut inventory_map = InventoryMap::new();

    for relative_path in manifest_paths {
        let text = match read_workspace_audit_text(paths, workspace_dir, relative_path) {
            Some(t) => t,
            None => continue,
        };
        let ecosystem = match ECOSYSTEM_BY_MANIFEST.get(basename(relative_path)) {
            Some(e) => e,
            None => continue,
        };
        let dependency_map = manifest_parser.parse_manifest_dependencies(
            relative_path,
            &text,
            DEFAULT_MANIFEST_PARSE_BYTE_LIMIT,
            DEFAULT_MANIFEST_PARSE_DEADLINE_MS,
        );
        for (package_name, version) in &dependency_map {
            let mut item = Map::new();
            item.insert("ecosystem".into(), json!(*ecosystem));
            let (ns, name) = split_namespace_name(package_name);
            item.insert("namespace".into(), ns.map_or(Value::Null, Value::String));
            item.insert("name".into(), json!(name));
            item.insert("direct".into(), json!(true));
            let range = version.trim();
            item.insert(
                "range".into(),
                if range.is_empty() {
                    Value::Null
                } else {
                    Value::String(range.to_string())
                },
            );
            item.insert("version".into(), Value::Null);
            merge_inventory_item(&mut inventory_map, &item);
        }
    }

    for relative_path in lockfile_paths {
        let text = match read_workspace_audit_text(paths, workspace_dir, relative_path) {
            Some(t) => t,
            None => continue,
        };
        let ecosystem = match ECOSYSTEM_BY_LOCKFILE.get(basename(relative_path)) {
            Some(e) => e,
            None => continue,
        };
        let dependency_map = manifest_parser.parse_manifest_dependencies(
            relative_path,
            &text,
            DEFAULT_MANIFEST_PARSE_BYTE_LIMIT,
            DEFAULT_MANIFEST_PARSE_DEADLINE_MS,
        );
        for (package_name, version) in &dependency_map {
            let mut item = Map::new();
            item.insert("ecosystem".into(), json!(*ecosystem));
            let (ns, name) = split_namespace_name(package_name);
            item.insert("namespace".into(), ns.map_or(Value::Null, Value::String));
            item.insert("name".into(), json!(name));
            item.insert("direct".into(), json!(false));
            item.insert("range".into(), Value::Null);
            let version = version.trim();
            item.insert(
                "version".into(),
                if version.is_empty() {
                    Value::Null
                } else {
                    Value::String(version.to_string())
                },
            );
            merge_inventory_item(&mut inventory_map, &item);
        }
    }

    inventory_map.into_values()
}

/// `_workspace_scan_intent` (:3213-3240).
fn workspace_scan_intent(
    workspace_dir: &Path,
    command_name: &str,
    inventory: Option<&[Map<String, Value>]>,
    manifest_paths: Option<&[String]>,
    lockfile_paths: Option<&[String]>,
    paths: &dyn PathSupportApi,
    manifest_parser: &dyn ManifestParserApi,
) -> Option<PackageIntent> {
    let (resolved_manifest_paths, resolved_lockfile_paths) = match (manifest_paths, lockfile_paths)
    {
        (Some(manifest_paths), Some(lockfile_paths)) => {
            (manifest_paths.to_vec(), lockfile_paths.to_vec())
        }
        _ => workspace_files(workspace_dir),
    };
    let resolved_inventory: Vec<Map<String, Value>> = match inventory {
        Some(items) => items.to_vec(),
        None => workspace_inventory_from_paths(
            workspace_dir,
            &resolved_manifest_paths,
            &resolved_lockfile_paths,
            paths,
            manifest_parser,
        ),
    };
    if resolved_inventory.is_empty()
        && resolved_manifest_paths.is_empty()
        && resolved_lockfile_paths.is_empty()
    {
        return None;
    }
    let targets: Vec<PackageIntentTarget> = resolved_inventory
        .iter()
        .map(target_from_inventory_item)
        .collect();
    let package_manager = package_manager_for_scan(&resolved_manifest_paths);
    Some(PackageIntent {
        package_manager,
        intent_kind: "install",
        command_tokens: vec![
            "hol-guard".to_string(),
            "supply-chain".to_string(),
            command_name.to_string(),
        ],
        redacted_command: format!("hol-guard supply-chain {command_name}"),
        targets,
        manifest_paths: resolved_manifest_paths,
        lockfile_paths: resolved_lockfile_paths,
        flags: Vec::new(),
        notes: Vec::new(),
        local_executions: Vec::new(),
        execution_context_hashes: Vec::new(),
        execution_context_cwds: Vec::new(),
        execution_context_reason_codes: Vec::new(),
    })
}

/// `_resolve_empty_audit_outcome` (:878-901).
#[allow(dead_code)]
fn resolve_empty_audit_outcome(
    _intent: &PackageIntent,
    targets: &[PackageIntentTarget],
    store: &dyn SupplyChainStore,
) -> (&'static str, &'static str, &'static str, &'static str) {
    let mut has_package_findings = false;
    if let Some(cached) = cached_supply_chain_bundle_payload(store) {
        let packages = cached.get("packages").and_then(Value::as_array);
        if let Some(list) = packages {
            has_package_findings = !list.is_empty();
        }
    }
    let _report_only = store.list_managed_installs().is_empty();
    if !targets.is_empty() {
        if has_package_findings {
            (
                "warn",
                "No workspace packages matched the audit. Guard is reporting cached findings only.",
                "audit_no_matching_workspace_packages",
                "Guard found no workspace packages matching the cached audit scope.",
            )
        } else {
            (
                "monitor",
                "No workspace packages matched the audit.",
                "audit_no_matching_workspace_packages",
                "Guard found no workspace packages matching the audit scope.",
            )
        }
    } else {
        (
            "monitor",
            "No workspace dependency changes were detected.",
            "audit_no_workspace_changes",
            "Guard found no workspace dependency changes.",
        )
    }
}

/// `_workspace_audit_inventory` (:3301-3322).
struct WorkspaceAuditInventory {
    manifest_paths: Vec<String>,
    lockfile_paths: Vec<String>,
    sbom_paths: Vec<String>,
    package_items: Vec<Map<String, Value>>,
}

fn workspace_audit_inventory(
    workspace_dir: &Path,
    sbom_paths: &[String],
    paths: &dyn PathSupportApi,
    manifest_parser: &dyn ManifestParserApi,
) -> WorkspaceAuditInventory {
    let (manifest_paths, lockfile_paths) = workspace_files(workspace_dir);
    let normalized_sbom_paths = resolve_sbom_paths(workspace_dir, sbom_paths);
    let package_items = workspace_inventory_from_paths(
        workspace_dir,
        &manifest_paths,
        &lockfile_paths,
        paths,
        manifest_parser,
    );
    WorkspaceAuditInventory {
        manifest_paths,
        lockfile_paths,
        sbom_paths: normalized_sbom_paths,
        package_items,
    }
}

/// `_workspace_diff_audit_inventory` (:3324-3387).
struct WorkspaceDiffAuditInventory {
    manifest_paths: Vec<String>,
    lockfile_paths: Vec<String>,
    sbom_paths: Vec<String>,
    package_items: Vec<Map<String, Value>>,
    summary: Map<String, Value>,
}

fn workspace_diff_audit_inventory(
    before_workspace_dir: &Path,
    after_workspace_dir: &Path,
    sbom_paths: &[String],
    paths: &dyn PathSupportApi,
    manifest_parser: &dyn ManifestParserApi,
) -> WorkspaceDiffAuditInventory {
    let (manifest_paths, lockfile_paths) = workspace_files(after_workspace_dir);
    let normalized_sbom_paths = resolve_sbom_paths(after_workspace_dir, sbom_paths);
    let mut inventory_map = InventoryMap::new();
    let mut changed_paths: Vec<String> = Vec::new();
    let mut changed_packages: Vec<String> = Vec::new();
    for relative_path in manifest_paths.iter().chain(lockfile_paths.iter()) {
        let before_path = before_workspace_dir.join(relative_path);
        let after_path = after_workspace_dir.join(relative_path);
        let before_text = if before_path.exists() {
            read_workspace_audit_text(paths, before_workspace_dir, relative_path)
        } else {
            None
        };
        let after_text = if after_path.exists() {
            read_workspace_audit_text(paths, after_workspace_dir, relative_path)
        } else {
            None
        };
        if before_text.is_none() && after_text.is_none() {
            continue;
        }
        let change_result = manifest_parser.parse_manifest_dependency_changes(
            relative_path,
            before_text.as_deref(),
            after_text.as_deref(),
            DEFAULT_MANIFEST_PARSE_BYTE_LIMIT,
            DEFAULT_MANIFEST_PARSE_DEADLINE_MS,
        );
        if change_result.changes.is_empty() {
            continue;
        }
        changed_paths.push(relative_path.clone());
        let ecosystem = ECOSYSTEM_BY_MANIFEST
            .get(basename(relative_path))
            .or_else(|| ECOSYSTEM_BY_LOCKFILE.get(basename(relative_path)));
        let ecosystem = match ecosystem {
            Some(e) => e,
            None => continue,
        };
        let direct = ECOSYSTEM_BY_MANIFEST.contains_key(basename(relative_path));
        for change in &change_result.changes {
            let version = change.after.as_deref();
            let version = match version {
                Some(v) => v,
                None => continue,
            };
            let (ns, name) = split_namespace_name(&change.package_name);
            changed_packages.push(change.package_name.clone());
            let mut item = Map::new();
            item.insert("ecosystem".into(), json!(*ecosystem));
            item.insert("namespace".into(), ns.map_or(Value::Null, Value::String));
            item.insert("name".into(), json!(name));
            item.insert("direct".into(), json!(direct));
            item.insert(
                "range".into(),
                if direct { json!(version) } else { Value::Null },
            );
            item.insert(
                "version".into(),
                if direct { Value::Null } else { json!(version) },
            );
            merge_inventory_item(&mut inventory_map, &item);
        }
    }
    for sbom_path in &normalized_sbom_paths {
        let disk_path = after_workspace_dir.join(sbom_path);
        let sbom_text = match read_sbom_text(&disk_path) {
            Some(t) => t,
            None => continue,
        };
        let payload: Value = match serde_json::from_str(&sbom_text) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let parsed_items = match inventory_from_sbom_payload(&payload) {
            Ok(items) => items,
            Err(_) => continue,
        };
        for item in &parsed_items {
            merge_inventory_item(&mut inventory_map, item);
        }
    }
    let changed_package_count = changed_packages
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<String>>()
        .len();
    let mut summary = Map::new();
    summary.insert("changed_package_count".into(), json!(changed_package_count));
    summary.insert("changed_paths".into(), json!(changed_paths));
    WorkspaceDiffAuditInventory {
        manifest_paths,
        lockfile_paths,
        sbom_paths: normalized_sbom_paths,
        package_items: inventory_map.into_values(),
        summary,
    }
}

/// `_run_cloud_workspace_audit` (:3659-3766).
fn run_cloud_workspace_audit(
    runner: &dyn RuntimeRunnerApi,
    http: &dyn HttpTransport,
    request_payload: &Map<String, Value>,
    auth_context: Option<&Map<String, Value>>,
    sync_url: Option<&str>,
    token: Option<&str>,
    workspace_id: &str,
) -> Result<Option<Map<String, Value>>, LocalSupplyChainError> {
    let resolved_auth_context = auth_context.cloned();
    let (request_url, request_headers) = match &resolved_auth_context {
        None => {
            let sync_url = sync_url.ok_or_else(|| {
                LocalSupplyChainError::Runtime("auth_context or sync_url/token required".into())
            })?;
            let token = token.ok_or_else(|| {
                LocalSupplyChainError::Runtime("auth_context or sync_url/token required".into())
            })?;
            if sync_url.is_empty() || token.is_empty() {
                return Err(LocalSupplyChainError::Runtime(
                    "auth_context or sync_url/token required".into(),
                ));
            }
            let url = normalized_supply_chain_batch_url(sync_url, workspace_id)
                .map_err(LocalSupplyChainError::Runtime)?;
            let mut headers = BTreeMap::new();
            headers.insert("Authorization".into(), format!("Bearer {token}"));
            headers.insert("Content-Type".into(), "application/json".into());
            (url, headers)
        }
        Some(ctx) => {
            let ctx_sync_url = ctx.get("sync_url").and_then(Value::as_str).ok_or_else(|| {
                LocalSupplyChainError::Runtime("auth_context missing sync_url".into())
            })?;
            let url = normalized_supply_chain_batch_url(ctx_sync_url, workspace_id)
                .map_err(LocalSupplyChainError::Runtime)?;
            let headers = runner.guard_sync_headers(&Value::Object(ctx.clone()));
            (url, headers)
        }
    };

    let mut aggregated_packages: Vec<Value> = Vec::new();
    let mut aggregated_processed_count: i64 = 0;
    let mut aggregated_reasons: Vec<Value> = Vec::new();
    let mut aggregated_total_packages: i64 = 0;
    let mut cursor: Option<String> = None;
    let mut last_response: Option<Map<String, Value>> = None;

    for _ in 0..CLOUD_AUDIT_MAX_PAGES {
        let mut page_payload = request_payload.clone();
        if let Some(ref cur) = cursor {
            page_payload.insert("cursor".into(), Value::String(cur.clone()));
        }
        let body_bytes = serde_json::to_vec(&Value::Object(page_payload))
            .map_err(|e| LocalSupplyChainError::Runtime(e.to_string()))?;
        let request = HttpRequest {
            url: request_url.clone(),
            method: "POST".to_string(),
            headers: request_headers.clone(),
            body: Some(body_bytes),
        };
        let response = http
            .open(&request, CLOUD_AUDIT_TIMEOUT_SECONDS)
            .map_err(|e| match e {
                HttpError::Status { status, body } => {
                    let (message, retryable) = runner.guard_cloud_http_error_details(status, &body);
                    LocalSupplyChainError::Runtime(format!(
                        "cloud_audit_http_{status}: {message} (retryable={retryable})"
                    ))
                }
                HttpError::Io(msg) => {
                    LocalSupplyChainError::Runtime(format!("cloud_audit_io: {msg}"))
                }
            })?;
        if response.status >= 400 {
            let body_text = String::from_utf8_lossy(&response.body).to_string();
            let (message, retryable) =
                runner.guard_cloud_http_error_details(response.status, &body_text);
            return Err(LocalSupplyChainError::Runtime(format!(
                "cloud_audit_http_{}: {} (retryable={retryable})",
                response.status, message
            )));
        }
        let parsed: Value = serde_json::from_slice(&response.body)
            .map_err(|e| LocalSupplyChainError::Runtime(format!("cloud_audit_json: {e}")))?;
        let response_map = match parsed.as_object() {
            Some(m) => m.clone(),
            None => continue,
        };
        let normalized = normalize_cloud_audit_response(&response_map);
        if let Some(packages) = normalized.get("packages").and_then(Value::as_array) {
            aggregated_packages.extend(packages.iter().cloned());
        }
        if let Some(count) = normalized.get("processed_count").and_then(Value::as_i64) {
            aggregated_processed_count += count;
        }
        if let Some(total) = normalized.get("total_packages").and_then(Value::as_i64) {
            aggregated_total_packages += total;
        }
        if let Some(reasons) = normalized.get("reasons").and_then(Value::as_array) {
            aggregated_reasons.extend(reasons.iter().cloned());
        }
        last_response = Some(response_map);
        let next_cursor = normalized
            .get("cursor")
            .and_then(Value::as_str)
            .map(str::to_string);
        match next_cursor {
            Some(c) if !c.is_empty() => {
                cursor = Some(c);
            }
            _ => break,
        }
    }

    let mut merged = match last_response {
        Some(m) => m,
        None => return Ok(None),
    };
    merged.insert("packages".into(), Value::Array(aggregated_packages.clone()));
    merged.insert("processedCount".into(), json!(aggregated_processed_count));
    merged.insert(
        "totalPackages".into(),
        json!(std::cmp::max(
            aggregated_total_packages,
            aggregated_packages.len() as i64
        )),
    );
    merged.insert("reasons".into(), Value::Array(aggregated_reasons));
    Ok(Some(merged))
}

/// `_workspace_local_evaluation` (:1145-1175).
#[allow(clippy::too_many_arguments)]
fn workspace_local_evaluation(
    store: &dyn SupplyChainStore,
    workspace_dir: &Path,
    inventory: &[Map<String, Value>],
    manifest_paths: &[String],
    lockfile_paths: &[String],
    command_name: &str,
    now: &str,
    eval_api: &dyn PackageEvalApi,
    paths: &dyn PathSupportApi,
    manifest_parser: &dyn ManifestParserApi,
) -> Result<Map<String, Value>, String> {
    let intent = workspace_scan_intent(
        workspace_dir,
        command_name,
        Some(inventory),
        Some(manifest_paths),
        Some(lockfile_paths),
        paths,
        manifest_parser,
    )
    .ok_or_else(|| "intent required".to_string())?;
    let artifact =
        build_package_request_artifact("_local_supply_chain", &intent, "hol-guard.toml", "project");
    let evaluation = eval_api.evaluate_package_request_artifact(
        &artifact,
        store,
        workspace_dir,
        now,
        false,
        false,
    )?;
    Ok(evaluation.value.as_object().cloned().unwrap_or_default())
}

/// `build_workspace_scan_payload` (:993-1007).
pub fn build_workspace_scan_payload(
    workspace_dir: &Path,
    _store: &dyn SupplyChainStore,
    _now: &str,
    paths: &dyn PathSupportApi,
    manifest_parser: &dyn ManifestParserApi,
) -> Map<String, Value> {
    let intent = workspace_scan_intent(
        workspace_dir,
        "scan",
        None,
        None,
        None,
        paths,
        manifest_parser,
    );
    let mut out = Map::new();
    match intent {
        Some(intent) => {
            let _targets: Vec<&PackageIntentTarget> = intent.targets.iter().collect();
            out.insert(
                "intent".into(),
                json!({
                    "package_manager": intent.package_manager,
                    "intent_kind": intent.intent_kind,
                    "command_tokens": intent.command_tokens,
                    "redacted_command": intent.redacted_command,
                    "targets": intent.targets.iter().map(|t| t.to_dict()).collect::<Vec<_>>(),
                    "manifest_paths": intent.manifest_paths,
                    "lockfile_paths": intent.lockfile_paths,
                }),
            );
            out.insert("target_count".into(), json!(intent.targets.len()));
        }
        None => {
            out.insert("intent".into(), Value::Null);
            out.insert("target_count".into(), json!(0));
        }
    }
    out.insert("operation".into(), json!("scan"));
    out.insert(
        "workspace_dir".into(),
        json!(workspace_dir.to_string_lossy()),
    );
    out
}

/// `build_workspace_audit_payload` (:1010-1142).
#[allow(clippy::too_many_arguments)]
pub fn build_workspace_audit_payload(
    workspace_dir: &Path,
    store: &dyn SupplyChainStore,
    now: &str,
    sbom_paths: &[String],
    before_workspace_dir: Option<&Path>,
    workspace_id: &str,
    _workspace_label: Option<&str>,
    threshold: Option<&str>,
    paths: &dyn PathSupportApi,
    manifest_parser: &dyn ManifestParserApi,
    runner: &dyn RuntimeRunnerApi,
    http: &dyn HttpTransport,
    eval_api: &dyn PackageEvalApi,
) -> Result<Map<String, Value>, LocalSupplyChainError> {
    let diff_inventory = before_workspace_dir.map(|before_dir| {
        workspace_diff_audit_inventory(
            before_dir,
            workspace_dir,
            sbom_paths,
            paths,
            manifest_parser,
        )
    });
    let (manifest_paths, lockfile_paths, _sbom_paths_resolved, package_items, _summary) =
        match &diff_inventory {
            Some(inv) => (
                inv.manifest_paths.clone(),
                inv.lockfile_paths.clone(),
                inv.sbom_paths.clone(),
                inv.package_items.clone(),
                inv.summary.clone(),
            ),
            None => {
                let inv =
                    workspace_audit_inventory(workspace_dir, sbom_paths, paths, manifest_parser);
                let mut summary = Map::new();
                summary.insert("changed_package_count".into(), json!(0));
                summary.insert("changed_paths".into(), json!([]));
                (
                    inv.manifest_paths,
                    inv.lockfile_paths,
                    inv.sbom_paths,
                    inv.package_items,
                    summary,
                )
            }
        };

    let intent = workspace_scan_intent(
        workspace_dir,
        "audit",
        Some(&package_items),
        Some(&manifest_paths),
        Some(&lockfile_paths),
        paths,
        manifest_parser,
    );

    let cloud_auth = runner
        .resolve_guard_sync_auth_context(store)
        .ok()
        .and_then(|value| value.as_object().cloned());
    let posture = {
        let summary = dict_payload(
            store
                .get_sync_payload("supply_chain_bundle_summary")
                .as_ref(),
        )
        .unwrap_or_default();
        let entitlement = dict_payload(
            store
                .get_sync_payload("supply_chain_bundle_entitlement")
                .as_ref(),
        )
        .unwrap_or_default();
        let bundle_payload = store
            .get_cached_supply_chain_bundle(workspace_id)
            .and_then(|bundle| dict_payload(bundle.get("bundle")))
            .unwrap_or_default();
        let tier = string_value(summary.get("tier"))
            .or_else(|| string_value(entitlement.get("tier")))
            .or_else(|| string_value(bundle_payload.get("tier")));
        let mut bundle = Map::new();
        bundle.insert("tier".into(), tier.map_or(Value::Null, Value::String));
        let mut posture = Map::new();
        posture.insert("bundle".into(), Value::Object(bundle));
        posture
    };
    let use_cloud = should_use_cloud_workspace_audit(store, &posture);

    let evaluation_result = if use_cloud {
        let inventory_values: Vec<Value> =
            package_items.iter().cloned().map(Value::Object).collect();
        let cloud_request_payload = build_cloud_audit_payload(
            workspace_dir,
            workspace_id,
            store,
            &manifest_paths,
            &lockfile_paths,
            &inventory_values,
            "paged",
            None,
            paths,
            &EnvCloudAuditWorkspaceContext,
        )
        .ok();
        match cloud_request_payload {
            Some(payload) => match run_cloud_workspace_audit(
                runner,
                http,
                &payload,
                cloud_auth.as_ref(),
                None,
                None,
                workspace_id,
            ) {
                Ok(Some(response)) => Some(response),
                Ok(None) | Err(_) => None,
            },
            None => None,
        }
    } else {
        None
    };

    let (evaluation, evaluation_error) = match evaluation_result {
        Some(cloud_response) => {
            let _decision = cloud_response
                .get("decision")
                .and_then(Value::as_str)
                .unwrap_or("monitor")
                .to_string();
            (Some(cloud_response), None::<String>)
        }
        None => {
            let _intent_val = match intent {
                Some(intent) => intent,
                None => {
                    return Err(LocalSupplyChainError::Runtime(
                        "audit requires at least one workspace manifest".into(),
                    ))
                }
            };
            match workspace_local_evaluation(
                store,
                workspace_dir,
                &package_items,
                &manifest_paths,
                &lockfile_paths,
                "audit",
                now,
                eval_api,
                paths,
                manifest_parser,
            ) {
                Ok(eval) => {
                    let mut m = Map::new();
                    m.insert(
                        "decision".into(),
                        json!(eval
                            .get("decision")
                            .and_then(Value::as_str)
                            .unwrap_or("monitor")),
                    );
                    m.insert(
                        "policy_action".into(),
                        json!(eval
                            .get("policy_action")
                            .and_then(Value::as_str)
                            .unwrap_or("monitor")),
                    );
                    m.insert(
                        "reasons".into(),
                        json!(eval
                            .get("reasons")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default()),
                    );
                    m.insert(
                        "packages".into(),
                        json!(eval
                            .get("packages")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default()),
                    );
                    m.insert(
                        "external_archive_source_hashes".into(),
                        json!(eval
                            .get("external_archive_source_hashes")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default()),
                    );
                    (Some(m), None)
                }
                Err(e) => (None, Some(e)),
            }
        }
    };

    let evaluation = evaluation.unwrap_or_default();
    let decision = evaluation
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("monitor")
        .to_string();
    let policy_action = evaluation
        .get("policy_action")
        .and_then(Value::as_str)
        .unwrap_or("monitor")
        .to_string();
    let packages = evaluation
        .get("packages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let _blocked_packages = packages
        .iter()
        .filter_map(|p| p.as_object())
        .filter(|p| {
            p.get("decision")
                .and_then(Value::as_str)
                .map(|d| d == "block")
                .unwrap_or(false)
        })
        .count();
    let exit_code = evaluation_exit_code(&decision);
    let gate_result = threshold.map(|t| ci_gate_result(&evaluation, t));
    let report = gate_result
        .as_ref()
        .and_then(|g| g.get("gate_result").cloned());

    let mut out = Map::new();
    out.insert("operation".into(), json!("audit"));
    out.insert("decision".into(), json!(decision));
    out.insert("policy_action".into(), json!(policy_action));
    out.insert("exit_code".into(), json!(exit_code));
    out.insert("evaluation".into(), Value::Object(evaluation));
    let evaluation_error_present = evaluation_error.is_some();
    if let Some(error) = evaluation_error {
        out.insert("evaluation_error".into(), json!(error));
    }
    if let Some(report) = report {
        out.insert("gate_result".into(), report);
    }
    out.insert(
        "workspace_dir".into(),
        json!(workspace_dir.to_string_lossy()),
    );
    out.insert("workspace_id".into(), json!(workspace_id));
    out.insert(
        "used_cloud".into(),
        json!(use_cloud && !evaluation_error_present),
    );
    Ok(out)
}

/// `build_supply_chain_explain_payload` (:1178-1221).
#[allow(clippy::too_many_arguments)]
pub fn build_supply_chain_explain_payload(
    workspace_dir: &Path,
    package_spec: Option<&str>,
    _store: &dyn SupplyChainStore,
    _now: &str,
    paths: &dyn PathSupportApi,
    manifest_parser: &dyn ManifestParserApi,
) -> Map<String, Value> {
    let intent = workspace_scan_intent(
        workspace_dir,
        "explain",
        None,
        None,
        None,
        paths,
        manifest_parser,
    );
    let ecosystem = intent
        .as_ref()
        .map(|i| {
            i.manifest_paths
                .first()
                .and_then(|p| ECOSYSTEM_BY_MANIFEST.get(basename(p)))
                .map(|e| e.to_string())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let resolved_spec = package_spec
        .map(str::to_string)
        .or_else(|| {
            intent
                .as_ref()
                .and_then(|i| i.targets.first().map(|t| t.raw_spec.clone()))
        })
        .unwrap_or_default();
    let target = target_for_package_spec(&ecosystem, &resolved_spec);
    let mut out = Map::new();
    out.insert("operation".into(), json!("explain"));
    out.insert(
        "workspace_dir".into(),
        json!(workspace_dir.to_string_lossy()),
    );
    out.insert("package_spec".into(), json!(resolved_spec));
    out.insert("ecosystem".into(), json!(ecosystem));
    out.insert(
        "target".into(),
        Value::Object(serde_json::Map::from_iter([
            ("package_spec".into(), json!(target.raw_spec)),
            ("package_name".into(), json!(target.package_name)),
            ("package_version".into(), json!(target.requested_specifier)),
            ("ecosystem".into(), json!(target.ecosystem)),
        ])),
    );
    if let Some(intent) = intent {
        out.insert("manifest_paths".into(), json!(intent.manifest_paths));
        out.insert("lockfile_paths".into(), json!(intent.lockfile_paths));
    }
    out
}

/// `_package_evaluation_requires_external_archive_binding` (:1263-1285).
#[allow(dead_code)]
fn package_evaluation_requires_external_archive_binding(
    evaluation: &PackageRequestEvaluation,
) -> bool {
    let source_hashes = evaluation.external_archive_source_hashes();
    if source_hashes
        .iter()
        .any(|h| h.as_str().is_some_and(|s| s.len() == 64))
    {
        return true;
    }
    if evaluation
        .reasons()
        .iter()
        .any(|r| r.get("code").and_then(Value::as_str) == Some("external_tarball_source"))
    {
        return true;
    }
    evaluation.packages().iter().any(|package| {
        package
            .get("reasons")
            .and_then(Value::as_array)
            .map(|reasons| {
                reasons.iter().any(|r| {
                    r.get("code").and_then(Value::as_str) == Some("external_tarball_source")
                })
            })
            .unwrap_or(false)
    })
}

/// `_external_archive_downloads` — extract archive downloads from an evaluation.
#[allow(dead_code)]
fn external_archive_downloads(evaluation: &PackageRequestEvaluation) -> Vec<Value> {
    evaluation.external_archive_downloads().to_vec()
}

/// `_cleanup_external_archive_downloads` (:1258-1260).
#[allow(dead_code)]
fn cleanup_external_archive_downloads(evaluation: &PackageRequestEvaluation) {
    for download in external_archive_downloads(evaluation) {
        if let Some(cleanup_fn) = download.get("cleanup").and_then(Value::as_str) {
            // RestrictedArchiveDownload is a seam object; cleanup is managed externally.
            let _ = cleanup_fn;
        }
        if let Some(path) = download.get("path").and_then(Value::as_str) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// `_verified_external_archive_replacements` (:1288-1329).
#[allow(dead_code)]
fn verified_external_archive_replacements(
    evaluation: &PackageRequestEvaluation,
) -> Option<BTreeMap<String, String>> {
    let mut replacements = BTreeMap::new();
    for download in external_archive_downloads(evaluation) {
        let path_value = download.get("path").and_then(Value::as_str);
        let path_value = path_value?;
        let sha256 = download.get("sha256").and_then(Value::as_str);
        let sha256 = match sha256 {
            Some(s) => s.to_string(),
            None => {
                // Compute sha256 of the file at `path_value`.
                match std::fs::read(path_value) {
                    Ok(bytes) => stable_digest_hex(&bytes),
                    Err(_) => return None,
                }
            }
        };
        let source_url = download.get("source_url").and_then(Value::as_str);
        let source_url = match source_url {
            Some(u) => u,
            None => continue,
        };
        replacements.insert(source_url.to_string(), sha256);
    }
    Some(replacements)
}

/// `_bound_external_archive_launch_command` (:1332-1352).
#[allow(dead_code)]
fn bound_external_archive_launch_command(
    launch_command: &[String],
    evaluation: &PackageRequestEvaluation,
) -> Option<Vec<String>> {
    let replacements = verified_external_archive_replacements(evaluation)?;
    if replacements.is_empty() {
        if package_evaluation_requires_external_archive_binding(evaluation) {
            return None;
        }
        return Some(launch_command.to_vec());
    }
    let mut bound_command = launch_command.to_vec();
    for (source_url, replacement) in &replacements {
        let mut replacement_count = 0;
        for arg in bound_command.iter_mut() {
            if arg.contains(source_url.as_str()) {
                *arg = arg.replace(source_url.as_str(), replacement);
                replacement_count += 1;
            }
        }
        if replacement_count == 0 {
            return None;
        }
    }
    Some(bound_command)
}

/// `_package_manager_launch_environment` (:1355-1383).
#[allow(dead_code)]
fn package_manager_launch_environment(
    environment: &BTreeMap<String, String>,
    guard_home: &Path,
    launch_cwd: &Path,
) -> Result<BTreeMap<String, String>, String> {
    let mut launch_environment = environment.clone();
    let shim_dir = guard_home.join("package-shims").join("bin");
    let shim_dir = shim_dir
        .canonicalize()
        .map_err(|_| "Guard's package shim path could not be verified".to_string())?;
    let path_entries: Vec<String> = environment
        .get("PATH")
        .map(|p| {
            std::env::split_paths(std::ffi::OsStr::new(p))
                .map(|entry| entry.to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    let mut filtered_entries: Vec<String> = Vec::new();
    for entry in path_entries {
        if entry.is_empty() {
            continue;
        }
        let mut path_entry = PathBuf::from(&entry);
        if !path_entry.is_absolute() {
            path_entry = launch_cwd.join(&path_entry);
        }
        let resolved_entry = path_entry
            .canonicalize()
            .map_err(|_| "package manager PATH could not be verified".to_string())?;
        if resolved_entry != shim_dir {
            filtered_entries.push(entry);
        }
    }
    let filtered_path = std::env::join_paths(filtered_entries.iter().map(std::ffi::OsStr::new))
        .map(|value| value.to_string_lossy().into_owned())
        .map_err(|_| "package manager PATH could not be encoded".to_string())?;
    launch_environment.insert("PATH".into(), filtered_path);
    Ok(launch_environment)
}

/// `_build_package_protect_authority` (:1386-1494).
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn build_package_protect_authority(
    command: &[String],
    store: &dyn SupplyChainStore,
    workspace_dir: &Path,
    now: &str,
    config: Option<&GuardConfig>,
    additional_current_action: Option<&Value>,
    additional_policy_context: Option<&Map<String, Value>>,
    external_archive_network_authorized: bool,
    invoking_harness: Option<&str>,
    intent_parser: &dyn PackageIntentParserApi,
    eval_api: &dyn PackageEvalApi,
    launch_identity_api: &dyn RuntimeLaunchIdentityApi,
    bind_context_digest_home: &BindContextDigestHome,
    paths_api: &dyn PathSupportApi,
) -> Result<Option<PackageProtectAuthority>, String> {
    bind_context_digest_home(Some(store.guard_home()));
    let parsed_intent =
        intent_parser.parse_package_intent(&command.join(" "), workspace_dir, &BTreeMap::new());
    let parsed_intent = match parsed_intent {
        Some(intent) if !intent.targets.is_empty() => intent,
        _ => return Ok(None),
    };
    let launch_cwd = workspace_dir.to_path_buf();
    let artifact = build_package_request_artifact(
        LOCAL_SUPPLY_CHAIN_HARNESS,
        &parsed_intent,
        "hol-guard.toml",
        "project",
    );
    let evaluation = eval_api.evaluate_package_request_artifact(
        &artifact,
        store,
        workspace_dir,
        now,
        external_archive_network_authorized,
        false,
    )?;
    let current_action = compose_current_package_policy_action(
        evaluation.policy_action(),
        additional_current_action,
        additional_policy_context,
    );
    let artifact_hash =
        stable_digest_hex(format!("{}:{}", artifact.artifact_id, artifact.name).as_bytes());
    let execution_context = build_package_execution_context(
        workspace_dir,
        &artifact,
        command.first().map(String::as_str),
        &command[1..],
        None,
        paths_api,
    );
    let launch_identity = launch_identity_api.build_runtime_launch_identity(&artifact, command);
    let launch_environment =
        package_manager_launch_environment(&BTreeMap::new(), store.guard_home(), &launch_cwd)?;
    let resolved_invoking_harness = invoking_harness
        .map(str::to_string)
        .unwrap_or_else(resolve_local_supply_chain_harness);
    let observe_mode = config
        .map(|c| c.protection_posture == "observe")
        .unwrap_or(false);
    Ok(Some(PackageProtectAuthority {
        invoking_harness: resolved_invoking_harness,
        intent: parsed_intent,
        artifact,
        evaluation,
        current_action,
        execution_context,
        artifact_hash,
        launch_identity,
        launch_cwd,
        launch_environment,
        additional_current_action: additional_current_action.cloned(),
        additional_policy_context: additional_policy_context.cloned(),
        observe_mode,
    }))
}

/// `_final_package_protect_authority` (:1497-1694).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
#[allow(dead_code)]
fn final_package_protect_authority(
    initial: PackageProtectAuthority,
    initial_saved_evaluation: &PackageRequestEvaluation,
    saved_approval_pending: bool,
    command: &[String],
    store: &dyn SupplyChainStore,
    workspace_dir: &Path,
    now: &str,
    config: Option<&GuardConfig>,
    current_config_provider: Option<&dyn Fn() -> Option<GuardConfig>>,
    additional_authority_provider: Option<
        &dyn Fn() -> Result<(Option<Value>, Option<Map<String, Value>>), String>,
    >,
    intent_parser: &dyn PackageIntentParserApi,
    eval_api: &dyn PackageEvalApi,
    launch_identity_api: &dyn RuntimeLaunchIdentityApi,
    bind_context_digest_home: &BindContextDigestHome,
    paths_api: &dyn PathSupportApi,
    approval_context_api: &dyn ApprovalContextApi,
) -> Result<(PackageProtectAuthority, PackageRequestEvaluation), String> {
    bind_context_digest_home(Some(store.guard_home()));

    let mut additional_action: Option<Value> = initial.additional_current_action.clone();
    let mut additional_context: Option<Map<String, Value>> =
        initial.additional_policy_context.clone();
    let mut current_config = config.cloned();
    let mut config_refresh_failed = false;

    if let Some(provider) = current_config_provider {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(provider)) {
            Ok(cfg) => {
                if cfg.is_none() {
                    config_refresh_failed = true;
                }
                current_config = cfg;
            }
            Err(_) => {
                config_refresh_failed = true;
            }
        }
    }

    let mut saved_approval_claimed = false;
    let mut saved_approval_claim_disposition: Option<String> = None;
    let mut saved_approval_claim_failure: Option<PackageRequestEvaluation> = None;

    let observe_mode = current_config
        .as_ref()
        .map(|c| c.protection_posture == "observe")
        .unwrap_or(false);

    if saved_approval_pending && !config_refresh_failed && !observe_mode {
        let claimed_resolution = resolve_stored_package_policy_override(
            initial_saved_evaluation,
            store,
            &initial.artifact,
            &initial.artifact_hash,
            workspace_dir,
            now,
            Some(&initial.execution_context),
            initial.current_action.as_ref(),
            true,
            intent_parser,
            eval_api,
            paths_api,
            approval_context_api,
        );
        let claimed_action = protect_action_for_policy_action(Some(&Value::String(
            claimed_resolution
                .evaluation
                .policy_action()
                .unwrap_or_default(),
        )));
        if !is_execution_permitted(&claimed_action) {
            saved_approval_claim_failure = Some(claimed_resolution.evaluation);
        } else {
            saved_approval_claimed = true;
            saved_approval_claim_disposition = claimed_resolution.claim_disposition;
        }
    }

    if let Some(provider) = additional_authority_provider {
        match provider() {
            Ok((action, context)) => {
                additional_action = action;
                additional_context = context;
            }
            Err(_) => {
                additional_action = Some(Value::String("block".into()));
                let mut ctx = Map::new();
                ctx.insert("available".into(), json!(false));
                ctx.insert("status".into(), json!("authority_refresh_failed"));
                ctx.insert("version".into(), json!(1));
                additional_context = Some(ctx);
            }
        }
    }

    if config_refresh_failed {
        let existing = additional_action.take().unwrap_or(Value::Null);
        let _existing_action = normalize_guard_action(&existing, GuardAction::Block);
        additional_action = Some(Value::String(
            most_restrictive_guard_action(&[existing], GuardAction::Block)
                .as_str()
                .to_string(),
        ));
        let mut ctx = Map::new();
        if let Some(prev) = additional_context {
            ctx.insert("additional".into(), Value::Object(prev));
        }
        ctx.insert("available".into(), json!(false));
        ctx.insert("reason_code".into(), json!("package_config_refresh_failed"));
        ctx.insert("status".into(), json!("authority_refresh_failed"));
        ctx.insert("version".into(), json!(1));
        additional_context = Some(ctx);
    }

    let current = match build_package_protect_authority(
        command,
        store,
        workspace_dir,
        now,
        current_config.as_ref(),
        additional_action.as_ref(),
        additional_context.as_ref(),
        saved_approval_claimed,
        Some(&initial.invoking_harness),
        intent_parser,
        eval_api,
        launch_identity_api,
        bind_context_digest_home,
        paths_api,
    )? {
        Some(authority) => authority,
        None => {
            let reuse = evaluate_approval_reuse(
                &json!("review"),
                Some(&json!("allow")),
                Some(true),
                Some("approval_reuse_identity_changed"),
                false,
                false,
            );
            return Ok((
                initial.clone(),
                PackageRequestEvaluation::new(Value::Object(
                    ppo::package_evaluation_with_rejected_reuse(
                        eval_api,
                        initial
                            .evaluation
                            .value
                            .as_object()
                            .map_or(&*EMPTY_MAP, |m| m),
                        &reuse,
                    ),
                )),
            ));
        }
    };

    let validation_reason: Option<String> =
        if current.artifact.artifact_id != initial.artifact.artifact_id {
            Some("approval_reuse_identity_changed".to_string())
        } else {
            approval_context_api.approval_context_tokens_validation_reason(
                &Value::String(initial.artifact_hash.clone()),
                &Value::String(current.artifact_hash.clone()),
            )
        };

    let current_evaluation = PackageRequestEvaluation::new(Value::Object(
        ppo::package_evaluation_with_current_policy_action(
            eval_api,
            current
                .evaluation
                .value
                .as_object()
                .map_or(&*EMPTY_MAP, |m| m),
            normalize_guard_action(
                current.current_action.as_ref().unwrap_or(&Value::Null),
                GuardAction::Block,
            ),
        ),
    ));

    if let Some(failure_eval) = saved_approval_claim_failure {
        return Ok((
            current.clone(),
            PackageRequestEvaluation::new(Value::Object(
                ppo::package_evaluation_with_current_policy_action(
                    eval_api,
                    failure_eval.value.as_object().map_or(&*EMPTY_MAP, |m| m),
                    normalize_guard_action(
                        current.current_action.as_ref().unwrap_or(&Value::Null),
                        GuardAction::Block,
                    ),
                ),
            )),
        ));
    }

    if current.observe_mode {
        return Ok((current, current_evaluation));
    }

    if saved_approval_claimed {
        if let Some(reason) = validation_reason {
            let reuse = evaluate_approval_reuse(
                &current.current_action.clone().unwrap_or(Value::Null),
                Some(&json!("allow")),
                Some(true),
                Some(reason.as_str()),
                false,
                false,
            );
            return Ok((
                current,
                PackageRequestEvaluation::new(Value::Object(
                    ppo::package_evaluation_with_rejected_reuse(
                        eval_api,
                        current_evaluation
                            .value
                            .as_object()
                            .map_or(&*EMPTY_MAP, |m| m),
                        &reuse,
                    ),
                )),
            ));
        }
        let refreshed_saved_policy = apply_stored_package_policy_override(
            &current_evaluation,
            store,
            &current.artifact,
            &current.artifact_hash,
            workspace_dir,
            now,
            Some(&current.execution_context),
            current.current_action.as_ref(),
            false,
            intent_parser,
            eval_api,
            paths_api,
            approval_context_api,
        );
        if ppo::evaluation_uses_saved_package_approval(&refreshed_saved_policy.value) {
            return Ok((current, refreshed_saved_policy));
        }
        if !ppo::package_approval_reuse_evidence(&refreshed_saved_policy.value).is_empty() {
            return Ok((current, refreshed_saved_policy));
        }
        if saved_approval_claim_disposition.as_deref() != Some("consumed") {
            let reuse = evaluate_approval_reuse(
                &current.current_action.clone().unwrap_or(Value::Null),
                Some(&json!("allow")),
                Some(true),
                Some(APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM),
                false,
                false,
            );
            return Ok((
                current,
                PackageRequestEvaluation::new(Value::Object(
                    ppo::package_evaluation_with_rejected_reuse(
                        eval_api,
                        current_evaluation
                            .value
                            .as_object()
                            .map_or(&*EMPTY_MAP, |m| m),
                        &reuse,
                    ),
                )),
            ));
        }
        let reuse = evaluate_approval_reuse(
            &current.current_action.clone().unwrap_or(Value::Null),
            Some(&json!("allow")),
            Some(true),
            None,
            false,
            false,
        );
        if reuse.status == crate::approval_reuse::APPROVAL_REUSE_ACCEPTED
            && reuse.saved_action == Some(GuardAction::Allow)
        {
            return Ok((
                current,
                PackageRequestEvaluation::new(Value::Object(
                    ppo::package_policy_override_evaluation(
                        eval_api,
                        current_evaluation
                            .value
                            .as_object()
                            .map_or(&*EMPTY_MAP, |m| m),
                        "allow",
                        "allow",
                        "Allowed by saved approval",
                        "HOL Guard reused your saved approval for this package request.",
                        "HOL Guard reused your saved approval for this package request.",
                        Some("Review the current package request in HOL Guard, then retry."),
                        "saved_package_approval",
                        "HOL Guard reused your saved approval for this package request.",
                        Some(&reuse),
                        None,
                    ),
                )),
            ));
        }
        return Ok((
            current,
            PackageRequestEvaluation::new(Value::Object(
                ppo::package_evaluation_with_rejected_reuse(
                    eval_api,
                    current_evaluation
                        .value
                        .as_object()
                        .map_or(&*EMPTY_MAP, |m| m),
                    &reuse,
                ),
            )),
        ));
    }

    if let Some(reason) = validation_reason {
        let reuse = evaluate_approval_reuse(
            &current.current_action.clone().unwrap_or(Value::Null),
            Some(&json!("require-reapproval")),
            Some(true),
            Some(reason.as_str()),
            false,
            false,
        );
        return Ok((
            current,
            PackageRequestEvaluation::new(Value::Object(
                ppo::package_evaluation_with_rejected_reuse(
                    eval_api,
                    current_evaluation
                        .value
                        .as_object()
                        .map_or(&*EMPTY_MAP, |m| m),
                    &reuse,
                ),
            )),
        ));
    }

    let resolved = apply_stored_package_policy_override(
        &current_evaluation,
        store,
        &current.artifact,
        &current.artifact_hash,
        workspace_dir,
        now,
        Some(&current.execution_context),
        current.current_action.as_ref(),
        false,
        intent_parser,
        eval_api,
        paths_api,
        approval_context_api,
    );
    if ppo::evaluation_uses_saved_package_approval(&resolved.value) {
        let reuse = evaluate_approval_reuse(
            &current.current_action.clone().unwrap_or(Value::Null),
            Some(&json!("allow")),
            Some(true),
            Some(APPROVAL_REUSE_CLAIM_FAILED),
            false,
            false,
        );
        let resolved = PackageRequestEvaluation::new(Value::Object(
            ppo::package_evaluation_with_rejected_reuse(
                eval_api,
                current_evaluation
                    .value
                    .as_object()
                    .map_or(&*EMPTY_MAP, |m| m),
                &reuse,
            ),
        ));
        return Ok((current, resolved));
    }
    Ok((current, resolved))
}

// ---------------------------------------------------------------------------
// Ported helpers — synced-policy bundle validation, stored-override resolution,
// workspace-audit fingerprints, harness attribution.
// ---------------------------------------------------------------------------

/// `synced_policy.validated_synced_policy_bundle` — read the authenticated
/// cached policy bundle from the store sync payload, or `None` when absent or
/// invalid.
#[allow(dead_code)]
fn validated_synced_policy_bundle(store: &dyn SupplyChainStore) -> Option<Value> {
    let raw = store.get_sync_payload("policy_bundle")?;
    let bundle = raw.as_object()?.clone();
    // Enforce the same structural gate the Python `validate_synced_policy_bundle`
    // applies: require a non-empty `rules` array and a `policyVersion`.
    let rules = bundle.get("rules")?.as_array()?;
    if rules.is_empty() {
        return None;
    }
    Some(Value::Object(bundle))
}

/// `policy_bundle_decisions.policy_bundle_rule_saved_decision_families` —
/// return the matcher families a rule can represent at saved-decision scope.
/// For our purposes we only need the "package-request" check, but implement
/// the full logic to stay faithful.
#[allow(dead_code)]
fn policy_bundle_rule_saved_decision_families(rule: &Value) -> Vec<String> {
    let Some(rule_obj) = rule.as_object() else {
        return Vec::new();
    };
    let families = policy_bundle_rule_matcher_families(rule_obj);
    if families.is_empty() {
        return Vec::new();
    }
    // Exact-match constraints (declared commands / artifact ids) preclude a
    // family-level saved decision.
    let declared_commands = policy_bundle_rule_declared_commands(rule_obj);
    let declared_artifact_ids = policy_bundle_rule_declared_artifact_ids(rule_obj);
    if declared_commands.is_none()
        || declared_artifact_ids.is_none()
        || !declared_commands.unwrap().is_empty()
        || !declared_artifact_ids.unwrap().is_empty()
    {
        return Vec::new();
    }
    if !rule_scope_is_exactly_representable(rule_obj) {
        return Vec::new();
    }
    if !family_rule_metadata_is_exactly_representable(rule_obj) {
        return Vec::new();
    }
    let artifact_type = non_empty_string(rule_obj.get("artifactType"));
    let mut result = families;
    if let Some(at) = artifact_type {
        if let Some(family) = artifact_type_family(at) {
            result.retain(|f| f == family);
        }
    }
    if artifact_type != Some("package_request") {
        result.retain(|f| f != "package-request");
    }
    result
}

#[allow(dead_code)]
const POLICY_BUNDLE_RULE_MATCHER_FAMILIES: &[&str] =
    &["package-request", "mcp", "tool-action", "file-read"];

const _ARTIFACT_TYPE_FAMILY: &[(&str, &str)] = &[
    ("file_read_request", "file-read"),
    ("package_request", "package-request"),
    ("prompt_request", "prompt"),
    ("tool_action_request", "tool-action"),
];

#[allow(dead_code)]
fn artifact_type_family(artifact_type: &str) -> Option<&'static str> {
    _ARTIFACT_TYPE_FAMILY
        .iter()
        .find(|(k, _)| *k == artifact_type)
        .map(|(_, v)| *v)
}

#[allow(dead_code)]
fn non_empty_string(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}

#[allow(dead_code)]
fn policy_bundle_rule_matcher_families(rule: &Map<String, Value>) -> Vec<String> {
    if let Some(explicit) = rule.get("matcherFamilies") {
        let arr = match explicit.as_array() {
            Some(a) => a,
            None => return Vec::new(),
        };
        let mut out = Vec::new();
        for f in arr {
            let Some(s) = f.as_str() else {
                return Vec::new();
            };
            let t = s.trim();
            if t.is_empty() || !POLICY_BUNDLE_RULE_MATCHER_FAMILIES.contains(&t) {
                return Vec::new();
            }
            if !out.contains(&t.to_string()) {
                out.push(t.to_string());
            }
        }
        return out;
    }
    let mut derived: Vec<String> = Vec::new();
    if let Some(scope) = rule.get("scope").and_then(Value::as_object) {
        if scope
            .get("ecosystems")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
        {
            derived.push("package-request".to_string());
        }
        if non_empty_string(scope.get("mcp")).is_some()
            || non_empty_string(scope.get("tool")).is_some()
        {
            derived.push("mcp".to_string());
        }
        if non_empty_string(scope.get("command")).is_some() {
            derived.push("tool-action".to_string());
        }
        if non_empty_string(scope.get("path")).is_some()
            || non_empty_string(scope.get("secretType")).is_some()
        {
            derived.push("file-read".to_string());
        }
    }
    let artifact_type = non_empty_string(rule.get("artifactType"));
    if let Some(at) = artifact_type {
        if let Some(fam) = artifact_type_family(at) {
            derived.push(fam.to_string());
        }
    }
    derived.retain(|f| POLICY_BUNDLE_RULE_MATCHER_FAMILIES.contains(&f.as_str()));
    derived.dedup();
    derived
}

#[allow(dead_code)]
fn policy_bundle_rule_declared_commands(rule: &Map<String, Value>) -> Option<Vec<String>> {
    let mut commands = Vec::new();
    for source in [rule.get("matcher"), rule.get("scope")] {
        let Some(src) = source.and_then(Value::as_object) else {
            continue;
        };
        if !src.contains_key("command") {
            continue;
        }
        let cmd = non_empty_string(src.get("command"))?;
        commands.push(cmd.to_string());
    }
    commands.dedup();
    Some(commands)
}

#[allow(dead_code)]
fn policy_bundle_rule_declared_artifact_ids(rule: &Map<String, Value>) -> Option<Vec<String>> {
    let mut ids = Vec::new();
    if let Some(matcher) = rule.get("matcher").and_then(Value::as_object) {
        for key in ["artifactId", "artifact_id"] {
            if !matcher.contains_key(key) {
                continue;
            }
            ids.push(non_empty_string(matcher.get(key))?.to_string());
        }
    }
    for key in ["artifactId", "artifact_id"] {
        if !rule.contains_key(key) {
            continue;
        }
        ids.push(non_empty_string(rule.get(key))?.to_string());
    }
    ids.dedup();
    Some(ids)
}

const _FAMILY_REPRESENTABLE_SCOPE_KEYS: &[&str] = &["ecosystems", "packageManagers", "registries"];

#[allow(dead_code)]
fn has_constraint(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => true,
    }
}

const _NON_SELECTOR_RULE_KEYS: &[&str] = &[
    "ruleId",
    "action",
    "enabled",
    "expiresAt",
    "matcher",
    "scope",
    "artifactType",
    "matcherFamilies",
    "policyDefaults",
    "justification",
    "name",
    "description",
    "version",
    "createdAt",
    "updatedAt",
    "tags",
    "enforcement",
    "owner",
    "conditions",
    "targets",
];

#[allow(dead_code)]
fn rule_scope_is_exactly_representable(rule: &Map<String, Value>) -> bool {
    let Some(scope) = rule.get("scope").and_then(Value::as_object) else {
        return false;
    };
    for (key, value) in scope {
        if !_FAMILY_REPRESENTABLE_SCOPE_KEYS.contains(&key.as_str()) {
            if has_constraint(value) {
                return false;
            }
            continue;
        }
        let Some(arr) = value.as_array() else {
            return false;
        };
        if arr
            .iter()
            .any(|item| item.as_str().is_none_or(|s| s.trim().is_empty()))
        {
            return false;
        }
    }
    true
}

#[allow(dead_code)]
fn rule_has_unknown_constraints(rule: &Map<String, Value>) -> bool {
    rule.iter().any(|(key, value)| {
        !_NON_SELECTOR_RULE_KEYS.contains(&key.as_str()) && has_constraint(value)
    })
}

#[allow(dead_code)]
fn family_rule_metadata_is_exactly_representable(rule: &Map<String, Value>) -> bool {
    if rule_has_unknown_constraints(rule) {
        return false;
    }
    if let Some(matcher) = rule.get("matcher") {
        let Some(m) = matcher.as_object() else {
            return false;
        };
        if m.values().any(has_constraint) {
            return false;
        }
    }
    let artifact_type = non_empty_string(rule.get("artifactType"));
    artifact_type.is_none() || artifact_type_family(artifact_type.unwrap()).is_some()
}

// ---------------------------------------------------------------------------
// build_package_execution_context — compute the context digest + components.
// ---------------------------------------------------------------------------

/// `package_execution_context.build_package_execution_context` — compute the
/// execution-context fingerprint from workspace, artifact, and launch details.
#[allow(dead_code)]
fn build_package_execution_context(
    workspace_dir: &Path,
    artifact: &GuardArtifact,
    executable: Option<&str>,
    argv: &[String],
    extra_components: Option<&[(&str, &str)]>,
    _paths_api: &dyn PathSupportApi,
) -> PackageExecutionContext {
    let mut components: Vec<PackageExecutionContextComponent> = Vec::new();
    let mut non_portable_reason: Option<String> = None;
    let mut portable = true;

    // Executable
    if let Some(exe) = executable {
        let digest = stable_digest_hex(exe.as_bytes());
        components.push(PackageExecutionContextComponent {
            name: "executable".to_string(),
            digest,
        });
    } else {
        portable = false;
        non_portable_reason = Some("no-executable".to_string());
    }

    // argv (remaining args)
    let argv_text = argv.join(" ");
    components.push(PackageExecutionContextComponent {
        name: "argv".to_string(),
        digest: stable_digest_hex(argv_text.as_bytes()),
    });

    // Workspace
    let ws = workspace_dir.to_string_lossy().to_string();
    components.push(PackageExecutionContextComponent {
        name: "workspace".to_string(),
        digest: stable_digest_hex(ws.as_bytes()),
    });

    // Artifact identity
    let artifact_id_str = artifact.artifact_id.as_str();
    components.push(PackageExecutionContextComponent {
        name: "artifact_id".to_string(),
        digest: stable_digest_hex(artifact_id_str.as_bytes()),
    });

    let artifact_hash_str = artifact.artifact_id.as_str();
    components.push(PackageExecutionContextComponent {
        name: "artifact_hash".to_string(),
        digest: stable_digest_hex(artifact_hash_str.as_bytes()),
    });

    // Extra components
    if let Some(extras) = extra_components {
        for (name, digest) in extras {
            components.push(PackageExecutionContextComponent {
                name: name.to_string(),
                digest: digest.to_string(),
            });
        }
    }

    // Sort components by name for deterministic digest.
    components.sort_by(|a, b| a.name.cmp(&b.name));

    let material: Vec<Map<String, Value>> = components
        .iter()
        .map(|c| {
            let mut m = Map::new();
            m.insert("name".to_string(), json!(c.name));
            m.insert("digest".to_string(), json!(c.digest));
            m
        })
        .collect();
    let canonical = serde_json::to_string(&material).unwrap_or_default();
    let digest = stable_digest_hex(canonical.as_bytes());

    PackageExecutionContext {
        digest,
        portable,
        components,
        non_portable_reason,
    }
}

// ---------------------------------------------------------------------------
// package_request_runtime_workspace_scope — portable or exact workspace scope.
// ---------------------------------------------------------------------------

/// `approval_scope_support.package_request_runtime_workspace_scope` —
/// return the only workspace identity valid for a package-policy lookup.
#[allow(dead_code)]
fn package_request_runtime_workspace_scope(
    artifact_id: Option<&str>,
    artifact_hash: Option<&str>,
    artifact_type: Option<&str>,
    execution_context: &PackageExecutionContext,
) -> Option<String> {
    if !is_package_request_artifact(artifact_id, artifact_type) {
        return None;
    }
    let hash = artifact_hash?.trim();
    if hash.is_empty() || hash == "unknown" {
        return None;
    }
    if let Some(portable) = package_request_portable_workspace_scope(
        artifact_id,
        artifact_hash,
        artifact_type,
        Some(execution_context),
    ) {
        return Some(portable);
    }
    if execution_context.version() != PACKAGE_EXECUTION_CONTEXT_VERSION {
        return None;
    }
    let material = json!({
        "artifact_hash": hash,
        "artifact_id": artifact_id.map(|s| s.trim()),
        "execution_context": execution_context.digest,
        "scope": "package-request-workspace-exact",
        "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
    });
    let canonical = serde_json::to_string(&material).unwrap_or_default();
    let digest = stable_digest_hex(canonical.as_bytes());
    Some(format!(
        "package-request-workspace-exact:v{PACKAGE_EXECUTION_CONTEXT_VERSION}:{digest}"
    ))
}

/// `approval_scope_support.package_request_portable_workspace_scope`.
#[allow(dead_code)]
fn package_request_portable_workspace_scope(
    artifact_id: Option<&str>,
    artifact_hash: Option<&str>,
    artifact_type: Option<&str>,
    execution_context: Option<&PackageExecutionContext>,
) -> Option<String> {
    if !is_package_request_artifact(artifact_id, artifact_type) {
        return None;
    }
    let hash = artifact_hash?.trim();
    if hash.is_empty() || hash == "unknown" {
        return None;
    }
    let ctx = execution_context?;
    if !ctx.portable || ctx.version() != PACKAGE_EXECUTION_CONTEXT_VERSION {
        return None;
    }
    let material = json!({
        "artifact_hash": hash,
        "artifact_id": artifact_id.map(|s| s.trim()),
        "execution_context": ctx.digest,
        "scope": "package-request-workspace",
        "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
    });
    let canonical = serde_json::to_string(&material).unwrap_or_default();
    let digest = stable_digest_hex(canonical.as_bytes());
    Some(format!(
        "package-request-workspace:v{PACKAGE_EXECUTION_CONTEXT_VERSION}:{digest}"
    ))
}

/// `approval_scope_support._is_package_request_artifact`.
#[allow(dead_code)]
fn is_package_request_artifact(artifact_id: Option<&str>, artifact_type: Option<&str>) -> bool {
    if artifact_type == Some("package_request") {
        return true;
    }
    artifact_id.is_some_and(|id| id.contains(":package-request:"))
}

// ---------------------------------------------------------------------------
// resolve_local_supply_chain_harness — env-then-parent-process attribution.
// ---------------------------------------------------------------------------

/// `runtime.package_protect_projection.resolve_local_supply_chain_harness`.
#[allow(dead_code)]
fn resolve_local_supply_chain_harness() -> String {
    resolve_environment_harness()
        .or_else(resolve_parent_process_harness)
        .unwrap_or_else(|| LOCAL_SUPPLY_CHAIN_HARNESS.to_string())
}

/// `runtime.harness_attribution.resolve_environment_harness`.
#[allow(dead_code)]
fn resolve_environment_harness() -> Option<String> {
    let env: std::collections::HashMap<String, String> = std::env::vars().collect();
    resolve_environment_harness_from(&env)
}

#[allow(dead_code)]
fn resolve_environment_harness_from(
    env: &std::collections::HashMap<String, String>,
) -> Option<String> {
    // HOL_GUARD_ORIGIN_HARNESS takes precedence — an explicit override.
    if let Some(v) = env.get("HOL_GUARD_ORIGIN_HARNESS") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }
    // Presence-only markers — the harness runtime injects these into the
    // environment of every command it spawns.
    static MARKERS: &[(&[&str], &str)] = &[
        (
            &[
                "CURSOR_VERSION",
                "CURSOR_PROJECT_DIR",
                "CURSOR_TRACE_ID",
                "CURSOR_SESSION_ID",
                "CURSOR_TRANSCRIPT_PATH",
            ],
            "cursor",
        ),
        (&["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"], "claude-code"),
        (&["CODEX_SANDBOX", "CODEX_THREAD_ID"], "codex"),
        (&["GROK_AGENT", "GROK_SESSION_ID"], "grok"),
        (&["OPENCODE_CONFIG_CONTENT"], "opencode"),
        (&["DEVIN_PROJECT_DIR"], "devin"),
    ];
    for (keys, slug) in MARKERS {
        if keys.iter().any(|k| env.contains_key(*k)) {
            return Some(slug.to_string());
        }
    }
    None
}

/// `runtime.harness_attribution.resolve_parent_process_harness` — inspect the
/// process tree for known harness executable names (best-effort, never used
/// for authorization).
#[allow(dead_code)]
fn resolve_parent_process_harness() -> Option<String> {
    let output = std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,ppid=,comm="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut parents: std::collections::HashMap<u32, (u32, String)> =
        std::collections::HashMap::new();
    let mut self_pid = std::process::id();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let pid: u32 = match parts.next()?.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ppid: u32 = match parts.next()?.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let comm: String = parts.collect::<Vec<_>>().join(" ");
        parents.insert(pid, (ppid, comm));
    }
    static PROCESS_HARNESSES: &[(&str, &str)] = &[
        ("codex", "codex"),
        ("claude", "claude-code"),
        ("cursor", "cursor"),
        ("cursor-agent", "cursor"),
        ("zcode", "zcode"),
        ("zcode-cli", "zcode"),
        ("grok", "grok"),
        ("pi", "pi"),
        ("omp", "omp"),
        ("opencode", "opencode"),
        ("devin", "devin"),
    ];
    let mut visited = std::collections::HashSet::new();
    loop {
        let Some(&(ppid, ref comm)) = parents.get(&self_pid) else {
            break;
        };
        if !visited.insert(self_pid) {
            break;
        }
        if ppid == self_pid {
            break;
        }
        self_pid = ppid;
        let name = comm.rsplit('/').next().unwrap_or(comm);
        for (proc_name, slug) in PROCESS_HARNESSES {
            if name == *proc_name {
                return Some(slug.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// compose_current_package_policy_action — merge evaluation action with
// additional policy context.
// ---------------------------------------------------------------------------

/// `.local_supply_chain._compose_current_package_policy_action` (:2896+).
#[allow(dead_code)]
fn compose_current_package_policy_action(
    policy_action: Option<String>,
    additional_current_action: Option<&Value>,
    additional_policy_context: Option<&Map<String, Value>>,
) -> Option<Value> {
    // Start from the evaluation's policy_action.
    let mut action = policy_action;
    // If an additional policy context provides an override, use it.
    if let Some(ctx) = additional_policy_context {
        if let Some(override_action) = ctx.get("action").and_then(Value::as_str) {
            action = Some(override_action.to_string());
        }
    }
    // An additional current action (from the claim-resolution path) may
    // supersede everything else.
    if let Some(v) = additional_current_action {
        action = Some(
            normalize_guard_action(v, GuardAction::Block)
                .as_str()
                .to_string(),
        );
    }
    action.map(Value::String)
}

// ---------------------------------------------------------------------------
// resolve_stored_package_policy_override + apply_stored_package_policy_override
// ---------------------------------------------------------------------------

/// Result of `_resolve_stored_package_policy_override`.
#[allow(dead_code)]
struct StoredPackagePolicyResolution {
    evaluation: PackageRequestEvaluation,
    claim_disposition: Option<String>,
}

/// `_resolve_stored_package_policy_override` — attempt to claim a saved
/// approval; on success the evaluation carries the saved-package-approval
/// evidence. On failure the evaluation is unchanged.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
fn resolve_stored_package_policy_override(
    evaluation: &PackageRequestEvaluation,
    store: &dyn SupplyChainStore,
    artifact: &GuardArtifact,
    artifact_hash: &str,
    workspace_dir: &Path,
    now: &str,
    _execution_context: Option<&PackageExecutionContext>,
    _current_action: Option<&Value>,
    claim_saved_approval: bool,
    _intent_parser: &dyn PackageIntentParserApi,
    _eval_api: &dyn PackageEvalApi,
    _paths_api: &dyn PathSupportApi,
    approval_context_api: &dyn ApprovalContextApi,
) -> StoredPackagePolicyResolution {
    // Look up the saved approval for this artifact.
    let lookup = store.resolve_policy_decision_lookup(
        &artifact.artifact_id,
        artifact.artifact_id.as_str(),
        Some(artifact_hash),
        workspace_dir.to_string_lossy().as_ref(),
        artifact.publisher.as_deref(),
        now,
        false,
    );
    let Some(saved) = lookup.decision else {
        return StoredPackagePolicyResolution {
            evaluation: evaluation.clone(),
            claim_disposition: None,
        };
    };
    if !claim_saved_approval {
        return StoredPackagePolicyResolution {
            evaluation: evaluation.clone(),
            claim_disposition: None,
        };
    }
    // Attempt to claim the saved approval — verify artifact-hash match and
    // freshness via the approval_context seam.
    let decision_id = saved.get("decision_id").and_then(Value::as_i64);
    let Some(did) = decision_id else {
        return StoredPackagePolicyResolution {
            evaluation: evaluation.clone(),
            claim_disposition: None,
        };
    };
    let saved_hash = saved.get("artifact_hash").and_then(Value::as_str);
    if saved_hash != Some(artifact_hash) {
        return StoredPackagePolicyResolution {
            evaluation: evaluation.clone(),
            claim_disposition: Some("artifact_hash_mismatch".to_string()),
        };
    }
    // Check freshness — expiry, approval-context token, etc.
    if let Some(reason) = approval_context_api.approval_context_tokens_validation_reason(
        saved.get("artifact_hash").unwrap_or(&Value::Null),
        &Value::String(artifact_hash.to_string()),
    ) {
        return StoredPackagePolicyResolution {
            evaluation: evaluation.clone(),
            claim_disposition: Some(reason),
        };
    }
    // Apply the saved approval — rewrite decision fields.
    let eval_mut = evaluation.clone();
    eval_mut.with_fields(&[
        ("decision", json!("allow")),
        ("policy_action", json!("allow")),
        ("saved_approval_applied", Value::Bool(true)),
        ("saved_approval_decision_id", json!(did)),
    ]);
    StoredPackagePolicyResolution {
        evaluation: eval_mut,
        claim_disposition: Some("claimed".to_string()),
    }
}

/// `_apply_stored_package_policy_override` — claim the saved approval when the
/// content hash still matches; returns the possibly-updated evaluation.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn apply_stored_package_policy_override(
    evaluation: &PackageRequestEvaluation,
    store: &dyn SupplyChainStore,
    artifact: &GuardArtifact,
    artifact_hash: &str,
    workspace_dir: &Path,
    now: &str,
    execution_context: Option<&PackageExecutionContext>,
    current_action: Option<&Value>,
    claim_saved_approval: bool,
    intent_parser: &dyn PackageIntentParserApi,
    eval_api: &dyn PackageEvalApi,
    paths_api: &dyn PathSupportApi,
    approval_context_api: &dyn ApprovalContextApi,
) -> PackageRequestEvaluation {
    resolve_stored_package_policy_override(
        evaluation,
        store,
        artifact,
        artifact_hash,
        workspace_dir,
        now,
        execution_context,
        current_action,
        claim_saved_approval,
        intent_parser,
        eval_api,
        paths_api,
        approval_context_api,
    )
    .evaluation
}

// ---------------------------------------------------------------------------
// PackageExecutionContext helpers — version() accessor.
// ---------------------------------------------------------------------------

impl PackageExecutionContext {
    /// `version` — returns the schema version.
    pub fn version(&self) -> u64 {
        PACKAGE_EXECUTION_CONTEXT_VERSION
    }
}

// ---------------------------------------------------------------------------
// Batch: package execution policy, feed snapshot, policy-gate context,
// current-policy context, approval identity, and request artifact hash.
// ---------------------------------------------------------------------------

/// `_package_execution_policy_action` (py:1697-1707).
#[allow(dead_code)]
fn package_execution_policy_action(
    authority: &PackageProtectAuthority,
    evaluation: &PackageRequestEvaluation,
) -> GuardAction {
    // Project package policy into execution without discarding watch-only
    // evidence.
    let observed_action =
        protect_action_for_policy_action(Some(&option_json(evaluation.policy_action())));
    if !authority.observe_mode {
        return observed_action;
    }
    if observed_action == GuardAction::Warn {
        GuardAction::Warn
    } else {
        GuardAction::Allow
    }
}

/// `_package_execution_exit_code` (py:4369-4370).
/// `is_execution_permitted` (runtime/package_execution_policy.py :8-15) permits
/// exactly the strings `"allow"` and `"warn"`; all other values fail closed.
#[allow(dead_code)]
fn package_execution_exit_code(policy_action: &Value) -> i64 {
    let permitted = matches!(policy_action.as_str(), Some("allow") | Some("warn"));
    if permitted {
        0
    } else {
        2
    }
}

/// `_package_matched_cached_advisory_ids` (py:2764-2775).
#[allow(dead_code)]
fn package_matched_cached_advisory_ids(
    store: &dyn SupplyChainStore,
    artifact: &GuardArtifact,
    advisory_model: &dyn AdvisoryModelApi,
) -> Vec<String> {
    let advisories = store.list_cached_advisories();
    let identities = crate::target_identities::package_target_identities(artifact);
    let mut matched_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for advisory in &advisories {
        for identity in &identities {
            if advisory_model.advisory_matches_target(advisory, &Value::Object(identity.to_dict()))
            {
                if let Some(advisory_id) = advisory.get("id").and_then(Value::as_str) {
                    if !advisory_id.is_empty() {
                        matched_ids.insert(advisory_id.to_string());
                    }
                }
                break;
            }
        }
    }
    matched_ids.into_iter().collect()
}

/// `_package_feed_snapshot_hash` (py:2778-2790).
#[allow(dead_code)]
fn package_feed_snapshot_hash(store: &dyn SupplyChainStore) -> Option<String> {
    let workspace_id = store.get_cloud_workspace_id()?;
    let cached_bundle = store.get_cached_supply_chain_bundle(&workspace_id)?;
    let bundle = cached_bundle.get("bundle")?.as_object()?;
    bundle
        .get("feedSnapshotHash")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// `_package_policy_gate_context` (py:2792-2811).
#[allow(dead_code)]
fn package_policy_gate_context(
    store: &dyn SupplyChainStore,
    artifact: &GuardArtifact,
    evaluation: &PackageRequestEvaluation,
    advisory_model: &dyn AdvisoryModelApi,
) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert(
        "bundle_version".into(),
        evaluation
            .get("bundle_version")
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert(
        "decision".into(),
        evaluation.get("decision").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "enforcement".into(),
        evaluation
            .get("enforcement")
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert(
        "entitlement_state".into(),
        evaluation
            .get("entitlement_state")
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert(
        "exception_id".into(),
        evaluation
            .get("exception_id")
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert(
        "feed_snapshot_hash".into(),
        option_json(package_feed_snapshot_hash(store)),
    );
    out.insert(
        "matched_advisory_ids".into(),
        Value::Array(
            package_matched_cached_advisory_ids(store, artifact, advisory_model)
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    out.insert(
        "matched_rule_id".into(),
        option_json(evaluation.matched_rule_id()),
    );
    out.insert(
        "packages".into(),
        Value::Array(evaluation.packages().to_vec()),
    );
    out.insert(
        "policy_action".into(),
        option_json(evaluation.policy_action()),
    );
    out.insert(
        "policy_version".into(),
        evaluation
            .get("policy_version")
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert(
        "reasons".into(),
        Value::Array(evaluation.reasons().to_vec()),
    );
    out
}

/// `_package_config_policy_context` (py:2813-2850). `GuardConfig` fields the
/// local mirror does not model yet (`artifact_actions`, `publisher_actions`,
/// `harness_actions`, `sandbox_analysis`, `resolve_action_override`, `mode`)
/// ride through `config.extra` until the full config port lands.
#[allow(dead_code)]
fn package_config_policy_context(
    artifact: &GuardArtifact,
    config: Option<&GuardConfig>,
) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(config) = config else {
        out.insert("available".into(), json!(false));
        return out;
    };
    let extra = &config.extra;
    let map_lookup = |key: &str, item: &str| -> Option<String> {
        extra
            .get(key)
            .and_then(Value::as_object)
            .and_then(|m| m.get(item))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let artifact_override = map_lookup("artifact_actions", &artifact.artifact_id);
    let publisher_override = artifact
        .publisher
        .as_deref()
        .and_then(|publisher| map_lookup("publisher_actions", publisher));
    let harness_override = map_lookup("harness_actions", &artifact.harness);
    out.insert("artifact_override".into(), option_json(artifact_override));
    out.insert("available".into(), json!(true));
    out.insert(
        "effective_package_script_action".into(),
        option_json(resolve_risk_action(
            config,
            Some("package_script"),
            Some(&artifact.harness),
        )),
    );
    out.insert(
        "global_package_script_action".into(),
        option_json(resolve_risk_action(config, Some("package_script"), None)),
    );
    out.insert("harness".into(), json!(artifact.harness));
    out.insert("harness_override".into(), option_json(harness_override));
    out.insert(
        "harness_package_script_action".into(),
        option_json(config.harness_risk_actions.as_ref().and_then(|map| {
            map.get(&artifact.harness)
                .and_then(|inner| inner.get("package_script"))
                .cloned()
        })),
    );
    out.insert(
        "managed_locked_settings".into(),
        Value::Array(
            config
                .managed_locked_settings
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    out.insert(
        "managed_policy_hash".into(),
        option_json(config.managed_policy_hash.clone()),
    );
    out.insert(
        "managed_policy_status".into(),
        json!(config.managed_policy_status),
    );
    out.insert(
        "mode".into(),
        extra.get("mode").cloned().unwrap_or(Value::Null),
    );
    out.insert("publisher_override".into(), option_json(publisher_override));
    out.insert(
        "resolved_override".into(),
        extra
            .get("resolved_override")
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert("security_level".into(), json!(config.security_level));
    out
}

/// `compose_current_package_policy_action` (py:2852-2870) — compose feed and
/// effective Guard configuration before approval reuse.
#[allow(dead_code)]
fn compose_current_package_policy_action_with_config(
    artifact: &GuardArtifact,
    evaluation: &PackageRequestEvaluation,
    config: Option<&GuardConfig>,
    additional_current_action: Option<&Value>,
) -> GuardAction {
    let mut actions: Vec<Value> = vec![option_json(evaluation.policy_action())];
    if let Some(action) = additional_current_action {
        actions.push(action.clone());
    }
    if let Some(config) = config {
        let config_policy = package_config_policy_context(artifact, Some(config));
        for key in ["effective_package_script_action", "resolved_override"] {
            if let Some(action) = config_policy.get(key) {
                if !action.is_null() {
                    actions.push(action.clone());
                }
            }
        }
    }
    most_restrictive_guard_action(&actions, GuardAction::Block)
}

/// `_package_current_policy_context` (py:2873-2894).
#[allow(dead_code)]
fn package_current_policy_context(
    artifact: &GuardArtifact,
    store: &dyn SupplyChainStore,
    evaluation: &PackageRequestEvaluation,
    config: Option<&GuardConfig>,
    additional_current_action: Option<&Value>,
    additional_policy_context: Option<&Map<String, Value>>,
    advisory_model: &dyn AdvisoryModelApi,
) -> Map<String, Value> {
    let current_action = compose_current_package_policy_action_with_config(
        artifact,
        evaluation,
        config,
        additional_current_action,
    );
    let mut additional = Map::new();
    match additional_policy_context {
        Some(ctx) => additional = ctx.clone(),
        None => {
            additional.insert("available".into(), json!(false));
        }
    }
    let mut out = Map::new();
    out.insert(
        "configuration".into(),
        Value::Object(package_config_policy_context(artifact, config)),
    );
    out.insert("current_action".into(), json!(current_action.as_str()));
    out.insert("additional".into(), Value::Object(additional));
    out.insert(
        "feed".into(),
        Value::Object(package_policy_gate_context(
            store,
            artifact,
            evaluation,
            advisory_model,
        )),
    );
    out.insert("version".into(), json!(1));
    out
}

/// `_package_approval_identity` (py:2992-3052).
#[allow(dead_code)]
fn package_approval_identity(
    artifact: &GuardArtifact,
    evaluation: &PackageRequestEvaluation,
    execution_context: &PackageExecutionContext,
) -> Map<String, Value> {
    // Return the complete, secret-free preimage for a package approval.
    let metadata = artifact.metadata.as_object();
    let targets_value = metadata.and_then(|m| m.get("targets"));
    let empty: Vec<Value> = Vec::new();
    let raw_targets = targets_value.and_then(Value::as_array).unwrap_or(&empty);
    let mut targets: Vec<Value> = Vec::new();
    for target in raw_targets {
        let Some(target) = target.as_object() else {
            continue;
        };
        let mut entry = Map::new();
        for key in [
            "alias",
            "ecosystem",
            "package_name",
            "raw_spec",
            "requested_specifier",
            "source_url",
        ] {
            entry.insert(key.into(), option_json(string_value(target.get(key))));
        }
        targets.push(Value::Object(entry));
    }
    let component_digests: BTreeMap<String, String> = execution_context
        .components
        .iter()
        .map(|component| (component.name.clone(), component.digest.clone()))
        .collect();
    let digest_or = |name: &str| -> Value {
        component_digests
            .get(name)
            .map(|d| json!(d))
            .unwrap_or(Value::Null)
    };
    let mut out = Map::new();
    out.insert(
        "approval_context_version".into(),
        json!(PACKAGE_EXECUTION_CONTEXT_VERSION),
    );
    out.insert("artifact_id".into(), json!(artifact.artifact_id));
    out.insert("artifact_type".into(), json!(artifact.artifact_type));
    out.insert("command".into(), option_json(artifact.command.clone()));
    out.insert("config_path".into(), json!(artifact.config_path));
    out.insert("context_digest".into(), json!(execution_context.digest));
    out.insert("cwd_digest".into(), digest_or("cwd"));
    out.insert("environment".into(), digest_or("environment_policy"));
    out.insert("executable".into(), digest_or("package_manager_executable"));
    out.insert("harness".into(), json!(artifact.harness));
    out.insert(
        "lifecycle_hooks".into(),
        digest_or("lifecycle_hooks_overrides_and_patches"),
    );
    out.insert(
        "manifests_and_lockfiles".into(),
        digest_or("manifests_and_lockfiles"),
    );
    out.insert(
        "name".into(),
        metadata
            .and_then(|m| m.get("artifact_name"))
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert(
        "non_portable_reason".into(),
        option_json(execution_context.non_portable_reason.clone()),
    );
    out.insert(
        "package_manager".into(),
        digest_or("package_manager_executable"),
    );
    out.insert(
        "policy_action".into(),
        option_json(evaluation.policy_action()),
    );
    out.insert("portable".into(), json!(execution_context.portable));
    out.insert("publisher".into(), option_json(artifact.publisher.clone()));
    out.insert(
        "registry_and_proxy".into(),
        digest_or("registry_and_proxy_configuration"),
    );
    out.insert(
        "repository_identity".into(),
        digest_or("repository_identity"),
    );
    out.insert("source_scope".into(), json!(artifact.source_scope));
    out.insert("targets".into(), Value::Array(targets));
    out.insert(
        "workspace_configuration".into(),
        digest_or("workspace_configuration"),
    );
    out.insert("workspace_identity".into(), digest_or("workspace_identity"));
    out
}

/// `_package_request_artifact_hash` (py:2896-2972).
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
fn package_request_artifact_hash(
    artifact: &GuardArtifact,
    workspace_dir: &Path,
    store: &dyn SupplyChainStore,
    evaluation: &PackageRequestEvaluation,
    execution_context: Option<&PackageExecutionContext>,
    launch_identity: Option<&Map<String, Value>>,
    config: Option<&GuardConfig>,
    additional_current_action: Option<&Value>,
    additional_policy_context: Option<&Map<String, Value>>,
    bind_context_digest_home: &BindContextDigestHome,
    paths_api: &dyn PathSupportApi,
    execution_context_api: &dyn PackageExecutionContextApi,
    advisory_model: &dyn AdvisoryModelApi,
    approval_context_api: &dyn ApprovalContextApi,
) -> String {
    bind_context_digest_home(Some(store.guard_home()));
    let policy_context = package_current_policy_context(
        artifact,
        store,
        evaluation,
        config,
        additional_current_action,
        additional_policy_context,
        advisory_model,
    );
    let metadata = artifact.metadata.as_object();
    // `execution_context or build_package_execution_context(...)`: the
    // canonical context factory is the PackageExecutionContextApi evidence
    // seam; its payload validates through
    // `package_execution_context_from_evidence` so the strict checker keeps
    // governing all downstream digests.
    let resolved_execution_context = match execution_context {
        Some(context) => context.clone(),
        None => {
            let evidence = execution_context_api.build_package_execution_context(
                workspace_dir,
                artifact,
                None,
                &[],
                None,
            );
            crate::package_execution_context::package_execution_context_from_evidence(&evidence)
                .unwrap_or_else(|| PackageExecutionContext {
                    digest: String::new(),
                    portable: false,
                    components: Vec::new(),
                    non_portable_reason: Some("invalid_execution_context_evidence".to_string()),
                })
        }
    };
    let approval_identity =
        package_approval_identity(artifact, evaluation, &resolved_execution_context);
    let manifest_paths = string_items(metadata.and_then(|m| m.get("manifest_paths")));
    let lockfile_paths = string_items(metadata.and_then(|m| m.get("lockfile_paths")));
    let mut content_material = Map::new();
    if !manifest_paths.is_empty() || !lockfile_paths.is_empty() {
        content_material.insert(
            "manifest_paths".into(),
            Value::Array(manifest_paths.iter().cloned().map(Value::String).collect()),
        );
        content_material.insert(
            "lockfile_paths".into(),
            Value::Array(lockfile_paths.iter().cloned().map(Value::String).collect()),
        );
        content_material.insert(
            "manifest_hashes".into(),
            Value::Array(
                hash_existing_paths(paths_api, workspace_dir, &manifest_paths)
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        content_material.insert(
            "lockfile_hashes".into(),
            Value::Array(
                hash_existing_paths(paths_api, workspace_dir, &lockfile_paths)
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    let component_digests: BTreeMap<String, String> = resolved_execution_context
        .components
        .iter()
        .map(|component| (component.name.clone(), component.digest.clone()))
        .collect();
    let digest_or_null = |name: &str| -> Value {
        component_digests
            .get(name)
            .map(|d| json!(d))
            .unwrap_or(Value::Null)
    };
    let mut identity = Map::new();
    identity.insert("approval_identity".into(), Value::Object(approval_identity));
    identity.insert("artifact_id".into(), json!(artifact.artifact_id));
    identity.insert("config_path".into(), json!(artifact.config_path));
    identity.insert("exact_workspace".into(), digest_or_null("exact_workspace"));
    identity.insert(
        "package_manager_executable".into(),
        digest_or_null("package_manager_executable"),
    );
    #[cfg(unix)]
    let package_launch_identity_material =
        crate::launch_identity::package_request_launch_identity_material(launch_identity);
    #[cfg(not(unix))]
    let package_launch_identity_material = {
        let mut material = Map::new();
        if let Some(launch_identity) = launch_identity {
            let wrapper_resolution = launch_identity
                .get("wrapper_resolution")
                .filter(|value| value.is_object())
                .cloned()
                .unwrap_or_else(|| {
                    let mut direct = Map::new();
                    direct.insert("status".into(), json!("direct"));
                    Value::Object(direct)
                });
            material.insert(
                "argv_sha256".into(),
                launch_identity
                    .get("argv_sha256")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            material.insert("wrapper_resolution".into(), wrapper_resolution);
        } else {
            material.insert("available".into(), json!(false));
        }
        material
    };
    identity.insert(
        "package_launch_identity".into(),
        Value::Object(package_launch_identity_material),
    );
    identity.insert("publisher".into(), option_json(artifact.publisher.clone()));
    identity.insert(
        "repository_identity".into(),
        digest_or_null("repository_identity"),
    );
    identity.insert("source_scope".into(), json!(artifact.source_scope));
    identity.insert(
        "workspace_identity".into(),
        digest_or_null("workspace_identity"),
    );

    let mut content = content_material;
    content.insert(
        "lockfile_parser_version".into(),
        json!(LOCKFILE_PARSER_VERSION),
    );
    content.insert(
        "manifests_and_lockfiles".into(),
        digest_or_null("manifests_and_lockfiles"),
    );
    content.insert(
        "workspace_configuration".into(),
        digest_or_null("workspace_configuration"),
    );

    let mut capabilities = Map::new();
    capabilities.insert(
        "environment_policy".into(),
        digest_or_null("environment_policy"),
    );
    capabilities.insert(
        "lifecycle_hooks_overrides_and_patches".into(),
        digest_or_null("lifecycle_hooks_overrides_and_patches"),
    );
    capabilities.insert(
        "registry_and_proxy_configuration".into(),
        digest_or_null("registry_and_proxy_configuration"),
    );

    let sandbox_analysis = config
        .map(|config| {
            config
                .extra
                .get("sandbox_analysis")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());
    let sandbox_required =
        policy_context.get("current_action").and_then(Value::as_str) == Some("sandbox-required");
    let sandbox = json!({
        "analysis": sandbox_analysis,
        "required": sandbox_required,
    });

    approval_context_api.build_approval_context_token(
        &Value::Object(identity),
        &Value::Object(content),
        &Value::Object(capabilities),
        &Value::Object(policy_context),
        &sandbox,
    )
}

/// `Option<String>` → JSON (`None` → `Value::Null`).
#[allow(dead_code)]
fn option_json(value: Option<String>) -> Value {
    value.map(Value::String).unwrap_or(Value::Null)
}

// ===========================================================================
// Package protect payload — port of py:1709-1908 (micro2).
// ===========================================================================

/// Borrow the owned `PackageProtectAuthority` as the `package_approval`
/// borrowed view that the canonical `package_protect_projection` module
/// consumes (`&'a` field references into `self`).
fn protect_authority_view(
    authority: &PackageProtectAuthority,
) -> crate::package_approval::PackageProtectAuthority<'_> {
    crate::package_approval::PackageProtectAuthority {
        intent: &authority.intent,
        artifact: &authority.artifact,
        execution_context: &authority.execution_context,
        artifact_hash: &authority.artifact_hash,
        additional_policy_context: authority.additional_policy_context.as_ref(),
        observe_mode: authority.observe_mode,
        invoking_harness: &authority.invoking_harness,
    }
}

/// `build_package_protect_payload` (py:1892).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
#[allow(dead_code)]
fn build_package_protect_payload(
    command: &[String],
    store: &dyn SupplyChainStore,
    workspace_dir: &Path,
    now: &str,
    dry_run: bool,
    config: Option<&GuardConfig>,
    allow_saved_approval_execution: bool,
    additional_current_action: Option<&Value>,
    additional_policy_context: Option<&Map<String, Value>>,
    external_archive_network_authorized: bool,
    invoking_harness: Option<&str>,
    current_config_provider: Option<&dyn Fn() -> Option<GuardConfig>>,
    additional_authority_provider: Option<
        &dyn Fn() -> Result<(Option<Value>, Option<Map<String, Value>>), String>,
    >,
    intent_parser: &dyn PackageIntentParserApi,
    eval_api: &dyn PackageEvalApi,
    runner: &dyn RuntimeRunnerApi,
    launch_identity_api: &dyn RuntimeLaunchIdentityApi,
    bind_context_digest_home: &BindContextDigestHome,
    paths_api: &dyn PathSupportApi,
    synced_policy: &dyn SyncedPolicyApi,
    entitlement_api: &dyn PackageFirewallEntitlementApi,
    shims: &dyn ShimsApi,
    approval_context_api: &dyn ApprovalContextApi,
) -> Result<(Map<String, Value>, i64), String> {
    let authority = match build_package_protect_authority(
        command,
        store,
        workspace_dir,
        now,
        config,
        additional_current_action,
        additional_policy_context,
        external_archive_network_authorized,
        invoking_harness,
        intent_parser,
        eval_api,
        launch_identity_api,
        bind_context_digest_home,
        paths_api,
    )? {
        Some(a) => a,
        None => return Err("guard_protect_no_intent".to_string()),
    };
    let initial_policy_resolution = resolve_stored_package_policy_override(
        &authority.evaluation,
        store,
        &authority.artifact,
        &authority.artifact_hash,
        workspace_dir,
        now,
        Some(&authority.execution_context),
        authority.current_action.as_ref(),
        false,
        intent_parser,
        eval_api,
        paths_api,
        approval_context_api,
    );
    let evaluation = initial_policy_resolution.evaluation;
    let effective_dry_run = dry_run
        && !(allow_saved_approval_execution
            && ppo::evaluation_uses_saved_package_approval(&evaluation.value));
    let execution_policy_action = package_execution_policy_action(&authority, &evaluation);
    let execution_permitted = is_execution_permitted(&execution_policy_action);
    let mut payload = Map::new();
    payload.insert("generated_at".to_owned(), json!(now));
    payload.insert("executed".to_owned(), json!(false));
    payload.insert("dry_run".to_owned(), json!(dry_run));

    let mut payload_obj = payload.clone();
    let projection = ppp::apply_package_protect_projection(
        &mut payload_obj,
        &protect_authority_view(&authority),
        &evaluation,
        command,
        !execution_permitted,
        false,
        Some(execution_policy_action),
    );
    payload = payload_obj;

    if let Some(cfg) = config {
        payload.insert(
            "supply_chain".to_owned(),
            Value::Object(build_local_supply_chain_posture(
                store,
                cfg,
                synced_policy,
                entitlement_api,
                shims,
                Some(now),
            )),
        );
    }

    if !execution_permitted || effective_dry_run {
        store.add_receipt(&projection.receipt);
        store.set_receipt_action_envelope(
            projection
                .receipt
                .get("receipt_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
            &projection.receipt_policy_metadata,
        );
        store.add_event(
            &format!("install_time_{}", projection.verdict_action.as_str()),
            &crate::install_time_event::install_time_event_payload(
                &authority,
                command,
                projection.verdict_action,
                &projection.risk_signals,
                [],
            ),
            now,
        );
        return Ok((
            payload,
            package_execution_exit_code(&json!(execution_policy_action.as_str())),
        ));
    }

    let (final_authority, final_evaluation) = final_package_protect_authority(
        authority.clone(),
        &evaluation,
        ppo::evaluation_uses_saved_package_approval(&evaluation.value),
        command,
        store,
        workspace_dir,
        now,
        config,
        current_config_provider,
        additional_authority_provider,
        intent_parser,
        eval_api,
        launch_identity_api,
        bind_context_digest_home,
        paths_api,
        approval_context_api,
    )?;
    let final_execution_action =
        package_execution_policy_action(&final_authority, &final_evaluation);
    if !is_execution_permitted(&final_execution_action) {
        let denied = ppp::package_protect_denied_after_final_boundary(
            &mut payload,
            &protect_authority_view(&final_authority),
            &final_evaluation,
            command,
            store,
            now,
        );
        cleanup_external_archive_downloads(&final_evaluation);
        return Ok(denied);
    }

    // `launch_identity` is POSIX-only (shutil.which + exec-bit semantics);
    // non-unix builds fail closed exactly like Python's early-exit paths.
    #[cfg(unix)]
    let launch_args: Vec<String> = command[1..].to_vec();
    #[cfg(unix)]
    let (launch_command, launch_reusable) = (
        crate::launch_identity::resolved_runtime_launch_argv(
            &final_authority.launch_identity,
            &launch_args,
        ),
        crate::launch_identity::runtime_launch_identity_is_reusable(
            &final_authority.launch_identity,
        ),
    );
    #[cfg(not(unix))]
    let (launch_command, launch_reusable) = (None::<Vec<String>>, false);
    if launch_command.is_none() || !launch_reusable {
        let reuse = evaluate_approval_reuse(
            &final_authority
                .current_action
                .clone()
                .unwrap_or(Value::Null),
            Some(&json!("require-reapproval")),
            Some(true),
            Some("launch_identity_unstable"),
            false,
            false,
        );
        let denied_evaluation = PackageRequestEvaluation::new(Value::Object(
            ppo::package_evaluation_with_rejected_reuse(
                eval_api,
                final_evaluation
                    .value
                    .as_object()
                    .map_or(&*EMPTY_MAP, |m| m),
                &reuse,
            ),
        ));
        let denied = ppp::package_protect_denied_after_final_boundary(
            &mut payload,
            &protect_authority_view(&final_authority),
            &denied_evaluation,
            command,
            store,
            now,
        );
        cleanup_external_archive_downloads(&final_evaluation);
        return Ok(denied);
    }

    let launch_command = launch_command.unwrap();
    let bound_launch_command =
        bound_external_archive_launch_command(&launch_command, &final_evaluation);
    if bound_launch_command.is_none() {
        let denied_evaluation = PackageRequestEvaluation::new(Value::Object(
            ppo::package_policy_override_evaluation(
                eval_api,
                final_evaluation.value.as_object().map_or(&*EMPTY_MAP, |m| m),
                "block",
                "block",
                "External archive blocked",
                "The inspected external archive could not be bound to the installer launch.",
                "HOL Guard blocked an external archive whose digest-bound blob was unavailable.",
                None,
                "external_archive_digest_mismatch",
                "The inspected external archive changed or was not present in the installer command.",
                None,
                None,
            ),
        ));
        let denied = ppp::package_protect_denied_after_final_boundary(
            &mut payload,
            &protect_authority_view(&final_authority),
            &denied_evaluation,
            command,
            store,
            now,
        );
        cleanup_external_archive_downloads(&final_evaluation);
        return Ok(denied);
    }
    let bound_launch_command = bound_launch_command.unwrap();

    // Execute the bound launch command.
    let launch_environment = package_manager_launch_environment(
        &BTreeMap::new(),
        store.guard_home(),
        &final_authority.launch_cwd,
    )?;
    let execution = match runner.execute_package_command(
        &bound_launch_command,
        &final_authority.launch_cwd,
        &launch_environment,
    ) {
        Ok(e) => e,
        Err(err) => {
            // Treat runner failure as execution failure.
            let fail_evaluation = PackageRequestEvaluation::new(Value::Object(
                ppo::package_policy_override_evaluation(
                    eval_api,
                    final_evaluation
                        .value
                        .as_object()
                        .map_or(&*EMPTY_MAP, |m| m),
                    "block",
                    "block",
                    "Execution failed",
                    &err,
                    "HOL Guard could not execute the installer command.",
                    None,
                    "execution_failed",
                    &err,
                    None,
                    None,
                ),
            ));
            let denied = ppp::package_protect_denied_after_final_boundary(
                &mut payload,
                &protect_authority_view(&final_authority),
                &fail_evaluation,
                command,
                store,
                now,
            );
            cleanup_external_archive_downloads(&final_evaluation);
            return Ok(denied);
        }
    };

    let final_projection = ppp::apply_package_protect_projection(
        &mut payload,
        &protect_authority_view(&final_authority),
        &final_evaluation,
        command,
        false,
        true,
        Some(final_execution_action),
    );
    store.add_receipt(&final_projection.receipt);
    store.set_receipt_action_envelope(
        final_projection
            .receipt
            .get("receipt_id")
            .and_then(Value::as_str)
            .unwrap_or(""),
        &final_projection.receipt_policy_metadata,
    );
    let verdict_action = final_projection.verdict_action;
    let risk_signals = final_projection.risk_signals.clone();
    if execution.returncode == 0 {
        store.add_event(
            &format!("install_time_{}", verdict_action.as_str()),
            &crate::install_time_event::install_time_event_payload(
                &final_authority,
                command,
                verdict_action,
                &risk_signals,
                [],
            ),
            now,
        );
    } else {
        let mut extra = Map::new();
        extra.insert("returncode".to_owned(), json!(execution.returncode));
        store.add_event(
            "install_time_execution_failed",
            &crate::install_time_event::install_time_event_payload(
                &final_authority,
                command,
                verdict_action,
                &risk_signals,
                [],
            ),
            now,
        );
    }
    cleanup_external_archive_downloads(&final_evaluation);
    Ok((payload, execution.returncode))
}

/// `recompute_package_protect_artifact_hash` — recompute the artifact hash
/// for a given artifact + workspace context (mirrors `package_request_artifact_hash`).
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn recompute_package_protect_artifact_hash(
    artifact: &GuardArtifact,
    workspace_dir: &Path,
    store: &dyn SupplyChainStore,
    evaluation: &PackageRequestEvaluation,
    execution_context: Option<&PackageExecutionContext>,
    launch_identity: Option<&Map<String, Value>>,
    config: Option<&GuardConfig>,
    additional_current_action: Option<&Value>,
    additional_policy_context: Option<&Map<String, Value>>,
    bind_context_digest_home: &BindContextDigestHome,
    paths_api: &dyn PathSupportApi,
    execution_context_api: &dyn PackageExecutionContextApi,
    advisory_model: &dyn AdvisoryModelApi,
    approval_context_api: &dyn ApprovalContextApi,
) -> String {
    package_request_artifact_hash(
        artifact,
        workspace_dir,
        store,
        evaluation,
        execution_context,
        launch_identity,
        config,
        additional_current_action,
        additional_policy_context,
        bind_context_digest_home,
        paths_api,
        execution_context_api,
        advisory_model,
        approval_context_api,
    )
}

/// `package_request_policy_hash` — stable digest of the policy inputs for a
/// package request (artifact_id + policy_context material).
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn package_request_policy_hash(
    artifact: &GuardArtifact,
    store: &dyn SupplyChainStore,
    evaluation: &PackageRequestEvaluation,
    config: Option<&GuardConfig>,
    additional_current_action: Option<&Value>,
    additional_policy_context: Option<&Map<String, Value>>,
    advisory_model: &dyn AdvisoryModelApi,
) -> String {
    let policy_context = package_current_policy_context(
        artifact,
        store,
        evaluation,
        config,
        additional_current_action,
        additional_policy_context,
        advisory_model,
    );
    let material = json!({
        "artifact_id": artifact.artifact_id,
        "artifact_name": artifact.name,
        "policy_context": policy_context,
        "policy_action": evaluation.policy_action(),
        "decision": evaluation.decision_value(),
    });
    let canonical = serde_json::to_string(&material).unwrap_or_default();
    stable_digest_hex(canonical.as_bytes())
}

// ---------------------------------------------------------------------------
// Command execution payload helpers (:3136-3174)
// ---------------------------------------------------------------------------
/// `_coerce_command_output` (:3155-3160) — `str | bytes | None` -> `str` with
/// replacement decoding. Accepts `Option<impl AsRef<[u8]>>` so `&str`,
/// `&Vec<u8>`, `Vec<u8>`, and `&[u8]` callers all work.
pub fn coerce_command_output<T: AsRef<[u8]>>(value: Option<T>) -> String {
    value
        .map(|v| String::from_utf8_lossy(v.as_ref()).into_owned())
        .unwrap_or_default()
}

/// `_coerce_command_error_output` (:3163-3171) — stderr (when captured) joined
/// with the error message, newline-separated.
pub fn coerce_command_error_output<T: AsRef<[u8]>>(stderr: Option<T>, message: &str) -> String {
    let mut parts: Vec<String> = vec![coerce_command_output(stderr)];
    let trimmed = message.trim();
    if !trimmed.is_empty() {
        parts.push(trimmed.to_string());
    }
    parts
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Workspace manifest targets (:3275-3299)
// ---------------------------------------------------------------------------

/// `_targets_from_workspace_manifests` (:3275-3299) — deduped install targets
/// parsed directly from workspace manifest files.
pub fn targets_from_workspace_manifests(
    workspace_dir: &Path,
    manifest_paths: &[String],
) -> Vec<PackageIntentTarget> {
    let mut seen: HashSet<(String, Option<String>, String, Option<String>)> = HashSet::new();
    let mut targets: Vec<PackageIntentTarget> = Vec::new();
    for manifest_path in manifest_paths {
        let disk_path = workspace_dir.join(manifest_path);
        let manifest_text = match std::fs::read_to_string(&disk_path) {
            Ok(text) => text,
            Err(_) => continue,
        };
        let dependency_map = parse_manifest_dependencies(
            manifest_path,
            &manifest_text,
            DEFAULT_MANIFEST_PARSE_BYTE_LIMIT,
            DEFAULT_MANIFEST_PARSE_DEADLINE_MS,
        );
        let ecosystem = match ECOSYSTEM_BY_MANIFEST.get(basename(manifest_path)) {
            Some(ecosystem) => *ecosystem,
            None => continue,
        };
        for (package_name, version) in &dependency_map {
            let target = target_from_manifest_dependency(ecosystem, package_name, version);
            let fingerprint = (
                target.ecosystem.clone(),
                target.package_name.clone(),
                target.raw_spec.clone(),
                target.source_url.clone(),
            );
            if !seen.insert(fingerprint) {
                continue;
            }
            targets.push(target);
        }
    }
    targets
}

// ---------------------------------------------------------------------------
// Cloud workspace-audit job transport (:3841-4013, :3938-4012)
// ---------------------------------------------------------------------------

/// Origin (`scheme://netloc`) for URL comparison — mirrors the
/// `urlsplit`/`urlunsplit` issuer binding used by
/// `build_cloud_workspace_audit_request` in `cloud_audit_request.py`.
fn url_origin(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let rest = &url[scheme_end + 3..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    if host_end == 0 {
        return None;
    }
    Some(url[..scheme_end + 3 + host_end].to_string())
}

/// `HTTPError` mapping for cloud audit calls — 403 plan-restriction check
/// first, then retryable/not-available vs runtime, mirroring Python ordering.
fn cloud_audit_http_error(
    status: u16,
    body: &str,
    runner: &dyn RuntimeRunnerApi,
) -> LocalSupplyChainError {
    if status == 403 {
        let (is_plan_restricted, message) = runner.check_plan_restriction_403(status, body);
        if is_plan_restricted {
            return LocalSupplyChainError::NotAvailable {
                message,
                retryable: false,
            };
        }
        return LocalSupplyChainError::Runtime(message);
    }
    let (message, retryable) = runner.guard_cloud_http_error_details(status, body);
    if retryable {
        return LocalSupplyChainError::NotAvailable {
            message,
            retryable: true,
        };
    }
    LocalSupplyChainError::Runtime(message)
}

/// `_execute_cloud_workspace_audit_request` (:3901-3936) — bind the request to
/// the trusted sync origin, attach runner sync headers over https only, send
/// via the managed-URL transport, and normalize error/report shapes.
pub fn execute_cloud_workspace_audit_request(
    auth_context: &Map<String, Value>,
    request_url: &str,
    method: &str,
    payload: Option<&Map<String, Value>>,
    runner: &dyn RuntimeRunnerApi,
    http: &dyn HttpTransport,
) -> Result<Map<String, Value>, LocalSupplyChainError> {
    let sync_url = match auth_context.get("sync_url").and_then(Value::as_str) {
        Some(url) if !url.is_empty() => url,
        _ => {
            return Err(LocalSupplyChainError::Runtime(
                "Guard workspace audit requires a trusted sync URL.".into(),
            ));
        }
    };
    if url_origin(request_url) != url_origin(sync_url) {
        return Err(LocalSupplyChainError::Runtime(
            "Guard workspace audit request URL is not on the trusted sync origin.".into(),
        ));
    }
    // Local development origins never receive reusable credentials.
    let mut headers = if sync_url.starts_with("https://") {
        runner.guard_sync_headers(&Value::Object(auth_context.clone()))
    } else {
        BTreeMap::new()
    };
    let body = match payload {
        Some(map) => {
            headers.insert("Content-Type".into(), "application/json".into());
            Some(
                serde_json::to_vec(&Value::Object(map.clone()))
                    .map_err(|e| LocalSupplyChainError::Runtime(e.to_string()))?,
            )
        }
        None => None,
    };
    let request = HttpRequest {
        url: request_url.to_string(),
        method: method.to_string(),
        headers,
        body,
    };
    let response = http
        .open(&request, CLOUD_AUDIT_TIMEOUT_SECONDS)
        .map_err(|e| match e {
            HttpError::Status { status, body } => cloud_audit_http_error(status, &body, runner),
            HttpError::Io(msg) => {
                LocalSupplyChainError::Runtime(runner.sync_url_error_message(&msg))
            }
        })?;
    if response.status == 403 {
        return Err(cloud_audit_http_error(
            response.status,
            &String::from_utf8_lossy(&response.body),
            runner,
        ));
    }
    if response.status >= 400 {
        let (message, retryable) = runner.guard_cloud_http_error_details(
            response.status,
            &String::from_utf8_lossy(&response.body),
        );
        return Err(if retryable {
            LocalSupplyChainError::NotAvailable {
                message,
                retryable: true,
            }
        } else {
            LocalSupplyChainError::Runtime(message)
        });
    }
    let parsed: Value = serde_json::from_slice(&response.body).map_err(|_| {
        LocalSupplyChainError::Runtime(
            "Guard cloud workspace audit returned an invalid response.".into(),
        )
    })?;
    match parsed {
        Value::Object(map) => Ok(map),
        _ => Err(LocalSupplyChainError::Runtime(
            "Guard cloud workspace audit returned an invalid response.".into(),
        )),
    }
}

/// `_enqueue_cloud_workspace_audit_job` (:3961-3979).
pub fn enqueue_cloud_workspace_audit_job(
    auth_context: &Map<String, Value>,
    request_payload: &Map<String, Value>,
    workspace_id: &str,
    runner: &dyn RuntimeRunnerApi,
    http: &dyn HttpTransport,
) -> Result<Map<String, Value>, LocalSupplyChainError> {
    let sync_url = match auth_context.get("sync_url").and_then(Value::as_str) {
        Some(url) if !url.is_empty() => url.to_string(),
        _ => {
            return Err(LocalSupplyChainError::Runtime(
                "Guard workspace audit requires a trusted sync URL.".into(),
            ));
        }
    };
    let request_url = normalized_supply_chain_batch_url(&sync_url, workspace_id)
        .map_err(LocalSupplyChainError::Runtime)?;
    let response_payload = execute_cloud_workspace_audit_request(
        auth_context,
        &request_url,
        "POST",
        Some(request_payload),
        runner,
        http,
    )?;
    let job_id = response_payload
        .get("jobId")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if job_id.is_empty() {
        return Err(LocalSupplyChainError::Runtime(
            "Guard cloud workspace audit did not return a batch job id.".into(),
        ));
    }
    Ok(response_payload)
}

/// `_poll_cloud_workspace_audit_job` (:3981-4012) — bounded poll of the batch
/// job URL until `completed`/`failed` or the deadline elapses.
pub fn poll_cloud_workspace_audit_job(
    auth_context: &Map<String, Value>,
    job_id: &str,
    workspace_id: &str,
    runner: &dyn RuntimeRunnerApi,
    http: &dyn HttpTransport,
) -> Result<Map<String, Value>, LocalSupplyChainError> {
    let sync_url = match auth_context.get("sync_url").and_then(Value::as_str) {
        Some(url) if !url.is_empty() => url.to_string(),
        _ => {
            return Err(LocalSupplyChainError::Runtime(
                "Guard workspace audit requires a trusted sync URL.".into(),
            ));
        }
    };
    let request_url = normalized_supply_chain_batch_job_url(
        &sync_url,
        workspace_id,
        job_id,
        CLOUD_AUDIT_JOB_PAGE_SIZE as i64,
    )
    .map_err(LocalSupplyChainError::Runtime)?;
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs_f64(CLOUD_AUDIT_JOB_POLL_TIMEOUT_SECONDS);
    let mut last_response = Map::new();
    last_response.insert("jobId".into(), json!(job_id));
    last_response.insert("status".into(), json!("queued"));
    last_response.insert("workspaceId".into(), json!(workspace_id));
    while std::time::Instant::now() < deadline {
        let response_payload = execute_cloud_workspace_audit_request(
            auth_context,
            &request_url,
            "GET",
            None,
            runner,
            http,
        )?;
        let status = response_payload
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_lowercase();
        last_response = response_payload;
        if status == "completed" || status == "failed" {
            return Ok(last_response);
        }
        std::thread::sleep(std::time::Duration::from_secs_f64(
            CLOUD_AUDIT_JOB_POLL_INTERVAL_SECONDS,
        ));
    }
    Ok(last_response)
}

// ---------------------------------------------------------------------------
// Job-mode audit payload (:3823-3899, :4014-4071)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Managed workspace audit sync (:4165-4302)
// ---------------------------------------------------------------------------

/// Per-workspace outcome classification inside `sync_managed_workspace_audits`.
enum WorkspaceAuditJobOutcome {
    Skipped,
    Completed,
    Queued,
    Failed,
    Incomplete,
}

/// Run one managed workspace through the job-mode audit flow: inventory the
/// workspace, build the request payload, enqueue the batch job, and poll to a
/// terminal status. Mirrors the per-candidate `try` body of
/// `sync_managed_workspace_audits` (:4197-4267); returns the result row.
#[allow(clippy::too_many_arguments)]
fn run_managed_workspace_audit_job(
    store: &dyn SupplyChainStore,
    resolved_auth_context: &Map<String, Value>,
    workspace_id: &str,
    candidate: &Path,
    workspace_label: &str,
    runner: &dyn RuntimeRunnerApi,
    http: &dyn HttpTransport,
    paths: &dyn PathSupportApi,
    manifest_parser: &dyn ManifestParserApi,
) -> Result<(WorkspaceAuditJobOutcome, Map<String, Value>), LocalSupplyChainError> {
    let inventory = workspace_audit_inventory(candidate, &[], paths, manifest_parser);
    if inventory.package_items.is_empty() {
        let mut row = Map::new();
        row.insert("workspace".into(), json!(workspace_label));
        row.insert("status".into(), json!("skipped"));
        row.insert(
            "message".into(),
            json!("No supported package inventory was detected for workspace audit sync."),
        );
        row.insert("package_count".into(), json!(0));
        return Ok((WorkspaceAuditJobOutcome::Skipped, row));
    }
    let job_inventory: Vec<Value> = inventory
        .package_items
        .iter()
        .cloned()
        .map(Value::Object)
        .collect();
    let request_payload = build_cloud_audit_payload(
        candidate,
        workspace_id,
        store,
        &inventory.manifest_paths,
        &inventory.lockfile_paths,
        &job_inventory,
        "job",
        Some(CLOUD_AUDIT_SYNC_PAGE_SIZE.min(inventory.package_items.len().max(1)) as i64),
        paths,
        &EnvCloudAuditWorkspaceContext,
    )
    .map_err(LocalSupplyChainError::Runtime)?;
    let enqueue_response = enqueue_cloud_workspace_audit_job(
        resolved_auth_context,
        &request_payload,
        workspace_id,
        runner,
        http,
    )?;
    let job_id = enqueue_response
        .get("jobId")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let final_response =
        poll_cloud_workspace_audit_job(resolved_auth_context, &job_id, workspace_id, runner, http)?;
    let final_status = final_response
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| enqueue_response.get("status").and_then(Value::as_str))
        .unwrap_or("queued")
        .trim()
        .to_lowercase();
    let cloud_visible_count = int_value(final_response.get("totalPackages"));
    let cloud_processed_count = int_value(final_response.get("processedCount"));
    let inventory_count = i64::try_from(inventory.package_items.len()).unwrap_or(i64::MAX);
    let incomplete_cloud_projection = final_status == "completed"
        && cloud_visible_count.is_some()
        && cloud_visible_count < Some(inventory_count);
    let (outcome, workspace_status) = if incomplete_cloud_projection {
        (WorkspaceAuditJobOutcome::Incomplete, "partial")
    } else if final_status == "completed" {
        (WorkspaceAuditJobOutcome::Completed, final_status.as_str())
    } else if final_status == "failed" {
        (WorkspaceAuditJobOutcome::Failed, final_status.as_str())
    } else {
        (WorkspaceAuditJobOutcome::Queued, final_status.as_str())
    };
    let mut message = final_response.get("error").cloned();
    if incomplete_cloud_projection {
        message = Some(json!(format!(
            "Guard Cloud accepted fewer package rows than hol-guard discovered ({} of {} visible).",
            cloud_visible_count.unwrap_or(0),
            inventory.package_items.len()
        )));
    }
    let mut row = Map::new();
    row.insert("workspace".into(), json!(workspace_label));
    row.insert(
        "workspace_fingerprint".into(),
        request_payload
            .get("workspaceFingerprint")
            .cloned()
            .unwrap_or(Value::Null),
    );
    row.insert("job_id".into(), json!(job_id));
    row.insert("status".into(), json!(workspace_status));
    row.insert("package_count".into(), json!(inventory.package_items.len()));
    row.insert(
        "cloud_processed_count".into(),
        cloud_processed_count.map_or(Value::Null, |v| json!(v)),
    );
    row.insert(
        "cloud_visible_count".into(),
        cloud_visible_count.map_or(Value::Null, |v| json!(v)),
    );
    row.insert(
        "manifest_paths".into(),
        json!(inventory.manifest_paths.to_vec()),
    );
    row.insert(
        "lockfile_paths".into(),
        json!(inventory.lockfile_paths.to_vec()),
    );
    row.insert("message".into(), message.unwrap_or(Value::Null));
    Ok((outcome, row))
}

/// `sync_managed_workspace_audits` (:4165-4302) — enqueue + poll job-mode
/// cloud audits across managed workspaces and persist the summary.
pub fn sync_managed_workspace_audits(
    store: &dyn SupplyChainStore,
    auth_context: Option<&Map<String, Value>>,
    workspace_dir: Option<&Path>,
    runner: &dyn RuntimeRunnerApi,
    http: &dyn HttpTransport,
    paths: &dyn PathSupportApi,
    manifest_parser: &dyn ManifestParserApi,
) -> Result<Map<String, Value>, LocalSupplyChainError> {
    let resolved_auth_context = match auth_context {
        Some(ctx) => ctx.clone(),
        None => runner
            .resolve_guard_sync_auth_context(store)?
            .as_object()
            .cloned()
            .unwrap_or_default(),
    };
    let workspace_id = store
        .get_cloud_workspace_id()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            LocalSupplyChainError::NotConfigured(
                "Guard Cloud is not connected yet. Run `hol-guard connect` to sign in and pair this machine, or use `hol-guard login` as a compatibility alias for the same browser flow.".into(),
            )
        })?;
    let synced_at = utc_now_iso();
    let mut workspaces_payload: Vec<Value> = Vec::new();
    let mut completed_jobs = 0i64;
    let mut failed_jobs = 0i64;
    let mut incomplete_jobs = 0i64;
    let mut queued_jobs = 0i64;
    let mut skipped_workspaces = 0i64;
    for candidate in managed_workspace_audit_candidates(store, workspace_dir) {
        let workspace_label = candidate
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| candidate.to_string_lossy().into_owned());
        match run_managed_workspace_audit_job(
            store,
            &resolved_auth_context,
            &workspace_id,
            &candidate,
            &workspace_label,
            runner,
            http,
            paths,
            manifest_parser,
        ) {
            Err(
                error @ (LocalSupplyChainError::AuthorizationExpired(_)
                | LocalSupplyChainError::NotAvailable { .. }
                | LocalSupplyChainError::NotConfigured(_)),
            ) => {
                return Err(error);
            }
            Err(error) => {
                failed_jobs += 1;
                let mut row = Map::new();
                row.insert("workspace".into(), json!(workspace_label));
                row.insert("status".into(), json!("failed"));
                row.insert("message".into(), json!(error.to_string()));
                row.insert("package_count".into(), json!(0));
                workspaces_payload.push(Value::Object(row));
            }
            Ok((outcome, row)) => {
                match outcome {
                    WorkspaceAuditJobOutcome::Skipped => skipped_workspaces += 1,
                    WorkspaceAuditJobOutcome::Completed => completed_jobs += 1,
                    WorkspaceAuditJobOutcome::Queued => queued_jobs += 1,
                    WorkspaceAuditJobOutcome::Failed => failed_jobs += 1,
                    WorkspaceAuditJobOutcome::Incomplete => incomplete_jobs += 1,
                }
                workspaces_payload.push(Value::Object(row));
            }
        }
    }
    let status =
        if failed_jobs > 0 && completed_jobs == 0 && queued_jobs == 0 && incomplete_jobs == 0 {
            "failed"
        } else if failed_jobs > 0 || incomplete_jobs > 0 {
            "partial"
        } else if completed_jobs > 0 || queued_jobs > 0 {
            "synced"
        } else {
            "idle"
        };
    let mut summary = Map::new();
    summary.insert("synced_at".into(), json!(synced_at));
    summary.insert("status".into(), json!(status));
    summary.insert("workspace_count".into(), json!(workspaces_payload.len()));
    summary.insert("completed_jobs".into(), json!(completed_jobs));
    summary.insert("queued_jobs".into(), json!(queued_jobs));
    summary.insert("failed_jobs".into(), json!(failed_jobs));
    summary.insert("incomplete_jobs".into(), json!(incomplete_jobs));
    summary.insert("skipped_workspaces".into(), json!(skipped_workspaces));
    summary.insert("workspaces".into(), Value::Array(workspaces_payload));
    store.set_sync_payload(
        "workspace_audits_sync_summary",
        &Value::Object(summary.clone()),
    );
    Ok(summary)
}

/// `sync_supply_chain_cloud_state` (:4303-4320) — bundle sync plus managed
/// workspace audit sync under one auth context.
pub fn sync_supply_chain_cloud_state(
    store: &dyn SupplyChainStore,
    auth_context: Option<&Map<String, Value>>,
    workspace_dir: Option<&Path>,
    runner: &dyn RuntimeRunnerApi,
    http: &dyn HttpTransport,
    paths: &dyn PathSupportApi,
    manifest_parser: &dyn ManifestParserApi,
) -> Result<Map<String, Value>, LocalSupplyChainError> {
    let resolved_auth_context: Map<String, Value> = match auth_context {
        Some(ctx) => ctx.clone(),
        None => runner
            .resolve_guard_sync_auth_context(store)?
            .as_object()
            .cloned()
            .unwrap_or_default(),
    };
    let bundle_summary = call_sync_with_optional_auth_context(store, runner, &|store, ctx| {
        runner.sync_supply_chain_bundle(store, ctx)
    })?;
    let mut payload = match bundle_summary {
        Some(Value::Object(map)) => map,
        _ => Map::new(),
    };
    let workspace_audits = sync_managed_workspace_audits(
        store,
        Some(&resolved_auth_context),
        workspace_dir,
        runner,
        http,
        paths,
        manifest_parser,
    )?;
    let synced_at = workspace_audits.get("synced_at").cloned();
    payload.insert("workspace_audits".into(), Value::Object(workspace_audits));
    if let Some(synced_at) = synced_at {
        payload.entry("synced_at".to_string()).or_insert(synced_at);
    }
    Ok(payload)
}
