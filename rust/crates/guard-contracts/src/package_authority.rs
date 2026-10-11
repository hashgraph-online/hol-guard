//! `PackageAuthority` — wire contracts for the resident ops that run the
//! package-intent parse, supply-chain evaluation, and package-authority
//! decision chain inside the resident under one lock.
//!
//! `PackageIntentParse` mirrors `package_intent_parser.parse_package_intent`
//! (:213); `SupplyChainEval` mirrors
//! `supply_chain_package_eval.evaluate_package_request_artifact` (:1232);
//! `PackageAuthorityDecide` composes parse → artifact build → eval for the
//! `hol-guard package protect` authority path.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const PACKAGE_AUTHORITY_REQUEST_SCHEMA: &str = "guard-package-authority-request.v1";
/// Schema discriminator for the result.
pub const PACKAGE_AUTHORITY_RESULT_SCHEMA: &str = "guard-package-authority-result.v1";
/// Capability advertised by the runtime when these operations are available.
pub const PACKAGE_AUTHORITY_FEATURE: &str = "package-authority-v1";
/// Capability advertised when the package-evaluation composition op exists.
pub const PACKAGE_EVALUATION_COMPOSE_FEATURE: &str = "package-evaluation-compose-v1";
pub const PACKAGE_APPROVAL_HASH_FEATURE: &str = "package-approval-hash-v1";
/// Capability advertised when the stored package policy resolution op exists.
pub const PACKAGE_POLICY_RESOLVE_FEATURE: &str = "package-policy-resolve-v1";
/// Capability advertised when `supply_chain_eval` is the sole package-verdict
/// authority: the resident owns Cloud, bundle, lockfile and heuristic
/// decisions, and callers have no Python evaluation to fall back to.
pub const SUPPLY_CHAIN_EVAL_FEATURE: &str = "supply-chain-eval-v1";

/// Largest canonical request serialization any of these ops will accept.
pub const PACKAGE_AUTHORITY_MAX_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// PackageIntentParse — `parse_package_intent` port entry.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageIntentParseRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// Raw command text to parse.
    pub command_text: String,
    /// Optional workspace directory used by filesystem-backed intent probing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    /// Optional home directory (`Path.home()` fallback when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_dir: Option<String>,
    /// Optional canonical command object. Python sends a `CanonicalCommand`
    /// dict. This parse ignores it; accepting any JSON value keeps a present
    /// object from failing the request and falling back to Python.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_command: Option<Value>,
    /// Explicit environment overlay. Non-string maps are ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageIntentParseResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the raw request bytes, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or `native_package_intent_parse_failed`.
    pub code: String,
    /// `intent.to_dict()` or `null` when no intent was parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// Exact targets for ephemeral enforcement, never public intent metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_private_metadata: Option<Value>,
}

// ---------------------------------------------------------------------------
// SupplyChainEval — `evaluate_package_request_artifact` port entry.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainEvalRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// Absolute path to the guard store SQLite database (`guard.db`).
    pub store_path: String,
    /// Resolved guard home (`~/.hol`); used for config + state lookups.
    pub guard_home: String,
    /// The `GuardArtifact` dict (`{kind, metadata, files}`).
    pub artifact: Value,
    /// Optional workspace directory for workspace-bound evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_dir: Option<String>,
    /// ISO-8601 UTC timestamp override (else wall clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    /// Allow restricted-archive HTTP fetches (default false → blocked).
    #[serde(default)]
    pub external_archive_network_authorized: bool,
    /// Retain external-archive temp blobs for evidence (default false).
    #[serde(default)]
    pub retain_external_archive_blob: bool,
    /// Ephemeral enforcement values. Never persisted; used only to verify
    /// public target hashes against the private spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_private_metadata: Option<Value>,
    /// Test-only Guard Cloud auth-context override forwarded by
    /// `supply_chain_eval_native` when `PYTEST_CURRENT_TEST` +
    /// `HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON` are set. Kept out of the
    /// `package_authority_decide` request surface; only the discrete
    /// `supply_chain_eval` op honors it so coverage tests exercise the
    /// resident's auth-expired / cloud-transport branches hermetically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_auth_context_override: Option<Value>,
    /// Test-only Guard Cloud entitlement override forwarded by
    /// `supply_chain_eval_native` when `PYTEST_CURRENT_TEST` +
    /// `HOL_GUARD_TEST_PACKAGE_ENTITLEMENT_JSON` are set. Lets coverage tests
    /// exercise the resident's unpaid-entitlement fallback (an expired cloud
    /// session under `paid_guard_cloud_required` degrades to local bundle
    /// intelligence rather than fail-closing) without monkeypatching a
    /// Python-only resolver the resident never runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_entitlement_override: Option<Value>,
    /// Test-only public-registry metadata fixtures, keyed by the exact
    /// metadata URL the resolver requests (`https://registry.npmjs.org/<name>`
    /// or `https://pypi.org/pypi/<name>/json`) with the registry JSON object
    /// as the value (`null` or an absent key means unresolved). Replaces the
    /// network fetch so range-resolution tests are hermetic; the resolver's
    /// URL selection and version choice still run for real.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_metadata_override: Option<Value>,
    /// Saved-policy lookup the caller hydrated after the resident answered
    /// `saved_policy_probe_required` for a cached Cloud validation error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_policy_probe: Option<SavedPolicyProbeV1>,
    /// Outcomes of the network exchanges the resident asked the caller to
    /// perform under its managed network policy (`supply_chain_egress_required`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_supplied: Option<Vec<crate::EgressSuppliedV1>>,
    /// Caller-owned private directory holding response bodies too large to
    /// inline. The resident reads plain file names inside it and never writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_spool_dir: Option<String>,
}

/// The `lookup["decision"]` row the caller read for a cached Cloud validation
/// error, or `None` when no saved policy matched. The resident applies the
/// stale-family and block-only rules; it does not trust the row for anything
/// else.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SavedPolicyProbeV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainEvalResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or `native_supply_chain_eval_failed`.
    pub code: String,
    /// `PackageRequestEvaluation.to_dict()` on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
// ---------------------------------------------------------------------------
// ApplyStoredPackagePolicy — `_apply_stored_package_policy_override` resident
// op. Carries the already-computed package_request evaluation plus the inputs
// the override reads; `execution_context` stays None so the resident computes
// it via `build_package_execution_context` parity.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApplyStoredPackagePolicyRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// Absolute path to the guard store SQLite database (`guard.db`).
    pub store_path: String,
    /// Resolved guard home (`~/.hol`).
    pub guard_home: String,
    /// The already-evaluated `PackageRequestEvaluation.to_dict()` payload.
    pub evaluation: Value,
    /// The `GuardArtifact` dict (`{kind, metadata, files}`).
    pub artifact: Value,
    /// Content hash of the artifact under evaluation.
    pub artifact_hash: String,
    /// Workspace directory bound to the request.
    pub workspace_dir: String,
    /// ISO-8601 UTC timestamp.
    pub now: String,
    /// Ephemeral enforcement values; forwarded into the rebuilt artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_private_metadata: Option<Value>,
    /// Caller-provided current action (else the evaluation's `policy_action`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_action: Option<Value>,
    /// When false, the saved approval is reported but not claimed.
    #[serde(default = "default_true")]
    pub claim_saved_approval: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApplyStoredPackagePolicyResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or `native_apply_stored_package_policy_failed`.
    pub code: String,
    /// Updated `PackageRequestEvaluation.to_dict()` on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

// ---------------------------------------------------------------------------
// PackageAuthorityDecide — compose parse → artifact → eval for the package
// protect authority path. One native call returns the full decision payload.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuthorityDecideRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// Raw command text under evaluation.
    pub command_text: String,
    /// Absolute path to the guard store SQLite database (`guard.db`).
    pub store_path: String,
    /// Resolved guard home.
    pub guard_home: String,
    /// Optional workspace directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_dir: Option<String>,
    /// ISO-8601 UTC timestamp override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    /// `artifact_kind` forwarded to `build_package_request_artifact`
    /// (e.g. `"claude_hook"`, `"command"`).
    pub artifact_kind: String,
    /// `artifact_type` label forwarded to `build_package_request_artifact`
    /// (e.g. `"hook"`, `"project"`).
    pub artifact_type: String,
    #[serde(default)]
    pub external_archive_network_authorized: bool,
    #[serde(default)]
    pub retain_external_archive_blob: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuthorityDecideResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, `no_intent`, or `native_package_authority_decide_failed`.
    pub code: String,
    /// `{ intent, artifact, evaluation }` on success — evaluation is the
    /// `PackageRequestEvaluation.to_dict()` payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

/// Native cached-feed matching for a package policy context. The runtime reads
/// the complete advisory cache; callers cannot provide preselected matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAdvisoryIdsRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub store_path: String,
    pub guard_home: String,
    pub artifact: Value,
}

/// Pure composition of a package verdict rewrite. The caller supplies only the
/// evaluation fields the rewrite reads (`policy_action`, `reasons`,
/// `packages`) plus the kind-specific facts; the runtime chooses every
/// resulting decision, policy action, reason, and copy field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageEvaluationComposeRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    /// `current_policy_action`, `rejected_reuse`, `saved_allow`,
    /// `saved_block`, or `external_archive_override`.
    pub kind: String,
    pub evaluation: Value,
    /// `current_policy_action` only: the current package policy action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_action: Option<String>,
    /// `rejected_reuse`, `saved_allow`, `saved_block`: the reuse evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_reuse: Option<Value>,
    /// `saved_allow` (`reused` | `claimed_revalidated`) and
    /// `external_archive_override` (`launch_unbound` | `mcp_unbound` |
    /// `binding_unavailable` | `shim_delegated`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// `saved_allow` `reused` only: `consumed` or `retained`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_disposition: Option<String>,
    /// `saved_block` only: the saved-policy clear command shown to the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clear_command: Option<String>,
}

// ---------------------------------------------------------------------------
// PackageApprovalHash — resident op owning the package approval identity,
// the composed current policy action, and the approval-context artifact hash
// that `local_supply_chain.py` used to compute in Python.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageApprovalHashRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    /// `current_action` (composed action only) or `artifact_hash` (composed
    /// action plus the approval-context token).
    pub kind: String,
    /// `GuardArtifact.to_dict()`.
    pub artifact: Value,
    /// Evaluation fields the policy composition reads: `policy_action`,
    /// `bundle_version`, `decision`, `enforcement`, `entitlement_state`,
    /// `exception_id`, `matched_rule_id`, `packages`, `policy_version`,
    /// `reasons`.
    pub evaluation: Value,
    /// Hydrated `GuardConfig` policy view (`{"available": false}` when no
    /// config is bound).
    pub config_policy: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_current_action: Option<Value>,
    /// `artifact_hash` only: the signed-store path the cached advisory feed is
    /// read from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_path: Option<String>,
    /// `artifact_hash` only: the workspace the manifest and lockfile paths are
    /// confined to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_dir: Option<String>,
    /// `artifact_hash` only: `{digest, version, components: [{name, digest}]}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_context: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_identity: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_policy_context: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feed_snapshot_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_analysis: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_control_digest: Option<String>,
}

// ---------------------------------------------------------------------------
// PackagePolicyResolve — resident op owning the stored package policy
// override: the saved allow, saved block and rejected-reuse verdicts. The
// caller hydrates the store facts (lookup, diagnostic, approval request row,
// bundle rules, claim disposition) and performs the claim; the runtime decides
// every verdict and returns a patch over the caller's evaluation.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackagePolicyResolveRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    /// Evaluation fields the rewrites read: `policy_action`, `reasons`, `packages`.
    pub evaluation: Value,
    /// Additional current action folded into the evaluation's policy action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_action: Option<Value>,
    pub harness: String,
    pub artifact_id: String,
    pub artifact_hash: String,
    pub workspace_dir: String,
    /// The saved policy row the store lookup (or the daemon) resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Value>,
    /// The store ignored a saved row because local integrity failed.
    pub ignored_integrity: bool,
    /// A daemon policy authority owns the claim for `decision`.
    pub daemon_authority: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnosed_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnosed_stored_hash: Option<String>,
    /// Validated synced-bundle rules whose id matches the decision owner;
    /// absent when no validated bundle is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_rules: Option<Vec<Value>>,
    /// The approval request row named by `decision.request_id`, if readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request: Option<Value>,
    pub claim_saved_approval: bool,
    /// Outcome of the caller-run claim; absent on the first call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_succeeded: Option<bool>,
}

// ---------------------------------------------------------------------------
// PackagePosture — resident op owning the local supply-chain posture: the
// status, health, bundle and policy projection `local_supply_chain.py` used to
// derive in Python. The caller hydrates the store payloads, the bound
// configuration actions and the package-manager shim status; the runtime
// decides every derived field.
// ---------------------------------------------------------------------------

/// Capability advertised when the supply-chain posture op exists.
pub const PACKAGE_POSTURE_FEATURE: &str = "package-posture-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackagePostureRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    /// Snapshot time; the runtime clock is used when absent or unparsable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    /// A Guard Cloud sync profile is stored locally.
    pub credentials_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// `supply_chain_bundle_summary` sync payload (empty object when unset).
    pub summary: Value,
    /// `supply_chain_bundle_entitlement` sync payload (empty object when unset).
    pub entitlement: Value,
    /// Validated synced policy payload (empty object when unset).
    pub remote_policy: Value,
    /// The cached signed bundle body (empty object when unset).
    pub bundle_payload: Value,
    pub security_level: String,
    /// Configured `cloud_advisory` / `package_script` risk actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_cloud_advisory_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_package_script_action: Option<String>,
    /// Package-manager shim status; carried through unchanged.
    pub package_manager_protection: Value,
}
