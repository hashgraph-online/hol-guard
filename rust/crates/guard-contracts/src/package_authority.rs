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
