//! `PackageWorkspaceScope` - wire contract for the resident op that derives the
//! workspace identity a saved package approval is stored and matched under.
//!
//! A package-request approval is keyed by a scope string built from the
//! artifact identity and the package execution context. Deriving it twice --
//! once in the runtime and once in the caller -- lets the two drift, and a
//! drifted key silently stops a saved "Always allow" from matching, so the user
//! is asked again for a package they already approved. The runtime owns the
//! derivation; the caller ships the artifact fields and the execution-context
//! evidence it already received from the runtime.
//!
//! The op is pure: no IO, no SQLite.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const PACKAGE_WORKSPACE_SCOPE_REQUEST_SCHEMA: &str = "guard-package-workspace-scope-request.v1";
/// Schema discriminator for the result.
pub const PACKAGE_WORKSPACE_SCOPE_RESULT_SCHEMA: &str = "guard-package-workspace-scope-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const PACKAGE_WORKSPACE_SCOPE_FEATURE: &str = "package-workspace-scope-v1";
/// Largest canonical request serialization the op will accept.
pub const PACKAGE_WORKSPACE_SCOPE_MAX_BYTES: usize = 1024 * 1024;

/// The artifact identity plus the execution-context evidence the scope binds to.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageWorkspaceScopeRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub artifact_id: Option<String>,
    #[serde(default)]
    pub artifact_hash: Option<String>,
    #[serde(default)]
    pub artifact_type: Option<String>,
    /// `PackageExecutionContext.to_evidence()`, or null when the caller has no
    /// context. Evidence that does not validate yields a null scope, matching a
    /// caller that could not build a current context.
    #[serde(default)]
    pub execution_context: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageWorkspaceScopeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_package_workspace_scope_*` failure codes.
    pub code: String,
    /// `{"portable": string|null, "runtime": string|null}`. `portable` is set
    /// only for a complete portable context; `runtime` is the identity a policy
    /// lookup must use, and falls back to the context-bound exact scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
