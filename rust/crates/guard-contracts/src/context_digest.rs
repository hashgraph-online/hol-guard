//! Bounded native request-context digest contract.
//!
//! Approval-context tokens and configured environment/header digests are
//! authority-bearing artifacts: a saved approval is reusable only while these
//! digests are unchanged. Computing them is therefore native work — Python
//! callers send the raw components and receive the canonical token/digest
//! back through the resident protocol or `hol-guard-runtime context-digest
//! --stdin`.

use crate::{BrowserMcpArtifactV1, BrowserMcpRequestV1, BrowserMcpResultV1};
use crate::{McpToolPolicyRequestV1, McpToolPolicyResultV1};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Schema discriminator for the request.
pub const CONTEXT_DIGEST_REQUEST_SCHEMA: &str = "guard-context-digest-request.v1";
/// Schema discriminator for the result.
pub const CONTEXT_DIGEST_RESULT_SCHEMA: &str = "guard-context-digest-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CONTEXT_DIGEST_FEATURE: &str = "context-digest-v1";

/// Opaque approval-context token prefix shared with the persisted contract.
pub const APPROVAL_CONTEXT_TOKEN_PREFIX: &str = "guard-approval-context:v1:";
/// Longest accepted token body.
pub const APPROVAL_CONTEXT_TOKEN_MAX_BYTES: usize = 2_048;
/// Largest canonical component serialization the digest op will hash.
pub const CONTEXT_COMPONENT_MAX_BYTES: usize = 1024 * 1024;

/// First-difference reasons for approval-context validation. These strings
/// are part of the persisted/presentation contract with the Python side.
pub const APPROVAL_CONTEXT_VALIDATION_REASONS: [&str; 5] = [
    "approval_reuse_identity_changed",
    "approval_reuse_content_changed",
    "approval_reuse_capability_changed",
    "approval_reuse_policy_changed",
    "approval_reuse_sandbox_changed",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextDigestComponentsV1 {
    pub identity: Value,
    pub content: Value,
    pub capabilities: Value,
    /// Raw policy component. The runtime wraps it with the caller-supplied
    /// extension-control digest before hashing, matching the historical
    /// construction exactly.
    pub policy: Value,
    pub sandbox: Value,
    /// Digest produced by the extension-control snapshot currently bound to
    /// the request. The caller still owns that snapshot's lifetime; the
    /// worker only binds its value into the policy component hash.
    pub extension_control_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpServerIdentityRequestV1 {
    pub config_path: String,
    pub command: String,
    pub args: Vec<String>,
    pub transport: String,
    pub environment: Option<Vec<(String, String)>>,
    pub env_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolIdentityRequestV1 {
    pub server_hash: String,
    pub tool_name: String,
    pub schema: Option<Value>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpServerIdentityV1 {
    pub config_path: String,
    pub command: String,
    pub args_hash: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub package_source: String,
    pub transport: String,
    pub env_keys: Vec<String>,
    pub env_values_hash: String,
    pub identity_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolIdentityV1 {
    pub server_hash: String,
    pub tool_name: String,
    pub schema_hash: String,
    pub description_hash: String,
    pub identity_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpServerDescriptorRequestV1 {
    pub identity: McpServerIdentityV1,
    pub config_path: String,
    pub args: Vec<String>,
    pub publisher: Option<String>,
    pub install_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolDescriptorRequestV1 {
    pub identity: McpToolIdentityV1,
    pub schema: Option<Value>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolContentDigestRequestV1 {
    pub artifact_id: String,
    pub config_path: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolApprovalDigestRequestV1 {
    pub content: McpToolContentDigestRequestV1,
    pub transport: Option<String>,
    pub server_fingerprint: Option<Value>,
    pub server_identity: Option<Value>,
    pub tool_identity: Option<Value>,
    pub authority_hash: Option<Value>,
    pub provider_hash: Option<Value>,
    pub workspace: Option<String>,
}

/// Full MCP tool-call approval hash composed in one request. Rust owns
/// browser-intent normalization, exact-argument filtering, content digest,
/// risk categories, and the approval-context token — the Python caller ships
/// only raw artifact metadata, raw arguments, and config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolApprovalHashRequestV1 {
    /// Raw tool-call artifact fields (name, command, metadata) plus the
    /// identity/publisher/capability material the approval context needs.
    pub artifact: BrowserMcpArtifactV1,
    /// Identity fields that live outside `metadata` on the Python artifact.
    pub artifact_id: String,
    pub config_path: String,
    pub harness: String,
    pub publisher: Option<String>,
    /// `source_scope` is a required string on the artifact DTO, but the token
    /// row persists whatever the caller sends — keep `Value` for parity.
    pub source_scope: Value,
    pub transport: Option<String>,
    /// Raw call arguments; JSON strings are parsed natively, browser
    /// volatile fields are dropped only when the artifact is browser-class.
    pub arguments: Value,
    /// `config is None` → approval-digest row; `Some` → context token.
    pub config: Option<Map<String, Value>>,
    pub workspace: Option<String>,
    /// Bound extension-control digest; required only for the token path.
    /// `skip_serializing_if` keeps the request digest byte-identical to the
    /// Python sender, which omits the key entirely on the digest path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_control_digest: Option<String>,
}

/// Sub-operation carried by a single context-digest request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextDigestKindV1 {
    /// Build the opaque approval-context token for a full component set.
    BuildApprovalContextToken {
        components: ContextDigestComponentsV1,
    },
    /// Compare two already-built tokens, returning the first changed
    /// dimension or none. Malformed input fails closed as changed content.
    ValidateApprovalContextTokens {
        saved_token: Value,
        current_token: Value,
    },
    /// Build the current token from components and compare it against a
    /// saved token in one round trip.
    ValidateApprovalContext {
        saved_token: Value,
        components: ContextDigestComponentsV1,
    },
    /// Domain-separated digest over a configured environment subset.
    ///
    /// `values` carries caller-ordered `["key", value]` pairs because distinct
    /// raw keys can collide after whitespace stripping and the legacy caller
    /// resolves the collision by last entry in iteration order, which a plain
    /// JSON object cannot transport.
    ConfiguredEnvironmentHash {
        values: Option<Value>,
        configured_keys: Option<Vec<String>>,
    },
    /// Domain-separated digest over a configured header subset; same ordered
    /// pair transport as `ConfiguredEnvironmentHash`.
    ConfiguredHeadersHash {
        values: Option<Value>,
        configured_keys: Option<Vec<String>>,
    },
    /// Stable launch-identity digest over the raw argv list.
    LaunchArgvDigest {
        argv: Vec<String>,
    },
    /// Canonical-JSON SHA-256 over caller-supplied material.
    ///
    /// `material` is serialized through the CPython-exact canonical writer
    /// (`sort_keys`, separators `(",",":")`, `ensure_ascii`, `allow_nan=false`)
    /// and hashed. `prefix`, when present, is prepended to the hex digest
    /// (e.g. `"sha256:"` for shell-execution context keys). The transport is
    /// a JSON value — raw bytes are NOT representable; use
    /// `OpaqueMaterialDigest` for UTF-8 string material.
    CanonicalSha256 {
        material: Value,
        prefix: Option<String>,
    },
    /// SHA-256 over the UTF-8 bytes of a string (no JSON serialization).
    /// Covers `_opaque_identity_digest`-style digests where the material is
    /// already a string (module specifier, source text, `h:s:n` server key).
    OpaqueMaterialDigest {
        material: String,
    },
    /// Select and hash package-manager policy environment values natively.
    PackageEnvironmentPolicy {
        manager: String,
        environment: BTreeMap<String, String>,
        referenced_names: Vec<String>,
    },
    McpLaunchEnvironment {
        inherited: BTreeMap<String, String>,
        configured: BTreeMap<String, String>,
    },
    /// Validate a persisted package context and recompute its evidence digest.
    PackageExecutionContextFromEvidence {
        material: Value,
    },
    /// Select the first valid package context from scanner evidence.
    PackageExecutionContextFromScannerEvidence {
        material: Value,
    },
    McpServerIdentity {
        request: McpServerIdentityRequestV1,
    },
    McpToolIdentity {
        request: McpToolIdentityRequestV1,
    },
    McpServerDescriptor {
        request: McpServerDescriptorRequestV1,
    },
    McpToolDescriptor {
        request: McpToolDescriptorRequestV1,
    },
    McpToolContentDigest {
        request: McpToolContentDigestRequestV1,
    },
    BrowserMcp {
        request: BrowserMcpRequestV1,
    },
    McpToolRisk {
        artifact: BrowserMcpArtifactV1,
        arguments: Value,
    },
    McpToolPolicy {
        request: McpToolPolicyRequestV1,
    },
    /// Compose the full MCP tool-call approval hash in one request.
    /// `config` absent → legacy `mcp_tool_approval_digest` row; present →
    /// `guard-approval-context:v1:` token. `mcp_tool_risk` carries the
    /// resolved risk categories.
    BuildMcpToolApprovalHash {
        request: McpToolApprovalHashRequestV1,
    },
    /// Legacy standalone digest row — recomputes `persisted_mcp_digest` for a
    /// stored `mcp_tool_approval_digest` payload (no risk categories, no token).
    McpToolApprovalDigest {
        request: McpToolApprovalDigestRequestV1,
    },
    PackageLauncherToken {
        command_name: String,
        args: Vec<String>,
    },
}

// `deny_unknown_fields` cannot combine with `flatten` (serde rejects the
// variant fields outright); strictness is enforced per-variant on the kind
// enum instead.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextDigestRequestV1 {
    pub schema: String,
    pub request_id: String,
    #[serde(flatten)]
    pub kind: ContextDigestKindV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageContextComponentV1 {
    pub name: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageContextEvidenceV1 {
    pub digest: String,
    pub portable: bool,
    pub components: Vec<PackageContextComponentV1>,
    pub non_portable_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageLauncherResultV1 {
    pub package: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextDigestResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the raw request bytes, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_context_*` failure codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Always emitted — `null` is the explicit "unchanged" verdict, so a
    /// result omitting the key is malformed rather than ambiguous.
    #[serde(default)]
    pub validation_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_values: Option<BTreeMap<String, Option<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_launch_environment: Option<BTreeMap<String, String>>,
    /// Explicit null means the supplied persisted evidence is invalid.
    #[serde(default)]
    pub package_context: Option<PackageContextEvidenceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server_identity: Option<McpServerIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool_identity: Option<McpToolIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_launcher: Option<PackageLauncherResultV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_descriptor: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_mcp: Option<BrowserMcpResultV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool_risk: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool_policy: Option<McpToolPolicyResultV1>,
}
