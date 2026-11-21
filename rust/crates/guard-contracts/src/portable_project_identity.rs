//! `ProjectIdentity` — wire contract for the resident portable project
//! identity op.
//!
//! The request names one workspace; the result carries the portable Git
//! project identity its conventional clone derives, or none. A workspace the
//! resolver cannot settle is neither: the result is an error, so no caller
//! reads an unsettled workspace as one that has no identity. The identity is
//! classification only: it lives in repository-controlled metadata, so no
//! caller may grant authority on it alone.

use serde::{Deserialize, Serialize};

/// Schema discriminator for the request.
pub const PROJECT_IDENTITY_REQUEST_SCHEMA: &str = "guard-project-identity-request.v1";
/// Schema discriminator for the result.
pub const PROJECT_IDENTITY_RESULT_SCHEMA: &str = "guard-project-identity-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const PROJECT_IDENTITY_FEATURE: &str = "project-identity-v1";
/// Largest canonical request serialization the op will accept.
pub const PROJECT_IDENTITY_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProjectIdentityRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: ProjectIdentityQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProjectIdentityQueryV1 {
    /// The identity of `workspace`: itself when it already is a portable
    /// identity, otherwise the one its Git metadata derives.
    Resolve {
        workspace: String,
        /// The asking process's working directory, which a workspace named
        /// relative to it is read under. A caller that sends none leaves a
        /// relative workspace unsettled.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProjectIdentityPayloadV1 {
    Resolve { identity: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProjectIdentityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_project_identity_*` failure codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<ProjectIdentityPayloadV1>,
}
