//! `PackageContextBuild` — wire contract for the resident package execution
//! context build op.
//!
//! The request carries the process facts the Python builder used to read from
//! its own interpreter (working directory, home directory, the ambient `PATH`
//! and the environment it was asked to describe), so the result depends only on
//! the request and the files it names. The result always carries `status`, so
//! the Python transport can tell success from a typed failure and never builds
//! a context itself.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Schema discriminator for the request.
pub const PACKAGE_CONTEXT_BUILD_REQUEST_SCHEMA: &str = "guard-package-context-build-request.v1";
/// Schema discriminator for the result.
pub const PACKAGE_CONTEXT_BUILD_RESULT_SCHEMA: &str = "guard-package-context-build-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const PACKAGE_CONTEXT_BUILD_FEATURE: &str = "package-context-build-v1";
/// Largest canonical request serialization the op will accept.
pub const PACKAGE_CONTEXT_BUILD_MAX_BYTES: usize = 512 * 1024;

/// The artifact metadata keys the build reads, already reduced to strings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageContextBuildMetadataV1 {
    /// `metadata["package_manager"]` when it is a string.
    #[serde(default)]
    pub package_manager: Option<String>,
    /// `metadata["package_executable"]` when it is a string.
    #[serde(default)]
    pub package_executable: Option<String>,
    /// String items of `metadata["flags"]`.
    #[serde(default)]
    pub flags: Vec<String>,
    /// String items of `metadata["manifest_paths"]`.
    #[serde(default)]
    pub manifest_paths: Vec<String>,
    /// String items of `metadata["lockfile_paths"]`.
    #[serde(default)]
    pub lockfile_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageContextBuildRequestV1 {
    pub schema: String,
    /// Caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    pub guard_home: String,
    /// `workspace_dir`, before `expanduser().resolve()`.
    pub workspace_dir: String,
    #[serde(default)]
    pub metadata: PackageContextBuildMetadataV1,
    /// The explicit executable, when the caller named one.
    #[serde(default)]
    pub executable: Option<String>,
    #[serde(default)]
    pub executable_args: Vec<String>,
    /// The environment being described (`os.environ` when the caller gave none).
    pub environment: BTreeMap<String, String>,
    /// `os.getcwd()`.
    pub process_cwd: String,
    /// `Path.home()`.
    pub process_home: String,
    /// `os.environ.get("HOME")`.
    #[serde(default)]
    pub process_home_env: Option<String>,
    /// `os.environ.get("PATH")`.
    #[serde(default)]
    pub process_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageContextBuildComponentV1 {
    pub name: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageContextBuildContextV1 {
    pub digest: String,
    pub portable: bool,
    pub components: Vec<PackageContextBuildComponentV1>,
    pub non_portable_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageContextBuildResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_package_context_build_*` failure codes.
    pub code: String,
    /// The failure reason, when the build failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<PackageContextBuildContextV1>,
}
