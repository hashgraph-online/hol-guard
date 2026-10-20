//! `ShimAdmin` — wire contract for the resident package-shim administration op.
//!
//! The request carries the process facts the shim logic used to read from its
//! own interpreter (environment, home, working directory, executable), so the
//! result depends only on the request and the files it names. The result
//! always carries `status`, so the Python transport can tell success from a
//! typed failure and never recomputes a result itself.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const SHIM_ADMIN_REQUEST_SCHEMA: &str = "guard-shim-admin-request.v2";
/// Schema discriminator for the result.
pub const SHIM_ADMIN_RESULT_SCHEMA: &str = "guard-shim-admin-result.v2";
/// Capability advertised by the runtime when this operation is available.
pub const SHIM_ADMIN_FEATURE: &str = "shim-admin-v4";
/// Largest canonical request serialization the op will accept.
pub const SHIM_ADMIN_MAX_BYTES: usize = 512 * 1024;

/// Process facts the Python shim code read from `sys`, `os` and `Path`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ShimAdminFactsV2 {
    /// `os.environ` (only the keys the subop needs; a probe sends them all
    /// because the shim child inherits them).
    pub environ: BTreeMap<String, String>,
    /// `Path.home()`.
    pub home: String,
    /// `os.getcwd()`.
    pub cwd: String,
    /// `sys.executable`.
    pub executable: String,
    /// `getattr(sys, "frozen", False)`.
    pub frozen: bool,
    /// `resolve_frozen_guard_cli()`; read only when `frozen`.
    #[serde(default)]
    pub frozen_cli: String,
    /// `trusted_frozen_guard_cli_paths()`; read only when `frozen`.
    #[serde(default)]
    pub trusted_frozen_cli_paths: Vec<String>,
    /// `sys.version_info[:2]`.
    pub python_version: [u32; 2],
    /// `_trusted_import_root()`.
    pub import_root: String,
    /// `sys.argv[0]`, when `sys.argv` is non-empty.
    #[serde(default)]
    pub argv0: Option<String>,
    /// `os.name == "nt"`.
    pub windows: bool,
    /// `SQLITE_CONNECT_TIMEOUT_SECONDS`.
    pub sqlite_connect_timeout_seconds: f64,
    /// ISO-8601 UTC timestamp standing in for `datetime.now(timezone.utc)`.
    pub now: String,
    /// `shims._is_transient_path` of the package-shim directory.
    /// Absent: the resident applies its own transient-path check.
    #[serde(default)]
    pub shim_dir_transient: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ShimAdminRequestV2 {
    pub schema: String,
    /// Caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// `status` | `dashboard_status` | `cloud_coverage` | `path_order` |
    /// `install` | `activate` | `repair` | `uninstall` | `probe_intercepts` |
    /// `supported_managers` | `ensure_package_shim_profile` |
    /// `remove_guard_profile_blocks` | `record_audit` |
    /// `digest_binding_sink`.
    pub subop: String,
    pub guard_home: String,
    /// `HarnessContext.home_dir`.
    #[serde(default)]
    pub home_dir: Option<String>,
    /// `HarnessContext.workspace_dir`, or the probe workspace override.
    #[serde(default)]
    pub workspace_dir: Option<String>,
    /// Explicit managers (None = the subop's default).
    #[serde(default)]
    pub managers: Option<Vec<String>>,
    /// PATH override (None = `facts.environ["PATH"]`).
    #[serde(default)]
    pub path_env: Option<String>,
    /// `path_order` and `digest_binding_sink`: the manager to inspect.
    #[serde(default)]
    pub manager: Option<String>,
    /// `digest_binding_sink`: the package executable the artifact names.
    #[serde(default)]
    pub executable: Option<String>,
    /// `digest_binding_sink`: the raw command the harness is about to run.
    #[serde(default)]
    pub command: Option<String>,
    /// `activate`: repair instead of install.
    #[serde(default)]
    pub repair: Option<bool>,
    /// `probe_intercepts`: probe even when PATH is inactive.
    #[serde(default)]
    pub allow_inactive_path: Option<bool>,
    /// `probe_intercepts`: judge PATH by the dashboard projection.
    #[serde(default)]
    pub project_shell_profile: Option<bool>,
    /// `probe_intercepts`: per-shim timeout.
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// `cloud_coverage`: the `generated_at` override.
    #[serde(default)]
    pub generated_at: Option<String>,
    pub facts: ShimAdminFactsV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ShimAdminResultV2 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_shim_admin_*` failure codes.
    pub code: String,
    /// The failure reason, when the subop raised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// An object, or an array for `supported_managers`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}
