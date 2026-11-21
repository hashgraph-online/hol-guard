//! Runtime identity records. The built-in engine has no package files, so
//! these only carry the derived identity of the engine compiled into Guard.
use guard_cigar_release::ReleaseBinding;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Private host-selected paths. Never derive these from an agent context call.
/// For the built-in engine `python` holds the Guard executable that hosts the
/// bridge, and `site_packages` is empty.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSelection {
    pub python: PathBuf,
    pub site_packages: PathBuf,
    pub work_dir: PathBuf,
}

/// Identity of the engine a runtime runs. Guard derives it from the engine
/// compiled into it and the target platform (see `start_builtin`), so it needs
/// no saved installation record; public HTTP/MCP clients may not supply or
/// replace it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleApproval {
    pub schema: String,
    pub platform: String,
    pub python_sha256: String,
    pub package_tree_sha256: String,
    pub worker_sha256: String,
    pub files: usize,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseBinding>,
}
