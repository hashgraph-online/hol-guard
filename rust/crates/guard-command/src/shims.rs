//! Native package-shim administration.
//!
//! This module owns the status, probe, install, repair, activation and
//! PATH-order logic that used to live in Python `guard/shims.py`. The result
//! shapes, file formats and generated shim bytes are those of that Python
//! implementation; the parity vectors under `tests/fixtures` were recorded from
//! it.
//!
//! Nothing here reads the resident's own process state. Everything the Python
//! code took from `os.environ`, `sys`, `Path.home()` and the working directory
//! arrives as explicit [`ShimFacts`], so a result depends only on the request
//! and the files it names.

mod admin;
mod audit;
mod audit_manifest;
mod digest_binding_sink;
mod frozen;
mod generate;
mod manifest;
mod path_order;
mod probe;
mod profile;
mod pyfs;
mod pyfs_nt;
mod status;
mod template;
mod values;
mod winpath;

use std::collections::BTreeMap;

pub use admin::{
    activate_package_shims, install_package_shims, repair_package_shims, uninstall_package_shims,
};
pub use audit::record_package_shim_audit_result;
pub use digest_binding_sink::package_shim_digest_binding_sink;
pub use path_order::get_path_order_status;
pub use probe::{probe_package_shim_intercepts, ProbeOptions};
pub use profile::{
    ensure_package_shim_path_in_shell_profile, remove_guard_profile_blocks,
    strip_managed_marker_blocks,
};
pub use status::{
    package_shim_cloud_coverage, package_shim_dashboard_status, package_shim_protection,
    package_shim_protection_from_status, package_shim_status,
};

/// Sentinel assignment the generated shims carry (`<name> = True`).
pub const FROZEN_PACKAGE_SHIM_SENTINEL: &str = "HOL_GUARD_PACKAGE_SHIM_SENTINEL";
/// Environment variable that turns a shim run into an intercept probe.
pub const SHIM_PROBE_ENV_VAR: &str = "HOL_GUARD_SHIM_PROBE";
/// Value of [`SHIM_PROBE_ENV_VAR`] for a probe run.
pub const SHIM_PROBE_ENV_VALUE: &str = "1";
/// Descriptor environment variable POSIX shims use for immediate status.
pub const PACKAGE_SHIM_STATUS_FD_ENV_VAR: &str = "HOL_GUARD_PACKAGE_SHIM_STATUS_FD";

pub(crate) const PACKAGE_SHIM_MANIFEST: &str = "manifest.json";
pub(crate) const GUARD_PROFILE_MARKER: &str = "# HOL Guard harness launchers";
pub(crate) const PACKAGE_PROFILE_MARKER: &str = "# HOL Guard package manager shims";

/// Supported managers; every manager's command is its own name.
const PACKAGE_SHIM_COMMANDS: [&str; 20] = [
    "brew", "bun", "bunx", "bundle", "cargo", "composer", "go", "gradle", "mvn", "npm", "npx",
    "pip", "pip3", "pipenv", "pipx", "pnpm", "poetry", "uv", "uvx", "yarn",
];

/// The shim command for `manager`, when supported.
pub(crate) fn package_shim_command(manager: &str) -> Option<&'static str> {
    PACKAGE_SHIM_COMMANDS
        .iter()
        .copied()
        .find(|candidate| *candidate == manager)
}

/// `package_shim_supported_managers()`: the supported managers, sorted.
#[must_use]
pub fn package_shim_supported_managers() -> Vec<&'static str> {
    let mut managers = PACKAGE_SHIM_COMMANDS.to_vec();
    managers.sort_unstable();
    managers
}

/// Process facts the Python implementation read from its own interpreter.
#[derive(Debug, Clone)]
pub struct ShimFacts {
    /// `os.environ` (only the keys the caller chose to forward; a probe
    /// forwards all of them because the shim child inherits them).
    pub environ: BTreeMap<String, String>,
    /// `Path.home()`.
    pub home: String,
    /// `os.getcwd()`.
    pub cwd: String,
    /// `sys.executable`.
    pub executable: String,
    /// `getattr(sys, "frozen", False)`.
    pub frozen: bool,
    /// `resolve_frozen_guard_cli()`; only read when `frozen`.
    pub frozen_cli: String,
    /// `trusted_frozen_guard_cli_paths()`; only read when `frozen`.
    pub trusted_frozen_cli_paths: Vec<String>,
    /// `sys.version_info[:2]`.
    pub python_version: (u32, u32),
    /// `_trusted_import_root()`.
    pub import_root: String,
    /// `sys.argv[0]`, when `sys.argv` is non-empty.
    pub argv0: Option<String>,
    /// `os.name == "nt"`.
    pub windows: bool,
    /// `SQLITE_CONNECT_TIMEOUT_SECONDS`.
    pub sqlite_connect_timeout_seconds: f64,
    /// ISO-8601 UTC timestamp standing in for `datetime.now(timezone.utc)`.
    pub now: String,
    /// `shims._is_transient_path` of this request's package-shim directory.
    /// `None` means the resident applies `is_transient_path` itself.
    pub shim_dir_transient: Option<bool>,
}

/// The `HarnessContext` the Python functions took, plus the process facts.
#[derive(Debug, Clone)]
pub struct ShimContext {
    pub guard_home: String,
    pub home_dir: Option<String>,
    pub workspace_dir: Option<String>,
    pub facts: ShimFacts,
}

impl ShimContext {
    /// Build a context the way `HarnessContext(...)` holds its paths: each is
    /// a `Path`, so empty and `.` segments and a trailing slash are dropped.
    #[must_use]
    pub fn new(
        guard_home: &str,
        home_dir: Option<&str>,
        workspace_dir: Option<&str>,
        facts: ShimFacts,
    ) -> Self {
        Self {
            guard_home: facts.norm(guard_home),
            home_dir: home_dir.map(|value| facts.norm(value)),
            workspace_dir: workspace_dir.map(|value| facts.norm(value)),
            facts,
        }
    }

    /// `guard_home / "package-shims" / "bin"`.
    pub(crate) fn shim_dir(&self) -> String {
        let root = self.facts.join(&self.guard_home, "package-shims");
        self.facts.join(&root, "bin")
    }

    /// `guard_home / "package-shims" / "manifest.json"`.
    pub(crate) fn manifest_path(&self) -> String {
        let root = self.facts.join(&self.guard_home, "package-shims");
        self.facts.join(&root, PACKAGE_SHIM_MANIFEST)
    }

    /// `os.pathsep`.
    pub(crate) fn pathsep(&self) -> char {
        if self.facts.windows {
            ';'
        } else {
            ':'
        }
    }

    /// `os.environ.get("PATH", "")`.
    pub(crate) fn env_path(&self) -> &str {
        self.facts.environ.get("PATH").map_or("", String::as_str)
    }
}

/// Failure of an admin call; the Python code raised in these cases.
pub type ShimResult<T> = Result<T, String>;
