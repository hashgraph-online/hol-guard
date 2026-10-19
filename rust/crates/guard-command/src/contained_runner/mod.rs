//! Faithful Rust port of the contained node, TypeScript and package-script
//! runners: containment contract, OS-enforced snapshot execution and proofs.

pub(crate) mod common;
pub(crate) mod contract;
pub(crate) mod decision;
pub(crate) mod exec;
pub(crate) mod flows;
pub(crate) mod health;
mod input_snapshot;
pub(crate) mod node_evidence;
pub(crate) mod pkg_json;
mod process;
pub(crate) mod runner_options;
mod sandbox_argv;
pub(crate) mod script_evidence;
pub(crate) mod snapshot;
pub(crate) mod ts_inputs;

#[cfg(test)]
mod vector_fs_tests;
#[cfg(test)]
mod vector_support;
#[cfg(test)]
mod vector_tests;

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

/// Resident-facing launch request shared by the three contained runners.
pub struct RunnerLaunch<'a> {
    pub workspace: &'a Path,
    pub manager: &'a str,
    pub argv: &'a [String],
    pub shim_directory: &'a Path,
    pub environment: &'a BTreeMap<String, String>,
    /// Process timeout in seconds; `None` selects the 120 second default.
    pub timeout_seconds: Option<f64>,
}

impl RunnerLaunch<'_> {
    fn launch(&self) -> flows::Launch<'_> {
        flows::Launch {
            workspace: self.workspace,
            manager: self.manager,
            argv: self.argv,
            shim_directory: self.shim_directory,
            environment: self.environment,
            timeout_seconds: self
                .timeout_seconds
                .unwrap_or(flows::DEFAULT_TIMEOUT_SECONDS),
        }
    }
}

/// Contained local Node runner (`npx`/`bunx` test, lint or diagnostic tool).
pub fn execute_node(launch: &RunnerLaunch, execution: &Value) -> Result<Value, String> {
    flows::run_node(&launch.launch(), execution)?.to_value()
}

/// Contained local TypeScript compiler check (`npx tsc`).
pub fn execute_typescript(launch: &RunnerLaunch, execution: &Value) -> Result<Value, String> {
    flows::run_typescript(&launch.launch(), execution)?.to_value()
}

/// Contained local Bun package script.
pub fn execute_package_script(launch: &RunnerLaunch) -> Result<Value, String> {
    flows::run_package_script(&launch.launch())?.to_value()
}

/// Whether one exact `bun run <operation>` still binds to its package, lock,
/// executable and inputs in `workspace`.
///
/// `_bounded_local_runner_chain_is_safe`
/// (`secret_file_request_services/shell_quote_parsing.py:198`) asks the
/// evidence builder exactly this one question and keeps nothing else from the
/// answer, so the resident can answer it from the crate's own port instead of
/// calling back into Python. An unreadable workspace, a script that does not
/// bind, or any builder error is not complete: the chain stays unrecognized
/// and the caller refuses it.
pub fn bun_script_evidence_complete(argv: &[String], workspace: &Path) -> bool {
    matches!(
        script_evidence::build_local_package_script_evidence("bun", argv, workspace),
        Ok(Some(evidence)) if evidence.complete
    )
}
