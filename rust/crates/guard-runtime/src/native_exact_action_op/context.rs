//! What every proof reads: the transported environment, the clock and the
//! seams to the resident's own launch-identity and package-intent engines.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use serde_json::{json, Value};

use super::reasons::{Proof, UNPROVEN_LAUNCH};

/// One file of package-execution evidence.
#[derive(Clone, Debug)]
pub(crate) struct EvidenceFile {
    pub(crate) path: String,
    pub(crate) resolved_path: Option<String>,
    pub(crate) status: String,
    pub(crate) content_hash: Option<String>,
}

/// One local execution the package-intent parser proved for a command.
#[derive(Clone, Debug)]
pub(crate) struct LocalExecution {
    pub(crate) local_executable: Option<EvidenceFile>,
    pub(crate) manager: Option<EvidenceFile>,
    pub(crate) manager_is_guard_shim: bool,
    pub(crate) package_name: Option<String>,
    pub(crate) executable_name: Option<String>,
    pub(crate) manifests: Vec<EvidenceFile>,
    pub(crate) lockfiles: Vec<EvidenceFile>,
}

/// The resident engines the proofs build on; tests substitute fixed answers so
/// vectors do not depend on the machine's executables.
pub(crate) trait Engines {
    /// Only the POSIX Python bootstrap proof reads the Guard home.
    #[cfg_attr(windows, allow(dead_code))]
    fn guard_home(&self) -> Option<&Path> {
        None
    }
    fn launch_identity(
        &self,
        executable: &str,
        args: &[String],
        cwd: &str,
        home: Option<&str>,
        env: &BTreeMap<String, String>,
    ) -> Value;
    fn launch_reusable(&self, identity: &Value) -> bool;
    /// The machine-wide git config file git would read. Windows reads the
    /// install's own files instead (`git_windows`).
    #[cfg_attr(windows, allow(dead_code))]
    fn system_git_config(&self) -> String {
        "/etc/gitconfig".to_owned()
    }
    /// The local executions of `command`; `None` when it has no package intent.
    fn local_executions(
        &self,
        command: &str,
        cwd: &str,
        home: Option<&str>,
        env: &BTreeMap<String, String>,
    ) -> Option<Vec<LocalExecution>>;
}

pub(crate) struct Ctx<'a> {
    pub(crate) home: Option<&'a str>,
    pub(crate) env: &'a BTreeMap<String, String>,
    pub(crate) deadline: Instant,
    pub(crate) engines: &'a dyn Engines,
}

impl Ctx<'_> {
    /// Running out of time is an unproven launch, never a partial proof.
    pub(super) fn check(&self) -> Proof<()> {
        if Instant::now() >= self.deadline {
            return Err(UNPROVEN_LAUNCH);
        }
        Ok(())
    }
}

/// The production engines: the resident's own launch-identity and package-intent code.
pub(crate) struct ResidentEngines<'a> {
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) guard_home: Option<&'a Path>,
}

fn evidence_file(
    file: &guard_command::package_intent_common::PackageExecutionFileEvidence,
) -> EvidenceFile {
    EvidenceFile {
        path: file.path.clone(),
        resolved_path: file.resolved_path.clone(),
        status: file.status.to_owned(),
        content_hash: file.content_hash.clone(),
    }
}

impl Engines for ResidentEngines<'_> {
    fn guard_home(&self) -> Option<&Path> {
        self.guard_home
    }

    fn launch_identity(
        &self,
        executable: &str,
        args: &[String],
        cwd: &str,
        home: Option<&str>,
        env: &BTreeMap<String, String>,
    ) -> Value {
        let argv: Vec<Value> = args.iter().map(|arg| json!(arg)).collect();
        let launch_env: Value = env
            .iter()
            .map(|(key, value)| (key.clone(), json!(value)))
            .collect();
        guard_command::launch_identity::build_runtime_launch_identity(
            &json!(executable),
            &argv,
            true,
            false,
            None,
            Some(Path::new(cwd)),
            home.map(Path::new),
            Some(&launch_env),
        )
    }

    fn launch_reusable(&self, identity: &Value) -> bool {
        guard_command::launch_identity::runtime_launch_identity_is_reusable(identity)
    }

    fn local_executions(
        &self,
        command: &str,
        cwd: &str,
        home: Option<&str>,
        env: &BTreeMap<String, String>,
    ) -> Option<Vec<LocalExecution>> {
        // The parser resolves the manager from the caller's `PATH` alone.
        let environment = env
            .get("PATH")
            .filter(|path| !path.is_empty())
            .map(|path| BTreeMap::from([("PATH".to_owned(), path.clone())]));
        let intent = guard_command::package_intent_parser::parse_package_intent(
            command,
            Some(Path::new(cwd)),
            home.map(Path::new),
            None,
            environment.as_ref(),
        )?;
        Some(
            intent
                .local_executions
                .iter()
                .map(|execution| LocalExecution {
                    local_executable: execution.local_executable.as_ref().map(evidence_file),
                    manager: execution.manager.as_ref().map(evidence_file),
                    manager_is_guard_shim: execution.manager_is_guard_shim,
                    package_name: execution.package_name.clone(),
                    executable_name: execution.executable_name.clone(),
                    manifests: execution.manifests.iter().map(evidence_file).collect(),
                    lockfiles: execution.lockfiles.iter().map(evidence_file).collect(),
                })
                .collect(),
        )
    }
}
