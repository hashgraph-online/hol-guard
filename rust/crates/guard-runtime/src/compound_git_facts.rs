//! Observed environment facts behind the compound Git decision.
//!
//! The trait is the single seam between argument/shape logic and everything
//! that touches the machine (Git binary trust, config probes, process
//! environment). Production answers come from the git-execution-safety
//! checks; parity vectors pin them with a stub.

use std::path::{Path, PathBuf};

use guard_contracts::{
    CompoundGitInspectionRequestV1, GitExecutionSafetyCheckV1, GitExecutionSafetyRequestV1,
    GIT_EXECUTION_SAFETY_REQUEST_SCHEMA,
};

use crate::git_execution_safety_binary::resolve_trusted_git;
use crate::git_execution_safety_checks::decide;
use crate::git_execution_safety_config::routing_environment_is_clean;
use crate::git_execution_safety_probe::{ProbeOutput, Prober};

pub(crate) trait GitFacts {
    /// A process environment value from the caller's snapshot.
    fn env(&self, name: &str) -> Option<&str>;
    fn trusted_git(&self, cwd: &Path) -> Option<PathBuf>;
    fn routing_environment_is_clean(&self) -> bool;
    fn fetch_origin_is_safe(&self, cwd: &Path, git: &Path) -> bool;
    fn status_is_safe(&self, cwd: &Path, git: &Path) -> bool;
    fn push_origin_is_safe(&self, cwd: &Path, git: &Path, branch: &str) -> bool;
    fn object_query_is_safe(&self, cwd: &Path, git: &Path) -> bool;
    /// Run a bounded, non-interactive Git query. `None` is a failed probe.
    fn probe(&self, git: &Path, cwd: &Path, arguments: &[&str]) -> Option<ProbeOutput>;
}

pub(crate) struct ResidentGitFacts<'a> {
    request: &'a CompoundGitInspectionRequestV1,
}

impl<'a> ResidentGitFacts<'a> {
    pub(crate) fn new(request: &'a CompoundGitInspectionRequestV1) -> Self {
        Self { request }
    }

    fn safety(
        &self,
        check: GitExecutionSafetyCheckV1,
        cwd: &Path,
        git: &Path,
        branch: Option<&str>,
    ) -> bool {
        let request = GitExecutionSafetyRequestV1 {
            schema: GIT_EXECUTION_SAFETY_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            check,
            cwd: cwd.to_string_lossy().into_owned(),
            home: self.request.home.clone(),
            account_home: self.request.account_home.clone(),
            groups: self.request.groups.clone(),
            environment: self.request.environment.clone(),
            git_binary: Some(git.to_string_lossy().into_owned()),
            git_path: None,
            arguments: Vec::new(),
            branch: branch.map(str::to_owned),
            reference: None,
        };
        decide(&request).allowed
    }
}

impl GitFacts for ResidentGitFacts<'_> {
    fn env(&self, name: &str) -> Option<&str> {
        self.request.environment.get(name).map(String::as_str)
    }

    fn trusted_git(&self, cwd: &Path) -> Option<PathBuf> {
        resolve_trusted_git(
            cwd,
            &self.request.environment,
            Path::new(&self.request.home),
            &self.request.groups,
        )
    }

    fn routing_environment_is_clean(&self) -> bool {
        routing_environment_is_clean(&self.request.environment)
    }

    fn fetch_origin_is_safe(&self, cwd: &Path, git: &Path) -> bool {
        self.safety(GitExecutionSafetyCheckV1::FetchOrigin, cwd, git, None)
    }

    fn status_is_safe(&self, cwd: &Path, git: &Path) -> bool {
        self.safety(GitExecutionSafetyCheckV1::StatusConfig, cwd, git, None)
    }

    fn push_origin_is_safe(&self, cwd: &Path, git: &Path, branch: &str) -> bool {
        self.safety(
            GitExecutionSafetyCheckV1::PushOrigin,
            cwd,
            git,
            Some(branch),
        )
    }

    fn object_query_is_safe(&self, cwd: &Path, git: &Path) -> bool {
        self.safety(GitExecutionSafetyCheckV1::ObjectQuery, cwd, git, None)
    }

    fn probe(&self, git: &Path, cwd: &Path, arguments: &[&str]) -> Option<ProbeOutput> {
        Prober {
            git,
            cwd,
            environment: &self.request.environment,
        }
        .run(arguments)
    }
}
