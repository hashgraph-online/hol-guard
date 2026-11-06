//! Observed environment facts behind the compound Git decision.
//!
//! The trait is the single seam between argument/shape logic and everything
//! that touches the machine (Git binary trust, config probes, process
//! environment). Production answers come from the git-execution-safety
//! checks; parity vectors pin them with a stub.

use std::cell::RefCell;
use std::collections::HashMap;
use std::mem::Discriminant;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

/// Aggregate budget for one evaluation. It sits below the caller's own
/// deadline so an overlong chain is denied by the resident, and stops using
/// its worker, instead of outliving a caller that already gave up.
pub(crate) const EVALUATION_BUDGET: Duration = Duration::from_secs(6);

type ProbeKey = (PathBuf, PathBuf, Vec<String>);
type SafetyKey = (
    Discriminant<GitExecutionSafetyCheckV1>,
    PathBuf,
    PathBuf,
    Option<String>,
);

/// Production facts for one request. Every fact is answered at most once per
/// distinct question (a chain repeats the same config probes for each segment
/// in a directory) and nothing new starts after the evaluation deadline, so
/// work is bounded by the budget; an expired deadline answers as a failed
/// probe, which every caller treats as a denial.
pub(crate) struct ResidentGitFacts<'a> {
    request: &'a CompoundGitInspectionRequestV1,
    deadline: Instant,
    trusted: RefCell<HashMap<PathBuf, Option<PathBuf>>>,
    probes: RefCell<HashMap<ProbeKey, Option<ProbeOutput>>>,
    safety_checks: RefCell<HashMap<SafetyKey, bool>>,
}

impl<'a> ResidentGitFacts<'a> {
    pub(crate) fn new(request: &'a CompoundGitInspectionRequestV1) -> Self {
        Self::with_deadline(request, Instant::now() + EVALUATION_BUDGET)
    }

    pub(crate) fn with_deadline(
        request: &'a CompoundGitInspectionRequestV1,
        deadline: Instant,
    ) -> Self {
        Self {
            request,
            deadline,
            trusted: RefCell::default(),
            probes: RefCell::default(),
            safety_checks: RefCell::default(),
        }
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn safety(
        &self,
        check: GitExecutionSafetyCheckV1,
        cwd: &Path,
        git: &Path,
        branch: Option<&str>,
    ) -> bool {
        let key = (
            std::mem::discriminant(&check),
            cwd.to_path_buf(),
            git.to_path_buf(),
            branch.map(str::to_owned),
        );
        if let Some(answer) = self.safety_checks.borrow().get(&key) {
            return *answer;
        }
        if self.expired() {
            return false;
        }
        let answer = self.uncached_safety(check, cwd, git, branch);
        self.safety_checks.borrow_mut().insert(key, answer);
        answer
    }

    fn uncached_safety(
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
        if let Some(answer) = self.trusted.borrow().get(cwd) {
            return answer.clone();
        }
        if self.expired() {
            return None;
        }
        let answer = resolve_trusted_git(
            cwd,
            &self.request.environment,
            Path::new(&self.request.home),
            &self.request.groups,
        );
        self.trusted
            .borrow_mut()
            .insert(cwd.to_path_buf(), answer.clone());
        answer
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
        let key = (
            git.to_path_buf(),
            cwd.to_path_buf(),
            arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
        );
        if let Some(answer) = self.probes.borrow().get(&key) {
            return answer.clone();
        }
        if self.expired() {
            return None;
        }
        let answer = Prober {
            git,
            cwd,
            environment: &self.request.environment,
        }
        .run(arguments);
        self.probes.borrow_mut().insert(key, answer.clone());
        answer
    }
}
