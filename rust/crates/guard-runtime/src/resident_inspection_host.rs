//! The inspection host the resident's command reviews read the world through.
//!
//! Every question the shared command model asks about git, trusted binaries
//! and the environment is answered from the request's observed facts and the
//! resident's own git safety checks; nothing here runs on Python's side.

use guard_command::{GitCheck, GitProbe, InspectionHost};
use guard_contracts::{
    CodexToolOutputFactsV1, CompoundGitSegmentV1, GitExecutionSafetyCheckV1,
    GitExecutionSafetyRequestV1, GIT_EXECUTION_SAFETY_REQUEST_SCHEMA,
};

pub(crate) struct ResidentInspectionHost<'a> {
    pub(crate) facts: &'a CodexToolOutputFactsV1,
}

impl ResidentInspectionHost<'_> {
    fn decide_git(
        &self,
        check: GitExecutionSafetyCheckV1,
        cwd: Option<&str>,
        arguments: &[String],
        git_path: Option<&str>,
    ) -> bool {
        self.git_request_allowed(check, cwd, arguments, git_path, None)
    }

    pub(crate) fn git_request_allowed(
        &self,
        check: GitExecutionSafetyCheckV1,
        cwd: Option<&str>,
        arguments: &[String],
        git_path: Option<&str>,
        reference: Option<&str>,
    ) -> bool {
        let request = GitExecutionSafetyRequestV1 {
            schema: GIT_EXECUTION_SAFETY_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            check,
            cwd: cwd.unwrap_or(&self.facts.home).to_owned(),
            home: self.facts.home.clone(),
            account_home: self.facts.account_home.clone(),
            groups: self.facts.groups.clone(),
            environment: self.facts.environment.clone(),
            git_binary: None,
            git_path: git_path.map(str::to_owned),
            arguments: arguments.to_vec(),
            branch: None,
            reference: reference.map(str::to_owned),
        };
        crate::git_execution_safety_checks::decide(&request).allowed
    }
}

impl InspectionHost for ResidentInspectionHost<'_> {
    fn env(&self, name: &str) -> Option<String> {
        self.facts.environment.get(name).cloned()
    }

    fn environment(&self) -> Vec<(String, String)> {
        self.facts
            .environment
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }

    fn git_executable(&self) -> Option<String> {
        self.facts.git_executable.clone()
    }

    fn git_binary_trusted(&self, git: &str, cwd: &str) -> bool {
        self.decide_git(
            GitExecutionSafetyCheckV1::BinaryTrusted,
            Some(cwd),
            &[],
            Some(git),
        )
    }

    fn git_safety(&self, check: GitCheck, cwd: Option<&str>, arguments: &[String]) -> bool {
        let check = match check {
            GitCheck::ResolveBinary => GitExecutionSafetyCheckV1::ResolveBinary,
            GitCheck::ConfigEnvironmentClean => GitExecutionSafetyCheckV1::ConfigEnvironmentClean,
            GitCheck::StatusArguments => GitExecutionSafetyCheckV1::StatusArguments,
            GitCheck::StatusConfig => GitExecutionSafetyCheckV1::StatusConfig,
        };
        self.decide_git(check, cwd, arguments, None)
    }

    fn compound_git_chain(&self, segments: &[CompoundGitSegmentV1], complete: bool) -> bool {
        self.svc_compound_chain(segments, complete)
    }

    fn git_inspection_segment(
        &self,
        segment: &CompoundGitSegmentV1,
        home_dir: Option<&str>,
    ) -> bool {
        self.svc_inspection_segment(segment, home_dir)
    }

    fn cached_diff_pathspecs(&self, values: &[String]) -> bool {
        self.svc_cached_diff_pathspecs(values)
    }

    fn git_show_config(
        &self,
        segment: &CompoundGitSegmentV1,
        repository_path: Option<&str>,
    ) -> bool {
        self.svc_show_config(segment, repository_path)
    }

    fn git_log_execution_free_config(&self, cwd: &str, git: &str) -> bool {
        self.svc_log_config(cwd, git)
    }

    fn standalone_git_routine(
        &self,
        segments: &[CompoundGitSegmentV1],
        complete: bool,
        home_dir: Option<&str>,
    ) -> bool {
        self.svc_standalone_routine(segments, complete, home_dir)
    }

    fn trusted_path_command(&self, command: &str, cwd: &str, home_dir: &str) -> bool {
        self.svc_trusted_path_command(command, cwd, home_dir)
    }

    /// The evidence builder reads the package, lock and executable through the
    /// crate's `O_NOFOLLOW` integrity helpers, which are POSIX-only, so
    /// `contained_runner` itself is `cfg(unix)`. Off Unix the resident keeps the
    /// trait's fail-closed answer and the chain stays unrecognized, exactly as
    /// it did before this hook was answered anywhere.
    #[cfg(unix)]
    fn bun_script_evidence_complete(&self, script_args: &[String], workspace: &str) -> bool {
        guard_command::contained_runner::bun_script_evidence_complete(
            script_args,
            std::path::Path::new(workspace),
        )
    }

    fn trusted_git_binary(&self, cwd: &str) -> Option<String> {
        self.svc_trusted_git(cwd)
    }

    fn git_probe(&self, git: &str, args: &[String], cwd: &str) -> Option<GitProbe> {
        self.svc_probe(git, args, cwd)
    }

    fn git_worktree_add_config(&self, git: &str, cwd: &str, reference: &str) -> bool {
        self.svc_worktree_add_config(git, cwd, reference)
    }

    fn git_lfs_trusted(&self, cwd: &str) -> bool {
        self.svc_trusted_path_command("git-lfs", cwd, &self.facts.home)
    }

    fn home_git_c_path(&self, command: &str) -> Option<String> {
        self.svc_home_git_c_path(command)
    }

    fn git_object_existence_query(&self, command: &str, cwd: &str) -> bool {
        self.svc_object_existence(command, cwd)
    }

    fn real_path(&self, path: &str) -> Option<String> {
        path.starts_with('/')
            .then(|| crate::oci_path::resolve_lenient(path))
    }
}
