//! Resident filesystem and sensitivity services for the fused shell kernels.
use crate::codex_tool_output_op::ResidentInspectionHost;
use guard_command::{GitCheck, GitProbe, GitRun, InspectionHost};
use guard_contracts::CompoundGitSegmentV1;
use serde_json::json;

pub(crate) struct DeveloperInspectionHost<'a> {
    pub(crate) base: ResidentInspectionHost<'a>,
    pub(crate) authority: crate::direct_tool_context_op::Authority<'a>,
}
impl InspectionHost for DeveloperInspectionHost<'_> {
    fn env(&self, name: &str) -> Option<String> {
        self.base.env(name)
    }
    fn environment(&self) -> Vec<(String, String)> {
        self.base.environment()
    }
    fn git_executable(&self) -> Option<String> {
        self.base.git_executable()
    }
    fn git_binary_trusted(&self, git: &str, cwd: &str) -> bool {
        self.base.git_binary_trusted(git, cwd)
    }
    fn git_safety(&self, check: GitCheck, cwd: Option<&str>, arguments: &[String]) -> bool {
        self.base.git_safety(check, cwd, arguments)
    }
    fn run_git(&self, git: &str, args: &[String], cwd: &str) -> GitRun {
        self.base.run_git(git, args, cwd)
    }
    fn compound_git_chain(&self, segments: &[CompoundGitSegmentV1], complete: bool) -> bool {
        self.base.compound_git_chain(segments, complete)
    }
    fn git_inspection_segment(
        &self,
        segment: &CompoundGitSegmentV1,
        home_dir: Option<&str>,
    ) -> bool {
        self.base.git_inspection_segment(segment, home_dir)
    }
    fn cached_diff_pathspecs(&self, values: &[String]) -> bool {
        self.base.cached_diff_pathspecs(values)
    }
    fn git_show_config(
        &self,
        segment: &CompoundGitSegmentV1,
        repository_path: Option<&str>,
    ) -> bool {
        self.base.git_show_config(segment, repository_path)
    }
    fn git_log_execution_free_config(&self, cwd: &str, git: &str) -> bool {
        self.base.git_log_execution_free_config(cwd, git)
    }
    fn standalone_git_routine(
        &self,
        segments: &[CompoundGitSegmentV1],
        complete: bool,
        home_dir: Option<&str>,
    ) -> bool {
        self.base
            .standalone_git_routine(segments, complete, home_dir)
    }
    fn trusted_path_command(&self, command: &str, cwd: &str, home_dir: &str) -> bool {
        self.base.trusted_path_command(command, cwd, home_dir)
    }
    fn trusted_git_binary(&self, cwd: &str) -> Option<String> {
        self.base.trusted_git_binary(cwd)
    }
    fn git_probe(&self, git: &str, args: &[String], cwd: &str) -> Option<GitProbe> {
        self.base.git_probe(git, args, cwd)
    }
    fn git_worktree_add_config(&self, git: &str, cwd: &str, reference: &str) -> bool {
        self.base.git_worktree_add_config(git, cwd, reference)
    }
    fn git_lfs_trusted(&self, cwd: &str) -> bool {
        self.base.git_lfs_trusted(cwd)
    }
    fn home_git_c_path(&self, command: &str) -> Option<String> {
        self.base.home_git_c_path(command)
    }
    fn git_object_existence_query(&self, command: &str, cwd: &str) -> bool {
        self.base.git_object_existence_query(command, cwd)
    }
    fn direct_tool_authority(
        &self,
    ) -> Option<&dyn guard_command::direct_vitest::DirectToolAuthority> {
        Some(&self.authority)
    }
    fn current_uid(&self) -> Option<u32> {
        #[cfg(unix)]
        {
            Some(nix::unistd::getuid().as_raw())
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
    fn secret_content_found(&self, text: &str, is_path: bool) -> bool {
        if is_path {
            return true;
        }
        let request =
            json!({"text":text,"suppress_samples":false,"documentation_sample_context":false});
        guard_command::content_sensitivity::evaluate(
            "content",
            &request,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .map_or(true, |result| {
            result["ok"]
                .as_array()
                .is_none_or(|matches| !matches.is_empty())
        })
    }
}
