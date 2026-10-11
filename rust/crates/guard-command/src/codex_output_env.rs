//! Process facts and git execution for the Codex tool-output review.
//!
//! The review is pure text and filesystem logic. Everything that depends on the
//! caller's process (environment, trusted git binary, git execution safety, a
//! bounded git run) goes through [`InspectionHost`] so the host (the resident)
//! owns process execution and this crate stays free of it.

use guard_contracts::CompoundGitSegmentV1;

use crate::codex_output_py::PyPath;

/// Which git execution safety check to run (`git_execution_safety_checks`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitCheck {
    ResolveBinary,
    ConfigEnvironmentClean,
    StatusArguments,
    StatusConfig,
}

/// Outcome of one bounded git run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GitRun {
    Output(Vec<u8>),
    Failed(&'static str),
}

/// Process-dependent services the review needs.
pub trait InspectionHost {
    /// Value of an environment variable from the caller's snapshot.
    fn env(&self, name: &str) -> Option<String>;
    /// `shutil.which("git")` from the caller.
    fn git_executable(&self) -> Option<String>;
    /// One git execution safety decision.
    fn git_safety(&self, check: GitCheck, cwd: Option<&str>, arguments: &[String]) -> bool;
    /// Whether this exact, already canonical `git` executable is trusted to run
    /// in `cwd` (not under the home, temp or working directory, no loose modes).
    fn git_binary_trusted(&self, git: &str, cwd: &str) -> bool;
    /// Run `git <args>` in `cwd` with the bounded pathspec profile.
    fn run_git(&self, git: &str, args: &[String], cwd: &str) -> GitRun;
    /// `is_low_risk_compound_git_inspection` over a modeled, complete chain.
    /// Hosts without a git inspection service refuse.
    fn compound_git_chain(&self, _segments: &[CompoundGitSegmentV1], _complete: bool) -> bool {
        false
    }
    /// `is_low_risk_git_inspection_segment` for one modeled segment.
    fn git_inspection_segment(
        &self,
        _segment: &CompoundGitSegmentV1,
        _home_dir: Option<&str>,
    ) -> bool {
        false
    }
    /// `_cached_diff_pathspecs_allowed` over the pathspecs after `--`.
    fn cached_diff_pathspecs(&self, _values: &[String]) -> bool {
        false
    }
    /// `_git_show_has_execution_free_config` for one modeled segment.
    fn git_show_config(
        &self,
        _segment: &CompoundGitSegmentV1,
        _repository_path: Option<&str>,
    ) -> bool {
        false
    }
    /// `is_low_risk_standalone_git_routine` over a modeled chain.
    fn standalone_git_routine(
        &self,
        _segments: &[CompoundGitSegmentV1],
        _complete: bool,
        _home_dir: Option<&str>,
    ) -> bool {
        false
    }
    /// `_trusted_path_command`: a trusted executable on the search path.
    fn trusted_path_command(&self, _command: &str, _cwd: &str, _home_dir: &str) -> bool {
        false
    }
    /// `build_local_package_script_evidence("bun", args, workspace)` is complete.
    fn bun_script_evidence_complete(&self, _script_args: &[String], _workspace: &str) -> bool {
        false
    }
}

/// Per-request context.
pub struct Ctx<'a> {
    pub host: &'a dyn InspectionHost,
    /// `os.getcwd()` of the caller.
    pub(crate) process_cwd: PyPath,
    /// `Path.home()` of the caller.
    pub(crate) default_home: PyPath,
}

impl<'a> Ctx<'a> {
    pub fn new(host: &'a dyn InspectionHost, process_cwd: &str, default_home: &str) -> Self {
        Self {
            host,
            process_cwd: PyPath::new(process_cwd),
            default_home: PyPath::new(default_home),
        }
    }
}

impl Ctx<'_> {
    /// `Path(text).expanduser()`; `None` is the `RuntimeError` for a home that
    /// cannot be determined (`~user` forms are not expanded).
    pub(crate) fn expanduser(&self, text: &str) -> Option<PyPath> {
        let path = PyPath::new(text);
        let comps = path.components();
        if path.is_absolute() || !comps.first().is_some_and(|first| first.starts_with('~')) {
            return Some(path);
        }
        if comps[0] != "~" {
            return None;
        }
        let home = self
            .host
            .env("HOME")
            .unwrap_or_else(|| self.default_home.to_string());
        let rest = comps[1..].join("/");
        let joined = if rest.is_empty() {
            home.trim_end_matches('/').to_owned()
        } else {
            format!("{}/{}", home.trim_end_matches('/'), rest)
        };
        Some(PyPath::new(if joined.is_empty() { "/" } else { &joined }))
    }
}
