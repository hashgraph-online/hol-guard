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

/// Outcome of one bounded git probe (`subprocess.run(..., timeout=1)`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitProbe {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Process-dependent services the review needs.
pub trait InspectionHost {
    /// Value of an environment variable from the caller's snapshot.
    fn env(&self, name: &str) -> Option<String>;
    /// Every variable of the caller's snapshot (`os.environ.items()`).
    fn environment(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    /// `os.getuid()` of the caller; hosts that cannot report one refuse.
    fn current_uid(&self) -> Option<u32> {
        None
    }
    /// `build_runtime_executable_identity(command, search_path, cwd)` from the
    /// resident. Hosts without that service defer to the in-crate resolver.
    fn runtime_executable_identity(
        &self,
        _command: &str,
        _search_path: Option<&str>,
        _cwd: &str,
    ) -> Option<serde_json::Value> {
        None
    }
    /// `secrets.token_hex(16)`; hosts without a source defer to the OS.
    fn reuse_nonce(&self) -> Option<String> {
        None
    }
    /// `sys.executable` of the caller; hosts that cannot report one never
    /// grant the guard-interpreter trust.
    fn guard_executable(&self) -> Option<String> {
        None
    }
    /// Whether the resident secret classifier finds secret material in `text`.
    /// Hosts without that service refuse.
    fn secret_content_found(&self, _text: &str, _is_path: bool) -> bool {
        true
    }
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
    /// `git_log_has_execution_free_config(cwd, git_binary=git)`: the
    /// repository's `git log` configuration cannot execute anything.
    fn git_log_execution_free_config(&self, _cwd: &str, _git: &str) -> bool {
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
    /// `trusted_git_binary_for_cwd`: the canonical trusted git for `cwd`.
    fn trusted_git_binary(&self, _cwd: &str) -> Option<String> {
        None
    }
    /// One bounded `git <args>` run in `cwd` that keeps the exit status and
    /// both streams; `None` is an `OSError`, a timeout, or no process service.
    fn git_probe(&self, _git: &str, _args: &[String], _cwd: &str) -> Option<GitProbe> {
        None
    }
    /// `git_worktree_add_has_execution_free_config` for `reference`.
    fn git_worktree_add_config(&self, _git: &str, _cwd: &str, _reference: &str) -> bool {
        false
    }
    /// `shutil.which("git-lfs")` resolves to a trusted executable for `cwd`.
    fn git_lfs_trusted(&self, _cwd: &str) -> bool {
        false
    }
    /// `canonical_home_git_c_path`: an unquoted canonical home `-C` operand.
    fn home_git_c_path(&self, _command: &str) -> Option<String> {
        None
    }
    /// `is_safe_standalone_git_object_existence_query`.
    fn git_object_existence_query(&self, _command: &str, _cwd: &str) -> bool {
        false
    }
    /// Caller facts and resident filesystem trust for direct-tool recognition.
    /// Hosts without this service cannot authorize a TypeScript context.
    fn direct_tool_authority(&self) -> Option<&dyn crate::direct_vitest::DirectToolAuthority> {
        None
    }
    /// `os.path.exists(path)` on the caller's filesystem. Hosts that cannot
    /// answer report the path as present, the fail-closed answer for the
    /// "does not exist yet" allowances.
    fn path_exists(&self, _path: &str) -> bool {
        true
    }
    /// `os.path.realpath(path)` on the caller's filesystem; `None` refuses.
    fn real_path(&self, _path: &str) -> Option<String> {
        None
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
