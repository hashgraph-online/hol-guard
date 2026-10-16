//! Resident services behind the `InspectionHost` git and executable-trust
//! methods. Each one reuses the resident's own git-trust and compound-git
//! machinery over the request's observed facts; anything that cannot be
//! computed natively answers "not trusted" so the caller fails closed.

use std::path::Path;

use guard_command::GitProbe;
use guard_contracts::{
    CompoundGitCheckV1, CompoundGitInspectionRequestV1, CompoundGitSegmentV1,
    GitExecutionSafetyCheckV1, COMPOUND_GIT_INSPECTION_REQUEST_SCHEMA,
};

use crate::codex_tool_output_op::ResidentInspectionHost;
use crate::compound_git_facts::ResidentGitFacts;
use crate::compound_git_inspection_op::decide;
use crate::git_execution_safety_binary::{
    binary_path_is_trusted, resolve_trusted_git, which_for_cwd,
};
use crate::git_execution_safety_probe::Prober;

const MAX_TEXT_BYTES: usize = 16 * 1024;

fn bounded(text: &str) -> bool {
    text.len() <= MAX_TEXT_BYTES && !text.contains('\0')
}

impl ResidentInspectionHost<'_> {
    fn compound_request(&self, check: CompoundGitCheckV1) -> CompoundGitInspectionRequestV1 {
        CompoundGitInspectionRequestV1 {
            schema: COMPOUND_GIT_INSPECTION_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            check,
            segments: Vec::new(),
            complete: false,
            command_text: None,
            value: None,
            values: Vec::new(),
            cwd: None,
            home_dir: None,
            repository_path: None,
            pager_key: None,
            git_binary: None,
            home: self.facts.home.clone(),
            account_home: self.facts.account_home.clone(),
            groups: self.facts.groups.clone(),
            environment: self.facts.environment.clone(),
        }
    }

    fn decide_compound(
        &self,
        request: &CompoundGitInspectionRequestV1,
    ) -> Option<(bool, Option<String>)> {
        let facts = ResidentGitFacts::new(request);
        decide(request, &facts).map(|verdict| (verdict.allowed, verdict.value))
    }

    fn compound_allowed(&self, request: &CompoundGitInspectionRequestV1) -> bool {
        self.decide_compound(request)
            .is_some_and(|(allowed, _)| allowed)
    }

    fn segments_bounded(segments: &[CompoundGitSegmentV1]) -> bool {
        segments.len() <= 128
            && segments.iter().all(|segment| {
                segment.tokens.len() <= 512 && segment.tokens.iter().all(|t| bounded(t))
            })
    }

    pub(crate) fn svc_compound_chain(
        &self,
        segments: &[CompoundGitSegmentV1],
        complete: bool,
    ) -> bool {
        if !Self::segments_bounded(segments) {
            return false;
        }
        let mut request = self.compound_request(CompoundGitCheckV1::Compound);
        request.segments = segments.to_vec();
        request.complete = complete;
        self.compound_allowed(&request)
    }

    pub(crate) fn svc_inspection_segment(
        &self,
        segment: &CompoundGitSegmentV1,
        home_dir: Option<&str>,
    ) -> bool {
        if !Self::segments_bounded(std::slice::from_ref(segment)) {
            return false;
        }
        let mut request = self.compound_request(CompoundGitCheckV1::Segment);
        request.segments = vec![segment.clone()];
        request.home_dir = home_dir.map(str::to_owned);
        self.compound_allowed(&request)
    }

    pub(crate) fn svc_cached_diff_pathspecs(&self, values: &[String]) -> bool {
        if values.len() > 16 || !values.iter().all(|v| bounded(v)) {
            return false;
        }
        let mut request = self.compound_request(CompoundGitCheckV1::CachedDiffPathspecs);
        request.values = values.to_vec();
        self.compound_allowed(&request)
    }

    pub(crate) fn svc_show_config(
        &self,
        segment: &CompoundGitSegmentV1,
        repository_path: Option<&str>,
    ) -> bool {
        if !Self::segments_bounded(std::slice::from_ref(segment))
            || !repository_path.is_none_or(bounded)
        {
            return false;
        }
        let mut request = self.compound_request(CompoundGitCheckV1::ShowConfig);
        request.segments = vec![segment.clone()];
        request.repository_path = repository_path.map(str::to_owned);
        self.compound_allowed(&request)
    }

    pub(crate) fn svc_log_config(&self, cwd: &str, git: &str) -> bool {
        if !bounded(cwd) || !bounded(git) {
            return false;
        }
        let mut request = self.compound_request(CompoundGitCheckV1::LogConfig);
        request.cwd = Some(cwd.to_owned());
        request.git_binary = Some(git.to_owned());
        self.compound_allowed(&request)
    }

    pub(crate) fn svc_standalone_routine(
        &self,
        segments: &[CompoundGitSegmentV1],
        complete: bool,
        home_dir: Option<&str>,
    ) -> bool {
        if !Self::segments_bounded(segments) {
            return false;
        }
        let mut request = self.compound_request(CompoundGitCheckV1::Standalone);
        request.segments = segments.to_vec();
        request.complete = complete;
        request.home_dir = home_dir.map(str::to_owned);
        self.compound_allowed(&request)
    }

    pub(crate) fn svc_object_existence(&self, command: &str, cwd: &str) -> bool {
        if !bounded(command) || !bounded(cwd) {
            return false;
        }
        let mut request = self.compound_request(CompoundGitCheckV1::ObjectExistenceQuery);
        request.command_text = Some(command.to_owned());
        request.cwd = Some(cwd.to_owned());
        self.compound_allowed(&request)
    }

    pub(crate) fn svc_home_git_c_path(&self, command: &str) -> Option<String> {
        if !bounded(command) {
            return None;
        }
        let mut request = self.compound_request(CompoundGitCheckV1::HomeGitCPath);
        request.command_text = Some(command.to_owned());
        self.decide_compound(&request).and_then(|(_, value)| value)
    }

    pub(crate) fn svc_trusted_git(&self, cwd: &str) -> Option<String> {
        if !bounded(cwd) {
            return None;
        }
        resolve_trusted_git(
            Path::new(cwd),
            &self.facts.environment,
            Path::new(&self.facts.home),
            &self.facts.groups,
        )
        .map(|path| path.to_string_lossy().into_owned())
    }

    /// `_trusted_path_command`: search `PATH` from `cwd`, resolve, then trust.
    pub(crate) fn svc_trusted_path_command(
        &self,
        command: &str,
        cwd: &str,
        home_dir: &str,
    ) -> bool {
        if !bounded(command) || !bounded(cwd) || !bounded(home_dir) {
            return false;
        }
        let Ok(execution_cwd) = std::fs::canonicalize(cwd) else {
            return false;
        };
        let home = Path::new(home_dir);
        let Some(found) = which_for_cwd(command, &execution_cwd, &self.facts.environment, home)
        else {
            return false;
        };
        let Ok(resolved) = std::fs::canonicalize(found) else {
            return false;
        };
        binary_path_is_trusted(&resolved, &execution_cwd, home, &self.facts.groups)
    }

    pub(crate) fn svc_probe(&self, git: &str, args: &[String], cwd: &str) -> Option<GitProbe> {
        if !bounded(git) || !bounded(cwd) || args.len() > 64 || !args.iter().all(|a| bounded(a)) {
            return None;
        }
        let git_path = Path::new(git);
        let cwd_path = Path::new(cwd);
        if !git_path.is_absolute() || !cwd_path.is_absolute() {
            return None;
        }
        let prober = Prober {
            git: git_path,
            cwd: cwd_path,
            environment: &self.facts.environment,
        };
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = prober.run_capturing_stderr(&refs)?;
        Some(GitProbe {
            code: output.code?,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    pub(crate) fn svc_worktree_add_config(&self, git: &str, cwd: &str, reference: &str) -> bool {
        if !bounded(git) || !bounded(cwd) || !bounded(reference) {
            return false;
        }
        self.git_request_allowed(
            GitExecutionSafetyCheckV1::WorktreeAdd,
            Some(cwd),
            &[],
            Some(git),
            Some(reference),
        )
    }
}
