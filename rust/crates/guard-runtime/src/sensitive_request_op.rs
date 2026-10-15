//! Sensitive-request classifiers answered by the admitted, request-bound resident.
//!
//! Python sends one tool call and its own observations. The resident re-proves
//! git trust, derives extension-control authority from the snapshot, scans
//! content itself and answers; nothing here trusts a caller verdict.

use std::path::Path;

use guard_command::benign_request_api::ToolActionControls;
use guard_command::command_evaluation_controls::{
    authority_failure_for_health, control_layers_from_wire,
};
use guard_command::direct_vitest::DirectToolAuthority;
use guard_command::{Ctx, GitCheck, GitProbe, GitRun, InspectionHost};
use guard_contracts::{
    CodexToolOutputFactsV1, CompoundGitSegmentV1, HookControlSnapshotV1, RequestContextRequestV1,
    RequestContextSensitiveRequestV1, MAX_REQUEST_CONTEXT_PATH_BYTES,
};
use serde_json::{json, Value};

use crate::codex_tool_output_op::ResidentInspectionHost;
use crate::direct_tool_context_op::{admit, Authority};
use crate::request_context_op::Budget;

const INVALID: &str = "native_sensitive_request_input_invalid";
const MAX_INPUT_BYTES: usize = 6 * 1024 * 1024;
const MAX_QUERY_BYTES: usize = 64;

/// The resident host: git trust from the shared inspection host, plus the
/// caller identity, content scanning and direct-tool authority this request
/// was admitted with.
struct SensitiveRequestHost<'a> {
    inner: ResidentInspectionHost<'a>,
    owner_uid: Option<u32>,
    guard_executable: &'a str,
    authority: Authority<'a>,
    budget: &'a Budget,
}

impl InspectionHost for SensitiveRequestHost<'_> {
    fn env(&self, name: &str) -> Option<String> {
        self.inner.env(name)
    }
    fn environment(&self) -> Vec<(String, String)> {
        self.inner.environment()
    }
    fn current_uid(&self) -> Option<u32> {
        self.owner_uid
    }
    fn guard_executable(&self) -> Option<String> {
        Some(self.guard_executable.to_owned())
    }
    fn secret_content_found(&self, text: &str, _is_path: bool) -> bool {
        let body = json!({
            "text": text,
            "suppress_samples": false,
            "documentation_sample_context": false,
        });
        // Any scan failure counts as a finding: the caller then refuses the
        // body instead of treating it as clean.
        match guard_command::content_sensitivity::evaluate("content", &body, self.budget.deadline())
        {
            Ok(result) => result["ok"]
                .as_array()
                .is_none_or(|matches| !matches.is_empty()),
            Err(_) => true,
        }
    }
    fn git_executable(&self) -> Option<String> {
        self.inner.git_executable()
    }
    fn git_safety(&self, check: GitCheck, cwd: Option<&str>, arguments: &[String]) -> bool {
        self.within_budget() && self.inner.git_safety(check, cwd, arguments)
    }
    fn git_binary_trusted(&self, git: &str, cwd: &str) -> bool {
        self.within_budget() && self.inner.git_binary_trusted(git, cwd)
    }
    fn run_git(&self, git: &str, args: &[String], cwd: &str) -> GitRun {
        if !self.within_budget() {
            return GitRun::Failed("native_request_context_budget_exceeded");
        }
        self.inner.run_git(git, args, cwd)
    }
    fn compound_git_chain(&self, segments: &[CompoundGitSegmentV1], complete: bool) -> bool {
        self.within_budget() && self.inner.compound_git_chain(segments, complete)
    }
    fn git_inspection_segment(
        &self,
        segment: &CompoundGitSegmentV1,
        home_dir: Option<&str>,
    ) -> bool {
        self.within_budget() && self.inner.git_inspection_segment(segment, home_dir)
    }
    fn cached_diff_pathspecs(&self, values: &[String]) -> bool {
        self.within_budget() && self.inner.cached_diff_pathspecs(values)
    }
    fn git_show_config(
        &self,
        segment: &CompoundGitSegmentV1,
        repository_path: Option<&str>,
    ) -> bool {
        self.within_budget() && self.inner.git_show_config(segment, repository_path)
    }
    fn git_log_execution_free_config(&self, cwd: &str, git: &str) -> bool {
        self.within_budget() && self.inner.git_log_execution_free_config(cwd, git)
    }
    fn standalone_git_routine(
        &self,
        segments: &[CompoundGitSegmentV1],
        complete: bool,
        home_dir: Option<&str>,
    ) -> bool {
        self.within_budget()
            && self
                .inner
                .standalone_git_routine(segments, complete, home_dir)
    }
    fn trusted_path_command(&self, command: &str, cwd: &str, home_dir: &str) -> bool {
        self.within_budget() && self.inner.trusted_path_command(command, cwd, home_dir)
    }
    fn trusted_git_binary(&self, cwd: &str) -> Option<String> {
        if !self.within_budget() {
            return None;
        }
        self.inner.trusted_git_binary(cwd)
    }
    fn git_probe(&self, git: &str, args: &[String], cwd: &str) -> Option<GitProbe> {
        if !self.within_budget() {
            return None;
        }
        self.inner.git_probe(git, args, cwd)
    }
    fn git_worktree_add_config(&self, git: &str, cwd: &str, reference: &str) -> bool {
        self.within_budget() && self.inner.git_worktree_add_config(git, cwd, reference)
    }
    fn git_lfs_trusted(&self, cwd: &str) -> bool {
        self.within_budget() && self.inner.git_lfs_trusted(cwd)
    }
    fn home_git_c_path(&self, command: &str) -> Option<String> {
        self.inner.home_git_c_path(command)
    }
    fn git_object_existence_query(&self, command: &str, cwd: &str) -> bool {
        self.within_budget() && self.inner.git_object_existence_query(command, cwd)
    }
    fn direct_tool_authority(&self) -> Option<&dyn DirectToolAuthority> {
        Some(&self.authority)
    }
    fn path_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
    /// Non-strict like `os.path.realpath`: callers ask about paths that must
    /// not exist yet. A relative path has no request cwd here and is refused.
    fn real_path(&self, path: &str) -> Option<String> {
        path.starts_with('/')
            .then(|| crate::oci_path::resolve_lenient(path))
    }
}

impl SensitiveRequestHost<'_> {
    fn within_budget(&self) -> bool {
        self.budget.check().is_ok()
    }
}

fn controls(
    snapshot: Option<&HookControlSnapshotV1>,
) -> Result<Option<ToolActionControls>, &'static str> {
    let Some(snapshot) = snapshot else {
        return Ok(None);
    };
    let authority_failure = authority_failure_for_health(&snapshot.health)
        .map_err(|_| "native_sensitive_request_controls_invalid")?;
    let layers = control_layers_from_wire(&snapshot.layers)
        .map_err(|_| "native_sensitive_request_controls_invalid")?;
    Ok(Some(ToolActionControls {
        layers,
        authority_failure,
    }))
}

fn git_executable_is_bounded(value: Option<&str>) -> bool {
    value.is_none_or(|path| {
        !path.is_empty()
            && path.len() <= MAX_REQUEST_CONTEXT_PATH_BYTES
            && !path.contains(['\0', '\n', '\r'])
            && Path::new(path).is_absolute()
    })
}

pub(crate) fn evaluate(
    request: &RequestContextRequestV1,
    body: &RequestContextSensitiveRequestV1,
    budget: &Budget,
) -> Result<Value, &'static str> {
    admit(&body.facts, budget)?;
    let encoded = serde_json::to_vec(&body.input).map_err(|_| INVALID)?;
    if encoded.len() > MAX_INPUT_BYTES
        || body.query.is_empty()
        || body.query.len() > MAX_QUERY_BYTES
        || !git_executable_is_bounded(body.git_executable.as_deref())
    {
        return Err(INVALID);
    }
    let controls = controls(body.control_snapshot.as_ref())?;
    let facts = &body.facts;
    let inspection = CodexToolOutputFactsV1 {
        process_cwd: facts.cwd.clone(),
        home: facts.home_dir.clone(),
        account_home: Some(facts.caller_home.clone()),
        groups: facts.groups.clone(),
        environment: facts.environment.clone(),
        git_executable: body.git_executable.clone(),
    };
    let host = SensitiveRequestHost {
        inner: ResidentInspectionHost { facts: &inspection },
        owner_uid: request.owner_uid,
        guard_executable: &facts.launcher.python_executable,
        authority: Authority { facts, budget },
        budget,
    };
    let ctx = Ctx::new(&host, &facts.cwd, &facts.home_dir);
    budget.check()?;
    let result = guard_command::sensitive_request::evaluate(
        &body.query,
        &body.input,
        &ctx,
        controls.as_ref(),
    )?;
    budget.check()?;
    Ok(json!({"kind": "sensitive_request", "query": body.query, "result": result}))
}
