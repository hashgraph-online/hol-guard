//! The execution-context selection steps of
//! `secret_file_request_services/shell_request_classifier.py`
//! (`_classify_shell_tool_action_request`): the developer, home-risk, GitHub
//! home and bounded source-edit contexts that replace the modeled context.

// Consumed by the dispatcher wiring.
#![allow(dead_code)]

use std::path::Path;

use serde_json::Value;

use crate::codex_output_env::Ctx;
use crate::codex_output_source_paths::py_path;
use crate::direct_vitest::{
    direct_local_typescript_execution_context, direct_local_vitest_execution_context,
};
use crate::github_capability_contract::GitHubCommandAssessment;
use crate::github_capability_interaction::github_capability_requires_confirmation;
use crate::github_command_capabilities::classify_github_cli;
use crate::sfrs_destructive_classifier::looks_destructive_shell_command_in;
use crate::sfrs_developer_graph::{starts_with_literal_cd, GraphInputs};
use crate::sfrs_dispatcher_request::model_context;
use crate::sfrs_interpreter_identity::{python_interpreter_executable_identities, IdentityInputs};
use crate::sfrs_quote_parsing::{
    bounded_current_workspace_source_edit_execution_context, literal_cd_execution_context,
};
use crate::sfrs_source_edit_context::{
    bounded_verified_source_edit_execution_context, low_risk_developer_execution_context,
};
use crate::shell_execution_context::ShellExecutionContext;
use crate::shell_execution_context_support::SHELL_CWD_WORKSPACE_ESCAPE;

/// The inputs every selection step reads.
pub(crate) struct Env<'a> {
    pub detection: &'a str,
    pub raw: Option<&'a str>,
    pub cwd: Option<&'a Path>,
    pub home_dir: Option<&'a Path>,
    pub ctx: &'a Ctx<'a>,
}

/// The mutable classification state: the contexts and the interpreter
/// evidence derived from them.
pub(crate) struct Selection {
    pub execution_context: ShellExecutionContext,
    pub raw_execution_context: Option<ShellExecutionContext>,
    pub identities: Vec<Value>,
    pub bounded_source_edit: bool,
}

impl Env<'_> {
    /// The raw text when it exists and differs from the detection text.
    pub(crate) fn differing_raw(&self) -> Option<&str> {
        self.raw.filter(|raw| *raw != self.detection)
    }

    /// `raw_command_text or detection_command_text`.
    pub(crate) fn raw_or_detection(&self) -> &str {
        self.raw
            .filter(|raw| !raw.is_empty())
            .unwrap_or(self.detection)
    }

    /// `_python_interpreter_executable_identities` over the matching context.
    pub(crate) fn identities(
        &self,
        cwd: Option<&Path>,
        execution_context: &ShellExecutionContext,
        raw_execution_context: Option<&ShellExecutionContext>,
    ) -> Vec<Value> {
        let selected = if self.differing_raw().is_some() {
            raw_execution_context
        } else {
            Some(execution_context)
        };
        let (cwd, home) = (cwd.map(py_path), self.home_dir.map(py_path));
        let inputs = IdentityInputs {
            cwd: cwd.as_ref(),
            home_dir: home.as_ref(),
            environment: None,
            workspace_root: None,
            execution_context: selected,
        };
        python_interpreter_executable_identities(self.raw_or_detection(), &inputs, 0, self.ctx)
    }

    fn model(
        &self,
        text: &str,
        cwd: Option<&Path>,
        workspace: Option<&Path>,
    ) -> ShellExecutionContext {
        model_context(self.ctx, text, cwd, workspace, self.home_dir)
    }

    /// The model of the detection and raw texts under one cwd and workspace.
    fn model_pair(
        &self,
        cwd: Option<&Path>,
        workspace: Option<&Path>,
    ) -> (ShellExecutionContext, ShellExecutionContext) {
        let primary = self.model(self.detection, cwd, workspace);
        let raw = match self.differing_raw() {
            Some(raw) => self.model(raw, cwd, workspace),
            None => primary.clone(),
        };
        (primary, raw)
    }
}

impl Selection {
    fn adopt(
        &mut self,
        env: &Env,
        identity_cwd: Option<&Path>,
        execution_context: ShellExecutionContext,
        raw_execution_context: ShellExecutionContext,
    ) {
        self.execution_context = execution_context;
        self.raw_execution_context = Some(raw_execution_context);
        self.identities = env.identities(
            identity_cwd,
            &self.execution_context,
            self.raw_execution_context.as_ref(),
        );
    }
}

fn developer_context(text: &str, env: &Env, home: &Path) -> Option<ShellExecutionContext> {
    let ctx = env.ctx;
    let graph = GraphInputs {
        cwd: None,
        home_dir: home,
        ctx,
        managed_bin_dirs: &[],
        classify_github: classify_github_cli,
    };
    let direct = ctx.host.direct_tool_authority().and_then(|authority| {
        direct_local_vitest_execution_context(text, env.cwd, home, authority)
            .or_else(|| direct_local_typescript_execution_context(text, env.cwd, home, authority))
    });
    direct
        .or_else(|| literal_cd_execution_context(text, home, ctx))
        .or_else(|| low_risk_developer_execution_context(text, &graph))
}

/// The developer-context replacement for an incomplete modeled context.
pub(crate) fn apply_developer_context(env: &Env, selection: &mut Selection) {
    let Some(home) = env.home_dir else {
        return;
    };
    if selection.execution_context.complete {
        return;
    }
    let developer = developer_context(env.detection, env, home);
    let raw_developer = match env.differing_raw() {
        Some(raw) => developer_context(raw, env, home),
        None => developer.clone(),
    };
    if let (Some(developer), Some(raw_developer)) = (developer, raw_developer) {
        selection.adopt(env, Some(home), developer, raw_developer);
    }
}

/// A destructive home-relative command retains its home-modeled context.
pub(crate) fn apply_home_risk_context(env: &Env, selection: &mut Selection) {
    let Some(home) = env.home_dir else {
        return;
    };
    if selection.execution_context.reason_code.as_deref() != Some(SHELL_CWD_WORKSPACE_ESCAPE)
        || env.cwd.is_some()
    {
        return;
    }
    let (home_risk, raw_home_risk) = env.model_pair(Some(home), Some(home));
    let destructive = home_risk.complete
        && raw_home_risk.complete
        && starts_with_literal_cd(&home_risk)
        && starts_with_literal_cd(&raw_home_risk)
        && (looks_destructive_shell_command_in(
            env.detection,
            Some(home),
            Some(home),
            env.ctx,
            &home_risk,
        ) || env.differing_raw().is_some_and(|raw| {
            looks_destructive_shell_command_in(raw, Some(home), Some(home), env.ctx, &raw_home_risk)
        }));
    if destructive {
        selection.adopt(env, Some(home), home_risk, raw_home_risk);
    }
}

/// A read-only GitHub command re-models its workspace from the home.
pub(crate) fn apply_github_home_context(
    env: &Env,
    selection: &mut Selection,
    github: Option<&GitHubCommandAssessment>,
) {
    let Some(home) = env.home_dir else {
        return;
    };
    let read_only = github.is_some_and(|found| !github_capability_requires_confirmation(found));
    if !read_only
        || selection.execution_context.reason_code.as_deref() != Some(SHELL_CWD_WORKSPACE_ESCAPE)
    {
        return;
    }
    let (mut home_execution, mut raw_home_execution) = env.model_pair(env.cwd, Some(home));
    if !home_execution.complete && env.cwd.is_none() {
        let (fallback, fallback_raw) = env.model_pair(Some(home), Some(home));
        if starts_with_literal_cd(&fallback) && starts_with_literal_cd(&fallback_raw) {
            home_execution = fallback;
            raw_home_execution = fallback_raw;
        }
    }
    if home_execution.complete && raw_home_execution.complete {
        selection.adopt(env, env.cwd, home_execution, raw_home_execution);
    }
}

fn bounded_source_edit(text: &str, env: &Env, home: &Path) -> Option<ShellExecutionContext> {
    let graph = GraphInputs {
        cwd: None,
        home_dir: home,
        ctx: env.ctx,
        managed_bin_dirs: &[],
        classify_github: classify_github_cli,
    };
    bounded_verified_source_edit_execution_context(text, &graph)
        .or_else(|| bounded_current_workspace_source_edit_execution_context(text, env.cwd, home))
}

/// A bounded source edit replaces both contexts and lifts the destructive
/// verdict.
pub(crate) fn apply_bounded_source_edit(env: &Env, selection: &mut Selection) {
    let Some(home) = env.home_dir else {
        return;
    };
    let bounded = bounded_source_edit(env.detection, env, home);
    let raw_bounded = match env.differing_raw() {
        Some(raw) => bounded_source_edit(raw, env, home),
        None => bounded.clone(),
    };
    if let (Some(bounded), Some(raw_bounded)) = (bounded, raw_bounded) {
        selection.bounded_source_edit = true;
        selection.execution_context = bounded;
        selection.raw_execution_context = Some(raw_bounded);
    }
}
