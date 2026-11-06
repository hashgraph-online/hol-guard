//! Effect graph of a compound developer inspection command
//! (`developer_inspection.py`: `_compound_developer_effect_graph`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use guard_contracts::CompoundGitSegmentV1;

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::direct_vitest::direct_local_typescript_execution_context;
use crate::github_capability_contract::GitHubCommandAssessment;
use crate::github_capability_interaction::github_capability_requires_confirmation;
use crate::sfrs_constants::{
    READ_ONLY_LOOKUP_COMMANDS, READ_ONLY_LOOKUP_FILTERS, SAFE_STATIC_SHELL_COMMANDS,
};
use crate::sfrs_developer_inspection::{
    find_exec_ls_resolves_safely, read_only_lookup_primary_segment_is_safe,
    ripgrep_config_is_disabled, static_shell_segment_is_safe,
};
use crate::sfrs_gh_service::classify_with;
use crate::sfrs_interpreter_scripts::{
    is_python_interpreter_command, script_interpreter_texts, script_is_read_only_observer,
};
use crate::sfrs_jq::github_jq_filter_args_are_safe;
use crate::sfrs_path_word_lookups::resolved_path_operands_resolve_safely;
use crate::sfrs_read_only_filters::{
    read_only_lookup_filter_segment_is_safe, read_only_lookup_may_be_primary,
};
use crate::sfrs_shell_tokens::shell_segment_primary_command;
use crate::sfrs_static_safety::{
    leading_literal_cd_workspace_root, path_text_is_within_root, safe_cli_metadata_segment_is_safe,
    shell_syntax_check_segment_is_safe, shell_token_escapes_root,
    shell_token_has_command_substitution, without_safe_inspection_redirections,
};
use crate::shell_execution_context::{
    model_shell_execution_context, ShellExecutionContext, ShellExecutionSegment,
};
use crate::shell_secret_read_support::{
    local_read_operands_resolve_safely, search_file_operand_tokens,
};

/// `DeveloperShellEffect`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeveloperShellEffect {
    Directory,
    LocalRead,
    RemoteRead,
    StreamFilter,
    StaticOutput,
    SyntaxCheck,
}

/// `DeveloperShellSegmentEffect`.
#[derive(Clone, Debug)]
pub(crate) struct DeveloperShellSegmentEffect {
    pub index: usize,
    pub command_name: String,
    pub effect: DeveloperShellEffect,
}

/// `DeveloperShellEffectGraph`.
#[derive(Clone, Debug)]
pub(crate) struct DeveloperShellEffectGraph {
    pub context: ShellExecutionContext,
    pub segments: Vec<DeveloperShellSegmentEffect>,
}

impl DeveloperShellEffectGraph {
    pub(crate) fn has_observation(&self) -> bool {
        self.segments.iter().any(|segment| {
            matches!(
                segment.effect,
                DeveloperShellEffect::LocalRead
                    | DeveloperShellEffect::RemoteRead
                    | DeveloperShellEffect::SyntaxCheck
            )
        })
    }
}

/// Everything the graph reads from outside the command text.
pub(crate) struct GraphInputs<'a> {
    pub cwd: Option<&'a Path>,
    pub home_dir: &'a Path,
    pub ctx: &'a Ctx<'a>,
    pub managed_bin_dirs: &'a [PathBuf],
    pub classify_github: fn(&[String]) -> GitHubCommandAssessment,
}

/// `_low_risk_compound_developer_execution_context`.
pub(crate) fn low_risk_compound_developer_execution_context(
    command_text: &str,
    inputs: &GraphInputs,
) -> Option<ShellExecutionContext> {
    compound_developer_effect_graph(command_text, inputs).map(|graph| graph.context)
}

pub(crate) fn starts_with_literal_cd(context: &ShellExecutionContext) -> bool {
    if !context.complete || context.segments.is_empty() {
        return false;
    }
    let first = &context.segments[0];
    if !first.control_before.is_empty()
        || first.directory_operation.as_deref() != Some("cd")
        || first.tokens.is_empty()
    {
        return false;
    }
    first.tokens[0]
        .trim_matches(|c| c == '"' || c == '\'')
        .to_lowercase()
        == "cd"
}

pub(crate) fn git_segment(segment: &ShellExecutionSegment) -> CompoundGitSegmentV1 {
    CompoundGitSegmentV1 {
        tokens: segment.tokens.clone(),
        control_before: segment.control_before.clone(),
        control_after: segment.control_after.clone(),
        effective_cwd: segment
            .effective_cwd
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        directory_operation: segment.directory_operation.clone(),
    }
}

/// `is_low_risk_compound_git_inspection`.
fn is_low_risk_compound_git_inspection(context: &ShellExecutionContext, ctx: &Ctx) -> bool {
    let segments = &context.segments;
    if !context.complete
        || segments.len() < 2
        || segments[0].directory_operation.as_deref() != Some("cd")
    {
        return false;
    }
    let converted: Vec<CompoundGitSegmentV1> = segments.iter().map(git_segment).collect();
    ctx.host.compound_git_chain(&converted, context.complete)
}

pub(crate) fn known_context_effect_graph(
    context: ShellExecutionContext,
    observation: DeveloperShellEffect,
) -> DeveloperShellEffectGraph {
    let segments = context
        .segments
        .iter()
        .enumerate()
        .map(|(index, segment)| DeveloperShellSegmentEffect {
            index,
            command_name: shell_segment_primary_command(&segment.tokens)
                .0
                .unwrap_or_else(|| "unknown".to_owned()),
            effect: if segment.directory_operation.is_some() {
                DeveloperShellEffect::Directory
            } else {
                observation
            },
        })
        .collect();
    DeveloperShellEffectGraph { context, segments }
}

fn py_path(path: &Path) -> PyPath {
    PyPath::new(&path.to_string_lossy())
}

/// `_compound_developer_effect_graph`.
pub(crate) fn compound_developer_effect_graph(
    command_text: &str,
    inputs: &GraphInputs,
) -> Option<DeveloperShellEffectGraph> {
    let (home_dir, ctx) = (inputs.home_dir, inputs.ctx);
    let initial_root = inputs.cwd.unwrap_or(home_dir);
    let mut context = model_shell_execution_context(
        command_text,
        Some(initial_root),
        Some(initial_root),
        Some(home_dir),
    );
    if let Some(workspace_root) = leading_literal_cd_workspace_root(&context, home_dir) {
        let resolved_home = pyfs::resolve(&py_path(home_dir)).map(|path| path.to_string());
        let home_text = resolved_home.unwrap_or_else(|| home_dir.to_string_lossy().into_owned());
        if workspace_root.to_string_lossy() != home_text {
            context = model_shell_execution_context(
                command_text,
                Some(&workspace_root),
                Some(&workspace_root),
                Some(home_dir),
            );
        }
    }
    let leading_cd = starts_with_literal_cd(&context);
    if !leading_cd && inputs.cwd.is_none() {
        return None;
    }
    if !context.complete {
        return None;
    }
    if is_low_risk_compound_git_inspection(&context, ctx) {
        return Some(known_context_effect_graph(
            context,
            DeveloperShellEffect::LocalRead,
        ));
    }
    if let Some(typescript) = ctx.host.direct_tool_authority().and_then(|authority| {
        direct_local_typescript_execution_context(command_text, inputs.cwd, home_dir, authority)
    }) {
        if typescript.complete {
            return Some(known_context_effect_graph(
                typescript,
                DeveloperShellEffect::SyntaxCheck,
            ));
        }
    }
    let github_assessment =
        classify_with(command_text, Some(home_dir), ctx, inputs.classify_github);
    let github_is_low_risk = github_assessment
        .as_ref()
        .is_some_and(|found| !github_capability_requires_confirmation(found));
    if github_assessment.is_some() && !github_is_low_risk {
        return None;
    }
    let inspection_root: PathBuf = context
        .workspace_root
        .clone()
        .unwrap_or_else(|| home_dir.to_path_buf());
    let mut effects: Vec<DeveloperShellSegmentEffect> = Vec::new();
    let first_inspection_segment = usize::from(leading_cd);
    if leading_cd {
        effects.push(DeveloperShellSegmentEffect {
            index: 0,
            command_name: "cd".to_owned(),
            effect: DeveloperShellEffect::Directory,
        });
    }
    for (index, segment) in context
        .segments
        .iter()
        .enumerate()
        .skip(first_inspection_segment)
    {
        let effect = segment_effect(
            segment,
            &inspection_root,
            home_dir,
            github_is_low_risk,
            inputs,
        )?;
        effects.push(DeveloperShellSegmentEffect {
            index,
            command_name: effect.0,
            effect: effect.1,
        });
    }
    let graph = DeveloperShellEffectGraph {
        context,
        segments: effects,
    };
    graph.has_observation().then_some(graph)
}

fn segment_effect(
    segment: &ShellExecutionSegment,
    inspection_root: &Path,
    home_dir: &Path,
    github_is_low_risk: bool,
    inputs: &GraphInputs,
) -> Option<(String, DeveloperShellEffect)> {
    let ctx = inputs.ctx;
    if segment
        .control_before
        .iter()
        .chain(&segment.control_after)
        .any(|control| !matches!(control.as_str(), "&&" | "||" | "|" | ";" | "\n"))
    {
        return None;
    }
    let (command_name, command_index) = shell_segment_primary_command(&segment.tokens);
    let (command_name, command_index) = (command_name?, command_index?);
    let args = without_safe_inspection_redirections(&segment.tokens[command_index + 1..])?;
    let segment_root: PathBuf = segment
        .effective_cwd
        .clone()
        .unwrap_or_else(|| home_dir.to_path_buf());
    let piped = segment.control_before == ["|"];
    let safe_pipe_filter = READ_ONLY_LOOKUP_FILTERS.contains(&command_name.as_str())
        && piped
        && read_only_lookup_filter_segment_is_safe(
            &command_name,
            &args,
            Some(&segment_root),
            false,
            ctx,
        );
    let root_checked_args: Vec<String> =
        if safe_pipe_filter && matches!(command_name.as_str(), "grep" | "egrep" | "fgrep") {
            search_file_operand_tokens(&command_name, &args)
        } else {
            args.clone()
        };
    if !path_text_is_within_root(&segment_root.to_string_lossy(), inspection_root) {
        return None;
    }
    if root_checked_args
        .iter()
        .any(|arg| shell_token_escapes_root(arg, &segment_root, inspection_root))
    {
        return None;
    }
    let done = |effect| Some((command_name.clone(), effect));
    if segment.directory_operation.is_some() {
        return done(DeveloperShellEffect::Directory);
    }
    if command_name == "git" {
        let converted = git_segment(segment);
        if ctx.host.git_inspection_segment(&converted, None) {
            return done(DeveloperShellEffect::LocalRead);
        }
    }
    if command_name == "gh" && github_is_low_risk {
        return done(DeveloperShellEffect::RemoteRead);
    }
    if command_name == "jq" && piped && github_is_low_risk && github_jq_filter_args_are_safe(&args)
    {
        return done(DeveloperShellEffect::StreamFilter);
    }
    if safe_cli_metadata_segment_is_safe(
        &command_name,
        &args,
        &segment_root,
        &segment.tokens[command_index],
        command_index,
        ctx,
        inputs.managed_bin_dirs,
    ) {
        return done(DeveloperShellEffect::LocalRead);
    }
    if lookup_primary_is_safe(
        segment,
        &command_name,
        command_index,
        &args,
        safe_pipe_filter,
        &segment_root,
        inspection_root,
        home_dir,
        ctx,
    ) {
        return done(DeveloperShellEffect::LocalRead);
    }
    if safe_pipe_filter {
        return done(DeveloperShellEffect::StreamFilter);
    }
    if command_name == "wc"
        && !args.is_empty()
        && args.iter().all(|arg| {
            matches!(arg.as_str(), "-c" | "-l" | "-w")
                || (!arg.starts_with('-') && !shell_token_has_command_substitution(arg))
        })
    {
        return done(DeveloperShellEffect::LocalRead);
    }
    if command_name == "sort"
        && piped
        && args
            .iter()
            .all(|arg| matches!(arg.as_str(), "-n" | "-r" | "-u"))
    {
        return done(DeveloperShellEffect::StreamFilter);
    }
    if SAFE_STATIC_SHELL_COMMANDS.contains(&command_name.as_str())
        && static_shell_segment_is_safe(&args)
    {
        return done(DeveloperShellEffect::StaticOutput);
    }
    if shell_syntax_check_segment_is_safe(&command_name, &args) {
        return done(DeveloperShellEffect::SyntaxCheck);
    }
    if is_python_interpreter_command(&command_name) {
        let scripts = script_interpreter_texts(&segment.tokens);
        if !scripts.is_empty()
            && scripts
                .iter()
                .all(|script| script_is_read_only_observer(script))
        {
            return done(DeveloperShellEffect::LocalRead);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn lookup_primary_is_safe(
    segment: &ShellExecutionSegment,
    command_name: &str,
    command_index: usize,
    args: &[String],
    safe_pipe_filter: bool,
    segment_root: &Path,
    inspection_root: &Path,
    home_dir: &Path,
    ctx: &Ctx,
) -> bool {
    if !read_only_lookup_may_be_primary(
        READ_ONLY_LOOKUP_COMMANDS.contains(&command_name),
        &segment.control_before,
        safe_pipe_filter,
    ) {
        return false;
    }
    let prefix = &segment.tokens[..command_index];
    if command_name == "rg"
        && !ripgrep_config_is_disabled(args)
        && prefix
            .iter()
            .any(|token| token.starts_with("RIPGREP_CONFIG_PATH="))
    {
        return false;
    }
    read_only_lookup_primary_segment_is_safe(command_name, args, Some(segment_root), ctx)
        && (command_name != "find"
            || find_exec_ls_resolves_safely(args, prefix, segment_root, home_dir, ctx))
        && (!matches!(command_name, "readlink" | "realpath")
            || resolved_path_operands_resolve_safely(
                command_name,
                args,
                segment_root,
                inspection_root,
            ))
        && local_read_operands_resolve_safely(command_name, args, segment_root, inspection_root)
}
