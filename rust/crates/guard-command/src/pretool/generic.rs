#[path = "generic_evaluate.rs"]
mod evaluate;
use evaluate::evaluate_signals;

#[path = "chain_literals.rs"]
pub(crate) mod chain_literals;
#[path = "generic_command_rewrite.rs"]
mod command_rewrite;
#[path = "contained_publish.rs"]
pub(crate) mod contained_publish;
#[path = "env_prefix_projection.rs"]
mod env_prefix_projection;
pub use env_prefix_projection::bindable_setting;
#[path = "generic_cline_view.rs"]
mod cline_view;
#[path = "generic_extract.rs"]
mod extract;
#[path = "generic_omp.rs"]
mod omp;
#[path = "generic_omp_bash_cwd.rs"]
mod omp_bash_cwd;

/// Resolve the host's tool-level directory for an execution-owner preview.
/// This is path observation only; the owner must still judge current policy.
pub fn omp_bash_execution_directory(
    payload: &serde_json::Value,
    home_dir: Option<&str>,
    session: Option<&str>,
) -> Result<Option<String>, &'static str> {
    match omp_bash_cwd::resolve(payload, home_dir, session) {
        omp_bash_cwd::BashCwd::Session => Ok(session.map(str::to_owned)),
        omp_bash_cwd::BashCwd::Within(path) | omp_bash_cwd::BashCwd::Outside(path) => {
            Ok(Some(path))
        }
        omp_bash_cwd::BashCwd::Missing | omp_bash_cwd::BashCwd::Unresolved => {
            Err("bash_working_directory_unavailable")
        }
    }
}
#[cfg(all(test, unix))]
#[path = "generic_omp_bash_cwd_tests.rs"]
mod omp_bash_cwd_tests;
#[path = "open_quote.rs"]
mod open_quote;
#[path = "generic_pure_eval.rs"]
mod pure_eval;
#[path = "generic_read_note.rs"]
mod read_note;
#[path = "redirect_projection.rs"]
mod redirect_projection;
#[path = "generic_result.rs"]
mod result;
#[path = "venv_activation_projection.rs"]
mod venv_activation_projection;
#[path = "workspace_redirects.rs"]
pub(crate) mod workspace_redirects;
use command_rewrite::payload_with_command;

use crate::native_command_controls::CompiledNativeCommandControls;
use crate::CommandModelRequestV1;
use guard_contracts::{
    NativePromptRiskClassV1, PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1,
};
use serde_json::Value;

use super::evaluate_pre_tool_with_execution_context;
use extract::extract_generic_signals;
use result::{generic_action, generic_error_result, generic_result};
use std::time::Instant;

/// The command a virtualenv activation hands its verdict to, or `None` when
/// the activation is not one the scan can read through. The pre-tool pass
/// answers for the projected command, so a caller that routes that answer
/// somewhere which plans the call again has to plan the same text.
pub fn venv_activation_target(command: &str, context: super::PathContext<'_>) -> Option<String> {
    venv_activation_projection::project(command, context)
}

/// Bounded caller-supplied context, never authenticated provider facts.
pub struct UntrustedCommandContext {
    pub command: Option<String>,
    pub business_action_present: bool,
}

/// Share native aliases, nested JSON handling, ambiguity checks and limits.
pub fn extract_untrusted_command_context(
    payload: &Value,
) -> Result<UntrustedCommandContext, String> {
    let signals = extract_generic_signals(payload)
        .map_err(|_| "native_command_context_unavailable".to_owned())?;
    Ok(UntrustedCommandContext {
        command: signals.command,
        business_action_present: signals.business_action_present,
    })
}

/// Destinations a tool call names: URL-valued arguments plus explicit
/// `http(s)://` URLs in its command text. Empty when the payload cannot be
/// read; that payload already gets the extraction failure's own decision.
pub fn network_targets(payload: &Value, limit: usize) -> Vec<String> {
    let Ok(signals) = extract_generic_signals(payload) else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    for target in signals.url_values.into_iter().chain(
        signals
            .command
            .as_deref()
            .map(|command| crate::network_url::urls_in_text(command, limit))
            .unwrap_or_default(),
    ) {
        if targets.len() >= limit {
            break;
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    targets
}

#[path = "agent_metadata.rs"]
mod agent_metadata;

/// Reuse the exact host-input proof after execution; output content still
/// requires its independent native scan and installed policy enforcement.
pub fn bounded_task_metadata_output(payload: &serde_json::Value, harness: &str) -> bool {
    let Some(root) = payload.as_object() else {
        return false;
    };
    let Some(tool) = root.get("tool_name").and_then(serde_json::Value::as_str) else {
        return false;
    };
    if tool == "AskUserQuestion" && agent_metadata::names_guard_prompt(payload) {
        return false;
    }
    if root
        .get("toolName")
        .is_some_and(|alias| alias.as_str() != Some(tool))
    {
        return false;
    }
    let input = root
        .iter()
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "tool_response" | "toolResponse" | "toolResultPreview"
            )
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let input = serde_json::Value::Object(input);
    if harness == "omp" && omp::bounded_delegation_metadata(&input) {
        return true;
    }
    agent_metadata::bounded_task_list(&input, Some(tool))
}
#[path = "generic_github.rs"]
mod github;
#[path = "generic_tools.rs"]
mod tools;
#[path = "generic_web_fetch.rs"]
mod web_fetch;
pub(in crate::pretool) use tools::is_package_tool;
pub(in crate::pretool) use web_fetch::plain_public_url;

/// Evaluate the complete raw PreToolUse payload in native code. This stays
/// separate from `evaluate_pre_tool`, the compatibility command-model
/// operation used by older clients.
pub fn evaluate_pre_tool_envelope(harness: &str, event: &str, payload: &Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_extensions(harness, event, payload, None, None)
}

pub fn evaluate_pre_tool_envelope_with_extensions(
    harness: &str,
    event: &str,
    payload: &Value,
    controls: Option<&CompiledNativeCommandControls>,
    deadline: Option<Instant>,
) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(harness, event, payload, controls, deadline, None, None)
}

/// Like [`evaluate_pre_tool_envelope_with_extensions`] but also carries the
/// envelope's verified `home_dir`/`cwd` so `~/`-relative and absolute harness
/// paths (Devin sends `~/...` verbatim) share the non-sensitive read floor.
pub fn evaluate_pre_tool_envelope_with_context(
    harness: &str,
    event: &str,
    payload: &Value,
    controls: Option<&CompiledNativeCommandControls>,
    deadline: Option<Instant>,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        event,
        payload,
        controls,
        deadline,
        crate::pretool::PathContext {
            home_dir,
            cwd,
            cdpath_unset: false,
            rustup_override_absent: false,
            npm_config_inert: false,
            pip_config_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            psql_environment: Default::default(),
        },
        None,
    )
}

pub fn evaluate_pre_tool_envelope_with_execution_context(
    harness: &str,
    event: &str,
    payload: &Value,
    controls: Option<&CompiledNativeCommandControls>,
    deadline: Option<Instant>,
    context: super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> PreToolResultV1 {
    let mut context =
        super::PathContext::for_session(context.home_dir, context.cwd, execution_environment);
    let (projected_payload, cline_payload);
    let mut payload = payload;
    let within;
    if harness == "cline" {
        if let Some(view) = cline_view::evaluated_view(payload) {
            cline_payload = view;
            payload = &cline_payload;
        }
    }
    if harness == "omp"
        && event == "PreToolUse"
        && payload.get("tool_name").and_then(Value::as_str) == Some("bash")
    {
        match omp_bash_cwd::resolve(payload, context.home_dir, context.cwd) {
            omp_bash_cwd::BashCwd::Session => {}
            omp_bash_cwd::BashCwd::Within(directory) => {
                within = directory;
                context.cwd = Some(within.as_str());
            }
            // Outside the session directory the existing `cd` proofs decide,
            // so the call is judged as if it changed directory first.
            omp_bash_cwd::BashCwd::Outside(directory) => {
                let Some(command) = extract_generic_signals(payload)
                    .ok()
                    .and_then(|signals| signals.command)
                else {
                    return omp_bash_cwd_review(harness, event);
                };
                projected_payload = payload_with_command(
                    payload,
                    &command,
                    &format!("cd '{directory}' && {command}"),
                );
                payload = &projected_payload;
            }
            omp_bash_cwd::BashCwd::Missing => return omp_bash_cwd_missing(harness, event),
            omp_bash_cwd::BashCwd::Unresolved => return omp_bash_cwd_review(harness, event),
        }
    }
    let mut result = super::git_probe::with_memo(|| {
        super::search::with_walk_memo(|| {
            let evaluate = |payload: &Value| {
                evaluate_envelope(
                    harness,
                    event,
                    payload,
                    controls,
                    deadline,
                    context,
                    execution_environment,
                    true,
                )
            };
            let judged = chain_literals::rejudge(evaluate(payload), payload, context, evaluate);
            contained_publish::rejudge(judged, payload, context, evaluate)
        })
    });
    // Name what kept the extension controls from evaluating the command, a
    // code-loading or credential setting or an open quote, so the agent can
    // fix it and retry instead of guessing.
    if result.reason_code == "native_command_extension_evaluation_failed" {
        let command = extract_generic_signals(payload)
            .ok()
            .and_then(|signals| signals.command);
        // A code-loading setting refuses on its own, so name it before any
        // expanded setting that may sit beside it.
        if let Some(setting) = command
            .as_deref()
            .and_then(env_prefix_projection::code_loading_setting)
        {
            result.reason = match command
                .as_deref()
                .and_then(env_prefix_projection::node_heap_only_setting)
            {
                // A memory size is the usual reason to set it; say how to
                // raise the heap in a form the sandbox accepts.
                Some(mib) => format!(
                    "HOL Guard blocked this command because the {setting} setting can load code that the installed extension controls cannot check. To give Node more memory, pass the option to node itself and run the tool's script from node_modules, for example `node --max-old-space-size={mib} node_modules/typescript/bin/tsc --noEmit`. Guard runs that form in its read-only sandbox."
                ),
                None => format!(
                    "HOL Guard blocked this command because the {setting} setting can load code that the installed extension controls cannot check. Run the command without it."
                ),
            };
        } else if let Some(setting) = command
            .as_deref()
            .and_then(env_prefix_projection::substituted_setting)
        {
            result.reason = format!(
                "HOL Guard blocked this command because the {setting} setting is filled by a command substitution or variable expansion, which Guard does not allow in an environment prefix. Do not capture credentials or other output into a setting. Rely on the tool's own login (for example gh's active account), or run the commands separately without passing the output through the environment."
            );
        } else if let Some(setting) = command
            .as_deref()
            .and_then(env_prefix_projection::credential_setting)
        {
            result.reason = format!(
                "HOL Guard blocked this command because the {setting} setting passes a credential that the installed extension controls cannot check. Do not put credentials in an environment prefix. Rely on the tool's own login or the environment the session already has, or ask the user to run the command."
            );
        } else if command
            .as_deref()
            .is_some_and(open_quote::leaves_quote_open)
        {
            result.reason = "HOL Guard blocked this command because it has a shell syntax error: it leaves a quote open, so the shell cannot run it as written. Close or remove the stray quote and run it again.".into();
        }
    }
    result
}

fn omp_bash_cwd_review(harness: &str, event: &str) -> PreToolResultV1 {
    generic_result(
        generic_action(
            harness,
            event,
            PreToolActionTypeV1::Command,
            PreToolOperationV1::Execute,
            false,
            false,
        ),
        "review",
        "native_omp_bash_cwd_review",
        "HOL Guard could not resolve the working directory this command runs in, so it requires review. Pass an existing directory as an absolute path, a path relative to the session directory, or a path under ~.",
    )
}

// The command cannot start, so stopping it costs nothing. Saying why lets the
// agent fix the directory instead of waiting on an approval.
fn omp_bash_cwd_missing(harness: &str, event: &str) -> PreToolResultV1 {
    generic_result(
        generic_action(
            harness,
            event,
            PreToolActionTypeV1::Command,
            PreToolOperationV1::Execute,
            false,
            false,
        ),
        "block",
        evaluate::MISSING_PATH,
        "HOL Guard did not run this command because its working directory does not exist. Check the directory, for example by listing its parent, and try again with the correct one.",
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_envelope(
    harness: &str,
    event: &str,
    payload: &Value,
    controls: Option<&CompiledNativeCommandControls>,
    deadline: Option<Instant>,
    context: super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    project_redirects: bool,
) -> PreToolResultV1 {
    let context =
        super::PathContext::for_session(context.home_dir, context.cwd, execution_environment);
    let super::PathContext { home_dir, cwd, .. } = context;
    let yield_payload = (harness == "omp")
        .then(|| omp::yield_signal_payload(payload))
        .flatten();
    let mut signals = match extract_generic_signals(yield_payload.as_ref().unwrap_or(payload)) {
        Ok(value) => value,
        Err(error) => return generic_error_result(harness, event, error),
    };
    signals.github_read_only = harness == "omp"
        && event == "PreToolUse"
        && omp::strict_tool_input(payload)
            .is_some_and(|input| github::read_only_call(input, signals.tool_name.as_deref()));
    // A search pattern is data, not a command: a proven Claude `Grep` scope
    // skips the command authority but still passes the command controls below.
    let search_scope_proven = event == "PreToolUse"
        && harness == "claude-code"
        && signals.url_values.is_empty()
        && match signals.tool_name.as_deref() {
            Some("Grep") => {
                super::search_scope::claude_grep_directory_scope_proven(payload, home_dir, cwd)
            }
            Some("Glob") => super::search_scope::claude_glob_scope_proven(payload, home_dir, cwd),
            _ => false,
        };
    // Codex sends an edit as `apply_patch` with the patch body in `command`.
    // That body is an edit description, not shell, so it has its own proof.
    let apply_patch_proven = event == "PreToolUse"
        && harness == "codex"
        && signals.tool_name.as_deref() == Some("apply_patch")
        && signals.url_values.is_empty()
        && signals.path_values.is_empty()
        && !signals.independent_sensitive_target
        && signals.command.as_deref().is_some_and(|patch| {
            super::apply_patch_writes::routine_apply_patch(patch, home_dir, cwd)
        });
    // Oh My Pi sends an edit as `edit` with a hashline patch in `input`. Its
    // `+` rows are file content, so the patch has its own proof too.
    // Oh My Pi 18.8 copies the headers into `path`/`paths`; the proof reads
    // the edit without those copies once they are shown to match.
    let edit_payload = (event == "PreToolUse" && harness == "omp")
        .then(|| omp::edit_signal_payload(payload))
        .flatten();
    let edit_signals = edit_payload
        .as_ref()
        .and_then(|projected| extract_generic_signals(projected).ok());
    let edit_signals = edit_signals.as_ref().unwrap_or(&signals);
    let omp_hashline_edit = (event == "PreToolUse"
        && harness == "omp"
        && edit_signals.tool_name.as_deref() == Some("edit")
        && edit_signals.url_values.is_empty()
        && edit_signals.path_values.is_empty()
        && edit_signals.command.is_none()
        && !edit_signals.independent_sensitive_target)
        .then(|| omp::strict_tool_input(edit_payload.as_ref().unwrap_or(payload)))
        .flatten()
        .filter(|input| input.len() == 1)
        .and_then(|input| input.get("input")?.as_str())
        .and_then(|patch| super::omp_hashline_writes::evaluate_hashline_edit(patch, home_dir, cwd));
    // Exporting only Git-config isolation (`GIT_CONFIG_GLOBAL=/dev/null`)
    // removes configuration sources, so the remaining command's allow carries.
    if let Some(projected) = signals
        .command
        .as_deref()
        .filter(|_| !search_scope_proven && !apply_patch_proven)
        .and_then(env_prefix_projection::project_git_config_isolation)
    {
        let projected_payload = payload_with_command(
            payload,
            signals.command.as_deref().unwrap_or_default(),
            &projected,
        );
        if projected_payload != *payload {
            let projected = evaluate_envelope(
                harness,
                event,
                &projected_payload,
                controls,
                deadline,
                context,
                execution_environment,
                project_redirects,
            );
            if projected.minimum_action == "allow" {
                return projected;
            }
        }
    }
    if let Some(contained) = signals
        .command
        .as_deref()
        .filter(|_| project_redirects && !search_scope_proven && !apply_patch_proven)
        .and_then(|command| {
            workspace_redirects::contained(
                harness,
                event,
                payload,
                command,
                controls,
                deadline,
                context,
                execution_environment,
            )
        })
    {
        return contained;
    }
    // Activating a virtualenv exports settings and runs nothing else, so the
    // command after it carries the verdict, as an inert environment prefix
    // does: the unprojected pass fails only on the `source` itself. A rule
    // that gates the plain form keeps its fail-closed answer for this one.
    if let Some(projected) = signals
        .command
        .as_deref()
        .filter(|_| !search_scope_proven && !apply_patch_proven)
        .and_then(|command| venv_activation_projection::verdict_target(command, context))
    {
        let projected_payload = payload_with_command(
            payload,
            signals.command.as_deref().unwrap_or_default(),
            &projected,
        );
        if projected_payload != *payload {
            let projected = evaluate_envelope(
                harness,
                event,
                &projected_payload,
                controls,
                deadline,
                context,
                execution_environment,
                project_redirects,
            );
            if projected.minimum_action == "allow"
                || (projected.minimum_action == "sandbox-required"
                    && crate::hook_responses::contained_execution_profile(&projected.reason_code)
                        .is_some())
                || !extension_rule_matched(&projected)
            {
                return projected;
            }
        }
    }
    // An inert environment prefix cannot change how the rest of the command
    // runs, so the command without it carries the whole verdict.
    if let Some(projected) = signals
        .command
        .as_deref()
        .filter(|_| !search_scope_proven && !apply_patch_proven)
        .and_then(env_prefix_projection::project)
    {
        let projected_payload = payload_with_command(
            payload,
            signals.command.as_deref().unwrap_or_default(),
            &projected,
        );
        if projected_payload != *payload {
            let projected = evaluate_envelope(
                harness,
                event,
                &projected_payload,
                controls,
                deadline,
                context,
                execution_environment,
                project_redirects,
            );
            // Inert settings cannot widen what an extension rule already
            // allows, but a rule that gates the plain form keeps its own
            // fail-closed answer for wrapped forms. An ordinary value rides
            // only an exact proof; contained execution would drop it, so the
            // reviewed projection below judges every other verdict.
            if projected.minimum_action == "allow"
                || (!extension_rule_matched(&projected)
                    && !env_prefix_projection::removes_values(
                        signals.command.as_deref().unwrap_or_default(),
                    ))
            {
                return projected;
            }
        }
    }
    // A setting that may change behavior (`NODE_PATH=... node x.mjs`) leaves
    // the command unmodeled, which the extension controls cannot bound. Judge
    // the command without it, keep the full command's intrinsic verdict, and
    // never settle below review. The unprojected pass runs without controls,
    // so it cannot recurse here.
    if let Some(reviewed) = signals
        .command
        .as_deref()
        .filter(|_| controls.is_some() && !search_scope_proven && !apply_patch_proven)
        .and_then(|command| env_prefix_projection::project_reviewed(command, context))
    {
        let projected_payload = payload_with_command(
            payload,
            signals.command.as_deref().unwrap_or_default(),
            &reviewed.command,
        );
        let projected = (projected_payload != *payload).then(|| {
            evaluate_envelope(
                harness,
                event,
                &projected_payload,
                controls,
                deadline,
                context,
                execution_environment,
                project_redirects,
            )
        });
        // An extension rule that governs the command was written for its
        // plain form; a setting in front can change what it acts on (a target
        // org, a profile), so that command keeps failing closed.
        if let Some(projected) = projected.filter(|result| !extension_rule_matched(result)) {
            let raw = evaluate_envelope(
                harness,
                event,
                payload,
                None,
                deadline,
                context,
                execution_environment,
                false,
            );
            // The workspace sandbox runs the exact text, settings included,
            // so a contained verdict needs no review for them.
            let mut projected = projected;
            if matches!(raw.minimum_action.as_str(), "allow" | "warn" | "review")
                && !raw.action.sensitive_target
                && super::workspace_contained::carry_settings(
                    &mut projected,
                    signals.command.as_deref().unwrap_or_default(),
                    &reviewed.command,
                    context,
                    execution_environment,
                    harness,
                    event,
                )
            {
                return projected;
            }
            return env_prefix_projection::join_reviewed(projected, raw, &reviewed);
        }
    }

    if let Some(projection) = signals
        .command
        .as_deref()
        .filter(|_| project_redirects && !search_scope_proven && !apply_patch_proven)
        .and_then(|command| redirect_projection::project(command, context))
    {
        let projected_payload = payload_with_command(
            payload,
            signals.command.as_deref().unwrap_or_default(),
            &projection.command,
        );
        let projected = evaluate_envelope(
            harness,
            event,
            &projected_payload,
            controls,
            deadline,
            context,
            execution_environment,
            false,
        );
        // A chain that writes a workspace file beside local Git writes keeps
        // the review unless the Git proof and the written paths both hold.
        if projection.git_chain.as_deref().is_none_or(|targets| {
            redirect_projection::git_chain::settled(
                &projected,
                targets,
                context,
                deadline,
                execution_environment,
            )
        }) {
            let raw = evaluate_envelope(
                harness,
                event,
                payload,
                None,
                deadline,
                context,
                execution_environment,
                false,
            );
            return redirect_projection::join(projected, raw, &projection);
        }
    }
    let task_metadata = event == "PreToolUse"
        && agent_metadata::bounded_task_list(payload, signals.tool_name.as_deref())
        && signals.command.is_none()
        && !signals.package_present
        && signals.path_values.is_empty()
        && signals.url_values.is_empty();
    let omp_context = omp::OmpContext {
        yield_report_verified: yield_payload.is_some(),
        harness,
        event,
        controls,
        deadline,
        path: context,
        execution_environment,
    };
    let omp_result = omp::evaluate(payload, &signals, &omp_context);
    let command_decision = signals
        .command
        .as_deref()
        .filter(|_| !search_scope_proven && !apply_patch_proven)
        .map(|command| {
            evaluate_pre_tool_with_execution_context(
                &CommandModelRequestV1 {
                    command: command.to_owned(),
                    dialect: tools::command_dialect(signals.tool_name.as_deref()).to_owned(),
                    transport: "shell_string".to_owned(),
                    extraction_provenance: "pre-tool-generic".to_owned(),
                },
                home_dir,
                cwd,
                deadline,
                execution_environment,
            )
        });
    // Parsed benign commands may contain credential words as search patterns.
    // Preserve independent structured-path/content risk, not the raw-text hint.
    if command_decision.as_ref().is_some_and(|decision| {
        decision
            .as_ref()
            .is_ok_and(|decision| decision.explicitly_benign)
    }) {
        signals.sensitive_target = signals.independent_sensitive_target;
    }
    // A link to a secret file is that secret under another name.
    signals.sensitive_target |=
        super::secret_aliases::decision_names_secret_alias(command_decision.as_ref(), context);
    let hashline_edit_proven = omp_hashline_edit.is_some();
    let mut result = if search_scope_proven {
        generic_result(
            generic_action(
                harness,
                event,
                PreToolActionTypeV1::FileRead,
                PreToolOperationV1::Read,
                true,
                false,
            ),
            "allow",
            "native_bounded_search_scope",
            "The Rust authority proved this directory search cannot reach a sensitive file.",
        )
    } else if apply_patch_proven {
        generic_result(
            generic_action(
                harness,
                event,
                PreToolActionTypeV1::FileWrite,
                PreToolOperationV1::Write,
                true,
                false,
            ),
            "allow",
            "native_exact_safe_file_write",
            "The Rust authority proved every file this patch adds or updates is an ordinary file in the verified workspace, a registered worktree, the verified user home, or a private user-owned temporary directory and clears sensitive-path checks.",
        )
    } else if let Some(edit) = omp_hashline_edit {
        let action = generic_action(
            harness,
            event,
            PreToolActionTypeV1::FileWrite,
            PreToolOperationV1::Write,
            true,
            false,
        );
        match edit {
            super::omp_hashline_writes::HashlineEdit::Routine => generic_result(
                action,
                "allow",
                "native_exact_safe_file_write",
                "The Rust authority proved every file this edit changes is an ordinary workspace or worktree file that clears sensitive-path checks.",
            ),
            // The edit cannot apply, so stopping it costs nothing. Saying why
            // lets the agent fix the path instead of waiting on an approval.
            super::omp_hashline_writes::HashlineEdit::MissingTarget(path) => {
                let mut result = generic_result(action, "block", evaluate::MISSING_PATH, "");
                result.reason = evaluate::missing_path_reason(
                    "HOL Guard did not run this edit because a file it names does not exist. Check the path, for example by listing its parent directory, and try again with the correct one.",
                    "edit",
                    Some(&path),
                );
                result
            }
        }
    } else if harness == "omp"
        && event == "PreToolUse"
        && signals.tool_name.as_deref() == Some("edit")
        && omp::strict_tool_input(payload).is_some_and(super::omp_hashline_writes::headerless_edit)
    {
        generic_result(
            generic_action(
                harness,
                event,
                PreToolActionTypeV1::Harness,
                PreToolOperationV1::Set,
                true,
                false,
            ),
            "allow",
            "native_omp_edit_without_header",
            "The Rust authority found an edit with no file header: Oh My Pi refuses it, so it cannot change any file.",
        )
    } else if let Some(omp_result) = omp_result {
        omp_result
    } else if let Some(pure_result) = pure_eval::evaluate(harness, event, payload, &signals) {
        pure_result
    } else if task_metadata {
        generic_result(
            generic_action(harness, event, PreToolActionTypeV1::Harness,
                if signals.tool_name.as_deref() == Some("TaskOutput") { PreToolOperationV1::Read } else { PreToolOperationV1::Set }, true, false),
            "allow", "native_agent_task_metadata", "The Rust authority verified bounded host task metadata with no new execution or filesystem effects.",
        )
    } else {
        evaluate_signals(
            harness,
            event,
            &signals,
            command_decision.as_ref(),
            home_dir,
            cwd,
        )
    };
    // An Oh My Pi hashline edit writes the files its headers name, whatever
    // its `path` field says, so only the hashline proof may allow it.
    if harness == "omp"
        && !hashline_edit_proven
        && result.reason_code == "native_exact_safe_file_write"
        && signals.tool_name.as_deref() == Some("edit")
        && omp::strict_tool_input(payload)
            .is_none_or(|input| input.contains_key("input") || input.contains_key("_input"))
    {
        let (reason_code, reason) = result::review_reason(PreToolActionTypeV1::FileWrite);
        result = generic_result(result.action.clone(), "review", reason_code, reason);
    }
    if result.reason_code == "native_file_read_review" {
        if let Some(note) = omp::grep_review_note(payload, &signals, &omp_context) {
            result.reason = format!("{} {note}", result.reason);
        } else if let Some(reason) = read_note::read_review_reason(&signals, &omp_context) {
            result.reason = reason;
        }
    }
    if event == "UserPromptSubmit" {
        let mut classes = Vec::new();
        if result.action.sensitive_target && signals.content_sensitive {
            classes.push(if signals.env_reference {
                NativePromptRiskClassV1::LocalEnvRead
            } else {
                NativePromptRiskClassV1::SensitiveMaterial
            });
        }
        if signals.exfil_intent {
            classes.push(NativePromptRiskClassV1::ExfilIntent);
        }
        if signals.destructive_intent {
            classes.push(NativePromptRiskClassV1::DestructiveIntent);
        }
        if signals.subprocess_intent {
            classes.push(NativePromptRiskClassV1::SubprocessIntent);
        }
        if signals.guard_bypass_intent {
            classes.push(NativePromptRiskClassV1::GuardBypassIntent);
        }
        if signals.prompt_injection_intent {
            classes.push(NativePromptRiskClassV1::PromptInjectionIntent);
        }
        result.prompt_risk_classes = classes;
    }
    let command_model = command_decision
        .as_ref()
        .and_then(|decision| decision.as_ref().ok())
        .map(|decision| &decision.command_model);
    let mut result = match (controls, command_model) {
        (Some(controls), Some(model)) => controls.apply_with_tool_and_context(
            Some(model),
            result,
            signals.tool_name.as_deref(),
            &signals.package_values,
            deadline,
            super::PathContext {
                home_dir,
                cwd,
                ..context
            },
            execution_environment,
        ),
        (Some(controls), _) => controls.apply_with_tool(
            None,
            result,
            signals.tool_name.as_deref(),
            &signals.package_values,
            deadline,
        ),
        _ => result,
    };
    let pre_floor = (result.reason_code.clone(), result.minimum_action.clone());
    let floor_context = super::PathContext {
        home_dir,
        cwd,
        ..context
    };
    if event == "PreToolUse"
        // Existing helper-context review may delegate only to enforced
        // read-only containment below; do not replace that protection.
        && result.reason_code != "native_git_helper_context_review"
        && command_model.is_some_and(|model| {
            super::git_read_floor::requires_review(
                model,
                floor_context,
                deadline,
                execution_environment,
            )
        })
        && matches!(
            result.minimum_action.as_str(),
            "allow" | "warn" | "review"
        )
    {
        result.minimum_action = "require-reapproval".into();
        result.policy_action = "require-reapproval".into();
        result.decision = "deny".into();
        result.explicitly_benign = false;
        result.reason_code = "native_git_execution_context_review".into();
        result.reason = command_model
            .and_then(|model| {
                git_read_order_reason(model, floor_context, deadline, execution_environment)
            })
            .unwrap_or_else(|| "HOL Guard requires review because this Git read may execute a configured helper, or its effective configuration could not be verified.".into());
    }
    let contained_test_reason = command_model.and_then(|model| {
        super::restricted_test_commands::package_script::contained_test_reason(
            model,
            super::PathContext {
                home_dir,
                cwd,
                ..context
            },
        )
    });
    // macOS runs every credential-filtering profile. Windows runs the Python
    // and Node evaluation profiles, the read-only pytest profile, the Vite
    // build and the read-only Node tools (lint, typecheck and format checks)
    // in an AppContainer, for harnesses whose shell runs a sink command
    // written for it: Claude Code (Git Bash) and the Pi family (a bash
    // implementation) take the POSIX-quoted one, Codex a PowerShell one. The
    // sink command names only the profile, so every profile routes the same
    // way. Only harnesses that rewrite into the contained sink get the
    // receipt; others would see a bare deny.
    let windows_contained =
        matches!(
            contained_test_reason,
            Some(
                "native_python_eval_readonly_containment_required"
                    | "native_node_build_output_containment_required"
                    | "native_node_tool_readonly_containment_required"
                    | "native_node_eval_readonly_containment_required"
                    | "native_pytest_readonly_containment_required"
            )
        ) && matches!(harness, "claude-code" | "codex" | "omp" | "oh-my-pi" | "pi");
    if (cfg!(target_os = "macos") || (cfg!(windows) && windows_contained))
        && event == "PreToolUse"
        && matches!(
            harness,
            "omp" | "oh-my-pi" | "pi" | "zcode" | "claude-code" | "codex"
        )
        && cwd.is_some()
        && (result.action.action_type == PreToolActionTypeV1::Command
            || (matches!(
                contained_test_reason,
                Some(
                    "native_vitest_readonly_containment_required"
                        | "native_package_test_readonly_containment_required"
                        | "native_node_tool_readonly_containment_required"
                        | "native_node_build_output_containment_required"
                )
            ) && result.action.action_type == PreToolActionTypeV1::Package))
        && !result.action.sensitive_target
        && (result.reason_code == "native_command_review_required"
            || (contained_test_reason == Some("native_git_readonly_containment_required")
                && result.reason_code == "native_git_helper_context_review")
            || (matches!(
                contained_test_reason,
                Some(
                    "native_node_tool_readonly_containment_required"
                        | "native_vitest_readonly_containment_required"
                        | "native_package_test_readonly_containment_required"
                        | "native_node_build_output_containment_required"
                )
            ) && result.reason_code == "native_package_review"))
        && result.minimum_action == "review"
        && result.command_extensions.as_ref().is_none_or(|extensions| {
            extensions.binding.uncertainty_count == 0
                && extensions.evaluation_error.is_none()
                && extensions.observations.iter().all(|observation| {
                    contained_test_reason == Some("native_git_readonly_containment_required")
                        && matches!(
                            observation.rule_id.as_str(),
                            "command.git.diff" | "command.git.log" | "command.git.show"
                        )
                        && observation.uncertainty_reasons.is_empty()
                        && observation.effective_segment_indexes == [0]
                })
                && extensions
                    .permission_observations
                    .iter()
                    .all(|observation| {
                        super::restricted_test_commands::package_permission_contained(
                            contained_test_reason,
                            command_model,
                        ) && observation.extension_id == "command.package.node"
                            && observation.permission_id
                                == "command.package.node.permission.package-protection"
                            && observation.uncertainty_reasons.is_empty()
                    })
        })
        && contained_test_reason.is_some()
        // Inline source that needs the network would only fail in a sandbox
        // that withholds it; it keeps its review.
        && command_model.is_none_or(|model| {
            !super::script_content::inline_uses_network(
                model,
                signals.command.as_deref(),
                super::PathContext {
                    home_dir,
                    cwd,
                    ..context
                },
            )
        })
    {
        result.minimum_action = "sandbox-required".into();
        result.policy_action = "sandbox-required".into();
        result.reason_code = contained_test_reason
            .expect("checked required test profile")
            .into();
        result.reason = concat!(
            "HOL Guard requires protected read-only execution for this repository action. ",
            "Direct execution remains blocked.",
        )
        .into();
    }
    // A proven fast-forward of origin runs directly, as the pull it splits
    // does; the sandbox would cut the fetch beside it off the network.
    super::git_remote_ops::settle_fast_forward(
        &mut result,
        command_model,
        super::PathContext {
            home_dir,
            cwd,
            ..context
        },
        deadline,
        execution_environment,
    );
    super::workspace_contained::convert(
        &mut result,
        &pre_floor,
        command_model,
        controls,
        super::PathContext {
            home_dir,
            cwd,
            ..context
        },
        execution_environment,
        harness,
        event,
        signals.command.as_deref(),
    );
    super::git_local_writes::settle(
        &mut result,
        &pre_floor,
        command_model,
        controls,
        super::PathContext {
            home_dir,
            cwd,
            ..context
        },
        deadline,
        execution_environment,
    );
    if event == "PreToolUse" {
        super::lockfile_install::settle(
            &mut result,
            command_model,
            super::PathContext {
                home_dir,
                cwd,
                ..context
            },
            deadline,
            execution_environment,
        );
    }
    result
}

fn extension_rule_matched(result: &PreToolResultV1) -> bool {
    result.command_extensions.as_ref().is_some_and(|batch| {
        batch
            .observations
            .iter()
            .any(|row| !row.effective_segment_indexes.is_empty())
    })
}

/// The Git floor's reason when every Git read was proven helper-free on its
/// own and only an earlier step kept that proof from carrying over. Agents
/// given the generic helper reason stopped using Git altogether; naming the
/// step tells them the read is fine as its own command.
fn git_read_order_reason(
    model: &crate::CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<String> {
    let steps = super::git_read_floor::unsettled_steps_before_reads(
        model,
        context,
        deadline,
        execution_environment,
    )?;
    let named: Vec<String> = steps
        .iter()
        .take(3)
        .map(|index| {
            format!(
                "{} ({})",
                index + 1,
                super::compound_reason::step_label(&model.segments[*index])
            )
        })
        .collect();
    let more = if steps.len() > named.len() {
        " and others"
    } else {
        ""
    };
    let (noun, verb) = if steps.len() == 1 {
        ("Step", "runs")
    } else {
        ("Steps", "run")
    };
    Some(format!(
        "HOL Guard requires review because {noun} {}{more} {verb} before the Git read and could not be proven to leave Git's configuration unchanged. The Git read was checked and runs no configured helper; run it as its own command.",
        named.join(", "),
    ))
}
