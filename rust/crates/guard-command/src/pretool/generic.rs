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
#[path = "generic_extract.rs"]
mod extract;
#[path = "generic_omp.rs"]
mod omp;
#[path = "open_quote.rs"]
mod open_quote;
#[path = "generic_pure_eval.rs"]
mod pure_eval;
#[path = "redirect_projection.rs"]
mod redirect_projection;
#[path = "generic_result.rs"]
mod result;
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
            shell_home_matches: false,
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
    // code-loading setting or an open quote, so the agent can fix it and retry
    // instead of guessing.
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
            result.reason = format!(
                "HOL Guard blocked this command because the {setting} setting can load code that the installed extension controls cannot check. Run the command without it."
            );
        } else if let Some(setting) = command
            .as_deref()
            .and_then(env_prefix_projection::substituted_setting)
        {
            result.reason = format!(
                "HOL Guard blocked this command because the {setting} setting is filled by a command substitution or variable expansion, which Guard does not allow in an environment prefix. Do not capture credentials or other output into a setting. Rely on the tool's own login (for example gh's active account), or run the commands separately without passing the output through the environment."
            );
        } else if command
            .as_deref()
            .is_some_and(open_quote::leaves_quote_open)
        {
            result.reason = "HOL Guard blocked this command because it leaves a quote open, so the shell cannot run it as written. Close or remove the stray quote and run it again.".into();
        }
    }
    result
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
            // fail-closed answer for wrapped forms.
            if projected.minimum_action == "allow" || !extension_rule_matched(&projected) {
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
                    context,
                    execution_environment,
                    harness,
                    event,
                )
            {
                return projected;
            }
            return env_prefix_projection::join_reviewed(projected, raw, &reviewed.setting);
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
            return redirect_projection::join(
                projected,
                raw,
                projection.writes_file,
                projection.bounded_writes,
            );
        }
    }
    let task_metadata = event == "PreToolUse"
        && agent_metadata::bounded_task_list(payload, signals.tool_name.as_deref())
        && signals.command.is_none()
        && !signals.package_present
        && signals.path_values.is_empty()
        && signals.url_values.is_empty();
    let omp_result = omp::evaluate(
        payload,
        &signals,
        &omp::OmpContext {
            yield_report_verified: yield_payload.is_some(),
            harness,
            event,
            controls,
            deadline,
            path: context,
            execution_environment,
        },
    );
    let command_decision = signals
        .command
        .as_deref()
        .filter(|_| !search_scope_proven && !apply_patch_proven)
        .map(|command| {
            evaluate_pre_tool_with_execution_context(
                &CommandModelRequestV1 {
                    command: command.to_owned(),
                    dialect: "posix".to_owned(),
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
            "The Rust authority proved every file this patch adds or updates is an ordinary workspace file that clears sensitive-path checks.",
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
    if event == "PreToolUse"
        // Existing helper-context review may delegate only to enforced
        // read-only containment below; do not replace that protection.
        && result.reason_code != "native_git_helper_context_review"
        && command_model.is_some_and(|model| {
            super::git_read_floor::requires_review(
                model,
                super::PathContext { home_dir, cwd, ..context },
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
        result.reason = "HOL Guard requires review because this Git read may execute a configured helper, or its effective configuration could not be verified.".into();
    }
    let contained_test_reason = command_model.and_then(|model| {
        super::restricted_tests::readonly_test_reason(model).or_else(|| {
            super::contained_wrapper::contained_core(
                model,
                super::PathContext {
                    home_dir,
                    cwd,
                    ..context
                },
            )
            .and_then(|core| super::restricted_tests::readonly_test_reason(&core))
            .filter(|reason| *reason != "native_git_readonly_containment_required")
        })
    });
    // macOS only (the credential-filtering profile); only harnesses that rewrite
    // into the contained sink get the receipt, others would see a bare deny.
    if cfg!(target_os = "macos")
        && event == "PreToolUse"
        && matches!(
            harness,
            "omp" | "oh-my-pi" | "zcode" | "claude-code" | "codex"
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
                        super::restricted_tests::package_permission_contained(
                            contained_test_reason,
                            command_model,
                        ) && observation.extension_id == "command.package.node"
                            && observation.permission_id
                                == "command.package.node.permission.package-protection"
                            && observation.uncertainty_reasons.is_empty()
                    })
        })
        && contained_test_reason.is_some()
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
